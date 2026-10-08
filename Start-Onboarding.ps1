#=========================================================================
# Start-Onboarding.ps1  -  CyberArk Privilege Cloud auto-onboarding suite
#
# Modes (menu, or -Mode):
#   SafeOnly      create safe(s) + default/derived members
#   PlatformOnly  duplicate a reference (source) platform and activate it
#   Full          platform + safe + members + account (+ optional Verify/Reconcile)
#   AccountOnly   onboard account(s) into an existing safe and platform
#   Diagnose      connectivity check, API response shapes, safe members
#
# Examples:
#   .\Start-Onboarding.ps1                                   # interactive menu
#   .\Start-Onboarding.ps1 -Mode Full -CsvPath .\templates\Full.csv
#   .\Start-Onboarding.ps1 -Mode Full -CsvPath .\req.csv -WhatIf   # read-only pre-flight, no changes
#
# The CyberArk service user name and key are ALWAYS prompted at run time.
# Every run is logged (who ran it, from which device) to .\logs and uploaded
# to Azure Blob Storage when configured; an upload failure never stops the run.
#=========================================================================
[CmdletBinding()]
param(
    [ValidateSet("Menu", "SafeOnly", "PlatformOnly", "Full", "AccountOnly", "Diagnose")][string]$Mode = "Menu",
    [string]$CsvPath,
    [string]$ConfigPath,
    [ValidateSet("Ask", "Yes", "No")][string]$Verify = "Ask",
    [ValidateSet("Ask", "Yes", "No")][string]$Reconcile = "Ask",
    [switch]$WhatIf,
    [switch]$AssumeYes,
    [string]$DiagnoseSafe
)

$ScriptVersion = "2.0.0"
$Root = $PSScriptRoot

. "$Root\lib\Config.ps1"
. "$Root\lib\Logging.ps1"
. "$Root\lib\Api.ps1"
. "$Root\lib\Naming.ps1"
. "$Root\lib\Objects.ps1"
. "$Root\lib\Prompts.ps1"
. "$Root\lib\Workflows.ps1"

$ScriptPath = $PSCommandPath
$script:exitCode = 0

function Invoke-OnboardingRun {
    Import-OnboardingConfig -ConfigPath $ConfigPath
    $Global:Onb.Operator = Get-OperatorContext -ScriptPath $ScriptPath -ScriptVersion $ScriptVersion
    Initialize-Logging
    $Global:Onb.DryRun = [bool]$WhatIf

    Write-Log "===================================================" SECTION
    Write-Log " CyberArk Account Onboarding Suite v$ScriptVersion" SECTION
    Write-Log "===================================================" SECTION
    Write-RunContext -Operator $Global:Onb.Operator -Extra @{
        RequestedMode = $Mode; WhatIf = [bool]$WhatIf; ConfigFile = $Global:Onb.ConfigPath
        LocalOverride = $(if ($Global:Onb.LocalConfigLoaded) { $Global:Onb.LocalConfigLoaded } else { "(none)" })
        LogFile = $Global:Onb.LogFile
    }

    # ---- mode selection -------------------------------------------------
    if ($Mode -eq "Menu") { $Mode = Show-ModeMenu }
    if ($Mode -eq "Quit") { Write-Log "Operator quit from the menu. No changes made." WARN; return }
    $Global:Onb.Mode = $Mode
    Write-Log "Mode selected: $Mode" INFO

    # ---- Diagnose -------------------------------------------------------
    if ($Mode -eq "Diagnose") {
        Connect-CyberArk
        Invoke-Diagnose -SafeName $DiagnoseSafe
        return
    }

    # ---- read + validate CSV (no API calls yet) --------------------------
    if (-not $CsvPath) { $CsvPath = Read-CsvPathPrompt -Mode $Mode -Root $Root }
    if (-not (Test-Path -LiteralPath $CsvPath)) { throw "CSV not found: $CsvPath" }
    $csvHash = (Get-FileHash -LiteralPath $CsvPath -Algorithm SHA256).Hash
    Write-Log "Input CSV : $CsvPath (SHA256 $csvHash)" INFO
    $rows = @(Import-Csv -LiteralPath $CsvPath)
    if ($rows.Count -eq 0) { throw "CSV has no data rows." }

    $plan = New-OnboardingPlan -Mode $Mode -Rows $rows
    if ($plan.Errors.Count -gt 0) {
        Write-Log "Validation failed - fix the CSV and re-run. No API calls were made." ERROR
        $plan.Errors | ForEach-Object { Write-Log "  $_" ERROR }
        $script:exitCode = 1
        return
    }
    Write-Log "CSV validated: $($plan.Items.Count) row(s), $($plan.Safes.Count) safe(s), $($plan.Platforms.Count) platform(s)." SUCCESS
    if ($rows | Where-Object { $_.PSObject.Properties["InitialSecret"] -and $_.InitialSecret }) {
        Write-Log "The CSV contains InitialSecret value(s). Prefer leaving that column blank and typing secrets at the prompt; delete the file after use." WARN
    }

    # ---- sign in, read-only pre-flight, preview --------------------------
    Connect-CyberArk
    Invoke-Preflight -Mode $Mode -Plan $plan
    Show-Preview -Mode $Mode -Plan $plan

    if ($WhatIf) {
        Write-Log "WhatIf specified - pre-flight was read-only; nothing was created or changed." WARN
        return
    }

    # ---- run-time choices --------------------------------------------------
    $runVerify = $false; $runReconcile = $false; $promptSecrets = $false
    if ($Mode -in @("Full", "AccountOnly")) {
        $runVerify    = switch ($Verify)    { "Yes" { $true } "No" { $false } default { if ($AssumeYes) { $false } else { Read-YesNo "Run Verify on each onboarded account?" $false } } }
        $runReconcile = switch ($Reconcile) { "Yes" { $true } "No" { $false } default { if ($AssumeYes) { $false } else { Read-YesNo "Run Reconcile on each onboarded account? (this CHANGES the password)" $false } } }
        Write-Log "Operator choice - Verify: $runVerify, Reconcile: $runReconcile" INFO
        $noSecret = @($plan.Items | Where-Object { -not $_.InitialSecret }).Count
        if ($noSecret -gt 0 -and -not $AssumeYes) {
            $promptSecrets = Read-YesNo "$noSecret account(s) have no InitialSecret in the CSV. Type a secret for each one now (hidden input)?" $false
        }
    }

    if (-not $AssumeYes) {
        if (-not (Read-YesNo "Proceed with creating/updating everything shown above?" $false)) {
            Write-Log "Operator declined at the confirmation prompt. No changes made." WARN
            return
        }
    }
    Write-Log "Operator confirmed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - proceeding." SUCCESS

    # ---- execute ---------------------------------------------------------------
    $platformResults = $null; $safeResults = $null
    if ($Mode -in @("PlatformOnly", "Full")) { $platformResults = Invoke-PlatformPhase -Plan $plan }
    if ($Mode -in @("SafeOnly", "Full"))      { $safeResults = Invoke-SafePhase -Plan $plan }
    if ($Mode -in @("Full", "AccountOnly")) {
        Invoke-AccountPhase -Plan $plan -PlatformResults $platformResults -SafeResults $safeResults `
            -RunVerify $runVerify -RunReconcile $runReconcile -PromptSecrets $promptSecrets
    }

    Show-RunSummary
    if (@($Global:Onb.Results | Where-Object { $_.Status -eq "Failed" }).Count -gt 0) { $script:exitCode = 2 }
}

New-OnboardingState -Root $Root
try {
    Invoke-OnboardingRun
}
catch {
    Write-Log "UNHANDLED ERROR: $($_.Exception.Message)" ERROR
    Write-Log "$($_.ScriptStackTrace)" DEBUG
    $script:exitCode = 1
}
finally {
    Complete-Run
}
exit $script:exitCode
