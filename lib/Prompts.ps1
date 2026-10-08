#=========================================================================
# Prompts.ps1 - interactive helpers (menu, Y/N, CSV path).
#=========================================================================

function Read-YesNo {
    param([Parameter(Mandatory)][string]$Prompt, [bool]$Default = $false)
    $hint = if ($Default) { "[Y/n]" } else { "[y/N]" }
    while ($true) {
        $a = ([string](Read-Host "$Prompt $hint")).Trim()
        if ($a -eq "") { return $Default }
        if ($a -match "^(y|yes)$") { return $true }
        if ($a -match "^(n|no)$")  { return $false }
        Write-Host "  Please answer Y or N." -ForegroundColor Yellow
    }
}

function Show-ModeMenu {
    Write-Host ""
    Write-Host "==========  CyberArk Privilege Cloud - Auto Onboarding  ==========" -ForegroundColor White
    Write-Host "  1) Safe only            - create safe(s) + default/derived members"
    Write-Host "  2) Platform only        - duplicate a reference platform (+ activate)"
    Write-Host "  3) Full onboarding      - platform + safe + members + account (+ Verify/Reconcile)"
    Write-Host "  4) Account only         - onboard account(s) into an EXISTING safe and platform"
    Write-Host "  5) Diagnose             - connectivity check, API response shapes, safe members"
    Write-Host "  Q) Quit"
    while ($true) {
        $c = (Read-Host "Select an option").Trim().ToUpper()
        switch ($c) {
            "1" { return "SafeOnly" }
            "2" { return "PlatformOnly" }
            "3" { return "Full" }
            "4" { return "AccountOnly" }
            "5" { return "Diagnose" }
            "Q" { return "Quit" }
            default { Write-Host "  Enter 1-5 or Q." -ForegroundColor Yellow }
        }
    }
}

function Read-CsvPathPrompt {
    param([string]$Mode, [string]$Root)
    $template = Join-Path $Root "templates\$Mode.csv"
    Write-Host "  Template for this mode: $template" -ForegroundColor DarkGray
    while ($true) {
        $p = (Read-Host "Path to the intake CSV").Trim().Trim('"')
        if ($p -and (Test-Path -LiteralPath $p)) { return $p }
        Write-Host "  File not found." -ForegroundColor Yellow
    }
}
