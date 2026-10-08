#=========================================================================
# Onboard-Accounts.ps1
#
# Reads an intake CSV (see Templates\AccountOnboarding_Template.csv),
# builds/validates the Safe and Platform names per the naming convention
# in Common.ps1, groups rows into distinct safes, PREVIEWS everything the
# run will create, asks for one confirmation, then creates/reuses
# Platforms and Safes, adds safe members, onboards accounts, and triggers
# Verify + Reconcile.
#
# Usage:
#   .\Onboard-Accounts.ps1 -CsvPath .\Templates\AccountOnboarding_Template.csv
#   .\Onboard-Accounts.ps1 -CsvPath .\myrequest.csv -WhatIf   # preview only, no changes, no prompt
#=========================================================================
param(
    [Parameter(Mandatory)][string]$CsvPath,
    [switch]$WhatIf
)

. "$PSScriptRoot\Common.ps1"

Write-Log "===================================================" SECTION
Write-Log " CyberArk Account Onboarding" SECTION
Write-Log "===================================================" SECTION
Write-Log "Input CSV : $CsvPath" INFO

if (-not (Test-Path $CsvPath)) { Write-Log "CSV not found: $CsvPath" ERROR; exit 1 }
$rows = @(Import-Csv -Path $CsvPath)
if ($rows.Count -eq 0) { Write-Log "CSV has no data rows." ERROR; exit 1 }

$RequiredColumns = @(
    "Region", "Environment", "Technology", "AccessType", "Team",
    "Flavour", "AppTower", "PlatformAccountType", "RotationPolicy",
    "SourcePlatformID", "AccountUserName", "Address", "SecretType", "RequesterEmail"
)
$missingCols = $RequiredColumns | Where-Object { $_ -notin $rows[0].PSObject.Properties.Name }
if ($missingCols) { Write-Log "CSV is missing required column(s): $($missingCols -join ', ')" ERROR; exit 1 }

#region Pass 1: validate every row & build compliant names (no API calls yet)
$planItems = [System.Collections.Generic.List[PSCustomObject]]::new()
$rowErrors = [System.Collections.Generic.List[string]]::new()
$rowNum = 1

foreach ($row in $rows) {
    $rowNum++  # header is row 1

    $safeCheck = Test-SafeNameInputs -Region $row.Region -Environment $row.Environment -Technology $row.Technology `
        -AccessType $row.AccessType -Tier $row.Tier -Team $row.Team
    $platCheck = Test-PlatformNameInputs -Region $row.Region -Flavour $row.Flavour -AppTower $row.AppTower `
        -AccountType $row.PlatformAccountType -RotationPolicy $row.RotationPolicy -Vendor $row.Vendor -Exception $row.Exception

    if (-not $safeCheck.IsValid) { $rowErrors.Add("Row ${rowNum} (Safe): $($safeCheck.Errors -join '; ')") }
    if (-not $platCheck.IsValid) { $rowErrors.Add("Row ${rowNum} (Platform): $($platCheck.Errors -join '; ')") }
    if ([string]::IsNullOrWhiteSpace($row.SourcePlatformID)) { $rowErrors.Add("Row ${rowNum}: SourcePlatformID is required") }
    if ([string]::IsNullOrWhiteSpace($row.AccountUserName)) { $rowErrors.Add("Row ${rowNum}: AccountUserName is required") }
    if ([string]::IsNullOrWhiteSpace($row.Address)) { $rowErrors.Add("Row ${rowNum}: Address is required") }

    if ($safeCheck.IsValid -and $platCheck.IsValid) {
        $groups = Get-DerivedGroupNames -SafeName $safeCheck.SuggestedName
        $planItems.Add([pscustomobject]@{
            RowNum           = $rowNum
            SafeName         = $safeCheck.SuggestedName
            PlatformName     = $platCheck.SuggestedName
            SourcePlatformID = $row.SourcePlatformID
            SafeManagerGroup = $groups.SafeManagerGroup
            SafeUserGroup    = $groups.SafeUserGroup
            AccountUserName  = $row.AccountUserName
            Address          = $row.Address
            SecretType       = if ($row.SecretType) { $row.SecretType } else { "password" }
            InitialSecret    = $row.InitialSecret
            RequesterEmail   = $row.RequesterEmail
        })
    }
}

if ($rowErrors.Count -gt 0) {
    Write-Log "Validation failed on $($rowErrors.Count) row(s) -- fix the CSV and re-run. No API calls were made." ERROR
    $rowErrors | ForEach-Object { Write-Log "  $_" ERROR }
    exit 1
}
#endregion

#region Group rows into distinct safes / platforms
$safeGroups     = $planItems | Group-Object SafeName
$platformGroups = $planItems | Group-Object PlatformName, SourcePlatformID
#endregion

#region Preview + confirmation
Write-Log "=== Preview: $($safeGroups.Count) safe(s), $($platformGroups.Count) platform(s), $($planItems.Count) account(s) ===" SECTION
Write-Host ""
Write-Host ("{0,-30} {1,-30} {2,-25} {3}" -f "SafeName", "PlatformName", "AccountUserName", "Address") -ForegroundColor White
Write-Host ("-" * 110) -ForegroundColor DarkGray
foreach ($p in $planItems) {
    Write-Host ("{0,-30} {1,-30} {2,-25} {3}" -f $p.SafeName, $p.PlatformName, $p.AccountUserName, $p.Address)
}
Write-Host ""
foreach ($sg in $safeGroups) {
    $first = $sg.Group[0]
    Write-Host "Safe '$($sg.Name)' -- members that will be added:" -ForegroundColor Cyan
    foreach ($m in $DefaultSafeMembers) { Write-Host "  - $($m.MemberName)  (Full Control)" }
    Write-Host "  - $($first.SafeManagerGroup)  (Safe Manager)"
    Write-Host "  - $($first.SafeUserGroup)  (Safe User)"
}
Write-Host ""

if ($WhatIf) {
    Write-Log "WhatIf specified -- preview only, no changes made." WARN
    exit 0
}

$confirm = Read-Host "Proceed with creating/updating everything shown above? (Y/N)"
if ($confirm -notin @("Y", "y")) {
    Write-Log "User declined at confirmation prompt. Exiting without any changes." WARN
    exit 0
}
Write-Log "User confirmed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') -- proceeding with creation." SUCCESS
#endregion

Get-AuthToken

#region Step 1: Platforms (one duplicate per distinct PlatformName/SourcePlatformID pair)
# Each entry: @{ Success = bool; PlatformId = <the ID to actually pass to New-Account> }
# PlatformId is NOT assumed to equal $platformName -- see Resolve-NewPlatformId in Common.ps1.
$platformResults = @{}
foreach ($pg in $platformGroups) {
    $parts = $pg.Name -split ', ', 2
    $platformName = $parts[0]
    $sourceId     = $parts[1]
    Write-Log "--- Platform: $platformName (source: $sourceId) ---" SECTION

    $existing = Get-PlatformByName -PlatformId $platformName
    if ($existing) {
        Write-Log "Platform '$platformName' already exists -- reusing." INFO
        $existingId = if ($existing.PSObject.Properties.Name -contains "PlatformID") { $existing.PlatformID } else { $existing.general.id }
        if (-not $existingId) { $existingId = $platformName }
        $platformResults[$platformName] = @{ Success = $true; PlatformId = [string]$existingId }
        continue
    }

    $result = New-DuplicatedPlatform -SourcePlatformId $sourceId -NewPlatformName $platformName
    if ($result.Success) {
        $resolvedId = Resolve-NewPlatformId -DuplicateResponseData $result.Data -NewPlatformName $platformName
        $platformResults[$platformName] = @{ Success = $true; PlatformId = $resolvedId }
        Write-Log "Platform '$platformName' created by duplicating '$sourceId' (resolved platform ID for onboarding: '$resolvedId')." SUCCESS
    } else {
        $platformResults[$platformName] = @{ Success = $false; PlatformId = $null }
        Write-Log "Failed to duplicate platform '$platformName' from '$sourceId': $($result.Error)" ERROR
    }
}
#endregion

#region Step 2: Safes + Members (one per distinct SafeName)
# $safeResults gates whether accounts get onboarded -- it reflects whether the SAFE ITSELF
# exists, not whether every member grant succeeded. $safeMemberWarnings is reporting-only, so a
# failed AD group grant doesn't block onboarding into an otherwise-good safe.
$safeResults = @{}
$safeMemberWarnings = @{}
foreach ($sg in $safeGroups) {
    $safeName = $sg.Name
    $first    = $sg.Group[0]
    Write-Log "--- Safe: $safeName ---" SECTION

    $existingSafe = Get-SafeByName -SafeName $safeName
    if ($existingSafe) {
        Write-Log "Safe '$safeName' already exists -- reusing." INFO
    } else {
        $result = New-Safe -SafeName $safeName
        if (-not $result.Success) {
            Write-Log "Failed to create safe '$safeName': $($result.Error) -- its accounts will be skipped." ERROR
            $safeResults[$safeName] = $false
            continue
        }
        Write-Log "Safe '$safeName' created." SUCCESS
    }
    $safeResults[$safeName] = $true

    $memberOk = $true
    foreach ($m in $DefaultSafeMembers) {
        $r = Add-SafeMember -SafeName $safeName -MemberName $m.MemberName -Permissions $FullControlPermissions
        if (-not $r.Success -and $r.StatusCode -ne 409) { $memberOk = $false }
    }
    $r1 = Add-SafeMember -SafeName $safeName -MemberName $first.SafeManagerGroup -Permissions $SafeManagerPermissions
    if (-not $r1.Success -and $r1.StatusCode -ne 409) { $memberOk = $false }
    $r2 = Add-SafeMember -SafeName $safeName -MemberName $first.SafeUserGroup -Permissions $SafeUserPermissions
    if (-not $r2.Success -and $r2.StatusCode -ne 409) { $memberOk = $false }

    $safeMemberWarnings[$safeName] = -not $memberOk
    if (-not $memberOk) { Write-Log "One or more safe members failed on '$safeName' -- see errors above. Its accounts will still be onboarded; fix the member grant(s) separately." WARN }
}
#endregion

#region Step 3: Accounts + Verify + Reconcile
$results = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($p in $planItems) {
    Write-Log "--- Account: $($p.AccountUserName)@$($p.Address) in safe '$($p.SafeName)' ---" SECTION

    $platformInfo = $platformResults[$p.PlatformName]
    if (-not $platformInfo -or -not $platformInfo.Success) {
        Write-Log "Skipping account '$($p.AccountUserName)' -- platform '$($p.PlatformName)' failed earlier in this run." WARN
        $results.Add([pscustomobject]@{ RowNum = $p.RowNum; SafeName = $p.SafeName; PlatformName = $p.PlatformName; AccountUserName = $p.AccountUserName; AccountId = ""; VerifyStatus = ""; ReconcileStatus = ""; Status = "Skipped"; Reason = "Platform creation failed" })
        continue
    }
    if (-not $safeResults.ContainsKey($p.SafeName) -or -not $safeResults[$p.SafeName]) {
        Write-Log "Skipping account '$($p.AccountUserName)' -- safe '$($p.SafeName)' creation failed earlier in this run." WARN
        $results.Add([pscustomobject]@{ RowNum = $p.RowNum; SafeName = $p.SafeName; PlatformName = $p.PlatformName; AccountUserName = $p.AccountUserName; AccountId = ""; VerifyStatus = ""; ReconcileStatus = ""; Status = "Skipped"; Reason = "Safe creation failed" })
        continue
    }
    $memberWarning = if ($safeMemberWarnings[$p.SafeName]) { "Safe member grant(s) failed -- see log" } else { "" }

    $acctResult = New-Account -SafeName $p.SafeName -PlatformId $platformInfo.PlatformId -UserName $p.AccountUserName `
        -Address $p.Address -SecretType $p.SecretType -InitialSecret $p.InitialSecret
    if (-not $acctResult.Success) {
        Write-Log "Failed to onboard account '$($p.AccountUserName)': $($acctResult.Error)" ERROR
        $results.Add([pscustomobject]@{ RowNum = $p.RowNum; SafeName = $p.SafeName; PlatformName = $p.PlatformName; AccountUserName = $p.AccountUserName; AccountId = ""; VerifyStatus = ""; ReconcileStatus = ""; Status = "Failed"; Reason = $acctResult.Error })
        continue
    }
    $accountId = $acctResult.Data.id
    Write-Log "Account onboarded, id=$accountId." SUCCESS

    Invoke-AccountVerify -AccountId $accountId | Out-Null
    $verifyResult = Wait-ForAccountTask -AccountId $accountId -TaskType Verify

    Invoke-AccountReconcile -AccountId $accountId | Out-Null
    $reconcileResult = Wait-ForAccountTask -AccountId $accountId -TaskType Reconcile

    $status = if ($verifyResult.Success -and $reconcileResult.Success) { "Success" }
              elseif ($verifyResult.Success -or $reconcileResult.Success) { "PartialSuccess" }
              else { "Failed" }

    $results.Add([pscustomobject]@{
        RowNum = $p.RowNum; SafeName = $p.SafeName; PlatformName = $p.PlatformName
        AccountUserName = $p.AccountUserName; AccountId = $accountId
        VerifyStatus = $verifyResult.Status; ReconcileStatus = $reconcileResult.Status
        Status = $status; Reason = $memberWarning
    })

    if ($status -ne "Success") { Write-Log "Account '$($p.AccountUserName)' finished with status '$status' (verify=$($verifyResult.Status), reconcile=$($reconcileResult.Status))." WARN }
}
#endregion

#region Results output
$resultsFile = "$ScriptRoot\OnboardingResults_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$results | Export-Csv -Path $resultsFile -NoTypeInformation -Encoding UTF8
Write-Log "===================================================" SECTION
Write-Log " Run complete. Results written to $resultsFile" SECTION
Write-Log "===================================================" SECTION

$failCount = @($results | Where-Object { $_.Status -ne "Success" -or $_.Reason }).Count
if ($failCount -gt 0) {
    Write-Host ""
    Write-Host "$failCount item(s) need attention:" -ForegroundColor Yellow
    $results | Where-Object { $_.Status -ne "Success" -or $_.Reason } | Format-Table RowNum, SafeName, AccountUserName, Status, Reason -AutoSize
}
#endregion
