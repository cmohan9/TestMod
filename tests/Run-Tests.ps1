#=========================================================================
# Run-Tests.ps1 - offline unit tests (no tenant, no network, no Pester needed).
#   pwsh -File .\tests\Run-Tests.ps1        (or powershell.exe -File ...)
# Exit code = number of failed assertions.
#
# End-to-end testing against a mock server is described in tests\mock_server.py.
#=========================================================================
$Root = Split-Path -Parent $PSScriptRoot
. "$Root\lib\Config.ps1"
. "$Root\lib\Logging.ps1"
. "$Root\lib\Api.ps1"
. "$Root\lib\Naming.ps1"
. "$Root\lib\Objects.ps1"
. "$Root\lib\Workflows.ps1"

$script:Failed = 0
$script:Passed = 0
function Assert-Equal {
    param($Actual, $Expected, [string]$Name)
    if ("$Actual" -ceq "$Expected") { $script:Passed++; Write-Host "  PASS  $Name" -ForegroundColor Green }
    else { $script:Failed++; Write-Host "  FAIL  $Name`n        expected: [$Expected]`n        actual  : [$Actual]" -ForegroundColor Red }
}
function Assert-True { param($Condition, [string]$Name) Assert-Equal ([bool]$Condition) $true $Name }

# --- fresh state, base config only (no local override) ---------------------------------------
New-OnboardingState -Root $Root
$env:ONB_TEST = "1"
Import-OnboardingConfig -ConfigPath (Join-Path $Root "config\onboarding.config.json")
$Global:Onb.Operator = [pscustomobject]@{ UserId = "jdoe"; Identity = "CORP\jdoe" }

Write-Host "`nNaming" -ForegroundColor White
$s = Test-SafeNameInputs -Region OCA -Environment P -Technology WIN -AccessType LA -Tier T0 -Team TEST1
Assert-Equal $s.SuggestedName "OCA-P-WIN-LA-T0-TEST1" "safe name with tier"
$s = Test-SafeNameInputs -Region oca -Environment p -Technology win -AccessType la -Tier "" -Team team1
Assert-Equal $s.SuggestedName "OCA-P-WIN-LA-TEAM1" "safe name without tier, upper-cased"
$s = Test-SafeNameInputs -Region XX -Environment P -Technology WIN -AccessType LA -Tier T0 -Team "bad team"
Assert-True (-not $s.IsValid) "invalid region / team rejected"
$s = Test-SafeNameInputs -Region EMEA -Environment P -Technology HTTP -AccessType LSA -Tier T0 -Team "VERYLONGTEAMNAME"
Assert-True (-not $s.IsValid -and ($s.Errors -join " ") -match "exceeds max 28") "28-char safe name limit enforced"
$p = Test-PlatformNameInputs -Region OCA -Flavour WIN -AppTower AD -AccountType LA -RotationPolicy RA -Vendor "" -Exception ""
Assert-Equal $p.SuggestedName "OCA-WIN-AD-LA-RA" "platform name"
$p = Test-PlatformNameInputs -Region OCA -Flavour WIN -AppTower AD -AccountType LA -RotationPolicy RA -Vendor W -Exception EX1
Assert-Equal $p.SuggestedName "OCA-WIN-AD-LA-RA-W-EX1" "platform name with vendor + exception"
$p = Test-PlatformNameInputs -Region OT -Flavour WIN -AppTower AD -AccountType LA -RotationPolicy RA
Assert-True (-not $p.IsValid) "platform region OT is not allowed (safe-only region)"

Write-Host "`nSafe member permission sets (must match the supplied matrix)" -ForegroundColor White
$expectedTrue = @("useAccounts","retrieveAccounts","listAccounts","addAccounts","updateAccountContent","updateAccountProperties","initiateCPMAccountManagementOperations","specifyNextAccountContent","renameAccounts","deleteAccounts","unlockAccounts","manageSafe","manageSafeMembers","backupSafe","viewAuditLog","viewSafeMembers","accessWithoutConfirmation","createFolders","deleteFolders","moveAccountsAndFolders")
$pca = $Global:Onb.Members.permissionSets.PrivilegeCloudAdmin
$bg  = $Global:Onb.Members.permissionSets.BGAccount
Assert-True (@($expectedTrue | Where-Object { -not $pca.$_ }).Count -eq 0) "Privilege Cloud Administrators: first 20 permissions TRUE"
Assert-True (@($expectedTrue | Where-Object { -not $bg.$_ }).Count -eq 0) "BG account: first 20 permissions TRUE"
Assert-Equal $pca.requestsAuthorizationLevel1 $true "Privilege Cloud Administrators: requestsAuthorizationLevel1 TRUE"
Assert-Equal $pca.requestsAuthorizationLevel2 $false "Privilege Cloud Administrators: requestsAuthorizationLevel2 FALSE"
Assert-Equal $bg.requestsAuthorizationLevel1 $false "BG account: requestsAuthorizationLevel1 FALSE"
Assert-Equal $bg.requestsAuthorizationLevel2 $false "BG account: requestsAuthorizationLevel2 FALSE"
Assert-Equal @($pca.PSObject.Properties).Count 22 "permission set has 22 keys"
Assert-Equal @(Test-PermissionSets -Members $Global:Onb.Members).Count 0 "safe-members.json passes validation"

$plan = Get-SafeMemberPlan -SafeName "OCA-P-WIN-LA-T0-TEST1"
Assert-Equal (@($plan | ForEach-Object { $_.MemberName }) -join "|") "Privilege Cloud Administrators|Global-CyberArk-BGAccount|Global-Sec-OCA-P-WIN-LA-T0-TEST1-SafeManagers|Global-SEC-OCA-P-WIN-LA-T0-TEST1-Users" "member plan: defaults then derived groups"
$bad = Read-JsonFile -Path (Join-Path $Root "config\safe-members.json")
$bad.defaultMembers[0].permissionSet = "Nope"
Assert-True (@(Test-PermissionSets -Members $bad).Count -gt 0) "unknown permissionSet is reported"

# extra member + disabled member
$Global:Onb.Members.additionalMembers = @([pscustomobject]@{ memberName = "Extra-Group"; memberType = "Group"; searchIn = "Vault"; permissionSet = "SafeUser"; enabled = $true })
$Global:Onb.Members.defaultMembers[1].enabled = $false
$plan = Get-SafeMemberPlan -SafeName "S1"
Assert-True ($plan.MemberName -contains "Extra-Group") "additionalMembers entry is picked up"
Assert-True ($plan.MemberName -notcontains "Global-CyberArk-BGAccount") "enabled=false entry is skipped"
$Global:Onb.Members = Read-JsonFile -Path (Join-Path $Root "config\safe-members.json")

Write-Host "`nManaging CPM lookup" -ForegroundColor White
$m = $Global:Onb.Config.safeDefaults.managingCpm
Assert-Equal (Resolve-ManagingCpm -Region OCA -Tier T1 -Override "") "" "blank by default"
Assert-Equal @(Get-ManagingCpmCandidates -Region OCA -Tier T1 -Override "").Count 0 "no candidates when nothing is configured"
$m.byRegion.OCA = "CPM_OCA"; $m.byTier.T1 = "CPM_T1"; $m.byRegionTier.'OCA-T1' = "CPM_OCA_T1"; $m.default = "CPM_DEFAULT"
Assert-Equal (Resolve-ManagingCpm -Region OCA -Tier T1 -Override "") "CPM_OCA_T1" "tier present: region+tier wins over region"
Assert-Equal ((@(Get-ManagingCpmCandidates -Region OCA -Tier T1 -Override "CSV_CPM")) -join ",") "CSV_CPM,CPM_OCA_T1,CPM_T1,CPM_OCA,CPM_DEFAULT" "full precedence order: CSV, region+tier, tier, region, default"
$m.byRegionTier.'OCA-T1' = ""
Assert-Equal (Resolve-ManagingCpm -Region OCA -Tier T1 -Override "") "CPM_T1" "tier-only entry beats region when region+tier is blank"
Assert-Equal (Resolve-ManagingCpm -Region OCA -Tier T2 -Override "") "CPM_OCA" "tier without a tier entry falls back to region"
Assert-Equal (Resolve-ManagingCpm -Region OCA -Tier "" -Override "") "CPM_OCA" "no tier: region used"
Assert-Equal (Resolve-ManagingCpm -Region APAC -Tier "" -Override "") "CPM_DEFAULT" "no region entry: default used"
$m.byRegion.OCA = ""; $m.byTier.T1 = ""; $m.default = ""

Write-Host "`nDescriptions" -ForegroundColor White
Assert-Equal (Get-CreatedByDescription -Text "Server admin") "Server admin | Created by jdoe through script" "admin text + suffix"
Assert-Equal (Get-CreatedByDescription -Text "") "Created by jdoe through script" "empty text -> suffix only"
$long = "x" * 200
$d = Get-CreatedByDescription -Text $long -MaxLength 100
Assert-Equal $d.Length 100 "trimmed to max length"
Assert-True ($d.EndsWith(" | Created by jdoe through script")) "suffix survives trimming"

Write-Host "`nRedaction" -ForegroundColor White
Assert-True ((Protect-LogText "PUT https://a/b?sv=1&sig=AbC%2Fdef&x=1") -notmatch "AbC") "SAS signature redacted"
Assert-True ((Protect-LogText "Authorization: Bearer abc.def-ghi") -notmatch "abc\.def") "bearer token redacted"
Assert-True ((Get-RedactedBody @{ userName = "u"; secret = "P@ss" }) -notmatch "P@ss") "account secret redacted from body"

Write-Host "`nConfig merge" -ForegroundColor White
$base = '{"a":{"b":1,"c":2},"d":[1,2]}' | ConvertFrom-Json
$over = '{"a":{"c":9},"d":[3],"e":true}' | ConvertFrom-Json
$r = Merge-ConfigObject -Base $base -Override $over
Assert-Equal $r.a.b 1 "untouched nested value kept"
Assert-Equal $r.a.c 9 "nested value overridden"
Assert-Equal (@($r.d) -join ",") "3" "arrays replaced"
Assert-Equal $r.e $true "new key added"
Assert-True (Test-IsPlaceholder "XXXXXX") "XXXXXX is a placeholder"
Assert-True (-not (Test-IsPlaceholder "mystorage")) "real value is not a placeholder"

Write-Host "`nPlatform response shapes" -ForegroundColor White
$i = ConvertTo-PlatformInfo ('{"Id":12,"general":{"id":"WinDomain","name":"Windows Domain","active":false}}' | ConvertFrom-Json)
Assert-Equal "$($i.NumericId)|$($i.PlatformId)|$($i.Active)" "12|WinDomain|False" "shape A: Id + general.*"
$i = ConvertTo-PlatformInfo ('{"ID":7,"PlatformID":"UnixSSH","Name":"Unix via SSH","Active":true}' | ConvertFrom-Json)
Assert-Equal "$($i.NumericId)|$($i.PlatformId)|$($i.Active)" "7|UnixSSH|True" "shape B: ID + PlatformID"

Write-Host "`nDuplicate-response parsing (no API call needed when both IDs are present)" -ForegroundColor White
$r = Resolve-NewPlatform -DuplicateResponse ('{"ID":66,"PlatformID":"testPlatform","Name":"test Platform","Description":""}' | ConvertFrom-Json) -NewName "test Platform"
Assert-Equal "$($r.NumericId)|$($r.PlatformId)" "66|testPlatform" "documented shape: ID numeric, PlatformID string"

Write-Host "`nCSV validation per mode" -ForegroundColor White
$full = @([pscustomobject]@{
    Region = "OCA"; Environment = "P"; Technology = "WIN"; AccessType = "LA"; Tier = "T0"; Team = "TEST1"
    Flavour = "WIN"; AppTower = "AD"; PlatformAccountType = "LA"; RotationPolicy = "RA"; SourcePlatformID = "SRC"
    AccountUserName = "svc"; Address = "host"; Description = "d"; Prop_LogonDomain = "corp" })
$pl = New-OnboardingPlan -Mode Full -Rows $full
Assert-Equal $pl.Errors.Count 0 "Full: valid row accepted"
Assert-Equal $pl.Items[0].SafeName "OCA-P-WIN-LA-T0-TEST1" "Full: safe name built"
Assert-Equal $pl.Items[0].PlatformName "OCA-WIN-AD-LA-RA" "Full: platform name built"
Assert-Equal $pl.Items[0].Properties.LogonDomain "corp" "Full: Prop_* columns become platform account properties"
$pl = New-OnboardingPlan -Mode SafeOnly -Rows $full
Assert-Equal $pl.Errors.Count 0 "SafeOnly: accepts a Full CSV (extra columns ignored)"
$pl = New-OnboardingPlan -Mode AccountOnly -Rows $full
Assert-True ($pl.Errors.Count -gt 0 -and $pl.Errors[0] -match "missing required column") "AccountOnly: missing SafeName/PlatformID columns reported"
$two = @($full[0], ($full[0].PSObject.Copy()))
$two[1].SourcePlatformID = "OTHER"
$pl = New-OnboardingPlan -Mode Full -Rows $two
Assert-True (($pl.Errors -join " ") -match "different SourcePlatformID") "same target platform from two sources is an error"

Write-Host "`nTest data files (templates\testdata)" -ForegroundColor White
# file -> mode, expected errors, expected safes, platforms, items (errors=0 means the file must validate cleanly)
$cases = @(
    @("SafeOnly_Valid", "SafeOnly", 0, 8, 0, 9), @("SafeOnly_CpmOverride", "SafeOnly", 0, 1, 0, 1), @("SafeOnly_Invalid", "SafeOnly", 8, 0, 0, 0),
    @("PlatformOnly_Valid", "PlatformOnly", 0, 0, 6, 7), @("PlatformOnly_SourceMissing", "PlatformOnly", 0, 0, 2, 2),
    @("PlatformOnly_Invalid", "PlatformOnly", 8, 0, 0, 0), @("PlatformOnly_Conflict", "PlatformOnly", 1, 0, 1, 2),
    @("Full_Valid", "Full", 0, 5, 6, 7), @("Full_SourceMissing", "Full", 0, 2, 2, 2), @("Full_Invalid", "Full", 18, 0, 0, 0), @("Full_PlatformConflict", "Full", 1, 1, 1, 2),
    @("AccountOnly_Valid", "AccountOnly", 0, 1, 0, 3), @("AccountOnly_Runtime", "AccountOnly", 0, 2, 0, 4), @("AccountOnly_Invalid", "AccountOnly", 5, 0, 0, 0)
)
foreach ($c in $cases) {
    $file = Join-Path $Root "templates\testdata\$($c[0]).csv"
    $pl = New-OnboardingPlan -Mode $c[1] -Rows @(Import-Csv -LiteralPath $file)
    $safes = if ($pl.Safes) { $pl.Safes.Count } else { 0 }
    $plats = if ($pl.Platforms) { $pl.Platforms.Count } else { 0 }
    Assert-Equal "$($pl.Errors.Count)/$safes/$plats/$($pl.Items.Count)" ("{0}/{1}/{2}/{3}" -f $c[2], $c[3], $c[4], $c[5]) "$($c[0]): errors/safes/platforms/items"
}
$pl = New-OnboardingPlan -Mode Full -Rows @(Import-Csv -LiteralPath (Join-Path $Root "templates\testdata\Full_Valid.csv"))
Assert-Equal (($pl.Safes.Keys | Sort-Object) -join ",") "APAC-D-LIN-LSA-T1-ONBFULL,EMEA-T-DB-DSA-ONBFULL,GLB-P-WIN-DA-T2-ONBFULL,JP-Q-SQL-ENA-T0-ONBFULL,OCA-P-WIN-LA-T0-ONBFULL" "Full_Valid: exact safe names (documented in TEST-PLAN.md)"
Assert-Equal (($pl.Platforms.Keys | Sort-Object) -join ",") "APAC-UNX-UX-LS-RA-ONBFULL,EMEA-DB-ORA-DS-RS-W-ONBFULL,GLB-WIN-AD-DA-RA-T-ONBFULL,JP-WIN-PA-SA-RM-D-ONBFULL,OCA-WIN-AD-LA-RA-ONBFULL,OCA-WIN-SD-LA-RM-ONBFULL" "Full_Valid: exact platform names"
Assert-True ($pl.Items[3].AutoManage -eq $false -and $pl.Items[3].AccountName -eq "ONB-Custom-Name-Unix01") "Full_Valid: manual-management row keeps custom account name"
Assert-Equal $pl.Items[5].Properties.LogonDomain "CORP" "Full_Valid: Prop_LogonDomain carried through"

Write-Host ""
Write-Host ("Passed: {0}  Failed: {1}" -f $script:Passed, $script:Failed) -ForegroundColor $(if ($script:Failed) { "Red" } else { "Green" })
exit $script:Failed
