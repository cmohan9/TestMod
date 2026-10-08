#=========================================================================
# Objects.ps1 - CyberArk Privilege Cloud object operations
# (Platforms / Safes / Safe members / Accounts / Verify / Reconcile).
#
# Endpoint shapes marked (verify) follow the published Privilege Cloud
# REST API but were written without access to a live tenant. Run
#   .\Start-Onboarding.ps1 -Mode Diagnose
# once against your tenant to confirm the response shapes.
#=========================================================================

function Get-FirstProperty {
    param($Object, [string[]]$Paths)
    foreach ($path in $Paths) {
        $cur = $Object
        foreach ($seg in ($path -split "\.")) {
            if ($null -eq $cur) { break }
            $prop = $cur.PSObject.Properties[$seg]
            $cur = if ($prop) { $prop.Value } else { $null }
        }
        if ($null -ne $cur -and "$cur" -ne "") { return $cur }
    }
    return $null
}

#region Platforms
# Normalises the several response shapes Platforms endpoints use (verify).
function ConvertTo-PlatformInfo {
    param($Raw)
    if ($null -eq $Raw) { return $null }
    $numeric = $null
    foreach ($candidate in @((Get-FirstProperty $Raw @("Id", "ID", "PlatformNumericId")), (Get-FirstProperty $Raw @("general.id")))) {
        $n = 0
        if ($null -ne $candidate -and [int]::TryParse("$candidate", [ref]$n)) { $numeric = $n; break }
    }
    $stringId = Get-FirstProperty $Raw @("general.id", "PlatformID", "PlatformId", "platformId")
    if ($null -ne $stringId -and "$stringId" -match "^\d+$" -and $null -ne $numeric -and [int]$stringId -eq $numeric) {
        # the only "id" we saw was numeric - the string PlatformID is unknown
        $stringId = Get-FirstProperty $Raw @("PlatformID", "PlatformId", "platformId")
    }
    $active = Get-FirstProperty $Raw @("general.active", "Active", "active")
    return [pscustomobject]@{
        NumericId  = $numeric
        PlatformId = if ($null -ne $stringId) { [string]$stringId } else { $null }
        Name       = [string](Get-FirstProperty $Raw @("general.name", "Name", "name"))
        Active     = if ($null -eq $active) { $true } else { [bool]$active }
        Raw        = $Raw
    }
}

# Looks a target platform up by PlatformID or display name.
# Returns @{ Ok; Info } - Ok=$false means the lookup itself failed (NOT the same as "absent").
function Find-TargetPlatform {
    param([Parameter(Mandatory)][string]$Name)
    $r = Invoke-CyberArkApi -Method GET -Path "Platforms/Targets?search=$([uri]::EscapeDataString($Name))" -ExpectedStatus 404
    if (-not $r.Success) {
        if ($r.NotFound) { return @{ Ok = $true; Info = $null } }
        return @{ Ok = $false; Info = $null; Error = $r.Error }
    }
    $list = @()
    if ($r.Data -and $r.Data.PSObject.Properties["Platforms"]) { $list = @($r.Data.Platforms) }
    foreach ($raw in $list) {
        $info = ConvertTo-PlatformInfo $raw
        if ($info.PlatformId -eq $Name -or $info.Name -eq $Name) { return @{ Ok = $true; Info = $info } }
    }
    return @{ Ok = $true; Info = $null }
}

# Duplicates a target platform: POST Platforms/Targets/{numericId}/Duplicate/ with {Name, Description}.
# Documented response: { ID (numeric), PlatformID (string), Name, Description }.
function Copy-TargetPlatform {
    param([Parameter(Mandatory)][int]$SourceNumericId, [Parameter(Mandatory)][string]$NewName, [string]$Description)
    $body = @{ Name = $NewName; Description = $Description }
    return Invoke-CyberArkApi -Method POST -Path "Platforms/Targets/$SourceNumericId/Duplicate/" -Body $body
}

# Duplicated platforms are created INACTIVE and must be activated before accounts can use them.
function Enable-TargetPlatform {
    param([Parameter(Mandatory)][int]$NumericId)
    return Invoke-CyberArkApi -Method POST -Path "Platforms/Targets/$NumericId/activate/"
}

# Works out the numeric ID and the string PlatformID that Accounts use. The documented Duplicate
# response carries both (ID = numeric, PlatformID = string); older/other shapes may carry only one,
# in which case the platform is re-queried by name. Members it could not confirm are $null.
function Resolve-NewPlatform {
    param($DuplicateResponse, [Parameter(Mandatory)][string]$NewName)
    $numeric = $null; $stringId = $null
    $n = 0
    $idVal = Get-FirstProperty $DuplicateResponse @("ID", "Id", "id")
    if ($null -ne $idVal -and [int]::TryParse("$idVal", [ref]$n)) { $numeric = $n }
    $pidVal = Get-FirstProperty $DuplicateResponse @("PlatformID", "platformId")
    if ($null -ne $pidVal) {
        if ("$pidVal" -match "^\d+$") { if ($null -eq $numeric) { $numeric = [int]"$pidVal" } }
        else { $stringId = [string]$pidVal }
    }
    if ($null -ne $numeric -and $stringId) {
        return [pscustomobject]@{ NumericId = $numeric; PlatformId = $stringId; Active = $false }
    }

    $info = $null
    for ($i = 1; $i -le 3 -and -not $info; $i++) {
        $lookup = Find-TargetPlatform -Name $NewName
        if ($lookup.Ok -and $lookup.Info) { $info = $lookup.Info } else { Start-Sleep -Seconds 2 }
    }
    if ($info) {
        if ($null -eq $numeric) { $numeric = $info.NumericId }
        if (-not $stringId) { $stringId = $info.PlatformId }
        return [pscustomobject]@{ NumericId = $numeric; PlatformId = $stringId; Active = $info.Active }
    }
    return [pscustomobject]@{ NumericId = $numeric; PlatformId = $stringId; Active = $false }
}
#endregion

#region Safes
# Returns @{ Ok; Exists } - Ok=$false means the check failed (permission/network), not "absent".
function Test-SafeExists {
    param([Parameter(Mandatory)][string]$SafeName)
    $r = Invoke-CyberArkApi -Method GET -Path "Safes/$([uri]::EscapeDataString($SafeName))" -ExpectedStatus 404
    if ($r.Success)  { return @{ Ok = $true; Exists = $true } }
    if ($r.NotFound) { return @{ Ok = $true; Exists = $false } }
    return @{ Ok = $false; Exists = $false; Error = $r.Error }
}

# Ordered, de-duplicated, non-blank CPM candidates - most specific first:
#   CSV ManagingCPM column -> byRegionTier[REGION-TIER] -> byTier[TIER] -> byRegion[REGION] -> default
# When a Tier is present, the tier-based entries therefore win over the plain region entry.
function Get-ManagingCpmCandidates {
    param([string]$Region, [string]$Tier, [string]$Override)
    $m = $Global:Onb.Config.safeDefaults.managingCpm
    $list = New-Object System.Collections.ArrayList
    $add = { param($v) if ($v -and -not $list.Contains([string]$v)) { [void]$list.Add(([string]$v).Trim()) } }
    if ($Override) { & $add $Override }
    if ($Region -and $Tier -and $m.byRegionTier) {
        $p = $m.byRegionTier.PSObject.Properties["$($Region.ToUpper())-$($Tier.ToUpper())"]
        if ($p) { & $add $p.Value }
    }
    if ($Tier -and $m.byTier) {
        $p = $m.byTier.PSObject.Properties[$Tier.ToUpper()]
        if ($p) { & $add $p.Value }
    }
    if ($Region -and $m.byRegion) {
        $p = $m.byRegion.PSObject.Properties[$Region.ToUpper()]
        if ($p) { & $add $p.Value }
    }
    if ($m.default) { & $add $m.default }
    return $list.ToArray()
}

# First (preferred) candidate, or "" when none is configured.
function Resolve-ManagingCpm {
    param([string]$Region, [string]$Tier, [string]$Override)
    $c = @(Get-ManagingCpmCandidates -Region $Region -Tier $Tier -Override $Override)
    if ($c.Count -gt 0) { return [string]$c[0] }
    return ""
}

function New-CASafe {
    param([Parameter(Mandatory)][string]$SafeName, [string]$Description, [string]$ManagingCpm, [switch]$ExpectRejection)
    $d = $Global:Onb.Config.safeDefaults
    $body = @{ safeName = $SafeName; description = $Description; olacEnabled = [bool]$d.olacEnabled }
    if ($d.retentionMode -eq "days") { $body.numberOfDaysRetention = [int]$d.numberOfDaysRetention }
    else { $body.numberOfVersionsRetention = [int]$d.numberOfVersionsRetention }
    if ($ManagingCpm) { $body.managingCPM = $ManagingCpm }
    if ($ExpectRejection) { return Invoke-CyberArkApi -Method POST -Path "Safes" -Body $body -ExpectedStatus 400 }
    return Invoke-CyberArkApi -Method POST -Path "Safes" -Body $body
}

function New-MemberPlanEntry {
    param($Entry, [string]$Name, [string]$Source)
    return [pscustomobject]@{
        MemberName    = $Name
        MemberType    = $(if ($Entry.memberType) { [string]$Entry.memberType } else { "Group" })
        SearchIn      = $(if ($Entry.searchIn) { [string]$Entry.searchIn } else { "Vault" })
        PermissionSet = [string]$Entry.permissionSet
        Permissions   = $Global:Onb.Members.permissionSets.([string]$Entry.permissionSet)
        Source        = $Source
    }
}

# Everything that must be a member of a safe: default + additional (enabled) + derived per-safe groups.
function Get-SafeMemberPlan {
    param([Parameter(Mandatory)][string]$SafeName)
    $cfg = $Global:Onb.Members
    $plan = New-Object System.Collections.ArrayList
    foreach ($e in @($cfg.defaultMembers)) {
        if ($e -and ($null -eq $e.enabled -or $e.enabled)) { [void]$plan.Add((New-MemberPlanEntry $e $e.memberName "Default")) }
    }
    foreach ($e in @($cfg.additionalMembers)) {
        if ($e -and ($null -eq $e.enabled -or $e.enabled)) { [void]$plan.Add((New-MemberPlanEntry $e $e.memberName "Additional")) }
    }
    foreach ($e in @($cfg.derivedMembers)) {
        if ($e -and ($null -eq $e.enabled -or $e.enabled)) { [void]$plan.Add((New-MemberPlanEntry $e $e.nameTemplate.Replace("{SafeName}", $SafeName) "Derived")) }
    }
    return ,@($plan.ToArray())
}

# Adds one member. Outcome: Added | Exists (409) | Missing (404 - group not defined) | Failed.
function Add-CASafeMember {
    param([Parameter(Mandatory)][string]$SafeName, [Parameter(Mandatory)]$Member)
    $body = @{ memberName = $Member.MemberName; searchIn = $Member.SearchIn; memberType = $Member.MemberType; permissions = $Member.Permissions }
    $r = Invoke-CyberArkApi -Method POST -Path "Safes/$([uri]::EscapeDataString($SafeName))/Members" -Body $body -ExpectedStatus 404, 409
    $outcome = if ($r.Success) { "Added" } elseif ($r.StatusCode -eq 409) { "Exists" } elseif ($r.StatusCode -eq 404) { "Missing" } else { "Failed" }
    return [pscustomobject]@{ Outcome = $outcome; Member = $Member.MemberName; Error = $r.Error }
}
#endregion

#region Accounts
function Find-CAAccount {
    param([Parameter(Mandatory)][string]$SafeName, [Parameter(Mandatory)][string]$UserName, [Parameter(Mandatory)][string]$Address)
    $q = "Accounts?search=$([uri]::EscapeDataString("$UserName $Address"))&filter=$([uri]::EscapeDataString("safeName eq $SafeName"))"
    $r = Invoke-CyberArkApi -Method GET -Path $q -ExpectedStatus 404
    if (-not $r.Success) {
        if ($r.NotFound) { return @{ Ok = $true; Account = $null } }
        return @{ Ok = $false; Account = $null; Error = $r.Error }
    }
    $hit = @($r.Data.value) | Where-Object { $_ -and $_.userName -eq $UserName -and $_.address -eq $Address } | Select-Object -First 1
    return @{ Ok = $true; Account = $hit }
}

function Get-AccountName {
    param([string]$PlatformId, [string]$Address, [string]$UserName)
    $t = [string]$Global:Onb.Config.accountDefaults.nameTemplate
    if (-not $t) { return $null }
    return $t.Replace("{PlatformId}", $PlatformId).Replace("{Address}", $Address).Replace("{UserName}", $UserName)
}

function New-CAAccount {
    param(
        [Parameter(Mandatory)][string]$SafeName, [Parameter(Mandatory)][string]$PlatformId,
        [Parameter(Mandatory)][string]$UserName, [Parameter(Mandatory)][string]$Address,
        [string]$Name, [string]$SecretType = "password", [string]$Secret,
        [hashtable]$Properties = @{}, [bool]$AutoManage = $true, [string]$ManualReason, [string]$Description
    )
    $body = @{ safeName = $SafeName; platformId = $PlatformId; userName = $UserName; address = $Address; secretType = $SecretType }
    if ($Name)   { $body.name = $Name }
    if ($Secret) { $body.secret = $Secret }
    $props = @{}
    foreach ($k in $Properties.Keys) { $props[$k] = $Properties[$k] }
    $descProp = [string]$Global:Onb.Config.descriptions.accountPropertyName
    if ($Description -and $descProp) { $props[$descProp] = $Description }
    if ($props.Count -gt 0) { $body.platformAccountProperties = $props }
    if ($AutoManage) { $body.secretManagement = @{ automaticManagementEnabled = $true } }
    else { $body.secretManagement = @{ automaticManagementEnabled = $false; manualManagementReason = $(if ($ManualReason) { $ManualReason } else { "Onboarded as manually managed" }) } }

    $r = Invoke-CyberArkApi -Method POST -Path "Accounts" -Body $body
    # The platform may not define the description property; retry once without it rather than lose the account.
    if (-not $r.Success -and $r.StatusCode -eq 400 -and $Description -and $descProp -and $r.ErrorBody -match [regex]::Escape($descProp)) {
        Write-Log "Platform '$PlatformId' rejected property '$descProp' - retrying without the account description." WARN
        $props.Remove($descProp)
        if ($props.Count -gt 0) { $body.platformAccountProperties = $props } else { $body.Remove("platformAccountProperties") }
        $r = Invoke-CyberArkApi -Method POST -Path "Accounts" -Body $body
    }
    return $r
}

function Invoke-AccountTask {
    param([Parameter(Mandatory)][string]$AccountId, [Parameter(Mandatory)][ValidateSet("Verify", "Reconcile")][string]$Task)
    return Invoke-CyberArkApi -Method POST -Path "Accounts/$AccountId/$Task" -Body @{}
}

function Get-AccountTaskMarker {
    param([string]$AccountId, [string]$Task)
    $field = if ($Task -eq "Verify") { "lastVerifiedTime" } else { "lastReconciledTime" }
    $a = Invoke-CyberArkApi -Method GET -Path "Accounts/$AccountId"
    if (-not $a.Success -or -not $a.Data) { return $null }
    $sm = $a.Data.secretManagement
    return [pscustomobject]@{ Time = $(if ($sm) { $sm.$field } else { $null }); Status = $(if ($sm) { [string]$sm.status } else { "" }) }
}

# Verify/Reconcile only queue CPM work - poll until the timestamp moves past its pre-call value.
function Wait-AccountTask {
    param([Parameter(Mandatory)][string]$AccountId, [Parameter(Mandatory)][ValidateSet("Verify", "Reconcile")][string]$Task, $Before)
    $t = $Global:Onb.Config.tasks
    $deadline = (Get-Date).AddSeconds([int]$t.timeoutSeconds)
    $beforeTime = if ($Before) { $Before.Time } else { $null }
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds ([int]$t.pollIntervalSeconds)
        $now = Get-AccountTaskMarker -AccountId $AccountId -Task $Task
        if (-not $now) { continue }
        if ($now.Time -and (-not $beforeTime -or [double]$now.Time -gt [double]$beforeTime)) { return @{ Success = $true; Status = $now.Status } }
        if ($now.Status -eq "failure") { return @{ Success = $false; Status = "failure" } }
    }
    return @{ Success = $false; Status = "Timeout" }
}
#endregion
