#=========================================================================
# Naming.ps1 - Safe / Platform naming-convention builders + validators
# (code tables come from config\naming.json) and description helper.
#=========================================================================

function Build-SafeName {
    param(
        [Parameter(Mandatory)][string]$Region, [Parameter(Mandatory)][string]$Environment,
        [Parameter(Mandatory)][string]$Technology, [Parameter(Mandatory)][string]$AccessType,
        [string]$Tier, [Parameter(Mandatory)][string]$Team
    )
    $parts = @($Region.Trim().ToUpper(), $Environment.Trim().ToUpper(), $Technology.Trim().ToUpper(), $AccessType.Trim().ToUpper())
    if (-not [string]::IsNullOrWhiteSpace($Tier)) { $parts += $Tier.Trim().ToUpper() }
    $parts += $Team.Trim().ToUpper()
    return ($parts -join "-")
}

function Test-SafeNameInputs {
    param([string]$Region, [string]$Environment, [string]$Technology, [string]$AccessType, [string]$Tier, [string]$Team)
    $n = $Global:Onb.Naming.safe
    $errors = @()
    if ($Region -notin $n.regions)           { $errors += "Region '$Region' not in ($($n.regions -join ', '))" }
    if ($Environment -notin $n.environments) { $errors += "Environment '$Environment' not in ($($n.environments -join ', '))" }
    if ($Technology -notin $n.technologies)  { $errors += "Technology '$Technology' not in ($($n.technologies -join ', '))" }
    if ($AccessType -notin $n.accessTypes)   { $errors += "AccessType '$AccessType' not in ($($n.accessTypes -join ', '))" }
    if ($Tier -and $Tier -notin $n.tiers)    { $errors += "Tier '$Tier' not in ($($n.tiers -join ', '))" }
    if ([string]::IsNullOrWhiteSpace($Team)) { $errors += "Team is required" }
    elseif ($Team -notmatch "^[A-Za-z0-9_]+$") { $errors += "Team '$Team' may only contain letters, digits and underscore" }

    $built = $null
    if ($errors.Count -eq 0) {
        $built = Build-SafeName -Region $Region -Environment $Environment -Technology $Technology -AccessType $AccessType -Tier $Tier -Team $Team
        if ($built.Length -gt [int]$n.maxLength) { $errors += "Built safe name '$built' is $($built.Length) chars, exceeds max $($n.maxLength)" }
    }
    return [pscustomobject]@{ IsValid = ($errors.Count -eq 0); Errors = $errors; SuggestedName = $built }
}

function Build-PlatformName {
    param(
        [Parameter(Mandatory)][string]$Region, [Parameter(Mandatory)][string]$Flavour,
        [Parameter(Mandatory)][string]$AppTower, [Parameter(Mandatory)][string]$AccountType,
        [Parameter(Mandatory)][string]$RotationPolicy, [string]$Vendor, [string]$Exception
    )
    $parts = @($Region.Trim().ToUpper(), $Flavour.Trim().ToUpper(), $AppTower.Trim().ToUpper(), $AccountType.Trim().ToUpper(), $RotationPolicy.Trim().ToUpper())
    if (-not [string]::IsNullOrWhiteSpace($Vendor))    { $parts += $Vendor.Trim().ToUpper() }
    if (-not [string]::IsNullOrWhiteSpace($Exception)) { $parts += $Exception.Trim().ToUpper() }
    return ($parts -join "-")
}

function Test-PlatformNameInputs {
    param([string]$Region, [string]$Flavour, [string]$AppTower, [string]$AccountType, [string]$RotationPolicy, [string]$Vendor, [string]$Exception)
    $n = $Global:Onb.Naming.platform
    $errors = @()
    if ($Region -notin $n.regions)                 { $errors += "Region '$Region' not in ($($n.regions -join ', '))" }
    if ($Flavour -notin $n.flavours)               { $errors += "Flavour '$Flavour' not in ($($n.flavours -join ', '))" }
    if ($AppTower -notin $n.appTowers)             { $errors += "AppTower '$AppTower' not in ($($n.appTowers -join ', '))" }
    if ($AccountType -notin $n.accountTypes)       { $errors += "PlatformAccountType '$AccountType' not in ($($n.accountTypes -join ', '))" }
    if ($RotationPolicy -notin $n.rotationPolicies) { $errors += "RotationPolicy '$RotationPolicy' not in ($($n.rotationPolicies -join ', '))" }
    if ($Vendor -and $Vendor -notin $n.vendors)    { $errors += "Vendor '$Vendor' not in ($($n.vendors -join ', '))" }
    if ($Exception -and $Exception -notmatch "^[A-Za-z0-9_]+$") { $errors += "Exception '$Exception' may only contain letters, digits and underscore" }

    $built = $null
    if ($errors.Count -eq 0) {
        $built = Build-PlatformName -Region $Region -Flavour $Flavour -AppTower $AppTower -AccountType $AccountType -RotationPolicy $RotationPolicy -Vendor $Vendor -Exception $Exception
    }
    return [pscustomobject]@{ IsValid = ($errors.Count -eq 0); Errors = $errors; SuggestedName = $built }
}

#region Descriptions: "<admin text> | Created by <userId> through script"
function Get-CreatedByDescription {
    param([string]$Text, [int]$MaxLength = 0)
    $cfg    = $Global:Onb.Config.descriptions
    $userId = if ($Global:Onb.Operator) { $Global:Onb.Operator.UserId } else { [Environment]::UserName }
    $suffix = ([string]$cfg.suffixTemplate).Replace("{UserId}", $userId)
    $sep    = [string]$cfg.separator
    $admin  = if ($Text) { $Text.Trim() } else { "" }

    if ([string]::IsNullOrEmpty($admin)) {
        $full = $suffix
    } else {
        $full = "$admin$sep$suffix"
    }
    if ($MaxLength -gt 0 -and $full.Length -gt $MaxLength) {
        $room = $MaxLength - $sep.Length - $suffix.Length
        if (-not [string]::IsNullOrEmpty($admin) -and $room -gt 0) {
            $full = $admin.Substring(0, $room).TrimEnd() + $sep + $suffix
            Write-Log "Description trimmed to $MaxLength characters (admin text shortened, 'created by' suffix kept)." WARN
        } else {
            $full = $suffix.Substring(0, [Math]::Min($suffix.Length, $MaxLength))
            Write-Log "Description limit ($MaxLength) too small for the 'created by' suffix - admin text dropped." WARN
        }
    }
    return $full
}
#endregion
