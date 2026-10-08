#=========================================================================
# Config.ps1 - shared run state + configuration loading/validation.
# All run state lives in one global hashtable ($Global:Onb) so every lib
# file (and the tests) see the same values.
#=========================================================================

$RequiredPermissionKeys = @(
    "useAccounts", "retrieveAccounts", "listAccounts", "addAccounts", "updateAccountContent",
    "updateAccountProperties", "initiateCPMAccountManagementOperations", "specifyNextAccountContent",
    "renameAccounts", "deleteAccounts", "unlockAccounts", "manageSafe", "manageSafeMembers",
    "backupSafe", "viewAuditLog", "viewSafeMembers", "accessWithoutConfirmation",
    "createFolders", "deleteFolders", "moveAccountsAndFolders",
    "requestsAuthorizationLevel1", "requestsAuthorizationLevel2"
)

function New-OnboardingState {
    param([string]$Root)
    $Global:Onb = @{
        Root          = $Root
        Config        = $null
        Naming        = $null
        Members       = $null
        RunId         = [guid]::NewGuid().ToString()
        LogFile       = $null
        ResultsFile   = $null
        Operator      = $null
        Mode          = $null
        DryRun        = $false
        IdentityUrl   = $null
        PvwaBase      = $null
        ServiceUserId = $null
        ServiceSecret = $null
        Token         = $null
        TokenExpiry   = [datetime]::MinValue
        Results       = (New-Object System.Collections.ArrayList)
        Alerts        = (New-Object System.Collections.ArrayList)
        Finalized     = $false
    }
}

function Test-IsWindows {
    if ($PSVersionTable.PSEdition -eq "Desktop") { return $true }
    $v = Get-Variable -Name IsWindows -ErrorAction SilentlyContinue
    return [bool]($v -and $v.Value)
}

function Test-IsPlaceholder {
    param([string]$Value)
    return ([string]::IsNullOrWhiteSpace($Value) -or $Value -match "^[Xx]+$")
}

function Read-JsonFile {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "Config file not found: $Path" }
    try {
        return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json)
    } catch {
        throw "Config file '$Path' is not valid JSON: $($_.Exception.Message)"
    }
}

# Recursively overlays $Override on $Base (PSCustomObjects). Arrays and scalars are replaced.
function Merge-ConfigObject {
    param($Base, $Override)
    if ($null -eq $Override) { return $Base }
    foreach ($prop in $Override.PSObject.Properties) {
        $existing = $Base.PSObject.Properties[$prop.Name]
        if ($existing -and ($existing.Value -is [System.Management.Automation.PSCustomObject]) -and ($prop.Value -is [System.Management.Automation.PSCustomObject])) {
            Merge-ConfigObject -Base $existing.Value -Override $prop.Value | Out-Null
        } elseif ($existing) {
            $Base.($prop.Name) = $prop.Value
        } else {
            $Base | Add-Member -NotePropertyName $prop.Name -NotePropertyValue $prop.Value
        }
    }
    return $Base
}

function Test-PermissionSets {
    param($Members)
    $problems = @()
    foreach ($set in $Members.permissionSets.PSObject.Properties) {
        $keys = @($set.Value.PSObject.Properties.Name)
        $missing = $RequiredPermissionKeys | Where-Object { $_ -notin $keys }
        $unknown = $keys | Where-Object { $_ -notin $RequiredPermissionKeys }
        if ($missing) { $problems += "permission set '$($set.Name)' is missing: $($missing -join ', ')" }
        if ($unknown) { $problems += "permission set '$($set.Name)' has unknown key(s): $($unknown -join ', ')" }
    }
    $allMembers = @($Members.defaultMembers) + @($Members.additionalMembers)
    foreach ($m in $allMembers) {
        if (-not $m) { continue }
        if (-not $m.memberName) { $problems += "a member entry has no memberName" }
        if (-not $Members.permissionSets.PSObject.Properties[[string]$m.permissionSet]) {
            $problems += "member '$($m.memberName)' references unknown permissionSet '$($m.permissionSet)'"
        }
    }
    foreach ($d in @($Members.derivedMembers)) {
        if (-not $d) { continue }
        if (-not $Members.permissionSets.PSObject.Properties[[string]$d.permissionSet]) {
            $problems += "derived member '$($d.nameTemplate)' references unknown permissionSet '$($d.permissionSet)'"
        }
    }
    return $problems
}

function Import-OnboardingConfig {
    param([string]$ConfigPath)
    if (-not $ConfigPath) { $ConfigPath = Join-Path $Global:Onb.Root "config\onboarding.config.json" }
    $configDir = Split-Path -Parent $ConfigPath

    $cfg = Read-JsonFile -Path $ConfigPath
    $localPath = [System.IO.Path]::ChangeExtension($ConfigPath, ".local.json")
    if (Test-Path -LiteralPath $localPath) {
        $cfg = Merge-ConfigObject -Base $cfg -Override (Read-JsonFile -Path $localPath)
        $Global:Onb.LocalConfigLoaded = $localPath
    }
    $Global:Onb.Config = $cfg
    $Global:Onb.ConfigPath = $ConfigPath

    $Global:Onb.Naming  = Read-JsonFile -Path (Join-Path $configDir "naming.json")
    $Global:Onb.Members = Read-JsonFile -Path (Join-Path $configDir "safe-members.json")

    $problems = Test-PermissionSets -Members $Global:Onb.Members
    if ($problems.Count -gt 0) { throw "safe-members.json is invalid: $($problems -join '; ')" }

    $Global:Onb.IdentityUrl = if ($cfg.cyberark.identityUrl) { $cfg.cyberark.identityUrl.TrimEnd("/") } else { "https://$($cfg.cyberark.identityTenantId).id.cyberark.cloud" }
    $Global:Onb.PvwaBase    = if ($cfg.cyberark.apiBaseUrl)  { $cfg.cyberark.apiBaseUrl.TrimEnd("/") }  else { "https://$($cfg.cyberark.subdomain).privilegecloud.cyberark.cloud/PasswordVault/API" }
}

try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}
