#=========================================================================
# Common.ps1
# Shared configuration, authentication, API helpers, and CyberArk naming-
# convention builders/validators for the account-onboarding automation.
# Dot-source this file from Onboard-Accounts.ps1 (or any other script that
# needs the same auth/API/naming logic) rather than duplicating it:
#   . "$PSScriptRoot\Common.ps1"
#=========================================================================


$IdentityTenantId  = "XXXXXX"
$ServiceUserId     = "XXXXX@cyberark.cloud.XXXX"
$ServiceUserSecret = "XXXXXXXXXXXXXXXX"
$Subdomain         = "XXXXXX"
#>

$IdentityUrl = "https://$IdentityTenantId.id.cyberark.cloud"
$PvwaBase    = "https://$Subdomain.privilegecloud.cyberark.cloud/PasswordVault/API"

# Confirmed against a real tenant via Get-SafeMembers: CyberArk Identity mirrors Entra-synced
# groups straight into the Vault's own directory as plain Vault Groups (memberType "Group",
# searchIn "Vault") -- there's no separate "Role" member type on this API, and no external
# directory name needed. See the diagnostic note in the README if your tenant behaves differently.
$SafeMemberType = "Group"

$MaxRetries       = 4
$RetryWaitSeconds = 5

$ScriptRoot = $PSScriptRoot
$LogFile    = "$ScriptRoot\Onboarding_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}
#endregion

#region Logging (with secret/token redaction)
function Write-Log {
    param([string]$Message, [ValidateSet("INFO","WARN","ERROR","SUCCESS","DEBUG","SECTION")][string]$Level = "INFO")
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Add-Content -Path $LogFile -Value $line
    $c = @{ INFO = "Cyan"; WARN = "Yellow"; ERROR = "Red"; SUCCESS = "Green"; DEBUG = "DarkGray"; SECTION = "Magenta" }[$Level]
    Write-Host $line -ForegroundColor $c
}

# Field names that must never reach the log in plaintext (account secrets, client secret, etc.)
$SecretFieldNames = @("secret", "password", "ServiceUserSecret", "newSecret", "currentSecret", "client_secret")

function Get-RedactedBody {
    param($Body)
    if (-not $Body) { return $null }
    try {
        $clone = ($Body | ConvertTo-Json -Depth 10) | ConvertFrom-Json
        foreach ($f in $SecretFieldNames) {
            if ($clone.PSObject.Properties.Name -contains $f) { $clone.$f = "***REDACTED***" }
        }
        return ($clone | ConvertTo-Json -Depth 10 -Compress)
    } catch {
        return "(body could not be serialized for logging)"
    }
}
#endregion

#region Auth (OAuth client-credentials against CyberArk Identity, auto-refresh)
$Global:Token = $null
$Global:TokenExpiry = Get-Date

function Get-AuthToken {
    $body = @{ grant_type = "client_credentials"; client_id = $ServiceUserId; client_secret = $ServiceUserSecret }
    try {
        $r = Invoke-RestMethod -Uri "$IdentityUrl/oauth2/platformtoken" -Method POST -Body $body `
            -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
        $Global:Token = $r.access_token
        $exp = if ($r.expires_in) { [int]$r.expires_in } else { 900 }
        $Global:TokenExpiry = (Get-Date).AddSeconds($exp - 60)
        Write-Log "Token acquired (valid ~${exp}s)." SUCCESS
    } catch {
        Write-Log "Authentication FAILED: $($_.Exception.Message)" ERROR
        Write-Log "Cannot continue without a valid token. Exiting." ERROR
        exit 1
    }
}

function Get-Headers {
    if ((Get-Date) -ge $Global:TokenExpiry) { Write-Log "Refreshing token..." WARN; Get-AuthToken }
    return @{ Authorization = "Bearer $Global:Token"; "Content-Type" = "application/json" }
}
#endregion

#region Error body extraction (works whether this runs under Windows PowerShell 5.1 or PowerShell 7+)
# PS7's Invoke-RestMethod throws Microsoft.PowerShell.Commands.HttpResponseException, whose
# .Response is a System.Net.Http.HttpResponseMessage (no .GetResponseStream()); PS5.1's Desktop
# edition throws System.Net.WebException, whose .Response is an HttpWebResponse (has
# .GetResponseStream() but no .Content). $_.ErrorDetails.Message is populated by PowerShell
# itself on BOTH editions whenever the server returned a body, so try that first.
function Get-ErrorResponseBody {
    param($ErrorRecord)
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
        return $ErrorRecord.ErrorDetails.Message
    }
    try {
        $resp = $ErrorRecord.Exception.Response
        if (-not $resp) { return $null }
        if ($resp.PSObject.Methods.Name -contains "GetResponseStream") {
            $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
            return $reader.ReadToEnd()
        }
        if ($resp.PSObject.Properties.Name -contains "Content") {
            return $resp.Content.ReadAsStringAsync().Result
        }
    } catch {}
    return $null
}
#endregion

#region API helpers (GET/POST/PUT with retry, token-refresh, and redacted logging)
function Invoke-ApiGet {
    param([string]$Uri)
    $a = 0
    while ($a -le $MaxRetries) {
        $a++
        try {
            $resp = Invoke-RestMethod -Uri $Uri -Method GET -Headers (Get-Headers) -ErrorAction Stop
            Write-Log "GET $Uri -> OK" DEBUG
            return $resp
        } catch {
            $s = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
            $m = $_.Exception.Message
            $respBody = Get-ErrorResponseBody -ErrorRecord $_
            if ($s -in @(400, 403, 404, 501)) { Write-Log "GET $Uri -> $s $m $respBody (no retry)" WARN; return $null }
            if ($s -eq 401) { Write-Log "401 on GET - refreshing token" WARN; Get-AuthToken; continue }
            if ($a -le $MaxRetries) {
                $w = if ($s -eq 429) { $RetryWaitSeconds * $a } else { $RetryWaitSeconds }
                Write-Log "GET $Uri -> $s $m (retry $a in ${w}s)" WARN; Start-Sleep -Seconds $w
            } else { Write-Log "GET $Uri -> $s $m (retries exhausted)" ERROR; return $null }
        }
    }
    return $null
}

# POST/PUT helper. Returns @{ Success; Data; StatusCode; Error; ErrorBody } instead of throwing,
# so callers can decide whether a failure should stop the whole safe/row or just be reported.
function Invoke-ApiWrite {
    param(
        [Parameter(Mandatory)][ValidateSet("POST", "PUT")][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        $Body = $null
    )
    $json = if ($null -ne $Body) { $Body | ConvertTo-Json -Depth 10 } else { $null }
    $a = 0
    while ($a -le $MaxRetries) {
        $a++
        try {
            Write-Log "$Method $Uri  Body=$(Get-RedactedBody $Body)" DEBUG
            $resp = if ($json) {
                Invoke-RestMethod -Uri $Uri -Method $Method -Headers (Get-Headers) -Body $json -ErrorAction Stop
            } else {
                Invoke-RestMethod -Uri $Uri -Method $Method -Headers (Get-Headers) -ErrorAction Stop
            }
            Write-Log "$Method $Uri -> OK" SUCCESS
            return @{ Success = $true; Data = $resp; StatusCode = 200 }
        } catch {
            $s = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
            $m = $_.Exception.Message
            $respBody = Get-ErrorResponseBody -ErrorRecord $_
            if ($s -eq 401) { Write-Log "401 on $Method - refreshing token" WARN; Get-AuthToken; continue }
            if ($s -in @(400, 403, 404, 409, 422)) {
                Write-Log "$Method $Uri -> $s $m $respBody (no retry)" ERROR
                return @{ Success = $false; StatusCode = $s; Error = $m; ErrorBody = $respBody }
            }
            if ($a -le $MaxRetries) {
                $w = if ($s -eq 429) { $RetryWaitSeconds * $a } else { $RetryWaitSeconds }
                Write-Log "$Method $Uri -> $s $m (retry $a in ${w}s)" WARN; Start-Sleep -Seconds $w
            } else {
                Write-Log "$Method $Uri -> $s $m (retries exhausted)" ERROR
                return @{ Success = $false; StatusCode = $s; Error = $m; ErrorBody = $respBody }
            }
        }
    }
    return @{ Success = $false; StatusCode = 0; Error = "Retries exhausted" }
}
#endregion

#region Naming convention tables
# ── Safe naming: [Region]-[Environment]-[Technology]-[AccessType]-[Tier]-[Team]  (Tier optional)
$SafeRegionCodes      = @("OCA", "APAC", "EMEA", "JP", "OT", "GLB")
$SafeEnvironmentCodes = @("P", "D", "T", "Q")
$SafeTechnologyCodes  = @("WIN", "LIN", "WKS", "NET", "DB", "SQL", "ORC", "HTTP")
$SafeAccessTypeCodes  = @("LA", "LSA", "DSA", "ENA", "DA")
$SafeTierCodes        = @("T0", "T1", "T2")
$SafeNameMaxLength    = 28

# ── Platform naming: [Region]-[Flavour]-[AppTower]-[AccountType]-[RotationPolicy]-[Vendor]-[Exception]
$PlatformRegionCodes      = @("OCA", "APAC", "EMEA", "JP", "GLB")
$PlatformFlavourCodes     = @("WIN", "UNX", "DB", "CLD", "NTW")
$PlatformAppTowerCodes    = @("PA", "FW", "NW", "AD", "WT", "IN", "SD", "UX", "AZR", "ORA", "SQL", "PKI", "UAM", "BKP", "O365")
$PlatformAccountTypeCodes = @("LA", "DA", "LS", "DS", "RT", "SA")
$PlatformRotationCodes    = @("RM", "RA", "RS")
$PlatformVendorCodes      = @("W", "T", "D")   # optional

# Safe members added to EVERY safe, in addition to the two derived Safe Manager/User groups
# below. Replace the placeholder with your actual "BG group" name before running against a real
# tenant. NOTE: "Privilege Cloud Administrators" -- no "d" on "Privilege" -- confirmed via
# Get-SafeMembers against a real safe; a typo here silently fails as a plain "member not found".
$DefaultSafeMembers = @(
    @{ MemberName = "Privilege Cloud Administrators" },
    @{ MemberName = "AMS-AlgoSecWPMGroup" }
)


$FullControlPermissions = @{
    useAccounts = $true; retrieveAccounts = $true; listAccounts = $true
    addAccounts = $true; updateAccountContent = $true; updateAccountProperties = $true
    initiateCPMAccountManagementOperations = $true; specifyNextAccountContent = $true
    renameAccounts = $true; deleteAccounts = $true; unlockAccounts = $true
    manageSafe = $true; manageSafeMembers = $true; backupSafe = $true
    viewAuditLog = $true; viewSafeMembers = $true; accessWithoutConfirmation = $true
    createFolders = $true; deleteFolders = $true; moveAccountsAndFolders = $true
    requestsAuthorizationLevel1 = $false; requestsAuthorizationLevel2 = $false
}

$SafeManagerPermissions = @{
    useAccounts = $true; retrieveAccounts = $true; listAccounts = $true
    addAccounts = $true; updateAccountContent = $true; updateAccountProperties = $true
    initiateCPMAccountManagementOperations = $true; specifyNextAccountContent = $true
    renameAccounts = $true; deleteAccounts = $true; unlockAccounts = $true
    manageSafe = $true; manageSafeMembers = $true; backupSafe = $false
    viewAuditLog = $true; viewSafeMembers = $true; accessWithoutConfirmation = $false
    createFolders = $true; deleteFolders = $true; moveAccountsAndFolders = $true
    requestsAuthorizationLevel1 = $false; requestsAuthorizationLevel2 = $false
}

$SafeUserPermissions = @{
    useAccounts = $true; retrieveAccounts = $true; listAccounts = $true
    addAccounts = $false; updateAccountContent = $false; updateAccountProperties = $false
    initiateCPMAccountManagementOperations = $false; specifyNextAccountContent = $false
    renameAccounts = $false; deleteAccounts = $false; unlockAccounts = $false
    manageSafe = $false; manageSafeMembers = $false; backupSafe = $false
    viewAuditLog = $false; viewSafeMembers = $false; accessWithoutConfirmation = $false
    createFolders = $false; deleteFolders = $false; moveAccountsAndFolders = $false
    requestsAuthorizationLevel1 = $false; requestsAuthorizationLevel2 = $false
}
#endregion

#region Safe naming: builder + validator
function Build-SafeName {
    param(
        [Parameter(Mandatory)][string]$Region,
        [Parameter(Mandatory)][string]$Environment,
        [Parameter(Mandatory)][string]$Technology,
        [Parameter(Mandatory)][string]$AccessType,
        [string]$Tier,
        [Parameter(Mandatory)][string]$Team
    )
    $parts = @($Region.ToUpper(), $Environment.ToUpper(), $Technology.ToUpper(), $AccessType.ToUpper())
    if (-not [string]::IsNullOrWhiteSpace($Tier)) { $parts += $Tier.ToUpper() }
    $parts += $Team.ToUpper()
    return ($parts -join "-")
}

# Validates the component codes against the allowed lists and returns the canonical, compliant
# name. Callers should always use SuggestedName rather than trusting a manually typed safe name.
function Test-SafeNameInputs {
    param([string]$Region, [string]$Environment, [string]$Technology, [string]$AccessType, [string]$Tier, [string]$Team)
    $errors = @()
    if ($Region -notin $SafeRegionCodes) { $errors += "Region '$Region' not in ($($SafeRegionCodes -join ', '))" }
    if ($Environment -notin $SafeEnvironmentCodes) { $errors += "Environment '$Environment' not in ($($SafeEnvironmentCodes -join ', '))" }
    if ($Technology -notin $SafeTechnologyCodes) { $errors += "Technology '$Technology' not in ($($SafeTechnologyCodes -join ', '))" }
    if ($AccessType -notin $SafeAccessTypeCodes) { $errors += "AccessType '$AccessType' not in ($($SafeAccessTypeCodes -join ', '))" }
    if ($Tier -and $Tier -notin $SafeTierCodes) { $errors += "Tier '$Tier' not in ($($SafeTierCodes -join ', '))" }
    if ([string]::IsNullOrWhiteSpace($Team)) { $errors += "Team is required" }

    $built = $null
    if ($errors.Count -eq 0) {
        $built = Build-SafeName -Region $Region -Environment $Environment -Technology $Technology -AccessType $AccessType -Tier $Tier -Team $Team
        if ($built.Length -gt $SafeNameMaxLength) { $errors += "Built safe name '$built' is $($built.Length) chars, exceeds max $SafeNameMaxLength" }
    }
    return [pscustomobject]@{ IsValid = ($errors.Count -eq 0); Errors = $errors; SuggestedName = $built }
}
#endregion

#region Platform naming: builder + validator
function Build-PlatformName {
    param(
        [Parameter(Mandatory)][string]$Region,
        [Parameter(Mandatory)][string]$Flavour,
        [Parameter(Mandatory)][string]$AppTower,
        [Parameter(Mandatory)][string]$AccountType,
        [Parameter(Mandatory)][string]$RotationPolicy,
        [string]$Vendor,
        [string]$Exception
    )
    $parts = @($Region.ToUpper(), $Flavour.ToUpper(), $AppTower.ToUpper(), $AccountType.ToUpper(), $RotationPolicy.ToUpper())
    if (-not [string]::IsNullOrWhiteSpace($Vendor)) { $parts += $Vendor.ToUpper() }
    if (-not [string]::IsNullOrWhiteSpace($Exception)) { $parts += $Exception.ToUpper() }
    return ($parts -join "-")
}

function Test-PlatformNameInputs {
    param([string]$Region, [string]$Flavour, [string]$AppTower, [string]$AccountType, [string]$RotationPolicy, [string]$Vendor, [string]$Exception)
    $errors = @()
    if ($Region -notin $PlatformRegionCodes) { $errors += "Region '$Region' not in ($($PlatformRegionCodes -join ', '))" }
    if ($Flavour -notin $PlatformFlavourCodes) { $errors += "Flavour '$Flavour' not in ($($PlatformFlavourCodes -join ', '))" }
    if ($AppTower -notin $PlatformAppTowerCodes) { $errors += "AppTower '$AppTower' not in ($($PlatformAppTowerCodes -join ', '))" }
    if ($AccountType -notin $PlatformAccountTypeCodes) { $errors += "AccountType '$AccountType' not in ($($PlatformAccountTypeCodes -join ', '))" }
    if ($RotationPolicy -notin $PlatformRotationCodes) { $errors += "RotationPolicy '$RotationPolicy' not in ($($PlatformRotationCodes -join ', '))" }
    if ($Vendor -and $Vendor -notin $PlatformVendorCodes) { $errors += "Vendor '$Vendor' not in ($($PlatformVendorCodes -join ', '))" }

    $built = $null
    if ($errors.Count -eq 0) {
        $built = Build-PlatformName -Region $Region -Flavour $Flavour -AppTower $AppTower -AccountType $AccountType -RotationPolicy $RotationPolicy -Vendor $Vendor -Exception $Exception
    }
    return [pscustomobject]@{ IsValid = ($errors.Count -eq 0); Errors = $errors; SuggestedName = $built }
}
#endregion

#region Derived AD group names (fixed convention: Global-Sec-<SafeName>-SafeManagers / Global-SEC-<SafeName>-Users)
function Get-DerivedGroupNames {
    param([Parameter(Mandatory)][string]$SafeName)
    return [pscustomobject]@{
        SafeManagerGroup = "Global-Sec-$SafeName-SafeManagers"
        SafeUserGroup    = "Global-SEC-$SafeName-Users"
    }
}
#endregion

#region CyberArk object operations (Platform / Safe / Members / Account / Verify / Reconcile)
# NOTE: exact field names below (Platforms search/duplicate response shape, Accounts payload)
# follow the documented Privilege Cloud REST API but can vary slightly by tenant/API version.
# Validate against your tenant's API reference in a test safe before running this live.

function Get-PlatformByName {
    param([string]$PlatformId)
    $resp = Invoke-ApiGet -Uri "$PvwaBase/Platforms?search=$([uri]::EscapeDataString($PlatformId))"
    if ($resp -and $resp.Platforms) {
        return $resp.Platforms | Where-Object { $_.PlatformID -eq $PlatformId -or $_.general.id -eq $PlatformId } | Select-Object -First 1
    }
    return $null
}

function New-DuplicatedPlatform {
    param([string]$SourcePlatformId, [string]$NewPlatformName)
    # camelCase to match every other endpoint on this tenant's API (Safes/Accounts calls all use
    # camelCase and succeeded) -- if this still 400s, check the redacted error body for the exact
    # field CyberArk rejected and adjust here.
    $body = @{ name = $NewPlatformName; description = "Auto-onboarded platform (duplicated from $SourcePlatformId)" }
    return Invoke-ApiWrite -Method POST -Uri "$PvwaBase/Platforms/$SourcePlatformId/Duplicate" -Body $body
}

# Duplicate's response shape (which field carries the new platform's real ID) isn't confirmed
# against this tenant. Rather than assume the ID equals $NewPlatformName -- which would make
# Account onboarding fail downstream with a confusing "platform not found" if wrong -- try the
# common field names in the Duplicate response first, then re-query the platform by name as a
# fallback, and only fall back to the name itself (with a loud warning) if neither works.
function Resolve-NewPlatformId {
    param($DuplicateResponseData, [string]$NewPlatformName)
    foreach ($field in @("PlatformID", "platformId", "Id", "id")) {
        if ($DuplicateResponseData -and $DuplicateResponseData.PSObject.Properties.Name -contains $field -and $DuplicateResponseData.$field) {
            return [string]$DuplicateResponseData.$field
        }
    }
    $reQueried = Get-PlatformByName -PlatformId $NewPlatformName
    if ($reQueried) {
        $id = if ($reQueried.PSObject.Properties.Name -contains "PlatformID") { $reQueried.PlatformID } else { $reQueried.general.id }
        if ($id) { return [string]$id }
    }
    Write-Log "Could not confirm the real Platform ID for '$NewPlatformName' from the Duplicate response or a re-query -- falling back to using the name itself. Verify this manually if Account onboarding fails with 'platform not found'." WARN
    return $NewPlatformName
}

function Get-SafeByName {
    param([string]$SafeName)
    return Invoke-ApiGet -Uri "$PvwaBase/Safes/$([uri]::EscapeDataString($SafeName))"
}

# Diagnostic: returns the raw member list of an existing safe, so you can confirm the exact
# member names/memberType CyberArk uses on THIS tenant instead of guessing (this is how the
# "Privilege Cloud Administrators" naming and memberType:"Group" default were confirmed). Run
# against any safe that already has the member you're unsure about:
#   . .\Common.ps1; Get-AuthToken
#   (Get-SafeMembers -SafeName "SomeExistingSafeName").value | ConvertTo-Json -Depth 5
function Get-SafeMembers {
    param([string]$SafeName)
    return Invoke-ApiGet -Uri "$PvwaBase/Safes/$([uri]::EscapeDataString($SafeName))/Members"
}

function New-Safe {
    param([string]$SafeName, [string]$ManagingCPM = "", [string]$Description = "Auto-onboarded safe")
    $body = @{
        safeName                  = $SafeName
        description                = $Description
        managingCPM                = $ManagingCPM
        olacEnabled                = $false
        numberOfVersionsRetention  = 5
    }
    return Invoke-ApiWrite -Method POST -Uri "$PvwaBase/Safes" -Body $body
}

# 409 (member already exists) is treated as non-fatal by callers; 404 means the Role/user hasn't
# been provisioned/synced yet and must be created before this safe can be finished.
function Add-SafeMember {
    param([string]$SafeName, [string]$MemberName, [hashtable]$Permissions, [string]$SearchIn = "Vault", [string]$MemberType = $SafeMemberType)
    $body = @{
        memberName   = $MemberName
        searchIn     = $SearchIn
        memberType   = $MemberType
        permissions  = $Permissions
    }
    $result = Invoke-ApiWrite -Method POST -Uri "$PvwaBase/Safes/$([uri]::EscapeDataString($SafeName))/Members" -Body $body
    if (-not $result.Success -and $result.StatusCode -eq 404) {
        Write-Log "Member '$MemberName' not found in the directory -- it must be provisioned in AD before it can be added to safe '$SafeName'." ERROR
    }
    return $result
}

function New-Account {
    param([string]$SafeName, [string]$PlatformId, [string]$UserName, [string]$Address, [string]$SecretType = "password", [string]$InitialSecret = $null)
    $body = @{
        safeName   = $SafeName
        platformId = $PlatformId
        userName   = $UserName
        address    = $Address
        secretType = $SecretType
    }
    if ($InitialSecret) { $body.secret = $InitialSecret }
    return Invoke-ApiWrite -Method POST -Uri "$PvwaBase/Accounts" -Body $body
}

function Invoke-AccountVerify {
    param([string]$AccountId)
    return Invoke-ApiWrite -Method POST -Uri "$PvwaBase/Accounts/$AccountId/Verify" -Body @{}
}

function Invoke-AccountReconcile {
    param([string]$AccountId)
    return Invoke-ApiWrite -Method POST -Uri "$PvwaBase/Accounts/$AccountId/Reconcile" -Body @{}
}

# Verify/Reconcile just queue CPM work -- this polls the account until the relevant timestamp
# moves or the platform reports failure, instead of assuming the POST means it's done.
function Wait-ForAccountTask {
    param(
        [string]$AccountId,
        [Parameter(Mandatory)][ValidateSet("Verify", "Reconcile")][string]$TaskType,
        [int]$TimeoutSeconds = 300,
        [int]$PollIntervalSeconds = 15
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $field = if ($TaskType -eq "Verify") { "lastVerifiedTime" } else { "lastReconciledTime" }
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds $PollIntervalSeconds
        $acct = Invoke-ApiGet -Uri "$PvwaBase/Accounts/$AccountId"
        if ($acct -and $acct.secretManagement) {
            $status = $acct.secretManagement.status
            if ($acct.secretManagement.$field) { return @{ Success = $true; Status = $status } }
            if ($status -eq "failure") { return @{ Success = $false; Status = $status } }
        }
    }
    return @{ Success = $false; Status = "Timeout" }
}
#endregion
