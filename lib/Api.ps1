#=========================================================================
# Api.ps1 - authentication (credentials prompted at run time) and the
# single REST wrapper used for every CyberArk call.
#=========================================================================

#region Authentication
function ConvertFrom-SecureStringPlain {
    param([Parameter(Mandatory)][securestring]$Secure)
    return (New-Object System.Net.NetworkCredential("", $Secure)).Password
}

# Hidden-input prompt returning a SecureString. Piped/automated stdin cannot be hidden, so in that
# case the line is read normally and wrapped immediately. Returns $null if the input was empty.
function Read-SecretPrompt {
    param([Parameter(Mandatory)][string]$Prompt)
    if ([Console]::IsInputRedirected) {
        $line = Read-Host "$Prompt (read from redirected input)"
        if ($line) { return (ConvertTo-SecureString -String $line -AsPlainText -Force) }
        return $null
    }
    $sec = Read-Host $Prompt -AsSecureString
    if ($sec -and $sec.Length -gt 0) { return $sec }
    return $null
}

# Prompts the admin for the service user + key (hidden input). Nothing is written to disk or the log
# except the service user name (useful for the audit trail).
function Request-CyberArkCredentials {
    Write-Host ""
    Write-Host "CyberArk service account (used for all API calls in this run)" -ForegroundColor White
    $user = ""
    while ([string]::IsNullOrWhiteSpace($user)) {
        $user = ([string](Read-Host "  Service user name (e.g. svc-name@cyberark.cloud.1234)")).Trim()
    }
    $secret = $null
    while ($null -eq $secret) {
        $secret = Read-SecretPrompt -Prompt "  Service user key/secret (paste - input is hidden)"
    }
    $Global:Onb.ServiceUserId = $user
    $Global:Onb.ServiceSecret = $secret
    Write-Log "Service account supplied by operator: $user" INFO
}

# Requests a token with the stored credentials. Throws on failure (callers decide how to abort).
function Get-AuthToken {
    if (-not $Global:Onb.ServiceUserId -or -not $Global:Onb.ServiceSecret) { throw "No CyberArk credentials have been supplied." }
    $plain = ConvertFrom-SecureStringPlain -Secure $Global:Onb.ServiceSecret
    $body  = @{ grant_type = "client_credentials"; client_id = $Global:Onb.ServiceUserId; client_secret = $plain }
    try {
        $r = Invoke-RestMethod -Uri "$($Global:Onb.IdentityUrl)/oauth2/platformtoken" -Method POST -Body $body `
            -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
    } catch {
        $status = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
        throw "Authentication failed: $(Get-ApiErrorText -Status $status -Message $_.Exception.Message -ErrorBody (Get-ErrorResponseBody -ErrorRecord $_))"
    } finally {
        $plain = $null
    }
    if (-not $r.access_token) { throw "Authentication response did not contain an access_token." }
    $exp = if ($r.expires_in) { [int]$r.expires_in } else { 900 }
    $Global:Onb.Token       = $r.access_token
    $Global:Onb.TokenExpiry = (Get-Date).AddSeconds([Math]::Max($exp - 60, 30))
    Write-Log "Token acquired (valid ~${exp}s)." SUCCESS
}

# Interactive sign-in: up to 3 attempts, then throws.
function Connect-CyberArk {
    param([int]$MaxAttempts = 3)
    $cy = $Global:Onb.Config.cyberark
    if (-not $cy.identityUrl -and (Test-IsPlaceholder $cy.identityTenantId)) { throw "cyberark.identityTenantId is not set in the config (use config\onboarding.config.local.json)." }
    if (-not $cy.apiBaseUrl -and (Test-IsPlaceholder $cy.subdomain)) { throw "cyberark.subdomain is not set in the config (use config\onboarding.config.local.json)." }
    for ($i = 1; $i -le $MaxAttempts; $i++) {
        Request-CyberArkCredentials
        try { Get-AuthToken; return } catch {
            Write-Log "$($_.Exception.Message) (attempt $i of $MaxAttempts)" ERROR
            $Global:Onb.ServiceSecret = $null
        }
    }
    throw "Could not authenticate to CyberArk after $MaxAttempts attempts."
}

function Get-ApiHeaders {
    if ((Get-Date) -ge $Global:Onb.TokenExpiry) { Write-Log "Refreshing token..." WARN; Get-AuthToken }
    return @{ Authorization = "Bearer $($Global:Onb.Token)" }
}
#endregion

#region Error helpers (Windows PowerShell 5.1 and PowerShell 7+)
function Get-ErrorResponseBody {
    param($ErrorRecord)
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) { return $ErrorRecord.ErrorDetails.Message }
    try {
        $resp = $ErrorRecord.Exception.Response
        if (-not $resp) { return $null }
        if ($resp.PSObject.Methods.Name -contains "GetResponseStream") {
            $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
            return $reader.ReadToEnd()
        }
        if ($resp.PSObject.Properties.Name -contains "Content") { return $resp.Content.ReadAsStringAsync().Result }
    } catch {}
    return $null
}

# Turns CyberArk's {"ErrorCode":..,"ErrorMessage":..} body into one readable line.
function Get-ApiErrorText {
    param([int]$Status, [string]$Message, [string]$ErrorBody)
    $code = ""; $text = ""
    if ($ErrorBody) {
        try {
            $j = $ErrorBody | ConvertFrom-Json
            if ($j.ErrorCode)    { $code = [string]$j.ErrorCode }
            if ($j.ErrorMessage) { $text = [string]$j.ErrorMessage }
            elseif ($j.error_description) { $text = [string]$j.error_description }
            elseif ($j.message) { $text = [string]$j.message }
        } catch { $text = $ErrorBody }
    }
    if (-not $text) { $text = $Message }
    return ("HTTP {0} {1} {2}" -f $Status, $code, $text).Replace("  ", " ").Trim()
}
#endregion

#region REST wrapper
function New-ApiResult {
    param([bool]$Success, [int]$StatusCode = 0, $Data = $null, [string]$Error = "", [string]$ErrorBody = "", [bool]$DryRun = $false)
    return [pscustomobject]@{
        Success    = $Success
        StatusCode = $StatusCode
        Data       = $Data
        Error      = $Error
        ErrorBody  = $ErrorBody
        NotFound   = ($StatusCode -eq 404)
        DryRun     = $DryRun
    }
}

# Never throws. Distinguishes "not found" (NotFound=$true) from any other failure, so callers can
# not mistake a permission/network error for "object does not exist".
#  - GET: retried on network errors, 429 and 5xx.
#  - Writes: retried only on 429/503 (never after an ambiguous timeout, to avoid duplicates).
#  - 401: token refreshed once, then the call is repeated.
function Invoke-CyberArkApi {
    param(
        [Parameter(Mandatory)][ValidateSet("GET", "POST", "PUT", "DELETE")][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        $Body = $null,
        [int[]]$ExpectedStatus = @()
    )
    $uri = "$($Global:Onb.PvwaBase)/$Path"
    $isRead = ($Method -eq "GET")

    if (-not $isRead -and $Global:Onb.DryRun) {
        Write-Log "[WHATIF] $Method $Path - not sent (dry run)." WARN
        return New-ApiResult -Success $true -DryRun $true
    }

    $json = if ($null -ne $Body) { $Body | ConvertTo-Json -Depth 10 } else { $null }
    $max  = [int]$Global:Onb.Config.retry.maxRetries
    $wait = [int]$Global:Onb.Config.retry.waitSeconds
    $attempt = 0
    $tokenRefreshed = $false

    while ($true) {
        $attempt++
        try {
            $params = @{ Uri = $uri; Method = $Method; Headers = (Get-ApiHeaders); ErrorAction = "Stop" }
            if ($null -ne $json) {
                $params.Body = [System.Text.Encoding]::UTF8.GetBytes($json)
                $params.ContentType = "application/json; charset=utf-8"
            }
            if ($isRead) { Write-Log "GET $Path" DEBUG } else { Write-Log "$Method $Path  Body=$(Get-RedactedBody $Body)" DEBUG }
            $resp = Invoke-RestMethod @params
            Write-Log "$Method $Path -> OK" DEBUG
            return New-ApiResult -Success $true -StatusCode 200 -Data $resp
        } catch {
            $status  = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
            $errBody = Get-ErrorResponseBody -ErrorRecord $_
            $errText = Get-ApiErrorText -Status $status -Message $_.Exception.Message -ErrorBody $errBody

            if ($status -eq 401 -and -not $tokenRefreshed) {
                Write-Log "401 on $Method $Path - refreshing token and retrying once." WARN
                $tokenRefreshed = $true
                try { Get-AuthToken } catch { return New-ApiResult -Success $false -StatusCode 401 -Error $_.Exception.Message }
                continue
            }

            $retryable = if ($isRead) { $status -in @(0, 429, 500, 502, 503, 504) } else { $status -in @(429, 503) }
            if ($retryable -and $attempt -le $max) {
                $w = if ($status -eq 429) { $wait * $attempt } else { $wait }
                Write-Log "$Method $Path -> $errText (retry $attempt of $max in ${w}s)" WARN
                Start-Sleep -Seconds $w
                continue
            }

            $level = if ($status -in $ExpectedStatus) { "DEBUG" } elseif ($isRead) { "WARN" } else { "ERROR" }
            Write-Log "$Method $Path -> $errText" $level
            if ($errBody -and $level -ne "DEBUG") {
                $raw = ([string]$errBody -replace "\s+", " ")
                if ($raw.Length -gt 1500) { $raw = $raw.Substring(0, 1500) + "..." }
                Write-Log "  raw response body: $raw" DEBUG
            }
            return New-ApiResult -Success $false -StatusCode $status -Error $errText -ErrorBody ([string]$errBody)
        }
    }
}
#endregion
