#=========================================================================
# Logging.ps1 - local run log, operator/device audit context, redaction,
# and Azure Blob upload (upload failure NEVER stops the run).
#=========================================================================

#region Redaction
function Protect-LogText {
    param([string]$Text)
    if (-not $Text) { return $Text }
    $t = $Text
    $t = [regex]::Replace($t, "(?i)(sig=)[^&\s""']+", '$1***REDACTED***')
    $t = [regex]::Replace($t, "(?i)(client_secret=)[^&\s""']+", '$1***REDACTED***')
    $t = [regex]::Replace($t, "(?i)(Bearer\s+)[A-Za-z0-9\-\._~\+\/]+=*", '$1***REDACTED***')
    return $t
}

# Field names that must never reach the log in plaintext.
$SecretFieldNames = @("secret", "password", "newSecret", "currentSecret", "client_secret")

function Get-RedactedBody {
    param($Body)
    if ($null -eq $Body) { return $null }
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

#region Write-Log
function Write-Log {
    param(
        [Parameter(Mandatory, Position = 0)][AllowEmptyString()][string]$Message,
        [Parameter(Position = 1)][ValidateSet("INFO", "WARN", "ERROR", "SUCCESS", "DEBUG", "SECTION", "ALERT")][string]$Level = "INFO"
    )
    $text  = Protect-LogText $Message
    $runId = if ($Global:Onb -and $Global:Onb.RunId) { $Global:Onb.RunId.Substring(0, 8) } else { "--------" }
    $line  = "[{0}] [{1}] [{2}] {3}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $runId, $text

    if ($Global:Onb -and $Global:Onb.LogFile) {
        try { Add-Content -LiteralPath $Global:Onb.LogFile -Value $line -Encoding UTF8 -WhatIf:$false } catch {}
    }

    $showDebug = $Global:Onb -and $Global:Onb.Config -and $Global:Onb.Config.logging.consoleDebug
    if ($Level -eq "DEBUG" -and -not $showDebug) { return }
    switch ($Level) {
        "ALERT"   { Write-Host $line -ForegroundColor White -BackgroundColor DarkRed }
        "ERROR"   { Write-Host $line -ForegroundColor Red }
        "WARN"    { Write-Host $line -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $line -ForegroundColor Green }
        "SECTION" { Write-Host $line -ForegroundColor Magenta }
        "DEBUG"   { Write-Host $line -ForegroundColor DarkGray }
        default   { Write-Host $line -ForegroundColor Cyan }
    }
}

# Red-highlighted item that is also collected for the end-of-run attention summary.
function Write-Alert {
    param([Parameter(Mandatory)][string]$Message)
    [void]$Global:Onb.Alerts.Add($Message)
    Write-Log $Message ALERT
}

function Initialize-Logging {
    $cfg    = $Global:Onb.Config.logging
    $folder = if ([System.IO.Path]::IsPathRooted($cfg.localFolder)) { $cfg.localFolder } else { Join-Path $Global:Onb.Root $cfg.localFolder }
    if (-not (Test-Path -LiteralPath $folder)) { New-Item -ItemType Directory -Path $folder -Force -WhatIf:$false | Out-Null }
    $stamp  = Get-Date -Format "yyyyMMdd_HHmmss"
    $user   = $Global:Onb.Operator.UserId
    $Global:Onb.LogFolder   = $folder
    $Global:Onb.LogFile     = Join-Path $folder "Onboarding_${stamp}_${user}.log"
    $Global:Onb.ResultsFile = Join-Path $folder "OnboardingResults_${stamp}_${user}.csv"
}
#endregion

#region Operator / device audit context
function Get-OperatorContext {
    param([string]$ScriptPath, [string]$ScriptVersion)

    $onWin = Test-IsWindows
    $ctx = [ordered]@{}
    $rawUser = [Environment]::UserName
    $ctx.UserId       = ($rawUser -replace "[^\w\.\-\$]", "_")
    $ctx.UserDomain   = [Environment]::UserDomainName
    $ctx.Identity     = "$([Environment]::UserDomainName)\$rawUser"
    $ctx.Upn          = ""
    $ctx.IsElevated   = ""
    if ($onWin) {
        try {
            $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
            $ctx.Identity   = $wi.Name
            $ctx.IsElevated = (New-Object Security.Principal.WindowsPrincipal($wi)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        } catch {}
        try { $upn = (& whoami.exe /upn 2>$null); if ($LASTEXITCODE -eq 0 -and $upn) { $ctx.Upn = ($upn | Select-Object -First 1).Trim() } } catch {}
    }

    $ctx.ComputerName = [Environment]::MachineName
    $ctx.Fqdn         = ""
    try { $ctx.Fqdn = [Net.Dns]::GetHostEntry("").HostName } catch {}

    $nics = @()
    try {
        foreach ($nic in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            if ($nic.OperationalStatus -ne "Up" -or $nic.NetworkInterfaceType -eq "Loopback") { continue }
            $ips = @($nic.GetIPProperties().UnicastAddresses | ForEach-Object { $_.Address.IPAddressToString })
            $mac = $nic.GetPhysicalAddress().ToString()
            $nics += "{0} [MAC {1}] {2}" -f $nic.Name, $mac, ($ips -join ", ")
        }
    } catch {}
    $ctx.NetworkAdapters = $nics

    $ctx.OS = [Environment]::OSVersion.VersionString
    $ctx.Manufacturer = ""; $ctx.Model = ""; $ctx.SerialNumber = ""
    if ($onWin) {
        try {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            $ctx.OS = "$($os.Caption) $($os.Version) (build $($os.BuildNumber))"
            $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
            $ctx.Manufacturer = $cs.Manufacturer; $ctx.Model = $cs.Model
            $ctx.SerialNumber = (Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop).SerialNumber
        } catch {}
    }

    $ctx.PowerShell     = "$($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"
    $ctx.HostName       = $Host.Name
    $ctx.ProcessId      = $PID
    $ctx.TimeZone       = [TimeZoneInfo]::Local.Id
    $ctx.StartedUtc     = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss") + "Z"
    $ctx.WorkingDir     = (Get-Location).Path

    $remote = @()
    if ($env:SESSIONNAME)  { $remote += "SESSIONNAME=$($env:SESSIONNAME)" }
    if ($env:CLIENTNAME)   { $remote += "CLIENTNAME=$($env:CLIENTNAME)" }
    if ($env:SSH_CLIENT)   { $remote += "SSH_CLIENT=$($env:SSH_CLIENT)" }
    $ctx.RemoteSession = if ($remote.Count) { $remote -join "; " } else { "local console / not detected" }

    $ctx.ScriptPath    = $ScriptPath
    $ctx.ScriptVersion = $ScriptVersion
    $ctx.ScriptSha256  = ""
    try { if ($ScriptPath -and (Test-Path -LiteralPath $ScriptPath)) { $ctx.ScriptSha256 = (Get-FileHash -LiteralPath $ScriptPath -Algorithm SHA256).Hash } } catch {}

    return [pscustomobject]$ctx
}

function Write-RunContext {
    param($Operator, [hashtable]$Extra = @{})
    Write-Log "================ RUN CONTEXT (who / where) ================" SECTION
    Write-Log "Run ID           : $($Global:Onb.RunId)" INFO
    foreach ($p in $Operator.PSObject.Properties) {
        if ($p.Name -eq "NetworkAdapters") {
            if (@($p.Value).Count -eq 0) { Write-Log "NetworkAdapters  : (none detected)" INFO }
            foreach ($n in $p.Value) { Write-Log "NetworkAdapter   : $n" INFO }
        } else {
            Write-Log ("{0,-16} : {1}" -f $p.Name, $p.Value) INFO
        }
    }
    foreach ($k in $Extra.Keys) { Write-Log ("{0,-16} : {1}" -f $k, $Extra[$k]) INFO }
    Write-Log "===========================================================" SECTION
}
#endregion

#region Azure Blob upload
function Test-AzureBlobConfigured {
    $c = $Global:Onb.Config.azureBlob
    if (-not $c -or -not $c.enabled) { return $false }
    if (Test-IsPlaceholder $c.container) { return $false }
    if (Test-IsPlaceholder $c.sasToken) { return $false }
    if (-not $c.endpointOverride -and (Test-IsPlaceholder $c.storageAccount)) { return $false }
    return $true
}

function Get-BlobBaseUrl {
    $c = $Global:Onb.Config.azureBlob
    if ($c.endpointOverride) { return $c.endpointOverride.TrimEnd("/") }
    $suffix = if ($c.endpointSuffix) { $c.endpointSuffix } else { "core.windows.net" }
    return "https://$($c.storageAccount).blob.$suffix"
}

function Get-BlobName {
    param([Parameter(Mandatory)][string]$FilePath)
    $c = $Global:Onb.Config.azureBlob
    $d = Get-Date
    $parts = @()
    if ($c.blobPrefix) { $parts += $c.blobPrefix.Trim("/") }
    $parts += $d.ToString("yyyy"), $d.ToString("MM"), $d.ToString("dd"), (Split-Path -Leaf $FilePath)
    return ($parts -join "/")
}

# Returns @{ Success; Error }. Never throws.
function Send-FileToBlob {
    param([Parameter(Mandatory)][string]$FilePath, [Parameter(Mandatory)][string]$BlobName)
    $c = $Global:Onb.Config.azureBlob
    try {
        $segments = ($BlobName -split "/") | ForEach-Object { [uri]::EscapeDataString($_) }
        $url = "{0}/{1}/{2}?{3}" -f (Get-BlobBaseUrl), [uri]::EscapeDataString($c.container), ($segments -join "/"), $c.sasToken.TrimStart("?")
        $headers = @{ "x-ms-blob-type" = "BlockBlob"; "x-ms-version" = $c.apiVersion }
        Invoke-RestMethod -Uri $url -Method Put -InFile $FilePath -Headers $headers `
            -ContentType "text/plain; charset=utf-8" -TimeoutSec ([int]$c.timeoutSeconds) -ErrorAction Stop | Out-Null
        return @{ Success = $true; Error = $null }
    } catch {
        $status = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
        $body   = Get-ErrorResponseBody -ErrorRecord $_
        $code   = ""
        if ($body -match "<Code>([^<]+)</Code>") { $code = $Matches[1] }
        $msg    = if ($body -match "<Message>([^<]+)</Message>") { $Matches[1] -replace "\s+", " " } else { $_.Exception.Message }
        $detail = ("HTTP $status $code $msg" -replace "\s{2,}", " ").Trim().TrimEnd(".")
        return @{ Success = $false; Error = (Protect-LogText $detail) }
    }
}

function Get-PendingUploadsPath { return (Join-Path $Global:Onb.LogFolder "PendingUploads.csv") }

function Add-PendingUpload {
    param([string]$FilePath, [string]$BlobName, [string]$ErrorText)
    $path = Get-PendingUploadsPath
    $existing = @()
    if (Test-Path -LiteralPath $path) { $existing = @(Import-Csv -LiteralPath $path) }
    if ($existing | Where-Object { $_.LocalPath -eq $FilePath }) { return }
    $row = [pscustomobject]@{ LocalPath = $FilePath; BlobName = $BlobName; FailedAt = (Get-Date -Format "yyyy-MM-dd HH:mm:ss"); Error = $ErrorText }
    (@($existing) + $row) | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8 -WhatIf:$false
}

function Invoke-PendingUploads {
    $path = Get-PendingUploadsPath
    if (-not (Test-Path -LiteralPath $path)) { return }
    $pending = @(Import-Csv -LiteralPath $path)
    if ($pending.Count -eq 0) { return }
    Write-Log "Retrying $($pending.Count) log file(s) that failed to upload on an earlier run..." INFO
    $stillPending = @()
    foreach ($p in $pending) {
        if (-not (Test-Path -LiteralPath $p.LocalPath)) {
            Write-Log "Pending upload skipped - local file no longer exists: $($p.LocalPath)" WARN
            continue
        }
        $r = Send-FileToBlob -FilePath $p.LocalPath -BlobName $p.BlobName
        if ($r.Success) {
            Write-Log "Earlier log uploaded to Azure Blob: $($p.BlobName)" SUCCESS
        } else {
            Write-Log "Still cannot upload '$($p.LocalPath)': $($r.Error)" WARN
            $stillPending += $p
        }
    }
    if ($stillPending.Count -gt 0) { $stillPending | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8 -WhatIf:$false }
    else { Remove-Item -LiteralPath $path -Force -WhatIf:$false }
}

# Upload run artifacts. On failure: log clearly, queue for manual/next-run upload, and carry on.
function Publish-RunArtifacts {
    param([string[]]$Paths)
    $existing = @($Paths | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
    if (-not (Test-AzureBlobConfigured)) {
        Write-Log "Azure Blob upload is disabled or not configured (azureBlob.* in onboarding.config*.json) - logs were kept LOCALLY only: $($existing -join '; ')" WARN
        return
    }
    $c = $Global:Onb.Config.azureBlob
    Invoke-PendingUploads
    foreach ($file in $existing) {
        $blob = Get-BlobName -FilePath $file
        $r = Send-FileToBlob -FilePath $file -BlobName $blob
        if ($r.Success) {
            Write-Log "Uploaded to Azure Blob: container '$($c.container)', blob '$blob'." SUCCESS
        } else {
            Write-Log "AZURE BLOB UPLOAD FAILED for '$file': $($r.Error). ACTION REQUIRED - upload this file manually to container '$($c.container)' (suggested blob name '$blob'). It has been queued in '$(Get-PendingUploadsPath)' and will be retried automatically on the next run." ERROR
            Add-PendingUpload -FilePath $file -BlobName $blob -ErrorText $r.Error
        }
    }
}
#endregion
