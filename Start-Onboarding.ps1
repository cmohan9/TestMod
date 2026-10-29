<#
.SYNOPSIS
    EPM SaaS (USA / na123) connectivity and TLS-inspection test. Run on an endpoint with the EPM agent.

.DESCRIPTION
    For each EPM URL (port 443) it checks:
      1. DNS lookup       (system resolver + nslookup)
      2. TCP 443          (same as: tnc <host> -p 443  -> TcpTestSucceeded)
      3. TLS handshake    (captures the certificate chain the endpoint really receives)
      4. TLS inspection   (chain must come from the public CA documented for that URL)
      5. HTTPS response   (detects L7 blocking)
    Also reports proxy settings, required root certificates and security/web-filter software.
    Source: https://docs.cyberark.com/epm/latest/en/content/installation/network-setup.htm

.PARAMETER ProxyServer
    Optional unauthenticated HTTP proxy (host:port). Default: direct connection, no proxy.

.EXAMPLE
    .\Test-EPMConnectivity.ps1
    .\Test-EPMConnectivity.ps1 -ProxyServer proxy.contoso.com:8080
#>
[CmdletBinding()]
param(
    [string]$ProxyServer,
    [ValidateRange(2,120)][int]$TimeoutSeconds = 10
)

$Port      = 443
$TimeoutMs = $TimeoutSeconds * 1000
if ($PSVersionTable.PSEdition -ne 'Core') { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 }

# ---- URLs (USA region + tenant na123) ----------------------------------------------------------
$Targets = @(
    @{ Type='Tenant URL';                  Host='na123.epm.cyberark.com';                    Expect=$null;                              Http=$true  }
    @{ Type='Tenant URL';                  Host='login.epm.cyberark.com';                    Expect=$null;                              Http=$true  }
    @{ Type='Tenant URL';                  Host='dispatcher1.epm.cyberark.com';              Expect=$null;                              Http=$true  }
    @{ Type='API regional subdomain';      Host='api-na.epm.cyberark.cloud';                 Expect=$null;                              Http=$true  }
    @{ Type='S3 URL (downloads)';          Host='epm-downloads.s3.us-east-2.amazonaws.com';  Expect='Amazon|Starfield|DigiCert';        Http=$true  }
    @{ Type='S3 URL (files/upgrades)';     Host='files-na.epm.cyberark.com';                 Expect='Google Trust Services|GlobalSign'; Http=$true  }
    @{ Type='Endpoint-service (MQTTS)';    Host='agents-na.epm.cyberark.com';                Expect='Amazon|Starfield';                 Http=$false }
)

$PublicCaRegex = 'Google Trust Services|GlobalSign|Amazon|Starfield|Cloudflare|DigiCert|Let''s Encrypt|ISRG|Sectigo|USERTrust|COMODO|SSL\.com|Entrust|Baltimore|Microsoft|Go ?Daddy|IdenTrust|Certum'
$InspectionVendorRegex = 'Zscaler|Palo Alto|PAN-OS|Fortinet|FortiGate|Forcepoint|Websense|Blue ?Coat|Symantec Web|Netskope|iboss|Umbrella|Cisco Web|McAfee Web|Skyhigh|Check ?Point|SonicWall|Sophos|WatchGuard|Barracuda|Trend Micro|Kaspersky|\bESET\b|Bitdefender|Avast|Fiddler|mitmproxy|Squid|Smoothwall|Menlo|Proofpoint|Trustwave|BIG-IP|NetScaler|Firewall|Inspection|Intercept|MITM|Proxy'
$FilterProcessRegex = 'ZSATunnel|ZSAService|stAgentSvc|Netskope|FPDLP|PanGPS|acumbrella|iboss|FortiClient|CSFalconService|SentinelAgent|cbdefense|CylanceSvc|bdservicehost|mfemms|SophosED|^ekrn$|^avp$|AvastSvc|vpnagent'

# ---- Helpers -----------------------------------------------------------------------------------
function Write-Section([string]$t) { Write-Host ''; Write-Host ('=' * 90) -ForegroundColor DarkGray; Write-Host " $t" -ForegroundColor Cyan; Write-Host ('=' * 90) -ForegroundColor DarkGray }
function Get-StatusColor([string]$s) { switch ($s) { 'PASS' {'Green'} 'WARN' {'Yellow'} 'FAIL' {'Red'} default {'Gray'} } }
function Get-CleanError($r) { $e = $r.Exception; while ($e.InnerException) { $e = $e.InnerException }; $e.Message }

function Test-DnsLookup([string]$h) {
    $o = @{ Ok=$false; Ips=@(); NsOk=$null; Detail='' }
    try { $ips = [Net.Dns]::GetHostAddresses($h) | ForEach-Object { $_.IPAddressToString }; if ($ips) { $o.Ok = $true; $o.Ips = @($ips) } }
    catch { $o.Detail = Get-CleanError $_ }
    if (Get-Command nslookup -ErrorAction SilentlyContinue) {
        try { $o.NsOk = [bool]((& nslookup $h 2>&1 | Out-String) -match '(?s)Name:\s+\S+.*Address') } catch { }
    }
    $o
}

function Invoke-TlsProbe([string]$h, [int]$port, [int]$ms, [string]$proxy) {
    $res = @{ TcpOk=$false; TcpMs=$null; TlsOk=$false; CertReceived=$false; TlsVersion=''; Chain=@(); PolicyErrors=''; Error=''; Note='' }
    $script:Cap = $null
    $client = New-Object System.Net.Sockets.TcpClient
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        $tHost = $h; $tPort = $port
        if ($proxy) { $p = $proxy -replace '^https?://',''; $tHost = ($p -split ':')[0]; $tPort = [int](($p -split ':')[1]) }
        $iar = $client.BeginConnect($tHost, $tPort, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($ms, $false)) { throw "TCP connect to ${tHost}:$tPort timed out after $($ms/1000)s" }
        $client.EndConnect($iar)
        $stream = $client.GetStream(); $stream.ReadTimeout = $ms; $stream.WriteTimeout = $ms

        if ($proxy) {   # HTTP CONNECT through the proxy
            $req = [Text.Encoding]::ASCII.GetBytes("CONNECT ${h}:$port HTTP/1.1`r`nHost: ${h}:$port`r`n`r`n")
            $stream.Write($req, 0, $req.Length)
            $sb = New-Object Text.StringBuilder
            while ($sb.ToString() -notmatch "`r`n`r`n") { $b = $stream.ReadByte(); if ($b -lt 0) { break }; [void]$sb.Append([char]$b) }
            $status = ($sb.ToString() -split "`r`n")[0]
            if ($status -notmatch '^HTTP/\d\.\d 200') { throw "Proxy refused CONNECT: $status" }
        }
        $res.TcpOk = $true; $res.TcpMs = [int]$sw.ElapsedMilliseconds

        # Accept any certificate, but record the chain so it can be checked for TLS inspection
        $cb = [System.Net.Security.RemoteCertificateValidationCallback]{
            param($sender, $cert, $chain, $errors)
            $list = @()
            if ($chain -and $chain.ChainElements.Count -gt 0) {
                foreach ($el in $chain.ChainElements) { $c = $el.Certificate; $list += [pscustomobject]@{ Subject=$c.Subject; Issuer=$c.Issuer } }
            } elseif ($cert) {
                $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $cert
                $list += [pscustomobject]@{ Subject=$c.Subject; Issuer=$c.Issuer }
            }
            $script:Cap = @{ Chain=$list; Errors=$errors.ToString() }
            return $true
        }
        $ssl = New-Object System.Net.Security.SslStream -ArgumentList $stream, $false, $cb
        $ssl.ReadTimeout = $ms; $ssl.WriteTimeout = $ms
        $proto = if ($PSVersionTable.PSEdition -eq 'Core') { [Security.Authentication.SslProtocols]::None } else { [Security.Authentication.SslProtocols]::Tls12 }
        try {
            $ssl.AuthenticateAsClient($h, $null, $proto, $false)
            $res.TlsOk = $true; $res.TlsVersion = $ssl.SslProtocol.ToString()
        } catch {
            $m = Get-CleanError $_
            if ($script:Cap) { $res.Note = "Server certificate received; handshake ended afterwards without a client certificate (expected for mTLS endpoint): $m" }
            else { throw "TLS handshake failed: $m" }
        }
        if ($script:Cap) { $res.CertReceived = $true; $res.Chain = @($script:Cap.Chain); $res.PolicyErrors = $script:Cap.Errors }
    } catch { $res.Error = Get-CleanError $_ }
    finally { $client.Close() }
    $res
}

function Get-InspectionVerdict($chain, [string]$errs, [string]$expect) {
    $c = @($chain); $leaf = $c[0]; $top = $c[$c.Count - 1]
    $all  = ($c | ForEach-Object { "$($_.Subject) $($_.Issuer)" }) -join ' '
    $desc = "leaf issuer [$($leaf.Issuer)], top of chain [$($top.Subject)]"
    if ($all -match $InspectionVendorRegex)         { return @{ Verdict='FAIL'; Detail="TLS inspection detected (matched '$($Matches[0])'): $desc" } }
    if ($all -notmatch $PublicCaRegex)              { return @{ Verdict='FAIL'; Detail="Certificate not from a known public CA - TLS inspection probable: $desc" } }
    if ($errs -match 'NameMismatch')                { return @{ Verdict='FAIL'; Detail="Certificate name does not match host (possible interception): $desc" } }
    if ($expect -and ($all -notmatch $expect))      { return @{ Verdict='WARN'; Detail="Public CA, but not the documented one ($expect): $desc" } }
    if ($errs -match 'ChainErrors')                 { return @{ Verdict='WARN'; Detail="Chain not trusted locally - install GTS Root R4 / Amazon Root CA 1: $desc" } }
    @{ Verdict='PASS'; Detail=$desc }
}

function Invoke-HttpProbe([string]$h, [int]$ms, [string]$proxy) {
    $o = @{ Ok=$false; Code=$null; Detail='' }
    try {
        $req = [Net.HttpWebRequest]::Create("https://$h/")
        $req.Timeout = $ms; $req.AllowAutoRedirect = $false; $req.UserAgent = 'EPM-Connectivity-Test/1.0'
        if ($proxy) { $req.Proxy = New-Object Net.WebProxy("http://$($proxy -replace '^https?://','')") } else { $req.Proxy = $null }
        $resp = $req.GetResponse(); $o.Ok = $true; $o.Code = [int]$resp.StatusCode; $resp.Close()
    } catch [Net.WebException] {
        if ($_.Exception.Response) { $o.Ok = $true; $o.Code = [int]$_.Exception.Response.StatusCode; $_.Exception.Response.Close() }   # any HTTP answer = reachable
        else { $o.Detail = "$($_.Exception.Status): $($_.Exception.Message)" }
    } catch { $o.Detail = Get-CleanError $_ }
    $o
}

function Set-Worst([string]$lvl) { if ($lvl -eq 'FAIL' -or ($lvl -eq 'WARN' -and $script:worst -ne 'FAIL')) { $script:worst = $lvl } }

# ---- Environment checks ------------------------------------------------------------------------
Write-Section ("EPM SaaS (USA / na123) connectivity test - {0}  [{1}]" -f [Environment]::MachineName, $(if ($ProxyServer) { "via proxy $ProxyServer" } else { 'direct, no proxy' }))
$isWin = ($PSVersionTable.PSEdition -ne 'Core') -or ($IsWindows -eq $true)
if ($isWin) {
    try { Write-Host (" WinHTTP proxy : " + ((& netsh winhttp show proxy 2>&1 | Out-String).Trim() -replace '\s+', ' ')) } catch { }
    try { $ie = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
          Write-Host (" WinINET proxy : enabled={0} server='{1}' PAC='{2}'" -f $ie.ProxyEnable, $ie.ProxyServer, $ie.AutoConfigURL) } catch { }
    $roots = @(Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue)
    foreach ($rc in @(@{ N='GTS Root R4'; Fb='GlobalSign' }, @{ N='Amazon Root CA 1'; Fb='Starfield Services Root' })) {
        if ($roots | Where-Object { $_.Subject -like "*CN=$($rc.N)*" }) { Write-Host (" Root cert     : {0} present" -f $rc.N) -ForegroundColor Green }
        elseif ($roots | Where-Object { $_.Subject -like "*$($rc.Fb)*" }) { Write-Host (" Root cert     : {0} missing (legacy '{1}' present - usually OK, installing it is recommended)" -f $rc.N, $rc.Fb) -ForegroundColor Yellow }
        else { Write-Host (" Root cert     : {0} missing and no fallback root - required in hardened/offline environments" -f $rc.N) -ForegroundColor Red }
    }
}
$procs = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match $FilterProcessRegex } | Select-Object -ExpandProperty ProcessName -Unique)
if ($procs.Count) { Write-Host (" Security/web-filter software running: {0} -> make sure it does not block or SSL-scan the EPM URLs." -f ($procs -join ', ')) -ForegroundColor Yellow }
else { Write-Host ' No well-known web-filter / SSL-scanning software detected.' }

# ---- Tests -------------------------------------------------------------------------------------
Write-Section "Testing $($Targets.Count) URLs on port $Port"
$results = @()
foreach ($t in $Targets) {
    $script:worst = 'PASS'; $notes = @()

    $dns = Test-DnsLookup $t.Host
    $dnsS = 'PASS'
    if (-not $dns.Ok) { $dnsS = if ($ProxyServer) { 'WARN' } else { 'FAIL' }; $notes += "DNS failed: $($dns.Detail) [manual: nslookup $($t.Host)]" }
    elseif ($dns.NsOk -eq $false) { $dnsS = 'WARN'; $notes += 'System resolver works but nslookup failed' }
    elseif ($dns.Ips | Where-Object { $_ -match '^(10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)' }) { $dnsS = 'WARN'; $notes += "Resolves to a private/sinkhole address ($($dns.Ips -join ', ')) - DNS filtering or intercepting proxy?" }
    Set-Worst $dnsS

    $tls  = Invoke-TlsProbe $t.Host $Port $TimeoutMs $ProxyServer
    $tcpS = if ($tls.TcpOk) { 'PASS' } else { 'FAIL' }
    $tlsS = if ($tls.TlsOk -or $tls.CertReceived) { 'PASS' } elseif ($tls.TcpOk) { 'FAIL' } else { 'N/A' }
    if (-not $tls.TcpOk) { $notes += "TCP $Port failed: $($tls.Error) [manual: tnc $($t.Host) -p $Port]" } elseif ($tlsS -eq 'FAIL') { $notes += $tls.Error }
    if ($tls.Note) { $notes += $tls.Note }
    Set-Worst $tcpS; if ($tlsS -eq 'FAIL') { Set-Worst 'FAIL' }

    $inspS = 'N/A'
    if ($tls.CertReceived) {
        $v = Get-InspectionVerdict $tls.Chain $tls.PolicyErrors $t.Expect
        $inspS = $v.Verdict; if ($inspS -ne 'PASS') { $notes += "TLS inspection: $($v.Detail)" }
        Set-Worst $inspS
    }

    $httpS = 'N/A'
    if ($t.Http -and $tls.TcpOk) {
        $h = Invoke-HttpProbe $t.Host $TimeoutMs $ProxyServer
        if ($h.Ok) { $httpS = 'PASS' } else { $httpS = 'FAIL'; $notes += "HTTPS request failed: $($h.Detail)" }
        Set-Worst $httpS
    }

    $row = [pscustomobject][ordered]@{
        Type=$t.Type; Host=$t.Host; DNS=$dnsS; IPs=($dns.Ips -join ' '); TCP443=$tcpS; TLS=$tlsS; TlsVersion=$tls.TlsVersion
        Inspection=$inspS; HTTPS=$httpS; Result=$script:worst; Notes=($notes -join ' | ')
    }
    $results += $row

    Write-Host ("[{0}] " -f $row.Result) -ForegroundColor (Get-StatusColor $row.Result) -NoNewline
    Write-Host ("{0,-26} {1,-45}" -f $t.Type, $t.Host) -NoNewline
    Write-Host ("DNS:{0} TCP:{1} TLS:{2} Inspect:{3} HTTPS:{4}" -f $dnsS, $tcpS, $tlsS, $inspS, $httpS) -ForegroundColor (Get-StatusColor $row.Result)
    foreach ($n in $notes) { Write-Host "        - $n" -ForegroundColor DarkYellow }
}

# ---- Summary -----------------------------------------------------------------------------------
Write-Section 'Summary'
$results | Format-Table Host, DNS, TCP443, TLS, TlsVersion, Inspection, HTTPS, Result -AutoSize | Out-String -Width 200 | Write-Host
$fail = @($results | Where-Object Result -eq 'FAIL').Count
$warn = @($results | Where-Object Result -eq 'WARN').Count
Write-Host (" PASS: {0}   WARN: {1}   FAIL: {2}" -f ($results.Count - $fail - $warn), $warn, $fail) -ForegroundColor $(if ($fail) {'Red'} elseif ($warn) {'Yellow'} else {'Green'})

$insp = @($results | Where-Object Inspection -eq 'FAIL')
if ($insp.Count) {
    Write-Host "`n TLS INSPECTION DETECTED / SUSPECTED on: $(($insp | ForEach-Object Host) -join ', ')" -ForegroundColor Red
    Write-Host ' EPM agents do not support TLS inspection - bypass it on the firewall/proxy/SASE and endpoint security software.' -ForegroundColor Red
}

$csv = Join-Path (Get-Location).Path ("EPM-Connectivity-{0}-{1}.csv" -f [Environment]::MachineName, (Get-Date -Format 'yyyyMMdd-HHmmss'))
try { $results | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8; Write-Host " Results saved: $csv" -ForegroundColor Cyan }
catch { Write-Host " Could not write CSV: $($_.Exception.Message)" -ForegroundColor Yellow }

if ($fail) { exit 1 } else { exit 0 }
