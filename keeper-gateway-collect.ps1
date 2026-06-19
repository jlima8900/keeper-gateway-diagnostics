<#
.SYNOPSIS
  Diagnostic data collector for a Keeper Gateway on Windows (KeeperPAM).

.DESCRIPTION
  Companion to keeper-gateway-collect.sh for Windows-native gateway installs
  (and Docker Desktop on Windows). Gathers host, service, event-log, network,
  time-sync, health-endpoint, and target-reachability state into a single
  REDACTED .zip you can attach to a support case.

  Collection is READ-ONLY. It never changes the gateway service or config and
  redacts secrets (GATEWAY_CONFIG, passwords, tokens, keys, seeds, bearer).

  NOTE: This script has NOT yet been validated on a live Windows gateway.
  Review output before sharing. Issues/PRs welcome.

.PARAMETER Region
  eu|us|au|jp|ca|gov  -- region for cloud reachability (default eu).
.PARAMETER Target
  HOST:PORT  -- test DNS+TCP to a rotation target (SSH 22, WinRM 5986, DB port).
.PARAMETER Minimal
  Scope down: skip the full listening-socket / interface inventory.
.PARAMETER NoNetwork
  Skip outbound reachability tests.
.PARAMETER OutDir
  Output directory (default: current directory).

.EXAMPLE
  .\keeper-gateway-collect.ps1 -Region us
  .\keeper-gateway-collect.ps1 -Target dc01.corp.local:5986 -Minimal
#>

[CmdletBinding()]
param(
  [ValidateSet('eu','us','au','jp','ca','gov')] [string]$Region = 'eu',
  [string]$Target = '',
  [switch]$Minimal,
  [switch]$NoNetwork,
  [string]$OutDir = '.'
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

# ---- region -> endpoints --------------------------------------------------
$tld = switch ($Region) { 'us'{'com'} 'eu'{'eu'} 'au'{'com.au'} 'jp'{'jp'} 'ca'{'ca'} 'gov'{'us'} default{'eu'} }
$Router = "connect.keepersecurity.$tld"
$Relay  = "krelay.keepersecurity.$tld"
$Cloud  = "keepersecurity.$tld"

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$out   = Join-Path $OutDir ("keeper-gw-diag-{0}-{1}" -f $env:COMPUTERNAME, $stamp)
foreach ($d in 'host','service','events','network','docker') { New-Item -ItemType Directory -Force -Path (Join-Path $out $d) | Out-Null }

$Notes = [System.Collections.Generic.List[string]]::new()
function Note([string]$m) { $Notes.Add($m); Write-Host "  $m" }

# ---- redaction ------------------------------------------------------------
# Over-redaction is the SAFE failure mode. Masks keyed secrets + bearer tokens
# + basic-auth in URLs + AWS keys + long base64/hex blobs.
function Protect-Secrets {
  param([string]$Text)
  if ($null -eq $Text) { return $Text }
  $keys = '([A-Za-z0-9_]*(PASSWORD|PASSWD|PWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|PASSPHRASE|CREDENTIALS?|_KEY|_SEED|SEED)|GATEWAY_CONFIG|KCM_LICENSE)'
  # multi-line PEM private-key blocks
  $Text = [regex]::Replace($Text, '(?s)(-----BEGIN [A-Z ]*PRIVATE KEY-----).*?(-----END [A-Z ]*PRIVATE KEY-----)', '$1[REDACTED_PRIVATE_KEY]$2')
  # keyed secrets: quoted value first (keeps spaces inside quotes), then unquoted-to-EOL
  $Text = [regex]::Replace($Text, "(?im)($keys\s*[:=]\s*)`"[^`"]*`"", '$1"[REDACTED]"')
  $Text = [regex]::Replace($Text, "(?im)($keys\s*[:=]\s*)[^`"\s].*$", '$1[REDACTED]')
  $Text = [regex]::Replace($Text, '(?i)(bearer )([A-Za-z0-9._~+/=-]{8,})', '$1[REDACTED]')
  $Text = [regex]::Replace($Text, '(://[^:/@\s]+:)([^@/\s]+)@', '$1[REDACTED]@')
  $Text = [regex]::Replace($Text, 'AKIA[0-9A-Z]{16}', '[REDACTED_AWS_KEY]')
  $Text = [regex]::Replace($Text, 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', '[REDACTED_JWT]')
  $Text = [regex]::Replace($Text, '[A-Za-z0-9+/_-]{40,}={0,2}', '[REDACTED_LONG_TOKEN]')
  return $Text
}
# run a scriptblock, capture output (redacted) to a file, never abort
function Cap {
  param([string]$File, [scriptblock]$Script, [switch]$Redact)
  try { $o = & $Script 2>&1 | Out-String } catch { $o = "(command failed: $_)" }
  if ($Redact) { $o = Protect-Secrets $o }
  Add-Content -Path $File -Value $o
}

# Portable TCP probe -- Test-NetConnection is absent on PowerShell Core / Server
# Core / hardened Windows; a missing cmdlet would otherwise mis-report BLOCKED.
function Test-Tcp {
  param([string]$ComputerName, [int]$Port, [int]$TimeoutMs = 6000)
  try {
    $c = [System.Net.Sockets.TcpClient]::new()
    $iar = $c.BeginConnect($ComputerName, $Port, $null, $null)
    if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs)) { $c.EndConnect($iar); $c.Close(); return $true }
    $c.Close(); return $false
  } catch { return $false }
}

Write-Host "Keeper Gateway diagnostic collector (Windows)"
Write-Host "Region=$Region  Output=$out`n"
if ($Minimal) {
  Write-Host ">>> Mode: MINIMAL -- scoped to gateway-relevant data (reduced infra exposure)."
} else {
  Write-Host @"
============================ DATA-EXPOSURE NOTICE ============================
 Full collection captures broad host context: services, event logs, ALL network
 interfaces/routes, firewall rules, and listening ports. Secrets ARE redacted,
 but the rest reveals host/infrastructure detail. Before sharing externally,
 review the bundle, or re-run with -Minimal to scope it down.
=============================================================================
"@
}
Write-Host ""

# ---- host -----------------------------------------------------------------
Write-Host "[*] Host"
$hostInfo = Join-Path $out 'host\info.txt'
Cap $hostInfo { Get-ComputerInfo | Select-Object OsName,OsVersion,OsArchitecture,CsName,CsProcessors,CsTotalPhysicalMemory,OsUptime }
Cap (Join-Path $out 'host\resources.txt') { Get-CimInstance Win32_OperatingSystem | Select-Object FreePhysicalMemory,TotalVisibleMemorySize }
Cap (Join-Path $out 'host\resources.txt') { Get-PSDrive -PSProvider FileSystem | Select-Object Name,Used,Free }

# time sync -- clock skew breaks TLS to the router/relay
$timeFile = Join-Path $out 'host\time.txt'
Cap $timeFile { Get-Date; w32tm /query /status }
try {
  $st = (w32tm /query /status 2>&1 | Out-String)
  # best-effort, English-locale heuristic -- only WARN on explicit failure signals
  if ($st -match 'not synchronized|0x800705B4|The service has not been started') {
    Note "WARN: Windows Time may not be synchronized (best-effort check) -- clock skew breaks TLS to the router/relay; verify 'w32tm /query /status'"
  }
} catch { Write-Verbose "w32tm time-sync check skipped: $_" }

# ---- gateway service ------------------------------------------------------
Write-Host "[*] Gateway service"
# match the PAM gateway service specifically -- NOT every "keeper" service
# (EPM / KeeperWatchdog contain "keeper" but are not the gateway).
$svc = Get-Service 2>$null | Where-Object { $_.Name -match 'gateway' -or $_.DisplayName -match '(Keeper|PAM).*Gateway' }
if ($svc) {
  Cap (Join-Path $out 'service\service.txt') { $svc | Format-List Name,DisplayName,Status,StartType }
  foreach ($s in $svc) {
    if ($s.Status -ne 'Running') { Note "WARN: gateway service '$($s.Name)' is $($s.Status) (not Running)" }
    else { Note "gateway service '$($s.Name)': Running" }
  }
} else {
  Note "no Keeper Gateway Windows service found (Docker Desktop deployment? check the docker section)"
}

# ---- event logs (rotation/connection errors land here) --------------------
Write-Host "[*] Event logs"
$evtFile = Join-Path $out 'events\application-errors.txt'
Cap $evtFile -Redact {
  Get-WinEvent -FilterHashtable @{ LogName='Application'; Level=1,2,3 } -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -match 'Keeper|Gateway|guac' -or $_.Message -match 'Keeper|gateway|rotat|WinRM' } |
    Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message | Format-List
}
# WinRM config is the rotation transport on Windows targets
Cap (Join-Path $out 'service\winrm.txt') { winrm get winrm/config 2>&1 }

# ---- network --------------------------------------------------------------
Write-Host "[*] Network"
$netFile = Join-Path $out 'network\host-network.txt'
Cap $netFile { Get-NetIPConfiguration -Detailed }
Cap $netFile { Get-NetRoute -AddressFamily IPv4 | Select-Object DestinationPrefix,NextHop,RouteMetric,ifIndex }
Cap $netFile { Get-DnsClientServerAddress }
if (-not $Minimal) {
  Cap $netFile { Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess | Sort-Object LocalPort }
  Cap (Join-Path $out 'network\firewall.txt') { Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultOutboundAction,DefaultInboundAction }
} else {
  Add-Content $netFile "(listening sockets / firewall detail skipped: -Minimal)"
}

# ---- outbound reachability ------------------------------------------------
if (-not $NoNetwork) {
  Write-Host "[*] Outbound reachability"
  $rf = Join-Path $out 'network\reachability.txt'
  @(
    "Required outbound egress (Keeper docs; gateway is outbound-only):",
    "  TCP 443             -> $Router (router) + $Cloud (cloud)",
    "  TCP+UDP 3478        -> $Relay (STUN/TURN)",
    "  TCP+UDP 49152-65535 -> WebRTC media (range; verify firewall allows it)",
    "  -- probe results --"
  ) | Add-Content $rf
  foreach ($hp in @(@($Router,443), @($Cloud,443), @($Relay,3478))) {
    $ok = Test-Tcp -ComputerName $hp[0] -Port $hp[1]
    Add-Content $rf ("TCP {0}:{1} -> {2}" -f $hp[0], $hp[1], $(if ($ok){'OPEN'}else{'BLOCKED'}))
    if (-not $ok) { Note "WARN: $($hp[0]):$($hp[1]) not reachable" }
  }
  # TLS cert of the router
  try {
    $tcp = [System.Net.Sockets.TcpClient]::new($Router, 443)
    $ssl = [System.Net.Security.SslStream]::new($tcp.GetStream(), $false, ({ $true }))
    $ssl.AuthenticateAsClient($Router)
    $cert = $ssl.RemoteCertificate
    Add-Content $rf "TLS $Router issuer=$($cert.Issuer) notAfter=$($cert.GetExpirationDateString())"
    $ssl.Dispose(); $tcp.Close()
  } catch { Add-Content $rf "TLS check to $Router failed: $_" }
}

# ---- gateway health endpoint ---------------------------------------------
Write-Host "[*] Gateway health endpoint"
$hcPort = if ($env:KEEPER_GATEWAY_HEALTH_CHECK_PORT) { $env:KEEPER_GATEWAY_HEALTH_CHECK_PORT } else { 8099 }
try {
  $h = Invoke-WebRequest -Uri "http://127.0.0.1:$hcPort/health" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
  Set-Content (Join-Path $out 'service\health.json') (Protect-Secrets $h.Content)
  if ($h.Content -match '"under_pressure"\s*:\s*true')   { Note "WARN: gateway reports UNDER PRESSURE -- scale CPU/RAM (slow/refused RBI)" }
  if ($h.Content -match '"can_accept_rbi"\s*:\s*false')  { Note "WARN: gateway reports can_accept_rbi=false -- refusing/degrading RBI now" }
  if ($h.Content -match '"latency_ms"\s*:\s*(\d+)')      { Note "control-plane websocket latency=$($Matches[1])ms" }
} catch {
  Note "TIP: health endpoint not reachable on :$hcPort (set KEEPER_GATEWAY_HEALTH_CHECK_ENABLED=true for websocket latency/pressure signals)"
}

# ---- target reachability (rotation/connection) ----------------------------
if ($Target) {
  Write-Host "[*] Target test: $Target"
  $th,$tp = $Target -split ':',2
  $tf = Join-Path $out 'network\target.txt'
  try {
    $dns = Resolve-DnsName $th -ErrorAction Stop | Select-Object Name,IPAddress
    Add-Content $tf "DNS $th -> $($dns.IPAddress -join ',')"
  } catch { Add-Content $tf "DNS resolution of $th FAILED: $_" }
  if ($tp) {
    $ok = Test-Tcp -ComputerName $th -Port $tp
    Add-Content $tf ("TCP {0}:{1} -> {2}" -f $th, $tp, $(if ($ok){'reachable'}else{'NOT reachable'}))
    if (-not $ok) { Note "rotation/connection target $Target not reachable (DNS or routing) -- see network/target.txt" }
  }
}

# ---- docker (Docker Desktop on Windows) -----------------------------------
if (Get-Command docker -ErrorAction SilentlyContinue) {
  Write-Host "[*] Docker"
  Cap (Join-Path $out 'docker\version.txt') { docker version }
  if ($Minimal) {
    Cap (Join-Path $out 'docker\ps.txt') { docker ps -a | Select-String -Pattern 'keeper|gateway|guac|NAMES' }
  } else {
    Cap (Join-Path $out 'docker\ps.txt') { docker ps -a }
  }
  $gw = (docker ps --format '{{.Names}} {{.Image}}' 2>$null | Select-String 'keeper/gateway|keepersecurityinc/gateway' | ForEach-Object { ($_ -split ' ')[0] } | Select-Object -First 1)
  if ($gw) {
    Cap (Join-Path $out 'docker\inspect.json') -Redact { docker inspect $gw }
    Cap (Join-Path $out 'docker\logs.txt') -Redact { docker logs --tail 2000 $gw }
    Note "gateway container (Docker Desktop): $gw"
  }
}

# ---- collection notice + secret scan + zip --------------------------------
$mode = if ($Minimal) { 'MINIMAL' } else { 'FULL' }
@"
COLLECTION NOTICE -- read before sharing this bundle
Generated: $(Get-Date)   Mode: $mode   Platform: Windows

CONTAINS: host info, gateway service + event logs, network (interfaces/routes/
DNS/firewall/sockets), reachability, health endpoint, target test, docker (if any).
DOES NOT CONTAIN: gateway config / GATEWAY_CONFIG payload, secret values
(redacted -> [REDACTED]). Broad host detail is captured; prefer -Minimal for
third parties. Secrets are redacted best-effort + scanned (see REDACTION-SCAN.txt).
"@ | Set-Content (Join-Path $out 'COLLECTION-NOTICE.txt')

Write-Host "[*] Secret scan"
$scan = Join-Path $out 'REDACTION-SCAN.txt'
$pat = '(?i)(-----BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}|://[^:/@\s]+:[^@/\s]+@|(GATEWAY_CONFIG|KCM_LICENSE|[A-Za-z0-9_]*(PASSWORD|PASSWD|PWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|PASSPHRASE|CREDENTIALS?|_KEY|_SEED|SEED))`"?\s*[:=]\s*`"?[^\s`",}]{6,})'
$hits = Get-ChildItem -Path $out -Recurse -File | Where-Object { $_.Name -ne 'REDACTION-SCAN.txt' } |
  Select-String -Pattern $pat | Where-Object { $_.Line -notmatch 'REDACTED' }
if ($hits) {
  $hits | ForEach-Object { "$($_.Filename):$($_.LineNumber): $($_.Line.Trim())" } | Set-Content $scan
  Note "WARN: secret-scan flagged $($hits.Count) line(s) that may be UNREDACTED -- review REDACTION-SCAN.txt before sharing"
} else {
  Set-Content $scan "no residual secret patterns detected ($(Get-Date))"
  Note "secret-scan: clean (no residual secret patterns detected)"
}

Write-Host "`n[*] Packaging"
$zip = "$out.zip"
try { Compress-Archive -Path $out -DestinationPath $zip -Force; Write-Host "Bundle: $zip" }
catch { Write-Host "Compress-Archive failed; the folder is still at $out" }

Write-Host "`nSummary"
if ($Notes.Count -eq 0) { Write-Host "  (no notable flags)" }
Write-Host "`nReview the bundle before sharing externally. Secrets are redacted best-effort + scanned."
