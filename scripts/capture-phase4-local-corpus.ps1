[CmdletBinding()]
param(
    [string]$OutputRoot,
    [int]$Port = 18765,
    [int]$CaptureSeconds = 8,
    [uri]$RemoteUri
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = Join-Path $PSScriptRoot '..\tests\fixtures\forensics\phase4-local'
}

function Require-Command([string]$Name) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command '$Name' was not found. Install/enable the corresponding Windows component and retry."
    }
}

if ($IsWindows -eq $false) {
    throw 'This corpus collector must run on Windows.'
}

Require-Command 'wevtutil.exe'
Require-Command 'pktmon.exe'

$sysmonChannel = 'Microsoft-Windows-Sysmon/Operational'
$sysmonLog = Get-WinEvent -ListLog $sysmonChannel -ErrorAction SilentlyContinue
if ($null -eq $sysmonLog -or -not $sysmonLog.IsEnabled) {
    throw "The '$sysmonChannel' log is unavailable or disabled. Install/configure Sysmon first; this script does not change event-log configuration."
}

$runId = Get-Date -Format 'yyyyMMdd-HHmmss'
$runDir = Join-Path ([IO.Path]::GetFullPath($OutputRoot)) $runId
New-Item -ItemType Directory -Path $runDir -Force | Out-Null

$sysmonPath = Join-Path $runDir 'sysmon.evtx'
$pcapngPath = Join-Path $runDir 'traffic.pcapng'
$pktmonEtl = Join-Path $runDir 'traffic.etl'
$manifestPath = Join-Path $runDir 'manifest.json'

trap {
    $_ | Out-File -FilePath (Join-Path $runDir 'collector-error.txt') -Encoding utf8
    break
}

$hostname = [Environment]::MachineName
$defaultInterface = Get-NetIPConfiguration |
    Where-Object { $_.IPv4DefaultGateway } |
    Select-Object -First 1
$ipv4 = if ($defaultInterface) {
    $defaultInterface.IPv4Address.IPAddress
} else {
    Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -ne '0.0.0.0' -and $_.AddressState -eq 'Preferred' } |
        Select-Object -First 1 -ExpandProperty IPAddress
}
$listenAddress = if ($ipv4) { $ipv4 } else { '127.0.0.1' }
$endpointHost = '127.0.0.1'
$endpointPort = $Port
$containerName = "soc-dfir-phase4-$runId"
$docker = Get-Command docker.exe -ErrorAction SilentlyContinue
$containerStarted = $false

Write-Host "Output: $runDir"
Write-Host "Host: $hostname; preferred IPv4: $ipv4"
Write-Host 'Starting pktmon capture (port filter is local to this test service)...'

& pktmon filter remove | Out-Null
& pktmon filter add -p $Port | Out-Null
& pktmon start --capture --pkt-size 0 --file-name $pktmonEtl | Out-Null

$job = $null
if ($RemoteUri) {
    $endpointHost = $RemoteUri.Host
    $endpointPort = if ($RemoteUri.Port -gt 0) { $RemoteUri.Port } elseif ($RemoteUri.Scheme -eq 'https') { 443 } else { 80 }
    & pktmon filter add -p $endpointPort | Out-Null
} elseif ($docker) {
    Write-Host "Starting isolated local Docker HTTP endpoint: $containerName"
    & $docker.Source run --rm --detach --name $containerName --publish "${ipv4}:${Port}:8000" `
        python:3.11-alpine python -m http.server 8000 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Docker failed to start the local HTTP endpoint (exit code $LASTEXITCODE)."
    }
    $endpointHost = $ipv4
    $endpointPort = $Port
    $containerStarted = $true
} else {
    $job = Start-Job -ScriptBlock {
        param([int]$ListenPort, [string]$ListenAddress)
        $listener = [Net.HttpListener]::new()
        $listener.Prefixes.Add("http://$ListenAddress`:$ListenPort/")
        $listener.Start()
        try {
            while ($true) {
                $context = $listener.GetContext()
                $body = [Text.Encoding]::UTF8.GetBytes('soc-dfir phase4 local corpus')
                $context.Response.StatusCode = 200
                $context.Response.ContentType = 'text/plain'
                $context.Response.ContentLength64 = $body.Length
                $context.Response.OutputStream.Write($body, 0, $body.Length)
                $context.Response.Close()
            }
        } finally {
            $listener.Stop()
            $listener.Close()
        }
    } -ArgumentList $Port, $listenAddress
}

try {
    Start-Sleep -Milliseconds 500
    $uri = if ($RemoteUri) { $RemoteUri.AbsoluteUri } else { "http://$endpointHost`:$endpointPort/?host=$hostname" }
    $response = Invoke-WebRequest -Uri $uri -UseBasicParsing
    if ($response.StatusCode -ne 200) {
        throw "Local test request returned HTTP $($response.StatusCode)."
    }
    Start-Sleep -Seconds $CaptureSeconds
}
finally {
    if ($job) {
        Stop-Job $job -ErrorAction SilentlyContinue | Out-Null
        Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
    if ($containerStarted) {
        & $docker.Source rm --force $containerName | Out-Null
    }
    & pktmon stop | Out-Null
    & pktmon etl2pcap $pktmonEtl --out $pcapngPath | Out-Null
}

if (-not (Test-Path $pcapngPath)) {
    throw "pktmon did not produce '$pcapngPath'. Run this script from an elevated PowerShell if capture access is denied."
}

# Export only the recent window. The source remains a genuine EVTX file; no
# JSON/event rewriting is performed. Sysmon event configuration is left intact.
$query = '*[System[TimeCreated[timediff(@SystemTime) <= 900000]]]'
& wevtutil.exe epl $sysmonChannel $sysmonPath '/ow:true' "/q:$query"
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $sysmonPath)) {
    throw "wevtutil failed to export the recent Sysmon window (exit code $LASTEXITCODE)."
}

$manifest = [ordered]@{
    schema = 'soc-dfir.phase4.local-corpus/v1'
    created_utc = [DateTime]::UtcNow.ToString('o')
    hostname = $hostname
    preferred_ipv4 = $ipv4
    endpoint = if ($RemoteUri) { $RemoteUri.AbsoluteUri } else { "http://$endpointHost`:$endpointPort/" }
    scenario = if ($RemoteUri) { 'PowerShell Invoke-WebRequest to an explicitly supplied test endpoint while pktmon captures the real packets.' } else { 'PowerShell Invoke-WebRequest to an isolated local Docker HTTP endpoint while pktmon captures the real packets.' }
    files = [ordered]@{
        sysmon_evtx = 'sysmon.evtx'
        traffic_pcapng = 'traffic.pcapng'
    }
    collection = [ordered]@{
        sysmon_channel = $sysmonChannel
        capture_tool = 'pktmon'
        capture_seconds_after_request = $CaptureSeconds
        filtered_port = $Port
    }
}
$manifest | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 $manifestPath

Write-Host "Created genuine EVTX: $sysmonPath"
Write-Host "Created genuine PCAPNG: $pcapngPath"
Write-Host "Manifest: $manifestPath"
Write-Host ''
Write-Host 'Next: set SOCDFIR_PHASE4_LOCAL_CORPUS to this directory and run:'
Write-Host '  cargo test -p engine-server --test phase4_local_corpus_test -- --nocapture'
