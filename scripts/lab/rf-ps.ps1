<#
.SYNOPSIS
  Run a PowerShell script block on a Windows host of a live RangeForge range.

.DESCRIPTION
  Opens an IAP tunnel to port 22 of the instance, connects with RangeForge's own
  ed25519 key as Administrator and runs the script through `powershell -EncodedCommand`.
  Output comes back on stdout. Used to generate real execution artifacts on lab hosts
  (prefetch, tasks, PowerShell history, services, VSS snapshots) before collecting them.

.EXAMPLE
  .\rf-ps.ps1 -Instance rf-1a182f1b960-dev-srv01 -Script { hostname; Get-Date }
  .\rf-ps.ps1 -Instance rf-1a182f1b960-dev-srv01 -File .\activity-windows.ps1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Instance,
    [scriptblock] $Script,
    [string] $File,
    [string] $Project = 'project-239e9680-1102-4329-a27',
    [string] $Zone = 'europe-west1-d',
    [int] $Port = 0,
    [int] $TimeoutSec = 1800
)

$ErrorActionPreference = 'Stop'
if (-not $Script -and -not $File) { throw 'Give -Script or -File' }
$body = if ($File) { Get-Content -Raw $File } else { $Script.ToString() }

$key = Join-Path $env:APPDATA 'rangeforge\rf_ed25519'
if (-not (Test-Path $key)) { throw "RangeForge key not found: $key" }

if ($Port -eq 0) {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start(); $Port = $listener.LocalEndpoint.Port; $listener.Stop()
}

$tunnelLog = Join-Path $env:TEMP "rf-tunnel-$Instance-$Port.log"
# gcloud is a .cmd shim: it has to be started through cmd.exe, and killed as a tree.
$gcloudArgs = "gcloud.cmd compute start-iap-tunnel $Instance 22 --local-host-port=localhost:$Port --zone=$Zone --project=$Project"
$tunnel = Start-Process -FilePath 'cmd.exe' -ArgumentList @('/c', $gcloudArgs) `
    -PassThru -WindowStyle Hidden -RedirectStandardError $tunnelLog

try {
    $ready = $false
    for ($i = 0; $i -lt 60 -and -not $ready; $i++) {
        Start-Sleep -Milliseconds 500
        try {
            $c = [System.Net.Sockets.TcpClient]::new()
            $c.Connect('127.0.0.1', $Port); $c.Close(); $ready = $true
        } catch { }
        if ($tunnel.HasExited) { throw "IAP tunnel exited: $(Get-Content $tunnelLog -Raw)" }
    }
    if (-not $ready) { throw "IAP tunnel did not open on port $Port" }

    # The script travels on stdin (`-Command -`): cmd.exe, the default OpenSSH shell on
    # Windows, caps a command line at 8191 characters, which an EncodedCommand exceeds fast.
    # ssh is run through cmd.exe so that the remote PowerShell's CLIXML error stream is not
    # parsed by the local PowerShell (it chokes on it and aborts the pipeline).
    $tmp = Join-Path $env:TEMP "rf-ps-$Port.ps1"
    Set-Content -Path $tmp -Value $body -Encoding UTF8
    $remote = 'powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command -'
    $sshCmd = "ssh -i `"$key`" -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -o LogLevel=ERROR -o ConnectTimeout=30 -o ServerAliveInterval=30 -o ServerAliveCountMax=20 -p $Port Administrator@127.0.0.1 `"$remote`" < `"$tmp`" 2>&1"
    & cmd.exe /c $sshCmd
    $code = $LASTEXITCODE
    Remove-Item $tmp -ErrorAction SilentlyContinue
    if ($code -ne 0) { Write-Warning "remote exit code $code" }
}
finally {
    if ($tunnel -and -not $tunnel.HasExited) { & taskkill /PID $tunnel.Id /T /F 2>&1 | Out-Null }
    Remove-Item $tunnelLog -ErrorAction SilentlyContinue
}
