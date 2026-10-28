<#
.SYNOPSIS
  Copy one file from a Windows RangeForge host over the IAP tunnel, as base64 on an SSH
  stdout stream (scp/sftp through the tunnel drop on long streams; a text stream does not).

.EXAMPLE
  .\rf-get.ps1 -Instance rf-1a182f1b960-dev-srv01 -RemotePath 'C:\RangeForge\x.zip' -Dest D:\cases\x.zip
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Instance,
    [Parameter(Mandatory)] [string] $RemotePath,
    [Parameter(Mandatory)] [string] $Dest,
    [string] $Project = 'project-239e9680-1102-4329-a27',
    [string] $Zone = 'europe-west1-d'
)
$ErrorActionPreference = 'Stop'
$key = Join-Path $env:APPDATA 'rangeforge\rf_ed25519'
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$listener.Start(); $Port = $listener.LocalEndpoint.Port; $listener.Stop()
$tunnelLog = Join-Path $env:TEMP "rf-tunnel-$Instance-$Port.log"
$gcloudArgs = "gcloud.cmd compute start-iap-tunnel $Instance 22 --local-host-port=localhost:$Port --zone=$Zone --project=$Project"
$tunnel = Start-Process -FilePath 'cmd.exe' -ArgumentList @('/c', $gcloudArgs) -PassThru -WindowStyle Hidden -RedirectStandardError $tunnelLog
try {
    $ready = $false
    for ($i = 0; $i -lt 60 -and -not $ready; $i++) {
        Start-Sleep -Milliseconds 500
        try { $c = [System.Net.Sockets.TcpClient]::new(); $c.Connect('127.0.0.1', $Port); $c.Close(); $ready = $true } catch { }
        if ($tunnel.HasExited) { throw "IAP tunnel exited: $(Get-Content $tunnelLog -Raw)" }
    }
    if (-not $ready) { throw "IAP tunnel did not open on port $Port" }
    $b64 = Join-Path $env:TEMP "rf-get-$Port.b64"
    $remote = "powershell -NoProfile -NonInteractive -Command `"[Convert]::ToBase64String([IO.File]::ReadAllBytes('$RemotePath'))`""
    $sshCmd = "ssh -i `"$key`" -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -o LogLevel=ERROR -o ServerAliveInterval=30 -o ServerAliveCountMax=20 -p $Port Administrator@127.0.0.1 `"$remote`" > `"$b64`""
    & cmd.exe /c $sshCmd
    if ($LASTEXITCODE -ne 0) { throw "ssh exit code $LASTEXITCODE" }
    $text = (Get-Content $b64 -Raw) -replace '\s', ''
    [IO.File]::WriteAllBytes($Dest, [Convert]::FromBase64String($text))
    Remove-Item $b64 -ErrorAction SilentlyContinue
    $sha = (Get-FileHash $Dest -Algorithm SHA256).Hash
    "saved $Dest ($((Get-Item $Dest).Length) bytes) sha256 $sha"
}
finally {
    if ($tunnel -and -not $tunnel.HasExited) { & taskkill /PID $tunnel.Id /T /F 2>&1 | Out-Null }
    Remove-Item $tunnelLog -ErrorAction SilentlyContinue
}
