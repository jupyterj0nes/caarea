<#
.SYNOPSIS
  Upload a file or folder to a Windows RangeForge host as a zip carried in base64 inside a
  PowerShell script on the SSH stdin (scp through the IAP tunnel is unreliable).

.EXAMPLE
  .\rf-put.ps1 -Instance rf-1a182f1b960-dev-srv01 -Source .\target\release\caarea.exe -RemoteDir C:\RangeForge\inbox
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Instance,
    [Parameter(Mandatory)] [string] $Source,
    [string] $RemoteDir = 'C:\RangeForge\inbox',
    [string] $Project = 'project-239e9680-1102-4329-a27',
    [string] $Zone = 'europe-west1-d'
)
$ErrorActionPreference = 'Stop'
$zip = Join-Path $env:TEMP ("rf-put-{0}.zip" -f [guid]::NewGuid().ToString('N'))
Compress-Archive -Path $Source -DestinationPath $zip -Force
$b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($zip))
Remove-Item $zip -ErrorAction SilentlyContinue
$name = Split-Path $Source -Leaf
$script = @"
`$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force '$RemoteDir' | Out-Null
`$zip = Join-Path '$RemoteDir' 'rf-put.zip'
[IO.File]::WriteAllBytes(`$zip, [Convert]::FromBase64String('$b64'))
Expand-Archive -Path `$zip -DestinationPath '$RemoteDir' -Force
Remove-Item `$zip -Force
Get-ChildItem '$RemoteDir' | Where-Object Name -like '$name*' | ForEach-Object { "uploaded `$(`$_.FullName) `$(`$_.Length) bytes sha256 `$((Get-FileHash `$_.FullName -Algorithm SHA256).Hash)" }
"@
$tmp = Join-Path $env:TEMP ("rf-put-{0}.ps1" -f [guid]::NewGuid().ToString('N'))
Set-Content -Path $tmp -Value $script -Encoding UTF8
try {
    & (Join-Path $PSScriptRoot 'rf-ps.ps1') -Instance $Instance -File $tmp -Project $Project -Zone $Zone
    "local sha256 $((Get-FileHash $Source -Algorithm SHA256).Hash)"
} finally {
    Remove-Item $tmp -ErrorAction SilentlyContinue
}
