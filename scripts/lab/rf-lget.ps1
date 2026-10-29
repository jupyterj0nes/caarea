<#
.SYNOPSIS
  Pull files from a Linux RangeForge host as a tar.gz carried in base64 on the SSH stdout
  (gcloud's scp uses pscp through the IAP tunnel and drops).

.EXAMPLE
  .\rf-lget.ps1 -Instance rf-1a182f1b960-leo-lnx01 -Paths '/var/log/journal','/var/log/apt' -Dest D:\cases\lnx01.tgz
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Instance,
    [Parameter(Mandatory)] [string[]] $Paths,
    [Parameter(Mandatory)] [string] $Dest,
    [string] $Project = 'project-239e9680-1102-4329-a27',
    [string] $Zone = 'europe-west1-d'
)
$ErrorActionPreference = 'Stop'
$list = ($Paths | ForEach-Object { "'$_'" }) -join ' '
$remote = "sudo tar czf - --ignore-failed-read $list 2>/dev/null | base64 -w0; echo; echo __RF_END__"
$out = Join-Path $env:TEMP ("rf-lget-{0}.txt" -f [guid]::NewGuid().ToString('N'))
& gcloud compute ssh $Instance --tunnel-through-iap --zone=$Zone --project=$Project --quiet --command $remote > $out 2>$null
$text = Get-Content $out -Raw
Remove-Item $out -ErrorAction SilentlyContinue
$b64 = ($text -split '__RF_END__')[0] -replace '[^A-Za-z0-9+/=]', ''
if ($b64.Length -lt 100) { throw "nothing received from $Instance" }
[IO.File]::WriteAllBytes($Dest, [Convert]::FromBase64String($b64))
"saved $Dest ($((Get-Item $Dest).Length) bytes) sha256 $((Get-FileHash $Dest -Algorithm SHA256).Hash)"
