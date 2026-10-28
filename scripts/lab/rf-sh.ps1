<#
.SYNOPSIS
  Run a shell command on a Linux host of a live RangeForge range (through IAP).

.EXAMPLE
  .\rf-sh.ps1 -Instance rf-1a182f1b960-leo-lnx01 -Command 'sudo ls -la /var/log; sudo journalctl --disk-usage'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Instance,
    [Parameter(Mandatory)] [string] $Command,
    [string] $Project = 'project-239e9680-1102-4329-a27',
    [string] $Zone = 'europe-west1-d'
)
$ErrorActionPreference = 'Stop'
& gcloud compute ssh $Instance --tunnel-through-iap --zone=$Zone --project=$Project --quiet `
    --ssh-flag='-o LogLevel=ERROR' --command $Command
