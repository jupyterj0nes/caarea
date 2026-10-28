<#
.SYNOPSIS
  Generates a real Microsoft-Windows-TaskScheduler/Operational sample (events 106, 129, 200, 201,
  141) on this machine and runs caarea against it.

.DESCRIPTION
  The TaskScheduler operational channel is disabled by default on Windows clients, so no public
  EVTX corpus carries 106/200 events. This script:
    1. enables the channel (asks for elevation once, UAC prompt),
    2. registers a harmless scheduled task, runs it and deletes it,
    3. exports the channel to an EVTX next to this script,
    4. runs caarea on the export and prints the TaskScheduler rows.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\gen_taskscheduler_sample.ps1
#>
param(
    [string]$OutDir = (Join-Path $PSScriptRoot "..\samples\taskscheduler"),
    [string]$Caarea = (Join-Path $PSScriptRoot "..\target\release\caarea.exe")
)

$ErrorActionPreference = "Stop"
$log = "Microsoft-Windows-TaskScheduler/Operational"
$taskName = "CAAREA_TaskScheduler_Sample"
New-Item -ItemType Directory -Force $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path

function Test-LogEnabled {
    (& wevtutil.exe gl $log | Select-String -Pattern 'enabled:\s*true' -Quiet)
}

if (-not (Test-LogEnabled)) {
    Write-Host "[1/4] Enabling $log (elevation required, accept the UAC prompt)..."
    Start-Process -FilePath wevtutil.exe -ArgumentList "sl `"$log`" /e:true" -Verb RunAs -Wait
    if (-not (Test-LogEnabled)) { throw "The channel is still disabled. Run this script from an elevated prompt." }
} else {
    Write-Host "[1/4] $log already enabled"
}

Write-Host "[2/4] Registering, running and deleting task '$taskName'..."
& schtasks.exe /Delete /TN $taskName /F 2>$null | Out-Null
& schtasks.exe /Create /TN $taskName /TR "cmd.exe /c echo caarea-taskscheduler-sample" /SC ONCE /ST 23:59 /F | Out-Null
& schtasks.exe /Run /TN $taskName | Out-Null
Start-Sleep -Seconds 5
& schtasks.exe /Delete /TN $taskName /F | Out-Null

Write-Host "[3/4] Exporting the channel..."
$evtx = Join-Path $OutDir "Microsoft-Windows-TaskScheduler%4Operational.evtx"
if (Test-Path $evtx) { Remove-Item $evtx -Force }
& wevtutil.exe epl $log $evtx
$ids = Get-WinEvent -Path $evtx -ErrorAction SilentlyContinue | Where-Object { $_.Message -like "*$taskName*" } | Group-Object Id | Sort-Object Name
Write-Host ("      events for the sample task: " + (($ids | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join ", "))

if (Test-Path $Caarea) {
    Write-Host "[4/4] Running caarea..."
    $csv = Join-Path $OutDir "taskscheduler_timeline.csv"
    & $Caarea -f $evtx -m evtx -o $csv --overwrite -s
    Import-Csv $csv | Where-Object { $_.artifact -like "evtx:taskscheduler:*" } |
        Select-Object timestamp, artifact, pid, subject_username, processname, commandline |
        Format-Table -AutoSize -Wrap | Out-String -Width 220
} else {
    Write-Host "[4/4] caarea binary not found at $Caarea; build it with 'cargo build --release' and run: caarea -f `"$evtx`" -m evtx -o out.csv"
}
