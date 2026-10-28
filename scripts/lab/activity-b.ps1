# Phase B: anti-forensics after a shadow copy exists. Deletes what phase A created, clears
# logs, removes a prefetch file. What is gone live must come back from the VSS snapshot,
# from freed hive cells, from $MFT/$UsnJrnl, or from carving.
$ErrorActionPreference = 'Continue'
$log = 'C:\RangeForge\caarea-activity.log'
function Log($m) { $line = "$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')) $m"; $line; Add-Content -Path $log -Value $line }

Log '=== phase B start ==='
Log 'shadow copy of the pre-clean-up state'
vssadmin create shadow /for=C: 2>&1 | Select-String 'Shadow Copy ID|Error' | ForEach-Object { Log $_.Line.Trim() }
Log ('shadow copies now: ' + ((vssadmin list shadows | Select-String 'Shadow Copy ID').Count))

Log 'delete scheduled task (4699 / TaskScheduler 141, TaskCache cell freed)'
schtasks /delete /tn "CaareaLabTask" /f | Out-Null

Log 'delete service (Services key freed)'
sc.exe delete CaareaSvc | Out-Null

Log 'remove WMI permanent consumer'
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Where-Object { $_.Filter -like '*CaareaFilter*' } | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='CaareaConsumer'" | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='CaareaFilter'" | Remove-WmiObject

Log 'remove run key value'
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v CaareaRun /f | Out-Null

Log 'delete the dropped binary and its prefetch file'
Remove-Item C:\Temp\caarea-test.exe -Force -ErrorAction SilentlyContinue
Get-ChildItem C:\Windows\Prefetch -Filter 'CAAREA-TEST.EXE-*.pf' | ForEach-Object { Log "deleting $($_.Name)"; Remove-Item $_.FullName -Force }

Log 'clear logs: Security (1102), BITS and Windows PowerShell (104)'
wevtutil cl Security
wevtutil cl 'Microsoft-Windows-Bits-Client/Operational'
wevtutil cl 'Windows PowerShell'

Log 'truncate PowerShell history'
$hist = Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
Set-Content -Path $hist -Value 'cls'

Log 'activity after the clean-up so the live logs are not empty'
whoami | Out-Null
hostname | Out-Null
powershell.exe -NoProfile -Command "Get-Date | Out-Null" | Out-Null
schtasks /create /tn "CaareaAfterCleanup" /tr "cmd.exe /c echo after > C:\Temp\after.txt" /sc once /st 23:58 /ru SYSTEM /f | Out-Null
Log 'second shadow copy (post clean-up)'
vssadmin create shadow /for=C: 2>&1 | Select-String 'Shadow Copy ID|Error' | ForEach-Object { Log $_.Line.Trim() }
Log ('shadow copies now: ' + ((vssadmin list shadows | Select-String 'Shadow Copy ID').Count))
Log '=== phase B done ==='
