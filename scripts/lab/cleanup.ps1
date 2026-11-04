$ErrorActionPreference = 'Continue'
# Undoes plant.ps1 and restores the audit policy.
reg delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' /v rf-updater /f 2>$null | Out-Null
reg delete 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' /v rf-sync /f 2>$null | Out-Null
& sc.exe delete RfSvc 2>$null | Out-Null
& schtasks /Delete /TN '\Microsoft\Windows\RfMaint\Cleanup' /F 2>$null | Out-Null
reg delete 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe' /f 2>$null | Out-Null
$orig = if (Test-Path 'C:\Windows\Temp\rf2\userinit.txt') { (Get-Content 'C:\Windows\Temp\rf2\userinit.txt' -Raw).Trim() } else { 'C:\Windows\system32\userinit.exe,' }
reg add 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' /v Userinit /t REG_SZ /d $orig /f | Out-Null
Remove-Item 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\rf-start.bat' -Force -ErrorAction SilentlyContinue
reg delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' /v rf-once /f 2>$null | Out-Null
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Where-Object { $_.Filter -like '*RfFilter*' } | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='RfConsumer'" | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='RfFilter'" | Remove-WmiObject
foreach ($p in 'C:\Users\Public\rfupd.exe', 'C:\Users\Public\svchost.exe', 'C:\Users\Public\invoice.pdf.exe', 'C:\Users\Public\rf.b64', 'C:\Users\Public\rf.bin', 'C:\Windows\Temp\a8f3k2q9.exe') { Remove-Item $p -Force -ErrorAction SilentlyContinue }
Remove-Item 'C:\ProgramData\rfsvc' -Recurse -Force -ErrorAction SilentlyContinue
& auditpol /set /subcategory:"Process Creation" /success:disable | Out-Null
reg delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' /v ProcessCreationIncludeCmdLine_Enabled /f 2>$null | Out-Null
Write-Output ('userinit now: ' + (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon').Userinit)
Write-Output ('run values: ' + ((Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run').Property -join ','))
Write-Output ('wmi filters: ' + (Get-WmiObject -Namespace root\subscription -Class __EventFilter | Measure-Object).Count)
Write-Output 'cleaned'
