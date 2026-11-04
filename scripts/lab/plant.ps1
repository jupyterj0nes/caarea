$ErrorActionPreference = 'Continue'
# Plants persistence and executions on a lab host, the way an intruder leaves them,
# so faramir and caarea can be scored against a known truth. Everything is undone by
# cleanup.ps1. Lab only.
$pub = 'C:\Users\Public'
$pd = 'C:\ProgramData\rfsvc'
New-Item -ItemType Directory -Force $pd | Out-Null
New-Item -ItemType Directory -Force 'C:\Windows\Temp\rf2' | Out-Null
Copy-Item C:\Windows\System32\cmd.exe "$pub\rfupd.exe" -Force
Copy-Item C:\Windows\System32\cmd.exe "$pub\svchost.exe" -Force
Copy-Item C:\Windows\System32\cmd.exe "$pub\invoice.pdf.exe" -Force
Copy-Item C:\Windows\System32\cmd.exe "$pd\svc.exe" -Force
Copy-Item C:\Windows\System32\cmd.exe 'C:\Windows\Temp\a8f3k2q9.exe' -Force
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Start-Sleep -Seconds 1'))

# ── persistence (faramir) ──
# P1 HKLM Run
reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' /v rf-updater /t REG_SZ /d "$pub\rfupd.exe -s" /f | Out-Null
# P2 HKCU Run of the administrator, encoded PowerShell
reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' /v rf-sync /t REG_SZ /d "powershell.exe -nop -w hidden -enc $enc" /f | Out-Null
# P3 service
& sc.exe create RfSvc binPath= "$pd\svc.exe" start= auto DisplayName= "RF Update Service" | Out-Null
# P4 scheduled task under a Microsoft-looking folder, never due
& schtasks /Create /TN '\Microsoft\Windows\RfMaint\Cleanup' /TR "$pub\rfupd.exe -t" /SC ONCE /ST 23:59 /SD 12/31/2030 /RU SYSTEM /F | Out-Null
# P5 IFEO debugger on sethc.exe
reg add 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe' /v Debugger /t REG_SZ /d 'C:\Windows\System32\cmd.exe' /f | Out-Null
# P6 Userinit with a second program (the original value kept for cleanup.ps1)
(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon').Userinit | Set-Content 'C:\Windows\Temp\rf2\userinit.txt'
reg add 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' /v Userinit /t REG_SZ /d "C:\Windows\system32\userinit.exe,$pub\rfupd.exe" /f | Out-Null
# P7 all-users startup folder script
$su = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp'
Set-Content -Path "$su\rf-start.bat" -Value "@powershell.exe -w hidden -c `"Start-Sleep 1`""
# P8 HKLM RunOnce with a double extension
reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' /v rf-once /t REG_SZ /d "$pub\invoice.pdf.exe" /f | Out-Null
# P9 WMI permanent event subscription
$f = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{Name='RfFilter'; EventNamespace='root\cimv2'; QueryLanguage='WQL'; Query="SELECT * FROM __InstanceModificationEvent WITHIN 3600 WHERE TargetInstance ISA 'Win32_LocalTime'"}
$c = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{Name='RfConsumer'; CommandLineTemplate="powershell.exe -nop -c Start-Sleep 1"}
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{Filter=$f; Consumer=$c} | Out-Null
Write-Output 'persistence planted'

# ── executions (caarea): process creation with command lines on, then the runs ──
& auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null
reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f | Out-Null
Start-Sleep -Seconds 2
# E1 the dropper from Users\Public
& cmd.exe /c "$pub\rfupd.exe /c exit"
# E2 a system binary name outside its folder
& cmd.exe /c "$pub\svchost.exe /c exit"
# E3 a random name from Windows\Temp
& cmd.exe /c "C:\Windows\Temp\a8f3k2q9.exe /c exit"
# E4 encoded PowerShell from cmd
& cmd.exe /c "powershell.exe -nop -w hidden -enc $enc"
# E5 the service binary from ProgramData
& cmd.exe /c "$pd\svc.exe /c exit"
# E6 a double extension
& cmd.exe /c "$pub\invoice.pdf.exe /c exit"
# E7 certutil decoding a file (LOLBin)
Set-Content -Path "$pub\rf.b64" -Value $enc
& cmd.exe /c "certutil -decode $pub\rf.b64 $pub\rf.bin"
# E8 rundll32 with a non-dll
& cmd.exe /c "rundll32.exe $pub\rf.bin,Start"
Start-Sleep -Seconds 3
Write-Output 'executions done'
