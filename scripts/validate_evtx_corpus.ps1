<#
.SYNOPSIS
  Compares caarea's EVTX output with Get-WinEvent, file by file, for every supported
  (provider, event id) pair. Prints the files whose counts differ.

.EXAMPLE
  .\validate_evtx_corpus.ps1 -Corpus C:\corpus\evtx_attack, C:\corpus\evtx_mitre -Caarea .\target\release\caarea.exe
#>
param(
    [Parameter(Mandatory)] [string[]] $Corpus,
    [string] $Caarea = (Join-Path $PSScriptRoot '..\target\release\caarea.exe'),
    [string] $Work = (Join-Path $env:TEMP 'caarea_evtx_validate')
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force $Work | Out-Null

# Mirror of classify_event in src/parsers/evtx.rs
function Supported($provider, $id) {
    $p = ([string]$provider).ToLowerInvariant()
    $unknown = [string]::IsNullOrEmpty($p)
    switch ($id) {
        { $_ -in 4688, 4689, 4697, 4698, 4699, 4700, 4701, 4702 } { return ($unknown -or $p.Contains('security-auditing')) }
        1102 { return ($unknown -or $p.Contains('eventlog')) }
        { $_ -in 7045, 7034, 7036 } { return ($unknown -or $p.Contains('service control manager')) }
        104 { return $p.Contains('eventlog') }
        { $_ -in 1033, 1034, 11707, 11724 } { return $p.Contains('msiinstaller') }
        1000 { return $p.Contains('application error') }
        1001 { return $p.Contains('windows error reporting') }
        { $_ -in 400, 800 } { return ($unknown -or $p -eq 'powershell') }
        { $_ -in 4103, 4104 } { return ($unknown -or $p.Contains('microsoft-windows-powershell')) }
        { $_ -in 9707, 9708 } { return $p.Contains('shell-core') }
        { $_ -in 8002, 8003, 8004, 8005, 8006, 8007, 8020, 8021, 8022 } { return $p.Contains('applocker') }
        { $_ -in 1015, 1116, 1117 } { return $p.Contains('windows defender') }
        { $_ -in 1, 5, 6, 7, 11 } { return $p.Contains('sysmon') }
        { $_ -in 100, 102, 106, 107, 108, 118, 119, 129, 140, 141, 200, 201 } { return $p.Contains('taskscheduler') }
        { $_ -in 5857, 5858, 5859, 5860, 5861 } { return $p.Contains('wmi-activity') }
        { $_ -in 3, 4, 59, 60 } { return $p.Contains('bits-client') }
    }
    return $false
}

$files = Get-ChildItem -Path $Corpus -Recurse -Filter *.evtx
$total = 0; $mismatch = 0; $expectedAll = 0; $gotAll = 0
foreach ($f in $files) {
    $total++
    $expected = 0
    try {
        $events = Get-WinEvent -Path $f.FullName -Oldest -ErrorAction Stop
        foreach ($e in $events) { if (Supported $e.ProviderName $e.Id) { $expected++ } }
    } catch {
        $events = @()
        if ($_.Exception.Message -notmatch 'No events were found') { Write-Host "SKIP (Get-WinEvent): $($f.Name): $($_.Exception.Message)"; continue }
    }
    # Counts come from caarea's own console summary: Defender quarantines CSVs that contain
    # offensive command lines, so the output file cannot be relied upon. Exact duplicate rows
    # (same ten columns) are collapsed by caarea; they are added back here so the comparison
    # is against the number of records parsed.
    $out = Join-Path $Work ($f.BaseName + '.csv')
    Remove-Item $out -ErrorAction SilentlyContinue
    $text = & $Caarea -f $f.FullName -o $out -m evtx 2>&1 | Out-String
    $got = 0
    if ($text -match 'Extracted a total of (\d+) execution events') { $got = [int]$Matches[1] }
    if ($text -match 'Removed (\d+) exact duplicate events') { $got += [int]$Matches[1] }
    $expectedAll += $expected; $gotAll += $got
    if ($got -ne $expected) {
        $mismatch++
        Write-Host ("DIFF {0,-70} expected={1,6} got={2,6}" -f $f.Name, $expected, $got)
    }
}
Write-Host ("files={0} mismatches={1} expected_total={2} got_total={3}" -f $total, $mismatch, $expectedAll, $gotAll)
