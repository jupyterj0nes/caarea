<#
.SYNOPSIS
  Measures how often every hunt rule fires on stock, clean evidence and writes the table
  that feeds hunt_score (src/hunt/rarity.rs).

.DESCRIPTION
  hunt_score is rarity on masstin's scale, -10 * log10 of a probability. For a rule the
  probability is how often its pattern fires on the rows of the reference timelines: this
  script runs `caarea --hunt` over each reference evidence set, counts the hits of every rule
  pattern (signature + "/" + pattern of the findings table) on the rows that are not planted,
  and prints the MEASURED table; with -Write it rewrites the table and REFERENCE_ROWS in
  rarity.rs in place. Rules that never fired keep 0 hits (90 points).

  The lab scripts of scripts/lab plant activity on the RangeForge hosts; the rows they plant
  are recognised by $Planted and left out of the hits, not of the row count (a few dozen rows
  in thousands).

.EXAMPLE
  .\scripts\measure_rarity.ps1 -Caarea .\target\release\caarea.exe -Out D:\ref -Write `
      -Set 'dev-srv01=evtx:D:\datasets\rangeforge\dev-srv01-a\files', 'leo-lnx01=linux:D:\datasets\rangeforge\leo-lnx01'

  Each set is name=modules:evidence_dir.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Caarea,
    [Parameter(Mandatory)] [string] $Out,
    [Parameter(Mandatory)] [string[]] $Set,
    [string] $Rarity = (Join-Path $PSScriptRoot '..\src\hunt\rarity.rs'),
    [switch] $Write
)
$ErrorActionPreference = 'Stop'

# What scripts/lab plants on the reference hosts: never counted as a stock hit.
$Planted = @(
    'caarea',                 # caarea-test.exe, caarea-test, CaareaLabTask, CaareaSvc, caarea.ps1
    'rangeforge',             # C:\RangeForge
    '\brf_',                  # rf_wpad_beacon.ps1 and the other rf_* drops
    'c:\\temp\\',             # the lab's scratch folder (activity-a.ps1)
    '/tmp/caarea',            # the planted cron job
    'ping -n 3 127\.0\.0\.1'  # CaareaSvc's binPath (services.exe > cmd.exe)
)
$PlantedRe = [regex]::new(($Planted -join '|'), 'IgnoreCase')

function Get-Points([int] $Hits, [int] $Rows) {
    if ($Hits -eq 0 -or $Rows -eq 0) { return 90 }
    $s = [math]::Round(-10 * [math]::Log10($Hits / $Rows))
    return [int][math]::Min(90, [math]::Max(0, $s))
}

$Caarea = (Resolve-Path $Caarea).Path
New-Item -ItemType Directory -Force $Out | Out-Null
$text = Get-Content -Raw -Encoding UTF8 $Rarity
$body = $text.Substring($text.IndexOf('pub const MEASURED'))
$keys = [regex]::Matches($body, '\("([A-Za-z0-9/_-]+)", *\d+\)') | ForEach-Object { $_.Groups[1].Value }

$totalRows = 0
$totalHits = @{}
foreach ($s in $Set) {
    $name, $rest = $s -split '=', 2
    $modules, $evidence = $rest -split ':', 2
    $timeline = Join-Path $Out "$name.csv"
    $findings = Join-Path $Out "$name.hunt.csv"
    Write-Host "+ caarea -m $modules -d $evidence -o $timeline --hunt --hunt-output $findings --overwrite -s"
    & $Caarea -m $modules -d $evidence -o $timeline --hunt --hunt-output $findings --overwrite -s
    if ($LASTEXITCODE -ne 0) { throw "caarea failed on $name" }
    $rows = @(Import-Csv -Encoding UTF8 $timeline).Count
    $totalRows += $rows
    $hits = @{}
    $planted = 0
    foreach ($r in Import-Csv -Encoding UTF8 $findings) {
        $what = "$($r.processname) $($r.commandline) $($r.parentprocessname)"
        if ($PlantedRe.IsMatch($what)) { $planted++; continue }
        $key = if ($r.pattern) { "$($r.signature)/$($r.pattern)" } else { $r.signature }
        $hits[$key] = 1 + [int]$hits[$key]
        $totalHits[$key] = 1 + [int]$totalHits[$key]
    }
    $stock = ($hits.Values | Measure-Object -Sum).Sum
    Write-Host ("{0}: {1} rows, {2} stock hits, {3} planted hits left out" -f $name, $rows, [int]$stock, $planted)
    foreach ($k in ($hits.Keys | Sort-Object)) { Write-Host ("    {0,-34} {1}" -f $k, $hits[$k]) }
}

$unknown = @($totalHits.Keys | Where-Object { $keys -notcontains $_ } | Sort-Object)
if ($unknown.Count) { Write-Warning ("keys that fired but are not in rarity.rs (add them): " + ($unknown -join ', ')) }

"REFERENCE_ROWS = $totalRows"
'| Pattern | Hits | Points |'
'| :--- | ---: | ---: |'
foreach ($k in $keys) {
    $h = [int]$totalHits[$k]
    '| `{0}` | {1} | {2} |' -f $k, $h, (Get-Points $h $totalRows)
}

if ($Write) {
    $rowsLiteral = $totalRows.ToString('#,0').Replace(',', '_')
    $new = [regex]::Replace($text, 'pub const REFERENCE_ROWS: u32 = [\d_]+;', "pub const REFERENCE_ROWS: u32 = $rowsLiteral;")
    foreach ($k in $keys) {
        $new = [regex]::Replace($new, '\("' + [regex]::Escape($k) + '", *\d+\)', ('("{0}", {1})' -f $k, [int]$totalHits[$k]))
    }
    [IO.File]::WriteAllText((Resolve-Path $Rarity).Path, $new, [Text.UTF8Encoding]::new($false))
    Write-Host "wrote $Rarity"
}
if ($unknown.Count) { exit 1 }
