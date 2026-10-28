# Runs the uploaded caarea.exe against the live system volume of a lab host, keeping the
# extracted artifacts under C:\RangeForge\live\stage-<timestamp> for later download.
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force C:\RangeForge\live | Out-Null
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmss')
$stage = "C:\RangeForge\live\stage-$stamp"
$csv = "C:\RangeForge\live\dev-srv01-$stamp.csv"
$log = "C:\RangeForge\live\caarea-live-$stamp.log"
$volume = '\\.\' + 'C:'
$sw = [Diagnostics.Stopwatch]::StartNew()
& C:\RangeForge\inbox\caarea.exe -f $volume -o $csv --stage-dir $stage --overwrite 2>&1 | Tee-Object -FilePath $log |
    Select-String -Pattern 'Live|partition|VSS|shadow|MFT|UsnJrnl|Windows artifacts|total|Error|⚠' | ForEach-Object { $_.Line.Trim() }
"elapsed $([int]$sw.Elapsed.TotalSeconds) s"
"csv $csv $((Get-Item $csv -ErrorAction SilentlyContinue).Length) bytes"
Get-ChildItem $stage -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum | ForEach-Object { "stage files $($_.Count) bytes $($_.Sum)" }
"stage $stage"
