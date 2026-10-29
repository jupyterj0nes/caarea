# Runs the uploaded caarea.exe against the live system volume with --carve (whole-disk
# scan plus the pagefile in place), keeping the extracted and carved files.
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force C:\RangeForge\live | Out-Null
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmss')
$stage = "C:\RangeForge\live\carve-$stamp"
$csv = "C:\RangeForge\live\carve-$stamp.csv"
$log = "C:\RangeForge\live\carve-$stamp.log"
$volume = '\\.\' + 'C:'
$sw = [Diagnostics.Stopwatch]::StartNew()
& C:\RangeForge\inbox\caarea.exe -f $volume -o $csv --stage-dir $stage --carve --overwrite 2>&1 | Tee-Object -FilePath $log |
    Select-String -Pattern 'Live|Carving|scanned|VSS store|MFT|UsnJrnl|total|Error|⚠' | ForEach-Object { $_.Line.Trim() }
"elapsed $([int]$sw.Elapsed.TotalSeconds) s"
"csv $csv $((Get-Item $csv -ErrorAction SilentlyContinue).Length) bytes"
Get-ChildItem "$stage\live_C\carved" -Directory -ErrorAction SilentlyContinue | Measure-Object | ForEach-Object { "carved dirs $($_.Count)" }
"stage $stage"
