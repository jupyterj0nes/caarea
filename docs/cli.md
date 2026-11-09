# Command reference

[← README](../README.md)

```text
caarea [OPTIONS] --output <PATH>

  -d, --directory <PATH>      Evidence directory or triage folder (repeatable)
  -f, --file <PATH>           Disk image, archive or single artifact (repeatable)
  -o, --output <PATH>         Destination CSV
  -m, --modules <MODULES>     evtx | registry | windows | linux | all   [default: all]
  -t, --toi <TIMESTAMP>       Centre of a time window of interest (ISO-8601)
  -w, --toi-window <HOURS>    Hours before and after the TOI       [default: 24]
      --start-time <TS>       Keep events from this time on
      --end-time <TS>         Keep events up to this time (a bare date includes the whole day)
      --tz <ZONE>             Time zone of the Linux hosts for zone-less logs (default: detected)
      --carve                 Also scan raw bytes (images, live volumes, pagefiles, blobs) for structures
                              no file system points to; off by default, reads the whole image
      --hunt                  Run the process hunt over the timeline; findings in <output>.hunt.csv
      --hunt-output <PATH>    Destination CSV for the findings
      --stage-dir <PATH>      Keep the artifacts extracted from images, live volumes and archives here
      --overwrite             Replace the output file if it exists
      --threads <N>           Worker threads for the parsers and the hunt (default: every logical
                              core, or RAYON_NUM_THREADS); the CSV is the same whatever the count
      --priority <low|normal> Process priority (default: normal; low yields the CPU to anything else)
  -s, --silent                Print nothing but errors
  -h, --help / -V, --version
```

## What to give it

| You have | Run |
| :--- | :--- |
| A disk image (E01, Ex01, raw, dd, 001) or a virtual disk (VMDK, VHD, VHDX) | `caarea -f disk.E01 -o out.csv` |
| A running Windows host (triage in place, as administrator) | `caarea -f \\.\C: -o out.csv --stage-dir D:\case\extracted` |
| A running Linux host (as root) | `caarea -f /dev/sda1 -o out.csv` |
| Triage packages (KAPE, Velociraptor, UAC, Cortex XDR, CyLR), zipped or not | `caarea -d /path/to/packages -o out.csv` |
| A folder you collected by hand (`C:\Windows\System32\winevt\Logs`, `/var/log`, ...) | `caarea -d /path/to/folder -o out.csv` |
| Single files (an EVTX, a hive, an `audit.log`) | `caarea -f Security.evtx -f SYSTEM -f audit.log -o out.csv` |
| A pagefile, a memory dump, a blob of unallocated clusters | `caarea -f pagefile.sys -o out.csv --carve` |

`-d` and `-f` repeat and mix. `-m` runs one parser family only (`evtx`, `registry`, `windows` for Prefetch and the other Windows file artifacts, `linux`), which is also the way to get one CSV per family when you need to know which source a row came from.

## Windows of time

`--toi 2026-09-24T12:00:00Z --toi-window 6` keeps the events six hours either side of the moment of interest; `--start-time` and `--end-time` set the window by its edges. Rows outside the window are not written, but they still feed the process tree, so a parent that started before the window is still named in `parentprocessname` and still counts for the hunt's genealogy.

## Threads, memory and priority

Nothing is fixed: the run is sized from the machine it finds (`src/threads.rs`), and the console says what it decided:

```
Threads: 12 (12 cores; --threads changes it, 1 runs serial); memory budget 3.0 GiB for the files in flight (11.9 GiB free)
```

**Threads.** The parsers and the hunt share one worker pool with as many threads as cores the process may use: twelve on a desktop of twelve, ninety-six on a server of ninety-six, fewer inside a container with a CPU quota or under an affinity mask. `--threads N` or `RAYON_NUM_THREADS` set it by hand; `--threads 1` runs everything in series.

**Memory.** A file being parsed costs several times its size while its records are in flight (an EVTX measured five times: a 10 MB Security log peaks 48 MB above the baseline), and the parsers take one file per thread, so a server with many cores holds many files at once. The files of a directory are therefore parsed in waves: within a wave, the files that can be in flight together (as many as threads) cost at most the budget, a quarter of the memory free when the run starts (512 MiB at least; 2 GiB when the system does not say; inside a Linux container the cgroup limit caps it). On a machine with memory to spare every directory is one wave and nothing changes: 168 EVTX files of 203 MB are one wave on a 3 GiB budget and peak at 600 MB on twelve threads. With little memory the waves keep the run out of swap, at a measured cost of 20 % when every file is a wave of its own (168 waves: 6.9 s against 4.4) and 15 % with a 300 MB budget. `CAAREA_FILE_BUDGET=<bytes>` sets the budget by hand.

**Priority.** The process runs at normal priority, as any other program does. `--priority low` drops it one step below normal, so the scheduler gives a core back the moment the console or anything else wants one; it was the default once, and measured a run starved for 10 to 73 seconds (against 1.5 to 4) whenever the antivirus was scanning the evidence or the CSV just written, so it is the option, not the default. If the case folder is excluded from real-time scanning, `low` costs 10 to 25 % under load and nothing on an idle machine.

None of this changes the output: files are listed and sorted first, parsed in that order wave after wave, rows collected in that order, and the timeline sorted on a total order (time, then every event column), so the CSV is the same byte with one thread or ninety-six, whatever the memory. The same bytes were checked on the default budget, on a one-byte budget (one file per wave) and on one thread over the two-host lab, 168 EVTX files and six Linux hosts; a test runs the pipeline on one thread and on the pool and compares the files. `CAAREA_TIMING=1` prints the time of every phase on stderr.

## What comes back

The CSV is written at the end of the run, in one piece; an existing file is not touched unless `--overwrite` is given. `--hunt` writes a second CSV next to it (`<output>.hunt.csv` unless `--hunt-output` names it). The console prints what was found per source and, with `--hunt`, how many rows were judged, which rules fired and the rows that deserve reading first with the reason in words; `-s` keeps only errors. Nothing is ever written into the evidence: archives and images are unpacked to a per-run temporary folder that is removed afterwards, or kept where `--stage-dir` says.
