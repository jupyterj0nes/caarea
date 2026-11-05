# What CAAREA reads

[← README](../README.md)

Every source below lands in the same fifteen-column CSV ([the format](csv-format.md)). Windows and Linux evidence can sit in the same run: a KAPE zip from the file server and a UAC tarball from the web server end up in one timeline, sorted together, each row stamped with its host.

## Windows

| Source | Events / keys | Notes |
| :--- | :--- | :--- |
| Security.evtx | 4688 process creation, 4689 process exit, 4608 startup (boot marker), 4697 service install, 4698-4702 task created / deleted / enabled / disabled / updated, 1102 audit log cleared | `DOMAIN\user`, PID from `NewProcessId`, task command pulled out of the task XML |
| System.evtx | 7045 service installed, 7034 service crashed, 7036 service state change, 104 log cleared, Kernel-General 12 OS started (boot marker), MsiInstaller 1033/1034/11707/11724 | account from `AccountName` |
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

Every `.evtx` in a folder is parsed and filtered by provider and event id, so renamed channel files are fine. Dirty hives are repaired before parsing: `.LOG1`/`.LOG2` entries are verified (Marvin32 hashes), applied in sequence order and only when they belong to that hive. The result matches, byte for byte, what Windows itself produces when it loads the same hive. Freed registry cells and unused `$MFT` records are read by default and carry the `deleted` origin in `artifact`.

## Linux

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

Linux logs that only carry wall-clock time are corrected with the host's own time zone, found in the evidence: see [Time zones](time-zones.md).

## Disk images and live volumes

E01/Ex01, raw/dd and virtual disks (VMware VMDK: monolithic or split, sparse or flat; Hyper-V VHD and VHDX, fixed or dynamic) are read in place, without converting or mounting. MBR and GPT partition tables, NTFS traversal, BitLocker detection (encrypted volumes are reported and skipped; decrypt first). Linux images are read the same way: ext2/3/4 partitions, bare partition images and ext4 logical volumes inside LVM2 are walked with a pure-Rust reader and the files listed above (plus `/etc/hostname`, `/etc/localtime` and its symlink target) are staged with their original paths. XFS and btrfs are not read yet.

From the live volume and from **every Volume Shadow Copy**: event logs, `config` hives with their transaction logs, `Amcache.hve`, `NTUSER.DAT` and `UsrClass.dat` of every profile, Prefetch, task XML, WER reports, Defender logs, PCA logs, SRUM, the WMI repository, `RecentFileCache.bcf`, `Syscache.hve`, `$MFT`, `$UsnJrnl:$J` and, per profile, the PowerShell history, Recent shortcuts and Jump Lists and the Timeline database. Shadow copies are read with [vshadow-rs](https://github.com/jupyterj0nes/vshadow-rs), pure Rust, straight from the image. Events that only exist in a shadow copy are tagged with the snapshot time (`evtx:4688:vss [2026-09-04T08:12:53Z]`); a live event and its snapshot twin are not shown twice.

A running Windows host is read the same way through its volume device (`caarea -f \\.\C: -o out.csv`, as administrator), and a running Linux host through its block device (`caarea -f /dev/sda1`). `--stage-dir` keeps the artifacts extracted from images, live volumes and archives.

## Triage packages and archives

KAPE, Velociraptor, UAC, Cortex XDR and CyLR packages are recognised zipped or unpacked, and so are plain zips and tarballs nested in each other (five levels deep). Archives are unpacked into an isolated, per-run temporary folder; entries cannot escape it, symlinks are never followed, and packages with the same file name from different hosts never overwrite each other. The evidence itself is only ever read.
