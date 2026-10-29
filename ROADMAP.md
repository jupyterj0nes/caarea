# CAAREA roadmap: missing execution artifacts and carving

Status (2026-10-28): phases 0 to 5 shipped (commits 7596fb7, 201143d), plus a live-volume
mode (`-f \\.\C:`) and `--stage-dir` that were not in the plan. Phase 6 (Linux) done:
ext4/LVM image reader, journald, apt/dnf/pacman/zypper, utmp, timers, containers, cloud-init,
cron mail, fish and REPL histories, `.gz`/`.xz` rotated logs, audit `SERVICE_START`/`USER_START`/
`ANOM_ABEND`/`AVC`, live Linux devices (`caarea -f /dev/sda1`). Validated live on LEO-LNX01
(Ubuntu 22.04): 88 artifacts staged from the ext4 root device, 22 artifact classes, 9684 rows;
auditd execve PIDs match pacct records for the same commands. Still pending from phase 6: WSL
`ext4.vhdx` inside a Windows image (needs a reader-based VHDX open).
Phase 7 (Windows carving) implemented: `--carve` scans images, live volumes, pagefiles
(in place through NTFS) and blobs in one pass for hives, EVTX chunks, orphan records, FILE,
INDX, USN and Prefetch; hives and EVTX go to the staging folder and the normal parsers, the
rest become rows directly. Known-copy skipping: hive fingerprints and chunk hashes of the
extracted logs; only freed MFT records on the disk itself. hiberfil is scanned raw (its
Xpress-compressed pages are not decoded yet).
Phase 8 (Linux carving) implemented on the same pass: journal files by header, pacct and
utmp records by strict structure, audit lines and `#epoch` history blocks by text search
(memchr); validated on an ext4 test image with the artifacts deleted (journal, audit lines,
history, wtmp all came back). Journal entries carried on the audit transport (no auditd)
are assembled into execve rows. Commits: 1d25ee3 (phase 6), e791642 (phase 7), 6a5f069
(phase 8). EVTX chunks are never parsed in the main process (CRC32 acceptance, child-process
validation with bisection); live carve of DEV-SRV01 (50 GB, 4 GB RAM): 15 min, 69795 rows, of
which 37223 only exist carved (older cleared Security log, index slack, journal records).
Phase 9 (heavy formats) implemented: SRUM through the pure-Rust `sootmark-ese` reader
(app resource, network usage, app timeline tables), Jump Lists and shortcuts through
`lnk-core` (DestList times and access counts, well-known AppIDs named), Windows Timeline
through bundled SQLite (`Activity` plus `ActivityOperation`, database copied with its WAL
to scratch before opening), WMI `OBJECTS.DATA` subscriptions by class-name scan with the
instance record's FILETIME, `RecentFileCache.bcf`, `Syscache.hve`, and the second-line
registry keys (MUICache, PCA store, RecentApps, FeatureUsage, CapabilityAccessManager).
Image and live extraction stage `sru`, `wbem\Repository`, `AppCompat\Programs`, `System
Volume Information\Syscache.hve`, per-profile `Recent` and `ConnectedDevicesPlatform`.
Validated: SRUM and Jump Lists on DEV-SRV01 live (1411 hourly resource rows, Explorer
Jump List entries with access counts); WMI on DEV-SRV01 (a real subscription created in
the lab plus one from an earlier run both recovered, with filter, consumer command line
and binding; the record stamp was matched to the WMI service start in the System log);
Jump Lists and shortcuts on a Windows 11 workstation; Timeline on the public dissect test
database (`datasets/public/timeline`, opened and focus rows), because neither Windows 11
nor Server 2022 record user activities any more. The lab's Server 2022 SRUM has neither
the app timeline table nor the network data usage table; the per-interface SDP tables are
left out on purpose. `RecentFileCache.bcf` and `Syscache.hve` have unit tests only (no
Windows 7 host in the lab).
Phase 10 done: the `blockcarve` crate (`D:\c00pr\tools\blockcarve`, AGPL-3.0, path
dependency until published) holds the sources, the scanner (`scan_many` with the block
callback), the hive-bin chain reader, EVTX chunk checksums and synthetic files with
bisection against a caller-supplied validator, `FILE`/`INDX` validators (feature `mft`),
Prefetch and journal headers. caarea, faramir (with a diagnostics-recording wrapper so its
error codes survive), allymacb (its block loop replaced by the shared scanner, text carving
holding back the last 8 KB of every block) and masstin (EWF through the guarded source,
`--skip-offsets` as a zero-serving source wrapper, CRC gate before the provider peek) all
build and pass their suites on it.
Lab notes: Windows Server does not write Prefetch even with `EnablePrefetcher=3`; the GCE VMDK
export needs a free instance slot in the region (the kept jumpbox fills the quota of 8).

Working plan, October 2026. Each phase ships on its own (tests, README, commit, push)
and leaves `main` usable. Order is by execution events recovered per day of work;
every live parser added in phases 1 to 6 is also what phases 7 to 9 carve.

## Ground rules

- **Default vs `--carve`.** Anything recovered from a structure we already parse
  (freed hive cells, unused `$MFT` records, shadow copies, journald files) runs by
  default. Anything that needs a raw byte scan (signatures in unallocated space,
  pagefile, hiberfil, swap, memory dumps) runs only with `--carve`. Same rule as
  faramir and allymacb.
- **Only self-timestamped structures are carved.** EVTX chunks and records, hive
  cells, `FILE`/`INDX`/USN records, prefetch, pacct, audit lines, journald, utmp.
  No timestamp-less strings. The timeline never gets a row without a real time.
- **Provenance vocabulary** (aligned with faramir), as segments of `artifact`, with
  the detail in brackets after it:
  - live: `evtx:4688`
  - only in a shadow copy: `evtx:4688:vss [2026-09-04T08:12:53Z]`
  - recovered from a freed structure: `registry:bam:deleted`
  - signature-carved: `evtx:4688:carved [@0x1c3f80000]`
  - freed cell inside a carved hive: `registry:run:carved:deleted [@0x…]`
  - container blobs: `… :carved [pagefile @0x…]`, `[hiberfil @0x…]`, `[swap @0x…]`
  Dedup compares all fields ignoring the provenance; precedence is explicit:
  live > vss > deleted > carved.
- **Shared engine.** The block scanner and guarded block sources are ported from
  faramir `carve/scan.rs` + `carve/source.rs` (themselves the masstin design).
  Validators are one module per structure. Phase 10 extracts the engine into a
  crate the four tools share.
- **Every carved object is parsed under a time budget** (thread + timeout), not
  only EVTX: sootmark over a garbage `hbin` or the `mft` crate over a pagefile page
  must never hang the run.
- **No new CSV columns.** Ten columns stay, so caarea, masstin and faramir output
  still concatenates.

## Phase 0: provenance and engine groundwork (0.5 day)

- `src/lib.rs::tag_events` / `artifact_base`: switch to the segment vocabulary;
  `dedup_events` with explicit precedence table instead of string order.
- `src/carve/{mod,scan,source}.rs`: port from faramir; adapt `diag` calls to
  caarea's `log_message` + a `CarveStats` summary line.
- `src/cli.rs`: `--carve` flag (no-op until phase 7), reserved `--carve-unalloc`.
- Tests: tag/dedup precedence; scanner unit tests from faramir (carry-over,
  SkipTo, stalled reads, read errors).
- README: "Where a row came from" section with the vocabulary.

## Phase 1: EVTX mappings (0.5 day)

`src/parsers/evtx.rs::classify_event` + `extract_event` only.

| Channel | IDs | Fields |
|---|---|---|
| Security | 4689 process exit, 4699/4700/4701/4702 task deleted/enabled/disabled/updated, 1102 log cleared | SubjectUser, ProcessName, TaskName, task XML command |
| System | 7034/7036 service crashed / state change, 104 log cleared, MsiInstaller 11707/11724/1033/1034 | service name, product, user |
| Application | 1000/1001 application error / WER | faulting app path, module |
| PowerShell/Operational | 4103 module logging | Payload `CommandInvocation`, `ParameterBinding`, ContextInfo user/host |
| Shell-Core/Operational | 9707/9708 Run command start/stop | Command, PID |
| AppLocker EXE and DLL, MSI and Script, Packaged app | 8002/8003/8004, 8005/8006/8007, 8020/8022 | FilePath, FqbnFileName, TargetUser, PID |
| Windows Defender/Operational | 1116/1117, 1015 | Path, Process Name, Threat Name, Action, User |
| Sysmon | 5 process end, 6 driver loaded, 7 image loaded, 11 file created | Image, ImageLoaded, TargetFilename, User |
| WMI-Activity | 5857, 5858, 5860 | ProviderName/Path, Operation, ClientProcessId, User |
| TaskScheduler/Operational | 100, 102, 107, 108, 118, 119, 201 | TaskName, UserContext, ActionName, ResultCode |
| BITS-Client | 59, 60 | url, processPath, user |

Validation: counts per file against `Get-WinEvent` on the 524-file corpus plus
local exported channels (AppLocker and Defender from this machine).

## Phase 2: Prefetch (1.5 days)

- `src/parsers/windows/prefetch.rs`: `MAM\x04` (Xpress Huffman per MS-XCA,
  own implementation, ~300 lines) and `SCCA` v17/23/26/30. Emit one row per run
  time (up to eight), `artifact=prefetch`, processname from the file name,
  commandline = loaded files summary (dll count, suspicious paths), volume info.
- `src/ingest/image.rs`: extract `Windows\Prefetch\*.pf`; `archive.rs`
  relevance: `.pf`.
- Tests: real `.pf` of each version (fixtures from this machine and ws01), hand
  built Huffman stream, truncated file.
- Validation: `ws01.vmdk` versus PECmd on the same folder.

## Phase 3: text and registry execution artifacts (2 days)

New folder `src/parsers/windows/` (move `registry.rs` there as `registry/`).

- `psreadline.rs`: `ConsoleHost_history.txt`, one row per line, timestamp =
  file mtime, user from the profile path, `artifact=powershell:history`,
  commandline = the line. Clearly documented as "time of the file".
- `muicache`: UsrClass `Local Settings\Software\Microsoft\Windows\Shell\MuiCache`;
  key last-written as time.
- `pca.rs`: NTUSER `AppCompatFlags\Compatibility Assistant\Store` (value name =
  path, key time), and Windows 11 `Windows\appcompat\pca\PcaAppLaunchDic.txt`
  (`path|yyyy-MM-dd HH:mm:ss.fff`) and `PcaGeneralDb0/1.txt` (UTF-16, pipe
  separated: time, type, path, product, vendor, version, exit code).
- `tasks_xml.rs`: `Windows\System32\Tasks\**` with roxmltree: `RegistrationInfo/
  Date`, `Author`, `Principal`, each `Exec/Command` + `Arguments`.
- `wer.rs`: `ProgramData\Microsoft\Windows\WER\Report{Archive,Queue}\**\Report.wer`
  (`AppPath`, `EventTime` FILETIME, `Sig[0].Value`, `TargetAppId`).
- `mplog.rs`: `ProgramData\Microsoft\Windows Defender\Support\MPLog-*.log`
  (UTF-16): `ProcessImageName`, `BM` behaviour monitoring lines, detections,
  `EstimatedImpact` scan lines, with their timestamps.
- Image/archive extraction lists extended accordingly.
- Validation: ws01 (every user profile), this machine's own artifacts.

## Phase 4: NTFS metadata, live and deleted (2.5 days)

Port from allymacb (`parsers/mft.rs`, `parsers/usn.rs`, `ingest/carve.rs`
validators). New `src/parsers/ntfs/{mft,usn,i30}.rs`, crate `mft = "0.7"`.

Caarea emits only execution-relevant rows, not a MACB timeline:

- `$MFT`: records (allocated and unused) of files with executable/script
  extensions, `.pf`, `.evtx`, hives, in temp/download/profile/system paths;
  resident `$DATA` of small scripts dumped to staging and shown in commandline.
  Deleted records: `ntfs:mft:deleted`.
- `$UsnJrnl:$J`: `FILE_CREATE`/`DATA_EXTEND`/`CLOSE` on executables and scripts;
  creation of `*.pf` emitted as `ntfs:usn:prefetch_created` (that is an execution
  with a time even when the `.pf` is gone); `DATA_TRUNCATION`/`FILE_DELETE` on
  `.evtx`, `.pf`, hives, `ConsoleHost_history.txt` as anti-forensics rows.
- `$I30` slack of `Prefetch`, `Temp`, `Downloads`, `Tasks`, `winevt\Logs`:
  deleted children with their timestamps (`ntfs:i30:deleted`).
- Recovery by MFT: a deleted `.evtx`, hive or `.pf` whose clusters still hold
  the data is dumped to staging under `<img>/deleted/` and parsed through the
  normal pipeline with `:deleted`.
- Image extraction: `$MFT`, `$UsnJrnl:$J`, `$LogFile` (kept for phase 7).
- Validation: ws01; mkntfs image where files are created, executed-like, deleted;
  compare with allymacb output on the same `$MFT`/`$J`.

## Phase 5: registry freed cells and historical log entries (1 day)

- Port faramir `windows/deleted.rs` (bounds-checked hbin walker, parent-chain
  path rebuild). Map recovered paths to caarea's registry artifacts: BAM/DAM,
  Run/RunOnce, Services (`ImagePath`), TaskCache `Tree`/`Tasks` (Actions blob),
  UserAssist, MuiCache, PCA store, Amcache `InventoryApplicationFile` /
  `InventoryApplication`, AppCompatCache entries if the value cell is freed.
- `src/parsers/tx_log.rs`: keep the HvLE entries with sequence lower than the
  hive's (today discarded), walk their dirty pages with the same cell walker,
  emit cells that no longer exist in the replayed hive: `registry:<x>:txlog`.
- Always on. Tests with the yarp deleted-tree/deleted-values hives; cross-check
  with `RECmd --recover` on ws01's SYSTEM/SOFTWARE/NTUSER.

## Phase 6: Linux live parsers (3 days)

- `src/ingest/linux_image.rs`: port masstin `parse_image_linux.rs`
  (ext4-view 1.0 + lvm2): MBR/GPT → ext4 partitions (also inside LVM) →
  extract the same path set `is_relevant_artifact` knows, plus `/var/log/journal`,
  `/var/lib/docker`, `/var/lib/systemd/timers`, `/var/mail`, `/var/spool/mail`.
  XFS: detect and warn (no reader).
- `journald.rs`: port masstin `parse_journal.rs` (systemd-journal-reader).
  Rows from `_CMDLINE`/`_EXE`/`_COMM`/`_PID`/`_UID`, `SYSLOG_IDENTIFIER` in
  {sudo, su, CRON, cron, systemd, pkexec, sshd session}, `MESSAGE` with
  `COMMAND=`, `CMD (`, `Started`/`Starting` unit, `Session … of user`.
- `packages.rs`: `apt/history.log` (`Start-Date`, `Commandline`, `Requested-By`),
  `dnf.log` + `dnf.rpm.log`, `yum.log`, `pacman.log`, `zypp/history`.
- `containers.rs`: docker `config.v2.json` (`Path`, `Args`, `Config.Cmd`,
  `Created`, `State.StartedAt/FinishedAt`, image), `<id>-json.log` first/last
  lines; containerd `io.containerd.runtime.v2.task/*/config.json`; podman
  `storage/overlay-containers/containers.json`; `/var/log/pods/**/*.log`.
- `persistence.rs`: `.timer` units and `/var/lib/systemd/timers/stamp-*.timer`
  mtime as last trigger.
- `audit.rs`: `SERVICE_START`/`SERVICE_STOP` (unit, pid), `USER_START`/`USER_END`,
  `ANOM_ABEND`, `AVC` denied with `comm=`/`exe=`/`scontext`.
- `histories.rs`: fish (`- cmd:` / `when:`), `.python_history`, `.mysql_history`,
  `.psql_history`, `.sqlite_history`, `.node_repl_history`, `.lesshst`,
  `.ash_history`, `.sh_history`.
- `cronmail.rs`: mbox parsing of `/var/mail/*`, `Subject: Cron <user@host> cmd`,
  `Date:`.
- `cloudinit.rs`: `cloud-init.log` `runcmd`/`Running command` lines,
  `cloud-init-output.log` blocks.
- `utmp.rs`: 384-byte records of `wtmp`/`btmp`/`lastlog` (sessions, tty, host).
- `archive.rs`: read `.gz` and `.xz` rotated logs in place (flate2 already linked,
  add `xz2` or `lzma-rs`).
- WSL: the `ext4.vhdx` under `LocalState` of each distro package in a Windows
  image goes through the same Linux image path, tagged with the distro name.
- Validation: WSL Ubuntu (journald, apt history, fish), Ubuntu 24.04 logs, a
  docker host fixture (synthetic `config.v2.json` + real one if available),
  UAC packages already in `datasets`.

## Phase 7: Windows carving under `--carve` (3 days)

`src/carve/{hive,evtx,ntfs,prefetch}.rs` + orchestration in `ingest/image.rs`
after live + VSS extraction. Whole-image scan; identity dedup against what the
live pass produced (faramir/allymacb style), `--carve-unalloc` later.

- Hives by `regf` (faramir `carve/hive.rs` + `fold.rs` logic): fingerprints of
  every hive already extracted, bin-chain follow, root nk check, truncated prefix
  kept, written to `<img>/carved/`, normal pipeline including phase 5 cells
  (`:carved:deleted`).
- EVTX chunks (masstin): `ElfChnk` peek with 3 s budget, synthetic EVTX per
  provider, validation in a child process (`CAAREA_VALIDATE_EVTX`), then the
  evtx parser; orphan `\x2a\x2a\x00\x00` records emitted as
  `evtx:orphan_record:carved` with their FILETIME only. Upgrade `evtx` to 0.11.
- `FILE` / `INDX` (allymacb validators with fixup checks) filtered to the same
  execution-relevant set as phase 4; USN records by structural checks
  (len % 8, major 2 minor 0, FILETIME in range, name length consistent).
- Prefetch `MAM\x04` and `SCCA` signatures; decompress and parse with phase 2.
- Containers scanned in full regardless of allocation: `pagefile.sys`,
  `swapfile.sys`, `hiberfil.sys` (Xpress LZ77 page sets, `HIBR` header),
  `MEMORY.DMP`, `Minidump\*.dmp`. Tag `[pagefile @0x…]` etc.
- `-f <blob> --carve`: any file that is not a recognised artifact is carved as a
  blob (pagefile, memory dump, unallocated dump), like faramir and allymacb.
- Summary line: MB scanned, signatures per type, accepted, rejected, identical
  to live, duplicates, truncated, read errors, stalls.
- Tests: synthetic disk builder (hives + EVTX + FILE records planted in a raw
  image with bad sectors and a truncated tail), stalled-reader test, identity
  fold tests. Validation: mkntfs image with deleted EVTX/hive/pf, ws01.

## Phase 8: Linux carving under `--carve` (2 days)

Same engine over ext4 partitions, swap partitions/files and blobs:

- `pacct` 64-byte records (version 3, printable comm, btime in range, etime
  plausible), journald files by `LPKSHHRH` header + declared size, audit lines
  `type=(SYSCALL|EXECVE|USER_CMD|CWD|PROCTITLE) msg=audit(\d{10}\.\d{3}:\d+)`
  reassembled by serial, bash history blocks with `#epoch` lines, fish history
  blocks, utmp records.
- ext4 structural recovery (default, not `--carve`): deleted dentries in `/tmp`,
  `/dev/shm`, `/var/tmp`, `/home/*`, `/root`, `/var/spool/cron`, `/etc/cron.d`,
  `/etc/systemd/system`; inode copies in the journal (inode 8) to recover
  scripts and crontabs whose extents are still intact.
- Validation: loop ext4 image built in WSL (write pacct/audit/history, rotate,
  delete, overwrite partially).

## Phase 9: heavier formats (3 days)

- SRUM (`SRUDB.dat`): decide between `libesedb` bindings (masstin already builds
  with it) and a pure-Rust ESE reader; tables `{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}`
  (AppResourceUseInfo), network usage, `SruDbIdMapTable` for app/user names.
- Jump Lists (`cfb` crate for OLECF + LNK parser; `lnk` crate or own) and
  `Recent\*.lnk`: app id → application table, target path, times.
- Windows Timeline `ActivitiesCache.db` (SQLite via `rusqlite` bundled):
  `Activity` table, `AppId` JSON, start/end times.
- Second-line registry: RecentApps, FeatureUsage, CapabilityAccessManager,
  `RecentFileCache.bcf`, `Syscache.hve`.
- WMI repository `OBJECTS.DATA`: regex scan for `CommandLineEventConsumer` /
  `ActiveScriptEventConsumer` / `__EventFilter` records.

## Phase 10: shared carving crate (1 day + 0.5 per tool)

Extract `BlockSource`, `DirectSource`, `GuardedSource`, `scan_signatures`,
`ScanConfig`, `HitAction`, `ScanStats` and the validators (`hive`, `evtx`, `ntfs`,
`prefetch`, `linux`) into a crate next to vshadow-rs. masstin, faramir, allymacb
and caarea depend on it; each tool keeps its own emission and dedup.

## Deliverables per phase

1. Code with unit tests (fixtures under `tests/fixtures/`, real-layout bytes).
2. Validation run on the datasets listed, numbers recorded in the commit message.
3. README tables updated (sources, command reference, limits).
4. `cargo clippy` clean, `cargo test` green, release build checked.
5. One commit per phase, pushed to `main`. No attribution trailers.

## Effort

| Phase | Days |
|---|---|
| 0 Provenance + engine | 0.5 |
| 1 EVTX mappings | 0.5 |
| 2 Prefetch | 1.5 |
| 3 Text/registry execution artifacts | 2 |
| 4 NTFS metadata | 2.5 |
| 5 Registry freed cells + txlog history | 1 |
| 6 Linux live parsers | 3 |
| 7 Windows carving | 3 |
| 8 Linux carving | 2 |
| 9 Heavy formats | 3 |
| 10 Shared crate | 2.5 |
| **Total** | **21.5** |

## Open decisions

- Provenance vocabulary change renames today's `[vss:…]` suffix. Agreed in
  principle; faramir keeps `removed_since_vss` for now.
- ESE reader for SRUM: bindings or pure Rust (phase 9).
- Whether phase 10 happens before or after phase 9.
