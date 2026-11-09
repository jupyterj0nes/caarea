# Changelog

## v0.4.1 (2026-11-09)

### Sized from the machine: threads from the cores, waves from the memory

No fixed figure anywhere (`src/threads.rs`). The pool takes every core the process may use, from `available_parallelism`, which honours affinity masks and container CPU quotas: twelve on a desktop of twelve, ninety-six on a server of ninety-six. What a big machine could overrun is memory, not CPU: an EVTX file costs five times its size while its records are in flight (measured: 10,308 KB of Security log peaks 48 MB above the baseline; 168 files of 203 MB peak 154 MB on one thread and 600 MB on twelve, about 40 MB per thread), and the parsers take one file per thread. The EVTX files and the hives of a directory are now parsed in waves: within a wave, the files that can be in flight at once (as many as threads) cost at most a budget of a quarter of the memory free at start (512 MiB at least, 2 GiB when the system does not say; the cgroup limit caps it inside a Linux container; `CAAREA_FILE_BUDGET=<bytes>` overrides). On a machine with memory to spare every directory is one wave and nothing changes; the waves cost 20 % when every file is one of its own (168 waves: 6.9 s against 4.4) and 15 % at a 300 MB budget. The console says what was decided: `Threads: 12 (12 cores; --threads changes it, 1 runs serial); memory budget 3.0 GiB for the files in flight (11.9 GiB free)`.

The order does not depend on any of it: the waves are cut in file order and collected one after the other. Checked byte for byte over the two-host lab (default budget, one-byte budget, one-byte budget on one thread) and over the 168-file set and six Linux hosts (default, one-byte and 300 MB budgets). The thread policy, the waves and the console line have unit tests (161 tests in all).

## v0.4.0 (2026-11-09)

### The same bytes on one thread or twelve, and faster where it was measured to pay

Reliability first. Two runs now write the same CSV byte for byte, and so do `--threads 1` and the full pool: the timeline is sorted on a total order (time, then every event column: `timeline::event_order`), the findings table on score, time, rule, row, pattern and title, and the Linux parsers read their files in path order. Archives keep each file's own modification time when they are unpacked (zip and tar), so the cron and systemd rows that fall back on the file time carry the host's date, not the extraction's; that was the one source of differences between runs. `tests/determinism.rs` runs the whole pipeline on the pool and on one thread over the XFS lab image and compares the files.

Then speed, measured on a 12-core machine (`CAAREA_TIMING=1` prints the time of every phase on stderr), change by change:

- **EVTX**: the `evtx` crate parses its chunks on rayon's pool, but our `par_bridge` consumed its iterator under the bridge's lock and serialised that work; the iterator is now drained from one thread and the records, taken as JSON values with no text round trip, are turned into rows in ordered batches of 4,096. One Security.evtx of 8,377 records: 1.03 s to 0.46 to 0.66 s. DeepBlueCLI (21 files): 1.28 s to 0.80 to 1.07 s.
- **Hunt**: the naming and path rules judge every row on its own, so the rows go to the pool. DeepBlueCLI: 0.74 s to 0.18 to 0.21 s.
- **Linux**: one file per task, in path order. Six hosts: 1.56 s to 0.72 s.
- Deduplication and the final sort use `par_sort`; measured no change (the sort was not the cost), kept for the order guarantee.
- Whole runs: DeepBlueCLI with `--hunt` 2.9 to 4.0 s before, 1.5 to 2.3 s after; the two-host lab 4.1 to 4.6 s before, 3.9 to 4.3 after (the tgz extraction dominates); 168 EVTX 6.7 to 7.1 s before, 5.9 to 6.0 after.

The policy: the pool takes every logical core (`--threads N` or `RAYON_NUM_THREADS` to say otherwise) and the process runs at normal priority (`--priority low` drops it one step below). Low was the default for a day and was measured against the previous build, five interleaved runs each, medians: DeepBlueCLI (21 EVTX) 3.46 s before, 1.44 s at normal, 1.67 s at low; the two-host lab 5.13, 3.47, 3.82; six Linux hosts 2.32, 1.30, 1.26. The bytes were the same every time, but five low-priority runs out of twenty-six took 10, 17, 38, 51 and 73 seconds while the antivirus scanned the CSV just written, and no normal-priority run did; a tool whose running time depends on what else the machine is doing is not reliable, so normal is the default and low the option. On a machine whose case folder is excluded from real-time scanning, low costs 10 to 25 % under load and nothing when idle.

Verified for this release, with the binary built from the release commit: the timeline and the findings have the same SHA-256 on the default pool twice, on one thread, on two threads and at both priorities, over the two-host lab (110,563 rows), six Linux hosts and DeepBlueCLI (the findings in full and 15 of the 21 timelines file by file; the antivirus quarantines the other six before they can be read, because of the strings they carry).

Not done, by measurement: the families of one directory in parallel would save about 1 s of 4 on the mixed lab triage but needs the console collected per family first (planned); several `-d` at once, image and shadow-copy extraction and carving are bound by the disk, not the CPU (0.26 cores measured on the ext4 image), and stay in series.

### XFS volumes

- Disk images with XFS partitions (GPT, MBR or a bare partition image) and XFS logical volumes inside LVM2 are read like the ext4 ones: the same files staged into the same tree, hostname and time zone included, through the `rust-fs-xfs` driver faramir uses (`src/ingest/xfs_image.rs`; v4 and v5 with checksums). XFS keeps no block journal, so nothing deleted comes back from it; `--carve` still reads the raw bytes. Tested on faramir's lab images (`tests/fixtures/linux_disk`: a GPT XFS partition and an LVM XFS logical volume with one canary per technique).

### `parentprocessname` names a process, `source_file` names the file

- The rows that put the file or the container they were read from into `parentprocessname` (Prefetch, Amcache, `$MFT` and `$UsnJrnl` rows, Defender logs, WER reports, the PowerShell history, `utmp`, container configs, the carver's rows) now leave it to `source_file`, which has the relative path, and say the launching component when there is one (`MsMpEng.exe`, `WerFault.exe`, `powershell.exe`, `dockerd`, `crond`) or nothing when the source names no creator. `N/A` is gone: the column is empty. The PowerShell history keeps its line in `source_file` (`PSReadLine/ConsoleHost_history.txt:line 3 of 5 (file time)`); the journal's audit rows no longer carry `(journal audit transport)` in the parent, `source_file` says it is the journal.

### Nineteen columns, in masstin's verticals

The timeline has the width and the column order of masstin's, like faramir's and allymacb's: fourteen event columns, each in the position of the masstin column closest in meaning and under caarea's own name, then the five-column tail. Readers of the fifteen-column layout need updating; the ten columns of v0.3.0 keep their values, byte for byte (compared on the DeepBlueCLI set, 13,590 rows), only their positions change.

- `timestamp, computer, artifact, event_id, state, target_username, reserved_1, processname, parentprocessname, subject_username, reserved_2, pid, commandline, source_file` and then `hunt, hunt_score, hunt_why, verdict, notes` ([docs/csv-format.md](docs/csv-format.md) has the table against masstin's). `target_username` moves ahead of `subject_username`, `parentprocessname` next to `processname` (masstin's source address: where it came from), `pid` to masstin's session id.
- **`state`** (vertical 5, masstin's logon type, faramir's `state`): how the row was obtained, `live`, `vss`, `deleted`, `txlog`, `carved`, `carved:deleted`, the segment `artifact` already carried, now on its own so it filters in one click.
- **`source_file`** (vertical 14, masstin's `log_filename`): the file the row was read from, relative to the evidence it came in, with the container first when there is one (`export/logs/Security.evtx`, `lnx01-logs:var/log/auth.log`, `disk:partition_0_vss_0/Windows/System32/config/SYSTEM`, the carved blob's name, the file name for `-f`). Every parser family stamps it per file (`utils::stamp_source_file`), the ingest adds the container (`EvidenceWorkspace::container_label`). The README's old "no source file column by design" is gone with it.
- `reserved_1` and `reserved_2` are always empty: masstin's domains have no execution equivalent.
- `timeline::event_csv` writes the fourteen; a unit test pins the header, the verticals and a row.

## v0.3.0 (2026-11-05)

### The hunt closes with the rows that deserve reading first

- `--hunt` ends its console output with up to five entries: the strongest state, the highest score, the strongest rule, the earliest; the state and the score, when and what ran, who created it, every rule that fired with its level and technique, the explanation in words (`why_unusual`) and the lineage. Rows with the same process and the same rules are one entry with a count and the span they cover; rows a clean host vouches for are left out (`hunt::top_rows`). The findings table and the timeline are unchanged.

### A README to read in two minutes, the detail in `docs/`

- The README opens with the logo (`resources/caarea_logo.png`: the carea leonés, the herding dog of León the tool is named after, drawn as a process tree), a recording of `caarea --hunt` over the public DeepBlueCLI set (`resources/demo-hunt.gif`, made with vhs) and a figure of three judged rows (`resources/hunt-rows.svg`), then says what the tool does, how to start, what comes out, what it reads and how it hunts, each in a screenful with a link to its page.
- The reference moved to `docs/`: `sources.md` (every source with event ids, keys and notes), `csv-format.md` (the fifteen columns and the tail, with a judged row), `hunting.md` (tail semantics, findings table, rule catalogue, process tree, the measurement of `hunt_score`, the clean reference), `carving.md`, `time-zones.md`, `cli.md`. Nothing was dropped; the text is the README's, with the paragraphs that had grown together split by topic. The example row of the dropper now reads as CAAREA writes it today (PID 3744, no parent name: a Windows 7 4688 whose creator is not in the log).

### What a clean host executes is vouched for

- **The clean reference is built in.** `src/hunt/clean/windows.tsv` and `linux.tsv` (written by `scripts/measure_clean.py` from the two clean reference hosts, the lab's beacon and the collection's own activity left out: 2,752 and 520 distinct artifact/process/command triples) become host-independent identities at start-up (`src/hunt/clean.rs`: environment variables expanded; user names, SIDs, GUIDs, version folders, random temp names, numbers and hashes neutralised; the per-session Temp subfolder dropped). A row with such an identity is `habitual`, score 0, its rule clauses kept and `on the clean reference hosts` added: the convention of the four tools for an entry something vouches for. On the clean PTR-SRV01 the 26 `candidate` rows (DISM, Defender stubs and cloud-agent scripts in scratch folders, three stock names the shape test took for generated) become `habitual`; nothing is `candidate` or `significant` on either clean host.
- **Measured on a planted host.** PTR-DC01 (same image, never measured) with eight executions planted and a WMI event consumer firing PowerShell: 5 of 9 found (`significant` for the system name outside its folder and the double extension, `candidate` for the two scratch folders and for each of the 1,740 WMI-launched PowerShell starts), no unplanted row flagged. The misses are rule gaps: an encoded command line launched from `cmd.exe`, a binary under `ProgramData`, `certutil -decode`, `rundll32` on a non-DLL.

### Rule rarity measured on clean hosts

- **The table in `src/hunt/rarity.rs` is measured on two clean lab hosts collected live** (PTR-SRV01, Windows Server 2016; LEO-LNX01, Ubuntu 22.04; 8,671 rows, nothing planted) instead of the attacked DEV-SRV01 with its plants filtered out. Three patterns fire on stock rows and are worth less than the bound: `PATH-SCRATCH/windows-writable` (18 hits, 27 points: `dismhost.exe`, Defender update stubs and the cloud agent's startup scripts run from `Windows\TEMP`), `PATH-SCRATCH/temp` (4, 33) and `NAM-RANDOM/generated` (4, 33: `SMSvcHost.exe`, `NGenTask.exe`, `BthUdTask.exe`). Every other pattern gets the bound the corpus gives, 39. The reference's limit is recorded with it: the default audit policy leaves the genealogy rules with 61 parentless process rows, so their 39 is a bound, not a measurement.

### The analysis tail speaks the convention of the four tools

The five columns that close the timeline (`hunt`, `hunt_score`, `hunt_why`, `verdict`, `notes`) now say the same thing in masstin, caarea, faramir and allymacb: masstin's `docs/csv-format.md`, *The same tail in caarea, faramir and allymacb*, is the reference. A case tool maps the tail once.

- **`hunt` admits six words only**: `significant`, `candidate`, `habitual`, `not_evaluated`, `baseline`, or empty. The first build of the tail wrote faramir's `malicious`, `suspicious`, `review` and reserved `anomalous`; they are gone. A high rule (catalogue score 85 and up) gives `significant`, a medium rule (60 to 84) `candidate`, a low rule leaves the state as it is; a statistical test (phase H4) will give `significant` when q ≤ alpha and `candidate` above, and owns the other three words. When a test and a rule both speak, the stronger state wins. `suspicious` is the analyst's word and lives in `verdict`.
- **`hunt_why` names the source.** A rule's clause begins with its id and level, `rule GEN-OFFICE-SHELL (high): winword.exe launched cmd.exe [T1566.001]`; a test's clause is in words, without the prefix. The strongest rule first, clauses separated by `; `, the lineage last as before. A reader that wants only the rules filters on `rule `.
- **`hunt_score` is rarity, not the author's confidence.** The column held the rule's catalogue score (85 for what was then `malicious`); that is not a `hunt_score`. It is now masstin's scale, `-10 · log10` of a probability, 0 to 100: a test contributes `-10 · log10(q)`, a rule contributes the same scale **measured**, how often its pattern fires on stock, clean reference hosts (one in 128 rows is 21 points; a pattern that never fired on the reference rows is 90). Contributions add, capped at 100. A rule not measured yet contributes 0 and `hunt_why` says `(rarity not measured)`. The table is `src/hunt/rarity.rs`, written by `scripts/measure_rarity.ps1` from the findings of `caarea --hunt` over the reference evidence with the lab's planted rows left out; `PATH-SCRATCH`, `NAM-RANDOM`, `NAM-LOOKALIKE`, `NAM-SYSTEM-PATH`, `PATH-REMOTE` and `GEN-RESTRICTED-PARENT` are measured per pattern. Measured on the two RangeForge lab hosts (DEV-SRV01, LEO-LNX01; 5,936 rows): no pattern fired on a stock row, so every rule is at 90 until a larger stock corpus is measured.
- **The catalogue score stays in the code and in the findings table**, which gains `level`, `rarity` and `pattern` after `score` (`rank, significant, p_value, q_value, score, level, rarity, signature, pattern, mitre, ...`); `significant` is `yes` for a high rule.
- The ten event columns are unchanged: compared before and after on DEV-SRV01 (4,918 rows) and the DeepBlueCLI EVTX set (13,590 rows), identical cell by cell; on LEO-LNX01 (1,018 rows) the only cells that differ are the timestamps of twelve cron and systemd rows, which carry the modification time of the files extracted from the archive and so change with every run (the Linux persistence parser's fallback, not this change).

### Process hunting (phase 11, H0 to H2)

- `--hunt`: the process tree of every host (PID and time, Sysmon GUIDs, exits, boot markers from Security 4608, Kernel-General 12, the first `smss.exe` / `wininit.exe`), genealogy rules from SANS *Hunt Evil* and Elastic's parent-child rule, naming and path rules (system binaries outside their folder, look-alike and generated names, double extensions, RTLO, scratch and user-writable folders, archive temp, ADS, shares), each with an ATT&CK technique, a lineage and an explanation; findings in `<output>.hunt.csv`.
- The timeline has fifteen columns: the ten event columns and the analysis tail, empty when the parsers write it. Security 4608 and Kernel-General 12 are parsed as `evtx:4608` / `evtx:12`.
- Parent resolution by creator PID on every timeline (auditd, pacct, 4688 before Windows 10).

## v0.2.0

Everything before phase 11: the parsers, images, shadow copies, carving and the Linux sources described in the README.
