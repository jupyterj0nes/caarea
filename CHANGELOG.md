# Changelog

## v0.4.0 (2026-11-05)

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
