# The CSV

[← README](../README.md)

CAAREA writes one RFC 4180 CSV with nineteen columns: fourteen that describe the event, written by the parsers, and an analysis tail of five that the parsers leave empty and that `--hunt` and the analyst fill. The layout is [masstin](https://github.com/jupyterj0nes/masstin)'s: as wide as its timeline, every caarea field in the vertical of the masstin field that means the same thing, under caarea's own names, so an execution timeline, a login timeline (masstin), a persistence timeline (faramir) and a filesystem timeline (allymacb) line up column by column and a case tool maps each header once. The tail is the one the four tools share, with the same words and the same scale (masstin's [`docs/csv-format.md`](https://github.com/jupyterj0nes/masstin/blob/main/docs/csv-format.md), *The same tail in caarea, faramir and allymacb*, is the reference).

Timestamps are UTC with a fixed width (`YYYY-MM-DDTHH:MM:SS.ffffffZ`), so sorting the text sorts the time. Rows that are identical in every column (two records with the same time, user, process and command line) are collapsed into one.

## The fourteen event columns

| # | masstin | caarea | Meaning |
| ---: | :--- | :--- | :--- |
| 1 | `time_created` | `timestamp` | When it happened, UTC |
| 2 | `dst_computer` | `computer` | Host name (from the event, the SYSTEM hive, the UAC hostname file or the package name) |
| 3 | `event_type` | `artifact` | Where the row comes from: `evtx:4688`, `evtx:sysmon:1`, `registry:bam`, `prefetch`, `linux:audit:execve`, ... Rows that were not read from the live evidence carry an extra segment and the detail in brackets: `evtx:4688:vss [2026-09-04T08:12:53Z]` (only in that shadow copy), `registry:bam:deleted` (recovered from a freed hive cell), `evtx:4688:carved [@0x1c3f80000]` (carved from raw bytes at that offset) |
| 4 | `event_id` | `event_id` | Windows event id, 0 otherwise |
| 5 | `logon_type` | `state` | How the row was obtained, the segment of `artifact` on its own so it filters in one click: `live`, `vss`, `deleted` (a freed hive cell, an unused `$MFT` record), `txlog` (an old transaction-log entry), `carved`, `carved:deleted` |
| 6 | `target_user_name` | `target_username` | Who it ran as, when different from who ran it (`sudo`, `su`, services) |
| 7 | `target_domain_name` | `reserved_1` | Always empty: a domain has no execution equivalent (the account keeps its `DOMAIN\user` form in the user columns) |
| 8 | `src_computer` | `processname` | Binary, script, task or package |
| 9 | `src_ip` | `parentprocessname` | Where the execution came from: the parent process (`C:\Windows\explorer.exe`, `/usr/bin/sudo`) or the component that launched the row (`services.exe`, `Task Scheduler`, `crond`, `systemd`, `WerFault.exe`). When the source only gave a PID (auditd, `pacct`, 4688 before Windows 10) and the creator's own row is in the timeline, the name is filled in as `/usr/bin/sudo (PID: 12493)`. Empty when the source names no creator (Prefetch, Amcache, ShimCache, BAM, `$MFT`, logins). Never a file or a container: that is `source_file` |
| 10 | `subject_user_name` | `subject_username` | Who ran it |
| 11 | `subject_domain_name` | `reserved_2` | Always empty |
| 12 | `logon_id` | `pid` | Process id when the source has one (for 4688 it is the *new* process); the id that ties rows together, as masstin's logon id does |
| 13 | `detail` | `commandline` | Full command line or the details of the artifact |
| 14 | `log_filename` | `source_file` | The file the row was read from, relative to the evidence it came in, with the container first when there is one: `export/logs/Security.evtx` for a folder, `lnx01-logs:var/log/auth.log` for an archive, `disk:partition_0_vss_0/Windows/System32/config/SYSTEM` for a shadow copy inside an image, `pagefile.sys` for a carved blob, the file name for a file given with `-f` |

## The analysis tail

| Column | Meaning |
| :--- | :--- |
| `hunt` | What the hunt made of the row, one of masstin's six values: `significant` (a high rule fired, or a statistical test with q ≤ alpha), `candidate` (a medium rule, or a low rule on a row no test judged, or a test above alpha), `habitual` (a clean reference host executes the same thing; also the statistical tests' word), `not_evaluated` and `baseline` (the statistical tests' words, from phase H4), or empty: nothing judged the row. When a rule and a test both speak, the stronger state wins; a low rule never lowers a test's state. A rule measured common (fewer than 10 points: it fires on more than one clean row in ten) is noise on that kind of row and gives neither state nor points, only its clause. `suspicious` is the analyst's word and lives in `verdict` |
| `hunt_score` | How rare the row is, an integer from 0 to 100 on masstin's scale, `-10 · log10` of a probability: 13 is one in twenty, 30 one in a thousand, 60 one in a million. A statistical test contributes `-10 · log10(q)`; a rule contributes the rarity of its pattern **measured** on stock, clean reference timelines (how often it fires there; a pattern that never fired gets the bound the corpus gives, see [How `hunt_score` is measured](hunting.md#how-hunt_score-is-measured)). Contributions add, capped at 100. A rule not measured yet adds 0 and says so in `hunt_why`. The rule's catalogue score never goes here; it stays in the findings table. Empty when nothing judged the row |
| `hunt_why` | Why, in words, naming the source: a rule's clause starts with `rule <ID> (<level>):`, a test's clause is in words without the prefix; the strongest first, separated by `; `, the lineage last. `rule GEN-OFFICE-SHELL (high): winword.exe launched cmd.exe [T1566.001]; rule GEN-PARENT-GONE (low): creator had exited [T1134.004]; lineage: explorer.exe > WINWORD.EXE > cmd.exe`. Filter on `rule ` to keep the rules, on its absence to keep the statistics |
| `verdict` | The analyst's: `suspicious`, `confirmed`, `benign`, or empty. Never written by CAAREA |
| `notes` | The analyst's free text |

Two real rows (the empty tail is written bare, `,,,,,`, as masstin writes it; an empty event field is `""`):

```csv
"2016-09-21T03:41:02.560546Z","IE10Win7","evtx:4688",4688,"live","","","C:\Windows\duKhLYUX.exe","","WORKGROUP\IE10WIN7$","",3744,"C:\Windows\duKhLYUX.exe","metasploit-psexec-native-target-security.evtx",,,,,
"2026-10-28T22:01:03.000000Z","rf-1a182f1b960-leo-lnx01","linux:syslog:sudo",0,"live","root","","/usr/bin/tee","sudo","c00pr","",0,"/usr/bin/tee /etc/cron.d/caarea","lnx01-logs:var/log/auth.log",,,,,
```

The same first row after `caarea --hunt` (the fourteen event columns do not change a byte; only the tail is filled):

```csv
"2016-09-21T03:41:02.560546Z","IE10Win7","evtx:4688",4688,"live","","","C:\Windows\duKhLYUX.exe","","WORKGROUP\IE10WIN7$","",3744,"C:\Windows\duKhLYUX.exe","metasploit-psexec-native-target-security.evtx","candidate",72,"rule PATH-WINDOWS-ROOT (medium): duKhLYUX.exe ran from the root of C:\Windows [T1036.005]; rule NAM-RANDOM (low): duKhLYUX.exe has a generated-looking name (random letters) [T1036]; lineage: duKhLYUX.exe",,
```

## Reading it

- **Timeline Explorer** (Eric Zimmerman) opens it as is; filter `hunt` for `significant` and `candidate`, sort `hunt_score` descending.
- **PowerShell**: `Import-Csv timeline.csv | ? hunt | sort {[int]$_.hunt_score} -Desc | ft hunt,hunt_score,timestamp,processname`.
- **Next to the other three.** Concatenate a masstin, a faramir, an allymacb and a caarea timeline (drop the extra headers) and sort on the first column: column 1 is always the time, 2 the host, 3 the kind of event, 14 the file it came from, 15 to 19 the tail. Each tool keeps its own header, so the first line says which it is.
- **masstin's viewer** and any case tool that already reads masstin's tail reads CAAREA's unchanged.
- Two CSVs from two hosts can be concatenated (drop the second header) and sorted by the first column: the fixed-width UTC timestamps keep them in order.
