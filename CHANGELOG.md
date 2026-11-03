# Changelog

## Unreleased

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
