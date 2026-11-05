# Process hunting

[← README](../README.md)

`--hunt` runs a set of rules over the finished timeline and writes what it made of each row into the row's analysis tail, the convention the four tools share ([the CSV](csv-format.md#the-analysis-tail)):

- `hunt` takes the state of the strongest rule: `significant` for a high rule, `candidate` for a medium or a low one (no test judged the row, and a score must come with a state). A row that a clean reference host also executes is `habitual`.
- `hunt_score` adds up the measured rarity of every rule that fired (a rule measured below 10 points is noise: no state, no points, its clause only), capped at 100.
- `hunt_why` names each rule with its level, strongest first, then the lineage: `rule PATH-WINDOWS-ROOT (medium): duKhLYUX.exe ran from the root of C:\Windows [T1036.005]; rule NAM-RANDOM (low): duKhLYUX.exe has a generated-looking name (random letters) [T1036]; lineage: duKhLYUX.exe`.

The fourteen event columns do not change, and `verdict` / `notes`, the analyst's columns, are never written.

```bash
caarea -f workstation.E01 -o workstation.csv --hunt
caarea -d /cases/acme/triage -o acme.csv --hunt --hunt-output acme.findings.csv --toi 2026-09-24T12:00:00Z
```

## What the console says

The run closes with the rows that deserve reading first, up to five: the strongest state, then the highest score, then the strongest rule, then the earliest. Rows with the same process and the same rules are one entry with a count and the span of time they cover, so a beacon that ran forty times takes one place, not forty; rows a clean host vouches for are left out. Each entry gives the state and the score, when and what ran, who created it, every rule that fired with its level and technique, the rule's explanation in words, and the lineage:

```text
  candidate   39  2026-10-28T20:20:00Z  (9 rows, until 2026-10-28T20:24:02Z)  C:\Users\Public\rf_wpad_beacon.ps1
                  created by powershell.exe
                  PATH-SCRATCH (medium): rf_wpad_beacon.ps1 ran from Users\Public [T1036]
                     C:\Users\Public: Users\Public is writable by everyone and readable by everyone, so it is
                     where tooling is dropped for every account on the host.
```

`-s` silences it with the rest of the console. The full list is the findings table.

## The findings table

The detailed findings go to a second CSV next to the timeline (`host.hunt.csv`, or `--hunt-output`), one row per rule hit, ranked by catalogue score:

```text
rank, significant, p_value, q_value, score, level, rarity, signature, pattern, mitre, title,
time_created, computer, pid, processname, commandline, parentprocessname, subject_username,
artifact, lineage, why_unusual, evidence
```

The first four and the last two columns are the ones masstin's and allymacb's hunt tables use; `significant` is `yes` for a high rule. `score` is the rule's catalogue score, 0 to 100, how sure the author is of the pattern (85 and up is `high`, 60 to 84 `medium`, below `low`), and it lives here and in the code, never in the timeline. `rarity` is what the hit added to `hunt_score`; `pattern` the variant of the rule that was measured (`temp` for `PATH-SCRATCH`, `hex` for `NAM-RANDOM`); `why_unusual` is one sentence saying why the row matters; `evidence` names the rows it was correlated with.

## The rules

The rules only state what a documented source states. The expected-parent and allowed-children tables come from the SANS *Hunt Evil* poster (Lee and Pilkington) cross-checked with Elastic's *Unusual Parent-Child Relationship* rule, which contributes the field exceptions (Defender, Citrix, VMware, Omnissa, Sophos). A pair the tables do not mention gets no opinion.

| Rule | Fires when | Catalogue score |
| :--- | :--- | :--- |
| `GEN-CORE-PARENT` | A core Windows process (`smss`, `csrss`, `wininit`, `winlogon`, `services`, `lsass`, `svchost`, `spoolsv`, `taskhostw`, `userinit`, `RuntimeBroker`, ...) was created by something other than its documented parent | 85 |
| `GEN-RESTRICTED-PARENT` | `smss`, `wininit`, `winlogon`, `lsass`, `csrss`, `autochk`, `wermgr` or `conhost` created a process outside their closed list of children | 70 to 90 |
| `GEN-OFFICE-SHELL`, `GEN-BROWSER-SHELL` | Office, a PDF reader or a browser launched a shell, script host or LOLBin | 75 to 85 |
| `GEN-WEBSERVER-SHELL`, `GEN-DATABASE-SHELL` | `w3wp`, `httpd`, `nginx`, `php-cgi`, Tomcat, `sqlservr`, or on Linux `apache2`, `nginx`, `php-fpm`, `mysqld`, `postgres`, launched a shell | 85 to 95 |
| `GEN-SVCACCT-SHELL` | A Linux service account (`www-data`, `apache`, `mysql`, `postgres`, ...) ran a shell, `nc`, `curl`, `python` | 80 |
| `GEN-SERVICES-SHELL`, `GEN-REMOTE-EXEC` | `services.exe` started a shell as a service binary; `PSEXESVC` or a clone launched anything | 70 to 80 |
| `GEN-ACCESSIBILITY-BACKDOOR` | `winlogon`, `utilman`, `sethc`, `osk`, `narrator`, `magnify`, `DisplaySwitch` or `AtBroker` launched a shell at the logon screen | 95 |
| `GEN-SPOOLER-SHELL`, `GEN-WMI-EXEC` | The print spooler launched a shell; `WmiPrvSE` launched one (remote WMI execution, also used by SCCM) | 60 to 85 |
| `GEN-SVCHOST-SHELL` | A service host launched `cmd`, `powershell`, `mshta`, `wscript`, `cscript`, `certutil` or `bitsadmin`. Scheduled tasks do this legitimately, so it is a pointer, not a verdict | 35 |
| `GEN-EXPLORER-SYSTEM` | A child of `explorer.exe` was created by a SYSTEM or service token | 65 |
| `GEN-PARENT-GONE` | The creator PID belongs to a process that had already exited: PID reuse the logs do not cover, or a spoofed parent | 55 |
| `GEN-DUPLICATE-CORE` | A second `lsass`, `services`, `wininit` or `LsaIso` started in the same boot | 75 |
| `GEN-CRON-SCRATCH` | cron ran a binary from `/tmp`, `/dev/shm`, `/var/tmp` | 75 |
| `NAM-SYSTEM-PATH` | A binary with the name of a system process (`svchost`, `lsass`, `csrss`, `explorer`, `rundll32`, some 150 more; on Linux `sshd`, `cron`, `bash`, `ps`, `ss`, the daemons and coreutils a rootkit replaces) ran or was written outside the folder it belongs to. `/usr/local` and `/opt` copies score 60 | 60 to 90 |
| `NAM-FAKE-KERNEL` | A process named like a kernel thread (`[kworker/0:1]`, `kthreadd`, `ksoftirqd`) came from an `execve` or has a path: kernel threads do neither | 95 |
| `NAM-LOOKALIKE` | A name one look-alike character away from a system binary (`svch0st`, `isass`, `rundl132`), or one edit away (`scvhost`) outside the system folders | 75 to 90 |
| `NAM-DOUBLE-EXT`, `NAM-RTLO`, `NAM-PADDED` | `invoice.pdf.exe`; a right-to-left override or zero-width character in the name; a run of spaces before the extension | 80 to 95 |
| `NAM-RANDOM` | A name a generator wrote: hexadecimal, a GUID outside the Installer folders, random case changes or no vowel (`duKhLYUX.exe`), one or two characters, mostly digits. Not inside System32, Program Files or the update and package folders | 50 to 60 |
| `PATH-WINDOWS-ROOT` | An executable directly in `C:\Windows` that is not one of the few that belong there (PsExec-style droppers) | 70 |
| `PATH-SCRATCH` | Ran or written in the Recycle Bin, a user-writable Windows folder (Temp, Tasks, Fonts, PerfLogs, `spool\drivers`), `Users\Public`, the root of ProgramData, AppData or the drive, Downloads, Temp; on Linux `/dev/shm`, the web root, a hidden folder, `/tmp`, `/var/tmp`, `/run`, a home directory. The folder sets the score; Temp and Downloads are pointers only | 40 to 85 |
| `PATH-ARCHIVE-TEMP` | Ran from the temporary extraction of an archive (`Temp\Rar$`, `Temp\7z`, `Temp\Temp1_`): an attachment opened and run in place | 65 |
| `PATH-ADS`, `PATH-REMOTE` | Ran from an NTFS alternate data stream; from a network share or a WebDAV path | 70 to 90 |

**What the rules need.** Genealogy only fires on sources that name a parent: Security 4688, Sysmon 1, auditd `execve`, `pacct`. The naming and path rules judge any row whose `processname` is an executable (a Windows path or name with a code extension, a Linux absolute path or process record), so they reach Prefetch, Amcache, BAM, ShimCache, UserAssist, AppLocker, the service and task events and the NTFS drops, where the title says *was written to* instead of *ran from*. Task names, service display names, WMI consumers and package names are left alone. On a Windows host with the default audit policy there is no 4688 at all; with 4688 but without command-line auditing the command line is empty. Stock behaviour that lives in scratch folders (Defender's `MPSigStub` and Chrome's updater under `Windows\Temp`, PowerShell's AppLocker probe, KB packages under SoftwareDistribution) is known and silent.

## The process tree behind it

Before the rules run, CAAREA rebuilds the process tree of every host from the creator PIDs (Security 4688 `ProcessId`, Sysmon `ParentProcessId` and the GUID pair, auditd and `pacct` `ppid`) and the exits (4689, Sysmon 5). A parent is the latest start of that PID before the child; a parent that had exited is reported, not guessed. A boot closes every PID: Security 4608 and Kernel-General 12 are read as boot markers (and written to the timeline as `evtx:4608` / `evtx:12`), as are the first `smss.exe` and `wininit.exe` of a boot, so a Windows 7 log that spans months without 4689 does not hand a service's PID to whatever held it before the reboot.

The tree also completes the timeline where the parser could only give a number: auditd and `pacct` rows show `/usr/bin/sudo (PID: 12493)` instead of `PID: 12493`, and Security 4688 from Windows 7 / 2008 R2 / 2012, which has no `ParentProcessName`, gets the creator's name the same way. A resolved name always keeps its `(PID: n)` so it can be told from one the log wrote. Rows outside a `--toi` window still feed the tree; they just report nothing.

## How `hunt_score` is measured

A rule's points are not chosen: they are how often its pattern fires on stock, clean hosts, on masstin's scale (one hit in 128 reference rows is 21 points, one in a thousand 30; a pattern that never fired gets the bound the corpus gives, `-10 · log10(1 / (rows + 1))`, 39 points on the 8,671 rows of the reference). `scripts/measure_rarity.ps1` runs `caarea --hunt` over the reference evidence, leaves out the rows the lab scripts planted, counts the hits of every pattern (a rule with several, `PATH-SCRATCH` per folder family, `NAM-RANDOM` per shape, is measured per pattern) and rewrites the table in `src/hunt/rarity.rs`, which records the corpus with it.

The table shipped was measured on two clean RangeForge lab hosts collected live, nothing planted: PTR-SRV01 (Windows Server 2016 with SQL Server Express and IIS: event logs, SRUM, Amcache, ShimCache, services, tasks) and LEO-LNX01 (Ubuntu 22.04: journal, syslog, package logs, cron), 8,671 rows in all. Three patterns fired on stock rows and are worth less than the bound:

| Pattern | Stock hits | Points | What fired it |
| :--- | ---: | ---: | :--- |
| `PATH-SCRATCH/windows-writable` | 18 | 27 | `dismhost.exe`, Defender's update stubs and the cloud agent's startup scripts all run from `Windows\TEMP` on a stock server |
| `PATH-SCRATCH/temp` | 4 | 33 | DISM again, from the administrator's Temp |
| `NAM-RANDOM/generated` | 4 | 33 | `SMSvcHost.exe`, `NGenTask.exe`, `BthUdTask.exe`: stock names the shape test takes for generated ones |
| every other pattern | 0 | 39 | the most 8,671 rows can vouch for; a row with three such rules reaches 100 |

The limit of this corpus is the audit policy: the stock server keeps the default one, so it holds 61 process-creation rows without command lines and no Sysmon, and the Linux host has no auditd; the genealogy rules (`GEN-*`), which need a parent, were barely exercised and their 39 is the bound, not a measurement. The next thing to collect is a clean host with process auditing and command lines on, used for a week, and the table will spread out when it is measured there.

## What a clean host vouches for

A rule judges one row; a stock machine produces some of the same rows every day (`dismhost.exe` from a GUID folder under Temp, Defender's update stubs, the cloud agent's startup scripts, `NGenTask.exe`). `src/hunt/clean/windows.tsv` and `linux.tsv` hold what the two clean reference hosts executed (`scripts/measure_clean.py`, the lab's own beacon and the collection's activity left out: 2,752 Windows triples and 520 Linux ones), and at start-up each becomes a host-independent identity (`src/hunt/clean.rs`: environment variables expanded, user names, SIDs, GUIDs, version folders, random temp names, numbers and hashes neutralised). A row with the same identity is vouched for by a clean machine whatever its rules say: the rules keep their clause, add no points, and the row is `habitual` with score 0 and `on the clean reference hosts` in `hunt_why`, the convention of the four tools for an entry something vouches for.

Measured: the clean PTR-SRV01 goes from 26 `candidate` rows to none (the 26 are `habitual`), the clean LEO-LNX01 stays at none. On the same lab's PTR-DC01, a domain controller from the same image on which `scripts/lab/plant.ps1`'s eight executions were run with process auditing and command lines on (a renamed `cmd.exe` from `Users\Public`, `svchost.exe` outside System32, a random name from `Windows\Temp`, encoded PowerShell from `cmd.exe`, a service binary under `ProgramData`, `invoice.pdf.exe`, `certutil -decode`, `rundll32` on a non-DLL) and a WMI event consumer was left firing `powershell.exe` every few seconds: the rules flag the first three and the double extension (`significant` the two name rules, `candidate` the two scratch folders) and every one of the 1,740 process creations the WMI consumer caused (`GEN-WMI-EXEC`); not one flagged row is unplanted. The four misses are rule gaps, not noise: nothing in the catalogue reads an encoded command line launched from `cmd.exe`, treats `ProgramData` as a scratch folder, or knows `certutil -decode` and `rundll32` on a file that is not a DLL.

## What is next

Command-line rules (encoded PowerShell, LOLBin arguments, `certutil -decode`, `rundll32` on a non-DLL), correlation (a drop in `$MFT` / USN followed by its execution, the statistical tests that own `habitual`, `not_evaluated` and `baseline`), filters on the hunt (`--hunt-min-score`, allow lists, a report) and a Sigma subset are the phases still open in the [ROADMAP](../ROADMAP.md).
