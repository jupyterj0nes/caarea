# Carving

[← README](../README.md)

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

EVTX chunks are never parsed in the main process: each is accepted by its CRC32 and validated in a child process with bisection, so a malformed chunk cannot take the run down. On a 50 GB live workstation volume with 4 GB of RAM a carve pass takes about fifteen minutes; on that host 37,223 of the 69,795 rows existed only carved (an older, cleared Security log, index slack, journal records). `hiberfil.sys` is scanned raw: its Xpress-compressed pages are not decoded yet.

The scanner, the guarded sources and the structural validators are the [blockcarve](https://github.com/jupyterj0nes/blockcarve) crate, shared with masstin, faramir and allymacb, so the four tools read raw bytes the same way and accept a structure for the same reasons.
