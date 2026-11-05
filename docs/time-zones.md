# Time zones, honestly

[← README](../README.md)

Every timestamp in the CSV is UTC. Most sources carry their own zone (EVTX, registry FILETIMEs, audit, pacct, RFC 3339 syslog, web logs with offset) and are simply converted.

Classic syslog lines (`Sep 20 03:10:01`), `dpkg.log` and `ps lstart` are wall-clock times of the host. CAAREA looks for the host's zone in the evidence, in this order, and prints what it found:

1. `/etc/timezone`
2. the target of the `/etc/localtime` symlink (kept by the extractor as `etc/localtime.symlink`)
3. `/etc/localtime` as a TZif file, parsed with its transition table
4. UAC `live_response/system/timedatectl_status.txt`
5. UAC `live_response/system/date.txt`
6. UTC, with a warning

Daylight saving is applied per date through the embedded tz database. Force a zone with `--tz Europe/Madrid`, `--tz +02:00` or `--tz UTC`.

Classic syslog has no year; it is inferred from the file's modification time, so logs spanning more than a year lose precision. The edges of a window (`--toi`, `--start-time`, `--end-time`) are read as UTC; a bare date in `--end-time` includes the whole day.
