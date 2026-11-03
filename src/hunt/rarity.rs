//! What a rule adds to `hunt_score`: how rare its pattern is on stock, clean hosts.
//!
//! `hunt_score` is rarity in the four tools (masstin, caarea, faramir, allymacb): masstin's
//! scale, `-10 · log10` of a probability, 0 to 100. A statistical test contributes
//! `-10 · log10(q)`. A rule contributes the same scale **measured, not chosen**: the
//! probability is how often the pattern fires on the rows of the reference timelines. One hit
//! in 128 rows is 21 points, one in a thousand 30. A pattern that never fired is not "never":
//! the corpus bounds what it can say, so it gets `-10 · log10(1 / (rows + 1))`, 39 points on
//! the 8,671 reference rows (the convention of the four tools, masstin's `docs/csv-format.md`). A rule's catalogue score (the author's confidence) is
//! not a `hunt_score` and stays in the code and in the findings table.
//!
//! The table below is written by `scripts/measure_rarity.ps1`: it runs `caarea --hunt` over the
//! reference evidence, drops the rows the lab scripts planted (listed in the script), counts
//! the hits of every key and prints `MEASURED`. A key that is not in the table is a rule not
//! measured yet: it contributes 0 and `hunt_why` says so. Re-run the script when the rules or
//! the reference corpus change, and keep `REFERENCE` and `REFERENCE_ROWS` with the table.

/// The reference corpus the table was measured on.
pub const REFERENCE: &str = "Two clean RangeForge lab hosts collected live on 2026-11-03, nothing planted: PTR-SRV01 (Windows Server 2016 with SQL Server Express and IIS: Security, System, Application, both PowerShell logs, TaskScheduler, WMI-Activity, Defender, AppLocker, WinRM, SRUM, Amcache, ShimCache, services, tasks, installed programs; the default audit policy, so 61 process-creation rows without command lines and no Sysmon) and LEO-LNX01 (Ubuntu 22.04: journal, syslog, dpkg and apt logs, cron, utmp, cloud-init; no auditd, no pacct). 8,671 rows. The genealogy rules, which need a parent, met only those 61 rows: their 39 is the corpus bound, not a measurement";

/// Rows of the reference timelines (both hosts).
pub const REFERENCE_ROWS: u32 = 8_671;

/// Top of the scale.
pub const SCORE_MAX: u8 = 100;

/// Points of a pattern that never fired on `rows` reference rows: the bound the corpus
/// gives, `-10 · log10(1 / (rows + 1))`.
pub fn never_fired(rows: u32) -> u8 {
    points_for(1, rows + 1)
}

/// Hits of every rule pattern on the reference rows. The key is the rule id, with
/// `/pattern` when the rule has several (`PATH-SCRATCH/temp`, `NAM-RANDOM/hex`).
/// Written by `scripts/measure_rarity.ps1`; the comments are the script's too.
pub const MEASURED: &[(&str, u32)] = &[
    // genealogy
    ("GEN-ACCESSIBILITY-BACKDOOR", 0),
    ("GEN-BROWSER-SHELL", 0),
    ("GEN-CORE-PARENT", 0),
    ("GEN-CRON-SCRATCH", 0),
    ("GEN-DATABASE-SHELL", 0),
    ("GEN-DUPLICATE-CORE", 0),
    ("GEN-EXPLORER-SYSTEM", 0),
    ("GEN-OFFICE-SHELL", 0),
    ("GEN-PARENT-GONE", 0),
    ("GEN-REMOTE-EXEC", 0),
    ("GEN-RESTRICTED-PARENT", 0),
    ("GEN-RESTRICTED-PARENT/critical", 0),
    ("GEN-SERVICES-SHELL", 0),
    ("GEN-SPOOLER-SHELL", 0),
    ("GEN-SVCACCT-SHELL", 0),
    ("GEN-SVCHOST-SHELL", 0),
    ("GEN-WEBSERVER-SHELL", 0),
    ("GEN-WMI-EXEC", 0),
    // naming
    ("NAM-DOUBLE-EXT", 0),
    ("NAM-FAKE-KERNEL", 0),
    ("NAM-LOOKALIKE/edit", 0),
    ("NAM-LOOKALIKE/homoglyph", 0),
    ("NAM-PADDED", 0),
    ("NAM-RANDOM/digits", 0),
    ("NAM-RANDOM/generated", 4),
    ("NAM-RANDOM/guid", 0),
    ("NAM-RANDOM/hex", 0),
    ("NAM-RANDOM/odd", 0),
    ("NAM-RANDOM/tiny", 0),
    ("NAM-RTLO", 0),
    ("NAM-SYSTEM-PATH", 0),
    ("NAM-SYSTEM-PATH/local", 0),
    // path
    ("PATH-ADS", 0),
    ("PATH-ARCHIVE-TEMP", 0),
    ("PATH-REMOTE/share", 0),
    ("PATH-REMOTE/webdav", 0),
    ("PATH-SCRATCH/dev-shm", 0),
    ("PATH-SCRATCH/downloads-desktop", 0),
    ("PATH-SCRATCH/drive-root", 0),
    ("PATH-SCRATCH/hidden", 0),
    ("PATH-SCRATCH/home", 0),
    ("PATH-SCRATCH/local-appdata", 0),
    ("PATH-SCRATCH/mnt", 0),
    ("PATH-SCRATCH/profile", 0),
    ("PATH-SCRATCH/programdata", 0),
    ("PATH-SCRATCH/public", 0),
    ("PATH-SCRATCH/recycle", 0),
    ("PATH-SCRATCH/roaming", 0),
    ("PATH-SCRATCH/root-home", 0),
    ("PATH-SCRATCH/run", 0),
    ("PATH-SCRATCH/temp", 4),
    ("PATH-SCRATCH/tmp", 0),
    ("PATH-SCRATCH/var", 0),
    ("PATH-SCRATCH/web-root", 0),
    ("PATH-SCRATCH/windows-writable", 18),
    ("PATH-WINDOWS-ROOT", 0),
];

/// The points of a pattern that fired `hits` times on `rows` reference rows: `-10 · log10
/// (hits / rows)`, rounded, 0 to `SCORE_MAX`; the corpus bound when it never fired.
pub fn points_for(hits: u32, rows: u32) -> u8 {
    if rows == 0 {
        return 0;
    }
    if hits == 0 {
        return never_fired(rows);
    }
    let p = hits as f64 / rows as f64;
    let s = (-10.0 * p.log10()).round();
    s.clamp(0.0, SCORE_MAX as f64) as u8
}

/// The points a rule pattern adds to `hunt_score`; None when the pattern was never measured.
pub fn points(key: &str) -> Option<u8> {
    MEASURED.iter().find(|(k, _)| *k == key).map(|(_, hits)| points_for(*hits, REFERENCE_ROWS))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_points_follow_masstins_scale() {
        assert_eq!(points_for(0, 8_671), 39);
        assert_eq!(never_fired(REFERENCE_ROWS), 39);
        assert_eq!(points("PATH-SCRATCH/windows-writable"), Some(27), "18 of 8,671: dismhost, Defender updates and the cloud agent's startup scripts run from Windows\\TEMP on a stock server");
        assert_eq!(points("NAM-RANDOM/generated"), Some(33));
        assert_eq!(points("PATH-SCRATCH/temp"), Some(33));
        assert_eq!(never_fired(12_183), 41);
        assert_eq!(points_for(0, 0), 0);
        assert_eq!(points_for(1, 128), 21);
        assert_eq!(points_for(1, 1_000), 30);
        assert_eq!(points_for(1, 100), 20);
        assert_eq!(points_for(500, 1_000), 3);
        assert_eq!(points_for(1_000, 1_000), 0);
        assert_eq!(points_for(2_000, 1_000), 0);
        assert_eq!(points_for(1, 4_000_000_000), 96);
        assert_eq!(points_for(0, 4_000_000_000), 96);
    }

    #[test]
    fn test_table_is_sorted_unique_and_known_keys_answer() {
        for w in MEASURED.windows(2) {
            assert!(w[0].0 < w[1].0, "{} before {}", w[0].0, w[1].0);
        }
        assert!(points("GEN-OFFICE-SHELL").is_some());
        assert!(points("PATH-SCRATCH/temp").is_some());
        assert_eq!(points("NO-SUCH-RULE"), None);
        assert_eq!(points("PATH-SCRATCH"), None, "a rule with patterns is measured per pattern");
    }
}
