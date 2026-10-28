//! Host time zone discovery for zone-less Linux timestamps (classic syslog, `dpkg.log`,
//! `ps lstart`, access logs without offset).
//!
//! The zone is taken from the evidence itself, in this order of confidence:
//! 1. `etc/timezone` (IANA name, Debian family)
//! 2. `etc/localtime.symlink` sidecar written by the archive extractor (`.../zoneinfo/<name>`)
//! 3. `etc/localtime` as a regular TZif file (RHEL family copies it) – parsed natively
//! 4. UAC `live_response/system/timedatectl_status.txt` (`Time zone: Europe/Madrid (CET, +0100)`)
//! 5. UAC `live_response/system/date.txt` abbreviation (`CET`, `EDT`, ...) – fixed offset only
//! 6. UTC, with a warning
//!
//! IANA names are resolved with the embedded tz database (`chrono-tz`), so DST is applied
//! correctly for every date; TZif files use their own transition table.

use chrono::{DateTime, Duration, FixedOffset, LocalResult, NaiveDateTime, TimeZone, Utc};
use chrono_tz::Tz;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

/// Parsed TZif (RFC 8536) zone file: transition table + local time types.
#[derive(Debug, Clone)]
pub struct TzifData {
    transitions: Vec<i64>,
    type_idx: Vec<u8>,
    /// (utoff seconds, is_dst)
    types: Vec<(i32, bool)>,
    pub footer: Option<String>,
}

impl TzifData {
    /// UTC offset (seconds) in force for a *local* wall-clock time.
    /// Ambiguous times (DST fall-back hour) resolve to the earlier instant; times inside a
    /// spring-forward gap resolve to the offset after the gap.
    pub fn offset_for_local(&self, local_secs: i64) -> i32 {
        if self.types.is_empty() {
            return 0;
        }
        if self.transitions.is_empty() {
            return self.types[0].0;
        }
        for i in 0..self.transitions.len() {
            let off = self.types[self.type_idx[i] as usize % self.types.len()].0 as i64;
            let start = self.transitions[i];
            let end = self.transitions.get(i + 1).copied().unwrap_or(i64::MAX);
            let utc = local_secs - off;
            if utc >= start && utc < end {
                return off as i32;
            }
        }
        // Before the first transition: first standard-time type (or type 0)
        let first_std = self.types.iter().find(|t| !t.1).map(|t| t.0).unwrap_or(self.types[0].0);
        if (local_secs - first_std as i64) < self.transitions[0] {
            return first_std;
        }
        // Inside a gap or after the last transition: offset of the last applicable type
        let last_idx = *self.type_idx.last().unwrap_or(&0) as usize % self.types.len();
        self.types[last_idx].0
    }
}

fn be_u32(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o + 4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Parses a TZif v1/v2/v3 file. The 64-bit (v2+) block is preferred when present.
pub fn parse_tzif(data: &[u8]) -> Option<TzifData> {
    if data.len() < 44 || &data[0..4] != b"TZif" {
        return None;
    }
    let version = data[4];
    let counts = |h: usize| -> Option<[usize; 6]> {
        let mut c = [0usize; 6];
        for (i, slot) in c.iter_mut().enumerate() {
            *slot = be_u32(data, h + 20 + i * 4)? as usize;
        }
        Some(c)
    };
    // [isutcnt, isstdcnt, leapcnt, timecnt, typecnt, charcnt]
    let c1 = counts(0)?;
    let v1_len = c1[3] * 4 + c1[3] + c1[4] * 6 + c1[5] + c1[2] * 8 + c1[1] + c1[0];

    let (hdr, c, time_size) = if version >= b'2' && data.len() >= 44 + v1_len + 44 && &data[44 + v1_len..44 + v1_len + 4] == b"TZif" {
        let h2 = 44 + v1_len;
        (h2, counts(h2)?, 8usize)
    } else {
        (0usize, c1, 4usize)
    };

    let mut p = hdr + 44;
    let timecnt = c[3];
    let typecnt = c[4];
    if typecnt == 0 {
        return None;
    }
    let mut transitions = Vec::with_capacity(timecnt);
    for _ in 0..timecnt {
        let t = if time_size == 8 {
            let b = data.get(p..p + 8)?;
            i64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
        } else {
            be_u32(data, p)? as i32 as i64
        };
        transitions.push(t);
        p += time_size;
    }
    let type_idx = data.get(p..p + timecnt)?.to_vec();
    p += timecnt;
    let mut types = Vec::with_capacity(typecnt);
    for _ in 0..typecnt {
        let b = data.get(p..p + 6)?;
        let utoff = i32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        types.push((utoff, b[4] != 0));
        p += 6;
    }
    p += c[5]; // designations
    p += c[2] * (time_size + 4); // leap seconds
    p += c[1] + c[0]; // isstd / isut indicators
    let footer = if time_size == 8 {
        data.get(p..)
            .map(|rest| String::from_utf8_lossy(rest).trim().to_string())
            .filter(|s| !s.is_empty())
    } else {
        None
    };

    Some(TzifData { transitions, type_idx, types, footer })
}

#[derive(Debug, Clone)]
enum Kind {
    Utc,
    Named(Tz),
    Fixed(FixedOffset),
    Tzif(TzifData),
}

/// The time zone a Linux host was running in, with its provenance.
#[derive(Debug, Clone)]
pub struct HostTimezone {
    kind: Kind,
    pub name: String,
    pub source: String,
}

/// Fixed offsets for the abbreviations UAC's `date.txt` may show (only unambiguous ones).
const ABBREVIATIONS: &[(&str, i32)] = &[
    ("UTC", 0), ("GMT", 0), ("Z", 0), ("WET", 0), ("WEST", 3600), ("BST", 3600),
    ("CET", 3600), ("CEST", 7200), ("EET", 7200), ("EEST", 10800), ("MSK", 10800),
    ("EST", -18000), ("EDT", -14400), ("CDT", -18000), ("MST", -25200), ("MDT", -21600),
    ("PST", -28800), ("PDT", -25200), ("AKST", -32400), ("AKDT", -28800), ("HST", -36000),
    ("JST", 32400), ("KST", 32400), ("AEST", 36000), ("AEDT", 39600), ("AWST", 28800),
    ("NZST", 43200), ("NZDT", 46800), ("ART", -10800), ("BRT", -10800), ("CLT", -14400),
    ("COT", -18000), ("PET", -18000), ("SAST", 7200), ("WAT", 3600), ("EAT", 10800),
];

fn parse_fixed_offset(s: &str) -> Option<FixedOffset> {
    let t = s.trim();
    let (sign, rest) = match t.chars().next()? {
        '+' => (1, &t[1..]),
        '-' => (-1, &t[1..]),
        _ => return None,
    };
    let digits: String = rest.chars().filter(|c| c.is_ascii_digit()).collect();
    let (h, m) = match digits.len() {
        1 | 2 => (digits.parse::<i32>().ok()?, 0),
        3 => (digits[..1].parse::<i32>().ok()?, digits[1..].parse::<i32>().ok()?),
        4 => (digits[..2].parse::<i32>().ok()?, digits[2..].parse::<i32>().ok()?),
        _ => return None,
    };
    if h > 14 || m > 59 {
        return None;
    }
    FixedOffset::east_opt(sign * (h * 3600 + m * 60))
}

impl HostTimezone {
    pub fn utc() -> Self {
        Self { kind: Kind::Utc, name: "UTC".to_string(), source: "default".to_string() }
    }

    pub fn is_utc(&self) -> bool {
        matches!(self.kind, Kind::Utc)
    }

    fn named(tz: Tz, source: &str) -> Self {
        Self { kind: Kind::Named(tz), name: tz.name().to_string(), source: source.to_string() }
    }

    fn fixed(off: FixedOffset, source: &str) -> Self {
        Self { kind: Kind::Fixed(off), name: format!("UTC{}", off), source: source.to_string() }
    }

    /// Builds a zone from a user specification: an IANA name (`Europe/Madrid`), `UTC`, or a
    /// fixed offset (`+02:00`, `-0500`, `+2`).
    pub fn from_spec(spec: &str) -> Option<Self> {
        let t = spec.trim();
        if t.eq_ignore_ascii_case("utc") || t.eq_ignore_ascii_case("z") || t.eq_ignore_ascii_case("gmt") {
            return Some(Self { kind: Kind::Utc, name: "UTC".to_string(), source: "--tz".to_string() });
        }
        if let Ok(tz) = t.parse::<Tz>() {
            return Some(Self::named(tz, "--tz"));
        }
        if let Some(off) = parse_fixed_offset(t) {
            return Some(Self::fixed(off, "--tz"));
        }
        ABBREVIATIONS
            .iter()
            .find(|(a, _)| a.eq_ignore_ascii_case(t))
            .and_then(|(_, secs)| FixedOffset::east_opt(*secs))
            .map(|off| Self::fixed(off, "--tz"))
    }

    /// Converts a wall-clock time of the host into UTC.
    pub fn local_to_utc(&self, ndt: NaiveDateTime) -> DateTime<Utc> {
        match &self.kind {
            Kind::Utc => DateTime::<Utc>::from_naive_utc_and_offset(ndt, Utc),
            Kind::Fixed(off) => {
                let shifted = ndt - Duration::seconds(off.local_minus_utc() as i64);
                DateTime::<Utc>::from_naive_utc_and_offset(shifted, Utc)
            }
            Kind::Named(tz) => match tz.from_local_datetime(&ndt) {
                LocalResult::Single(dt) | LocalResult::Ambiguous(dt, _) => dt.with_timezone(&Utc),
                LocalResult::None => tz
                    .from_local_datetime(&(ndt + Duration::hours(1)))
                    .earliest()
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|| DateTime::<Utc>::from_naive_utc_and_offset(ndt, Utc)),
            },
            Kind::Tzif(tzif) => {
                let local_secs = ndt.and_utc().timestamp();
                let off = tzif.offset_for_local(local_secs) as i64;
                DateTime::<Utc>::from_naive_utc_and_offset(ndt - Duration::seconds(off), Utc)
            }
        }
    }

    /// Human readable summary: `Europe/Madrid (source: etc/timezone)`
    pub fn describe(&self) -> String {
        format!("{} (source: {})", self.name, self.source)
    }

    fn from_iana_name(name: &str, source: &str) -> Option<Self> {
        let clean = name.trim().trim_matches('"').trim_matches('\'');
        if clean.is_empty() {
            return None;
        }
        if clean.eq_ignore_ascii_case("utc") || clean.eq_ignore_ascii_case("etc/utc") {
            return Some(Self { kind: Kind::Utc, name: "UTC".to_string(), source: source.to_string() });
        }
        clean.parse::<Tz>().ok().map(|tz| Self::named(tz, source))
    }

    fn from_zoneinfo_path(path: &str, source: &str) -> Option<Self> {
        let norm = path.trim().replace('\\', "/");
        let name = norm.split("zoneinfo/").nth(1).or_else(|| norm.split("zoneinfo.default/").nth(1))?;
        Self::from_iana_name(name, source)
    }

    fn from_timedatectl(text: &str, source: &str) -> Option<Self> {
        let line = text.lines().find(|l| l.contains("Time zone:"))?;
        let value = line.split("Time zone:").nth(1)?.trim();
        let name = value.split_whitespace().next().unwrap_or("");
        if let Some(tz) = Self::from_iana_name(name, source) {
            return Some(tz);
        }
        // "(CET, +0100)" fallback
        let inside = value.split('(').nth(1)?.trim_end_matches(')');
        let off = inside.split(',').nth(1).and_then(parse_fixed_offset)?;
        Some(Self::fixed(off, source))
    }

    fn from_date_output(text: &str, source: &str) -> Option<Self> {
        // "Wed Oct 28 15:58:29 CET 2026" / "Tue Sep 23 15:51:56 +0200 2026"
        let line = text.lines().find(|l| !l.trim().is_empty())?;
        for tok in line.split_whitespace() {
            if let Some(off) = parse_fixed_offset(tok) {
                return Some(Self::fixed(off, source));
            }
            if let Some((_, secs)) = ABBREVIATIONS.iter().find(|(a, _)| *a == tok) {
                return FixedOffset::east_opt(*secs).map(|off| Self::fixed(off, source));
            }
        }
        None
    }

    /// Discovers the host time zone from the evidence tree (see module docs for the order).
    pub fn detect(target: &Path) -> Self {
        let mut timezone_file = None;
        let mut localtime_link = None;
        let mut localtime_tzif = None;
        let mut timedatectl = None;
        let mut date_txt = None;

        for entry in WalkDir::new(target).max_depth(7).into_iter().flatten() {
            let p = entry.path();
            if !p.is_file() {
                continue;
            }
            let fname = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let parent = p
                .parent()
                .and_then(|d| d.file_name())
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_lowercase();
            match fname {
                "timezone" if parent == "etc" && timezone_file.is_none() => timezone_file = Some(p.to_path_buf()),
                "localtime.symlink" if parent == "etc" && localtime_link.is_none() => localtime_link = Some(p.to_path_buf()),
                "localtime" if parent == "etc" && localtime_tzif.is_none() => localtime_tzif = Some(p.to_path_buf()),
                "timedatectl_status.txt" if timedatectl.is_none() => timedatectl = Some(p.to_path_buf()),
                "date.txt" if parent == "system" && date_txt.is_none() => date_txt = Some(p.to_path_buf()),
                _ => {}
            }
        }

        if let Some(p) = timezone_file {
            if let Some(tz) = fs::read_to_string(&p).ok().and_then(|s| Self::from_iana_name(s.lines().next().unwrap_or(""), "etc/timezone")) {
                return tz;
            }
        }
        if let Some(p) = localtime_link {
            if let Some(tz) = fs::read_to_string(&p).ok().and_then(|s| Self::from_zoneinfo_path(&s, "etc/localtime symlink")) {
                return tz;
            }
        }
        if let Some(p) = localtime_tzif {
            if let Some(data) = fs::read(&p).ok().and_then(|d| parse_tzif(&d)) {
                let name = data.footer.clone().unwrap_or_else(|| "TZif".to_string());
                return Self { kind: Kind::Tzif(data), name, source: "etc/localtime (TZif)".to_string() };
            }
        }
        if let Some(p) = timedatectl {
            if let Some(tz) = fs::read_to_string(&p).ok().and_then(|s| Self::from_timedatectl(&s, "timedatectl_status.txt")) {
                return tz;
            }
        }
        if let Some(p) = date_txt {
            if let Some(tz) = fs::read_to_string(&p).ok().and_then(|s| Self::from_date_output(&s, "date.txt")) {
                return tz;
            }
        }
        Self { kind: Kind::Utc, name: "UTC".to_string(), source: "no time zone artifact found, assuming UTC".to_string() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    fn naive(y: i32, mo: u32, d: u32, h: u32, mi: u32) -> NaiveDateTime {
        NaiveDate::from_ymd_opt(y, mo, d).unwrap().and_hms_opt(h, mi, 0).unwrap()
    }

    fn fixture(name: &str) -> Vec<u8> {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tz").join(name);
        fs::read(p).expect("tz fixture")
    }

    #[test]
    fn test_tzif_real_zone_files() {
        let madrid = parse_tzif(&fixture("Europe_Madrid")).expect("parse Europe/Madrid TZif");
        assert_eq!(madrid.footer.as_deref(), Some("CET-1CEST,M3.5.0,M10.5.0/3"));
        let tz = HostTimezone { kind: Kind::Tzif(madrid), name: "x".into(), source: "test".into() };
        assert_eq!(tz.local_to_utc(naive(2026, 7, 15, 12, 0)).to_rfc3339(), "2026-07-15T10:00:00+00:00");
        assert_eq!(tz.local_to_utc(naive(2026, 1, 15, 12, 0)).to_rfc3339(), "2026-01-15T11:00:00+00:00");
        assert_eq!(tz.local_to_utc(naive(2010, 9, 20, 3, 10)).to_rfc3339(), "2010-09-20T01:10:00+00:00");

        let ny = parse_tzif(&fixture("America_New_York")).expect("parse America/New_York TZif");
        let tz = HostTimezone { kind: Kind::Tzif(ny), name: "x".into(), source: "test".into() };
        assert_eq!(tz.local_to_utc(naive(2026, 7, 15, 12, 0)).to_rfc3339(), "2026-07-15T16:00:00+00:00");
        assert_eq!(tz.local_to_utc(naive(2026, 1, 15, 12, 0)).to_rfc3339(), "2026-01-15T17:00:00+00:00");
    }

    #[test]
    fn test_named_zone_matches_tzif() {
        let named = HostTimezone::from_spec("Europe/Madrid").unwrap();
        let tzif = HostTimezone { kind: Kind::Tzif(parse_tzif(&fixture("Europe_Madrid")).unwrap()), name: "x".into(), source: "t".into() };
        for (y, mo, d, h) in [(2024, 3, 31, 1), (2024, 3, 31, 3), (2024, 10, 27, 1), (2025, 6, 1, 0), (2023, 12, 31, 23)] {
            let n = naive(y, mo, d, h, 30);
            assert_eq!(named.local_to_utc(n), tzif.local_to_utc(n), "{}", n);
        }
    }

    #[test]
    fn test_specs_and_text_sources() {
        assert_eq!(HostTimezone::from_spec("+02:00").unwrap().local_to_utc(naive(2026, 1, 1, 12, 0)).to_rfc3339(), "2026-01-01T10:00:00+00:00");
        assert_eq!(HostTimezone::from_spec("-0500").unwrap().local_to_utc(naive(2026, 1, 1, 12, 0)).to_rfc3339(), "2026-01-01T17:00:00+00:00");
        assert!(HostTimezone::from_spec("UTC").unwrap().is_utc());
        assert!(HostTimezone::from_spec("Mars/Olympus").is_none());

        let td = HostTimezone::from_timedatectl("               Local time: Wed 2026-10-28 15:58:29 CET\n                Time zone: Europe/Madrid (CET, +0100)\n", "t").unwrap();
        assert_eq!(td.name, "Europe/Madrid");
        let td2 = HostTimezone::from_timedatectl("Time zone: n/a (CEST, +0200)", "t").unwrap();
        assert_eq!(td2.local_to_utc(naive(2026, 7, 1, 12, 0)).to_rfc3339(), "2026-07-01T10:00:00+00:00");
        let d = HostTimezone::from_date_output("Wed Oct 28 15:58:29 CET 2026\n", "t").unwrap();
        assert_eq!(d.local_to_utc(naive(2026, 10, 28, 15, 58)).to_rfc3339(), "2026-10-28T14:58:00+00:00");
        let l = HostTimezone::from_zoneinfo_path("/usr/share/zoneinfo/America/New_York", "t").unwrap();
        assert_eq!(l.name, "America/New_York");
    }

    #[test]
    fn test_detect_from_evidence_tree() {
        let root = std::env::temp_dir().join(format!("caarea_tz_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("[root]/etc")).unwrap();
        fs::create_dir_all(root.join("live_response/system")).unwrap();

        // Only date.txt -> fixed offset
        fs::write(root.join("live_response/system/date.txt"), "Tue Sep 23 15:51:56 CEST 2026\n").unwrap();
        let tz = HostTimezone::detect(&root);
        assert_eq!(tz.source, "date.txt");
        assert_eq!(tz.local_to_utc(naive(2026, 9, 23, 15, 51)).to_rfc3339(), "2026-09-23T13:51:00+00:00");

        // TZif file wins over date.txt
        fs::write(root.join("[root]/etc/localtime"), fixture("America_New_York")).unwrap();
        let tz = HostTimezone::detect(&root);
        assert_eq!(tz.source, "etc/localtime (TZif)");

        // The symlink sidecar and etc/timezone win over the TZif file
        fs::write(root.join("[root]/etc/localtime.symlink"), "/usr/share/zoneinfo/Asia/Tokyo").unwrap();
        assert_eq!(HostTimezone::detect(&root).name, "Asia/Tokyo");
        fs::write(root.join("[root]/etc/timezone"), "Europe/Madrid\n").unwrap();
        let tz = HostTimezone::detect(&root);
        assert_eq!(tz.name, "Europe/Madrid");
        assert_eq!(tz.source, "etc/timezone");

        let _ = fs::remove_dir_all(&root);
        assert!(HostTimezone::detect(Path::new("/definitely/not/here")).is_utc());
    }
}
