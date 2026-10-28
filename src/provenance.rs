//! Where a row came from.
//!
//! Every event carries its artifact name (`evtx:4688`, `registry:bam`, `linux:audit:execve`).
//! When the row was not read from the live evidence, the origin is appended to that name as
//! extra segments, with the detail in brackets, so the column stays filterable and the
//! vocabulary is the same one faramir uses:
//!
//! | origin | example |
//! |---|---|
//! | live | `evtx:4688` |
//! | only in a Volume Shadow Copy | `evtx:4688:vss [2026-09-04T08:12:53Z]` |
//! | recovered from a freed structure (hive cell, unused MFT record) | `registry:bam:deleted` |
//! | recovered from an old transaction-log entry | `registry:run:txlog` |
//! | signature-carved from raw bytes | `evtx:4688:carved [@0x1c3f80000]` |
//! | freed cell inside a carved hive | `registry:run:carved:deleted [@0x1c3f80000]` |
//!
//! Deduplication compares every column ignoring the origin, and when two rows collide the
//! one with the lower [`Origin::rank`] is kept: live beats a shadow copy, a shadow copy beats
//! a recovered structure, a recovered structure beats a carved one.

use std::fmt;

/// How a row was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Origin {
    Live,
    Vss,
    Deleted,
    Txlog,
    Carved,
    CarvedDeleted,
}

impl Origin {
    /// Segments appended to the artifact name (empty for live rows).
    pub fn segment(self) -> &'static str {
        match self {
            Origin::Live => "",
            Origin::Vss => "vss",
            Origin::Deleted => "deleted",
            Origin::Txlog => "txlog",
            Origin::Carved => "carved",
            Origin::CarvedDeleted => "carved:deleted",
        }
    }

    /// Precedence when two otherwise identical rows collide: lower wins.
    pub fn rank(self) -> u8 {
        match self {
            Origin::Live => 0,
            Origin::Vss => 1,
            Origin::Deleted => 2,
            Origin::Txlog => 3,
            Origin::Carved => 4,
            Origin::CarvedDeleted => 5,
        }
    }

    /// Every non-live origin, longest segment first so parsing is unambiguous.
    const TAGGED: [Origin; 5] = [Origin::CarvedDeleted, Origin::Carved, Origin::Deleted, Origin::Txlog, Origin::Vss];
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if *self == Origin::Live { "live" } else { self.segment() })
    }
}

/// An origin plus its detail: snapshot time, byte offset, container name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Provenance {
    pub origin: Origin,
    /// Free text shown in brackets after the artifact: `2026-09-04T08:12:53Z`, `@0x1c3f80000`,
    /// `pagefile @0x4f000`. Empty when there is nothing to add.
    pub detail: String,
}

impl Provenance {
    pub fn live() -> Self {
        Provenance { origin: Origin::Live, detail: String::new() }
    }

    pub fn new(origin: Origin, detail: impl Into<String>) -> Self {
        Provenance { origin, detail: detail.into() }
    }

    /// Shadow copy created at `snapshot_time` (canonical UTC string).
    pub fn vss(snapshot_time: impl Into<String>) -> Self {
        Provenance::new(Origin::Vss, snapshot_time)
    }

    /// Carved at `offset` of `container` (`None` for the disk image itself).
    pub fn carved(offset: u64, container: Option<&str>) -> Self {
        let detail = match container {
            Some(c) => format!("{} @{:#x}", c, offset),
            None => format!("@{:#x}", offset),
        };
        Provenance::new(Origin::Carved, detail)
    }

    pub fn is_live(&self) -> bool {
        self.origin == Origin::Live
    }

    /// Artifact name with this provenance applied to `base`.
    pub fn apply(&self, base: &str) -> String {
        let mut out = String::with_capacity(base.len() + self.detail.len() + 16);
        out.push_str(base);
        if self.origin != Origin::Live {
            out.push(':');
            out.push_str(self.origin.segment());
        }
        if !self.detail.is_empty() {
            out.push_str(" [");
            out.push_str(&self.detail);
            out.push(']');
        }
        out
    }

    /// Human form for logs: `vss 2026-09-04T08:12:53Z`, `carved @0x1c3f80000`, `live`.
    pub fn describe(&self) -> String {
        if self.detail.is_empty() {
            self.origin.to_string()
        } else {
            format!("{} {}", self.origin, self.detail)
        }
    }
}

impl fmt::Display for Provenance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.describe())
    }
}

/// Splits a tagged artifact into its base name and provenance.
pub fn split(artifact: &str) -> (&str, Provenance) {
    let (name, detail) = match artifact.find(" [") {
        Some(pos) if artifact.ends_with(']') => (&artifact[..pos], &artifact[pos + 2..artifact.len() - 1]),
        _ => (artifact, ""),
    };
    for origin in Origin::TAGGED {
        let seg = origin.segment();
        if name.len() > seg.len() + 1
            && name.ends_with(seg)
            && name.as_bytes()[name.len() - seg.len() - 1] == b':'
        {
            let base = &name[..name.len() - seg.len() - 1];
            return (base, Provenance::new(origin, detail));
        }
    }
    (name, Provenance::new(Origin::Live, detail))
}

/// Artifact name without its provenance.
pub fn artifact_base(artifact: &str) -> &str {
    split(artifact).0
}

/// Precedence rank of a tagged artifact (0 = live).
pub fn artifact_rank(artifact: &str) -> u8 {
    split(artifact).1.origin.rank()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_rows_are_untouched() {
        assert_eq!(Provenance::live().apply("evtx:4688"), "evtx:4688");
        let (base, p) = split("evtx:4688");
        assert_eq!(base, "evtx:4688");
        assert_eq!(p, Provenance::live());
    }

    #[test]
    fn vss_round_trip() {
        let p = Provenance::vss("2026-09-04T08:12:53Z");
        let tagged = p.apply("evtx:4688");
        assert_eq!(tagged, "evtx:4688:vss [2026-09-04T08:12:53Z]");
        let (base, back) = split(&tagged);
        assert_eq!(base, "evtx:4688");
        assert_eq!(back, p);
    }

    #[test]
    fn deleted_without_detail_and_carved_deleted_with_offset() {
        let d = Provenance::new(Origin::Deleted, "");
        assert_eq!(d.apply("registry:bam"), "registry:bam:deleted");
        assert_eq!(split("registry:bam:deleted"), ("registry:bam", d));

        let cd = Provenance::new(Origin::CarvedDeleted, "@0x1c3f80000");
        let tagged = cd.apply("registry:run");
        assert_eq!(tagged, "registry:run:carved:deleted [@0x1c3f80000]");
        let (base, back) = split(&tagged);
        assert_eq!(base, "registry:run");
        assert_eq!(back.origin, Origin::CarvedDeleted);
        assert_eq!(back.detail, "@0x1c3f80000");
    }

    #[test]
    fn carved_detail_names_the_container() {
        assert_eq!(Provenance::carved(0x4f000, Some("pagefile")).apply("evtx:4688"), "evtx:4688:carved [pagefile @0x4f000]");
        assert_eq!(Provenance::carved(0x4f000, None).detail, "@0x4f000");
    }

    #[test]
    fn ranks_order_live_first() {
        assert!(artifact_rank("evtx:4688") < artifact_rank("evtx:4688:vss [t]"));
        assert!(artifact_rank("evtx:4688:vss [t]") < artifact_rank("evtx:4688:deleted"));
        assert!(artifact_rank("evtx:4688:deleted") < artifact_rank("evtx:4688:carved [@0x1]"));
        assert!(artifact_rank("evtx:4688:carved [@0x1]") < artifact_rank("evtx:4688:carved:deleted [@0x1]"));
    }

    #[test]
    fn brackets_inside_a_name_without_closing_are_left_alone() {
        assert_eq!(artifact_base("linux:web [odd"), "linux:web [odd");
        assert_eq!(artifact_base("linux:shell:bash_history"), "linux:shell:bash_history");
    }
}
