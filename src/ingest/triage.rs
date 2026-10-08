use std::path::Path;

/// Supported forensic triage package types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriageType {
    Kape,
    Velociraptor,
    CortexXdr,
    CyLROrLive,
    Uac,
    Generic,
}

impl TriageType {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Kape => "KAPE",
            Self::Velociraptor => "Velociraptor",
            Self::CortexXdr => "Cortex XDR",
            Self::CyLROrLive => "CyLR",
            Self::Uac => "UAC",
            Self::Generic => "Generic Triage",
        }
    }
}

/// Metadata discovered about a triage package
#[derive(Debug, Clone)]
pub struct TriageInfo {
    pub kind: TriageType,
    pub source_path: String,
    pub hostname: Option<String>,
}

/// Check whether a filename follows Velociraptor naming convention:
/// `<LETTER>_<YYYYMMDD>-<HHMMSS>_<username>` or `Extracted_<LETTER>_<YYYYMMDD>-<HHMMSS>_<username>`
fn is_velociraptor_filename(stem: &str) -> bool {
    let without_prefix = stem.strip_prefix("Extracted_").unwrap_or(stem);
    let bytes = without_prefix.as_bytes();
    if bytes.len() < 19 {
        return false;
    }
    if !bytes[0].is_ascii_alphabetic() || bytes[1] != b'_' {
        return false;
    }
    // 8 digits date
    if !bytes[2..10].iter().all(|b| b.is_ascii_digit()) || bytes[10] != b'-' {
        return false;
    }
    // 6 digits time
    if !bytes[11..17].iter().all(|b| b.is_ascii_digit()) || bytes[17] != b'_' {
        return false;
    }
    bytes.len() > 18
}

/// Check if archive path lives under a directory named Velociraptor
fn is_velociraptor_path(path: &str) -> bool {
    let lower = path.replace('\\', "/").to_lowercase();
    lower.contains("/velociraptor/")
}

/// Detects what kind of triage package an archive is, based on its entry names and path
pub fn detect_triage_type(archive_path: &str, entries: &[String]) -> Option<TriageType> {
    // 1. UAC (Unix-like Artifacts Collector)
    let has_uac_log = entries.iter().any(|n| {
        let t = n.replace('\\', "/");
        let clean = t.trim_start_matches("./");
        clean == "uac.log" || clean.ends_with("/uac.log")
    });
    let has_uac_layout = entries.iter().any(|n| {
        let t = n.replace('\\', "/");
        let clean = t.trim_start_matches("./");
        clean.starts_with("[root]/") || clean.contains("/[root]/") || clean.starts_with("live_response/")
    });
    if has_uac_log && has_uac_layout {
        return Some(TriageType::Uac);
    }
    let stem = Path::new(archive_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    if stem.starts_with("uac-") {
        return Some(TriageType::Uac);
    }

    // 2. Cortex XDR Offline Collector
    let has_outer_manifest = entries.iter().any(|n| n.to_lowercase() == "output/manifest.json");
    let has_outer_payload = entries.iter().any(|n| n.to_lowercase() == "output/cortex-xdr-payload.log");
    if has_outer_manifest && has_outer_payload {
        return Some(TriageType::CortexXdr);
    }

    // 3. Velociraptor
    let has_client_info = entries.iter().any(|n| n == "client_info.json" || n.ends_with("/client_info.json"));
    let has_collection_context = entries.iter().any(|n| n == "collection_context.json" || n.ends_with("/collection_context.json"));
    let has_uploads_json = entries.iter().any(|n| n == "uploads.json" || n.ends_with("/uploads.json"));
    if has_client_info && (has_collection_context || has_uploads_json) {
        return Some(TriageType::Velociraptor);
    }
    let has_metadata = entries.iter().any(|n| n == "metadata.json" || n.ends_with("/metadata.json"));
    let has_data_zip = entries.iter().any(|n| n == "data.zip" || n.ends_with("/data.zip"));
    if has_metadata && has_data_zip {
        return Some(TriageType::Velociraptor);
    }
    let has_vr_uploads = entries.iter().any(|n| {
        let norm = n.replace('\\', "/");
        norm.contains("uploads/auto/") || norm.contains("uploads/ntfs/")
    });
    if has_vr_uploads || is_velociraptor_filename(stem) || is_velociraptor_path(archive_path) {
        return Some(TriageType::Velociraptor);
    }

    // 4. KAPE
    let has_kape_cli = entries.iter().any(|n| {
        let lower = n.to_lowercase();
        lower == "_kape.cli" || lower.ends_with("/_kape.cli") || lower.ends_with("/kape.log")
    });
    if has_kape_cli {
        return Some(TriageType::Kape);
    }
    let kape_layout_count = entries.iter().filter(|n| {
        let norm = n.replace('\\', "/").to_lowercase();
        norm.contains("/c/windows/system32/winevt/logs/") || norm.starts_with("c/windows/system32/winevt/logs/")
    }).count();
    if kape_layout_count >= 3 {
        return Some(TriageType::Kape);
    }

    // 5. CyLR
    let has_cylr = entries.iter().any(|n| {
        let lower = n.to_lowercase();
        lower.contains("cylr") || lower.ends_with(".cylr.log")
    });
    if has_cylr {
        return Some(TriageType::CyLROrLive);
    }

    None
}

/// Best-effort hostname extraction from triage archive filename
pub fn extract_triage_hostname(archive_path: &str, kind: TriageType) -> Option<String> {
    let stem = Path::new(archive_path)
        .file_stem()?
        .to_str()?;

    match kind {
        TriageType::Uac => {
            // uac-<hostname>-<os>-<timestamp>
            let parts: Vec<&str> = stem.split('-').collect();
            if parts.len() >= 4 {
                let host = parts[1..parts.len() - 2].join("-");
                if !host.is_empty() && !host.eq_ignore_ascii_case("unknown") {
                    return Some(host);
                }
            }
            None
        }
        TriageType::CortexXdr => {
            // offline_collector_output_<HOST>_<YYYY-MM-DD>_<HH-MM-SS>
            let prefix = "offline_collector_output_";
            if let Some(rest) = stem.strip_prefix(prefix) {
                let bytes = rest.as_bytes();
                for (i, &b) in bytes.iter().enumerate() {
                    if b == b'_' && i + 5 < bytes.len() {
                        let next4 = &bytes[i + 1..i + 5];
                        if next4.iter().all(|c| c.is_ascii_digit()) && bytes[i + 5] == b'-' {
                            return Some(rest[..i].to_string());
                        }
                    }
                }
            }
            None
        }
        TriageType::Velociraptor => {
            // Collection-<HOST>-<TIMESTAMP>
            if let Some(rest) = stem.strip_prefix("Collection-") {
                let bytes = rest.as_bytes();
                for (i, &b) in bytes.iter().enumerate() {
                    if b == b'-' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
                        return Some(rest[..i].to_string());
                    }
                }
            }
            None
        }
        TriageType::Kape | TriageType::CyLROrLive | TriageType::Generic => {
            // Typical: <hostname>_<YYYYMMDD>_<HHMMSS>.zip
            let mut parts = stem.splitn(2, '_');
            let head = parts.next()?;
            let tail = parts.next()?;
            let tail_starts_with_digits = tail.chars().take(4).all(|c| c.is_ascii_digit());
            if tail_starts_with_digits && !head.is_empty() {
                Some(head.to_string())
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_triage_detect_velociraptor() {
        let entries = vec![
            "client_info.json".to_string(),
            "collection_context.json".to_string(),
            "uploads/auto/C/Windows/System32/winevt/Logs/Security.evtx".to_string(),
        ];
        let kind = detect_triage_type("Collection-SRV-DC01-20260406T100000Z.zip", &entries);
        assert_eq!(kind, Some(TriageType::Velociraptor));

        let host = extract_triage_hostname("Collection-SRV-DC01-20260406T100000Z.zip", TriageType::Velociraptor);
        assert_eq!(host, Some("SRV-DC01".to_string()));
    }

    #[test]
    fn test_triage_detect_kape() {
        let entries = vec![
            "_kape.cli".to_string(),
            "C/Windows/System32/winevt/Logs/Security.evtx".to_string(),
            "C/Windows/System32/config/SYSTEM".to_string(),
        ];
        let kind = detect_triage_type("DESKTOP-ABC123_20260406_183000.zip", &entries);
        assert_eq!(kind, Some(TriageType::Kape));

        let host = extract_triage_hostname("DESKTOP-ABC123_20260406_183000.zip", TriageType::Kape);
        assert_eq!(host, Some("DESKTOP-ABC123".to_string()));
    }

    #[test]
    fn test_triage_detect_cortex_xdr() {
        let entries = vec![
            "output/manifest.json".to_string(),
            "output/cortex-xdr-payload.log".to_string(),
        ];
        let kind = detect_triage_type("offline_collector_output_WEBSERV01_2026-04-06_12-00-00.zip", &entries);
        assert_eq!(kind, Some(TriageType::CortexXdr));

        let host = extract_triage_hostname("offline_collector_output_WEBSERV01_2026-04-06_12-00-00.zip", TriageType::CortexXdr);
        assert_eq!(host, Some("WEBSERV01".to_string()));
    }

    #[test]
    fn test_triage_detect_uac() {
        let entries = vec![
            "uac.log".to_string(),
            "[root]/var/log/syslog".to_string(),
        ];
        let kind = detect_triage_type("uac-ubuntuhost-linux-20260406120000.tar.gz", &entries);
        assert_eq!(kind, Some(TriageType::Uac));

        let host = extract_triage_hostname("uac-ubuntuhost-linux-20260406120000.tar.gz", TriageType::Uac);
        assert_eq!(host, Some("ubuntuhost".to_string()));
    }
}
