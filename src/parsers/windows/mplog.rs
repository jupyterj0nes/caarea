//! Microsoft Defender support logs (`ProgramData\Microsoft\Windows Defender\Support\
//! MPLog-*.log`, `MPDetection-*.log`): process images the engine looked at, with their PID
//! and the time, plus detections. Lines are `<ISO time> <text>`; the file is UTF-16 on
//! most builds and UTF-8 on some.

use std::path::Path;

use super::text::decode_text;
use crate::parsers::evtx::Event;
use crate::utils::normalize_iso;

pub fn is_mplog(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    (n.starts_with("mplog-") || n.starts_with("mpdetection-")) && n.ends_with(".log")
}

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let start = line.find(key)? + key.len();
    let rest = line[start..].trim_start_matches([':', ' ']);
    let end = rest.find(',').unwrap_or(rest.len());
    let v = rest[..end].trim();
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

fn split_time(line: &str) -> Option<(String, &str)> {
    let (ts, rest) = line.split_once(' ')?;
    if ts.len() < 20 || !ts.ends_with('Z') || ts.as_bytes()[4] != b'-' {
        return None;
    }
    Some((normalize_iso(ts)?, rest.trim()))
}

pub fn parse_text(text: &str, source: &str, computer: &str) -> Vec<Event> {
    let mut events = Vec::new();
    let mut last_time: Option<String> = None;
    let mut in_bm = false;
    let mut last_bm_image: Option<String> = None;
    let mk = |ts: String, artifact: &str, proc: String, pid: u32, details: String, user: String| Event {
        timestamp: ts,
        computer: computer.to_string(),
        artifact: artifact.to_string(),
        event_id: 0,
        pid,
        subject_username: user,
        target_username: String::new(),
        processname: proc,
        commandline: Some(details),
        parentprocessname: source.to_string(),
    };
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let (ts, body) = match split_time(line) {
            Some((t, b)) => {
                last_time = Some(t.clone());
                (Some(t), b)
            }
            None => (None, line),
        };
        if body.starts_with("BEGIN BM telemetry") {
            in_bm = true;
            last_bm_image = None;
            continue;
        }
        if body.starts_with("END BM telemetry") {
            in_bm = false;
            continue;
        }
        // Scan telemetry with the process that triggered the scan
        if let Some(image) = field(body, "ProcessImageName") {
            let pid = field(body, "Pid").and_then(|p| p.parse().ok()).unwrap_or(0);
            let impact = field(body, "EstimatedImpact").unwrap_or("");
            let total = field(body, "TotalTime").unwrap_or("");
            let count = field(body, "Count").unwrap_or("");
            if let Some(t) = ts.clone().or_else(|| last_time.clone()) {
                events.push(mk(
                    t,
                    "defender:mplog:process",
                    image.to_string(),
                    pid,
                    format!("Defender scanned on behalf of process: impact {} total {} count {}", impact, total, count).trim().to_string(),
                    String::new(),
                ));
            }
            continue;
        }
        // Behaviour monitoring blocks list the image that produced the telemetry
        if in_bm {
            if let Some(image) = body.strip_prefix("ImagePath:") {
                let image = image.trim().to_string();
                if last_bm_image.as_deref() != Some(image.as_str()) {
                    if let Some(t) = last_time.clone() {
                        events.push(mk(t, "defender:mplog:bm", image.clone(), 0, "Defender behaviour-monitoring telemetry".to_string(), String::new()));
                    }
                    last_bm_image = Some(image);
                }
            }
            continue;
        }
        // Detections (MPDetection.log and MPLog)
        if let Some(t) = ts {
            let upper = body.to_ascii_uppercase();
            if upper.starts_with("DETECTION") || upper.contains("THREAT NAME") || upper.contains("DETECTIONEVENT") {
                let file = body
                    .find("file:")
                    .map(|p| body[p + 5..].split([' ', ',', ';']).next().unwrap_or("").to_string())
                    .unwrap_or_default();
                let user = field(body, "user").map(|u| u.to_string()).unwrap_or_default();
                events.push(mk(t, "defender:detection", if file.is_empty() { "Defender detection".to_string() } else { file }, 0, body.to_string(), user));
            }
        }
    }
    events
}

pub fn parse_file(path: &Path, computer: &str) -> Vec<Event> {
    let Ok(raw) = std::fs::read(path) else { return Vec::new() };
    let source = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    parse_text(&decode_text(&raw), &source, computer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_process_bm_and_detection_lines() {
        let text = "2026-10-26T10:44:16.612Z ProductId: 2\n\
2026-10-27T09:01:02.123Z ProcessImageName: C:\\Temp\\evil.exe, Pid: 4242, TotalTime: 15, Count: 3, MaxTime: 10, MaxTimeFile: \\Device\\x.dll, EstimatedImpact: 2%\n\
2026-10-27T09:02:00.000Z BEGIN BM telemetry\nImagePath:D:\\tools\\installer.exe\nImagePath:D:\\tools\\installer.exe\nEND BM telemetry\n\
2026-10-27T09:03:00.000Z DETECTION Virus:DOS/EICAR_Test_File file:C:\\Temp\\eicar.com\n";
        let rows = parse_text(text, "MPLog-x.log", "H");
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].artifact, "defender:mplog:process");
        assert_eq!(rows[0].processname, "C:\\Temp\\evil.exe");
        assert_eq!(rows[0].pid, 4242);
        assert_eq!(rows[0].timestamp, "2026-10-27T09:01:02.123000Z");
        assert_eq!(rows[1].artifact, "defender:mplog:bm");
        assert_eq!(rows[1].processname, "D:\\tools\\installer.exe");
        assert_eq!(rows[2].artifact, "defender:detection");
        assert_eq!(rows[2].processname, "C:\\Temp\\eicar.com");
    }
}
