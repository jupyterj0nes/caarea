use chrono::{DateTime, Utc};
use regex::Regex;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::parsers::evtx::Event;

/// Parses web server access logs (Apache, Nginx, GlassFish) for dynamic script / webshell execution
pub fn parse_web_access_log(file_path: &Path, computer_name: &str) -> Vec<Event> {
    let mut events = Vec::new();
    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(_) => return events,
    };

    // Regex for Common / Combined Log Format:
    // 10.240.240.86 - - [23/Sep/2026:15:51:56 +0000] "POST /rlif.jsp HTTP/1.1" 200 4096 "..." "..."
    let log_re = match Regex::new(
        r#"^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^ "]+)(?:\s+HTTP/[0-9.]+)?\"\s+(\d{3})"#,
    ) {
        Ok(r) => r,
        Err(_) => return events,
    };

    let reader = BufReader::new(file);

    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(_) => continue,
        };

        if let Some(caps) = log_re.captures(&line) {
            let client_ip = caps[1].to_string();
            let raw_date = &caps[2];
            let method = &caps[3];
            let uri = &caps[4];
            let status_code = &caps[5];

            let lower_uri = uri.to_lowercase();

            // Filter for dynamic execution scripts or POST requests
            let is_script = lower_uri.contains(".jsp")
                || lower_uri.contains(".php")
                || lower_uri.contains(".cgi")
                || lower_uri.contains(".sh")
                || lower_uri.contains(".py")
                || lower_uri.contains(".pl")
                || lower_uri.contains(".war");

            let has_cmd_payload = lower_uri.contains("cmd=")
                || lower_uri.contains("exec=")
                || lower_uri.contains("whoami")
                || lower_uri.contains("id")
                || lower_uri.contains("curl")
                || lower_uri.contains("wget");

            let is_post = method == "POST";

            if is_script || has_cmd_payload || is_post {
                // Parse timestamp: "23/Sep/2026:15:51:56 +0000" or without timezone
                let iso_ts = match DateTime::parse_from_str(raw_date, "%d/%b/%Y:%H:%M:%S %z") {
                    Ok(dt) => dt.with_timezone(&Utc).to_rfc3339(),
                    Err(_) => match chrono::NaiveDateTime::parse_from_str(raw_date, "%d/%b/%Y:%H:%M:%S") {
                        Ok(ndt) => DateTime::<Utc>::from_naive_utc_and_offset(ndt, Utc).to_rfc3339(),
                        Err(_) => continue,
                    },
                };

                let script_name = uri.split('?').next().unwrap_or(uri).to_string();
                let artifact_label = if is_script {
                    "linux:web:script_execution"
                } else {
                    "linux:web:http_post"
                };

                events.push(Event {
                    timestamp: iso_ts,
                    computer: computer_name.to_string(),
                    artifact: artifact_label.to_string(),
                    event_id: 0,
                    pid: 0,
                    subject_username: client_ip.clone(),
                    target_username: "www-data/web".to_string(),
                    processname: script_name,
                    commandline: Some(format!("{} {} (Status: {}, Client: {})", method, uri, status_code, client_ip)),
                    parentprocessname: "httpd/nginx".to_string(),
                });
            }
        }
    }

    events
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_parse_web_log() {
        let temp_file = std::env::temp_dir().join(format!("test_web_{}.log", std::process::id()));
        {
            let mut f = File::create(&temp_file).unwrap();
            writeln!(f, r#"10.240.240.86 - - [23/Sep/2026:15:51:56 +0000] "POST /rlif.jsp HTTP/1.1" 200 4096 "-" "curl/7.29.0""#).unwrap();
            writeln!(f, r#"10.240.240.86 - - [23/Sep/2026:15:52:00 +0000] "GET /index.html HTTP/1.1" 200 120 "-" "-""#).unwrap();
        }

        let events = parse_web_access_log(&temp_file, "WEBHOST");
        let _ = std::fs::remove_file(&temp_file);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].processname, "/rlif.jsp");
        assert_eq!(events[0].subject_username, "10.240.240.86");
        assert_eq!(events[0].artifact, "linux:web:script_execution");
        assert!(events[0].timestamp.starts_with("2026-09-23T15:51:56"));
    }
}
