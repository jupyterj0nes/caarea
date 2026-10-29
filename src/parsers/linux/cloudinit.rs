//! cloud-init logs (`/var/log/cloud-init.log`): the `runcmd`, `bootcmd` and user-data scripts
//! a cloud instance executed at first boot, with their time; plus cron job output mails
//! (`/var/mail/<user>`, mbox) whose subject carries the command cron ran.

use std::path::Path;

use crate::parsers::evtx::Event;
use crate::parsers::linux::timezone::HostTimezone;
use crate::utils::iso_utc;

pub fn is_cloud_init_log(name: &str) -> bool {
    name == "cloud-init.log" || name.starts_with("cloud-init.log.")
}

pub fn is_mail_spool(path: &Path) -> bool {
    let p = path.to_string_lossy().replace('\\', "/").to_ascii_lowercase();
    p.contains("/var/mail/") || p.contains("/var/spool/mail/")
}

/// `2026-10-28 15:40:10,123 - subp.py[DEBUG]: Running command ['/var/lib/cloud/instance/scripts/runcmd'] with allowed return codes [0] (shell=False, capture=False)`
pub fn parse_cloud_init_log(path: &Path, computer: &str, tz: &HostTimezone) -> Vec<Event> {
    let Ok(text) = std::fs::read_to_string(path) else { return Vec::new() };
    let mut events = Vec::new();
    for line in text.lines() {
        let Some(pos) = line.find("Running command [") else { continue };
        let cmd_part = &line[pos + "Running command [".len()..];
        let cmd = cmd_part.split(']').next().unwrap_or("").replace(['\'', '"'], "").replace(", ", " ");
        if cmd.is_empty() {
            continue;
        }
        let stamp = line.split(" - ").next().unwrap_or("").split(',').next().unwrap_or("");
        let Ok(ndt) = chrono::NaiveDateTime::parse_from_str(stamp, "%Y-%m-%d %H:%M:%S") else { continue };
        let interesting = cmd.contains("/var/lib/cloud/instance/scripts")
            || cmd.contains("/var/lib/cloud/instances/")
            || cmd.contains("runcmd")
            || cmd.contains("bootcmd")
            || cmd.starts_with("sh ")
            || cmd.starts_with("/bin/sh")
            || cmd.starts_with("bash")
            || cmd.contains("curl")
            || cmd.contains("wget")
            || cmd.contains("apt")
            || cmd.contains("yum")
            || cmd.contains("dnf")
            || cmd.contains("useradd")
            || cmd.contains("systemctl");
        if !interesting {
            continue;
        }
        events.push(Event {
            timestamp: iso_utc(&tz.local_to_utc(ndt)),
            computer: computer.to_string(),
            artifact: "linux:cloud_init:command".to_string(),
            event_id: 0,
            pid: 0,
            subject_username: "root".to_string(),
            target_username: "root".to_string(),
            processname: cmd.split_whitespace().next().unwrap_or("").to_string(),
            commandline: Some(format!("cloud-init ran: {}", cmd)),
            parentprocessname: "cloud-init".to_string(),
        });
    }
    events
}

/// mbox spool: `Subject: Cron <root@host> /usr/bin/x` with its `Date:` header.
pub fn parse_mail_spool(path: &Path, computer: &str) -> Vec<Event> {
    let Ok(text) = std::fs::read_to_string(path) else { return Vec::new() };
    let user = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let mut events = Vec::new();
    for message in text.split("\nFrom ") {
        let mut date = None;
        let mut subject = String::new();
        for line in message.lines().take(60) {
            if let Some(d) = line.strip_prefix("Date: ") {
                date = chrono::DateTime::parse_from_rfc2822(d.trim()).ok().map(|dt| iso_utc(&dt.with_timezone(&chrono::Utc)));
            } else if let Some(s) = line.strip_prefix("Subject: ") {
                subject = s.trim().to_string();
            }
            if line.is_empty() {
                break;
            }
        }
        let (Some(ts), Some(rest)) = (date, subject.strip_prefix("Cron ")) else { continue };
        // "<root@host> /usr/bin/x args"
        let (who, cmd) = match rest.split_once("> ") {
            Some((w, c)) => (w.trim_start_matches('<').split('@').next().unwrap_or("").to_string(), c.trim().to_string()),
            None => (user.clone(), rest.to_string()),
        };
        events.push(Event {
            timestamp: ts,
            computer: computer.to_string(),
            artifact: "linux:cron:mail".to_string(),
            event_id: 0,
            pid: 0,
            subject_username: who.clone(),
            target_username: who,
            processname: cmd.split_whitespace().next().unwrap_or("").to_string(),
            commandline: Some(format!("cron job output mailed: {}", cmd)),
            parentprocessname: format!("mail spool {}", user),
        });
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloud_init_and_cron_mail() {
        let dir = std::env::temp_dir().join(format!("caarea_ci_{}", std::process::id()));
        std::fs::create_dir_all(dir.join("var").join("mail")).unwrap();
        let log = dir.join("cloud-init.log");
        std::fs::write(&log, "2026-10-28 15:40:10,123 - subp.py[DEBUG]: Running command ['/var/lib/cloud/instance/scripts/runcmd'] with allowed return codes [0]\n2026-10-28 15:40:11,000 - subp.py[DEBUG]: Running command ['systemd-detect-virt'] with allowed return codes [0]\n").unwrap();
        let rows = parse_cloud_init_log(&log, "H", &HostTimezone::utc());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].processname, "/var/lib/cloud/instance/scripts/runcmd");
        assert_eq!(rows[0].timestamp, "2026-10-28T15:40:10.000000Z");

        let mail = dir.join("var").join("mail").join("root");
        std::fs::write(&mail, "From root@host Wed Oct 28 22:02:01 2026\nDate: Wed, 28 Oct 2026 22:02:01 +0000\nSubject: Cron <root@host> /tmp/caarea-test > /dev/null\n\noutput\n").unwrap();
        let rows = parse_mail_spool(&mail, "H");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].artifact, "linux:cron:mail");
        assert_eq!(rows[0].processname, "/tmp/caarea-test");
        assert_eq!(rows[0].timestamp, "2026-10-28T22:02:01.000000Z");
        assert!(is_mail_spool(&mail));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
