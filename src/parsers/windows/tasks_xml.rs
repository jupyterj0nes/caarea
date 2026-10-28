//! Scheduled task definitions (`Windows\System32\Tasks\**`, XML, usually UTF-16): author,
//! principal, triggers and the commands the task runs. The row time is the file's
//! modification time (UTC from NTFS); the local registration date written inside the XML is
//! kept in the description.

use std::path::Path;

use super::text::{decode_text, file_mtime_iso};
use crate::parsers::evtx::{xml_unescape, Event};
use crate::utils::resolve_sid;

/// Does this content look like a task definition?
pub fn is_task_xml(head: &[u8]) -> bool {
    let text = decode_text(&head[..head.len().min(600)]);
    let t = text.trim_start();
    t.starts_with("<?xml") && text.contains("<Task ") && text.contains("mit/task")
}

fn tag<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{}>", name);
    let close = format!("</{}>", name);
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].trim())
}

fn all_tags<'a>(xml: &'a str, name: &str) -> Vec<&'a str> {
    let open = format!("<{}", name);
    let close = format!("</{}>", name);
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(p) = rest.find(&open) {
        let after = &rest[p + open.len()..];
        // skip attributes
        let Some(gt) = after.find('>') else { break };
        let body_start = gt + 1;
        let Some(e) = after[body_start..].find(&close) else { break };
        out.push(after[body_start..body_start + e].trim());
        rest = &after[body_start + e + close.len()..];
    }
    out
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TaskDefinition {
    pub uri: String,
    pub author: String,
    pub registered: String,
    pub principal: String,
    pub run_level: String,
    pub triggers: Vec<String>,
    pub actions: Vec<String>,
    pub enabled: bool,
}

pub fn parse_xml(xml: &str) -> TaskDefinition {
    let mut def = TaskDefinition { enabled: true, ..Default::default() };
    def.uri = tag(xml, "URI").map(xml_unescape).unwrap_or_default();
    def.author = tag(xml, "Author").map(xml_unescape).unwrap_or_default();
    def.registered = tag(xml, "Date").unwrap_or("").to_string();
    if let Some(p) = all_tags(xml, "Principal").first() {
        let who = tag(p, "UserId").or_else(|| tag(p, "GroupId")).unwrap_or("");
        def.principal = if who.starts_with("S-1-") { resolve_sid(who) } else { xml_unescape(who) };
        def.run_level = tag(p, "RunLevel").unwrap_or("").to_string();
    }
    if let Some(t) = all_tags(xml, "Triggers").first() {
        for name in [
            "BootTrigger",
            "LogonTrigger",
            "TimeTrigger",
            "CalendarTrigger",
            "EventTrigger",
            "RegistrationTrigger",
            "IdleTrigger",
            "SessionStateChangeTrigger",
            "WnfStateChangeTrigger",
        ] {
            let n = all_tags(t, name).len();
            if n > 0 {
                def.triggers.push(if n == 1 { name.to_string() } else { format!("{}x{}", name, n) });
            }
        }
    }
    for exec in all_tags(xml, "Exec") {
        let cmd = tag(exec, "Command").map(xml_unescape).unwrap_or_default();
        let args = tag(exec, "Arguments").map(xml_unescape).unwrap_or_default();
        if !cmd.is_empty() {
            def.actions.push(if args.is_empty() { cmd } else { format!("{} {}", cmd, args) });
        }
    }
    for com in all_tags(xml, "ComHandler") {
        if let Some(clsid) = tag(com, "ClassId") {
            let data = tag(com, "Data").map(xml_unescape).unwrap_or_default();
            def.actions.push(if data.is_empty() { format!("COM {}", clsid) } else { format!("COM {} {}", clsid, data) });
        }
    }
    if let Some(settings) = all_tags(xml, "Settings").first() {
        if tag(settings, "Enabled") == Some("false") {
            def.enabled = false;
        }
    }
    def
}

pub fn parse_file(path: &Path, computer: &str) -> Vec<Event> {
    let Ok(raw) = std::fs::read(path) else { return Vec::new() };
    if !is_task_xml(&raw) {
        return Vec::new();
    }
    let xml = decode_text(&raw);
    let def = parse_xml(&xml);
    let mtime = file_mtime_iso(path);
    if mtime.is_empty() {
        return Vec::new();
    }
    let name = if def.uri.is_empty() {
        path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default()
    } else {
        def.uri.clone()
    };
    let actions = if def.actions.is_empty() { vec![String::from("(no exec action)")] } else { def.actions.clone() };
    actions
        .iter()
        .map(|action| {
            let first = action.split_whitespace().next().unwrap_or("").trim_matches('"').to_string();
            let mut details = format!("Task {}: {}", name, action);
            if !def.triggers.is_empty() {
                details.push_str(&format!(" | triggers: {}", def.triggers.join(", ")));
            }
            if !def.registered.is_empty() {
                details.push_str(&format!(" | registered {} (local)", def.registered));
            }
            if !def.run_level.is_empty() {
                details.push_str(&format!(" | {}", def.run_level));
            }
            if !def.enabled {
                details.push_str(" | DISABLED");
            }
            Event {
                timestamp: mtime.clone(),
                computer: computer.to_string(),
                artifact: "task:xml".to_string(),
                event_id: 0,
                pid: 0,
                subject_username: def.author.clone(),
                target_username: def.principal.clone(),
                processname: first,
                commandline: Some(details),
                parentprocessname: "Task Scheduler".to_string(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const XML: &str = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Date>2026-10-28T20:19:57</Date><Author>DEV-SRV01\Administrator</Author><URI>\CaareaLabTask</URI></RegistrationInfo>
  <Triggers><TimeTrigger><StartBoundary>2026-10-28T23:59:00</StartBoundary><Enabled>true</Enabled></TimeTrigger><LogonTrigger/></Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings><Enabled>true</Enabled></Settings>
  <Actions Context="Author"><Exec><Command>cmd.exe</Command><Arguments>/c echo task &gt; C:\Temp\task.txt</Arguments></Exec></Actions>
</Task>"#;

    #[test]
    fn parses_definition() {
        let d = parse_xml(XML);
        assert_eq!(d.uri, "\\CaareaLabTask");
        assert_eq!(d.author, "DEV-SRV01\\Administrator");
        assert_eq!(d.principal, "NT AUTHORITY\\SYSTEM");
        assert_eq!(d.actions, vec!["cmd.exe /c echo task > C:\\Temp\\task.txt"]);
        assert_eq!(d.triggers, vec!["TimeTrigger"]);
        assert!(d.enabled);
        assert!(is_task_xml(XML.as_bytes()));
        let utf16: Vec<u8> = [0xFF, 0xFE].into_iter().chain(XML.encode_utf16().flat_map(|u| u.to_le_bytes())).collect();
        assert!(is_task_xml(&utf16));
    }
}
