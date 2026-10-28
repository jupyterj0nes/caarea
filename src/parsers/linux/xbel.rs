use quick_xml::events::Event as XmlEvent;
use quick_xml::Reader;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use crate::parsers::evtx::Event;
use crate::parsers::linux::histories::infer_user_from_history_path;
use crate::utils::normalize_iso;

/// Parses ~/.local/share/recently-used.xbel files (Gnome, KDE, XFCE recently opened files)
pub fn parse_xbel_file(file_path: &Path, computer_name: &str) -> Vec<Event> {
    let mut events = Vec::new();
    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(_) => return events,
    };

    let user = infer_user_from_history_path(file_path);
    let mut reader = Reader::from_reader(BufReader::new(file));
    reader.trim_text(true);

    let mut current_href = String::new();
    let mut current_added = String::new();
    let mut current_modified = String::new();

    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(ref e)) | Ok(XmlEvent::Empty(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();

                if name == "bookmark" {
                    current_href.clear();
                    current_added.clear();
                    current_modified.clear();

                    for attr in e.attributes().flatten() {
                        let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                        let val = String::from_utf8_lossy(&attr.value).to_string();
                        match key.as_str() {
                            "href" => current_href = val,
                            "added" => current_added = val,
                            "modified" => current_modified = val,
                            _ => {}
                        }
                    }
                } else if name == "bookmark:application" {
                    let mut app_name = String::new();
                    let mut app_exec = String::new();
                    let mut app_modified = String::new();

                    for attr in e.attributes().flatten() {
                        let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                        let val = String::from_utf8_lossy(&attr.value).to_string();
                        match key.as_str() {
                            "name" => app_name = val,
                            "exec" => app_exec = val,
                            "modified" => app_modified = val,
                            _ => {}
                        }
                    }

                    let ts = if !app_modified.is_empty() {
                        app_modified
                    } else if !current_modified.is_empty() {
                        current_modified.clone()
                    } else {
                        current_added.clone()
                    };

                    if !ts.is_empty() && !current_href.is_empty() {
                        let proc_name = if !app_name.is_empty() {
                            app_name.clone()
                        } else {
                            app_exec.split_whitespace().next().unwrap_or("app").to_string()
                        };

                        let clean_path = current_href.strip_prefix("file://").unwrap_or(&current_href);

                        events.push(Event {
                            timestamp: normalize_iso(&ts).unwrap_or(ts),
                            computer: computer_name.to_string(),
                            artifact: "linux:gui:recently_used".to_string(),
                            event_id: 0,
                            pid: 0,
                            subject_username: user.clone(),
                            target_username: user.clone(),
                            processname: proc_name,
                            commandline: Some(format!("App: {}, Opened: {}, Exec: {}", app_name, clean_path, app_exec)),
                            parentprocessname: "desktop_gui".to_string(),
                        });
                    }
                }
            }
            Ok(XmlEvent::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }

    events
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_parse_xbel() {
        let temp_file = std::env::temp_dir().join(format!("test_xbel_{}.xbel", std::process::id()));
        {
            let mut f = File::create(&temp_file).unwrap();
            writeln!(f, r#"<?xml version="1.0" encoding="UTF-8"?>
<xbel version="1.0" xmlns:bookmark="http://www.freedesktop.org/standards/desktop-bookmarks" xmlns:mime="http://www.freedesktop.org/standards/shared-mime-info">
  <bookmark href="file:///home/anita/secret_report.pdf" added="2026-09-24T10:00:00Z" modified="2026-09-24T10:05:00Z" visited="2026-09-24T10:00:00Z">
    <info>
      <metadata owner="http://freedesktop.org">
        <mime:mime-type type="application/pdf"/>
        <bookmark:applications>
          <bookmark:application name="Document Viewer" exec="&apos;evince %u&apos;" modified="2026-09-24T10:05:00Z" count="1"/>
        </bookmark:applications>
      </metadata>
    </info>
  </bookmark>
</xbel>"#).unwrap();
        }

        let events = parse_xbel_file(&temp_file, "LINUXHOST");
        let _ = std::fs::remove_file(&temp_file);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].processname, "Document Viewer");
        assert!(events[0].commandline.as_ref().unwrap().contains("secret_report.pdf"));
        assert_eq!(events[0].timestamp, "2026-09-24T10:05:00.000000Z");
    }
}
