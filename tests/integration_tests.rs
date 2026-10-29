use caarea::parsers::evtx::Event;
use caarea::parsers::registry::parse_registry_file;
use caarea::timeline::create_timeline;
use caarea::utils::{escape_csv, filter_by_toi, filetime_to_iso, resolve_sid};
use std::path::Path;

#[test]
fn test_default_hive_parsing_if_available() {
    let default_hive = Path::new(r"C:\Users\Default\NTUSER.DAT");
    if default_hive.exists() {
        let events = parse_registry_file(default_hive, true).expect("Should parse NTUSER.DAT");
        assert!(!events.is_empty(), "Expected at least one event from Default NTUSER.DAT");
        for event in &events {
            assert!(event.artifact.starts_with("registry:"));
            assert!(!event.timestamp.is_empty());
        }
    }
}

#[test]
fn test_event_timeline_sorting() {
    let e1 = Event {
        timestamp: "2025-01-01T12:00:00Z".to_string(),
        computer: "HOST1".to_string(),
        artifact: "evtx:4688".to_string(),
        event_id: 4688,
        pid: 1001,
        subject_username: "user".to_string(),
        target_username: "user".to_string(),
        processname: "cmd.exe".to_string(),
        commandline: Some("cmd.exe /c whoami".to_string()),
        parentprocessname: "explorer.exe".to_string(),
    };
    let e2 = Event {
        timestamp: "2024-12-31T23:59:59Z".to_string(),
        computer: "HOST1".to_string(),
        artifact: "registry:bam".to_string(),
        event_id: 0,
        pid: 0,
        subject_username: "user".to_string(),
        target_username: "user".to_string(),
        processname: r"\Device\HarddiskVolume2\Windows\notepad.exe".to_string(),
        commandline: None,
        parentprocessname: "N/A".to_string(),
    };

    let timeline = create_timeline(vec![e1.clone()], vec![e2.clone()]);
    assert_eq!(timeline.len(), 2);
    assert_eq!(timeline[0].timestamp, "2024-12-31T23:59:59Z");
    assert_eq!(timeline[1].timestamp, "2025-01-01T12:00:00Z");
}

#[test]
fn test_toi_window_filtering() {
    let events = vec![
        Event {
            timestamp: "2025-08-24T08:00:00Z".to_string(),
            computer: "SRV01".to_string(),
            artifact: "registry:shimcache".to_string(),
            event_id: 0,
            pid: 0,
            subject_username: "SYSTEM".to_string(),
            target_username: "N/A".to_string(),
            processname: "malware.exe".to_string(),
            commandline: None,
            parentprocessname: "N/A".to_string(),
        },
        Event {
            timestamp: "2025-08-25T14:30:00Z".to_string(),
            computer: "SRV01".to_string(),
            artifact: "evtx:4688".to_string(),
            event_id: 4688,
            pid: 4096,
            subject_username: "admin".to_string(),
            target_username: "admin".to_string(),
            processname: "powershell.exe".to_string(),
            commandline: Some("powershell.exe -enc ...".to_string()),
            parentprocessname: "cmd.exe".to_string(),
        },
        Event {
            timestamp: "2025-08-27T00:00:00Z".to_string(),
            computer: "SRV01".to_string(),
            artifact: "registry:tasks:last_start".to_string(),
            event_id: 0,
            pid: 0,
            subject_username: "SYSTEM".to_string(),
            target_username: "N/A".to_string(),
            processname: "cleanup.exe".to_string(),
            commandline: None,
            parentprocessname: "taskeng.exe".to_string(),
        },
    ];

    let toi = filter_by_toi(events, Some("2025-08-25 00:00:00"), Some("2025-08-26 23:59:59"));
    assert_eq!(toi.len(), 1);
    assert_eq!(toi[0].artifact, "evtx:4688");
    assert_eq!(toi[0].processname, "powershell.exe");
}

#[test]
fn test_csv_field_escaping() {
    assert_eq!(escape_csv("cmd /c \"echo hello\""), "cmd /c \"\"echo hello\"\"");
}

#[test]
fn test_sid_resolution() {
    assert_eq!(resolve_sid("S-1-5-18"), "NT AUTHORITY\\SYSTEM");
    assert_eq!(resolve_sid("S-1-5-19"), "NT AUTHORITY\\LOCAL SERVICE");
    assert_eq!(resolve_sid("S-1-5-20"), "NT AUTHORITY\\NETWORK SERVICE");
    assert_eq!(resolve_sid("S-1-5-32-544"), "BUILTIN\\Administrators");
}

#[test]
fn test_filetime_conversion() {
    assert_eq!(filetime_to_iso(0), None);
    let dt = filetime_to_iso(133500000000000000).expect("Valid timestamp");
    assert!(dt.contains("2024-01-17"));
}

#[test]
fn test_triage_zip_ingest() {
    use caarea::ingest::prepare_evidence;
    use std::io::Write;
    use zip::write::FileOptions;
    use zip::ZipWriter;

    let temp_zip_path = std::env::temp_dir().join(format!("test_kape_{}.zip", std::process::id()));
    {
        let file = std::fs::File::create(&temp_zip_path).expect("Create test zip");
        let mut zip = ZipWriter::new(file);

        // Add _kape.cli
        zip.start_file("_kape.cli", FileOptions::default()).expect("Add kape cli");
        zip.write_all(b"--tsource C: --tdest D:\\out").expect("Write kape cli");

        // Copy default NTUSER.DAT if available or synthetic regf
        let default_hive = Path::new(r"C:\Users\Default\NTUSER.DAT");
        if default_hive.exists() {
            let hive_bytes = std::fs::read(default_hive).expect("Read default hive");
            zip.start_file("C/Users/Default/NTUSER.DAT", FileOptions::default()).expect("Add hive");
            zip.write_all(&hive_bytes).expect("Write hive");
        }

        zip.finish().expect("Finish zip");
    }

    let files = vec![temp_zip_path.to_string_lossy().to_string()];
    let workspace = prepare_evidence(None, Some(&files), true, None, false).expect("Prepare evidence");

    assert!(!workspace.directories.is_empty(), "Extracted triage dir should be present");

    // Clean up
    drop(workspace);
    let _ = std::fs::remove_file(&temp_zip_path);
}
