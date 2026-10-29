//! Container runtimes: Docker (`/var/lib/docker/containers/<id>/config.v2.json`), containerd
//! (`io.containerd.runtime.v2.task/<ns>/<id>/config.json`, OCI spec) and podman
//! (`storage/overlay-containers/containers.json`). A container start is a process start
//! with a command line, an image and a user; on modern servers that is half the executions.

use std::path::Path;

use serde_json::Value;

use crate::parsers::evtx::Event;
use crate::utils::{iso_utc, parse_flexible_time};

pub fn is_container_file(path: &Path, name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let p = path.to_string_lossy().to_ascii_lowercase().replace('\\', "/");
    (n == "config.v2.json" && p.contains("/docker/containers/"))
        || (n == "config.json" && p.contains("io.containerd.runtime"))
        || (n == "containers.json" && p.contains("overlay-containers"))
}

fn s(v: &Value, path: &[&str]) -> String {
    let mut cur = v;
    for p in path {
        cur = &cur[*p];
    }
    match cur {
        Value::String(x) => x.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn join_array(v: &Value) -> String {
    v.as_array()
        .map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(" "))
        .unwrap_or_default()
}

fn time(v: &str) -> Option<String> {
    if v.is_empty() || v.starts_with("0001-01-01") {
        return None;
    }
    parse_flexible_time(v).map(|dt| iso_utc(&dt))
}

fn docker(v: &Value, computer: &str, source: &str) -> Vec<Event> {
    let name = s(v, &["Name"]).trim_start_matches('/').to_string();
    let id = s(v, &["ID"]);
    let short = id.chars().take(12).collect::<String>();
    let image = s(v, &["Config", "Image"]);
    let user = s(v, &["Config", "User"]);
    let path = s(v, &["Path"]);
    let args = join_array(&v["Args"]);
    let cmd = if path.is_empty() { join_array(&v["Config"]["Cmd"]) } else { format!("{} {}", path, args).trim().to_string() };
    let entrypoint = join_array(&v["Config"]["Entrypoint"]);
    let pid = v["State"]["Pid"].as_u64().unwrap_or(0) as u32;
    let mk = |ts: String, kind: &str, what: &str| Event {
        timestamp: ts,
        computer: computer.to_string(),
        artifact: format!("linux:container:{}", kind),
        event_id: 0,
        pid,
        subject_username: if user.is_empty() { "root".to_string() } else { user.clone() },
        target_username: String::new(),
        processname: cmd.split_whitespace().next().unwrap_or("").to_string(),
        commandline: Some(format!(
            "Docker container {} {} ({}): image {} cmd {}{}",
            what,
            name,
            short,
            image,
            cmd,
            if entrypoint.is_empty() { String::new() } else { format!(" entrypoint {}", entrypoint) }
        )),
        parentprocessname: format!("dockerd [{}]", source),
    };
    let mut out = Vec::new();
    if let Some(t) = time(&s(v, &["Created"])) {
        out.push(mk(t, "created", "created"));
    }
    if let Some(t) = time(&s(v, &["State", "StartedAt"])) {
        out.push(mk(t, "started", "started"));
    }
    if let Some(t) = time(&s(v, &["State", "FinishedAt"])) {
        out.push(mk(t, "finished", &format!("finished (exit {})", v["State"]["ExitCode"].as_i64().unwrap_or(0))));
    }
    out
}

fn containerd(v: &Value, computer: &str, source: &str, path: &Path) -> Vec<Event> {
    // OCI runtime spec: process.args, process.user.uid, annotations with image / names
    let args = join_array(&v["process"]["args"]);
    let uid = v["process"]["user"]["uid"].as_u64().map(|u| u.to_string()).unwrap_or_default();
    let image = s(v, &["annotations", "io.kubernetes.cri.image-name"]);
    let cname = s(v, &["annotations", "io.kubernetes.cri.container-name"]);
    let pod = s(v, &["annotations", "io.kubernetes.cri.sandbox-name"]);
    let Some(ts) = std::fs::metadata(path).ok().and_then(|m| m.modified().ok()).map(crate::utils::systemtime_to_iso) else {
        return Vec::new();
    };
    vec![Event {
        timestamp: ts,
        computer: computer.to_string(),
        artifact: "linux:container:started".to_string(),
        event_id: 0,
        pid: 0,
        subject_username: uid,
        target_username: String::new(),
        processname: args.split_whitespace().next().unwrap_or("").to_string(),
        commandline: Some(format!("containerd task {}{}: image {} args {} (config time)", cname, if pod.is_empty() { String::new() } else { format!(" in pod {}", pod) }, image, args)),
        parentprocessname: format!("containerd [{}]", source),
    }]
}

fn podman(v: &Value, computer: &str, source: &str) -> Vec<Event> {
    let mut out = Vec::new();
    if let Some(list) = v.as_array() {
        for c in list {
            let names = join_array(&c["names"]);
            let image = s(c, &["image"]);
            let id = s(c, &["id"]).chars().take(12).collect::<String>();
            if let Some(ts) = time(&s(c, &["created"])) {
                out.push(Event {
                    timestamp: ts,
                    computer: computer.to_string(),
                    artifact: "linux:container:created".to_string(),
                    event_id: 0,
                    pid: 0,
                    subject_username: String::new(),
                    target_username: String::new(),
                    processname: names.split_whitespace().next().unwrap_or(&id).to_string(),
                    commandline: Some(format!("Podman container created {} ({}): image {}", names, id, image)),
                    parentprocessname: format!("podman [{}]", source),
                });
            }
        }
    }
    out
}

pub fn parse_file(path: &Path, computer: &str) -> Vec<Event> {
    let Ok(text) = std::fs::read_to_string(path) else { return Vec::new() };
    let Ok(v) = serde_json::from_str::<Value>(&text) else { return Vec::new() };
    let name = path.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    let source = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    match name.as_str() {
        "config.v2.json" => docker(&v, computer, &source),
        "containers.json" => podman(&v, computer, &source),
        _ => containerd(&v, computer, &source, path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_config_rows() {
        let json = r#"{"ID":"abcdef1234567890","Name":"/miner","Path":"/bin/sh","Args":["-c","xmrig -o pool"],"Created":"2026-10-28T10:00:00.123456789Z","State":{"Pid":4242,"StartedAt":"2026-10-28T10:00:01.5Z","FinishedAt":"0001-01-01T00:00:00Z","ExitCode":0},"Config":{"Image":"alpine:3.19","User":"","Cmd":["xmrig"],"Entrypoint":null}}"#;
        let v: Value = serde_json::from_str(json).unwrap();
        let rows = docker(&v, "H", "config.v2.json");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].artifact, "linux:container:created");
        assert_eq!(rows[0].timestamp, "2026-10-28T10:00:00.123456Z");
        assert_eq!(rows[1].artifact, "linux:container:started");
        assert_eq!(rows[1].pid, 4242);
        assert_eq!(rows[1].processname, "/bin/sh");
        assert!(rows[1].commandline.as_deref().unwrap().contains("image alpine:3.19 cmd /bin/sh -c xmrig -o pool"));
    }
}
