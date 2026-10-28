use clap::{Arg, ArgAction, Command};
use std::env;
use std::path::Path;

/// Valid values for `--modules`
pub const VALID_MODULES: [&str; 4] = ["all", "evtx", "registry", "linux"];

/// Function to define CLI arguments
pub fn build_cli() -> Command {
    Command::new("caarea")
        .version(env!("CARGO_PKG_VERSION"))
        .about("CAAREA - Chronological Artifacts & Activity Reconstruction Engine for Analysis.\nBuilds a unified execution timeline from Windows and Linux forensic evidence.")
        .arg(
            Arg::new("directories")
                .short('d')
                .long("directory")
                .value_name("PATH")
                .help("Evidence directory or triage folder to scan (repeatable)")
                .action(ArgAction::Append),
        )
        .arg(
            Arg::new("files")
                .short('f')
                .long("file")
                .value_name("PATH")
                .help("Single artifact, archive or disk image to process: EVTX, hive, E01/RAW, ZIP/TAR, log (repeatable)")
                .action(ArgAction::Append),
        )
        .arg(
            Arg::new("modules")
                .short('m')
                .long("modules")
                .value_name("MODULES")
                .help("Parsers to run: evtx, registry, linux, all")
                .default_value("all"),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("PATH")
                .help("Destination CSV timeline path")
                .required(true),
        )
        .arg(
            Arg::new("toi")
                .short('t')
                .long("toi")
                .value_name("TIMESTAMP")
                .help("Time of Interest (ISO-8601) to center the timeline window on"),
        )
        .arg(
            Arg::new("toi_window")
                .short('w')
                .long("toi-window")
                .value_name("HOURS")
                .help("Hours before/after the TOI to include")
                .default_value("24"),
        )
        .arg(
            Arg::new("start_time")
                .long("start-time")
                .value_name("TIMESTAMP")
                .help("Keep events from this timestamp on (e.g. '2025-01-01' or '2025-01-01T00:00:00Z')"),
        )
        .arg(
            Arg::new("end_time")
                .long("end-time")
                .value_name("TIMESTAMP")
                .help("Keep events up to this timestamp (a bare date includes the whole day)"),
        )
        .arg(
            Arg::new("tz")
                .long("tz")
                .value_name("ZONE")
                .help("Time zone of the Linux host(s) for zone-less logs (classic syslog, dpkg, ps): IANA name, UTC or ±HH:MM. Default: detected from /etc/timezone, /etc/localtime, timedatectl or date output"),
        )
        .arg(
            Arg::new("overwrite")
                .long("overwrite")
                .help("Overwrite the output file if it already exists")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("silent")
                .short('s')
                .long("silent")
                .help("Suppress verbose logging output")
                .action(ArgAction::SetTrue),
        )
}

/// Validate input parameters
pub fn validate_input(
    directories: &Option<Vec<String>>,
    files: &Option<Vec<String>>,
    output: &str,
    modules: &str,
    silent: bool,
    overwrite: bool,
) -> Result<(), String> {
    if !VALID_MODULES.contains(&modules) {
        return Err(format!(
            "❌ Error: Unknown module '{}'. Valid values: {}",
            modules,
            VALID_MODULES.join(", ")
        ));
    }

    if directories.as_ref().map(|d| d.is_empty()).unwrap_or(true) && files.as_ref().map(|f| f.is_empty()).unwrap_or(true) {
        return Err("❌ Error: Provide at least one evidence source with -d/--directory or -f/--file.".to_string());
    }

    // Convert output path to absolute
    let output_path = normalize_path(output);

    // Validate directories
    if let Some(dirs) = directories {
        for dir in dirs {
            let normalized = normalize_path(dir);
            if !Path::new(&normalized).is_dir() {
                return Err(format!("❌ Error: Directory '{}' does not exist.", normalized));
            }
            if !silent {
                println!("📂 Processing directory: {}", normalized);
            }
        }
    }

    // Validate files
    if let Some(files) = files {
        for file in files {
            let normalized = normalize_path(file);
            if !Path::new(&normalized).is_file() {
                return Err(format!("❌ Error: File '{}' does not exist.", normalized));
            }
        }
    }

    // Validate output directory
    let parent_dir = Path::new(&output_path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| env::current_dir().unwrap_or_default());

    if !parent_dir.exists() {
        return Err(format!("❌ Error: Output directory '{}' does not exist.", parent_dir.display()));
    }

    // Check if output file already exists and handle `overwrite`
    if Path::new(&output_path).exists() && !overwrite {
        return Err(format!(
            "❌ Error: Output file '{}' already exists. Use '--overwrite' to replace it.",
            output_path
        ));
    }

    Ok(())
}

/// Normalize paths (convert to absolute)
fn normalize_path(path: &str) -> String {
    let abs_path = std::fs::canonicalize(path).unwrap_or_else(|_| env::current_dir().unwrap_or_default().join(path));
    abs_path.display().to_string()
}
