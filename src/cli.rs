use clap::{Arg, ArgAction, Command};
use std::path::Path;
use std::env;

/// Function to define CLI arguments
pub fn build_cli() -> Command {
    Command::new("Caarea - Execution Artifacts Timeliner")
        .version("1.0")
        .about("A powerful tool for extracting and analyzing execution artifacts for digital forensics and incident response (DFIR).")
        .arg(
            Arg::new("directories")
                .short('d')
                .long("directory")
                .help("Specify one or more directories to scan (relative or absolute paths)")
                .action(ArgAction::Append) // Allows multiple -d options
        )
        .arg(
            Arg::new("files")
                .short('f')
                .long("file")
                .help("Specify one or more files to process (relative or absolute paths)")
                .action(ArgAction::Append) // Allows multiple -f options
        )
        .arg(
            Arg::new("modules")
                .short('m')
                .long("modules")
                .help("Specify which parsers to run (e.g., evtx, registry, linux, or 'all')")
                .default_value("all")
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .help("Specify the output file path (relative or absolute)")
                .required(true)
        )
        .arg(
            Arg::new("silent")
                .long("silent")
                .help("Suppress all output messages")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("overwrite")
                .long("overwrite")
                .help("Overwrite output file if it already exists")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("start_time")
                .short('s')
                .long("start-time")
                .help("Filter events starting from this timestamp (e.g. '2025-01-01' or '2025-01-01T00:00:00')")
        )
        .arg(
            Arg::new("end_time")
                .short('e')
                .long("end-time")
                .help("Filter events up to this timestamp (e.g. '2025-01-02' or '2025-01-02T23:59:59')")
        )
}

/// Validate input parameters
pub fn validate_input(
    directories: &Option<Vec<String>>,
    files: &Option<Vec<String>>,
    output: &str,
    silent: bool,
    overwrite: bool,
) -> Result<(), String> {
    // Convert output path to absolute
    let output_path = normalize_path(output);

    // Validate directories
    if let Some(dirs) = directories {
        for dir in dirs {
            let normalized = normalize_path(dir);
            if !Path::new(&normalized).exists() {
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
            if !Path::new(&normalized).exists() {
                return Err(format!("❌ Error: File '{}' does not exist.", normalized));
            }
        }
    }

    // Validate output directory
    let parent_dir = Path::new(&output_path)
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| env::current_dir().unwrap());

    if !parent_dir.exists() {
        return Err(format!("❌ Error: Output directory '{}' does not exist.", parent_dir.display()));
    }

    // Check if output file already exists and handle `overwrite`
    if Path::new(&output_path).exists() {
        if !overwrite {
            return Err(format!(
                "❌ Error: Output file '{}' already exists. Use '--overwrite' to replace it.",
                output_path
            ));
        }
    }

    Ok(())
}

/// Normalize paths (convert to absolute)
fn normalize_path(path: &str) -> String {
    let abs_path = std::fs::canonicalize(path).unwrap_or_else(|_| env::current_dir().unwrap().join(path));
    abs_path.display().to_string()
}
