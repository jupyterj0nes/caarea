# CAAREA

**CAAREA** (*Chronological Artifacts & Activity Reconstruction Engine for Analysis*) is an ultra-fast, high-performance native Rust digital forensics and incident response (DFIR) tool designed to generate unified, chronologically sorted execution timelines from Windows and Linux forensic evidence.

Built entirely in Rust with zero Python/Perl runtime dependencies, CAAREA processes raw disk images (E01/RAW), enterprise triage packages (UAC, KAPE, Velociraptor, Cortex XDR, CyLR), and live system paths at native compiled speed.

---

## ⚡ Key Capabilities

### 🪟 Windows Execution Engine
* **Event Logs (EVTX):** Native parsing of Process Creation (4688 / Sysmon 1), Service Installs (7045), Scheduled Tasks (106/200), PowerShell ScriptBlock/Execution (4104), and WMI Execution.
* **Registry Reconstruction & Forensic Recovery:**
  * **HvLE & DIRT Transaction Log Replayer:** Native replayer for modern Incremental (`HvLE`) and legacy Dirty Vector (`DIRT`) transaction logs (`.LOG`, `.LOG1`, `.LOG2`) to recover data from unflushed hives.
  * **BAM / DAM:** Background Activity Moderator and Desktop Activity Moderator (`SYSTEM\CurrentControlSet\Services\bam\UserSettings`).
  * **ShimCache (AppCompatCache):** Multi-format parser across Windows 7, 8, 10, and 11.
  * **UserAssist:** ROT13 decoding and run count / execution time extraction from `NTUSER.DAT`.
  * **IFEO & Winlogon:** Persistence inspection via Image File Execution Options and Winlogon Shell/Userinit.
  * **Office TrustRecords:** Recent document execution and macro trust records.

### 🐧 Linux Execution Engine (6-Dimensional Suite)
* **Kernel Process Accounting (`pacct` / `psacct`):** Native binary parser for Linux kernel `struct acct_v3` (and legacy v1/v2), recovering terminated process executions, PIDs, UIDs, and exit flags even if shell histories were deleted.
* **Kernel Audit Subsystem (`auditd`):** Automated extraction and hex-decoding of `USER_CMD`, `EXECVE`, and syscall executions from `audit.log`.
* **Syslog Engine (Sudo & Cron):** Sub-second temporal inference for year-less syslog records (`/var/log/secure`, `/var/log/cron`, `/var/log/auth.log`) resolving year boundaries and leap years via file `mtime`.
* **Interactive Histories:** Multi-shell parsing for `.bash_history` (with Unix epoch timestamp support), `.zsh_history`, and `.viminfo` / `main.shada` (command history and file edit marks).
* **In-Memory & Fileless Detection:** Automated detection of in-memory execution via `memfd_create` (`/memfd:... (deleted)`), deleted binaries running in memory (`(deleted)`), and processes launched from volatile locations (`/tmp`, `/dev/shm`).
* **Desktop Recent Documents (`recently-used.xbel`):** XML Bookmark parsing capturing applications, opened documents, and modification timestamps.
* **Web Server & Script Execution:** Access log parser (Apache, Nginx, GlassFish) tracking dynamic execution requests (`.jsp`, `.php`, `.cgi`) and POST requests.
* **Kernel Segfaults & Exploit Crashes:** Automated detection of exploitation failures and segmentation faults from `dmesg` and crash logs.
* **Scheduled Tasks & Services:** Parser for `/etc/cron.d/*`, `/var/spool/cron/*`, and `/etc/systemd/system/*.service` definitions.

### 📦 Disk Image & Triage Ingestion
* **Enterprise E01 Image Streaming:** Direct streaming extraction from 500GB+ EnCase E01 forensic disk images without local download, bypassing the 4M chunk limitation.
* **RAW / DD / NTFS Parsing:** In-memory MFT and VSS filesystem traversal.
* **Recursive Archive Extraction:** Automated nested archive unpacking (`.tar.gz`, `.zip`, `.tgz`) with built-in password probing for infected or locked forensic packages (`infected`, `velox`, `malware`, etc.).
* **Automated Triage Recognition:** Heuristic identification of UAC, KAPE, Velociraptor, Cortex XDR, and CyLR structures.

---

## 📊 Standardized 10-Column RFC 4180 CSV Schema

CAAREA outputs a unified chronological timeline formatted as RFC 4180 compliant CSV:

| Column | Description |
| :--- | :--- |
| `timestamp` | ISO-8601 UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`) |
| `computer` | Hostname / Machine name |
| `artifact` | Specific artifact type (e.g. `windows:registry:bam`, `linux:syslog:sudo`) |
| `event_id` | Native Event ID (or 0 for non-EVTX artifacts) |
| `pid` | Process ID (if available, otherwise 0) |
| `subject_username` | Executing user or authenticated identity |
| `target_username` | Target security context or privilege elevated into |
| `processname` | Process / binary name |
| `commandline` | Full command line arguments and execution parameters |
| `parentprocessname` | Parent process name or launching entity |

---

## 🚀 Installation & Building

CAAREA requires the latest stable Rust toolchain:

```bash
# Clone the repository
git clone https://github.com/jupyterj0nes/caarea.git
cd caarea

# Build optimized release binary
cargo build --release
```

The compiled binary will be located at `target/release/caarea` (or `caarea.exe` on Windows).

---

## 💻 Usage

```text
caarea [OPTIONS] --output <PATH>

Options:
  -f, --file <PATH>           Path to a single artifact or disk image (E01, RAW, EVTX, Hive, Tarball)
  -d, --directory <PATH>      Path to an evidence directory or triage folder
  -o, --output <PATH>         Destination CSV timeline path [required]
  -m, --modules <MODULES>     Modules to run: evtx, registry, linux, all [default: all]
  -t, --toi <TIMESTAMP>       Time of Interest (ISO-8601) to center the timeline window
  -w, --toi-window <HOURS>    Hours before/after TOI to include [default: 24]
      --overwrite             Overwrite existing output CSV file without prompting
  -s, --silent                Suppress verbose logging output
  -h, --help                  Print help
  -V, --version               Print version
```

### Examples

**Analyze an entire fleet of UAC Linux triage archives over a network share:**
```bash
caarea -d "/mnt/cases/renfe/Evidence/UAC" -m linux -o "linux_fleet_timeline.csv" --overwrite
```

**Stream execution artifacts from a 500GB remote E01 disk image:**
```bash
caarea -f "\\nas\evidence\workstation.E01" -o "workstation_timeline.csv"
```

**Generate a focused timeline centered around a known Time of Interest (TOI):**
```bash
caarea -d "C:\Cases\Triage_Host01" --toi "2026-09-24T12:00:00Z" --toi-window 6 -o "incident_window.csv"
```

---

## 🔒 Forensic Soundness
* **Read-Only Evidence Access:** CAAREA never writes to or modifies the evidence source.
* **Isolated Reconstruction:** Registry transaction log replays and nested archive extractions occur strictly within temporary, in-memory or ephemeral working directories.

---

## 📄 License
Internal DFIR Research Tool - Created by [jupyterj0nes](https://github.com/jupyterj0nes).
