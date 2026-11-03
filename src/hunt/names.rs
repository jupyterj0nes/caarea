//! Names and folders: what the executable's path says before any rule looks at it.
//!
//! The directory families and the name classes are the ones faramir uses
//! (`hunt/normalize.rs` there), so the two tools say the same of the same path. Paths come
//! in many spellings (`\Device\HarddiskVolume2\`, `\VOLUME{guid}\`, `%SystemRoot%`,
//! `\??\`, forward slashes, quotes); [`expand_windows_path`] reduces them to one lowercase
//! form with a drive letter before the family is read.

/// Which operating system's conventions a row follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Windows,
    Linux,
}

/// The operating system of a row, from its artifact label.
pub fn os_of(artifact: &str) -> Os {
    if artifact.starts_with("linux:") {
        Os::Linux
    } else {
        Os::Windows
    }
}

/// The folder a path lives in, as a family a rule can reason about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirFamily {
    // Windows
    System32,
    SysWow64,
    WindowsDir,
    /// Folders under `\Windows` that ordinary users can write to (Temp, Tasks, Debug,
    /// Tracing, Fonts, spool\drivers\color, System32\Tasks, ...)
    WindowsWritable,
    ProgramFiles,
    ProgramData,
    UserAppData,
    UserLocalAppData,
    Temp,
    UserProfile,
    Public,
    Recycle,
    DriveRoot,
    Unc,
    // Linux
    UsrBin,
    UsrSbin,
    UsrLib,
    Bin,
    Sbin,
    Lib,
    Etc,
    Opt,
    UsrLocal,
    Var,
    Home,
    RootHome,
    Tmp,
    DevShm,
    VarTmp,
    Hidden,
    Run,
    Mnt,
    // both
    /// No folder at all: resolved through PATH or relative to the caller
    Bare,
    Other,
}

impl DirFamily {
    pub fn label(self) -> &'static str {
        match self {
            DirFamily::System32 => "System32",
            DirFamily::SysWow64 => "SysWOW64",
            DirFamily::WindowsDir => "Windows",
            DirFamily::WindowsWritable => "a user-writable Windows folder",
            DirFamily::ProgramFiles => "Program Files",
            DirFamily::ProgramData => "ProgramData",
            DirFamily::UserAppData => "AppData\\Roaming",
            DirFamily::UserLocalAppData => "AppData\\Local",
            DirFamily::Temp => "Temp",
            DirFamily::UserProfile => "a user profile",
            DirFamily::Public => "Users\\Public",
            DirFamily::Recycle => "the Recycle Bin",
            DirFamily::DriveRoot => "the drive root",
            DirFamily::Unc => "a network share",
            DirFamily::UsrBin => "/usr/bin",
            DirFamily::UsrSbin => "/usr/sbin",
            DirFamily::UsrLib => "/usr/lib",
            DirFamily::Bin => "/bin",
            DirFamily::Sbin => "/sbin",
            DirFamily::Lib => "/lib",
            DirFamily::Etc => "/etc",
            DirFamily::Opt => "/opt",
            DirFamily::UsrLocal => "/usr/local",
            DirFamily::Var => "/var",
            DirFamily::Home => "a home directory",
            DirFamily::RootHome => "/root",
            DirFamily::Tmp => "/tmp",
            DirFamily::DevShm => "/dev/shm",
            DirFamily::VarTmp => "/var/tmp",
            DirFamily::Hidden => "a hidden folder",
            DirFamily::Run => "/run",
            DirFamily::Mnt => "a mounted volume",
            DirFamily::Bare => "no folder",
            DirFamily::Other => "another folder",
        }
    }

    /// Where a Windows system binary may legitimately live.
    pub fn is_windows_system(self) -> bool {
        matches!(self, DirFamily::System32 | DirFamily::SysWow64)
    }

    /// Where a Linux system binary may legitimately live.
    pub fn is_linux_system(self) -> bool {
        matches!(self, DirFamily::UsrBin | DirFamily::UsrSbin | DirFamily::UsrLib | DirFamily::Bin | DirFamily::Sbin | DirFamily::Lib)
    }
}

/// Shape of a file name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameClass {
    /// Letters only (`svchost`, `OneDrive`)
    Alpha,
    /// Letters with some digits (`msedge2`, `ie4uinit`)
    AlphaDigits,
    /// Half or more of the characters are digits
    DigitHeavy,
    /// Eight or more hexadecimal characters with at least one digit
    HexLike,
    /// One or two characters
    Tiny,
    /// Non-ASCII or unusual punctuation
    Odd,
    /// Nothing to classify
    Empty,
}

impl NameClass {
    pub fn label(self) -> &'static str {
        match self {
            NameClass::Alpha => "plain name",
            NameClass::AlphaDigits => "name with digits",
            NameClass::DigitHeavy => "mostly digits",
            NameClass::HexLike => "hex-like name",
            NameClass::Tiny => "one or two characters",
            NameClass::Odd => "unusual characters",
            NameClass::Empty => "empty",
        }
    }
}

/// One lowercase Windows path with a drive letter, from any of the spellings the sources
/// use. `<user>` stands for the profile when a variable hid it.
pub fn expand_windows_path(p: &str) -> String {
    let mut s = p.trim().trim_matches(|c| c == '"' || c == '\'').replace('/', "\\").to_lowercase();
    if let Some(r) = s.strip_prefix("\\??\\") {
        s = r.to_string();
    } else if let Some(r) = s.strip_prefix("\\\\?\\") {
        s = r.to_string();
    } else if let Some(r) = s.strip_prefix("\\globalroot\\") {
        s = format!("\\{}", r);
    }
    // `\Device\HarddiskVolume2\Windows\...` (4688 before Windows 10, Sysmon rarely) and
    // `\VOLUME{guid}\Windows\...` (Prefetch): the volume is almost always the system one
    if let Some(r) = s.strip_prefix("\\device\\harddiskvolume") {
        let rest = r.trim_start_matches(|c: char| c.is_ascii_digit());
        s = format!("c:{}", rest);
    } else if s.starts_with("\\volume{") {
        if let Some(i) = s.find('}') {
            s = format!("c:{}", &s[i + 1..]);
        }
    }
    if let Some(r) = s.strip_prefix("\\systemroot\\") {
        s = format!("c:\\windows\\{r}");
    } else if let Some(r) = s.strip_prefix("systemroot\\") {
        s = format!("c:\\windows\\{r}");
    } else if let Some(r) = s.strip_prefix("system32\\") {
        s = format!("c:\\windows\\system32\\{r}");
    }
    const VARS: &[(&str, &str)] = &[
        ("%systemroot%", "c:\\windows"),
        ("%windir%", "c:\\windows"),
        ("%system32%", "c:\\windows\\system32"),
        ("%systemdrive%", "c:"),
        ("%osdrive%", "c:"),
        ("%programfiles(x86)%", "c:\\program files (x86)"),
        ("%programfiles%", "c:\\program files"),
        ("%programw6432%", "c:\\program files"),
        ("%commonprogramfiles(x86)%", "c:\\program files (x86)\\common files"),
        ("%commonprogramfiles%", "c:\\program files\\common files"),
        ("%programdata%", "c:\\programdata"),
        ("%allusersprofile%", "c:\\programdata"),
        ("%public%", "c:\\users\\public"),
        ("%appdata%", "c:\\users\\<user>\\appdata\\roaming"),
        ("%localappdata%", "c:\\users\\<user>\\appdata\\local"),
        ("%temp%", "c:\\users\\<user>\\appdata\\local\\temp"),
        ("%tmp%", "c:\\users\\<user>\\appdata\\local\\temp"),
        ("%userprofile%", "c:\\users\\<user>"),
        ("%homepath%", "\\users\\<user>"),
        ("%homedrive%", "c:"),
    ];
    for (var, val) in VARS {
        if s.contains(var) {
            s = s.replace(var, val);
        }
    }
    s
}

const WINDOWS_WRITABLE: &[&str] = &[
    "\\windows\\temp\\",
    "\\windows\\tasks\\",
    "\\windows\\debug\\",
    "\\windows\\tracing\\",
    "\\windows\\fonts\\",
    "\\windows\\pla\\",
    "\\windows\\registration\\crmlog\\",
    "\\windows\\system32\\tasks\\",
    "\\windows\\syswow64\\tasks\\",
    "\\windows\\system32\\spool\\drivers\\color\\",
    "\\windows\\system32\\spool\\printers\\",
    "\\windows\\system32\\microsoft\\crypto\\rsa\\machinekeys\\",
    "\\windows\\system32\\config\\systemprofile\\",
    "\\windows\\syswow64\\config\\systemprofile\\",
    "\\windows\\system32\\fxstmp\\",
    "\\windows\\syswow64\\fxstmp\\",
    "\\windows\\system32\\com\\dmp\\",
    "\\windows\\servicing\\packages\\",
    "\\windows\\servicing\\sessions\\",
    "\\perflogs\\",
];

/// Folder family of an expanded, lowercase Windows path.
pub fn windows_family(path: &str) -> DirFamily {
    let p = path;
    if p.is_empty() {
        return DirFamily::Bare;
    }
    if p.starts_with("\\\\") {
        return DirFamily::Unc;
    }
    let has_drive = p.len() >= 3 && p.as_bytes()[1] == b':' && p.as_bytes()[2] == b'\\';
    let rest = if has_drive {
        &p[2..]
    } else if p.starts_with('\\') {
        p
    } else {
        return if p.contains('\\') { DirFamily::Other } else { DirFamily::Bare };
    };
    for w in WINDOWS_WRITABLE {
        if rest.starts_with(w) {
            return DirFamily::WindowsWritable;
        }
    }
    if rest.starts_with("\\windows\\system32\\") {
        return DirFamily::System32;
    }
    if rest.starts_with("\\windows\\syswow64\\") {
        return DirFamily::SysWow64;
    }
    if rest.starts_with("\\windows\\") || rest.starts_with("\\winnt\\") {
        return DirFamily::WindowsDir;
    }
    if rest.starts_with("\\program files\\") || rest.starts_with("\\program files (x86)\\") {
        return DirFamily::ProgramFiles;
    }
    if rest.starts_with("\\programdata\\") {
        return DirFamily::ProgramData;
    }
    if rest.starts_with("\\$recycle.bin\\") || rest.starts_with("\\recycler\\") || rest.starts_with("\\recycled\\") {
        return DirFamily::Recycle;
    }
    if rest.starts_with("\\temp\\") || rest.starts_with("\\tmp\\") {
        return DirFamily::Temp;
    }
    if rest.starts_with("\\users\\public\\") {
        return DirFamily::Public;
    }
    for root in ["\\users\\", "\\documents and settings\\"] {
        if let Some(after_root) = rest.strip_prefix(root) {
            let Some(slash) = after_root.find('\\') else { return DirFamily::UserProfile };
            let inside = &after_root[slash..];
            if inside.starts_with("\\appdata\\local\\temp\\") || inside.starts_with("\\local settings\\temp\\") {
                return DirFamily::Temp;
            }
            if inside.starts_with("\\appdata\\roaming\\") || inside.starts_with("\\application data\\") {
                return DirFamily::UserAppData;
            }
            if inside.starts_with("\\appdata\\local\\") || inside.starts_with("\\appdata\\locallow\\") || inside.starts_with("\\local settings\\") {
                return DirFamily::UserLocalAppData;
            }
            return DirFamily::UserProfile;
        }
    }
    // `c:\file.exe`: nothing between the drive and the name
    if rest[1..].find('\\').is_none() {
        return DirFamily::DriveRoot;
    }
    DirFamily::Other
}

/// Folder family of a Linux path.
pub fn linux_family(path: &str) -> DirFamily {
    let p = path;
    if p.is_empty() {
        return DirFamily::Bare;
    }
    if !p.starts_with('/') {
        return if p.contains('/') { DirFamily::Other } else { DirFamily::Bare };
    }
    let system = [
        ("/usr/bin/", DirFamily::UsrBin),
        ("/usr/sbin/", DirFamily::UsrSbin),
        ("/usr/lib/", DirFamily::UsrLib),
        ("/usr/lib64/", DirFamily::UsrLib),
        ("/usr/lib32/", DirFamily::UsrLib),
        ("/usr/libexec/", DirFamily::UsrLib),
        ("/usr/share/", DirFamily::UsrLib),
        ("/snap/", DirFamily::UsrLib),
        ("/bin/", DirFamily::Bin),
        ("/sbin/", DirFamily::Sbin),
        ("/lib/", DirFamily::Lib),
        ("/lib64/", DirFamily::Lib),
        ("/lib32/", DirFamily::Lib),
    ];
    for (prefix, fam) in system {
        if p.starts_with(prefix) {
            return fam;
        }
    }
    let scratch = [
        ("/tmp/", DirFamily::Tmp),
        ("/dev/shm/", DirFamily::DevShm),
        ("/var/tmp/", DirFamily::VarTmp),
        ("/run/", DirFamily::Run),
        ("/var/run/", DirFamily::Run),
    ];
    for (prefix, fam) in scratch {
        if p.starts_with(prefix) {
            return fam;
        }
    }
    // a hidden folder anywhere outside the system tree
    let dir = match p.rfind('/') {
        Some(i) => &p[..i],
        None => p,
    };
    if dir.split('/').any(|c| c.len() > 1 && c.starts_with('.')) {
        return DirFamily::Hidden;
    }
    let rest = [
        ("/usr/local/", DirFamily::UsrLocal),
        ("/etc/", DirFamily::Etc),
        ("/opt/", DirFamily::Opt),
        ("/var/", DirFamily::Var),
        ("/home/", DirFamily::Home),
        ("/root/", DirFamily::RootHome),
        ("/mnt/", DirFamily::Mnt),
        ("/media/", DirFamily::Mnt),
        ("/srv/", DirFamily::Var),
    ];
    for (prefix, fam) in rest {
        if p.starts_with(prefix) {
            return fam;
        }
    }
    DirFamily::Other
}

/// Folder and file name of a path (`c:\windows\x.exe` gives `c:\windows`, `x.exe`).
pub fn split_path(os: Os, path: &str) -> (String, String) {
    let sep: &[char] = match os {
        Os::Windows => &['\\', '/'],
        Os::Linux => &['/'],
    };
    match path.rfind(sep) {
        Some(i) => (path[..i].to_string(), path[i + 1..].to_string()),
        None => (String::new(), path.to_string()),
    }
}

/// Extension of a file name, lowercase, with the dot (`.exe`), empty when none.
pub fn ext_of(name: &str) -> String {
    match name.rfind('.') {
        Some(i) if i > 0 && i + 1 < name.len() && name.len() - i <= 6 => name[i..].to_ascii_lowercase(),
        _ => String::new(),
    }
}

/// Name without its extension.
pub fn stem_of(name: &str) -> &str {
    match name.rfind('.') {
        Some(i) if i > 0 => &name[..i],
        _ => name,
    }
}

/// Extensions Windows runs as code.
pub const EXECUTABLE_EXTENSIONS: &[&str] = &[
    ".exe", ".dll", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".msi", ".msp", ".cpl", ".sys", ".ocx",
    ".jar",
];

/// Extensions a document, picture or archive has: the first half of a double extension.
pub const DOCUMENT_EXTENSIONS: &[&str] = &[
    ".pdf", ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".txt", ".rtf", ".odt", ".ods", ".csv", ".log", ".jpg", ".jpeg", ".png", ".gif", ".bmp",
    ".mp3", ".mp4", ".avi", ".zip", ".rar", ".7z", ".html", ".htm", ".xml", ".json",
];

pub fn is_windows_executable_name(name: &str) -> bool {
    let e = ext_of(name);
    !e.is_empty() && EXECUTABLE_EXTENSIONS.contains(&e.as_str())
}

/// Shape of a file name (extension removed first).
pub fn classify_name(name: &str) -> NameClass {
    let stem = stem_of(name).trim();
    if stem.is_empty() {
        return NameClass::Empty;
    }
    let chars: Vec<char> = stem.chars().collect();
    if chars
        .iter()
        .any(|c| !c.is_ascii() || !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ' ' | '.' | '+' | '(' | ')' | '@' | ',' | '~')))
    {
        return NameClass::Odd;
    }
    let alnum: Vec<char> = chars.iter().copied().filter(|c| c.is_ascii_alphanumeric()).collect();
    if alnum.len() <= 2 {
        return NameClass::Tiny;
    }
    let digits = alnum.iter().filter(|c| c.is_ascii_digit()).count();
    if alnum.len() >= 8 && digits > 0 && alnum.iter().all(|c| c.is_ascii_hexdigit()) {
        return NameClass::HexLike;
    }
    if digits * 2 >= alnum.len() {
        return NameClass::DigitHeavy;
    }
    if digits > 0 {
        return NameClass::AlphaDigits;
    }
    NameClass::Alpha
}

/// The shapes name generators give and people do not: six or more letters with no vowel
/// (`xkqzptr`), or eight or more letters that mix case the way `duKhLYUX` does, with
/// three or more capitals, three or more case changes and no lowercase run longer than
/// three. CamelCase names (`SecurityHealthSystray`, `RuntimeBroker`) keep whole words in
/// lowercase and stay out.
pub fn looks_generated(name: &str) -> bool {
    let stem = stem_of(name);
    let chars: Vec<char> = stem.chars().collect();
    if chars.len() < 6 || !chars.iter().all(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    let vowels = chars.iter().filter(|c| matches!(c.to_ascii_lowercase(), 'a' | 'e' | 'i' | 'o' | 'u' | 'y')).count();
    if vowels == 0 {
        return true;
    }
    if chars.len() < 8 {
        return false;
    }
    let uppers = chars.iter().filter(|c| c.is_ascii_uppercase()).count();
    let changes = chars.windows(2).filter(|w| w[0].is_ascii_uppercase() != w[1].is_ascii_uppercase()).count();
    let mut longest_lower = 0;
    let mut run = 0;
    for c in &chars {
        if c.is_ascii_lowercase() {
            run += 1;
            longest_lower = longest_lower.max(run);
        } else {
            run = 0;
        }
    }
    uppers >= 3 && changes >= 3 && longest_lower <= 3
}

/// Unicode controls that change how a name reads: right-to-left override and the other
/// bidi and zero-width characters.
pub fn has_bidi_or_zero_width(name: &str) -> bool {
    name.chars().any(|c| matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{200b}'..='\u{200f}' | '\u{feff}' | '\u{00ad}'))
}

/// Three or more spaces in a row before the extension: `invoice.pdf          .exe`.
pub fn has_padding(name: &str) -> bool {
    let stem = stem_of(name);
    stem.contains("   ") || (stem.ends_with(' ') && stem.trim_end().len() + 2 <= stem.len())
}

/// `name.pdf.exe`: a document extension followed by an executable one.
pub fn double_extension(name: &str) -> Option<(String, String)> {
    let last = ext_of(name);
    if last.is_empty() || !EXECUTABLE_EXTENSIONS.contains(&last.as_str()) {
        return None;
    }
    let inner = ext_of(stem_of(name).trim_end());
    if !inner.is_empty() && DOCUMENT_EXTENSIONS.contains(&inner.as_str()) {
        Some((inner, last))
    } else {
        None
    }
}

/// `c:\dir\readme.txt:payload.exe`: a colon after the drive names an alternate data stream.
pub fn ads_stream(path: &str) -> Option<String> {
    let body = if path.len() >= 2 && path.as_bytes()[1] == b':' { &path[2..] } else { path };
    let name = body.rsplit('\\').next().unwrap_or(body);
    name.find(':').filter(|&i| i > 0 && i + 1 < name.len()).map(|i| name[i + 1..].to_string())
}

/// Windows executables that live in `System32` / `SysWOW64` (and their WinSxS and
/// servicing copies) and nowhere else. The SANS *Hunt Evil* set, the LOLBins of System32,
/// the Windows services and the tools an intruder renames. Lowercase, with extension.
pub const WINDOWS_SYSTEM_BINARIES: &[&str] = &[
    "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "lsaiso.exe", "lsm.exe", "svchost.exe", "taskhost.exe", "taskhostw.exe",
    "taskhostex.exe", "taskeng.exe", "userinit.exe", "dwm.exe", "fontdrvhost.exe", "logonui.exe", "spoolsv.exe", "searchindexer.exe", "searchprotocolhost.exe",
    "searchfilterhost.exe", "dllhost.exe", "runtimebroker.exe", "sihost.exe", "ctfmon.exe", "conhost.exe", "cmd.exe", "powershell.exe", "powershell_ise.exe",
    "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe", "schtasks.exe", "sc.exe", "net.exe",
    "net1.exe", "wmic.exe", "wmiprvse.exe", "wsmprovhost.exe", "winrshost.exe", "taskmgr.exe", "backgroundtaskhost.exe", "audiodg.exe", "werfault.exe",
    "werfaultsecure.exe", "wermgr.exe", "msdtc.exe", "consent.exe", "tiworker.exe", "trustedinstaller.exe", "mmc.exe", "control.exe", "calc.exe", "mstsc.exe",
    "rdpclip.exe", "tstheme.exe", "wuauclt.exe", "usoclient.exe", "mousocoreworker.exe", "wudfhost.exe", "dashost.exe", "smartscreen.exe",
    "securityhealthservice.exe", "securityhealthsystray.exe", "autochk.exe", "winver.exe", "ping.exe", "ipconfig.exe", "netstat.exe", "whoami.exe", "nltest.exe",
    "at.exe", "reg.exe", "tasklist.exe", "taskkill.exe", "findstr.exe", "cmdkey.exe", "cipher.exe", "vssadmin.exe", "wbadmin.exe", "bcdedit.exe", "wevtutil.exe",
    "fsutil.exe", "icacls.exe", "cacls.exe", "takeown.exe", "netsh.exe", "nslookup.exe", "arp.exe", "route.exe", "systeminfo.exe", "quser.exe", "qwinsta.exe",
    "rwinsta.exe", "logoff.exe", "shutdown.exe", "robocopy.exe", "xcopy.exe", "expand.exe", "makecab.exe", "esentutl.exe", "odbcconf.exe", "cmstp.exe",
    "forfiles.exe", "pcalua.exe", "presentationhost.exe", "certreq.exe", "cscript.exe", "diskshadow.exe", "dism.exe", "ntdsutil.exe", "sethc.exe", "utilman.exe",
    "osk.exe", "narrator.exe", "magnify.exe", "displayswitch.exe", "atbroker.exe", "lsass.exe", "wbengine.exe", "vds.exe", "dfsvc.exe", "mavinject.exe",
    "msconfig.exe", "sdbinst.exe", "wscript.exe", "eventvwr.exe", "fodhelper.exe", "computerdefaults.exe", "sdclt.exe", "slui.exe", "cmdl32.exe", "rasautou.exe",
    "ftp.exe", "tftp.exe", "telnet.exe", "runas.exe", "runonce.exe", "wsl.exe", "bash.exe", "curl.exe", "tar.exe", "openwith.exe", "print.exe", "replace.exe",
    "extrac32.exe", "ie4uinit.exe", "unregmp2.exe", "compattelrunner.exe", "dxgiadaptercache.exe", "gpupdate.exe", "gpresult.exe", "lsass.exe", "spoolsv.exe",
];

/// System binaries that live outside `System32`, with the folder they belong to.
pub const WINDOWS_SYSTEM_BINARIES_ELSEWHERE: &[(&str, &[&str])] = &[
    ("explorer.exe", &["c:\\windows", "\\winsxs\\"]),
    ("msmpeng.exe", &["\\windows defender\\", "\\microsoft\\windows defender\\"]),
    ("nissrv.exe", &["\\windows defender\\"]),
    ("mpcmdrun.exe", &["\\windows defender\\"]),
    ("msbuild.exe", &["\\microsoft.net\\", "\\visual studio\\", "\\msbuild\\", "\\dotnet\\"]),
    ("installutil.exe", &["\\microsoft.net\\"]),
    ("regasm.exe", &["\\microsoft.net\\"]),
    ("regsvcs.exe", &["\\microsoft.net\\"]),
    ("csc.exe", &["\\microsoft.net\\", "\\visual studio\\", "\\dotnet\\", "\\roslyn\\"]),
    ("vbc.exe", &["\\microsoft.net\\", "\\visual studio\\", "\\roslyn\\"]),
    ("jsc.exe", &["\\microsoft.net\\"]),
    ("ngen.exe", &["\\microsoft.net\\"]),
    ("mscorsvw.exe", &["\\microsoft.net\\"]),
    ("aspnet_compiler.exe", &["\\microsoft.net\\"]),
    ("notepad.exe", &["c:\\windows", "\\system32", "\\syswow64", "\\winsxs\\", "\\windowsapps\\"]),
    ("regedit.exe", &["c:\\windows", "\\system32", "\\syswow64", "\\winsxs\\"]),
    ("hh.exe", &["c:\\windows", "\\winsxs\\"]),
    ("write.exe", &["c:\\windows", "\\system32", "\\winsxs\\"]),
    ("splwow64.exe", &["c:\\windows", "\\winsxs\\"]),
    ("bfsvc.exe", &["c:\\windows", "\\winsxs\\"]),
    ("winhlp32.exe", &["c:\\windows", "\\winsxs\\"]),
    ("helppane.exe", &["c:\\windows", "\\winsxs\\"]),
    ("fveupdate.exe", &["c:\\windows", "\\winsxs\\"]),
];

/// Besides `System32` and `SysWOW64`, the Windows folders that hold copies of system
/// binaries (component store, servicing, updates, store apps, .NET).
const WINDOWS_COPY_FOLDERS: &[&str] = &["\\winsxs\\", "\\servicing\\", "\\softwaredistribution\\", "\\systemapps\\", "\\immersivecontrolpanel\\", "\\microsoft.net\\", "\\windowsapps\\", "\\system32\\", "\\syswow64\\", "\\sysnative\\", "\\$windows.~bt\\", "\\$windows.~ws\\", "\\windows.old\\", "\\winre\\", "\\recovery\\", "\\boot\\"];

/// Executables that belong directly in `C:\Windows`, lowercase.
pub const WINDOWS_ROOT_BINARIES: &[&str] = &[
    "explorer.exe", "notepad.exe", "regedit.exe", "hh.exe", "write.exe", "splwow64.exe", "bfsvc.exe", "winhlp32.exe", "helppane.exe", "fveupdate.exe", "twunk_32.exe",
    "twunk_16.exe", "py.exe", "pyw.exe", "pyshellext.amd64.dll", "twain_32.dll", "mib.bin", "bootstat.dat", "setupact.log", "win.ini", "system.ini", "notepad.exe",
];

/// Whether a Windows system binary runs from a folder it belongs to. `dir` and `name`
/// are lowercase; the answer is None when the name is not a system binary.
pub fn windows_system_binary_ok(dir: &str, name: &str) -> Option<bool> {
    let dir_slash = format!("{}\\", dir);
    if let Some((_, places)) = WINDOWS_SYSTEM_BINARIES_ELSEWHERE.iter().find(|(n, _)| *n == name) {
        let ok = places.iter().any(|p| if p.starts_with("c:\\") { dir == *p } else { dir_slash.contains(p) });
        return Some(ok || WINDOWS_COPY_FOLDERS.iter().any(|c| dir_slash.contains(c)));
    }
    if WINDOWS_SYSTEM_BINARIES.contains(&name) {
        let fam = windows_family(&dir_slash);
        return Some(fam.is_windows_system() || (fam == DirFamily::WindowsDir && WINDOWS_COPY_FOLDERS.iter().any(|c| dir_slash.contains(c))));
    }
    None
}

/// Linux binaries that live in the system tree and nowhere else: daemons, shells, the
/// coreutils a rootkit replaces.
pub const LINUX_SYSTEM_BINARIES: &[&str] = &[
    "sshd", "sshd-session", "cron", "crond", "atd", "systemd", "init", "systemd-journald", "systemd-logind", "systemd-udevd", "udevd", "dbus-daemon", "rsyslogd",
    "syslogd", "auditd", "agetty", "getty", "login", "su", "sudo", "passwd", "bash", "sh", "dash", "zsh", "ksh", "ls", "ps", "ss", "netstat", "top", "htop", "ip",
    "ifconfig", "lsof", "find", "cat", "ld.so", "ld-linux.so", "ld-linux-x86-64.so.2", "chronyd", "ntpd", "dhclient", "networkmanager", "nginx", "apache2", "httpd",
    "mysqld", "mariadbd", "postgres", "docker", "dockerd", "containerd", "kubelet", "cupsd", "xinetd", "inetd", "vsftpd", "proftpd", "smbd", "nmbd", "named",
    "dnsmasq", "unbound", "snmpd", "postfix", "master", "exim4", "sendmail", "dovecot", "polkitd", "pkexec", "mount", "umount", "modprobe", "insmod", "rmmod",
    "iptables", "nft", "tcpdump", "nc", "ncat", "netcat", "socat", "curl", "wget", "ssh", "scp", "sftp", "rsync", "crontab", "systemctl", "journalctl", "useradd",
    "usermod", "chpasswd", "visudo", "apt", "apt-get", "dpkg", "yum", "dnf", "rpm", "pacman", "zypper", "snapd",
];

/// Names only the kernel gives its threads. A userland process with one of these names
/// that comes from an `execve` or a path is pretending.
pub const KERNEL_THREAD_NAMES: &[&str] = &[
    "kthreadd", "kworker", "ksoftirqd", "migration", "rcu_sched", "rcu_bh", "rcu_gp", "rcu_par_gp", "rcu_preempt", "rcu_tasks", "kswapd", "kcompactd", "watchdog",
    "watchdogd", "khugepaged", "kblockd", "jbd2", "ext4-rsv-conversion", "cpuhp", "kdevtmpfs", "oom_reaper", "writeback", "kintegrityd", "kauditd", "khungtaskd",
    "kstrp", "ksmd", "scsi_eh", "scsi_tmf", "ata_sff", "mm_percpu_wq", "slub_flushwq", "netns", "kthrotld", "acpi_thermal_pm", "md", "edac-poller", "devfreq_wq",
    "kswapd0", "zswap-shrink", "kworker/u", "irq/", "idle_inject", "cryptd", "ipv6_addrconf", "kstrp", "charger_manager", "ttm_swap", "kmpath_rdacd", "kaluad",
];

/// Whether a Linux process name is one of the kernel's thread names, brackets and
/// numbering removed (`[kworker/0:1]`, `kworker/u8:2-events`).
pub fn is_kernel_thread_name(name: &str) -> bool {
    let n = name.trim().trim_start_matches('[').trim_end_matches(']');
    let n = n.split(|c: char| c == '/' || c == ':' || c == '-' || c.is_ascii_digit()).next().unwrap_or(n);
    let n = n.trim();
    !n.is_empty() && KERNEL_THREAD_NAMES.iter().any(|k| k.trim_end_matches('/') == n)
}

/// Edit distance with adjacent transpositions counted as one (optimal string alignment),
/// so `scvhost` is one step from `svchost`.
pub fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (n, m) = (a.len(), b.len());
    let mut d = vec![vec![0usize; m + 1]; n + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=n {
        for j in 1..=m {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            d[i][j] = (d[i - 1][j] + 1).min(d[i][j - 1] + 1).min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                d[i][j] = d[i][j].min(d[i - 2][j - 2] + 1);
            }
        }
    }
    d[n][m]
}

/// The name with the look-alike characters folded: `0` to `o`, `1`, `l`, `I` and `|` to
/// `l`, `5` to `s`, `vv` to `w`, `rn` to `m`.
pub fn fold_homoglyphs(stem: &str) -> String {
    let mut s = String::with_capacity(stem.len());
    for c in stem.chars() {
        s.push(match c {
            '0' => 'o',
            '1' | 'I' | '|' | 'i' => 'l',
            '5' => 's',
            '8' => 'b',
            c => c.to_ascii_lowercase(),
        });
    }
    s.replace("vv", "w").replace("rn", "m")
}

/// Names a distance-1 test would wrongly pair with a system binary.
const LOOKALIKE_EXCEPTIONS: &[&str] = &["net1.exe", "net.exe", "at.exe", "sc.exe", "lsm.exe", "vds.exe", "ftp.exe", "tar.exe", "ip", "ss", "ps", "ls", "sh", "su", "nc", "cat", "md"];

/// The system binary a name imitates: a homoglyph of one, or one edit away from a name
/// of six or more characters. None for a system binary itself or a known exception.
pub fn lookalike_of(os: Os, name: &str) -> Option<(&'static str, &'static str)> {
    let lower = name.to_ascii_lowercase();
    let list: &[&str] = match os {
        Os::Windows => WINDOWS_SYSTEM_BINARIES,
        Os::Linux => LINUX_SYSTEM_BINARIES,
    };
    if list.contains(&lower.as_str()) || LOOKALIKE_EXCEPTIONS.contains(&lower.as_str()) {
        return None;
    }
    if os == Os::Windows {
        if WINDOWS_SYSTEM_BINARIES_ELSEWHERE.iter().any(|(n, _)| *n == lower) {
            return None;
        }
        if !is_windows_executable_name(&lower) {
            return None;
        }
    }
    let stem = stem_of(&lower);
    let folded = fold_homoglyphs(stem);
    for &sys in list {
        if LOOKALIKE_EXCEPTIONS.contains(&sys) {
            continue;
        }
        let sys_stem = stem_of(sys);
        if sys_stem.len() < 4 {
            continue;
        }
        if folded == fold_homoglyphs(sys_stem) && stem != sys_stem {
            return Some((sys, "homoglyph"));
        }
    }
    if stem.len() >= 6 {
        for &sys in list {
            let sys_stem = stem_of(sys);
            if sys_stem.len() >= 6 && edit_distance(stem, sys_stem) == 1 {
                return Some((sys, "one edit away"));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_windows_path() {
        assert_eq!(expand_windows_path(r"\Device\HarddiskVolume2\Windows\System32\cmd.exe"), r"c:\windows\system32\cmd.exe");
        assert_eq!(expand_windows_path(r"\VOLUME{01d8a1b2c3d4e5f6-a1b2c3d4}\TEMP\X.EXE"), r"c:\temp\x.exe");
        assert_eq!(expand_windows_path(r"%SYSTEM32%\CONHOST.EXE"), r"c:\windows\system32\conhost.exe");
        assert_eq!(expand_windows_path(r"%OSDRIVE%\USERS\BOB\APPDATA\LOCAL\TEMP\a.exe"), r"c:\users\bob\appdata\local\temp\a.exe");
        assert_eq!(expand_windows_path(r"\??\C:\Windows\explorer.exe"), r"c:\windows\explorer.exe");
        assert_eq!(expand_windows_path("\"C:/Program Files/App/app.exe\""), r"c:\program files\app\app.exe");
        assert_eq!(expand_windows_path(r"%windir%\system32\wermgr.exe"), r"c:\windows\system32\wermgr.exe");
    }

    #[test]
    fn test_families() {
        assert_eq!(windows_family(r"c:\windows\system32\cmd.exe"), DirFamily::System32);
        assert_eq!(windows_family(r"c:\windows\syswow64\cmd.exe"), DirFamily::SysWow64);
        assert_eq!(windows_family(r"c:\windows\explorer.exe"), DirFamily::WindowsDir);
        assert_eq!(windows_family(r"c:\windows\temp\x.exe"), DirFamily::WindowsWritable);
        assert_eq!(windows_family(r"c:\windows\system32\tasks\x.exe"), DirFamily::WindowsWritable);
        assert_eq!(windows_family(r"c:\perflogs\x.exe"), DirFamily::WindowsWritable);
        assert_eq!(windows_family(r"c:\users\public\x.exe"), DirFamily::Public);
        assert_eq!(windows_family(r"c:\users\bob\appdata\local\temp\x.exe"), DirFamily::Temp);
        assert_eq!(windows_family(r"c:\users\bob\appdata\roaming\x.exe"), DirFamily::UserAppData);
        assert_eq!(windows_family(r"c:\users\bob\downloads\x.exe"), DirFamily::UserProfile);
        assert_eq!(windows_family(r"c:\$recycle.bin\s-1-5-21\x.exe"), DirFamily::Recycle);
        assert_eq!(windows_family(r"c:\x.exe"), DirFamily::DriveRoot);
        assert_eq!(windows_family(r"\\srv\share\x.exe"), DirFamily::Unc);
        assert_eq!(windows_family("x.exe"), DirFamily::Bare);
        assert_eq!(linux_family("/usr/bin/sudo"), DirFamily::UsrBin);
        assert_eq!(linux_family("/tmp/x"), DirFamily::Tmp);
        assert_eq!(linux_family("/dev/shm/x"), DirFamily::DevShm);
        assert_eq!(linux_family("/home/bob/.cache/x"), DirFamily::Hidden);
        assert_eq!(linux_family("/var/www/html/x"), DirFamily::Var);
        assert_eq!(linux_family("/usr/local/sbin/sshd"), DirFamily::UsrLocal);
        assert_eq!(linux_family("sudo"), DirFamily::Bare);
    }

    #[test]
    fn test_name_classes_and_generated() {
        assert_eq!(classify_name("svchost.exe"), NameClass::Alpha);
        assert_eq!(classify_name("ie4uinit.exe"), NameClass::AlphaDigits);
        assert_eq!(classify_name("deadbeef01.exe"), NameClass::HexLike);
        assert_eq!(classify_name("x.exe"), NameClass::Tiny);
        assert_eq!(classify_name("1234abc.exe"), NameClass::DigitHeavy);
        assert_eq!(classify_name("Configuración.exe"), NameClass::Odd);
        assert!(looks_generated("duKhLYUX.exe"));
        assert!(looks_generated("xkqzptr.exe"));
        assert!(!looks_generated("OneDrive.exe"));
        assert!(!looks_generated("SecurityHealthSystray.exe"));
        assert!(!looks_generated("RuntimeBroker.exe"));
        assert!(!looks_generated("svchost.exe"));
    }

    #[test]
    fn test_double_extension_rtlo_padding_ads() {
        assert_eq!(double_extension("invoice.pdf.exe"), Some((".pdf".to_string(), ".exe".to_string())));
        assert_eq!(double_extension("report.docx .scr"), Some((".docx".to_string(), ".scr".to_string())));
        assert_eq!(double_extension("setup.exe"), None);
        assert_eq!(double_extension("Microsoft.PowerShell.Utility.dll"), None);
        assert!(has_bidi_or_zero_width("photo\u{202e}fdp.exe"));
        assert!(!has_bidi_or_zero_width("photo.exe"));
        assert!(has_padding("invoice.pdf          .exe"));
        assert!(!has_padding("my program.exe"));
        assert_eq!(ads_stream(r"c:\users\bob\readme.txt:payload.exe"), Some("payload.exe".to_string()));
        assert_eq!(ads_stream(r"c:\users\bob\readme.txt"), None);
    }

    #[test]
    fn test_system_binary_places() {
        assert_eq!(windows_system_binary_ok(r"c:\windows\system32", "svchost.exe"), Some(true));
        assert_eq!(windows_system_binary_ok(r"c:\windows\syswow64", "svchost.exe"), Some(true));
        assert_eq!(windows_system_binary_ok(r"c:\windows\winsxs\amd64_microsoft-windows-services_10.0", "svchost.exe"), Some(true));
        assert_eq!(windows_system_binary_ok(r"c:\users\bob\appdata\roaming\microsoft", "svchost.exe"), Some(false));
        assert_eq!(windows_system_binary_ok(r"c:\windows", "svchost.exe"), Some(false));
        assert_eq!(windows_system_binary_ok(r"c:\windows", "explorer.exe"), Some(true));
        assert_eq!(windows_system_binary_ok(r"c:\users\bob", "explorer.exe"), Some(false));
        assert_eq!(windows_system_binary_ok(r"c:\programdata\microsoft\windows defender\platform\4.18", "msmpeng.exe"), Some(true));
        assert_eq!(windows_system_binary_ok(r"c:\windows\microsoft.net\framework64\v4.0.30319", "msbuild.exe"), Some(true));
        assert_eq!(windows_system_binary_ok(r"c:\windows\system32\windowspowershell\v1.0", "powershell.exe"), Some(true));
        assert_eq!(windows_system_binary_ok(r"c:\program files\acme", "agent.exe"), None);
    }

    #[test]
    fn test_kernel_names_and_lookalikes() {
        assert!(is_kernel_thread_name("[kworker/0:1]"));
        assert!(is_kernel_thread_name("kworker/u8:2-events"));
        assert!(is_kernel_thread_name("kthreadd"));
        assert!(is_kernel_thread_name("ksoftirqd/3"));
        assert!(!is_kernel_thread_name("sshd"));
        assert!(!is_kernel_thread_name("kwrite"));
        assert_eq!(lookalike_of(Os::Windows, "svch0st.exe"), Some(("svchost.exe", "homoglyph")));
        assert_eq!(lookalike_of(Os::Windows, "isass.exe"), Some(("lsass.exe", "homoglyph")));
        assert_eq!(lookalike_of(Os::Windows, "scvhost.exe"), Some(("svchost.exe", "one edit away")));
        assert_eq!(lookalike_of(Os::Windows, "rundl132.exe"), Some(("rundll32.exe", "homoglyph")));
        assert_eq!(lookalike_of(Os::Windows, "svchost.exe"), None);
        assert_eq!(lookalike_of(Os::Windows, "net1.exe"), None);
        assert_eq!(lookalike_of(Os::Windows, "wscript.exe"), None);
        assert_eq!(lookalike_of(Os::Windows, "explorer.exe"), None);
        assert_eq!(lookalike_of(Os::Windows, "OneDrive.exe"), None);
        assert_eq!(lookalike_of(Os::Windows, "services.dll"), None);
        assert_eq!(lookalike_of(Os::Linux, "systemd"), None);
        assert_eq!(lookalike_of(Os::Linux, "systemd-journa1d"), Some(("systemd-journald", "homoglyph")));
        assert_eq!(edit_distance("svchost", "scvhost"), 1);
        assert_eq!(edit_distance("svchost", "svchosts"), 1);
        assert_eq!(edit_distance("svchost", "svcnost"), 1);
        assert_eq!(edit_distance("svchost", "lsass"), 6);
    }
}
