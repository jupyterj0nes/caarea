//! What clean hosts execute: the reference built into the binary, so a row a stock
//! machine also produces is vouched for by identity whatever its rules say.
//!
//! `clean/windows.tsv` and `clean/linux.tsv` hold the distinct (artifact, processname,
//! commandline) triples of the reference timelines, tab-separated, one per line (`scripts/measure_clean.py`, run on the
//! clean lab hosts of `rarity::REFERENCE` with the lab's own beacon and the collection's
//! activity left out). At start-up each triple becomes an identity ([`identity`]): lower
//! case, environment variables expanded, user names, SIDs, GUIDs, version folders, random
//! temp names, long numbers and hashes neutralised, so the same stock behaviour matches
//! across hosts, users and updates. A finding on a row whose identity is here keeps its
//! clause, adds no points and gives no state: the row is `habitual`, as the convention of
//! the four tools has it for an entry something vouches for (masstin's `docs/csv-format.md`).

use std::collections::HashSet;
use std::sync::OnceLock;

use super::names;

/// The words the tail adds to a vouched row.
pub const REASON: &str = "on the clean reference hosts";

static SET: OnceLock<HashSet<String>> = OnceLock::new();

fn load() -> HashSet<String> {
    let mut set = HashSet::new();
    for text in [include_str!("clean/windows.tsv"), include_str!("clean/linux.tsv")] {
        for line in text.lines().skip(1) {
            let mut it = line.splitn(3, '\t');
            let artifact = it.next().unwrap_or("");
            let process = it.next().unwrap_or("");
            let command = it.next().unwrap_or("");
            if !artifact.is_empty() {
                set.insert(identity(artifact, process, command));
            }
        }
    }
    set
}

/// Rows of the reference: how many identities are built in.
pub fn size() -> usize {
    SET.get_or_init(load).len()
}

/// Whether a row's identity is one a clean host produced.
pub fn is_clean(artifact: &str, processname: &str, commandline: &str) -> bool {
    let set = SET.get_or_init(load);
    !set.is_empty() && set.contains(&identity(artifact, processname, commandline))
}

/// The host-independent identity of a row: `artifact|process|command`, masked.
pub fn identity(artifact: &str, processname: &str, commandline: &str) -> String {
    let windows = !artifact.starts_with("linux:");
    let process = if windows { names::expand_windows_path(processname) } else { processname.to_string() };
    format!("{}|{}|{}", artifact.trim().to_ascii_lowercase(), mask(&process.to_lowercase(), windows), mask(&commandline.to_lowercase(), windows))
}

fn mask(s: &str, windows: bool) -> String {
    let mut c = s.replace('/', if windows { "\\" } else { "/" });
    if windows {
        c = mask_between(&c, "\\users\\", '\\', "<user>");
        c = mask_between(&c, "\\documents and settings\\", '\\', "<user>");
        if c.len() >= 2 && c.as_bytes()[1] == b':' {
            c.replace_range(0..1, "c");
        }
    } else {
        c = mask_between(&c, "/home/", '/', "<user>");
    }
    c = mask_sids(&c);
    c = mask_tokens(&c);
    // the per-session subfolder of a user's Temp (`Temp\\1\\`) is not identity
    if windows {
        c = c.replace("\\temp\\<n>\\", "\\temp\\");
    }
    c.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn mask_between(s: &str, prefix: &str, stop: char, with: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find(prefix) {
        out.push_str(&rest[..i + prefix.len()]);
        let after = &rest[i + prefix.len()..];
        out.push_str(with);
        match after.find(stop) {
            Some(j) => rest = &after[j..],
            None => rest = "",
        }
    }
    out.push_str(rest);
    out
}

fn mask_sids(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("s-1-5-21-") {
        out.push_str(&rest[..i]);
        let after = &rest[i..];
        let end = after.find(|c: char| !(c.is_ascii_digit() || c == '-' || c == 's')).unwrap_or(after.len());
        out.push_str("<sid>");
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

/// Tokens between separators (`\\`, `/`, space, braces, dots on either side of a hex run)
/// that carry no identity: GUIDs, version numbers, hashes, long numbers, random temp names.
fn mask_tokens(s: &str) -> String {
    let is_sep = |c: char| matches!(c, '\\' | '/' | ' ' | '{' | '}' | ',' | ';' | '=' | '(' | ')' | '"' | '\'');
    let mut out = String::with_capacity(s.len());
    for part in s.split_inclusive(is_sep) {
        let (tok, sep) = match part.char_indices().last() {
            Some((i, c)) if is_sep(c) => (&part[..i], &part[i..]),
            _ => (part, ""),
        };
        out.push_str(mask_token(tok));
        out.push_str(sep);
    }
    out
}

fn mask_token(tok: &str) -> &str {
    if tok.is_empty() {
        return tok;
    }
    let b = tok.as_bytes();
    let all = |f: fn(&u8) -> bool| b.iter().all(f);
    // a number of any length: a PID, a shimcache position, a counter, a flag value
    if all(|c| c.is_ascii_digit()) {
        return "<n>";
    }
    if tok.len() < 4 {
        return tok;
    }
    // 8-4-4-4-12 GUID
    if tok.len() == 36 && tok.split('-').map(|p| p.len()).eq([8, 4, 4, 4, 12]) && tok.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
        return "<guid>";
    }
    // a hash or a long hex run (SHA1, machine ids)
    if tok.len() >= 16 && all(|c| c.is_ascii_hexdigit()) {
        return "<hex>";
    }
    // a version: digits, dots and dashes with a dot, starting with a digit
    if b[0].is_ascii_digit() && tok.contains('.') && all(|c| c.is_ascii_digit() || *c == b'.' || *c == b'-') {
        return "<ver>";
    }
    // random temp names: tmpXXXXXXXX, a run of letters and digits with both in it and no vowel structure
    if tok.len() >= 8 && tok.starts_with("tmp") && tok[3..].chars().all(|c| c.is_ascii_alphanumeric()) {
        return "tmp<rand>";
    }
    // a GUID glued to a name: {guid}name, guidname (Defender's MpCommU folders)
    if tok.len() > 36 && tok[..36].split('-').map(|p| p.len()).eq([8, 4, 4, 4, 12]) && tok[..36].chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
        return "<guid>";
    }
    // a name that ends in a long number: metadata-scripts2138094187
    if let Some(i) = tok.rfind(|c: char| !c.is_ascii_digit()) {
        if tok.len() - i - 1 >= 6 {
            return &tok[..i + 1];
        }
    }
    tok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities_neutralise_what_varies_between_hosts() {
        assert_eq!(
            identity("registry:shimcache", r"C:\Windows\TEMP\B9277B8E-DD04-4D10-B7E1-73187F270566\dismhost.exe", "Position: 219, Executed: Unknown/NotRecorded"),
            identity("registry:shimcache", r"D:\Windows\TEMP\4F54EE36-EF49-4D4C-AF78-2D39F2959FC3\DismHost.exe", "Position: 2, Executed: Unknown/NotRecorded")
        );
        assert_eq!(
            identity("registry:amcache", r"c:\windows\temp\8578ace0-46b8-4630-9394-e343fd87d8a8mpcommu\mpam-fe_bd.exe", "SHA1: 0000398c0a0fcf96818398751238c600ead417d43113, Class: file"),
            identity("registry:amcache", r"c:\windows\temp\c72c75e9-af3a-4862-8fd8-950a16bd03d2mpcommu\mpam-fe_bd.exe", "SHA1: 0000398c0a0fcf96818398751238c600ead417d43114, Class: file")
        );
        assert_eq!(
            identity("registry:shimcache", r"C:\Windows\TEMP\tmp0l7weikr\python\python.exe", ""),
            identity("registry:shimcache", r"C:\Windows\TEMP\tmpab12cd34\python\python.exe", "")
        );
        assert_eq!(
            identity("registry:shimcache", r"C:\Windows\TEMP\metadata-scripts2138094187\windows-startup-script-cmd.cmd", ""),
            identity("registry:shimcache", r"C:\Windows\TEMP\metadata-scripts3936632003\windows-startup-script-cmd.cmd", "")
        );
        assert_eq!(
            identity("registry:services", r"%systemroot%\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe", "Service: NetTcpPortSharing"),
            identity("registry:services", r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe", "Service: NetTcpPortSharing")
        );
        assert_eq!(identity("x", r"C:\Users\bob\a.exe", "S-1-5-21-1-2-3-500"), identity("x", r"C:\Users\alice\a.exe", "S-1-5-21-9-8-7-1001"));
        assert_eq!(
            identity("registry:shimcache", r"C:\Users\vagrant\AppData\Local\Temp\507143E6-97D9-47A2-88D3-7F618B41791B\dismhost.exe", ""),
            identity("registry:shimcache", r"C:\Users\Administrator\AppData\Local\Temp\1\DB0815E8-2C29-4DBA-8917-39E7B78051C4\dismhost.exe", ""),
            "the session subfolder of Temp is not identity"
        );
        assert_ne!(identity("x", r"C:\Users\Public\rfupd.exe", ""), identity("x", r"C:\Users\Public\svchost.exe", ""));
        assert_eq!(identity("linux:journal:process", "/usr/bin/python3.10", "/home/bob/x.py 123456"), identity("linux:journal:process", "/usr/bin/python3.10", "/home/eve/x.py 654321"));
        assert_eq!(mask_token("4.18.26100.4-0"), "<ver>");
        assert_eq!(mask_token("v4.0.30319"), "v4.0.30319", "a leading letter is a name");
        assert_eq!(mask_token("1234"), "<n>");
        assert_eq!(mask_token("2"), "<n>");
        assert_eq!(mask_token("exit"), "exit");
    }

    #[test]
    fn the_reference_loads() {
        // the file may be the empty placeholder in a fresh checkout; it must parse either way
        let _ = size();
        assert!(!is_clean("registry:shimcache", r"C:\Users\Public\never-on-a-clean-host.exe", ""));
    }
}
