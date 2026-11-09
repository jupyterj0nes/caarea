//! How many threads a run takes and how much evidence it holds in flight, decided from the
//! machine when the flags do not say.
//!
//! Threads: every core the process may use (`std::thread::available_parallelism`, which honours
//! an affinity mask and a container's CPU quota), with no figure reserved and no fixed number:
//! twelve on a desktop of twelve, ninety-six on a server of ninety-six. `--threads N` or
//! `RAYON_NUM_THREADS` say otherwise; `1` runs every stage in series. The pool is rayon's
//! global one and every parallel stage shares it (the evtx crate's chunk decoding too), so the
//! total never exceeds the figure.
//!
//! Memory: a file being parsed costs several times its size while its records are in flight
//! (an EVTX measured five times: 10 MB of Security log peak 48 MB above the baseline), and
//! the parsers take one file per thread, so a server with many cores holds many files at
//! once. The files of a directory are therefore parsed in waves: within a wave the `workers`
//! largest files together cost at most the budget, a quarter of the memory free when the run
//! starts (512 MiB at least, 2 GiB when the system does not say; `CAAREA_FILE_BUDGET=<bytes>`
//! overrides). On a machine with memory to spare every directory is one wave and nothing
//! changes; on a machine with many cores and little memory the waves keep the run out of swap.
//! The waves are cut in the order the files were listed and collected in that order, so the
//! timeline does not depend on the budget, the thread count or the memory of the machine.

use std::ops::Range;
use std::sync::OnceLock;

static WORKERS: OnceLock<usize> = OnceLock::new();
static BUDGET: OnceLock<u64> = OnceLock::new();

/// What was decided for this run, for the console line.
#[derive(Debug, Clone)]
pub struct Decision {
    /// threads of the pool
    pub workers: usize,
    /// cores the process may use
    pub cores: usize,
    /// the figure came from `--threads` or `RAYON_NUM_THREADS`
    pub asked: bool,
    /// bytes a wave of files may cost at once
    pub budget: u64,
    /// physical memory free when the run started, when the system said
    pub free: Option<u64>,
}

/// Bytes of memory an EVTX file costs while it is being parsed, per byte of file (measured:
/// a 10,308 KB Security log peaked 48 MB above the baseline on one thread, a 2,116 KB
/// Application log 22 MB, with records extracted in batches of 4,096).
pub const EVTX_COST_PER_BYTE: u64 = 5;

/// Bytes a registry hive costs while it is being parsed, per byte of file: the hive is read
/// whole and walked, the rows are a fraction of it (an estimate, not a measurement; it only
/// decides how many hives share a wave, never what they produce).
pub const HIVE_COST_PER_BYTE: u64 = 3;

/// The threads for this run: `asked` when it says one or more, every core otherwise; and the
/// memory budget for the files in flight.
pub fn decide(asked: Option<usize>) -> Decision {
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let (workers, was_asked) = match asked {
        Some(n) if n >= 1 => (n, true),
        _ => (cores, false),
    };
    let free = available_memory();
    let budget = match std::env::var("CAAREA_FILE_BUDGET").ok().and_then(|s| s.trim().parse::<u64>().ok()) {
        Some(b) if b > 0 => b,
        _ => free.map(|m| (m / 4).max(512 << 20)).unwrap_or(2 << 30),
    };
    Decision { workers, cores, asked: was_asked, budget, free }
}

/// Builds the global pool with the figure (even when it is the machine's: rayon would otherwise
/// size its own the first time a stage touches it) and records the budget. Once per process.
pub fn install(d: &Decision) -> Result<(), String> {
    if WORKERS.set(d.workers).is_err() {
        return Ok(());
    }
    let _ = BUDGET.set(d.budget);
    rayon::ThreadPoolBuilder::new()
        .num_threads(d.workers)
        .thread_name(|i| format!("caarea-{}", i))
        .build_global()
        .map_err(|e| format!("cannot build the thread pool: {}", e))
}

/// The threads of this run: one before `install`.
pub fn workers() -> usize {
    WORKERS.get().copied().unwrap_or(1)
}

/// The memory budget of this run for files in flight, bytes.
pub fn file_budget() -> u64 {
    BUDGET.get().copied().unwrap_or(2 << 30)
}

/// One line for the console: what the run decided and why.
pub fn banner(d: &Decision) -> String {
    let threads = if d.asked {
        format!("{} (asked; the machine has {})", d.workers, d.cores)
    } else {
        format!("{} ({} core{}; --threads changes it, 1 runs serial)", d.workers, d.cores, if d.cores == 1 { "" } else { "s" })
    };
    let budget = match d.free {
        Some(free) => format!("{} for the files in flight ({} free)", human(d.budget), human(free)),
        None => format!("{} for the files in flight (the system does not say what is free)", human(d.budget)),
    };
    format!("Threads: {}; memory budget {}", threads, budget)
}

fn human(bytes: u64) -> String {
    if bytes >= 1 << 30 {
        format!("{:.1} GiB", bytes as f64 / (1u64 << 30) as f64)
    } else {
        format!("{} MiB", bytes >> 20)
    }
}

/// Cuts the files of a directory into the waves the budget allows, in the order given: within
/// a wave the `workers` largest files (the most that are in flight at once) together cost at
/// most `budget`. A file that alone exceeds it is a wave of its own. The ranges cover
/// `0..sizes.len()` in order, so collecting wave after wave keeps the file order.
pub fn waves(sizes: &[u64], cost_per_byte: u64, budget: u64, workers: usize) -> Vec<Range<usize>> {
    let k = workers.max(1);
    let mut out = Vec::new();
    let mut start = 0;
    // the k largest costs of the current wave, smallest first
    let mut top: Vec<u64> = Vec::with_capacity(k + 1);
    let mut top_sum: u64 = 0;
    for (i, &size) in sizes.iter().enumerate() {
        let cost = size.saturating_mul(cost_per_byte);
        let would_be = if top.len() < k {
            top_sum.saturating_add(cost)
        } else if cost > top[0] {
            top_sum - top[0] + cost
        } else {
            top_sum
        };
        if i > start && would_be > budget {
            out.push(start..i);
            start = i;
            top.clear();
            top_sum = 0;
        }
        // admit the file into the current wave
        let pos = top.partition_point(|&c| c < cost);
        top.insert(pos, cost);
        top_sum = top_sum.saturating_add(cost);
        if top.len() > k {
            top_sum -= top.remove(0);
        }
    }
    if start < sizes.len() {
        out.push(start..sizes.len());
    }
    out
}

/// Sizes of the files at `paths`, zero when the file system does not say.
pub fn sizes_of<P: AsRef<std::path::Path>>(paths: &[P]) -> Vec<u64> {
    paths.iter().map(|p| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)).collect()
}

/// Physical memory free right now, bytes, when the system tells.
#[cfg(windows)]
pub fn available_memory() -> Option<u64> {
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    let mut m: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
    m.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
    // SAFETY: a documented Win32 call that fills the struct whose size it is told.
    let ok = unsafe { GlobalMemoryStatusEx(&mut m) };
    (ok != 0 && m.ullAvailPhys > 0).then_some(m.ullAvailPhys)
}

#[cfg(target_os = "linux")]
pub fn available_memory() -> Option<u64> {
    // MemAvailable is what the kernel estimates can be used without swapping; inside a
    // container with a memory limit the cgroup's own figure is the smaller of the two.
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    let line = text.lines().find(|l| l.starts_with("MemAvailable:"))?;
    let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    let mut avail = kb * 1024;
    if let Some(limit) = cgroup_memory_limit() {
        avail = avail.min(limit);
    }
    Some(avail)
}

#[cfg(target_os = "linux")]
fn cgroup_memory_limit() -> Option<u64> {
    for path in ["/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"] {
        if let Ok(text) = std::fs::read_to_string(path) {
            let text = text.trim();
            if text == "max" {
                return None;
            }
            if let Ok(v) = text.parse::<u64>() {
                // the v1 "unlimited" is a very large number
                if v < 1 << 60 {
                    return Some(v);
                }
            }
        }
    }
    None
}

#[cfg(target_os = "macos")]
pub fn available_memory() -> Option<u64> {
    // the system does not say what is free in one call: half of what there is
    let mut total: u64 = 0;
    let mut len = std::mem::size_of::<u64>();
    // SAFETY: hw.memsize is a u64; the buffer and its length are given.
    let rc = unsafe { libc::sysctlbyname(c"hw.memsize".as_ptr(), &mut total as *mut u64 as *mut _, &mut len, std::ptr::null_mut(), 0) };
    (rc == 0 && total > 0).then_some(total / 2)
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub fn available_memory() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_core_unless_asked() {
        let d = decide(None);
        assert_eq!(d.workers, d.cores);
        assert!(!d.asked);
        assert!(d.budget >= 512 << 20);
        let d = decide(Some(3));
        assert_eq!(d.workers, 3);
        assert!(d.asked);
        let d = decide(Some(0));
        assert_eq!(d.workers, d.cores, "zero means the machine decides");
    }

    #[test]
    fn waves_cover_the_files_in_order() {
        // everything fits: one wave
        assert_eq!(waves(&[10, 20, 30], 5, 1000, 4), vec![0..3]);
        // nothing to do
        assert!(waves(&[], 5, 1000, 4).is_empty());
        // two threads: the two largest of a wave may cost at most 100
        // costs: 50, 50, 50, 50 -> any two cost 100: one wave
        assert_eq!(waves(&[10, 10, 10, 10], 5, 100, 2), vec![0..4]);
        // costs 50, 60, 50, 50: 50+60 > 100 cuts before the 60, 60+50 > 100 cuts after it,
        // the last two cost 100 together
        assert_eq!(waves(&[10, 12, 10, 10], 5, 100, 2), vec![0..1, 1..2, 2..4]);
        // the same files with budget 110: 50+60 fits, 60+50 fits, 60+50+50 holds the two
        // largest at 110: one wave
        assert_eq!(waves(&[10, 12, 10, 10], 5, 110, 2), vec![0..4]);
        // a file beyond the budget alone is a wave of its own, before and after
        assert_eq!(waves(&[1, 500, 1, 1], 5, 100, 8), vec![0..1, 1..2, 2..4]);
        // one thread: only the largest file of a wave counts
        assert_eq!(waves(&[30, 30, 30, 30], 5, 150, 1), vec![0..4]);
        assert_eq!(waves(&[30, 40, 30], 5, 150, 1), vec![0..1, 1..2, 2..3]);
        // the ranges always tile 0..n
        let sizes: Vec<u64> = (0..97).map(|i| (i * 7919 % 101) as u64).collect();
        for k in [1, 2, 5, 64] {
            for budget in [1, 50, 500, 5000, 1 << 40] {
                let w = waves(&sizes, 5, budget, k);
                assert_eq!(w.first().map(|r| r.start), Some(0));
                assert_eq!(w.last().map(|r| r.end), Some(sizes.len()));
                for pair in w.windows(2) {
                    assert_eq!(pair[0].end, pair[1].start);
                    assert!(!pair[0].is_empty());
                }
            }
        }
    }

    #[test]
    fn banner_says_what_was_decided() {
        let d = Decision { workers: 12, cores: 12, asked: false, budget: 3 << 30, free: Some(12 << 30) };
        assert_eq!(banner(&d), "Threads: 12 (12 cores; --threads changes it, 1 runs serial); memory budget 3.0 GiB for the files in flight (12.0 GiB free)");
        let d = Decision { workers: 1, cores: 8, asked: true, budget: 512 << 20, free: None };
        assert!(banner(&d).starts_with("Threads: 1 (asked; the machine has 8); memory budget 512 MiB"));
    }

    #[test]
    fn the_machine_says_something() {
        // on the three platforms we build for the figure exists and is plausible
        if let Some(free) = available_memory() {
            assert!(free > 64 << 20, "free memory {} bytes", free);
        }
    }
}
