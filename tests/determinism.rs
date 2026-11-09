//! The CSV is the same bytes whatever the thread count: the whole pipeline (parse, dedup,
//! parents, hunt, tails, order, write) runs once on the default pool and once on a pool of
//! one thread, over the XFS lab image, and the two files must be identical.

use std::io::Read;
use std::path::{Path, PathBuf};

fn gunzip_fixture(name: &str, into: &Path) -> PathBuf {
    let gz = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/linux_disk").join(format!("{}.gz", name));
    let mut dec = flate2::read::GzDecoder::new(std::fs::File::open(&gz).expect("fixture"));
    let mut bytes = Vec::new();
    dec.read_to_end(&mut bytes).unwrap();
    let out = into.join(name);
    std::fs::write(&out, bytes).unwrap();
    out
}

fn pipeline(vol: &Path, out: &Path) -> Vec<u8> {
    let mut events = caarea::parsers::linux::process_linux_target(vol, true).expect("linux parsers");
    caarea::dedup_events(&mut events);
    caarea::hunt::tree::resolve_parents(&mut events);
    let findings = caarea::hunt::run(&events, None, None);
    let tails = caarea::hunt::tails(events.len(), &findings);
    let mut rows: Vec<(caarea::parsers::evtx::Event, caarea::hunt::Tail)> = events.into_iter().zip(tails).collect();
    rows.sort_by(|a, b| caarea::timeline::event_order(&a.0, &b.0));
    let (events, tails): (Vec<_>, Vec<_>) = rows.into_iter().unzip();
    caarea::timeline::export_timeline(&events, &tails, out.to_str().unwrap(), true).unwrap();
    std::fs::read(out).unwrap()
}

#[test]
fn one_thread_and_many_write_the_same_bytes() {
    let d = std::env::temp_dir().join(format!("caarea_det_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    let img = gunzip_fixture("gpt_xfs.img", &d);
    let staging = d.join("staging");
    std::fs::create_dir_all(&staging).unwrap();
    let out = caarea::ingest::image::unpack_disk_image(&img, &staging, true).expect("unpack");
    let vol = walkdir::WalkDir::new(&out.live_dir)
        .min_depth(1)
        .max_depth(3)
        .into_iter()
        .flatten()
        .find(|e| e.file_type().is_dir() && e.path().join("etc").join("hostname").is_file())
        .map(|e| e.into_path())
        .expect("a staged Linux volume");

    let many = pipeline(&vol, &d.join("many.csv"));
    let one = rayon::ThreadPoolBuilder::new().num_threads(1).build().unwrap().install(|| pipeline(&vol, &d.join("one.csv")));
    let again = pipeline(&vol, &d.join("again.csv"));
    assert!(many.len() > 1000, "the lab volume gives a timeline");
    assert_eq!(many, one, "one thread and the default pool must write the same bytes");
    assert_eq!(many, again, "two runs on the same pool must write the same bytes");
    let _ = std::fs::remove_dir_all(&d);
}
