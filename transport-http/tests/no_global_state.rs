// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RED (`BUSBAR-1.6.0.md` THE DESIGN §2: "A plugin holds no process-global state: what it keeps is
//! per-instance"): the crate's production source declares no `static` item and no `thread_local!`.
//! What a framer keeps lives in its door's instance; a linked copy and a dropped-in copy, or two
//! instances, never share a slot.

use std::path::{Path, PathBuf};

/// Every `.rs` file under `dir`, test directories excluded (their fixtures are not shipped code).
fn production_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .expect("read the source directory")
        .map(|e| e.expect("a directory entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "tests") {
                continue;
            }
            production_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The lines of `text` that declare process-global state: a `static` item (any visibility,
/// `static mut` included) or a `thread_local!` block. A `&'static` lifetime is not one.
fn global_state(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim_start)
        .filter(|l| !l.starts_with("//"))
        .filter(|l| {
            let item = l
                .strip_prefix("pub")
                .map_or(*l, |rest| match rest.strip_prefix('(') {
                    Some(scoped) => scoped.split_once(')').map_or(rest, |(_, r)| r),
                    None => rest,
                })
                .trim_start();
            item.starts_with("static ") || l.contains("thread_local!")
        })
        .map(str::to_owned)
        .collect()
}

/// The scan's positive control: it sees a static in every visibility and a thread-local, and
/// passes a `const` and a `&'static` lifetime.
#[test]
fn the_scan_sees_a_static_where_one_is_written() {
    assert_eq!(global_state("static A: u8 = 0;").len(), 1);
    assert_eq!(global_state("    pub static B: u8 = 0;").len(), 1);
    assert_eq!(
        global_state("pub(crate) static C: std::sync::OnceLock<u8> = std::sync::OnceLock::new();")
            .len(),
        1
    );
    assert_eq!(global_state("static mut D: u8 = 0;").len(), 1);
    assert_eq!(global_state("thread_local! { static E: u8 = 0; }").len(), 1);
    assert!(global_state("const F: u8 = 0;\nfn g(x: &'static str) {}\n// static H").is_empty());
}

#[test]
fn the_crate_holds_no_process_global_state() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    production_sources(&src, &mut files);
    assert!(
        files.iter().any(|f| f.ends_with("door/mod.rs")),
        "the scan reads the door"
    );
    let hits: Vec<String> = files
        .iter()
        .flat_map(|f| {
            let text = std::fs::read_to_string(f).expect("read a source file");
            global_state(&text)
                .into_iter()
                .map(move |l| format!("{}: {l}", f.display()))
        })
        .collect();
    assert!(hits.is_empty(), "process-global state: {hits:#?}");
}
