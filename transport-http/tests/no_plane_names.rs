// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A TRANSPORT IS A WIRE, NEVER A PLANE — asserted over this crate's own source and its own manifest.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// The crate's purity vocabulary: the plane-crate spellings, the dialect words (named so a
struct Vocab {
    plane_crates: Vec<String>,
    dialect_words: HashMap<String, String>,
    entries: HashMap<String, String>,
}

impl Vocab {
    /// The dialect word filed under `key` (e.g. `DIALECT_1`) in the fixture.
    fn word(&self, key: &str) -> &str {
        self.dialect_words
            .get(key)
            .unwrap_or_else(|| panic!("fixture missing dialect word `{key}`"))
    }

    /// The literal text filed under `key` in the fixture's `[entries]` section.
    fn text(&self, key: &str) -> &str {
        self.entries
            .get(key)
            .unwrap_or_else(|| panic!("fixture missing entry `{key}`"))
    }
}

/// Parse `fixtures/plane_vocabulary.txt` (`[section]` headers, `key=value` or bare-value lines).
fn load_vocab() -> Vocab {
    const RAW: &str = include_str!("fixtures/plane_vocabulary.txt");
    let mut section = "";
    let mut plane_crates = Vec::new();
    let mut dialect_words = HashMap::new();
    let mut entries = HashMap::new();
    for line in RAW.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            section = name;
            continue;
        }
        match section {
            "plane_crates" => plane_crates.push(line.to_string()),
            "dialect_words" => {
                if let Some((k, v)) = line.split_once('=') {
                    dialect_words.insert(k.to_string(), v.to_string());
                }
            }
            _ => {
                if let Some((k, v)) = line.split_once('=') {
                    entries.insert(k.to_string(), v.to_string());
                }
            }
        }
    }
    assert!(
        !plane_crates.is_empty() && !dialect_words.is_empty() && !entries.is_empty(),
        "the vocabulary fixture parsed empty, which is a broken test rather than a clean crate"
    );
    Vocab {
        plane_crates,
        dialect_words,
        entries,
    }
}

/// The core names a transport may not reach for, in both spellings.
const CORE_NAMES: &[&str] = &[
    "busbar-kernel",
    "busbar_kernel",
    "busbar-caps",
    "busbar_contract::caps",
    "run_unit",
];

/// This crate's own root, from the manifest directory the test binary was built with.
fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every `.rs` file under a directory.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Whether `word` occurs in `haystack` with a non-alphanumeric neighbour on each side.
fn contains_word(haystack: &str, word: &str) -> bool {
    let lower = haystack.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut from = 0;
    while let Some(at) = lower[from..].find(word) {
        let start = from + at;
        let end = start + word.len();
        let before_ok = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
        let after_ok = end == bytes.len() || !bytes[end].is_ascii_alphanumeric();
        if before_ok && after_ok {
            return true;
        }
        from = end;
    }
    false
}

/// No source file in this crate names a plane, a plane crate or a dialect.
#[test]
fn the_source_names_no_plane() {
    let vocab = load_vocab();
    let mut files = Vec::new();
    rust_files(&crate_root().join("src"), &mut files);
    assert!(
        !files.is_empty(),
        "the scan found no source to judge, which is a broken test rather than a clean crate"
    );
    let mut found: Vec<String> = Vec::new();
    for file in &files {
        let text =
            std::fs::read_to_string(file).expect("a source file this crate owns is readable");
        for crate_name in &vocab.plane_crates {
            if text.contains(crate_name.as_str()) {
                found.push(format!("{}: names `{crate_name}`", file.display()));
            }
        }
        for word in vocab.dialect_words.values() {
            if contains_word(&text, word) {
                found.push(format!("{}: names the dialect `{word}`", file.display()));
            }
        }
        for core in CORE_NAMES {
            if text.contains(core) {
                found.push(format!("{}: names core (`{core}`)", file.display()));
            }
        }
    }
    assert!(
        found.is_empty(),
        "a transport is a wire, never a plane, and this crate's source names one:\n  {}",
        found.join("\n  ")
    );
}

/// The dependency KEYS (never comment text) in `[dependencies]`, `[dev-dependencies]` and
/// `[build-dependencies]` (including target-specific tables) that name a busbar crate a transport
/// may not depend on: anything `busbar-`/`busbar_` except the two contract crates and sibling
/// transports.
fn disallowed_busbar_dependency_keys(manifest: &str) -> Vec<String> {
    // Whether `key` is a busbar crate a transport may not depend on.
    fn disallowed(key: &str) -> bool {
        (key.starts_with("busbar-") || key.starts_with("busbar_"))
            && !(key == "busbar-contract"
                || key == "busbar-contract-transport"
                || key.starts_with("busbar-transport-"))
    }
    let mut in_deps = false;
    let mut out = Vec::new();
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            let header = line.trim_matches(|c| c == '[' || c == ']');
            in_deps = header.ends_with("dependencies");
            // The dotted-table form: `[dependencies.<key>]`, `[dev-dependencies.<key>]`,
            // `[target.'cfg'.build-dependencies.<key>]`.
            if let Some((_, key)) = header.rsplit_once("dependencies.") {
                let key = key.trim().trim_matches('"');
                if disallowed(key) {
                    out.push(key.to_string());
                }
            }
            continue;
        }
        if !in_deps || line.starts_with('#') {
            continue;
        }
        let Some((key, _)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().trim_matches('"');
        let key = key.split('.').next().unwrap_or(key);
        if disallowed(key) {
            out.push(key.to_string());
        }
    }
    out
}

/// No dependency of this crate — including a dev-dependency — is a plane crate or a core crate.
#[test]
fn the_manifest_names_neither_a_plane_nor_core() {
    let vocab = load_vocab();
    let manifest = std::fs::read_to_string(crate_root().join("Cargo.toml"))
        .expect("this crate's own manifest is readable");
    let mut found: Vec<String> = Vec::new();
    for crate_name in &vocab.plane_crates {
        if manifest.contains(crate_name.as_str()) {
            found.push(crate_name.clone());
        }
    }
    for core in CORE_NAMES {
        if manifest.contains(core) {
            found.push((*core).to_string());
        }
    }
    found.extend(disallowed_busbar_dependency_keys(&manifest));
    assert!(
        found.is_empty(),
        "a transport may name the two contract crates and its sibling transports and nothing else \
         of busbar's; this manifest names: {found:?}"
    );
}

/// The scan is not vacuous: a planted name is found, in both spellings and in the manifest's shape.
#[test]
fn the_scan_would_catch_a_planted_name() {
    let vocab = load_vocab();

    assert!(contains_word(
        vocab.text("NEEDLE_1_HAYSTACK"),
        vocab.word("DIALECT_1")
    ));
    assert!(contains_word(
        vocab.text("NEEDLE_2_HAYSTACK"),
        vocab.word("DIALECT_1")
    ));
    assert!(contains_word(
        vocab.text("NEEDLE_3_HAYSTACK"),
        vocab.word("DIALECT_2")
    ));
    assert!(contains_word(
        vocab.text("NEEDLE_4_HAYSTACK"),
        vocab.word("DIALECT_4")
    ));
    assert!(contains_word(
        vocab.text("NEEDLE_5_HAYSTACK"),
        vocab.word("DIALECT_6")
    ));

    assert!(!contains_word(
        vocab.text("NEG_1_HAYSTACK"),
        vocab.word("DIALECT_4")
    ));
    assert!(!contains_word(
        vocab.text("NEG_2_HAYSTACK"),
        vocab.word("DIALECT_1")
    ));

    let planted = vocab.text("PLANE_LINE");
    assert!(vocab
        .plane_crates
        .iter()
        .any(|c| planted.contains(c.as_str())));
    let planted_core = "busbar-kernel = { path = \"../busbar-kernel\" }";
    assert!(CORE_NAMES.iter().any(|c| planted_core.contains(c)));
    // And the manifest allow-list: a foreign busbar key is found, the permitted ones are not.
    let planted_manifest = "[dependencies]\n# busbar-store-sqlite in a comment\nbusbar-contract = { workspace = true }\nbusbar-transport-tcp = { workspace = true }\n[dev-dependencies]\nbusbar-auth-oidc = { workspace = true }\n[dev-dependencies.busbar-auth-oidc]\nworkspace = true\n";
    assert_eq!(
        disallowed_busbar_dependency_keys(planted_manifest),
        vec![
            "busbar-auth-oidc".to_string(),
            "busbar-auth-oidc".to_string()
        ]
    );
    // And the one call a transport would make if it reached past the driver seam at all.
    let planted_call = "busbar_kernel::teller::run_unit(&kernel, units, &ctx, run)";
    assert!(CORE_NAMES.iter().any(|c| planted_call.contains(c)));
}
