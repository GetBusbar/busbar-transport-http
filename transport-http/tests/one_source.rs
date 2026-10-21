// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! EACH FACT IS STATED ONCE (`BUSBAR-1.6.0.md` §2, "One Statement", l.236: "Each fact is declared
//! once; anything derivable is derived"): the door's status classes are read off the status rows it
//! states, as its fault reading is read off its fault rows, and the defaults its settings reader
//! applies are the ones its setting declarations state, never a second copy. (The declarations
//! agree with the host's own defaults: a unit test ties them.) RED before the fix: `class_of`
//! restated the classes as a hand-written match, and the reader applied the contract's constants
//! beside the declarations' own default strings.

#[test]
fn the_door_states_its_classes_and_defaults_once() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/door/mod.rs");
    let text = std::fs::read_to_string(&path).expect("the door's source");
    for restated in [
        "200..=299 =>",
        "400..=499 =>",
        "500..=599 =>",
        "DEFAULT_REQUEST_TIMEOUT_SECS)",
        "DEFAULT_REQUEST_BODY_MAX_BYTES as u64",
    ] {
        assert!(
            !text.contains(restated),
            "{}: `{restated}` restates a fact the door states elsewhere",
            path.display()
        );
    }
}
