// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The framings table: reached by token alone, never waited on, and a token that outlived its
//! framing reaches nothing.

use super::*;
use crate::door::engine::{Posture, Proto};

fn framing() -> Framing {
    let posture = Posture {
        keep_alive_interval: None,
        keep_alive_timeout: std::time::Duration::from_secs(10),
        adaptive_window: false,
        request_timeout: std::time::Duration::from_secs(30),
        max_body_bytes: 1024,
    };
    Framing::dial("http://127.0.0.1:9", Proto::H1, posture, 0).expect("dial")
}

/// Slots fill each segment in turn, every index in exactly one place.
#[test]
fn every_index_has_one_place() {
    let mut seen = std::collections::HashSet::new();
    let mut expect = (0, 0);
    for i in 0..BASE * ((1 << 6) - 1) {
        let p = place(i);
        assert_eq!(p, expect, "index {i}");
        assert!(seen.insert(p));
        expect = if expect.1 + 1 == BASE << expect.0 {
            (expect.0 + 1, 0)
        } else {
            (expect.0, expect.1 + 1)
        };
    }
}

/// A framing another op holds is answered at once (`Busy`), never waited for; once it is let go
/// the next op reaches it. Another framing is reached meanwhile: no lock is shared.
#[test]
fn a_held_framing_answers_busy_at_once() {
    let table = Framings::default();
    let a = table.insert(framing()).expect("a");
    let b = table.insert(framing()).expect("b");
    let held = table.reach(a).expect("reach a");
    std::thread::scope(|s| {
        s.spawn(|| {
            assert_eq!(table.reach(a).err(), Some(Reach::Busy));
            assert!(
                table.reach(b).is_ok(),
                "another framing is reached meanwhile"
            );
        });
    });
    drop(held);
    assert!(table.reach(a).is_ok());
}

/// A finished framing's token reaches nothing, even once its slot holds a new framing.
#[test]
fn a_token_that_outlived_its_framing_reaches_nothing() {
    let table = Framings::default();
    let a = table.insert(framing()).expect("a");
    table.remove(a).expect("remove");
    assert_eq!(table.reach(a).err(), Some(Reach::Gone));
    assert_eq!(table.remove(a).err(), Some(Reach::Gone));
    let b = table.insert(framing()).expect("b reuses the slot");
    assert_ne!(a, b);
    assert_eq!(untoken(a).map(|t| t.0), untoken(b).map(|t| t.0));
    assert_eq!(table.reach(a).err(), Some(Reach::Gone));
    assert!(table.reach(b).is_ok());
    assert_eq!(table.reach(0).err(), Some(Reach::Gone));
    assert_eq!(table.reach(u64::MAX).err(), Some(Reach::Gone));
}

/// RED (codeaudit concurrency M framings.rs:202): `finish` met a slot another op held (`cancel`'s
/// visit, say) and answered `Busy`, and nothing ever freed the slot. A removal waits for the op
/// holding it (ops answer in bounded CPU), then frees the framing and gives the slot back.
#[test]
fn a_removal_waits_for_the_op_holding_the_slot_and_frees_it() {
    let table = Framings::default();
    let a = table.insert(framing()).expect("a");
    let held = table.reach(a).expect("reach a");
    std::thread::scope(|s| {
        let removing = s.spawn(|| table.remove(a));
        std::thread::sleep(std::time::Duration::from_millis(20));
        drop(held);
        assert_eq!(removing.join().expect("join"), Ok(()), "the removal frees it");
    });
    assert_eq!(table.reach(a).err(), Some(Reach::Gone));
    let b = table.insert(framing()).expect("b");
    assert_eq!(
        untoken(a).map(|t| t.0),
        untoken(b).map(|t| t.0),
        "the slot was given back"
    );
}

/// RED (codeaudit concurrency/error-handling L framings.rs:173): an op that panicked holding a
/// slot poisoned it, and `finish` answered `no such framing` with the framing and the slot kept
/// for the instance's life. The framing is still not reached by any other op, but its removal frees
/// it, and the slot serves the next framing.
#[test]
fn a_poisoned_slot_is_still_freed_by_its_removal() {
    let table = Framings::default();
    let a = table.insert(framing()).expect("a");
    let _ = std::thread::scope(|s| {
        s.spawn(|| {
            let _held = table.reach(a).expect("reach a");
            panic!("an op panics holding its framing");
        })
        .join()
    });
    assert_eq!(table.reach(a).err(), Some(Reach::Gone), "not reached again");
    assert_eq!(table.remove(a), Ok(()), "its removal frees it");
    let b = table.insert(framing()).expect("b");
    assert_eq!(untoken(a).map(|t| t.0), untoken(b).map(|t| t.0));
    assert!(table.reach(b).is_ok(), "the slot serves the next framing");
}
