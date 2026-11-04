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
/// the next op reaches it.
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

/// Removing a framing waits for the operation holding its slot and then releases it.
#[test]
fn a_removal_waits_for_the_op_holding_the_slot_and_frees_it() {
    let table = Framings::default();
    let a = table.insert(framing()).expect("a");
    let held = table.reach(a).expect("reach a");
    std::thread::scope(|s| {
        let removing = s.spawn(|| table.remove(a));
        std::thread::sleep(std::time::Duration::from_millis(20));
        drop(held);
        assert_eq!(
            removing.join().expect("join"),
            Ok(()),
            "the removal frees it"
        );
    });
    assert_eq!(table.reach(a).err(), Some(Reach::Gone));
    let b = table.insert(framing()).expect("b");
    assert_eq!(
        untoken(a).map(|t| t.0),
        untoken(b).map(|t| t.0),
        "the slot was given back"
    );
}

/// Removing a poisoned slot still releases it.
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

/// Accelerate only the private table's generation to its final representable value. This does not
/// claim billions of real connection cycles; it proves the boundary where wrapping aliases.
#[test]
fn an_exhausted_slot_never_mints_a_generation_zero_alias() {
    let table = Framings::default();
    let original = table.insert(framing()).unwrap();
    let (index, _) = untoken(original).unwrap();
    table.reach(original).unwrap().generation = u32::MAX;
    let final_token = token(index, u32::MAX);
    assert!(table.reach(final_token).is_ok());
    table.remove(final_token).unwrap();
    let next = table.insert(framing()).unwrap();
    assert_ne!(untoken(next).unwrap().0, index, "exhausted slot is retired");
    assert_eq!(table.reach(original).err(), Some(Reach::Gone));
    assert_eq!(table.reach(final_token).err(), Some(Reach::Gone));
    assert_eq!(table.reach(token(index, 0)).err(), Some(Reach::Gone));
    assert!(table.reach(next).is_ok());
    table.remove(next).unwrap();
    let reused = table.insert(framing()).unwrap();
    assert_eq!(
        untoken(reused).unwrap().0,
        untoken(next).unwrap().0,
        "ordinary slots still recycle"
    );
    assert_ne!(reused, next);
}

struct CaptureDrop<'a> {
    table: &'a Framings,
    index: Option<u32>,
    dropped: &'a std::cell::Cell<bool>,
}

impl Drop for CaptureDrop<'_> {
    fn drop(&mut self) {
        assert!(
            self.table.free.try_lock().is_ok(),
            "reservation lock is released before prepared-state cleanup"
        );
        if let Some(index) = self.index {
            let (segment, at) = place(index as usize);
            assert!(
                self.table.segments[segment].get().unwrap()[at]
                    .0
                    .try_lock()
                    .is_ok(),
                "slot lock is released before prepared-state cleanup"
            );
        }
        self.dropped.set(true);
    }
}

#[test]
fn a_full_table_never_calls_the_boxing_factory_and_drops_its_capture_unlocked() {
    let table = Framings::default();
    table.free.lock().unwrap().next = (BASE * ((1 << SEGMENTS) - 1)) as u32;
    let dropped = std::cell::Cell::new(false);
    let capture = CaptureDrop {
        table: &table,
        index: None,
        dropped: &dropped,
    };
    let prepared = framing();
    assert!(table
        .insert_with(move || {
            let _capture = capture;
            drop(prepared);
            panic!("a full table must not invoke the owning-allocation factory")
        })
        .is_none());
    assert!(
        dropped.get(),
        "the rejected factory releases its prepared state"
    );
    assert!(
        table.segments.iter().all(|segment| segment.get().is_none()),
        "NoRoom creates no segment"
    );
}

#[test]
fn a_generation_failure_never_calls_the_boxing_factory_and_cleans_up_after_unlock() {
    let table = Framings::default();
    let original = table.insert(framing()).unwrap();
    let (index, _) = untoken(original).unwrap();
    table.remove(original).unwrap();
    let (segment, at) = place(index as usize);
    table.segments[segment].get().unwrap()[at]
        .0
        .lock()
        .unwrap()
        .generation = u32::MAX;
    let dropped = std::cell::Cell::new(false);
    let capture = CaptureDrop {
        table: &table,
        index: Some(index),
        dropped: &dropped,
    };
    let prepared = framing();
    assert!(table
        .insert_with(move || {
            let _capture = capture;
            drop(prepared);
            panic!("an exhausted generation must not invoke the owning-allocation factory")
        })
        .is_none());
    assert!(
        dropped.get(),
        "generation failure releases the captured prepared state"
    );
    assert_eq!(table.reach(token(index, 0)).err(), Some(Reach::Gone));
    let next = table.insert(framing()).unwrap();
    assert_ne!(
        untoken(next).unwrap().0,
        index,
        "the exhausted reservation stays retired"
    );
    assert!(table.reach(next).is_ok());
}

#[test]
fn the_boxing_factory_runs_under_the_reserved_slot_after_releasing_the_free_list() {
    let table = Framings::default();
    let prepared = framing();
    let held = table
        .insert_with(|| {
            assert!(table.free.try_lock().is_ok());
            let segment = table.segments[0]
                .get()
                .expect("the reserved slot's segment exists");
            assert!(matches!(
                segment[0].0.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            ));
            Held::Dial(Box::new(prepared))
        })
        .unwrap();
    assert!(matches!(table.reach(held).unwrap().held(), Held::Dial(_)));
    table.remove(held).unwrap();
    let accepted = Accepted::accept(0, std::sync::Arc::from([]));
    let held = table
        .insert_with(|| Held::Accept(Box::new(accepted)))
        .unwrap();
    assert!(matches!(table.reach(held).unwrap().held(), Held::Accept(_)));
    table.remove(held).unwrap();
}

impl Framings {
    /// Hold the dialled `framing`, answering its token, or `None` when every slot is in use.
    pub(in crate::door) fn insert(&self, framing: Framing) -> Option<u64> {
        self.insert_with(|| Held::Dial(Box::new(framing)))
    }
}
