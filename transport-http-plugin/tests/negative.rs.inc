// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Malformed metadata and readiness inputs derived from the actual product door.
use super::{bind, cdylib, row};
use busbar_contract::abi::mechanism::call::{AbiStr, OutHead, Outcome, RawOutcome};
use busbar_contract::abi::mechanism::door::{Door, DoorParts, KindTailHead, Statement};
use busbar_contract::abi::mechanism::rendering::{self, RENDERING_MAGIC};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::transport::{FramePiece, TransportTail};
use busbar_plugin_loader::dispatch::kinds::{
    auth::Auth, export::Export, hook::Hook, plane::Plane, secret::Secret, store::Store,
    transport::Transport,
};
use busbar_plugin_loader::dispatch::{
    load_dropped, load_linked, Dispatcher, Kind, LinkedRow, LoadError,
};
use std::sync::{
    atomic::{AtomicPtr, AtomicU64, Ordering},
    Mutex,
};
static SERIAL: Mutex<()> = Mutex::new(());
static CHANGED: AtomicPtr<Door> = AtomicPtr::new(std::ptr::null_mut());
static READY_CALLS: AtomicU64 = AtomicU64::new(0);
extern "C" fn changed_door() -> *const Door {
    CHANGED.load(Ordering::SeqCst)
}
fn actual() -> DoorParts {
    // SAFETY: the actual product exports a valid immutable static door.
    let parts = unsafe { Door::read_parts((row().door)()) };
    DoorParts {
        size: std::mem::size_of::<Door>() as u32,
        ..parts
    }
}
fn change(parts: DoorParts) {
    // SAFETY: only immutable metadata or the narrow failing-ready callback changes; the real
    // product's complete ABI operation table remains live for the process lifetime.
    let door = unsafe { Door::__from_parts(parts) };
    CHANGED.store(Box::into_raw(Box::new(door)), Ordering::SeqCst);
}
fn assert_rebuild(error: &LoadError) {
    assert!(
        error
            .to_string()
            .contains("rebuild against this busbar-contract"),
        "{error}"
    );
}
#[test]
fn red_a_door_at_another_kind_abi_is_refused() {
    let _guard = SERIAL.lock().unwrap();
    let real = actual();
    let host = KindCode::Transport.abi_version();
    assert_eq!(real.kind_abi, host);
    let d = Dispatcher::new(Default::default());
    for abi in [host + 1, host.wrapping_sub(1)] {
        change(DoorParts {
            kind_abi: abi,
            ..real
        });
        let want = LoadError::KindAbi {
            kind: KindCode::Transport,
            door: abi,
            host,
        };
        let e = busbar_plugin_loader::dispatch::load::rendering_of_raw(changed_door).unwrap_err();
        assert_eq!(e, want);
        assert!(e.to_string().contains("rebuild"));
        let e = LinkedRow::of_raw(changed_door)
            .and_then(|r| load_linked::<Transport>(&r, bind(&d)).map(|_| ()))
            .unwrap_err();
        assert_eq!(e, want);
        let mut stated = row().statement;
        let at = RENDERING_MAGIC.len() + 8;
        stated[at..at + 4].copy_from_slice(&abi.to_le_bytes());
        let e = load_dropped::<Transport>(&cdylib(), &stated, bind(&d))
            .err()
            .unwrap();
        assert_eq!(e, LoadError::ManifestKindAbi { stated: abi, host });
    }
}
#[test]
fn red_a_door_built_against_another_kind_layout_is_refused() {
    let _guard = SERIAL.lock().unwrap();
    let real = actual();
    let kind = KindCode::Transport;
    let host = kind.layout_fingerprint();
    assert_eq!(real.layout, host);
    let d = Dispatcher::new(Default::default());
    for stated in [host ^ 1, 0] {
        change(DoorParts {
            layout: stated,
            ..real
        });
        let refused =
            busbar_plugin_loader::dispatch::load::rendering_of_raw(changed_door).unwrap_err();
        let LoadError::KindLayout {
            kind: named,
            stated: said,
            host: read,
            ..
        } = &refused
        else {
            panic!("{refused:?}")
        };
        assert_eq!((*named, *said, *read), (kind, stated, host));
        assert_rebuild(&refused);
        let honest = LinkedRow {
            statement: row().statement,
            door: changed_door,
        };
        assert_eq!(
            load_linked::<Transport>(&honest, bind(&d)).err(),
            Some(refused.clone())
        );
        assert_eq!(
            LinkedRow::of_raw(changed_door)
                .and_then(|r| load_linked::<Transport>(&r, bind(&d)).map(|_| ()))
                .err(),
            Some(refused)
        );
    }
}
#[test]
fn red_a_transport_built_against_another_frame_piece_is_refused() {
    let _guard = SERIAL.lock().unwrap();
    let real = actual();
    let d = Dispatcher::new(Default::default());
    // SAFETY: the loaded real transport provides a complete static Statement and TransportTail.
    let st = unsafe { real.statement.read_unaligned() };
    let tail = unsafe { st.kind_tail.cast::<TransportTail>().read_unaligned() };
    let host = std::mem::size_of::<FramePiece>() as u32;
    let stated = host - 8;
    let tail = Box::leak(Box::new(TransportTail {
        frame_piece_size: stated,
        ..tail
    }));
    let st = Box::leak(Box::new(Statement {
        kind_tail: std::ptr::from_ref(tail).cast::<KindTailHead>(),
        ..st
    }));
    change(DoorParts {
        statement: st,
        ..real
    });
    let refused = busbar_plugin_loader::dispatch::load::rendering_of_raw(changed_door).unwrap_err();
    let LoadError::FramePieceSize {
        stated: said,
        host: read,
        ..
    } = &refused
    else {
        panic!("{refused:?}")
    };
    assert_eq!((*said, *read), (stated, host));
    assert_rebuild(&refused);
    assert_eq!(
        LinkedRow::of_raw(changed_door)
            .and_then(|r| load_linked::<Transport>(&r, bind(&d)).map(|_| ()))
            .err(),
        Some(refused)
    );
}
#[test]
fn red_a_statement_other_than_the_stated_one_is_refused() {
    let _guard = SERIAL.lock().unwrap();
    let real = actual();
    let d = Dispatcher::new(Default::default());
    // SAFETY: the genuine door's complete immutable static statement was validated above.
    let st = unsafe { real.statement.read_unaligned() };
    let st = Box::leak(Box::new(Statement {
        version: AbiStr::of("0.0.0-conformance-restated"),
        ..st
    }));
    change(DoorParts {
        statement: st,
        ..real
    });
    let lying = busbar_plugin_loader::dispatch::load::rendering_of_raw(changed_door).unwrap();
    rendering::read(&lying).unwrap();
    assert_ne!(lying, row().statement);
    let mismatched = LinkedRow {
        statement: lying.clone(),
        door: row().door,
    };
    assert_eq!(
        load_linked::<Transport>(&mismatched, bind(&d)).err(),
        Some(LoadError::StatementMismatch)
    );
    assert_eq!(
        load_dropped::<Transport>(&cdylib(), &lying, bind(&d)).err(),
        Some(LoadError::StatementMismatch)
    );
    let mismatched = LinkedRow {
        statement: row().statement,
        door: changed_door,
    };
    assert_eq!(
        load_linked::<Transport>(&mismatched, bind(&d)).err(),
        Some(LoadError::StatementMismatch)
    );
}
extern "C" fn fail_ready(
    _: *mut std::ffi::c_void,
    _: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> RawOutcome {
    READY_CALLS.fetch_add(1, Ordering::SeqCst);
    let raw = RawOutcome::of(Outcome::Failed);
    // SAFETY: READY receives the host's exclusive complete OutHead.
    unsafe {
        let head = &mut *out.cast::<OutHead>();
        head.outcome = raw;
        head.error = AbiStr::of("conformance: discovery refused");
    }
    raw
}
#[test]
fn red_a_failing_ready_refuses_the_boot() {
    let _guard = SERIAL.lock().unwrap();
    READY_CALLS.store(0, Ordering::SeqCst);
    change(DoorParts {
        ready: Some(fail_ready),
        ..actual()
    });
    let d = Dispatcher::new(Default::default());
    let r = LinkedRow::of_raw(changed_door).unwrap();
    let p = load_linked::<Transport>(&r, bind(&d)).unwrap();
    assert!(p.has_ready());
    super::open(&p);
    let before = p.inner.crossings.load(Ordering::SeqCst) - p.inner.resumes.load(Ordering::SeqCst);
    assert_eq!(
        p.ready(&d, std::time::Duration::from_secs(30)).unwrap_err(),
        format!(
            "plugin '{}' ready failed: conformance: discovery refused",
            p.name()
        )
    );
    assert_eq!(
        p.inner.crossings.load(Ordering::SeqCst) - p.inner.resumes.load(Ordering::SeqCst) - before,
        1
    );
    assert_eq!(READY_CALLS.load(Ordering::SeqCst), 1);
}
fn wrong_kind<K: Kind>(want: KindCode) {
    let d = Dispatcher::new(Default::default());
    assert_eq!(
        load_linked::<K>(&row(), bind(&d)).err(),
        Some(LoadError::ManifestKind {
            stated: KindCode::Transport,
            want
        })
    );
    assert_eq!(
        load_dropped::<K>(&cdylib(), &row().statement, bind(&d)).err(),
        Some(LoadError::ManifestKind {
            stated: KindCode::Transport,
            want
        })
    );
}
#[test]
fn red_a_door_asked_for_as_another_kind_is_refused() {
    wrong_kind::<Auth>(KindCode::Auth);
    wrong_kind::<Export>(KindCode::Export);
    wrong_kind::<Hook>(KindCode::Hook);
    wrong_kind::<Plane>(KindCode::Plane);
    wrong_kind::<Secret>(KindCode::Secret);
    wrong_kind::<Store>(KindCode::Store);
}
#[test]
fn the_declared_needs_are_the_statements() {
    let r = row();
    let read = rendering::read(&r.statement).unwrap();
    assert!(read.needs.is_empty());
    let declares: serde_json::Value =
        serde_json::from_str(include_str!("../../transport-http/declares.json")).unwrap();
    assert!(
        declares.get("needs").is_none() || declares["needs"].as_array().is_some_and(Vec::is_empty)
    );
}

#[test]
fn no_outbound_auth_family_is_driven() {
    let r = row();
    let read = rendering::read(&r.statement).unwrap();
    assert_eq!(read.kind, KindCode::Transport);
    let inputs: serde_json::Value = serde_json::from_str(include_str!("conformance.json")).unwrap();
    assert!(inputs["auth"]["outbound"].is_null());
}
