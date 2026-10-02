// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE `http` DOOR, BOTH WAYS IN**: the linked door (`busbar_transport_http::door::door`) and this
//! crate's built cdylib (the same door behind the one `export_door!`), each admitted through the
//! loader's ONE door validation and driven through the ONE dispatcher's crossing, give the same
//! Statement and the same wire bytes for one request. Run against the busbar rev this repo pins
//! (`.busbar-ref`).
//!
//! THE RED ARMS, same file: the door asked for as another kind is refused, linked (by the door's
//! own kind) and dropped in (by the stated kind, before `dlopen`). A missing cdylib PANICS: this
//! test IS the dropped-in door's proof, and never skips.

use std::mem::{size_of, zeroed};
use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Field, Outcome, BLOB_ABSENT};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::transport::{
    slot, BeginIn, ConnFacts, EncodeIn, FramePiece, FramerOut, FramerSink, SIDE_DIAL,
};
use busbar_plugin_loader::dispatch::kinds::hook::Hook;
use busbar_plugin_loader::dispatch::kinds::transport::Transport;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, load_linked, out_head, Bind, DispatchConfig, Dispatcher, Frame,
    LinkedRow, LoadError, NoSink, Plugin,
};

fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { zeroed() }
}

fn s(text: &str) -> AbiStr {
    AbiStr {
        ptr: text.as_ptr(),
        len: text.len(),
    }
}

/// This crate's built cdylib (uplifted or under `deps`, newest wins). A missing artifact is a
/// failure, never a skip.
fn cdylib() -> std::path::PathBuf {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let file = busbar_plugin_loader::plugin_library_filename("busbar_transport_http_plugin");
    [profile.join(&file), profile.join("deps").join(&file)]
        .into_iter()
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p)
        .unwrap_or_else(|| panic!("the busbar-transport-http-plugin cdylib ({file}) is not built"))
}

/// The row a compiled-in build holds for this door.
fn row() -> LinkedRow {
    LinkedRow::of(busbar_transport_http::door::door).expect("the door states itself")
}

fn bind(d: &Dispatcher) -> Bind {
    Bind {
        instance: Arc::from("the-instance"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: None,
    }
}

fn open(p: &Plugin<Transport>) {
    let mut i: OpenIn = z();
    i.head = in_head();
    i.settings = Blob {
        ptr: std::ptr::null(),
        len: 0,
        fmt: BLOB_ABSENT,
        flags: 0,
    };
    let mut o: OpenOut = z();
    o.head = out_head();
    let mut f = Frame::new(i, o);
    assert_eq!(p.call(life::OPEN, &mut f).outcome, Outcome::Ready);
}

/// One scripted exchange through the dispatcher: begin a dialled http/1.1 connection, encode one
/// request. What comes back is the wire bytes the door rendered.
fn script(p: &Plugin<Transport>) -> Vec<u8> {
    let mut wire = vec![0_u8; 8192];
    let mut frame = vec![0_u8; 8192];
    let mut pieces: Vec<FramePiece> = vec![z(); 8];
    let sink = || FramerSink {
        wire: wire.as_ptr().cast_mut(),
        wire_cap: wire.len(),
        frame: frame.as_ptr().cast_mut(),
        frame_cap: frame.len(),
        pieces: pieces.as_ptr().cast_mut(),
        pieces_cap: pieces.len(),
        now_monotonic_ns: 1,
        now_unix_ns: 1,
        heads: std::ptr::null_mut(),
        heads_cap: 0,
    };
    let mut facts: ConnFacts = z();
    facts.size = size_of::<ConnFacts>() as u32;
    facts.agreed_protocol = s("http/1.1");
    let mut i: BeginIn = z();
    i.head = in_head();
    i.side = SIDE_DIAL;
    i.target = s("http://127.0.0.1:40123");
    i.facts = &facts;
    i.sink = sink();
    let mut o: FramerOut = z();
    o.head = out_head();
    let mut f = Frame::new(i, o);
    assert_eq!(p.call(slot::BEGIN, &mut f).outcome, Outcome::Ready);

    let fields = [
        Field {
            name: s("method"),
            value: s("POST"),
        },
        Field {
            name: s("path"),
            value: s("/v1/chat"),
        },
        Field {
            name: s("content-type"),
            value: s("application/json"),
        },
    ];
    let body = b"{\"a\":1}";
    let mut e: EncodeIn = z();
    e.head = in_head();
    e.fields = fields.as_ptr();
    e.fields_len = fields.len();
    e.body = body.as_ptr();
    e.body_len = body.len();
    e.sink = sink();
    let mut eo: FramerOut = z();
    eo.head = out_head();
    let mut f = Frame::new(e, eo);
    assert_eq!(p.call(slot::ENCODE, &mut f).outcome, Outcome::Ready);
    wire[..f.out.yielded.wire_len as usize].to_vec()
}

#[test]
fn the_linked_and_the_dropped_in_door_are_one_framer() {
    let d = Dispatcher::new(DispatchConfig::default());
    let linked: Plugin<Transport> = load_linked(&row(), bind(&d)).expect("the linked door loads");
    let dropped: Plugin<Transport> =
        load_dropped(&cdylib(), &row().statement, bind(&d)).expect("the dropped-in door loads");
    assert_eq!(linked.name(), busbar_transport_http::linked::KEY);
    assert_eq!(dropped.name(), linked.name());
    open(&linked);
    open(&dropped);

    let a = script(&linked);
    let b = script(&dropped);
    let text = String::from_utf8_lossy(&a);
    assert!(
        text.starts_with("POST /v1/chat HTTP/1.1\r\n"),
        "the door rendered a request: {text:?}"
    );
    assert!(a.ends_with(b"{\"a\":1}"), "the body rides the message");
    assert_eq!(a, b, "both doors write the same bytes");
}

#[test]
fn the_door_asked_for_as_another_kind_is_refused_both_ways() {
    let d = Dispatcher::new(DispatchConfig::default());
    let want = (KindCode::Transport, KindCode::Hook);
    match load_linked::<Hook>(&row(), bind(&d)) {
        Err(LoadError::WrongKind { door, want: asked }) => assert_eq!((door, asked), want),
        other => panic!("the linked door loaded as a hook: {:?}", other.err()),
    }
    match load_dropped::<Hook>(&cdylib(), &row().statement, bind(&d)) {
        Err(LoadError::ManifestKind {
            stated,
            want: asked,
        }) => assert_eq!((stated, asked), want),
        other => panic!("the dropped-in door loaded as a hook: {:?}", other.err()),
    }
}
