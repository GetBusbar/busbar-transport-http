// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FRAMER'S OWN HEAD LINES, STATED BEFORE THE AUTH SIGNS (THE DESIGN §6 "Auth points and
//! guest lists", item 5: the transport finalises the head, then the auth runs, and "nothing is
//! added to the head after the auth has run, so what a signing style signed is what is sent").
//!
//! `locate` answers the lines this framer's wire adds to a request that does not state them
//! (`LocateIn::defaults_buf`), so the host puts them in the head BEFORE the auth signs it: 1.5.5's
//! client defaults in 1.5.5's order, `accept: */*` then `host`, the host as 1.5.5's URL parser
//! wrote it (lower case, the scheme's own port dropped, an IPv4 spelling as the address it names).
//! Driven through the door's table, as the host drives it.

use std::mem::{size_of, zeroed};

use busbar_contract::abi::mechanism::call::{AbiStr, Blob, InHead, Op, OutHead, Outcome};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::transport::{slot, LocateIn, LocateOut, Ops};

fn z<T>() -> T {
    // SAFETY: plain C data; all-zero is valid.
    unsafe { zeroed() }
}

fn call<I, O>(
    op: Option<Op>,
    inst: *mut std::ffi::c_void,
    i: &mut I,
    o: &mut O,
    index: u32,
) -> Outcome {
    // SAFETY: `I`/`O` lead with their heads.
    unsafe {
        let ih = std::ptr::from_mut(i).cast::<InHead>();
        (*ih).size = size_of::<I>() as u32;
        (*ih).op = index;
        (*std::ptr::from_mut(o).cast::<OutHead>()).size = size_of::<O>() as u32;
    }
    // SAFETY: the slot is the door's own, called with the `in` and `out` built above.
    #[allow(unused_unsafe)]
    let raw = unsafe {
        (op.expect("slot"))(
            inst,
            std::ptr::from_ref(i).cast(),
            std::ptr::from_mut(o).cast(),
        )
    };
    raw.outcome()
}

/// The lines `locate` states for `target`, as the host reads them off its buffer.
fn head_lines(target: &str) -> String {
    // SAFETY: `door()` answers the `'static` door of this crate.
    #[allow(unused_unsafe)]
    let d = unsafe { busbar_transport_http::door() };
    // SAFETY: the door's `'static` table.
    let ops: &Ops = unsafe { &*(*d).ops.cast::<Ops>() };
    let settings = "{}";
    let mut i: OpenIn = z();
    i.settings = Blob::json(settings.as_bytes());
    let mut o: OpenOut = z();
    assert_eq!(
        call(
            ops.head.open,
            std::ptr::null_mut(),
            &mut i,
            &mut o,
            life::OPEN
        ),
        Outcome::Ready
    );
    let inst = o.instance;
    let (mut authority, mut name, mut alpn, mut defaults) = (
        vec![0_u8; 256],
        vec![0_u8; 256],
        vec![0_u8; 256],
        vec![0_u8; 256],
    );
    let mut l: LocateIn = z();
    // SAFETY: `target` is the test's own text, live for every call it is passed to.
    l.target = unsafe { AbiStr::from_raw_parts(target.as_ptr(), target.len()) };
    l.authority_buf = authority.as_mut_ptr();
    l.authority_cap = authority.len();
    l.name_buf = name.as_mut_ptr();
    l.name_cap = name.len();
    l.alpn_buf = alpn.as_mut_ptr();
    l.alpn_cap = alpn.len();
    l.defaults_buf = defaults.as_mut_ptr();
    l.defaults_cap = defaults.len();
    let mut lo: LocateOut = z();
    assert_eq!(
        call(ops.locate, inst, &mut l, &mut lo, slot::LOCATE),
        Outcome::Ready,
        "{target}"
    );
    let mut c: InHead = z();
    let mut co: OutHead = z();
    call(ops.head.close, inst, &mut c, &mut co, life::CLOSE);
    String::from_utf8_lossy(&defaults[..lo.defaults_written as usize]).into_owned()
}

/// RED (Q row 159 transport-http MEDIUM 3): `locate` states `accept` and `host`, so the auth signs
/// the head that is sent. RED on the `locate` that stated no line and added both at `emit`, after
/// the auth had run.
#[test]
fn locate_states_the_framers_own_head_lines_before_the_auth_signs() {
    for (target, host) in [
        ("https://api.example.com/v1/messages", "api.example.com"),
        ("https://API.Example.com:443/v1", "api.example.com"),
        ("http://Example.COM:80/x", "example.com"),
        ("https://api.example.com:8443/v1", "api.example.com:8443"),
        ("http://127.1:8080/", "127.0.0.1:8080"),
        ("http://localhost:9", "localhost:9"),
    ] {
        assert_eq!(
            head_lines(target),
            format!("accept: */*\r\nhost: {host}\r\n"),
            "{target}"
        );
    }
}
