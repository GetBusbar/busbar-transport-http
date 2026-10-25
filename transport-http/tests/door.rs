// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `http` framer, driven through its own table the way the host drives it: the lifecycle's
//! settings texts, `refresh`, the role stubs, the missing instance, and what a failure text may
//! repeat of a target. (An integration test, so the crate itself stays `#![forbid(unsafe_code)]`:
//! driving a raw table is the host's side, and needs it.)

use std::ffi::c_void;
use std::mem::{size_of, zeroed};

use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, InHead, Op, OutHead, Outcome, BLOB_ABSENT, BLOB_JSON,
};
use busbar_contract::abi::mechanism::door::Door;
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, OpenIn, OpenOut, RefreshIn, ValidateIn,
};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::transport::{
    slot, AcceptIn, AcceptOut, AdoptIn, ArrivalIn, ArrivalOut, BeginIn, ConnIn, ConnOut, DialIn,
    EmitIn, FinishIn, FramerOut, FramingIn, IngestIn, IoOut, ListenIn, ListenOut, LocateIn,
    LocateOut, Ops, ReadIn, RefuseIn, ShutIn, WriteIn, SIDE_DIAL,
};
use busbar_transport_http::door;

fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { zeroed() }
}

fn s(t: &str) -> AbiStr {
    // SAFETY: `t` is the test's own text, live for every call it is passed to.
    unsafe { AbiStr::from_raw_parts(t.as_ptr(), t.len()) }
}

fn text(t: AbiStr) -> String {
    if t.len == 0 {
        return String::new();
    }
    // SAFETY: the framer's string, live for the call.
    String::from_utf8(unsafe { t.bytes() }.to_vec()).unwrap()
}

fn settings(json: &str) -> Blob {
    Blob {
        ptr: json.as_ptr(),
        len: json.len(),
        flags: 0,
        fmt: if json.is_empty() {
            BLOB_ABSENT
        } else {
            BLOB_JSON
        },
    }
}

fn ops() -> &'static Ops {
    // SAFETY: `door()` answers the `'static` door of this crate.
    #[allow(unused_unsafe)]
    let d: *const Door = unsafe { door::door() };
    // SAFETY: the door answers a `'static` door whose table is this kind's `Ops`.
    unsafe { &*(*d).ops.cast::<Ops>() }
}

fn call<I, O>(op: Option<Op>, inst: *mut c_void, i: &mut I, o: &mut O, index: u32) -> Outcome {
    // SAFETY: `I` leads with an `InHead`, `O` with an `OutHead` (the table's own structs).
    unsafe {
        let ih = std::ptr::from_mut(i).cast::<InHead>();
        (*ih).size = size_of::<I>() as u32;
        (*ih).op = index;
        (*ih).ticket = Ticket {
            slot: 1,
            generation: 1,
        };
        let oh = std::ptr::from_mut(o).cast::<OutHead>();
        (*oh).size = size_of::<O>() as u32;
    }
    // SAFETY: the slot is the door's own, called with the `in` and `out` built above.
    #[allow(unused_unsafe)]
    unsafe {
        (op.expect("every slot is filled"))(
            inst,
            std::ptr::from_ref(i).cast(),
            std::ptr::from_mut(o).cast(),
        )
    }
    .outcome()
}

/// An open instance over `json`.
fn open(json: &str) -> *mut c_void {
    let mut i: OpenIn = z();
    i.settings = settings(json);
    let mut o: OpenOut = z();
    let r = call(
        ops().head.open,
        std::ptr::null_mut(),
        &mut i,
        &mut o,
        life::OPEN,
    );
    assert_eq!(r, Outcome::Ready);
    o.instance
}

/// `validate` over `json`: its outcome and the text it wrote into the lent reason buffer.
fn validate(json: &str) -> (Outcome, String) {
    let mut reason = [0_u8; 256];
    let mut i: ValidateIn = z();
    i.settings = settings(json);
    i.err_buf = reason.as_mut_ptr();
    i.err_cap = reason.len();
    let mut o: OutHead = z();
    let r = call(
        ops().head.validate,
        std::ptr::null_mut(),
        &mut i,
        &mut o,
        life::VALIDATE,
    );
    (r, text(o.error))
}

/// `refresh` of `inst` to `json`: its outcome and its text.
fn refresh(inst: *mut c_void, json: &str) -> (Outcome, String) {
    let mut i: RefreshIn = z();
    i.generation = 2;
    i.settings = settings(json);
    let mut o: OutHead = z();
    let r = call(ops().head.refresh, inst, &mut i, &mut o, life::REFRESH);
    (r, text(o.error))
}

/// `locate` of `target`: its outcome, the protocol offer it answered and its text.
fn locate(inst: *mut c_void, target: &str) -> (Outcome, Vec<u8>, String) {
    let (mut a, mut n, mut l) = ([0_u8; 256], [0_u8; 256], [0_u8; 64]);
    let mut i: LocateIn = z();
    i.target = s(target);
    (i.authority_buf, i.authority_cap) = (a.as_mut_ptr(), a.len());
    (i.name_buf, i.name_cap) = (n.as_mut_ptr(), n.len());
    (i.alpn_buf, i.alpn_cap) = (l.as_mut_ptr(), l.len());
    let mut o: LocateOut = z();
    let r = call(ops().locate, inst, &mut i, &mut o, slot::LOCATE);
    (r, l[..o.alpn_written as usize].to_vec(), text(o.head.error))
}

// ── refresh ──────────────────────────────────────────────────────────────────────────────────────

/// RED: `refresh` answered READY and kept the settings `open` read, whatever the new blob said.
/// A refresh reads the new settings with `validate`'s texts: a bad blob is FAILED and the old
/// settings stay; a good one applies to what is begun after it (here the cleartext offer, which
/// the prior-knowledge key sets).
#[test]
fn refresh_reads_the_new_settings_and_keeps_the_old_on_a_bad_blob() {
    let inst = open("");
    assert_eq!(locate(inst, "http://a.test/").1, b"");
    assert_eq!(
        refresh(inst, r#"{"advanced.upstream_http1_only":"yes"}"#),
        (
            Outcome::Failed,
            "settings: advanced.upstream_http1_only must be true or false".to_owned()
        )
    );
    assert_eq!(
        refresh(inst, r#"{"limits.request_body_max_bytes":0}"#),
        (
            Outcome::Failed,
            "settings: limits.request_body_max_bytes must be a count of bytes above 0".to_owned()
        )
    );
    assert_eq!(
        locate(inst, "http://a.test/").1,
        b"",
        "the old settings stay"
    );
    assert_eq!(
        refresh(inst, r#"{"advanced.upstream_h2_prior_knowledge":true}"#),
        (Outcome::Ready, String::new())
    );
    assert_eq!(locate(inst, "http://a.test/").1, b"\x02h2");
}

// ── settings, through the door ───────────────────────────────────────────────────────────────────

/// RED: `validate` refused a bad blob as `settings: not JSON`, a wrong kind as `<key>: not of its
/// declared kind`, and read past an undeclared key. Each is now the canon's text.
#[test]
fn validate_answers_the_canon_settings_texts() {
    assert_eq!(validate(""), (Outcome::Ready, String::new()));
    assert_eq!(
        validate("["),
        (
            Outcome::Failed,
            "settings: must be a JSON object".to_owned()
        )
    );
    assert_eq!(
        validate(r#"{"limits.nope":1}"#),
        (
            Outcome::Failed,
            "settings: limits.nope is not a setting this transport reads".to_owned()
        )
    );
    assert_eq!(
        validate(r#"{"limits.upstream_request_timeout_secs":0}"#),
        (
            Outcome::Failed,
            "settings: limits.upstream_request_timeout_secs must be a count of seconds above 0"
                .to_owned()
        )
    );
}

// ── the role stubs and the missing instance ──────────────────────────────────────────────────────

/// One op of `inst` over all-zero `in` and `out`: its outcome and its text.
fn op<I, O>(f: Option<Op>, inst: *mut c_void, index: u32) -> (Outcome, String) {
    let mut i: I = z();
    let mut o: O = z();
    let r = call(f, inst, &mut i, &mut o, index);
    // SAFETY: every `out` leads with an `OutHead`.
    let head = unsafe { std::ptr::from_ref(&o).cast::<OutHead>().read() };
    (r, text(head.error))
}

/// RED: every op of the role this framer does not play answered a bare REFUSED, with no words.
/// Each is now REFUSED in the canon's words, naming the op.
#[test]
fn every_op_of_the_carrier_role_and_each_unserved_framer_op_is_refused_in_words() {
    let inst = open("");
    let o = ops();
    let refused = |op: &str| {
        (
            Outcome::Refused,
            format!("{op}: the http framer does not serve this op"),
        )
    };
    assert_eq!(
        op::<ListenIn, ListenOut>(o.listen, inst, slot::LISTEN),
        refused("listen")
    );
    assert_eq!(
        op::<AcceptIn, AcceptOut>(o.accept, inst, slot::ACCEPT),
        refused("accept")
    );
    assert_eq!(
        op::<DialIn, ConnOut>(o.dial, inst, slot::DIAL),
        refused("dial")
    );
    assert_eq!(
        op::<ReadIn, IoOut>(o.read, inst, slot::READ),
        refused("read")
    );
    assert_eq!(
        op::<WriteIn, IoOut>(o.write, inst, slot::WRITE),
        refused("write")
    );
    assert_eq!(
        op::<ConnIn, OutHead>(o.flush, inst, slot::FLUSH),
        refused("flush")
    );
    assert_eq!(
        op::<ShutIn, OutHead>(o.shut, inst, slot::SHUT),
        refused("shut")
    );
    assert_eq!(
        op::<ArrivalIn, ArrivalOut>(o.arrival, inst, slot::ARRIVAL),
        refused("arrival")
    );
    assert_eq!(
        op::<RefuseIn, FramerOut>(o.refuse, inst, slot::REFUSE),
        refused("refuse")
    );
    assert_eq!(
        op::<FramingIn, FramerOut>(o.detach, inst, slot::DETACH),
        refused("detach")
    );
    assert_eq!(
        op::<AdoptIn, FramerOut>(o.adopt, inst, slot::ADOPT),
        refused("adopt")
    );
}

/// RED: `begin` with no open instance answered a bare FAILED, and `ingest`, `emit`, `timer` and
/// `finish` answered `no such framing` with no op named. Each is now `<op>: no open instance`.
#[test]
fn a_framer_op_with_no_open_instance_is_failed_in_words() {
    let none = std::ptr::null_mut();
    let o = ops();
    let failed = |op: &str| (Outcome::Failed, format!("{op}: no open instance"));
    let mut i: BeginIn = z();
    i.side = SIDE_DIAL;
    i.target = s("http://a.test/");
    let mut out: FramerOut = z();
    let r = call(o.begin, none, &mut i, &mut out, slot::BEGIN);
    assert_eq!((r, text(out.head.error)), failed("begin"));
    assert_eq!(
        op::<IngestIn, FramerOut>(o.ingest, none, slot::INGEST),
        failed("ingest")
    );
    assert_eq!(
        op::<EmitIn, FramerOut>(o.emit, none, slot::EMIT),
        failed("emit")
    );
    assert_eq!(
        op::<FramingIn, FramerOut>(o.timer, none, slot::TIMER),
        failed("timer")
    );
    assert_eq!(
        op::<FinishIn, FramerOut>(o.finish, none, slot::FINISH),
        failed("finish")
    );
}

/// RED: an op on a framing the instance does not hold answered `no such framing`, naming no op.
/// Every kind-op text now leads with its op.
#[test]
fn a_framer_op_on_an_unknown_framing_names_its_op() {
    let inst = open("");
    let o = ops();
    let gone = |op: &str| (Outcome::Failed, format!("{op}: no such framing"));
    assert_eq!(
        op::<IngestIn, FramerOut>(o.ingest, inst, slot::INGEST),
        gone("ingest")
    );
    assert_eq!(
        op::<EmitIn, FramerOut>(o.emit, inst, slot::EMIT),
        gone("emit")
    );
    assert_eq!(
        op::<FramingIn, FramerOut>(o.timer, inst, slot::TIMER),
        gone("timer")
    );
    assert_eq!(
        op::<FinishIn, FramerOut>(o.finish, inst, slot::FINISH),
        gone("finish")
    );
}
