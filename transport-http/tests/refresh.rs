// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Door-table cells, driven through the door's own table as the host drives it.
//!
//! RED (Q128 transport-http, the refresh LOW): a reload's settings are applied by `refresh`, read
//! as `open` reads them, or refused with `open`'s words while the settings in force stay. Driven
//! through the door's own table, as the host drives it. RED on the door that answered every
//! `refresh` READY and kept the settings `open` read, so a changed protocol key or body cap was
//! silently ignored.

use std::mem::{size_of, zeroed};

use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, InHead, Op, OutHead, Outcome, BLOB_JSON,
};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut, RefreshIn};
use busbar_contract::abi::transport::{
    slot, BeginIn, ConnFacts, EmitIn, FramePiece, FramerOut, FramerSink, LocateIn, LocateOut, Ops,
    SIDE_DIAL,
};

fn z<T>() -> T {
    // SAFETY: plain C data; all-zero is valid.
    unsafe { zeroed() }
}

fn s(text: &str) -> AbiStr {
    AbiStr {
        ptr: text.as_ptr(),
        len: text.len(),
    }
}

fn json(text: &str) -> Blob {
    Blob {
        ptr: text.as_ptr(),
        len: text.len(),
        fmt: BLOB_JSON,
        flags: 0,
    }
}

/// One call through the table: its outcome and the error text its head names.
fn call<I, O>(
    op: Option<Op>,
    inst: *mut std::ffi::c_void,
    i: &mut I,
    o: &mut O,
    index: u32,
) -> (Outcome, String) {
    // SAFETY: `I`/`O` lead with their heads.
    unsafe {
        let ih = std::ptr::from_mut(i).cast::<InHead>();
        (*ih).size = size_of::<I>() as u32;
        (*ih).op = index;
        (*std::ptr::from_mut(o).cast::<OutHead>()).size = size_of::<O>() as u32;
    }
    let r = (op.expect("slot"))(
        inst,
        std::ptr::from_ref(i).cast(),
        std::ptr::from_mut(o).cast(),
    );
    // SAFETY: as above; the error, when named, lives until the instance's next answer.
    let error = unsafe {
        let e = (*std::ptr::from_mut(o).cast::<OutHead>()).error;
        if e.ptr.is_null() {
            String::new()
        } else {
            String::from_utf8_lossy(std::slice::from_raw_parts(e.ptr, e.len)).into_owned()
        }
    };
    (r.outcome(), error)
}

struct Door {
    ops: &'static Ops,
    inst: *mut std::ffi::c_void,
}

impl Door {
    fn open(settings: &str) -> Self {
        let d = busbar_transport_http::door::door();
        // SAFETY: the door's `'static` table.
        let ops: &Ops = unsafe { &*(*d).ops.cast::<Ops>() };
        let mut i: OpenIn = z();
        i.settings = json(settings);
        let mut o: OpenOut = z();
        let (r, e) = call(
            ops.head.open,
            std::ptr::null_mut(),
            &mut i,
            &mut o,
            life::OPEN,
        );
        assert_eq!(r, Outcome::Ready, "open: {e}");
        Self {
            ops,
            inst: o.instance,
        }
    }

    fn refresh(&self, generation: u64, settings: &str) -> (Outcome, String) {
        let mut i: RefreshIn = z();
        i.generation = generation;
        i.settings = json(settings);
        let mut o: OutHead = z();
        call(
            self.ops.head.refresh,
            self.inst,
            &mut i,
            &mut o,
            life::REFRESH,
        )
    }

    /// The protocol offer `locate` states for `target`.
    fn offer(&self, target: &str) -> Vec<u8> {
        let (mut a, mut n, mut l, mut d) = (
            vec![0_u8; 256],
            vec![0_u8; 256],
            vec![0_u8; 64],
            vec![0_u8; 512],
        );
        let mut i: LocateIn = z();
        i.target = s(target);
        (i.authority_buf, i.authority_cap) = (a.as_mut_ptr(), a.len());
        (i.name_buf, i.name_cap) = (n.as_mut_ptr(), n.len());
        (i.alpn_buf, i.alpn_cap) = (l.as_mut_ptr(), l.len());
        (i.defaults_buf, i.defaults_cap) = (d.as_mut_ptr(), d.len());
        let mut o: LocateOut = z();
        let (r, e) = call(self.ops.locate, self.inst, &mut i, &mut o, slot::LOCATE);
        assert_eq!(r, Outcome::Ready, "locate: {e}");
        l.truncate(usize::try_from(o.alpn_written).expect("a length"));
        l
    }

    /// `locate` on `target` with a defaults buffer of `cap` bytes: its outcome, and the bytes it
    /// says it wrote and needs.
    fn locate_with_defaults(&self, target: &str, cap: usize) -> (Outcome, u64, u64) {
        let (mut a, mut n, mut l) = (vec![0_u8; 256], vec![0_u8; 256], vec![0_u8; 64]);
        let mut d = vec![0_u8; cap];
        let mut i: LocateIn = z();
        i.target = s(target);
        (i.authority_buf, i.authority_cap) = (a.as_mut_ptr(), a.len());
        (i.name_buf, i.name_cap) = (n.as_mut_ptr(), n.len());
        (i.alpn_buf, i.alpn_cap) = (l.as_mut_ptr(), l.len());
        if cap > 0 {
            (i.defaults_buf, i.defaults_cap) = (d.as_mut_ptr(), cap);
        }
        let mut o: LocateOut = z();
        let (r, _) = call(self.ops.locate, self.inst, &mut i, &mut o, slot::LOCATE);
        (r, o.defaults_written, o.defaults_needed)
    }

    /// Whether a framing begun now carries a 5-byte request body: `emit`'s outcome.
    fn carries_five_bytes(&self) -> Outcome {
        let mut wire = vec![0_u8; 64 * 1024];
        let mut frame = vec![0_u8; 1024];
        let mut pieces: Vec<FramePiece> = vec![z(); 8];
        let (wp, fp, pp) = (wire.as_mut_ptr(), frame.as_mut_ptr(), pieces.as_mut_ptr());
        let sink = || FramerSink {
            wire: wp,
            wire_cap: 64 * 1024,
            frame: fp,
            frame_cap: 1024,
            pieces: pp,
            pieces_cap: 8,
            now_monotonic_ns: 5_000_000_000,
            now_unix_ns: 1_790_000_000_000_000_000,
            heads: std::ptr::null_mut(),
            heads_cap: 0,
        };
        let mut facts: ConnFacts = z();
        facts.size = size_of::<ConnFacts>() as u32;
        let mut b: BeginIn = z();
        b.side = SIDE_DIAL;
        b.target = s("http://127.0.0.1:9");
        b.facts = &facts;
        b.sink = sink();
        let mut fo: FramerOut = z();
        let (r, e) = call(self.ops.begin, self.inst, &mut b, &mut fo, slot::BEGIN);
        assert_eq!(r, Outcome::Ready, "begin: {e}");
        let message = b"POST /x HTTP/1.1\r\ncontent-length: 5\r\n\r\nhello";
        let mut m: EmitIn = z();
        m.framing = fo.framing;
        m.stream = 1;
        m.bytes = message.as_ptr();
        m.len = message.len();
        m.end_of_frame = 1;
        m.sink = sink();
        let mut mo: FramerOut = z();
        call(self.ops.emit, self.inst, &mut m, &mut mo, slot::EMIT).0
    }
}

impl Drop for Door {
    fn drop(&mut self) {
        let mut c: InHead = z();
        let mut co: OutHead = z();
        let _ = call(self.ops.head.close, self.inst, &mut c, &mut co, life::CLOSE);
    }
}

const BOTH: &[u8] = b"\x02h2\x08http/1.1";
const H1: &[u8] = b"\x08http/1.1";

/// A changed protocol key is applied: the next `locate` offers what the reload says.
#[test]
fn a_refresh_applies_the_reloads_protocol_key() {
    let door = Door::open("{}");
    assert_eq!(door.offer("https://example.test/"), BOTH);
    let (r, e) = door.refresh(2, r#"{"advanced.upstream_http1_only":true}"#);
    assert_eq!(r, Outcome::Ready, "{e}");
    assert_eq!(
        door.offer("https://example.test/"),
        H1,
        "the reload's http1-only key is the one in force"
    );
    let (r, e) = door.refresh(3, "{}");
    assert_eq!(r, Outcome::Ready, "{e}");
    assert_eq!(door.offer("https://example.test/"), BOTH, "and back");
}

/// A changed body cap is applied to a framing begun after the reload.
#[test]
fn a_refresh_applies_the_reloads_body_cap() {
    let door = Door::open("{}");
    assert_eq!(door.carries_five_bytes(), Outcome::Ready);
    let (r, e) = door.refresh(2, r#"{"limits.request_body_max_bytes":4}"#);
    assert_eq!(r, Outcome::Ready, "{e}");
    assert_ne!(
        door.carries_five_bytes(),
        Outcome::Ready,
        "a 5-byte body is over the reload's 4-byte cap"
    );
}

/// A reload `open` would refuse is refused with `open`'s words, and the settings in force stay.
#[test]
fn a_refresh_with_bad_settings_is_refused_and_changes_nothing() {
    let door = Door::open(r#"{"advanced.upstream_http1_only":true}"#);
    let (r, e) = door.refresh(2, r#"{"advanced.upstream_http1_only":"yes"}"#);
    assert_eq!(r, Outcome::Failed);
    assert_eq!(e, "advanced.upstream_http1_only: not of its declared kind");
    let (r, _) = door.refresh(3, "[");
    assert_eq!(r, Outcome::Failed, "a blob that is not JSON is refused");
    assert_eq!(
        door.offer("https://example.test/"),
        H1,
        "the settings in force before the refused reloads stay"
    );
}

/// RED (Q128 transport-http, the empty defaults buffer): the framer's own head lines (`accept`,
/// `host`) are owed to every request (THE DESIGN §6 step 5), so a host that lends no room for them,
/// or too little, is answered short with the size they need, never READY with no lines (a request
/// that would go out with no `host` on HTTP/1.1). RED on the `locate` that answered READY and wrote
/// nothing when the host lent no defaults buffer.
#[test]
fn locate_answers_short_when_the_defaults_buffer_cannot_hold_its_lines() {
    let door = Door::open("{}");
    let want = "accept: */*\r\nhost: 127.0.0.1:9\r\n".len() as u64;
    for cap in [0, 4] {
        let (r, written, needed) = door.locate_with_defaults("http://127.0.0.1:9", cap);
        assert_eq!(r, Outcome::Failed, "a {cap}-byte defaults buffer is short");
        assert_eq!(written, 0, "nothing is written on a short answer");
        assert_eq!(
            needed, want,
            "the short answer names the size the lines need"
        );
    }
    let (r, written, _) = door.locate_with_defaults("http://127.0.0.1:9", 512);
    assert_eq!(r, Outcome::Ready);
    assert_eq!(written, want);
}
