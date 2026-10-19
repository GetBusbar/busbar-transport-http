// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DIALLED SIDE CALLS ITS BINDING'S AUTH (`BUSBAR-1.6.0.md` §6 "Auth points and guest lists"
//! item 5, l.964-967: "The transport finalises the head (its own lines: host, length, framing),
//! calls the auth at its points, adds the lines the auth returns, replacing any plane line of the
//! same name, and encodes. Nothing is added to the head after the auth has run"; coordinator
//! rulings 18 and the phase-2 brief: the auth lines go FIRST on the wire, v1.5.5's order, and an
//! auth that refuses fails the open).
//!
//! The test is the HOST: it opens the door with a scripted host services table whose `auth.call`
//! answers an outbound binding's fields and records the head it was shown, begins a dialled framing
//! with the binding (`BeginIn::auth`, `BeginIn::points`), encodes a request whose head carries only
//! the plane's own lines, and emits it with the stream's unit (`EmitIn::unit`). The wire the framer
//! writes is then read the way a far end reads it: HTTP/1.1 line by line, HTTP/2 by hyper's server.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

use busbar_contract::abi::auth::{FieldSpan, FIELD_QUERY, FIELD_SENSITIVE, POINT_HEAD, POINT_PEER};
use busbar_contract::abi::host::service::{
    AuthAnswer, AuthCallIn, AuthRef, HeadView, HostSlots, ServiceOut, UnitRef, FLOW_CONTINUE,
    SERVICES,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Field, InHead, Op, OutHead, Outcome, RawOutcome, Span,
};
use busbar_contract::abi::mechanism::door::Door;
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables, Ticket};
use busbar_contract::abi::mechanism::DOOR_SYMBOL;
use busbar_contract::abi::transport::check::check_framer;
use busbar_contract::abi::transport::{
    slot, BeginIn, ConnFacts, EmitIn, EncodeIn, FramePiece, FramerOut, FramerSink, HeadSlots,
    IngestIn, Ops, PIECE_STREAM_FAILED, SIDE_DIAL, YIELD_MORE,
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

fn call<I, O>(op: Option<Op>, inst: *mut c_void, i: &mut I, o: &mut O, index: u32) -> Outcome {
    // SAFETY: `I` leads with an `InHead`, `O` with an `OutHead` (the table's own structs).
    unsafe {
        let ih = std::ptr::from_mut(i).cast::<InHead>();
        (*ih).size = size_of::<I>() as u32;
        (*ih).op = index;
        let oh = std::ptr::from_mut(o).cast::<OutHead>();
        (*oh).size = size_of::<O>() as u32;
    }
    (op.expect("every slot is filled"))(
        inst,
        std::ptr::from_ref(i).cast(),
        std::ptr::from_mut(o).cast(),
    )
    .outcome()
}

// ── the scripted kernel: the outbound binding's auth ────────────────────────────────────────────

/// What the auth was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Shown {
    point: u32,
    unit: u64,
    method: String,
    target: String,
    authority: String,
    query: Option<String>,
    fields: Vec<(String, String)>,
    body: Option<Vec<u8>>,
}

/// One connection's auth: the fields it answers (name, value, flags), whether it refuses.
#[derive(Default)]
struct Script {
    fields: Vec<(&'static str, &'static str, u32)>,
    refuses: bool,
    shown: Vec<Shown>,
}

static SCRIPTS: Mutex<BTreeMap<u64, Script>> = Mutex::new(BTreeMap::new());
static NEXT_CTX: AtomicU64 = AtomicU64::new(1);

static SLOTS: LazyLock<HostSlots> = LazyLock::new(|| {
    let mut t: HostSlots = z();
    t.size = size_of::<HostSlots>() as u32;
    t.slots = SERVICES;
    t.auth_call = Some(auth_call);
    t
});

/// The binding's handle and the stream's unit.
const BINDING: AuthRef = AuthRef { id: 7, mac: 8 };
const UNIT: UnitRef = UnitRef { id: 41, mac: 42 };
const TICKET: Ticket = Ticket {
    slot: 1,
    generation: 1,
};

/// # Safety
/// A non-NULL `p` names `len` live bytes.
unsafe fn bytes_of(p: *const u8, len: usize) -> Vec<u8> {
    if p.is_null() || len == 0 {
        return Vec::new();
    }
    // SAFETY: the caller's contract.
    unsafe { std::slice::from_raw_parts(p, len) }.to_vec()
}

/// # Safety
/// `v` is the door's live view.
unsafe fn shown(
    v: &HeadView,
) -> (
    String,
    String,
    String,
    Option<String>,
    Vec<(String, String)>,
) {
    // SAFETY: the caller's contract.
    unsafe {
        let text = |a: AbiStr| String::from_utf8(bytes_of(a.ptr, a.len)).expect("text");
        let fields = if v.fields.is_null() {
            Vec::new()
        } else {
            std::slice::from_raw_parts(v.fields, v.fields_len)
                .iter()
                .map(|f| (text(f.name).to_ascii_lowercase(), text(f.value)))
                .collect()
        };
        (
            text(v.method),
            text(v.target),
            text(v.authority),
            (!v.query.ptr.is_null()).then(|| text(v.query)),
            fields,
        )
    }
}

extern "C" fn auth_call(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK wrapper hands a live `AuthCallIn`, its buffers and a live `out`.
    unsafe {
        let i = input.cast::<AuthCallIn>().read_unaligned();
        let mut scripts = SCRIPTS.lock().expect("scripts");
        let script = scripts.get_mut(&ctx.handle).expect("a script");
        let (method, target, authority, query, fields) = shown(&i.request);
        script.shown.push(Shown {
            point: i.point,
            unit: i.unit.id,
            method,
            target,
            authority,
            query,
            fields,
            body: (!i.body.ptr.is_null()).then(|| bytes_of(i.body.ptr, i.body.len)),
        });
        if script.refuses {
            (*out).outcome = RawOutcome::of(Outcome::Refused);
            return RawOutcome::of(Outcome::Refused);
        }
        let mut at = 0usize;
        let mut n = 0usize;
        if i.point != POINT_PEER {
            for (name, value, flags) in &script.fields {
                let ns = Span {
                    offset: at as u32,
                    len: name.len() as u32,
                };
                std::ptr::copy_nonoverlapping(name.as_ptr(), i.buf.add(at), name.len());
                at += name.len();
                let vs = Span {
                    offset: at as u32,
                    len: value.len() as u32,
                };
                std::ptr::copy_nonoverlapping(value.as_ptr(), i.buf.add(at), value.len());
                at += value.len();
                i.spans.add(n).write_unaligned(FieldSpan {
                    name: ns,
                    value: vs,
                    flags: *flags,
                    _reserved: 0,
                });
                n += 1;
            }
        }
        i.answer.write_unaligned(AuthAnswer {
            size: size_of::<AuthAnswer>() as u32,
            flow: FLOW_CONTINUE,
            unit: if i.point == POINT_PEER {
                UnitRef::NONE
            } else {
                i.unit
            },
        });
        (*out).len = at as u64;
        (*out).items = n as u64;
        (*out).outcome = RawOutcome::of(Outcome::Ready);
    }
    RawOutcome::of(Outcome::Ready)
}

// ── the host ─────────────────────────────────────────────────────────────────────────────────────

struct Host {
    ops: &'static Ops,
    inst: *mut c_void,
    ctx: u64,
    framing: u64,
    wire: Vec<u8>,
    frame: Vec<u8>,
    pieces: Vec<FramePiece>,
    heads: Vec<HeadSlots>,
    /// Every wire byte the framer wrote.
    out: Vec<u8>,
    /// Whether any piece failed its stream.
    failed: bool,
}

impl Host {
    fn open(ops: &'static Ops, script: Script) -> Self {
        let ctx = NEXT_CTX.fetch_add(1, Ordering::SeqCst);
        SCRIPTS.lock().expect("scripts").insert(ctx, script);
        let tables = HostTables {
            size: size_of::<HostTables>() as u32,
            _reserved: 0,
            ctx: HostCtx { handle: ctx },
            wake: None,
            conns: std::ptr::null(),
            services: &*SLOTS,
            io: std::ptr::null(),
        };
        let mut i: OpenIn = z();
        i.host = &tables;
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
        Self {
            ops,
            inst: o.instance,
            ctx,
            framing: 0,
            wire: vec![0; 64 * 1024],
            frame: vec![0; 64 * 1024],
            pieces: vec![z(); 64],
            heads: vec![HeadSlots::default(); 4],
            out: Vec::new(),
            failed: false,
        }
    }

    fn sink(&mut self) -> FramerSink {
        FramerSink {
            wire: self.wire.as_mut_ptr(),
            wire_cap: self.wire.len(),
            frame: self.frame.as_mut_ptr(),
            frame_cap: self.frame.len(),
            pieces: self.pieces.as_mut_ptr(),
            pieces_cap: self.pieces.len(),
            now_monotonic_ns: 1_000_000_000,
            now_unix_ns: 1_790_000_000_000_000_000,
            heads: self.heads.as_mut_ptr(),
            heads_cap: self.heads.len(),
        }
    }

    fn take(&mut self, r: Outcome, o: &FramerOut) -> Outcome {
        let n = o.yielded.pieces_len as usize;
        check_framer(
            r,
            o,
            &self.pieces[..n],
            self.wire.len() as u64,
            self.frame.len() as u64,
            self.pieces.len() as u64,
        )
        .expect("the answer passes the kind's check");
        if r != Outcome::Ready {
            return r;
        }
        self.out
            .extend_from_slice(&self.wire[..o.yielded.wire_len as usize]);
        self.failed |= self.pieces[..n]
            .iter()
            .any(|p| p.flags & PIECE_STREAM_FAILED != 0);
        assert_eq!(o.yielded.flags & YIELD_MORE, 0, "the sink is roomy");
        r
    }

    /// `begin` on the dial side to `target`, its agreed protocol `agreed`, with the binding's
    /// `points` (and its handle, when there are any).
    fn begin(&mut self, target: &str, agreed: &str, points: u32) -> Outcome {
        let mut facts: ConnFacts = z();
        facts.size = size_of::<ConnFacts>() as u32;
        if !agreed.is_empty() {
            facts.agreed_protocol = s(agreed);
        }
        let mut i: BeginIn = z();
        i.head.ticket = TICKET;
        i.side = SIDE_DIAL;
        i.target = s(target);
        i.facts = &facts;
        i.points = points;
        if points != 0 {
            i.auth = BINDING;
        }
        i.sink = self.sink();
        let mut o: FramerOut = z();
        let r = call(self.ops.begin, self.inst, &mut i, &mut o, slot::BEGIN);
        self.framing = o.framing;
        self.take(r, &o)
    }

    /// `encode` a request whose head is `fields` (the plane's own lines, the method and path among
    /// them) and `body`: the message, or `None` when encode refused it.
    fn encode(&mut self, fields: &[(&str, &str)], body: &[u8]) -> Option<Vec<u8>> {
        let fields: Vec<Field> = fields
            .iter()
            .map(|(n, v)| Field {
                name: s(n),
                value: s(v),
            })
            .collect();
        let mut i: EncodeIn = z();
        i.fields = fields.as_ptr();
        i.fields_len = fields.len();
        i.body = body.as_ptr();
        i.body_len = body.len();
        i.sink = self.sink();
        let mut o: FramerOut = z();
        let r = call(self.ops.encode, self.inst, &mut i, &mut o, slot::ENCODE);
        (r == Outcome::Ready).then(|| self.wire[..o.yielded.wire_len as usize].to_vec())
    }

    /// `emit` `message` on stream 1 with the stream's unit, as the host emits a dialled request.
    fn emit(&mut self, message: &[u8]) -> Outcome {
        let mut i: EmitIn = z();
        i.head.ticket = TICKET;
        i.framing = self.framing;
        i.stream = 1;
        i.bytes = message.as_ptr();
        i.len = message.len();
        i.end_of_frame = 1;
        i.unit = UNIT;
        i.sink = self.sink();
        let mut o: FramerOut = z();
        let r = call(self.ops.emit, self.inst, &mut i, &mut o, slot::EMIT);
        self.take(r, &o)
    }

    /// `ingest` the far end's `bytes`.
    fn ingest(&mut self, bytes: &[u8]) -> Outcome {
        let mut i: IngestIn = z();
        i.head.ticket = TICKET;
        i.framing = self.framing;
        i.bytes = bytes.as_ptr();
        i.len = bytes.len();
        i.sink = self.sink();
        let mut o: FramerOut = z();
        let r = call(self.ops.ingest, self.inst, &mut i, &mut o, slot::INGEST);
        self.take(r, &o)
    }

    fn shown(&self) -> Vec<Shown> {
        SCRIPTS.lock().expect("scripts")[&self.ctx].shown.clone()
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let mut i: InHead = z();
        let mut o: OutHead = z();
        call(self.ops.head.close, self.inst, &mut i, &mut o, life::CLOSE);
        SCRIPTS.lock().expect("scripts").remove(&self.ctx);
    }
}

// ── the far end's reading ────────────────────────────────────────────────────────────────────────

/// The HTTP/1.1 head on `wire`: its request line, then its field lines (name lower-cased, value).
fn h1_head(wire: &[u8]) -> (String, Vec<(String, String)>) {
    let text = String::from_utf8_lossy(wire);
    let head = text.split("\r\n\r\n").next().unwrap_or_default();
    let mut lines = head.split("\r\n");
    let start = lines.next().unwrap_or_default().to_owned();
    let fields = lines
        .filter_map(|l| l.split_once(": "))
        .map(|(k, v)| (k.to_ascii_lowercase(), v.to_owned()))
        .collect();
    (start, fields)
}

/// What an HTTP/2 far end (hyper's server) reads off `wire`: its first request's field lines in
/// order, its `:authority` and its path and query.
fn h2_head(wire: Vec<u8>) -> (Vec<(String, String)>, String, String) {
    use tokio::io::AsyncWriteExt;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async move {
        let (mut client, server) = tokio::io::duplex(1 << 20);
        client.write_all(&wire).await.expect("the wire");
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let svc = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
            let tx = tx.clone();
            async move {
                let lines: Vec<(String, String)> = req
                    .headers()
                    .iter()
                    .map(|(k, v)| {
                        (
                            k.as_str().to_owned(),
                            String::from_utf8_lossy(v.as_bytes()).into_owned(),
                        )
                    })
                    .collect();
                let authority = req.uri().authority().map(ToString::to_string);
                let target = req
                    .uri()
                    .path_and_query()
                    .map(ToString::to_string)
                    .unwrap_or_default();
                let _ = tx.send((lines, authority.unwrap_or_default(), target));
                Ok::<_, Infallible>(hyper::Response::new(
                    http_body_util::Empty::<bytes::Bytes>::new(),
                ))
            }
        });
        let conn = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
            .serve_connection(hyper_util::rt::TokioIo::new(server), svc);
        tokio::spawn(conn);
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .expect("a request in time")
            .expect("a request");
        drop(client);
        got
    })
}

/// THE COMPARATOR: the head on the wire is EXACTLY the auth's own lines, first, then the head the
/// auth was shown (less any line the auth's replaced, and less `skip`, a line the wire carries as a
/// pseudo-field), and nothing else, in that order.
fn auth_then_shown(
    wire: &[(String, String)],
    auth: &[(&str, &str)],
    shown: &[(String, String)],
    skip: &[&str],
) -> Result<(), String> {
    let mut want: Vec<(String, String)> = auth
        .iter()
        .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
        .collect();
    want.extend(
        shown
            .iter()
            .filter(|(n, _)| !auth.iter().any(|(a, _)| a.eq_ignore_ascii_case(n)))
            .filter(|(n, _)| !skip.contains(&n.as_str()))
            .cloned(),
    );
    if wire == want.as_slice() {
        Ok(())
    } else {
        Err(format!(
            "the wire {wire:?} is not the auth's lines then the head it saw {want:?}"
        ))
    }
}

// ── the cells ────────────────────────────────────────────────────────────────────────────────────

const TARGET: &str = "http://peer.test:8080/v1/x";
const AUTH: &[(&str, &str)] = &[("authorization", "Bearer signed-over-the-whole-head")];

/// The plane's own lines: no `accept`, no `host`, no length (the host adds none; the framer writes
/// its own).
fn plane() -> Vec<(&'static str, &'static str)> {
    vec![
        ("method", "POST"),
        ("path", "/v1/x"),
        ("content-type", "application/json"),
        ("x-plane", "1"),
    ]
}

fn script() -> Script {
    Script {
        fields: AUTH
            .iter()
            .map(|(n, v)| (*n, *v, FIELD_SENSITIVE))
            .collect(),
        ..Script::default()
    }
}

/// HTTP/1.1: the auth was shown the whole finalised head (the framer's own `accept`, `host` and
/// length line included: shown host, length and framing), and the head on the wire is its lines
/// first, then exactly that head.
fn h1_wire_is_the_shown_head(label: &str, ops: &'static Ops) {
    let mut h = Host::open(ops, script());
    assert_eq!(
        h.begin(TARGET, "http/1.1", POINT_HEAD),
        Outcome::Ready,
        "{label}"
    );
    let message = h
        .encode(&plane(), b"hi")
        .expect("encode writes the length line");
    assert_eq!(h.emit(&message), Outcome::Ready, "{label}");
    let shown = h.shown();
    let [Shown {
        point: POINT_HEAD,
        unit,
        method,
        target,
        authority,
        fields,
        body: None,
        ..
    }] = &shown[..]
    else {
        panic!("{label}: one head call: {shown:?}");
    };
    assert_eq!(*unit, UNIT.id, "{label}: the call carries the emit's unit");
    assert_eq!(
        (method.as_str(), target.as_str()),
        ("POST", "/v1/x"),
        "{label}"
    );
    assert_eq!(authority, "peer.test:8080", "{label}");
    let has = |n: &str, v: &str| fields.iter().any(|(k, x)| k == n && x == v);
    assert!(
        has("host", "peer.test:8080"),
        "{label}: shown the host: {fields:?}"
    );
    assert!(has("accept", "*/*"), "{label}: shown accept: {fields:?}");
    assert!(
        has("content-length", "2"),
        "{label}: shown the length: {fields:?}"
    );
    let (start, wire) = h1_head(&h.out);
    assert_eq!(start, "POST /v1/x HTTP/1.1", "{label}");
    auth_then_shown(&wire, AUTH, fields, &[]).unwrap_or_else(|e| panic!("{label}: {e}"));
}

/// HTTP/2: the far end reads the auth's lines first, then the head the auth was shown, `host` as
/// the `:authority`.
fn h2_wire_is_the_shown_head(label: &str, ops: &'static Ops) {
    let mut h = Host::open(ops, script());
    assert_eq!(h.begin(TARGET, "h2", POINT_HEAD), Outcome::Ready, "{label}");
    // The far end's SETTINGS: the connection is open.
    assert_eq!(
        h.ingest(&[0, 0, 0, 4, 0, 0, 0, 0, 0]),
        Outcome::Ready,
        "{label}"
    );
    let message = h
        .encode(&plane(), b"hi")
        .expect("encode writes the length line");
    assert_eq!(h.emit(&message), Outcome::Ready, "{label}");
    let shown = h.shown();
    let [Shown { fields, .. }] = &shown[..] else {
        panic!("{label}: one head call: {shown:?}");
    };
    let (wire, authority, target) = h2_head(h.out.clone());
    assert_eq!(
        authority, "peer.test:8080",
        "{label}: the shown host is the :authority"
    );
    assert_eq!(target, "/v1/x", "{label}");
    auth_then_shown(&wire, AUTH, fields, &["host"]).unwrap_or_else(|e| panic!("{label}: {e}"));
}

/// An auth whose answer is a query parameter (`FIELD_QUERY`): it joins the target, never a field
/// line.
fn a_query_field_joins_the_target(label: &str, ops: &'static Ops) {
    let mut h = Host::open(
        ops,
        Script {
            fields: vec![("key", "k 1", FIELD_QUERY)],
            ..Script::default()
        },
    );
    assert_eq!(
        h.begin(TARGET, "http/1.1", POINT_HEAD),
        Outcome::Ready,
        "{label}"
    );
    let message = h.encode(&plane(), b"hi").expect("encode");
    assert_eq!(h.emit(&message), Outcome::Ready, "{label}");
    let (start, wire) = h1_head(&h.out);
    assert_eq!(start, "POST /v1/x?key=k%201 HTTP/1.1", "{label}");
    assert!(!wire.iter().any(|(k, _)| k == "key"), "{label}: {wire:?}");
}

/// An auth that refuses (`auth.call` REFUSED) fails the open: no head without the auth's lines ever
/// reaches the wire.
fn a_refusing_auth_fails_the_open(label: &str, ops: &'static Ops) {
    let mut h = Host::open(
        ops,
        Script {
            refuses: true,
            ..script()
        },
    );
    assert_eq!(
        h.begin(TARGET, "http/1.1", POINT_HEAD),
        Outcome::Ready,
        "{label}"
    );
    let message = h.encode(&plane(), b"hi").expect("encode");
    let r = h.emit(&message);
    assert!(
        r == Outcome::Failed || h.failed,
        "{label}: the open fails: {r:?}"
    );
    assert_eq!(h.shown().len(), 1, "{label}: the auth was called");
    assert!(
        !String::from_utf8_lossy(&h.out).contains("POST"),
        "{label}: no head went out: {:?}",
        String::from_utf8_lossy(&h.out)
    );
}

/// A binding needing `Peer`: the peer call is made once, at `begin`, before any head, carrying no
/// request; the head call follows on the emit.
fn the_peer_point_is_called_at_begin(label: &str, ops: &'static Ops) {
    let mut h = Host::open(ops, script());
    assert_eq!(
        h.begin(TARGET, "http/1.1", POINT_PEER | POINT_HEAD),
        Outcome::Ready,
        "{label}"
    );
    let shown = h.shown();
    assert!(
        matches!(&shown[..], [Shown { point: POINT_PEER, unit: 0, method, fields, body: None, .. }] if method.is_empty() && fields.is_empty()),
        "{label}: one peer call at begin, no request: {shown:?}"
    );
    let message = h.encode(&plane(), b"hi").expect("encode");
    assert_eq!(h.emit(&message), Outcome::Ready, "{label}");
    let points: Vec<u32> = h.shown().iter().map(|s| s.point).collect();
    assert_eq!(points, vec![POINT_PEER, POINT_HEAD], "{label}");
}

/// No binding (`points` 0): no auth call, and the framer still writes its own lines, once.
fn no_binding_calls_no_auth(label: &str, ops: &'static Ops) {
    let mut h = Host::open(ops, script());
    assert_eq!(h.begin(TARGET, "http/1.1", 0), Outcome::Ready, "{label}");
    let message = h.encode(&plane(), b"hi").expect("encode");
    assert_eq!(h.emit(&message), Outcome::Ready, "{label}");
    assert!(h.shown().is_empty(), "{label}");
    let (_, wire) = h1_head(&h.out);
    let names: Vec<&str> = wire.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "content-type",
            "x-plane",
            "accept",
            "host",
            "content-length"
        ],
        "{label}"
    );
}

fn linked() -> &'static Ops {
    let d = busbar_transport_http_plugin::door::door();
    // SAFETY: the door's `'static` table.
    unsafe { &*(*d).ops.cast::<Ops>() }
}

fn dropped() -> (&'static Ops, &'static libloading::Library) {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let file = busbar_plugin_loader::plugin_library_filename("busbar_transport_http_plugin");
    let path = [profile.join(&file), profile.join("deps").join(&file)]
        .into_iter()
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p)
        .unwrap_or_else(|| panic!("the dropped-in image ({file}) is not built"));
    // SAFETY: our own cdylib, built by this `cargo test`.
    let lib: &'static libloading::Library = Box::leak(Box::new(
        unsafe { libloading::Library::new(path) }.expect("load"),
    ));
    // SAFETY: the one exported symbol, a `DoorFn`.
    let door: libloading::Symbol<'_, extern "C" fn() -> *const Door> =
        unsafe { lib.get(DOOR_SYMBOL) }.expect("the door symbol");
    let d = door();
    // SAFETY: the dropped-in door's `'static` table.
    (unsafe { &*(*d).ops.cast::<Ops>() }, lib)
}

fn both(cell: fn(&str, &'static Ops)) {
    let (d, _lib) = dropped();
    for (label, ops) in [("linked", linked()), ("dropped", d)] {
        cell(label, ops);
    }
}

/// The comparator's positive control: a head with a line added AFTER the auth's (the defect the
/// rule forbids) is told apart from the head the auth signed.
#[test]
fn a_line_added_after_the_auth_fails_the_comparator() {
    let shown = vec![
        ("content-type".to_owned(), "application/json".to_owned()),
        ("host".to_owned(), "peer.test:8080".to_owned()),
    ];
    let mut wire: Vec<(String, String)> = AUTH
        .iter()
        .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
        .collect();
    wire.extend(shown.iter().cloned());
    assert_eq!(auth_then_shown(&wire, AUTH, &shown, &[]), Ok(()));
    wire.push(("content-length".to_owned(), "2".to_owned()));
    assert!(auth_then_shown(&wire, AUTH, &shown, &[]).is_err());
}

#[test]
fn the_h1_head_is_the_auths_lines_then_every_line_it_was_shown() {
    both(h1_wire_is_the_shown_head);
}

#[test]
fn the_h2_head_is_the_auths_lines_then_every_line_it_was_shown() {
    both(h2_wire_is_the_shown_head);
}

#[test]
fn an_auth_query_field_joins_the_target() {
    both(a_query_field_joins_the_target);
}

#[test]
fn an_auth_that_refuses_fails_the_open() {
    both(a_refusing_auth_fails_the_open);
}

#[test]
fn a_peer_binding_is_called_once_at_begin() {
    both(the_peer_point_is_called_at_begin);
}

#[test]
fn with_no_binding_no_auth_is_called_and_the_framer_writes_its_own_lines() {
    both(no_binding_calls_no_auth);
}
