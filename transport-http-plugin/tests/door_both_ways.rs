// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `http` DOOR'S CONFORMANCE: the same door, compiled in and dropped in, driven the same way.

use std::collections::{BTreeMap, VecDeque};
use std::convert::Infallible;
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use busbar_contract::abi::auth::{
    FieldSpan, FIELD_QUERY, FIELD_SENSITIVE, POINT_HEAD, POINT_HEAD_BODY, POINT_PEER, SPAN_ABSENT,
};
use busbar_contract::abi::host::service::{
    AuthAnswer, AuthCallIn, AuthRef, HeadView, HostSlots, RefusalAnswer, ServiceOut, UnitHandInIn,
    UnitRef, UnitRefuseIn, FLOW_CONTINUE, FLOW_STOP, LINE_NONE, REFUSE_CHECK_FAILED,
    REFUSE_METHOD_MISS, REFUSE_NO_ROUTE, REFUSE_OVER_GATE, REFUSE_STOPPED, SCHEME_PLAIN,
    SCHEME_SECURE, SERVICES,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, Field, InHead, Op, OutHead, Outcome, RawOutcome, Span, BLOB_JSON, BLOB_OCTETS,
    FLAG_RESUME,
};
use busbar_contract::abi::mechanism::door::Door;
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, CancelIn, CancelOut, OpenIn, OpenOut,
};
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables, Ticket};
use busbar_contract::abi::mechanism::DOOR_SYMBOL;
use busbar_contract::abi::transport::check::{check_framer, check_framer_fields, check_head_slots};
use busbar_contract::abi::transport::route::{
    FieldPredicate, LineEntry, RouteMatch, FIELD_PRESENT, FIELD_VALUE_PREFIX, METHOD_ANY,
    METHOD_GET, METHOD_POST, PATH_EXACT, PATH_PREFIX,
};
use busbar_contract::abi::transport::{
    slot, BeginIn, ConnFacts, EmitIn, EncodeIn, FramePiece, FramerOut, FramerSink, FramingIn,
    HeadSlots, IngestIn, LocateIn, LocateOut, Ops, RefuseIn, CANCEL_NOTHING_MOVED, CANCEL_PARTIAL,
    PIECE_CONTINUED, PIECE_END, PIECE_END_OF_FRAME, PIECE_FIELDS, PIECE_HAS_CODE,
    PIECE_HAS_DECLARED_LEN, PIECE_STREAM_FAILED, SIDE_ACCEPT, SIDE_DIAL, YIELD_ENDED,
    YIELD_HAS_DEADLINE, YIELD_MORE, YIELD_STREAM_FULL,
};
use busbar_contract::abi::transport::{
    FAULT_NONE, FAULT_TRANSIENT, STATUS_CALLER_FAULT, STATUS_SUCCESS,
};
use bytes::Bytes;
use hyper::body::{Body, Frame, Incoming};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

/// The sink's capacities: wire bytes, frame bytes, pieces.
#[derive(Clone, Copy)]
struct Caps(usize, usize, usize);
const ROOMY: Caps = Caps(64 * 1024, 64 * 1024, 64);
/// Small enough that every answer overflows, so every op is re-called with `YIELD_MORE`.
const TIGHT: Caps = Caps(7, 5, 1);
const SEC: u64 = 1_000_000_000;

fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { zeroed() }
}

fn s(text: &'static str) -> AbiStr {
    AbiStr {
        ptr: text.as_ptr(),
        len: text.len(),
    }
}

/// A response body the test releases: the first chunk at once, the rest when told.
struct ChanBody(mpsc::Receiver<Bytes>);
impl Body for ChanBody {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.0.poll_recv(cx).map(|o| o.map(|b| Ok(Frame::data(b))))
    }
}

/// The socket the host holds: what the server wrote and the host has not ingested, and a switch
struct Socket {
    rx: Mutex<(VecDeque<u8>, bool)>,
    silent: AtomicBool,
    to_server: mpsc::UnboundedSender<Vec<u8>>,
    release: mpsc::Sender<()>,
}

fn serve(rt: &tokio::runtime::Runtime, h2: bool) -> Arc<Socket> {
    let (cli, srv) = tokio::io::duplex(1 << 20);
    let (rel_tx, rel_rx) = mpsc::channel::<()>(4);
    let rel_rx = Arc::new(tokio::sync::Mutex::new(rel_rx));
    rt.spawn(async move {
        let svc = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
            let rel = rel_rx.clone();
            async move {
                if req.uri().path() == "/hang" {
                    std::future::pending::<()>().await;
                }
                let req_path = req.uri().path().to_owned();
                let got = http_body_util::BodyExt::collect(req.into_body())
                    .await
                    .expect("request body")
                    .to_bytes();
                let (tx, rx) = mpsc::channel(4);
                if req_path == "/limited" {
                    let mut r = hyper::Response::new(ChanBody(rx));
                    *r.status_mut() = hyper::StatusCode::TOO_MANY_REQUESTS;
                    r.headers_mut()
                        .insert("retry-after", hyper::header::HeaderValue::from_static("7"));
                    return Ok::<_, Infallible>(r);
                }
                tokio::spawn(async move {
                    let _ = tx.send(Bytes::from(format!("got={};a", got.len()))).await;
                    rel.lock().await.recv().await;
                    let _ = tx.send(Bytes::from_static(b"b")).await;
                    let _ = tx.send(Bytes::from_static(b"c")).await;
                });
                Ok::<_, Infallible>(hyper::Response::new(ChanBody(rx)))
            }
        });
        let io = hyper_util::rt::TokioIo::new(srv);
        if h2 {
            let _ = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(io, svc)
                .await;
        } else {
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, svc)
                .await;
        }
    });
    let (to_tx, mut to_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let sock = Arc::new(Socket {
        rx: Mutex::new((VecDeque::new(), false)),
        silent: AtomicBool::new(false),
        to_server: to_tx,
        release: rel_tx,
    });
    let (mut rd, mut wr) = tokio::io::split(cli);
    let s2 = sock.clone();
    rt.spawn(async move {
        let mut buf = vec![0_u8; 16384];
        loop {
            let n = rd.read(&mut buf).await.unwrap_or(0);
            if !s2.silent.load(Ordering::SeqCst) || n == 0 {
                let mut g = s2.rx.lock().expect("rx");
                g.0.extend(&buf[..n]);
                g.1 |= n == 0;
            }
            if n == 0 {
                break;
            }
        }
    });
    rt.spawn(async move {
        while let Some(b) = to_rx.recv().await {
            if wr.write_all(&b).await.is_err() {
                break;
            }
        }
    });
    sock
}

/// One frame piece as the host read it out of its sink.
#[derive(Debug, Clone)]
struct Got {
    stream: u64,
    bytes: Vec<u8>,
    flags: u16,
    code: u32,
    /// The body length the piece states its head declared (`PIECE_HAS_DECLARED_LEN`), if any.
    declared_len: Option<u64>,
    /// The status class, fault reading and `Retry-After` seconds the door wrote on the piece.
    status_class: u8,
    fault: u8,
    retry_after_secs: u64,
}

struct Host {
    ops: &'static Ops,
    inst: *mut c_void,
    now: u64,
    framing: u64,
    sock: Arc<Socket>,
    wire_log: Vec<u8>,
    /// Every byte the far end sent, as ingested.
    heard_log: Vec<u8>,
    frame_log: Vec<u8>,
    deadline: Option<u64>,
    more: bool,
    caps: Caps,
    wire: Vec<u8>,
    frame: Vec<u8>,
    pieces: Vec<FramePiece>,
    heads: Vec<HeadSlots>,
    /// Every head slot's reason phrase the framer yielded, by stream.
    reasons: Vec<(u64, Vec<u8>)>,
}

/// # Safety
/// The caller supplies this slot's concrete ABI input/output types, live nested ranges, and
/// the instance belonging to this door (or null only for an operation permitting no instance).
unsafe fn call<I, O>(
    op: Option<Op>,
    inst: *mut c_void,
    i: &mut I,
    o: &mut O,
    index: u32,
) -> Outcome {
    // SAFETY: `I` leads with an `InHead`, `O` with an `OutHead` (the table's own structs).
    unsafe {
        let ih = std::ptr::from_mut(i).cast::<InHead>();
        (*ih).size = size_of::<I>() as u32;
        (*ih).op = index;
        let oh = std::ptr::from_mut(o).cast::<OutHead>();
        (*oh).size = size_of::<O>() as u32;
    }
    // SAFETY: the caller upholds this raw shim's exact slot, frame, instance and live-range contract.
    let raw = unsafe {
        (op.expect("every slot is filled"))(
            inst,
            std::ptr::from_ref(i).cast(),
            std::ptr::from_mut(o).cast(),
        )
    };
    raw.outcome()
}

impl Host {
    fn open(ops: &'static Ops, settings: &'static str, sock: Arc<Socket>, caps: Caps) -> Self {
        let mut i: OpenIn = z();
        i.settings = Blob {
            ptr: settings.as_ptr(),
            len: settings.len(),
            fmt: BLOB_JSON,
            flags: 0,
        };
        let mut o: OpenOut = z();
        assert_eq!(
            // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
            // and the door instance for this synchronous call; the selected slot and index agree.
            unsafe {
                call(
                    ops.head.open,
                    std::ptr::null_mut(),
                    &mut i,
                    &mut o,
                    life::OPEN,
                )
            },
            Outcome::Ready
        );
        Self {
            ops,
            inst: o.instance,
            now: 7 * SEC,
            framing: 0,
            sock,
            wire_log: Vec::new(),
            heard_log: Vec::new(),
            frame_log: Vec::new(),
            deadline: None,
            more: false,
            caps,

            wire: vec![0; caps.0.max(4096)],
            frame: vec![0; caps.1],
            pieces: vec![z(); caps.2],
            heads: vec![HeadSlots::default(); 4],
            reasons: Vec::new(),
        }
    }

    fn sink(&mut self) -> FramerSink {
        FramerSink {
            wire: self.wire.as_mut_ptr(),
            wire_cap: self.caps.0,
            frame: self.frame.as_mut_ptr(),
            frame_cap: self.caps.1,
            pieces: self.pieces.as_mut_ptr(),
            pieces_cap: self.caps.2,
            now_monotonic_ns: self.now,
            now_unix_ns: 1_790_000_000 * SEC + self.now,
            heads: self.heads.as_mut_ptr(),
            heads_cap: self.heads.len(),
        }
    }

    /// Take an op's answer: judge it by the kind's own check, send its wire bytes, keep its pieces.
    fn take(&mut self, outcome: Outcome, o: &FramerOut, got: &mut Vec<Got>) -> Outcome {
        let n = o.yielded.pieces_len as usize;
        check_framer(
            outcome,
            o,
            &self.pieces[..n],
            self.caps.0 as u64,
            self.caps.1 as u64,
            self.caps.2 as u64,
        )
        .expect("the answer passes the kind's check");
        if outcome != Outcome::Ready {
            return outcome;
        }
        let frame = &self.frame[..o.yielded.frame_len as usize];
        check_framer_fields(&self.pieces[..n], frame).expect("no pseudo-field in a field block");
        check_head_slots(o, &self.heads, self.heads.len() as u64).expect("the head slots pass");
        for h in &self.heads[..o.yielded.heads_len as usize] {
            let at = h.reason.offset as usize;
            self.reasons
                .push((h.stream, frame[at..at + h.reason.len as usize].to_vec()));
        }
        let w = self.wire[..o.yielded.wire_len as usize].to_vec();
        if !w.is_empty() {
            self.wire_log.extend_from_slice(&w);
            self.sock.to_server.send(w).expect("server");
        }
        for p in &self.pieces[..n] {
            self.frame_log
                .extend_from_slice(&self.frame[p.offset as usize..(p.offset + p.len) as usize]);
            got.push(Got {
                stream: p.stream,
                bytes: self.frame[p.offset as usize..(p.offset + p.len) as usize].to_vec(),
                flags: p.flags,
                code: p.code,
                declared_len: (p.flags & PIECE_HAS_DECLARED_LEN != 0).then_some(p.declared_len),
                status_class: p.status_class,
                fault: p.fault,
                retry_after_secs: p.retry_after_secs,
            });
        }
        self.deadline =
            (o.yielded.flags & YIELD_HAS_DEADLINE != 0).then_some(o.yielded.next_deadline_ns);
        self.more = o.yielded.flags & YIELD_MORE != 0;
        outcome
    }

    /// Re-call a framing op that answered `YIELD_MORE`, with NO new bytes, until it stops.
    fn drain(&mut self, index: u32, stream: u64, got: &mut Vec<Got>) -> Outcome {
        let mut calls = 0_u32;
        while self.more {
            calls += 1;
            assert!(calls < 100_000, "a YIELD_MORE re-call never ran dry");
            let mut o: FramerOut = z();
            let r = match index {
                slot::EMIT => {
                    let mut i: EmitIn = z();
                    i.framing = self.framing;
                    i.stream = stream;
                    i.sink = self.sink();
                    // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
                    // and the door instance for this synchronous call; the selected slot and index agree.
                    unsafe { call(self.ops.emit, self.inst, &mut i, &mut o, index) }
                }
                slot::INGEST => {
                    let mut i: IngestIn = z();
                    i.framing = self.framing;
                    i.sink = self.sink();
                    // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
                    // and the door instance for this synchronous call; the selected slot and index agree.
                    unsafe { call(self.ops.ingest, self.inst, &mut i, &mut o, index) }
                }
                _ => {
                    let mut i: FramingIn = z();
                    i.framing = self.framing;
                    i.sink = self.sink();
                    // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
                    // and the door instance for this synchronous call; the selected slot and index agree.
                    unsafe { call(self.ops.timer, self.inst, &mut i, &mut o, index) }
                }
            };
            if self.take(r, &o, got) != Outcome::Ready {
                return r;
            }
        }
        Outcome::Ready
    }

    fn begin(&mut self, agreed: &'static str) {
        let mut facts: ConnFacts = z();
        facts.size = size_of::<ConnFacts>() as u32;
        if !agreed.is_empty() {
            facts.agreed_protocol = s(agreed);
        }
        let mut i: BeginIn = z();
        i.side = SIDE_DIAL;
        i.target = s("http://upstream.test");
        i.facts = &facts;
        i.sink = self.sink();
        let mut o: FramerOut = z();
        // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
        // and the door instance for this synchronous call; the selected slot and index agree.
        let r = unsafe { call(self.ops.begin, self.inst, &mut i, &mut o, slot::BEGIN) };
        self.framing = o.framing;
        let mut got = Vec::new();
        assert_eq!(self.take(r, &o, &mut got), Outcome::Ready);
        assert_eq!(self.drain(slot::TIMER, 0, &mut got), Outcome::Ready);
    }

    /// `encode` an envelope, then `emit` it on `stream`.
    fn ask(&mut self, stream: u64, path: &'static str, body: &'static str) -> Vec<Got> {
        let len = body.len().to_string();
        let fields = [
            Field {
                name: s("method"),
                value: s("POST"),
            },
            Field {
                name: s("path"),
                value: s(path),
            },
            Field {
                name: s("authorization"),
                value: s("Bearer sk-test"),
            },
            Field {
                name: s("content-type"),
                value: s("application/json"),
            },
            Field {
                name: s("content-length"),
                value: AbiStr {
                    ptr: len.as_ptr(),
                    len: len.len(),
                },
            },
        ];
        let mut i: EncodeIn = z();
        i.fields = fields.as_ptr();
        i.fields_len = fields.len();
        i.body = body.as_ptr();
        i.body_len = body.len();
        i.sink = self.sink();

        i.sink.wire_cap = self.wire.len();
        let mut o: FramerOut = z();
        assert_eq!(
            // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
            // and the door instance for this synchronous call; the selected slot and index agree.
            unsafe { call(self.ops.encode, self.inst, &mut i, &mut o, slot::ENCODE) },
            Outcome::Ready
        );
        let message = self.wire[..o.yielded.wire_len as usize].to_vec();
        let mut i: EmitIn = z();
        i.framing = self.framing;
        i.stream = stream;
        i.bytes = message.as_ptr();
        i.len = message.len();
        i.end_of_frame = 1;
        i.sink = self.sink();
        let mut o: FramerOut = z();
        let mut got = Vec::new();
        // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
        // and the door instance for this synchronous call; the selected slot and index agree.
        let r = unsafe { call(self.ops.emit, self.inst, &mut i, &mut o, slot::EMIT) };
        assert_eq!(self.take(r, &o, &mut got), Outcome::Ready);
        assert_eq!(self.drain(slot::EMIT, stream, &mut got), Outcome::Ready);
        got
    }

    /// `encode` an envelope carrying one extra field `name` = `v`; the outcome only.
    fn encode_with_field(&mut self, name: &'static str) -> Outcome {
        let fields = [
            Field {
                name: s("authorization"),
                value: s("Bearer sk-test"),
            },
            Field {
                name: s(name),
                value: s("v"),
            },
        ];
        let mut i: EncodeIn = z();
        i.fields = fields.as_ptr();
        i.fields_len = fields.len();
        i.body = "".as_ptr();
        i.body_len = 0;
        i.sink = self.sink();
        i.sink.wire_cap = self.wire.len();
        let mut o: FramerOut = z();
        // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
        // and the door instance for this synchronous call; the selected slot and index agree.
        unsafe { call(self.ops.encode, self.inst, &mut i, &mut o, slot::ENCODE) }
    }

    /// Ingest whatever the far end sends until `done` holds of what was handed up (the explicit
    fn pump_until(&mut self, done: impl Fn(&[Got]) -> bool, got: &mut Vec<Got>) -> Outcome {
        let deadline = std::time::Instant::now() + PUMP_DEADLINE;
        while !done(got) {
            assert!(
                std::time::Instant::now() < deadline,
                "the far end did not get there in {PUMP_DEADLINE:?}"
            );
            if let Some(outcome) = self.pump_once(got) {
                return outcome;
            }
        }
        Outcome::Ready
    }

    /// Ingest whatever the far end has sent until it stays quiet for `quiet` (for a cell that
    fn pump(&mut self, quiet: Duration, got: &mut Vec<Got>) -> Outcome {
        let mut idle = Duration::ZERO;
        let step = Duration::from_millis(10);
        while idle < quiet {
            let (bytes, end) = {
                let mut g = self.sock.rx.lock().expect("rx");
                (g.0.drain(..).collect::<Vec<u8>>(), g.1)
            };
            if bytes.is_empty() && !end {
                std::thread::sleep(step);
                idle += step;
                continue;
            }
            idle = Duration::ZERO;
            let mut i: IngestIn = z();
            i.framing = self.framing;
            i.bytes = bytes.as_ptr();
            i.len = bytes.len();
            i.end = u32::from(end);
            i.sink = self.sink();
            let mut o: FramerOut = z();
            // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
            // and the door instance for this synchronous call; the selected slot and index agree.
            let r = unsafe { call(self.ops.ingest, self.inst, &mut i, &mut o, slot::INGEST) };
            if self.take(r, &o, got) != Outcome::Ready {
                return r;
            }
            let r = self.drain(slot::INGEST, 0, got);
            if r != Outcome::Ready {
                return r;
            }
            if end {
                break;
            }
        }
        Outcome::Ready
    }

    /// One pass of [`Host::pump`]: `None` when the far end sent nothing yet (after a short wait),
    fn pump_once(&mut self, got: &mut Vec<Got>) -> Option<Outcome> {
        let (bytes, end) = {
            let mut g = self.sock.rx.lock().expect("rx");
            (g.0.drain(..).collect::<Vec<u8>>(), g.1)
        };
        if bytes.is_empty() && !end {
            std::thread::sleep(Duration::from_millis(10));
            return None;
        }
        self.heard_log.extend_from_slice(&bytes);
        let mut i: IngestIn = z();
        i.framing = self.framing;
        i.bytes = bytes.as_ptr();
        i.len = bytes.len();
        i.end = u32::from(end);
        i.sink = self.sink();
        let mut o: FramerOut = z();
        // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
        // and the door instance for this synchronous call; the selected slot and index agree.
        let r = unsafe { call(self.ops.ingest, self.inst, &mut i, &mut o, slot::INGEST) };
        if self.take(r, &o, got) != Outcome::Ready {
            return Some(r);
        }
        let r = self.drain(slot::INGEST, 0, got);
        if r != Outcome::Ready {
            return Some(r);
        }
        end.then_some(Outcome::Ready)
    }

    /// Move the clock to `at` and call `timer` if the framer asked for a deadline by then.
    fn advance(&mut self, at: u64, got: &mut Vec<Got>) -> Outcome {
        self.now = at;
        if self.deadline.is_some_and(|d| d <= at) {
            let mut i: FramingIn = z();
            i.framing = self.framing;
            i.sink = self.sink();
            let mut o: FramerOut = z();
            // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
            // and the door instance for this synchronous call; the selected slot and index agree.
            let r = unsafe { call(self.ops.timer, self.inst, &mut i, &mut o, slot::TIMER) };
            if self.take(r, &o, got) != Outcome::Ready {
                return r;
            }
            return self.drain(slot::TIMER, 0, got);
        }
        Outcome::Ready
    }

    /// PING ACK frames the far end has sent (HTTP/2).
    fn acks(&self) -> usize {
        let log = &self.heard_log;
        let (mut i, mut k) = (0, 0);
        while i + 9 <= log.len() {
            let len =
                usize::from(log[i]) << 16 | usize::from(log[i + 1]) << 8 | usize::from(log[i + 2]);
            if log[i + 3] == 6 && log[i + 4] & 1 != 0 {
                k += 1;
            }
            i += 9 + len;
        }
        k
    }

    /// Ingest until the far end has answered every PING the framer wrote (HTTP/2).
    fn pump_acks(&mut self, got: &mut Vec<Got>) {
        let deadline = std::time::Instant::now() + PUMP_DEADLINE;
        while self.acks() < self.pings() {
            assert!(
                std::time::Instant::now() < deadline,
                "the far end did not answer its pings in {PUMP_DEADLINE:?}"
            );
            if self.pump_once(got).is_some_and(|r| r != Outcome::Ready) {
                break;
            }
        }
    }

    /// Non-ACK PING frames the framer has written (HTTP/2, after the 24-byte preface).
    fn pings(&self) -> usize {
        let log = &self.wire_log;
        let (mut i, mut k) = (24, 0);
        while i + 9 <= log.len() {
            let len =
                usize::from(log[i]) << 16 | usize::from(log[i + 1]) << 8 | usize::from(log[i + 2]);
            if log[i + 3] == 6 && log[i + 4] & 1 == 0 {
                k += 1;
            }
            i += 9 + len;
        }
        k
    }

    fn close(self) {
        let mut i: InHead = z();
        let mut o: OutHead = z();
        // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
        // and the door instance for this synchronous call; the selected slot and index agree.
        unsafe { call(self.ops.head.close, self.inst, &mut i, &mut o, life::CLOSE) };
    }
}

/// How long [`Host::pump_until`] waits for the far end, however loaded the runner.
const PUMP_DEADLINE: Duration = Duration::from_secs(30);

/// A head frame was handed up.
fn has_head(got: &[Got]) -> bool {
    got.iter().any(|g| g.flags & PIECE_HAS_CODE != 0)
}

fn text(got: &[Got], stream: u64) -> String {
    got.iter()
        .filter(|g| g.stream == stream && g.code == 0)
        .map(|g| String::from_utf8_lossy(&g.bytes).into_owned())
        .collect()
}

/// The stream ended whole: its framer SAID so (`PIECE_END`, on an empty piece that ends its frame).
fn ended(got: &[Got], stream: u64) -> bool {
    got.iter().any(|g| {
        g.stream == stream
            && g.flags & PIECE_END != 0
            && g.bytes.is_empty()
            && g.flags & PIECE_END_OF_FRAME != 0
    })
}

#[derive(Clone, Copy, PartialEq)]
enum Case {
    /// Cleartext, no protocol agreed, the prior-knowledge key on: HTTP/2.
    H2cPriorKnowledge,
    /// Connection security agreed `h2`.
    AlpnH2,
    /// HTTP/2 with the far end gone silent: the keep-alive timeout.
    KeepAliveTimeout,
    /// Connection security agreed `http/1.1` (the http1-only key's offer).
    Http1Only,
}

fn scenario(label: &str, ops: &'static Ops, rt: &tokio::runtime::Runtime, case: Case) {
    assert!(
        tokio::runtime::Handle::try_current().is_err(),
        "the framer is driven outside any runtime"
    );
    let h2 = case != Case::Http1Only;
    let sock = serve(rt, h2);
    let (settings, agreed) = match case {
        Case::H2cPriorKnowledge | Case::KeepAliveTimeout => {
            (r#"{"advanced.upstream_h2_prior_knowledge":true}"#, "")
        }
        Case::AlpnH2 => ("{}", "h2"),
        Case::Http1Only => (r#"{"advanced.upstream_http1_only":true}"#, "http/1.1"),
    };
    let mut host = Host::open(ops, settings, sock.clone(), ROOMY);
    host.begin(agreed);
    let t0 = host.now;
    let mut got = host.ask(1, "/v1/messages", "hello");
    assert_eq!(
        host.pump_until(|g| text(g, 1) == "got=5;a", &mut got),
        Outcome::Ready
    );
    let head = got
        .iter()
        .find(|g| g.flags & PIECE_HAS_CODE != 0)
        .expect("a head frame");
    println!("PROOF {label}: HEAD {}", head.code);
    assert_eq!((head.stream, head.code), (1, 200));

    assert_eq!(
        (head.status_class, head.fault, head.retry_after_secs),
        (STATUS_SUCCESS, FAULT_NONE, 0),
        "{label}: the 200 head's class, fault reading and retry-after"
    );

    assert_ne!(head.flags & PIECE_FIELDS, 0, "the head is a fields piece");

    assert_eq!(head.declared_len, None, "{label}: no declared length");
    let block = String::from_utf8_lossy(&head.bytes).into_owned();
    assert!(!block.starts_with("HTTP/"), "{block}");

    let reason: &[(u64, Vec<u8>)] = if case == Case::Http1Only {
        &[(1, b"OK".to_vec())]
    } else {
        &[]
    };
    assert_eq!(host.reasons, reason, "{label}");
    assert!(
        block.split_terminator("\r\n").all(|l| l.contains(": ")
            && l.split(": ")
                .next()
                .is_some_and(|n| n == n.to_ascii_lowercase())),
        "{block}"
    );
    println!("PROOF {label}: body so far {:?}", text(&got, 1));
    assert_eq!(text(&got, 1), "got=5;a");
    assert!(!ended(&got, 1), "the stalled response is not whole");

    if h2 {
        host.pump_acks(&mut got);
        let p0 = host.pings();
        if case == Case::KeepAliveTimeout {
            sock.silent.store(true, Ordering::SeqCst);
        }
        assert_eq!(host.advance(t0 + 29 * SEC, &mut got), Outcome::Ready);
        let p29 = host.pings();
        assert_eq!(
            host.advance(t0 + 30 * SEC + SEC / 2, &mut got),
            Outcome::Ready
        );
        host.pump(Duration::from_millis(200), &mut got);
        let p30 = host.pings();
        println!("PROOF {label}: keep-alive pings before={p0} at_29s={p29} at_30.5s={p30}");
        assert!(p0 >= 1, "the adaptive window pinged when data arrived");
        assert_eq!(p29, p0, "no keep-alive ping before 30s");
        assert_eq!(p30, p0 + 1, "one keep-alive ping at 30s");
        if case == Case::KeepAliveTimeout {
            assert_eq!(
                host.advance(t0 + 39 * SEC, &mut got),
                Outcome::Ready,
                "not before 10s"
            );
            let r = host.advance(t0 + 41 * SEC, &mut got);
            println!("PROOF {label}: at 41s the timer op answers {r:?}");
            assert_eq!(
                r,
                Outcome::Failed,
                "the unanswered ping fails the connection"
            );
            host.close();
            return;
        }
    }
    rt.block_on(sock.release.send(())).expect("release");
    host.pump_until(|g| ended(g, 1), &mut got);
    println!(
        "PROOF {label}: body {:?}, whole={}",
        text(&got, 1),
        ended(&got, 1)
    );
    assert_eq!(text(&got, 1), "got=5;abc");
    assert!(ended(&got, 1));
    host.close();
}

fn linked() -> &'static Ops {
    let d = busbar_transport_http_plugin::door::door();
    // SAFETY: the door's `'static` table.
    unsafe { &*(*d).ops().cast::<Ops>() }
}

fn dropped() -> (&'static Ops, &'static libloading::Library) {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let file = busbar_plugin_loader::plugin_library_filename("busbar_transport_http_plugin");
    let path = match std::env::var_os("BUSBAR_PLUGIN_CDYLIB") {
        Some(path) => {
            let path = std::path::PathBuf::from(path);
            assert!(path.is_absolute(), "BUSBAR_PLUGIN_CDYLIB must be absolute");
            path
        }
        None => profile.join(file),
    };
    assert!(
        path.is_file(),
        "build this product's actual cdylib before testing: {}",
        path.display()
    );
    // SAFETY: our own cdylib, built by this `cargo test`.
    let lib: &'static libloading::Library = Box::leak(Box::new(
        unsafe { libloading::Library::new(path) }.expect("load"),
    ));
    // SAFETY: the one exported symbol, a `DoorFn`.
    let door: libloading::Symbol<'_, extern "C" fn() -> *const Door> =
        unsafe { lib.get(DOOR_SYMBOL) }.expect("the door symbol");
    let d = door();
    // SAFETY: the dropped-in door's `'static` table.
    (unsafe { &*(*d).ops().cast::<Ops>() }, lib)
}

#[test]
fn the_linked_and_the_dropped_in_door_frame_the_same() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let l = linked();
    let (d, _lib) = dropped();
    assert!(
        !std::ptr::eq(l, d),
        "two images: the linked table and the dropped-in one"
    );
    for (image, ops) in [("linked", l), ("dropped", d)] {
        for (name, case) in [
            ("h2c-prior-knowledge", Case::H2cPriorKnowledge),
            ("alpn-h2", Case::AlpnH2),
            ("h2-keepalive-timeout", Case::KeepAliveTimeout),
            ("http1-only", Case::Http1Only),
        ] {
            scenario(&format!("{image} {name}"), ops, &rt, case);
        }
    }
}

/// Two requests on ONE HTTP/2 connection: the one whose head never comes fails ALONE, at the
fn one_stream_fails_alone(label: &str, ops: &'static Ops, rt: &tokio::runtime::Runtime) {
    let sock = serve(rt, true);
    let mut host = Host::open(
        ops,
        r#"{"advanced.upstream_h2_prior_knowledge":true,"limits.upstream_request_timeout_secs":5}"#,
        sock.clone(),
        ROOMY,
    );
    host.begin("");
    let t0 = host.now;
    let mut got = host.ask(1, "/hang", "");
    got.extend(host.ask(3, "/v1/messages", "hello"));
    assert_eq!(
        host.pump_until(|g| text(g, 3) == "got=5;a", &mut got),
        Outcome::Ready
    );
    assert_eq!(text(&got, 3), "got=5;a", "the sibling answered");
    assert_eq!(host.advance(t0 + 4 * SEC, &mut got), Outcome::Ready);
    assert!(
        !got.iter().any(|g| g.flags & PIECE_STREAM_FAILED != 0),
        "not before 5s"
    );
    rt.block_on(sock.release.send(())).expect("release");
    host.pump_until(|g| ended(g, 3), &mut got);
    println!(
        "PROOF {label}: stream 3 {:?}, whole={}",
        text(&got, 3),
        ended(&got, 3)
    );
    assert_eq!(text(&got, 3), "got=5;abc");
    assert!(ended(&got, 3));
    assert_eq!(
        host.advance(t0 + 5 * SEC + SEC / 10, &mut got),
        Outcome::Ready,
        "the connection lives"
    );
    let failed: Vec<&Got> = got
        .iter()
        .filter(|g| g.flags & PIECE_STREAM_FAILED != 0)
        .collect();
    assert_eq!(failed.len(), 1, "one stream failed");
    println!(
        "PROOF {label}: stream {} failed alone: {:?}",
        failed[0].stream,
        String::from_utf8_lossy(&failed[0].bytes)
    );
    assert_eq!(failed[0].stream, 1);
    assert_eq!(
        failed[0].bytes,
        b"the request timeout passed before the response was whole"
    );
    assert!(failed[0].flags & PIECE_END_OF_FRAME != 0);
    host.close();
}

/// The wire and frame bytes of one exchange, as the host collected them.
fn exchange(ops: &'static Ops, rt: &tokio::runtime::Runtime, caps: Caps) -> (Vec<u8>, Vec<u8>) {
    let sock = serve(rt, true);
    let mut host = Host::open(
        ops,
        r#"{"advanced.upstream_h2_prior_knowledge":true}"#,
        sock.clone(),
        caps,
    );
    host.begin("");
    let mut got = host.ask(1, "/v1/messages", "hello");
    host.pump_until(|g| text(g, 1) == "got=5;a", &mut got);
    rt.block_on(sock.release.send(())).expect("release");
    host.pump_until(|g| ended(g, 1), &mut got);
    assert!(ended(&got, 1), "the exchange completed");

    let mut mid_line = false;
    for g in got.iter().filter(|g| g.flags & PIECE_FIELDS != 0) {
        assert_eq!(
            g.flags & PIECE_CONTINUED != 0,
            mid_line,
            "{:?}",
            String::from_utf8_lossy(&g.bytes)
        );
        mid_line = g.flags & PIECE_END_OF_FRAME == 0 && !g.bytes.ends_with(b"\n");
    }

    let mut frames = host.frame_log.clone();
    if let Some(at) = frames.windows(6).position(|w| w == b"date: ") {
        let end = at
            + frames[at..]
                .windows(2)
                .position(|w| w == b"\r\n")
                .expect("a line")
            + 2;
        frames.drain(at..end);
    }
    let out = (stable_h2_wire(&host.wire_log), frames);
    host.close();
    out
}

/// Compare every request and connection-setup byte while allowing PING and WINDOW_UPDATE
fn stable_h2_wire(wire: &[u8]) -> Vec<u8> {
    const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    assert!(
        wire.starts_with(PREFACE),
        "an h2 exchange starts with its preface"
    );
    let mut stable = PREFACE.to_vec();
    let mut at = PREFACE.len();
    while at < wire.len() {
        assert!(wire.len() - at >= 9, "a complete frame header is retained");
        let len = (usize::from(wire[at]) << 16)
            | (usize::from(wire[at + 1]) << 8)
            | usize::from(wire[at + 2]);
        let end = at + 9 + len;
        assert!(end <= wire.len(), "a complete frame payload is retained");
        match wire[at + 3] {
            6 => {
                assert_eq!(len, 8, "a PING is eight bytes");
                assert_eq!(
                    &wire[at + 5..at + 9],
                    &[0; 4],
                    "a PING is connection-scoped"
                );
            }
            8 => assert_eq!(len, 4, "a WINDOW_UPDATE is four bytes"),
            _ => stable.extend_from_slice(&wire[at..end]),
        }
        at = end;
    }
    stable
}

/// The re-call rule's check: an exchange collected through a sink so small that every op is
fn recall_continues(tight: &(Vec<u8>, Vec<u8>), roomy: &(Vec<u8>, Vec<u8>)) -> Result<(), String> {
    if tight.0 != roomy.0 {
        return Err(format!(
            "wire differs: {} bytes vs {}",
            tight.0.len(),
            roomy.0.len()
        ));
    }
    if tight.1 != roomy.1 {
        return Err(format!(
            "frames differ: {} bytes vs {}",
            tight.1.len(),
            roomy.1.len()
        ));
    }
    Ok(())
}

#[test]
fn one_h2_stream_fails_alone_linked_and_dropped() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let (d, _lib) = dropped();
    one_stream_fails_alone("linked", linked(), &rt);
    one_stream_fails_alone("dropped", d, &rt);
}

/// A `429` with `retry-after: 7` reaches the host as a head whose piece states the caller-fault
#[test]
fn a_429_head_states_its_class_fault_and_retry_after() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let (d, _lib) = dropped();
    for (label, ops) in [("linked", linked()), ("dropped", d)] {
        let sock = serve(&rt, true);
        let mut host = Host::open(
            ops,
            r#"{"advanced.upstream_h2_prior_knowledge":true}"#,
            sock,
            ROOMY,
        );
        host.begin("");
        let mut got = host.ask(1, "/limited", "hello");
        assert_eq!(host.pump_until(has_head, &mut got), Outcome::Ready);
        let head = got
            .iter()
            .find(|g| g.flags & PIECE_HAS_CODE != 0)
            .expect("a head frame");
        assert_eq!(head.code, 429, "{label}");
        assert_eq!(
            (head.status_class, head.fault, head.retry_after_secs),
            (STATUS_CALLER_FAULT, FAULT_TRANSIENT, 7),
            "{label}: the 429 head's class, fault reading and retry-after"
        );
        host.close();
    }
}

#[test]
fn a_yield_more_recall_answers_nothing_twice() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let (d, _lib) = dropped();
    for (image, ops) in [("linked", linked()), ("dropped", d)] {
        let roomy = exchange(ops, &rt, ROOMY);
        let tight = exchange(ops, &rt, TIGHT);
        println!(
            "PROOF {image}: re-called exchange wire={} frame={} bytes, same as roomy: {:?}",
            tight.0.len(),
            tight.1.len(),
            recall_continues(&tight, &roomy)
        );
        assert_eq!(recall_continues(&tight, &roomy), Ok(()));

        let mut dup = tight.clone();
        let first = dup.1[..5].to_vec();
        dup.1.splice(5..5, first);
        assert!(
            recall_continues(&dup, &roomy).is_err(),
            "a duplicated piece is caught"
        );

        let mut dup = tight.clone();
        assert!(!dup.0.is_empty(), "the exchange wrote wire bytes");
        let at = dup.0.len().min(5);
        let first = dup.0[..at].to_vec();
        dup.0.splice(at..at, first);
        assert!(
            recall_continues(&dup, &roomy).is_err(),
            "a duplicated run of wire bytes is caught"
        );
    }
}

/// A field name that is not an RFC 9110 token (`authorization:x`) would be re-read as a second
#[test]
fn a_non_token_field_name_fails_encode_through_the_door() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let (d, _lib) = dropped();
    for ops in [linked(), d] {
        let sock = serve(&rt, true);
        let mut host = Host::open(
            ops,
            r#"{"advanced.upstream_h2_prior_knowledge":true}"#,
            sock,
            ROOMY,
        );
        host.begin("");
        assert_eq!(host.encode_with_field("x-ok"), Outcome::Ready);
        for bad in ["authorization:x", "a b", ""] {
            assert_eq!(host.encode_with_field(bad), Outcome::Failed, "{bad:?}");
        }
        host.close();
    }
}

/// One accepted connection driven through the table as the connector drives it: the host hands the
struct AcceptHost {
    ops: &'static Ops,
    inst: *mut c_void,
    framing: u64,
    wire: Vec<u8>,
    frame: Vec<u8>,
    pieces: Vec<FramePiece>,
    heads: Vec<HeadSlots>,
    /// Every wire byte the framer owed the far side.
    out: Vec<u8>,
    /// Every request piece: (stream, bytes, flags), and every head slot's method and target.
    got: Vec<(u64, Vec<u8>, u16)>,
    words: Vec<(u64, Vec<u8>, Vec<u8>)>,
    /// The listener's guest list, lent for the framing's life (`BeginIn::lines`).
    lines: Box<[LineEntry]>,
    /// The scripted kernel's context: the key of this host's [`Script`].
    ctx: u64,
    /// The ticket `begin`, `ingest` and `emit` run on, as the host tickets them (`timer` and
    ticket: Ticket,
    /// An answer said the connection is over (`YIELD_ENDED`).
    ended: bool,
    /// The host's monotonic clock, as the sink states it.
    now: u64,
    /// The protocol the last answer stated it agreed (`FramerYield::agreed`).
    agreed: u32,
}

impl AcceptHost {
    fn begin_policy_again(&mut self, policy: &[u8], flags: u32) -> Outcome {
        let mut i: BeginIn = z();
        i.head.ticket = self.ticket;
        i.head.flags = flags;
        i.head.extensions = Blob {
            ptr: policy.as_ptr(),
            len: policy.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        };
        i.side = SIDE_ACCEPT;
        i.scheme = SCHEME_PLAIN;
        i.lines = self.lines.as_ptr();
        i.lines_len = self.lines.len();
        i.sink = self.sink();
        let mut o: FramerOut = z();
        // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
        // and the door instance for this synchronous call; the selected slot and index agree.
        let result = unsafe { call(self.ops.begin, self.inst, &mut i, &mut o, slot::BEGIN) };
        if result == Outcome::Ready {
            self.framing = o.framing;
        }
        self.take(result, &o)
    }

    fn ingest_policy(
        &mut self,
        bytes: &[u8],
        policy: &[u8],
        flags: u32,
    ) -> (
        Outcome,
        Option<busbar_contract::abi::transport::guest_policy::Open>,
    ) {
        use busbar_contract::abi::{
            mechanism::{extensions, lifecycle::ReleaseIn},
            transport::guest_policy,
        };
        let mut i: IngestIn = z();
        i.head.ticket = self.ticket;
        i.head.flags = flags;
        i.head.extensions = Blob {
            ptr: policy.as_ptr(),
            len: policy.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        };
        i.framing = self.framing;
        i.bytes = bytes.as_ptr();
        i.len = bytes.len();
        i.sink = self.sink();
        let mut o: FramerOut = z();
        // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
        // and the door instance for this synchronous call; the selected slot and index agree.
        let result = unsafe { call(self.ops.ingest, self.inst, &mut i, &mut o, slot::INGEST) };
        // SAFETY: the answer lease is still live; copy before releasing its bytes below.
        let extension = unsafe { bytes_of(o.head.extensions.ptr, o.head.extensions.len) };
        let request = extensions::get(&extension, guest_policy::EXT_GUEST_OPEN)
            .map(|v| guest_policy::Open::decode(v).unwrap());
        if request.is_some() {
            assert_eq!(result, Outcome::Ready);
            assert_ne!(o.yielded.flags & YIELD_MORE, 0);
            assert_eq!(
                (
                    o.yielded.wire_len,
                    o.yielded.frame_len,
                    o.yielded.pieces_len
                ),
                (0, 0, 0)
            );
        }
        let result = self.take(result, &o);
        if o.head.lease != 0 {
            let mut release: ReleaseIn = z();
            release.lease = o.head.lease;
            let mut out: OutHead = z();
            assert_eq!(
                // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
                // and the door instance for this synchronous call; the selected slot and index agree.
                unsafe {
                    call(
                        self.ops.head.release,
                        self.inst,
                        &mut release,
                        &mut out,
                        life::RELEASE,
                    )
                },
                Outcome::Ready
            );
        }
        (result, request)
    }

    /// An accepted connection on a listener whose one line takes every `POST /v1/messages` with
    fn open(ops: &'static Ops) -> Self {
        Self::open_with(
            ops,
            vec![line(1, 0, METHOD_ANY, "/v1/messages", 0)],
            Script::default(),
        )
    }

    /// An accepted connection on a listener with guest list `lines`, the auth handle answered by
    fn open_with(ops: &'static Ops, lines: Vec<LineEntry>, script: Script) -> Self {
        Self::open_on(ops, lines, script, |_| {}, SCHEME_PLAIN)
    }

    /// [`AcceptHost::open_with`] on a connection whose `ConnFacts` `facts` fills, as the host's
    fn open_on(
        ops: &'static Ops,
        lines: Vec<LineEntry>,
        script: Script,
        facts: fn(&mut ConnFacts),
        scheme: u8,
    ) -> Self {
        let (host, result) = Self::open_on_policy(ops, lines, script, facts, scheme, &[]);
        assert_eq!(result, Outcome::Ready, "begin on the accepted side");
        host
    }

    fn open_on_policy(
        ops: &'static Ops,
        lines: Vec<LineEntry>,
        script: Script,
        facts: fn(&mut ConnFacts),
        scheme: u8,
        policy: &[u8],
    ) -> (Self, Outcome) {
        Self::open_in(ops, None, lines, script, facts, scheme, policy)
    }

    /// A second accepted connection on the SAME open instance as `first` (and so the same script),
    /// under guest list `lines`: the instance's kept lists are met again.
    fn open_again(first: &Self, lines: Vec<LineEntry>) -> Self {
        let (host, result) = Self::open_in(
            first.ops,
            Some((first.inst, first.ctx)),
            lines,
            Script::default(),
            |_| {},
            SCHEME_PLAIN,
            &[],
        );
        assert_eq!(result, Outcome::Ready, "begin again on the same instance");
        host
    }

    /// [`AcceptHost::open_on`] on `existing` (an open instance and its context) when given, else on
    /// a fresh instance.
    fn open_in(
        ops: &'static Ops,
        existing: Option<(*mut c_void, u64)>,
        lines: Vec<LineEntry>,
        script: Script,
        facts: fn(&mut ConnFacts),
        scheme: u8,
        policy: &[u8],
    ) -> (Self, Outcome) {
        let state = facts;
        let (instance, ctx) = match existing {
            Some(on) => on,
            None => {
                let ctx = NEXT_CTX.fetch_add(1, Ordering::SeqCst);
                scripts().insert(ctx, script);
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
                    // SAFETY: the host owns matching ABI frames, nested buffers and table.
                    unsafe {
                        call(
                            ops.head.open,
                            std::ptr::null_mut(),
                            &mut i,
                            &mut o,
                            life::OPEN,
                        )
                    },
                    Outcome::Ready
                );
                (o.instance, ctx)
            }
        };
        let mut h = Self {
            ops,
            inst: instance,
            framing: 0,
            wire: vec![0; 64 * 1024],
            frame: vec![0; 64 * 1024],
            pieces: vec![z(); 64],
            heads: vec![HeadSlots::default(); 4],
            out: Vec::new(),
            got: Vec::new(),
            words: Vec::new(),
            lines: lines.into_boxed_slice(),
            ctx,
            ticket: TICKET,
            ended: false,
            now: 7 * SEC,
            agreed: 0,
        };
        let mut facts: ConnFacts = z();
        facts.size = size_of::<ConnFacts>() as u32;
        state(&mut facts);
        let mut i: BeginIn = z();
        i.head.ticket = h.ticket;
        i.head.extensions = Blob {
            ptr: policy.as_ptr(),
            len: policy.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        };
        i.side = SIDE_ACCEPT;

        i.scheme = scheme;
        i.facts = &facts;
        i.lines = h.lines.as_ptr();
        i.lines_len = h.lines.len();
        i.sink = h.sink();
        let mut o: FramerOut = z();
        // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
        // and the door instance for this synchronous call; the selected slot and index agree.
        let r = unsafe { call(ops.begin, h.inst, &mut i, &mut o, slot::BEGIN) };
        h.framing = o.framing;
        let r = h.take(r, &o);
        (h, r)
    }

    fn sink(&mut self) -> FramerSink {
        FramerSink {
            wire: self.wire.as_mut_ptr(),
            wire_cap: self.wire.len(),
            frame: self.frame.as_mut_ptr(),
            frame_cap: self.frame.len(),
            pieces: self.pieces.as_mut_ptr(),
            pieces_cap: self.pieces.len(),
            now_monotonic_ns: self.now,
            now_unix_ns: 1_790_000_000 * SEC,
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
        self.agreed = o.yielded.agreed;
        let frame = self.frame[..o.yielded.frame_len as usize].to_vec();
        check_framer_fields(&self.pieces[..n], &frame).expect("no pseudo-field in a field block");
        check_head_slots(o, &self.heads, self.heads.len() as u64).expect("the head slots pass");
        for h in &self.heads[..o.yielded.heads_len as usize] {
            let at = |s: busbar_contract::abi::transport::FrameSpan| {
                frame[s.offset as usize..(s.offset + s.len) as usize].to_vec()
            };
            self.words.push((h.stream, at(h.method), at(h.target)));
        }
        self.out
            .extend_from_slice(&self.wire[..o.yielded.wire_len as usize]);
        self.ended |= o.yielded.flags & YIELD_ENDED != 0;
        for p in &self.pieces[..n] {
            self.got.push((
                p.stream,
                frame[p.offset as usize..(p.offset + p.len) as usize].to_vec(),
                p.flags,
            ));
        }
        r
    }

    fn ingest(&mut self, bytes: &[u8]) -> Outcome {
        self.ingest_with(bytes, 0)
    }

    /// `ingest` with head flags `flags` (`FLAG_RESUME`: the host re-issuing the op that answered
    fn ingest_with(&mut self, bytes: &[u8], flags: u32) -> Outcome {
        let mut i: IngestIn = z();
        i.head.ticket = self.ticket;
        i.head.flags = flags;
        i.framing = self.framing;
        i.bytes = bytes.as_ptr();
        i.len = bytes.len();
        i.sink = self.sink();
        let mut o: FramerOut = z();
        // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
        // and the door instance for this synchronous call; the selected slot and index agree.
        let r = unsafe { call(self.ops.ingest, self.inst, &mut i, &mut o, slot::INGEST) };
        self.take(r, &o)
    }

    fn emit(&mut self, stream: u64, bytes: &[u8], end: bool, status: u32) -> Outcome {
        self.emit_with(stream, bytes, end, status, 0).0
    }

    /// `emit` with head flags `flags` (`FLAG_RESUME`: the host re-issuing the op that answered
    fn emit_with(
        &mut self,
        stream: u64,
        bytes: &[u8],
        end: bool,
        status: u32,
        flags: u32,
    ) -> (Outcome, u32) {
        let mut i: EmitIn = z();
        i.head.ticket = self.ticket;
        i.head.flags = flags;
        i.framing = self.framing;
        i.stream = stream;
        i.bytes = bytes.as_ptr();
        i.len = bytes.len();
        i.end_of_frame = u32::from(end);
        i.status = status;
        i.sink = self.sink();
        let mut o: FramerOut = z();
        // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
        // and the door instance for this synchronous call; the selected slot and index agree.
        let r = unsafe { call(self.ops.emit, self.inst, &mut i, &mut o, slot::EMIT) };
        (self.take(r, &o), o.yielded.flags)
    }

    /// `refuse`: `bytes` for `stream` (`None`: the whole connection), with the neutral `status`
    fn refuse(
        &mut self,
        stream: Option<u64>,
        bytes: &[u8],
        status: u32,
        head_sent: bool,
    ) -> Outcome {
        let mut first = true;
        loop {
            let mut i: RefuseIn = z();
            i.framing = self.framing;
            i.stream = stream.unwrap_or(0);
            i.has_stream = u32::from(stream.is_some());
            let b: &[u8] = if first { bytes } else { &[] };
            i.bytes = b.as_ptr();
            i.len = b.len();
            i.status = status;
            i.head_sent = u32::from(head_sent);
            i.sink = self.sink();
            let mut o: FramerOut = z();
            // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
            // and the door instance for this synchronous call; the selected slot and index agree.
            let r = unsafe { call(self.ops.refuse, self.inst, &mut i, &mut o, slot::REFUSE) };
            let more = o.yielded.flags & YIELD_MORE != 0;
            let r = self.take(r, &o);
            if r != Outcome::Ready || !more {
                return r;
            }
            first = false;
        }
    }

    /// `detach`, on no ticket, re-called while it answers `YIELD_MORE`: its outcome and every
    fn detach(&mut self) -> (Outcome, Vec<u8>) {
        let mut handed = Vec::new();
        loop {
            let mut i: FramingIn = z();
            i.framing = self.framing;
            i.sink = self.sink();
            let mut o: FramerOut = z();
            // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
            // and the door instance for this synchronous call; the selected slot and index agree.
            let r = unsafe { call(self.ops.detach, self.inst, &mut i, &mut o, slot::DETACH) };
            let more = o.yielded.flags & YIELD_MORE != 0;
            let frame = self.frame[..o.yielded.frame_len as usize].to_vec();
            let r = self.take(r, &o);
            handed.extend_from_slice(&frame);
            if r != Outcome::Ready || !more {
                return (r, handed);
            }
        }
    }

    /// `cancel` of the op on `ticket`: its disposition.
    fn cancel(&mut self, ticket: Ticket) -> u32 {
        let mut i: CancelIn = z();
        i.ticket = ticket;
        let mut o: CancelOut = z();
        assert_eq!(
            // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
            // and the door instance for this synchronous call; the selected slot and index agree.
            unsafe {
                call(
                    self.ops.head.cancel,
                    self.inst,
                    &mut i,
                    &mut o,
                    life::CANCEL,
                )
            },
            Outcome::Ready
        );
        o.disposition
    }

    /// `timer`, on no ticket: the connector crosses it on a blank `in` (it never pends).
    fn timer(&mut self) -> Outcome {
        let mut i: FramingIn = z();
        i.framing = self.framing;
        i.sink = self.sink();
        let mut o: FramerOut = z();
        // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
        // and the door instance for this synchronous call; the selected slot and index agree.
        let r = unsafe { call(self.ops.timer, self.inst, &mut i, &mut o, slot::TIMER) };
        self.take(r, &o)
    }

    /// The tickets the door's `auth.call`s were issued under, in order.
    fn tickets(&self) -> Vec<Ticket> {
        scripts()[&self.ctx].tickets.clone()
    }

    /// The completion sequence numbers the door's `auth.call`s were issued under, in order.
    fn seqs(&self) -> Vec<u32> {
        scripts()[&self.ctx].seqs.clone()
    }

    /// Every call the door made on the auth handle, in order.
    fn asked(&self) -> Vec<Asked> {
        scripts()[&self.ctx].asked.clone()
    }

    /// The request head pieces that went up.
    fn heads_up(&self) -> usize {
        self.got.iter().filter(|g| g.2 & PIECE_FIELDS != 0).count()
    }

    fn close(self) {
        let mut i: InHead = z();
        let mut o: OutHead = z();
        // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
        // and the door instance for this synchronous call; the selected slot and index agree.
        unsafe { call(self.ops.head.close, self.inst, &mut i, &mut o, life::CLOSE) };
        scripts().remove(&self.ctx);
    }
}

/// The wire bytes with the `date` line (the second hyper answered in) taken out.
fn undated(mut wire: Vec<u8>) -> Vec<u8> {
    if let Some(at) = wire.windows(6).position(|w| w == b"date: ") {
        let end = at
            + wire[at..]
                .windows(2)
                .position(|w| w == b"\r\n")
                .expect("a line")
            + 2;
        wire.drain(at..end);
    }
    wire
}

/// One request answered through the door's accepted side: the answer's wire bytes, undated.
fn answered(label: &str, ops: &'static Ops) -> Vec<u8> {
    let mut h = AcceptHost::open(ops);
    assert_eq!(
        h.ingest(b"POST /v1/messages?beta=1 HTTP/1.1\r\nhost: busbar.test\r\ncontent-length: 5\r\ncontent-type: application/json\r\n\r\nhello"),
        Outcome::Ready
    );
    assert_eq!(
        h.words,
        vec![(1, b"POST".to_vec(), b"/v1/messages?beta=1".to_vec())],
        "{label}: the request's method and target are head slots"
    );
    let head = h
        .got
        .iter()
        .find(|g| g.2 & PIECE_FIELDS != 0)
        .expect("a head")
        .1
        .clone();
    assert_eq!(
        String::from_utf8_lossy(&head),
        "host: busbar.test\r\ncontent-length: 5\r\ncontent-type: application/json\r\n",
        "{label}: the exact admitted field block retains content-length"
    );
    let body: Vec<u8> = h
        .got
        .iter()
        .filter(|g| g.2 & PIECE_FIELDS == 0)
        .flat_map(|g| g.1.clone())
        .collect();
    assert_eq!(body, b"hello", "{label}");
    assert!(
        h.got
            .iter()
            .any(|g| g.1.is_empty() && g.2 & PIECE_END != 0 && g.2 & PIECE_FIELDS == 0),
        "{label}: the request is whole"
    );

    assert_eq!(
        h.emit(1, b"content-type: text/plain\r\n", false, 0),
        Outcome::Failed,
        "{label}: the head emit states the status"
    );
    assert_eq!(
        h.emit(
            1,
            b"content-type: text/plain\r\ncontent-length: 2\r\n",
            false,
            201
        ),
        Outcome::Ready
    );
    assert_eq!(
        h.emit(1, b"ok", true, 200),
        Outcome::Failed,
        "{label}: only the head emit states a status"
    );
    assert_eq!(h.emit(1, b"ok", true, 0), Outcome::Ready);
    let wire = undated(h.out.clone());
    println!("PROOF {label}: answer {:?}", String::from_utf8_lossy(&wire));
    h.close();
    wire
}

/// An accepting listener offers `h2, http/1.1`.
fn accept_offer(ops: &'static Ops) -> Vec<u8> {
    let mut i: OpenIn = z();
    let mut o: OpenOut = z();
    // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
    // and the door instance for this synchronous call; the selected slot and index agree.
    unsafe {
        call(
            ops.head.open,
            std::ptr::null_mut(),
            &mut i,
            &mut o,
            life::OPEN,
        )
    };
    let inst = o.instance;
    let (mut auth, mut name, mut alpn) = (vec![0_u8; 256], vec![0_u8; 256], vec![0_u8; 256]);
    let mut li: LocateIn = z();
    li.accept = 1;
    li.authority_buf = auth.as_mut_ptr();
    li.authority_cap = auth.len();
    li.name_buf = name.as_mut_ptr();
    li.name_cap = name.len();
    li.alpn_buf = alpn.as_mut_ptr();
    li.alpn_cap = alpn.len();
    let mut lo: LocateOut = z();
    assert_eq!(
        // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
        // and the door instance for this synchronous call; the selected slot and index agree.
        unsafe { call(ops.locate, inst, &mut li, &mut lo, slot::LOCATE) },
        Outcome::Ready
    );
    let mut ci: InHead = z();
    let mut co: OutHead = z();
    // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
    // and the door instance for this synchronous call; the selected slot and index agree.
    unsafe { call(ops.head.close, inst, &mut ci, &mut co, life::CLOSE) };
    alpn[..lo.alpn_written as usize].to_vec()
}

#[test]
fn the_accepted_side_answers_alike_linked_and_dropped_in() {
    let (d, _lib) = dropped();
    let linked_wire = answered("linked", linked());
    let dropped_wire = answered("dropped", d);
    assert_eq!(
        linked_wire, dropped_wire,
        "one door, two images, one answer"
    );
    assert_eq!(
        String::from_utf8_lossy(&linked_wire),
        "HTTP/1.1 201 Created\r\ncontent-type: text/plain\r\ncontent-length: 2\r\n\r\nok"
    );
    for (image, ops) in [("linked", linked()), ("dropped", d)] {
        let offer = accept_offer(ops);
        println!("PROOF {image}: accept offer {offer:?}");
        assert_eq!(offer, b"\x02h2\x08http/1.1", "{image}: Q137");
    }
}

/// One call the door made on the host auth handle, as the scripted kernel read it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Asked {
    /// `auth.call`: the point, the handle's id, the unit's id, the request view and the body.
    Auth {
        point: u32,
        auth: u64,
        unit: u64,
        view: View,
        body: Option<Vec<u8>>,
    },
    /// `unit.hand_in`: the handle's id, the unit's id, the line and the (stripped) request view.
    HandIn {
        auth: u64,
        unit: u64,
        line: u32,
        view: View,
    },
    /// `unit.refuse`: the unit's id, the cause and the line.
    Refuse { unit: u64, cause: u32, line: u32 },
}

/// A [`HeadView`] as the kernel read it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct View {
    method: String,
    target: String,
    query: Option<String>,
    fields: Vec<(String, Vec<u8>)>,
    /// `SCHEME_*`, as the view declared it.
    scheme: u8,
}

impl View {
    fn has_field(&self, name: &str) -> bool {
        self.fields
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case(name))
    }
}

/// What the scripted kernel answers on one connection, and what it was asked.
#[derive(Default)]
struct Script {
    /// Each `auth.call`'s answer in turn: the flow and the names to strip (`FIELD_SENSITIVE` a
    /// field line, `FIELD_QUERY` a query key). Past the last: CONTINUE, nothing named.
    auth: VecDeque<(u32, Vec<(&'static str, u32)>)>,
    /// `unit.hand_in`'s flow.
    hand_in: u32,
    /// The services that answer FAILED (no answer at all): `auth.call`, `unit.hand_in`,
    /// `unit.refuse`.
    fails: Fails,
    /// How many `auth.call`s answer NOT-READY (PENDING) before the script answers.
    pend: usize,
    /// One selected stream's next auth call pends, after its siblings may have handed in.
    pend_stream: Option<u64>,
    /// One auth callback's 1-based ordinal pends, independent of stream scheduling order.
    pend_call: Option<usize>,
    /// Each `auth.call`'s completion sequence number.
    seqs: Vec<u32>,
    /// Each `auth.call`'s ticket.
    tickets: Vec<Ticket>,
    /// The request each `unit.refuse` was handed, in order.
    refused: Vec<View>,
    asked: Vec<Asked>,
    /// The fields `unit.refuse` answers, in order; empty: `content-type: application/json` alone.
    refusal_fields: Vec<(&'static str, &'static str)>,
    /// The next `auth.call` first crosses a `cancel` into the door (`table`, instance), while the
    /// op that made the call holds its framing.
    reenter: Option<(&'static Ops, usize)>,
    /// What that `cancel` answered: its outcome and disposition.
    reentered: Option<(Outcome, u32)>,
}

/// Which of the auth handle's services answer FAILED.
#[derive(Default, Clone, Copy)]
struct Fails {
    auth: bool,
    hand_in: bool,
    refuse: bool,
}

/// The unit the scripted kernel mints on a request's first call.
const MINTED: UnitRef = UnitRef { id: 41, mac: 42 };

/// Each connection's script, by its host context.
static SCRIPTS: Mutex<BTreeMap<u64, Script>> = Mutex::new(BTreeMap::new());
static NEXT_CTX: AtomicU64 = AtomicU64::new(1);

fn scripts() -> std::sync::MutexGuard<'static, BTreeMap<u64, Script>> {
    SCRIPTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The host services table: the auth handle's three slots, scripted; every other unserved.
static SLOTS: LazyLock<HostSlots> = LazyLock::new(|| {
    let mut t: HostSlots = z();
    t.size = size_of::<HostSlots>() as u32;
    t.slots = SERVICES;
    t.auth_call = Some(auth_call);
    t.unit_hand_in = Some(unit_hand_in);
    t.unit_refuse = Some(unit_refuse);
    t
});

/// A guest-list line: id `id`, its auth handle `100 + id`, an exact path.
fn line(id: u32, points: u32, methods: u32, path: &'static str, body_limit: u64) -> LineEntry {
    LineEntry {
        line: id,
        points,
        auth: AuthRef {
            id: 100 + u64::from(id),
            mac: 7,
        },
        body_limit,
        route: RouteMatch {
            methods,
            path_form: PATH_EXACT,
            path: s(path),
            fields: std::ptr::null(),
            fields_len: 0,
            rung: 0,
            _reserved: 0,
        },
    }
}

/// The bytes `s` names (an absent string reads empty).
///
/// # Safety
/// A non-NULL `s` names `s.len` live bytes.
unsafe fn bytes_of(p: *const u8, len: usize) -> Vec<u8> {
    if p.is_null() || len == 0 {
        return Vec::new();
    }
    // SAFETY: the caller's contract.
    unsafe { std::slice::from_raw_parts(p, len) }.to_vec()
}

/// A [`HeadView`] read.
///
/// # Safety
/// `v` is the door's live view, borrowed for the call.
unsafe fn view_of(v: &HeadView) -> View {
    // SAFETY: the caller's contract.
    unsafe {
        let text = |a: AbiStr| String::from_utf8(bytes_of(a.ptr, a.len)).expect("text");
        let fields = if v.fields.is_null() {
            Vec::new()
        } else {
            std::slice::from_raw_parts(v.fields, v.fields_len)
                .iter()
                .map(|f| (text(f.name), bytes_of(f.value.ptr, f.value.len)))
                .collect()
        };
        View {
            method: text(v.method),
            target: text(v.target),
            query: (!v.query.ptr.is_null()).then(|| text(v.query)),
            fields,
            scheme: v.scheme,
        }
    }
}

fn ready(out: *mut ServiceOut) -> RawOutcome {
    outcome(out, Outcome::Ready)
}

fn outcome(out: *mut ServiceOut, o: Outcome) -> RawOutcome {
    // SAFETY: the wrapper's live `out`.
    unsafe { (*out).outcome = RawOutcome::of(o) };
    RawOutcome::of(o)
}

extern "C" fn auth_call(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    let reenter = SCRIPTS
        .lock()
        .expect("scripts")
        .get_mut(&ctx.handle)
        .and_then(|s| s.reenter.take());
    if let Some((ops, inst)) = reenter {
        let mut i: CancelIn = z();
        i.ticket = Ticket {
            slot: 77,
            generation: 1,
        };
        let mut o: CancelOut = z();
        // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
        // and the door instance for this synchronous call; the selected slot and index agree.
        let r = unsafe {
            call(
                ops.head.cancel,
                inst as *mut c_void,
                &mut i,
                &mut o,
                life::CANCEL,
            )
        };
        if let Some(s) = scripts().get_mut(&ctx.handle) {
            s.reentered = Some((r, o.disposition));
        }
    }
    // SAFETY: the SDK wrapper hands a live `AuthCallIn`, its buffers and a live `out`.
    unsafe {
        let i = input.cast::<AuthCallIn>().read_unaligned();
        let mut scripts = scripts();
        let script = scripts.get_mut(&ctx.handle).expect("a script");
        script.asked.push(Asked::Auth {
            point: i.point,
            auth: i.auth.id,
            unit: i.unit.id,
            view: view_of(&i.request),
            body: (!i.body.ptr.is_null()).then(|| bytes_of(i.body.ptr, i.body.len)),
        });
        script.seqs.push(i.head.handle.seq);
        script.tickets.push(i.head.handle.ticket);

        if i.head.handle.ticket.is_none() {
            return outcome(out, Outcome::Refused);
        }
        if script.fails.auth {
            return outcome(out, Outcome::Failed);
        }
        if script.pend > 0 {
            script.pend -= 1;
            return outcome(out, Outcome::Pending);
        }
        if script.pend_stream == Some(i.stream) {
            script.pend_stream = None;
            return outcome(out, Outcome::Pending);
        }
        if script.pend_call == Some(script.seqs.len()) {
            script.pend_call = None;
            return outcome(out, Outcome::Pending);
        }
        let (flow, names) = script
            .auth
            .pop_front()
            .unwrap_or((FLOW_CONTINUE, Vec::new()));
        let mut at = 0usize;
        for (n, (name, flags)) in names.iter().enumerate() {
            std::ptr::copy_nonoverlapping(name.as_ptr(), i.buf.add(at), name.len());
            i.spans.add(n).write_unaligned(FieldSpan {
                name: Span {
                    offset: at as u32,
                    len: name.len() as u32,
                },
                value: Span {
                    offset: SPAN_ABSENT,
                    len: 0,
                },
                flags: *flags,
                _reserved: 0,
            });
            at += name.len();
        }
        let unit = if i.point == POINT_PEER {
            UnitRef::NONE
        } else if i.unit.is_none() {
            MINTED
        } else {
            i.unit
        };
        i.answer.write_unaligned(AuthAnswer {
            size: size_of::<AuthAnswer>() as u32,
            flow,
            unit,
        });
        (*out).len = at as u64;
        (*out).items = names.len() as u64;
    }
    ready(out)
}

extern "C" fn unit_hand_in(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK wrapper hands a live `UnitHandInIn` and a live `out`.
    unsafe {
        let i = input.cast::<UnitHandInIn>().read_unaligned();
        let mut scripts = scripts();
        let script = scripts.get_mut(&ctx.handle).expect("a script");
        script.asked.push(Asked::HandIn {
            auth: i.auth.id,
            unit: i.unit.id,
            line: i.line,
            view: view_of(&i.request),
        });
        if script.fails.hand_in {
            return outcome(out, Outcome::Failed);
        }
        i.answer.write_unaligned(AuthAnswer {
            size: size_of::<AuthAnswer>() as u32,
            flow: script.hand_in,
            unit: if i.unit.is_none() { MINTED } else { i.unit },
        });
    }
    ready(out)
}

/// The kernel's refusal status and body, preserving 1.5.5's no-route and size-gate bodies.
fn refusal(cause: u32) -> (u16, &'static str) {
    match cause {
        REFUSE_NO_ROUTE => (
            404,
            r#"{"error":{"code":null,"message":"the requested resource was not found","param":null,"type":"not_found_error"}}"#,
        ),
        REFUSE_METHOD_MISS => (405, r#"{"error":"method"}"#),
        REFUSE_OVER_GATE => (
            413,
            r#"{"error":{"code":null,"message":"request body exceeds the maximum allowed size","param":null,"type":"request_too_large"}}"#,
        ),
        REFUSE_STOPPED => (401, r#"{"error":"unauthenticated"}"#),
        _ => (403, r#"{"error":"check"}"#),
    }
}

/// The bytes the kernel's refusal for `cause` becomes on HTTP/1.1, undated: its status line, its
fn refusal_wire(cause: u32) -> String {
    let (status, body) = refusal(cause);
    let reason = hyper::StatusCode::from_u16(status)
        .expect("status")
        .canonical_reason()
        .expect("reason");
    format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    )
}

extern "C" fn unit_refuse(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK wrapper hands a live `UnitRefuseIn` and a live `out`.
    unsafe {
        let i = input.cast::<UnitRefuseIn>().read_unaligned();
        let mut scripts = scripts();
        let script = scripts.get_mut(&ctx.handle).expect("a script");
        script.asked.push(Asked::Refuse {
            unit: i.unit.id,
            cause: i.cause,
            line: i.line,
        });
        script.refused.push(view_of(&i.request));
        if script.fails.refuse {
            return outcome(out, Outcome::Failed);
        }
        let named = if script.refusal_fields.is_empty() {
            vec![("content-type", "application/json")]
        } else {
            script.refusal_fields.clone()
        };
        drop(scripts);
        let (status, body) = refusal(i.cause);

        let fields: &'static [Field] = Box::leak(
            named
                .into_iter()
                .map(|(name, value)| Field {
                    name: s(name),
                    value: s(value),
                })
                .collect::<Vec<Field>>()
                .into_boxed_slice(),
        );
        i.answer.write_unaligned(RefusalAnswer {
            size: size_of::<RefusalAnswer>() as u32,
            status,
            _reserved: 0,
            fields: fields.as_ptr(),
            fields_len: fields.len(),
            body: Blob {
                ptr: body.as_ptr(),
                len: body.len(),
                fmt: BLOB_OCTETS,
                flags: 0,
            },
        });
    }
    ready(out)
}

/// One request on a fresh accepted connection with guest list `lines` and kernel `script`.
fn admitted(ops: &'static Ops, lines: Vec<LineEntry>, script: Script, req: &[u8]) -> AcceptHost {
    let mut h = AcceptHost::open_with(ops, lines, script);
    assert_eq!(h.ingest(req), Outcome::Ready);
    h
}

/// A request refused by the kernel: the kernel's bytes framed verbatim, nothing up.
fn refused_verbatim(label: &str, h: &AcceptHost, cause: u32) {
    assert_eq!(h.heads_up(), 0, "{label}: nothing went up to the host");
    assert!(h.words.is_empty(), "{label}: no head slots went up");
    assert_eq!(
        String::from_utf8_lossy(&undated(h.out.clone())),
        refusal_wire(cause),
        "{label}: the kernel's refusal, framed verbatim"
    );
}

const POST_HELLO: &[u8] =
    b"POST /v1/messages HTTP/1.1\r\nhost: busbar.test\r\ncontent-length: 5\r\n\r\nhello";

/// No line's route holds: `unit.refuse(NO_ROUTE, LINE_NONE)` with no unit, its bytes framed.
fn no_route(label: &str, ops: &'static Ops) {
    let h = admitted(
        ops,
        vec![line(7, 0, METHOD_POST, "/v1/messages", 0)],
        Script::default(),
        b"GET /nope HTTP/1.1\r\nhost: busbar.test\r\n\r\n",
    );
    assert_eq!(
        h.asked(),
        vec![Asked::Refuse {
            unit: 0,
            cause: REFUSE_NO_ROUTE,
            line: LINE_NONE
        }],
        "{label}"
    );
    refused_verbatim(label, &h, REFUSE_NO_ROUTE);
    h.close();
}

/// The path holds on a line that admits no `GET`: `METHOD_MISS` on that line.
fn method_miss(label: &str, ops: &'static Ops) {
    let h = admitted(
        ops,
        vec![line(7, 0, METHOD_POST, "/v1/messages", 0)],
        Script::default(),
        b"GET /v1/messages HTTP/1.1\r\nhost: busbar.test\r\n\r\n",
    );
    assert_eq!(
        h.asked(),
        vec![Asked::Refuse {
            unit: 0,
            cause: REFUSE_METHOD_MISS,
            line: 7
        }],
        "{label}"
    );
    refused_verbatim(label, &h, REFUSE_METHOD_MISS);
    h.close();
}

/// The head auth answers STOP: `unit.refuse(STOPPED)` with the unit it minted; no hand-in.
fn head_stop(label: &str, ops: &'static Ops) {
    let h = admitted(
        ops,
        vec![line(3, POINT_HEAD, METHOD_POST, "/v1/messages", 0)],
        Script {
            auth: VecDeque::from([(FLOW_STOP, Vec::new())]),
            ..Script::default()
        },
        POST_HELLO,
    );
    let asked = h.asked();
    assert_eq!(asked.len(), 2, "{label}: {asked:?}");
    assert!(
        matches!(
            &asked[0],
            Asked::Auth {
                point: POINT_HEAD,
                auth: 103,
                unit: 0,
                body: None,
                ..
            }
        ),
        "{label}: {asked:?}"
    );
    assert_eq!(
        asked[1],
        Asked::Refuse {
            unit: MINTED.id,
            cause: REFUSE_STOPPED,
            line: 3
        },
        "{label}"
    );
    refused_verbatim(label, &h, REFUSE_STOPPED);
    h.close();
}

/// A `HeadBody` line whose body passes its limit: `OVER_GATE` is asked BEFORE any verdict, and
fn over_gate(label: &str, ops: &'static Ops) {
    let h = admitted(
        ops,
        vec![line(8, POINT_HEAD_BODY, METHOD_POST, "/v1/messages", 4)],
        Script::default(),
        POST_HELLO,
    );
    assert_eq!(
        h.asked(),
        vec![Asked::Refuse {
            unit: 0,
            cause: REFUSE_OVER_GATE,
            line: 8
        }],
        "{label}: no auth call before the size gate"
    );
    refused_verbatim(label, &h, REFUSE_OVER_GATE);
    h.close();
}

/// A `HeadBody` line within its limit: the auth is shown the head and the whole body, then the
fn head_body_within(label: &str, ops: &'static Ops) {
    let h = admitted(
        ops,
        vec![line(8, POINT_HEAD_BODY, METHOD_POST, "/v1/messages", 16)],
        Script::default(),
        POST_HELLO,
    );
    let asked = h.asked();
    assert!(
        matches!(&asked[..], [
            Asked::Auth { point: POINT_HEAD_BODY, auth: 108, unit: 0, body: Some(b), .. },
            Asked::HandIn { auth: 108, unit: 41, line: 8, .. },
        ] if b == b"hello"),
        "{label}: {asked:?}"
    );
    assert_eq!(h.heads_up(), 1, "{label}");
    let body: Vec<u8> = h
        .got
        .iter()
        .filter(|g| g.2 & PIECE_FIELDS == 0)
        .flat_map(|g| g.1.clone())
        .collect();
    assert_eq!(body, b"hello", "{label}");
    h.close();
}

/// What the auth names is stripped before the hand-in and before anything goes up: a field line
fn strips(label: &str, ops: &'static Ops) {
    let h = admitted(
        ops,
        vec![line(3, POINT_HEAD, METHOD_POST, "/v1/messages", 0)],
        Script {
            auth: VecDeque::from([(
                FLOW_CONTINUE,
                vec![("X-Api-Key", FIELD_SENSITIVE), ("key", FIELD_QUERY)],
            )]),
            ..Script::default()
        },
        b"POST /v1/messages?beta=1&key=sk-secret&Key=keep HTTP/1.1\r\nhost: busbar.test\r\nx-api-key: sk-secret\r\ncontent-length: 5\r\n\r\nhello",
    );
    let asked = h.asked();
    let [Asked::Auth { view: shown, .. }, Asked::HandIn {
        auth: 103,
        unit,
        line: 3,
        view,
    }] = &asked[..]
    else {
        panic!("{label}: an auth call, then the hand-in: {asked:?}");
    };
    assert_eq!(*unit, MINTED.id, "{label}: the unit the auth call minted");
    assert!(
        shown.has_field("x-api-key"),
        "{label}: the auth saw the credential"
    );
    assert_eq!(
        shown.query.as_deref(),
        Some("beta=1&key=sk-secret&Key=keep"),
        "{label}"
    );
    assert_eq!(view.target, "/v1/messages", "{label}");
    assert!(
        !view.has_field("x-api-key"),
        "{label}: stripped before the hand-in"
    );
    assert!(view.has_field("host"), "{label}");
    assert_eq!(view.query.as_deref(), Some("beta=1&Key=keep"), "{label}");
    assert_eq!(
        h.words,
        vec![(
            1,
            b"POST".to_vec(),
            b"/v1/messages?beta=1&Key=keep".to_vec()
        )],
        "{label}: the stripped target went up"
    );
    let up: Vec<u8> = h.got.iter().flat_map(|g| g.1.clone()).collect();
    assert!(
        !up.windows(9).any(|w| w == b"sk-secret") && !up.windows(9).any(|w| w == b"x-api-key"),
        "{label}: the plane never sees a credential: {:?}",
        String::from_utf8_lossy(&up)
    );
    h.close();
}

/// The hand-in answers STOP: `unit.refuse(CHECK_FAILED)` with the unit, nothing up.
fn hand_in_stop(label: &str, ops: &'static Ops) {
    let h = admitted(
        ops,
        vec![line(3, POINT_HEAD, METHOD_POST, "/v1/messages", 0)],
        Script {
            hand_in: FLOW_STOP,
            ..Script::default()
        },
        POST_HELLO,
    );
    let asked = h.asked();
    assert_eq!(asked.len(), 3, "{label}: {asked:?}");
    assert!(
        matches!(
            asked[1],
            Asked::HandIn {
                unit: 41,
                line: 3,
                ..
            }
        ),
        "{label}"
    );
    assert_eq!(
        asked[2],
        Asked::Refuse {
            unit: MINTED.id,
            cause: REFUSE_CHECK_FAILED,
            line: 3
        },
        "{label}"
    );
    refused_verbatim(label, &h, REFUSE_CHECK_FAILED);
    h.close();
}

/// A `none` line: no auth call; the hand-in carries no unit (the kernel mints it there), and the
fn none_line(label: &str, ops: &'static Ops) {
    let h = admitted(
        ops,
        vec![line(5, 0, METHOD_POST, "/v1/messages", 0)],
        Script::default(),
        POST_HELLO,
    );
    let asked = h.asked();
    assert!(
        matches!(
            &asked[..],
            [Asked::HandIn {
                auth: 105,
                unit: 0,
                line: 5,
                ..
            }]
        ),
        "{label}: {asked:?}"
    );
    assert_eq!(h.heads_up(), 1, "{label}");
    h.close();
}

/// The unit is carried: a `{Peer, Head}` line calls the peer point once (no request, no unit),
fn unit_carried(label: &str, ops: &'static Ops) {
    let h = admitted(
        ops,
        vec![line(
            6,
            POINT_PEER | POINT_HEAD,
            METHOD_POST,
            "/v1/messages",
            0,
        )],
        Script::default(),
        POST_HELLO,
    );
    let asked = h.asked();
    assert!(
        matches!(&asked[..], [
            Asked::Auth { point: POINT_PEER, auth: 106, unit: 0, view: p, body: None },
            Asked::Auth { point: POINT_HEAD, auth: 106, unit: 0, .. },
            Asked::HandIn { auth: 106, unit: 41, line: 6, .. },
        ] if *p == View::default()),
        "{label}: {asked:?}"
    );
    assert_eq!(h.heads_up(), 1, "{label}");
    h.close();
}

/// A request the kernel neither admitted nor refused: nothing went up to the plane, and the door
fn never_reached_the_plane(label: &str, h: &AcceptHost) {
    assert_eq!(h.heads_up(), 0, "{label}: nothing went up to the host");
    assert!(h.words.is_empty(), "{label}: no head slots went up");
    assert!(
        h.got.is_empty(),
        "{label}: no piece of the request went up: {:?}",
        h.got
    );
    assert!(
        h.out.is_empty(),
        "{label}: no bytes of the transport's own: {:?}",
        String::from_utf8_lossy(&h.out)
    );

    assert!(h.ended, "{label}: the connection is closed");
}

/// The hand-in answers FAILED: the request is not handed up.
fn hand_in_fails(label: &str, ops: &'static Ops) {
    let h = admitted(
        ops,
        vec![line(5, 0, METHOD_POST, "/v1/messages", 0)],
        Script {
            fails: Fails {
                hand_in: true,
                ..Fails::default()
            },
            ..Script::default()
        },
        POST_HELLO,
    );
    let asked = h.asked();
    assert!(
        matches!(&asked[..], [Asked::HandIn { line: 5, .. }]),
        "{label}: {asked:?}"
    );
    never_reached_the_plane(label, &h);
    h.close();
}

/// The auth call answers FAILED: no hand-in, nothing up.
fn auth_call_fails(label: &str, ops: &'static Ops) {
    let h = admitted(
        ops,
        vec![line(3, POINT_HEAD, METHOD_POST, "/v1/messages", 0)],
        Script {
            fails: Fails {
                auth: true,
                ..Fails::default()
            },
            ..Script::default()
        },
        POST_HELLO,
    );
    let asked = h.asked();
    assert!(
        matches!(
            &asked[..],
            [Asked::Auth {
                point: POINT_HEAD,
                ..
            }]
        ),
        "{label}: {asked:?}"
    );
    never_reached_the_plane(label, &h);
    h.close();
}

/// The refusal answers FAILED, after no route and after a hand-in STOP: nothing up either way.
fn refusal_fails(label: &str, ops: &'static Ops) {
    let fails = Fails {
        refuse: true,
        ..Fails::default()
    };
    let h = admitted(
        ops,
        vec![line(7, 0, METHOD_POST, "/v1/messages", 0)],
        Script {
            fails,
            ..Script::default()
        },
        b"GET /nope HTTP/1.1\r\nhost: busbar.test\r\n\r\n",
    );
    assert_eq!(
        h.asked(),
        vec![Asked::Refuse {
            unit: 0,
            cause: REFUSE_NO_ROUTE,
            line: LINE_NONE
        }],
        "{label}"
    );
    never_reached_the_plane(label, &h);
    h.close();
    let h = admitted(
        ops,
        vec![line(5, 0, METHOD_POST, "/v1/messages", 0)],
        Script {
            hand_in: FLOW_STOP,
            fails,
            ..Script::default()
        },
        POST_HELLO,
    );
    let asked = h.asked();
    assert!(
        matches!(
            &asked[..],
            [
                Asked::HandIn { .. },
                Asked::Refuse {
                    cause: REFUSE_CHECK_FAILED,
                    line: 5,
                    ..
                }
            ]
        ),
        "{label}: {asked:?}"
    );
    never_reached_the_plane(label, &h);
    h.close();
}

/// Query keys are percent-decoded before matching, as in the 1.5.5 inbound query reader.
fn strips_a_decoded_query_key(label: &str, ops: &'static Ops) {
    let h = admitted(
        ops,
        vec![line(3, POINT_HEAD, METHOD_POST, "/v1/messages", 0)],
        Script {
            auth: VecDeque::from([(FLOW_CONTINUE, vec![("key", FIELD_QUERY)])]),
            ..Script::default()
        },
        b"POST /v1/messages?beta=1&%6Bey=sk-secret&Key=keep HTTP/1.1\r\nhost: busbar.test\r\ncontent-length: 5\r\n\r\nhello",
    );
    let asked = h.asked();
    let [Asked::Auth { .. }, Asked::HandIn { view, .. }] = &asked[..] else {
        panic!("{label}: an auth call, then the hand-in: {asked:?}");
    };
    assert_eq!(view.query.as_deref(), Some("beta=1&Key=keep"), "{label}");
    assert_eq!(
        h.words,
        vec![(
            1,
            b"POST".to_vec(),
            b"/v1/messages?beta=1&Key=keep".to_vec()
        )],
        "{label}: the stripped target went up"
    );
    let up: Vec<u8> = h.got.iter().flat_map(|g| g.1.clone()).collect();
    assert!(
        !up.windows(9).any(|w| w == b"sk-secret"),
        "{label}: the plane never sees a credential"
    );
    h.close();
}

/// The ticket the cells' framings run on, where a cell needs one.
const TICKET: Ticket = Ticket {
    slot: 1,
    generation: 1,
};

/// `timer` is no ticketed op (`contract!(TIMER, true, false, ..)`: it never pends): it never calls
fn timer_never_calls_the_auth(label: &str, ops: &'static Ops) {
    let mut h = AcceptHost::open_with(
        ops,
        vec![line(3, POINT_HEAD, METHOD_POST, "/v1/messages", 0)],
        Script {
            pend: 1,
            ..Script::default()
        },
    );
    assert_eq!(
        h.ingest(POST_HELLO),
        Outcome::Pending,
        "{label}: the auth call pends"
    );
    assert_eq!(h.asked().len(), 1, "{label}");
    assert_eq!(
        h.timer(),
        Outcome::Ready,
        "{label}: a timer with no deadline passed is Ready"
    );
    assert_eq!(
        h.asked().len(),
        1,
        "{label}: a timer never calls the auth handle: {:?}",
        h.asked()
    );
    assert_eq!(
        h.heads_up(),
        0,
        "{label}: nothing went up past the parked call"
    );

    assert_eq!(
        h.ingest_with(POST_HELLO, FLAG_RESUME),
        Outcome::Ready,
        "{label}"
    );
    assert_eq!(h.heads_up(), 1, "{label}: the resumed request went up");
    h.close();
}

/// A pending `auth.call` parks the op; the host's resume re-issues the op with the same bytes and
fn a_resume_reissues_the_same_handle(label: &str, ops: &'static Ops) {
    let mut h = AcceptHost::open_with(
        ops,
        vec![line(3, POINT_HEAD, METHOD_POST, "/v1/messages", 0)],
        Script {
            pend: 1,
            ..Script::default()
        },
    );
    assert_eq!(h.ingest(POST_HELLO), Outcome::Pending, "{label}");
    assert_eq!(
        h.heads_up(),
        0,
        "{label}: the op yields nothing while it pends"
    );
    assert_eq!(
        h.ingest_with(POST_HELLO, FLAG_RESUME),
        Outcome::Ready,
        "{label}"
    );
    let seqs = h.seqs();
    assert!(
        seqs.len() == 2 && seqs[0] == seqs[1],
        "{label}: the same handle re-issued: {seqs:?}"
    );
    assert_eq!(h.heads_up(), 1, "{label}: one request went up");
    let body: Vec<u8> = h
        .got
        .iter()
        .filter(|g| g.2 & PIECE_FIELDS == 0)
        .flat_map(|g| g.1.clone())
        .collect();
    assert_eq!(body, b"hello", "{label}: its bytes taken once");
    h.close();
}

/// A `cancel` of an op parked on a pending `auth.call`: its bytes were taken, so the disposition is
fn cancel_of_a_parked_op(label: &str, ops: &'static Ops) {
    let mut h = AcceptHost::open_with(
        ops,
        vec![line(3, POINT_HEAD, METHOD_POST, "/v1/messages", 0)],
        Script {
            pend: 1,
            ..Script::default()
        },
    );
    let other = Ticket {
        slot: 9,
        generation: 1,
    };
    assert_eq!(
        h.cancel(other),
        CANCEL_NOTHING_MOVED,
        "{label}: nothing parked"
    );
    assert_eq!(h.ingest(POST_HELLO), Outcome::Pending, "{label}");
    assert_eq!(
        h.cancel(TICKET),
        CANCEL_PARTIAL,
        "{label}: its bytes were taken"
    );
    assert_eq!(h.ingest(b""), Outcome::Ready, "{label}: a fresh op");
    let seqs = h.seqs();
    assert!(
        seqs.len() == 2 && seqs[0] != seqs[1],
        "{label}: the cancelled call is not re-issued: {seqs:?}"
    );
    assert_eq!(h.heads_up(), 1, "{label}");
    h.close();
}

/// Cancellation waits for the operation holding the framing and then releases it.
fn cancel_meeting_a_held_framing(label: &str, ops: &'static Ops) {
    let mut h = AcceptHost::open_with(
        ops,
        vec![line(3, POINT_HEAD, METHOD_POST, "/v1/messages", 0)],
        Script::default(),
    );
    if let Some(s) = scripts().get_mut(&h.ctx) {
        s.reenter = Some((ops, h.inst as usize));
    }
    assert_eq!(h.ingest(POST_HELLO), Outcome::Ready, "{label}");
    let reentered = scripts()[&h.ctx].reentered;
    let (r, disposition) = reentered.expect("the cancel crossed while the framing was held");
    assert_eq!(
        r,
        Outcome::Failed,
        "{label}: a cancel that could not look at a held framing says so, not NOTHING_MOVED \
         (disposition {disposition})"
    );
    h.close();
}

/// A request decoded during a host refusal is admitted normally.
fn a_request_decoded_during_refuse_is_admitted(label: &str, ops: &'static Ops) {
    let one = b"POST /v1/messages HTTP/1.1\r\nhost: busbar.test\r\ncontent-length: 5\r\n\r\nhello";
    let two: Vec<u8> = one.iter().chain(one.iter()).copied().collect();
    let mut h = admitted(
        ops,
        vec![line(5, 0, METHOD_POST, "/v1/messages", 0)],
        Script::default(),
        &two,
    );
    assert_eq!(
        h.heads_up(),
        1,
        "{label}: one request at a time on HTTP/1.1"
    );
    assert_eq!(
        h.refuse(Some(1), b"no", 403, false),
        Outcome::Ready,
        "{label}"
    );
    assert_eq!(
        h.heads_up(),
        2,
        "{label}: the request decoded during the refuse went up in it"
    );
    h.close();
}

/// A refused detach retains the framing's owed bytes.
fn a_refused_detach_keeps_the_owed_bytes(label: &str, ops: &'static Ops) {
    let mut h = admitted(
        ops,
        vec![line(5, 0, METHOD_POST, "/v1/messages", 0)],
        Script::default(),
        POST_HELLO,
    );

    h.wire = vec![0; 16];
    assert_eq!(
        h.emit(1, b"content-length: 5\r\n", false, 200),
        Outcome::Ready,
        "{label}"
    );
    assert_eq!(h.emit(1, b"hello", true, 0), Outcome::Ready, "{label}");
    assert_eq!(h.detach().0, Outcome::Refused, "{label}: nothing switched");
    h.wire = vec![0; 64 * 1024];
    assert_eq!(h.timer(), Outcome::Ready, "{label}");
    assert_eq!(
        String::from_utf8_lossy(&undated(h.out.clone())),
        "HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello",
        "{label}: every answer byte reached the far side"
    );
    h.close();
}

/// A resumed emit reports that its stream queue is full.
fn a_resumed_emit_states_its_stream_full(label: &str, ops: &'static Ops) {
    let mut h = AcceptHost::open_with(
        ops,
        vec![
            line(3, POINT_HEAD, METHOD_ANY, "/a", 0),
            line(5, 0, METHOD_ANY, "/b", 0),
        ],
        Script {
            pend: 1,
            ..Script::default()
        },
    );

    assert_eq!(
        h.ingest(&h2_requests(&[(1, "/a"), (3, "/b")])),
        Outcome::Pending,
        "{label}"
    );
    let parked = h.ticket;
    h.ticket = Ticket {
        slot: 2,
        generation: 1,
    };
    assert_eq!(h.ingest(b""), Outcome::Ready, "{label}");
    let b = h
        .words
        .iter()
        .find(|(_, _, t)| t == b"/b")
        .map(|(s, _, _)| *s)
        .expect("B went up");

    assert_eq!(h.emit(b, b"", false, 200), Outcome::Ready, "{label}");
    let chunk = vec![b'x'; 64 * 1024];
    for _ in 0..5 {
        assert_eq!(h.emit(b, &chunk, false, 0), Outcome::Ready, "{label}");
    }

    assert_eq!(h.cancel(parked), CANCEL_PARTIAL, "{label}");
    if let Some(s) = scripts().get_mut(&h.ctx) {
        s.pend = 1;
    }
    h.ticket = Ticket {
        slot: 3,
        generation: 1,
    };
    assert_eq!(
        h.emit_with(b, &chunk, false, 0, 0).0,
        Outcome::Pending,
        "{label}: the emit parks on A's auth"
    );
    let (r, flags) = h.emit_with(b, &chunk, false, 0, FLAG_RESUME);
    assert_eq!(r, Outcome::Ready, "{label}: resumed");
    assert_ne!(
        flags & YIELD_STREAM_FULL,
        0,
        "{label}: the resume states B's queue full"
    );
    h.close();
}

/// Requests pipelined past any per-op bound are each answered in the op that decoded them: none is
fn pipelined_refusals(label: &str, ops: &'static Ops) {
    const N: usize = 24;
    let one = b"GET /nope HTTP/1.1\r\nhost: busbar.test\r\n\r\n";
    let many: Vec<u8> = one.iter().copied().cycle().take(one.len() * N).collect();
    let h = admitted(
        ops,
        vec![line(7, 0, METHOD_POST, "/v1/messages", 0)],
        Script::default(),
        &many,
    );
    let refused = h
        .asked()
        .iter()
        .filter(|a| {
            matches!(
                a,
                Asked::Refuse {
                    cause: REFUSE_NO_ROUTE,
                    ..
                }
            )
        })
        .count();
    assert_eq!(
        refused, N,
        "{label}: every pipelined request answered in the one op"
    );
    let answers = h
        .out
        .windows(22)
        .filter(|w| *w == b"HTTP/1.1 404 Not Found")
        .count();
    assert_eq!(answers, N, "{label}");
    h.close();
}

/// Refusing an accepted stream before its head keeps other streams usable.
fn refuse_a_stream_before_its_head(label: &str, ops: &'static Ops) {
    let mut h = admitted(
        ops,
        vec![line(5, 0, METHOD_POST, "/v1/messages", 0)],
        Script::default(),
        POST_HELLO,
    );
    assert_eq!(h.heads_up(), 1, "{label}");
    let body = br#"{"error":"overloaded"}"#;
    assert_eq!(
        h.refuse(Some(1), body, 503, false),
        Outcome::Ready,
        "{label}"
    );
    assert_eq!(
        String::from_utf8_lossy(&undated(h.out.clone())),
        format!(
            "HTTP/1.1 503 Service Unavailable\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            String::from_utf8_lossy(body)
        ),
        "{label}"
    );
    h.close();
}

/// `head_sent`: the answer's head already went; the stream ends failed. On HTTP/1.1 the connection
fn refuse_a_stream_after_its_head(label: &str, ops: &'static Ops) {
    let mut h = admitted(
        ops,
        vec![line(5, 0, METHOD_POST, "/v1/messages", 0)],
        Script::default(),
        POST_HELLO,
    );
    assert_eq!(
        h.emit(1, b"content-type: text/event-stream\r\n", false, 200),
        Outcome::Ready
    );
    assert_eq!(h.emit(1, b"data: x\n\n", false, 0), Outcome::Ready);
    assert_eq!(h.refuse(Some(1), b"", 500, true), Outcome::Ready, "{label}");
    let wire = String::from_utf8_lossy(&h.out).into_owned();
    assert!(wire.starts_with("HTTP/1.1 200 OK\r\n"), "{label}: {wire:?}");
    assert!(
        !wire.ends_with("0\r\n\r\n"),
        "{label}: no terminating chunk: {wire:?}"
    );
    assert!(h.ended, "{label}: the connection is over");
    h.close();
}

/// The whole connection (`has_stream` 0): the refusal's bytes are the transport's whole envelope
fn refuse_the_connection(label: &str, ops: &'static Ops) {
    let mut h = AcceptHost::open(ops);
    let bytes = b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\n\r\n";
    assert_eq!(h.refuse(None, bytes, 0, false), Outcome::Ready, "{label}");
    assert_eq!(h.out, bytes, "{label}");
    assert!(h.ended, "{label}: the connection is over");
    h.close();
}

/// THE SCHEME THE AUTH IS SHOWN (`HeadView::scheme`, busbar e858ecc: `0` is refused off the peer
fn shows_the_scheme(label: &str, ops: &'static Ops) {
    let cases: [SchemeCase; 4] = [
        ("cleartext", |_| {}, SCHEME_PLAIN, SCHEME_PLAIN),
        (
            "TLS, no SNI, ALPN or certificate",
            |_| {},
            SCHEME_SECURE,
            SCHEME_SECURE,
        ),
        (
            "TLS, SNI and ALPN",
            |f| {
                f.offered_name = s("busbar.test");
                f.agreed_protocol = s("http/1.1");
            },
            SCHEME_SECURE,
            SCHEME_SECURE,
        ),
        (
            "cleartext, facts naming SNI and ALPN",
            |f| {
                f.offered_name = s("busbar.test");
                f.agreed_protocol = s("http/1.1");
            },
            SCHEME_PLAIN,
            SCHEME_PLAIN,
        ),
    ];
    for (secured, facts, stated, want) in cases {
        let mut h = AcceptHost::open_on(
            ops,
            vec![line(3, POINT_HEAD, METHOD_POST, "/v1/messages", 0)],
            Script::default(),
            facts,
            stated,
        );
        assert_eq!(h.ingest(POST_HELLO), Outcome::Ready, "{label}");
        let asked = h.asked();
        let [Asked::Auth { view: shown, .. }, Asked::HandIn { view, .. }] = &asked[..] else {
            panic!("{label}: an auth call, then the hand-in: {asked:?}");
        };
        assert_eq!(shown.scheme, want, "{label}: {secured}: the auth's view");
        assert_eq!(view.scheme, want, "{label}: {secured}: the hand-in's view");
        h.close();
    }
}

/// A PENDING `auth.call` PARKS ONLY ITS OWN STREAM, on its own ticket (busbar e858ecc, the transport
fn parks_on_its_own_ticket(label: &str, ops: &'static Ops) {
    let mut h = AcceptHost::open_with(
        ops,
        vec![line(3, POINT_HEAD, METHOD_POST, "/v1/messages", 0)],
        Script {
            pend: 1,
            ..Script::default()
        },
    );
    let other = Ticket {
        slot: 2,
        generation: 1,
    };
    assert_eq!(h.ingest(POST_HELLO), Outcome::Pending, "{label}");
    h.ticket = other;
    assert_eq!(
        h.ingest(b""),
        Outcome::Ready,
        "{label}: a fresh op on another ticket flows"
    );
    assert_eq!(
        h.tickets(),
        vec![TICKET],
        "{label}: the parked handle is never re-issued under another ticket"
    );
    h.ticket = TICKET;
    assert_eq!(
        h.ingest_with(b"", FLAG_RESUME),
        Outcome::Ready,
        "{label}: the resume"
    );
    let seqs = h.seqs();
    assert_eq!(h.tickets(), vec![TICKET, TICKET], "{label}");
    assert!(seqs.len() == 2 && seqs[0] == seqs[1], "{label}: {seqs:?}");
    assert_eq!(h.heads_up(), 1, "{label}");
    h.close();
}

/// The door offers the peer authentication point.
fn offers_the_peer_point(label: &str, door: *const Door) {
    use busbar_contract::abi::auth::AuthPoints;
    use busbar_contract::abi::transport::check::check_offered_points;
    // SAFETY: the door's `'static` Statement and its `'static` extensions blob.
    let ext = unsafe {
        let st = &*(*door).statement();
        if st.extensions.ptr.is_null() {
            &[][..]
        } else {
            std::slice::from_raw_parts(st.extensions.ptr, st.extensions.len)
        }
    };
    assert_eq!(
        check_offered_points(ext),
        Ok(AuthPoints(POINT_PEER | POINT_HEAD | POINT_HEAD_BODY)),
        "{label}"
    );
}

/// The peer point runs once per connection before any request head call.
fn peer_once_per_connection(label: &str, ops: &'static Ops) {
    let mut h = AcceptHost::open_with(
        ops,
        vec![line(
            6,
            POINT_PEER | POINT_HEAD,
            METHOD_POST,
            "/v1/messages",
            0,
        )],
        Script::default(),
    );
    assert_eq!(h.ingest(POST_HELLO), Outcome::Ready, "{label}");
    assert_eq!(
        h.emit(1, b"content-length: 0\r\n", true, 204),
        Outcome::Ready
    );
    assert_eq!(h.ingest(POST_HELLO), Outcome::Ready, "{label}");
    let points: Vec<u32> = h
        .asked()
        .iter()
        .filter_map(|a| match a {
            Asked::Auth { point, .. } => Some(*point),
            _ => None,
        })
        .collect();
    assert_eq!(points, vec![POINT_PEER, POINT_HEAD, POINT_HEAD], "{label}");
    assert_eq!(h.heads_up(), 2, "{label}");
    h.close();
}

/// THE PEER RULE (busbar 9aff8cf7b7 `check_auth_call`: at the peer point "no field, no name and no
fn a_peer_answer_naming_lines_is_refused(label: &str, ops: &'static Ops) {
    let mut h = AcceptHost::open_with(
        ops,
        vec![line(
            6,
            POINT_PEER | POINT_HEAD,
            METHOD_POST,
            "/v1/messages",
            0,
        )],
        Script {
            auth: VecDeque::from([(FLOW_CONTINUE, vec![("x-credential", FIELD_SENSITIVE)])]),
            ..Script::default()
        },
    );
    assert_eq!(h.ingest(POST_HELLO), Outcome::Ready, "{label}");
    let asked = h.asked();
    assert!(
        matches!(&asked[..], [Asked::Auth { point: POINT_PEER, view, body: None, .. }] if *view == View::default()),
        "{label}: one peer call, carrying no request: {asked:?}"
    );
    assert_eq!(h.heads_up(), 0, "{label}: nothing went up");
    assert!(h.out.is_empty(), "{label}: no bytes of the transport's own");

    assert!(h.ended, "{label}: the connection is closed");
    h.close();
}

/// One scheme cell: its label, the handshake facts, the scheme the host states for the listener,
type SchemeCase = (&'static str, fn(&mut ConnFacts), u8, u8);

/// One HTTP/2 frame: its type, flags, stream and payload (RFC 9113 §4.1).
fn h2_frame(ty: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len())
        .expect("a small frame")
        .to_be_bytes();
    let mut f = vec![len[1], len[2], len[3], ty, flags];
    f.extend_from_slice(&stream.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// The preface, an empty SETTINGS, and one whole `GET` request per `(stream, path)` (HPACK:
fn h2_requests(requests: &[(u32, &str)]) -> Vec<u8> {
    let mut wire = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    wire.extend(h2_frame(4, 0, 0, &[]));
    for (stream, path) in requests {
        let mut block = vec![
            0x82,
            0x86,
            0x04,
            u8::try_from(path.len()).expect("a short path"),
        ];
        block.extend_from_slice(path.as_bytes());
        block.extend_from_slice(&[0x01, 11]);
        block.extend_from_slice(b"busbar.test");
        wire.extend(h2_frame(1, 0x5, *stream, &block));
    }
    wire
}

/// An accepted connection that negotiated `h2` is served as HTTP/2 from its first byte.
fn alpn_h2_is_served_as_h2(label: &str, ops: &'static Ops) {
    let mut h = AcceptHost::open_on(
        ops,
        vec![line(5, 0, METHOD_ANY, "/v1/messages", 0)],
        Script::default(),
        |f| f.agreed_protocol = s("h2"),
        SCHEME_SECURE,
    );
    assert_eq!(
        h.ingest(&h2_requests(&[(1, "/v1/messages")])),
        Outcome::Ready,
        "{label}"
    );
    assert_eq!(
        h.words,
        vec![(1, b"GET".to_vec(), b"/v1/messages".to_vec())],
        "{label}: the HTTP/2 request went up"
    );
    assert!(
        h.out.starts_with(&[0, 0]) && h.out.get(3) == Some(&4),
        "{label}: the server's own SETTINGS open its side: {:?}",
        h.out
    );
    h.close();
}

/// A pending `auth.call` parks only its own stream.
fn a_pending_auth_parks_only_its_stream(label: &str, ops: &'static Ops) {
    let mut h = AcceptHost::open_with(
        ops,
        vec![
            line(3, POINT_HEAD, METHOD_ANY, "/a", 0),
            line(5, 0, METHOD_ANY, "/b", 0),
        ],
        Script {
            pend: 1,
            ..Script::default()
        },
    );
    assert_eq!(
        h.ingest(&h2_requests(&[(1, "/a"), (3, "/b")])),
        Outcome::Pending,
        "{label}: A's auth pends"
    );
    assert!(
        h.asked()
            .iter()
            .any(|a| matches!(a, Asked::HandIn { line: 5, .. })),
        "{label}: B is admitted in the op A parked in: {:?}",
        h.asked()
    );
    h.ticket = Ticket {
        slot: 2,
        generation: 1,
    };
    assert_eq!(
        h.ingest(b""),
        Outcome::Ready,
        "{label}: a fresh op on another ticket"
    );
    assert!(
        h.words.iter().any(|(_, _, t)| t == b"/b"),
        "{label}: B's head went up: {:?}",
        h.words
    );
    assert!(
        !h.words.iter().any(|(_, _, t)| t == b"/a"),
        "{label}: A stays parked"
    );
    h.close();
}

/// THE REQUEST BEING REFUSED (busbar step 2, `UnitRefuseIn::request`: "The request being refused,
fn refusal_carries_the_request(label: &str, ops: &'static Ops) {
    for (req, method, target) in [
        (
            &b"GET /nope?x=1 HTTP/1.1\r\nhost: busbar.test\r\n\r\n"[..],
            "GET",
            "/nope",
        ),
        (
            &b"GET /v1/messages HTTP/1.1\r\nhost: busbar.test\r\n\r\n"[..],
            "GET",
            "/v1/messages",
        ),
    ] {
        let h = admitted(
            ops,
            vec![line(7, 0, METHOD_POST, "/v1/messages", 0)],
            Script::default(),
            req,
        );
        let refused = scripts()[&h.ctx].refused.clone();
        let [view] = &refused[..] else {
            panic!("{label}: one refusal: {refused:?}");
        };
        assert_eq!(
            (view.method.as_str(), view.target.as_str()),
            (method, target),
            "{label}"
        );
        assert!(view.has_field("host"), "{label}: {view:?}");
        assert_eq!(
            view.scheme, SCHEME_PLAIN,
            "{label}: the connection's scheme"
        );
        h.close();
    }
}

/// THE KERNEL'S REFUSAL KEEPS ITS FIELDS (D3): every field `unit.refuse` answers is framed on the
fn kernel_refusal_keeps_its_fields(label: &str, ops: &'static Ops) {
    let script = Script {
        refusal_fields: vec![
            ("content-type", "application/json"),
            ("www-authenticate", "Bearer realm=\"busbar\""),
            ("x-request-id", "r-1"),
        ],
        ..Script::default()
    };
    let h = admitted(
        ops,
        vec![line(7, 0, METHOD_POST, "/v1/messages", 0)],
        script,
        b"GET /nope HTTP/1.1\r\nhost: busbar.test\r\n\r\n",
    );
    assert_eq!(h.heads_up(), 0, "{label}: nothing went up to the host");
    let (status, body) = refusal(REFUSE_NO_ROUTE);
    assert_eq!(status, 404, "{label}");
    assert_eq!(
        String::from_utf8_lossy(&undated(h.out.clone())),
        format!(
            "HTTP/1.1 404 Not Found\r\ncontent-type: application/json\r\nwww-authenticate: Bearer realm=\"busbar\"\r\nx-request-id: r-1\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        ),
        "{label}: the kernel's fields, in order, on its refusal"
    );
    h.close();
}

/// An upgrade handed to another framer receives no HTTP answer here.
fn upgrade_detached_unanswered(label: &str, ops: &'static Ops) {
    let request: &[u8] = b"GET /v1/session HTTP/1.1\r\nhost: busbar.test\r\nconnection: upgrade\r\nupgrade: websocket\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\nsec-websocket-version: 13\r\n\r\n";
    let mut h = admitted(
        ops,
        vec![line(3, POINT_HEAD, METHOD_ANY, "/v1/session", 0)],
        Script::default(),
        request,
    );
    assert_eq!(
        h.heads_up(),
        1,
        "{label}: the upgrade request was admitted and went up"
    );
    assert!(
        h.asked()
            .iter()
            .any(|a| matches!(a, Asked::Auth { point, .. } if *point == POINT_HEAD)),
        "{label}: through its line's auth"
    );
    let after: &[u8] = b"\x81\x02hi";
    assert_eq!(h.ingest(after), Outcome::Ready, "{label}");
    let (r, handed) = h.detach();
    assert_eq!(r, Outcome::Ready, "{label}: detach");
    let mut sent = request.to_vec();
    sent.extend_from_slice(after);
    assert_eq!(
        String::from_utf8_lossy(&handed),
        String::from_utf8_lossy(&sent),
        "{label}: the upgrade request's head and what followed it, as sent"
    );
    assert!(
        h.out.is_empty(),
        "{label}: nothing answered, no 101: {:?}",
        String::from_utf8_lossy(&h.out)
    );
    assert!(h.ended, "{label}: the framing has ended");
    h.close();
}

/// A `HEAD` request receives the response head without a body, matching the 1.5.5 hyper server.
fn head_answered_without_a_body(label: &str, ops: &'static Ops) {
    let mut h = AcceptHost::open(ops);
    assert_eq!(
        h.ingest(b"HEAD /v1/messages HTTP/1.1\r\nhost: busbar.test\r\n\r\n"),
        Outcome::Ready
    );
    assert_eq!(
        h.words,
        vec![(1, b"HEAD".to_vec(), b"/v1/messages".to_vec())],
        "{label}: the request went up"
    );
    assert_eq!(
        h.emit(
            1,
            b"content-type: text/plain\r\ncontent-length: 5\r\n",
            false,
            200
        ),
        Outcome::Ready,
        "{label}: the head"
    );

    let outcome = h.emit(1, b"hello", true, 0);
    assert!(
        matches!(outcome, Outcome::Ready | Outcome::Failed),
        "{label}: a HEAD body completes or its already-ended stream is refused: {outcome:?}"
    );
    let wire = String::from_utf8_lossy(&undated(h.out.clone())).into_owned();
    println!("PROOF {label}: head answer {wire:?}");
    assert!(wire.starts_with("HTTP/1.1 200 OK\r\n"), "{label}: {wire:?}");
    assert!(
        wire.contains("content-type: text/plain\r\n"),
        "{label}: {wire:?}"
    );
    assert_eq!(
        wire.matches("content-length: 5\r\n").count(),
        1,
        "{label}: HEAD keeps the representation length: {wire:?}"
    );
    assert!(
        !wire.to_ascii_lowercase().contains("transfer-encoding:"),
        "{label}: HEAD has no body transfer coding: {wire:?}"
    );
    assert!(
        wire.ends_with("\r\n\r\n"),
        "{label}: the head alone: {wire:?}"
    );
    assert!(!wire.contains("hello"), "{label}: no body byte: {wire:?}");
    h.close();
}

/// Incomplete request heads expire after 30 seconds on the host's clock, matching 1.5.5.
fn header_read_bound(label: &str, ops: &'static Ops) {
    let mut h = AcceptHost::open(ops);
    let start = h.now;
    assert_eq!(
        h.ingest(b"GET /v1/messages HTTP/1.1\r\nhost: slo"),
        Outcome::Ready
    );
    h.now = start + 10 * SEC;
    assert_eq!(
        h.ingest(b"w.busbar"),
        Outcome::Ready,
        "{label}: one more trickle"
    );
    h.now = start + 29 * SEC;
    assert_eq!(h.timer(), Outcome::Ready, "{label}");
    assert!(!h.ended, "{label}: not before 30 s");
    h.now = start + 31 * SEC;
    assert_eq!(h.timer(), Outcome::Ready, "{label}");
    assert!(h.ended, "{label}: the bound ends the connection");
    assert_eq!(h.heads_up(), 0, "{label}: no request went up");
    assert!(h.words.is_empty(), "{label}: no head slots went up");
    h.close();
}

/// A host-framed stream refusal crosses `RefuseIn` byte for byte.
fn host_framed_refusal_arrives_byte_identical(label: &str, ops: &'static Ops) {
    let mut h = admitted(
        ops,
        vec![line(5, 0, METHOD_POST, "/v1/messages", 0)],
        Script::default(),
        POST_HELLO,
    );
    assert_eq!(h.heads_up(), 1, "{label}: the request went up");
    let bytes: &[u8] = b"HTTP/1.1 429 Too Many Requests\r\ncontent-type: application/json\r\nretry-after: 7\r\ncontent-length: 22\r\n\r\n{\"error\":\"rate_limit\"}";
    assert_eq!(
        h.refuse(Some(1), bytes, 0, false),
        Outcome::Ready,
        "{label}"
    );
    assert_eq!(
        String::from_utf8_lossy(&h.out),
        String::from_utf8_lossy(bytes),
        "{label}: the host's refusal, byte-identical"
    );
    assert!(h.ended, "{label}: the connection is over");
    h.close();
}

/// The HTTP/2 frames `wire` holds, in order: `(type, flags, stream, payload)`.
fn h2_frames(wire: &[u8]) -> Vec<(u8, u8, u32, Vec<u8>)> {
    let mut frames = Vec::new();
    let mut at = 0;
    while at + 9 <= wire.len() {
        let len = (usize::from(wire[at]) << 16)
            | (usize::from(wire[at + 1]) << 8)
            | usize::from(wire[at + 2]);
        let stream = u32::from_be_bytes([wire[at + 5], wire[at + 6], wire[at + 7], wire[at + 8]])
            & 0x7fff_ffff;
        let end = (at + 9 + len).min(wire.len());
        frames.push((
            wire[at + 3],
            wire[at + 4],
            stream,
            wire[at + 9..end].to_vec(),
        ));
        at = end;
    }
    frames
}

/// THE ANSWER ENDS WITH THE REQUEST BODY UNREAD (the over-cap case: the host answers `413` while
fn answer_ends_with_the_body_unread(label: &str, ops: &'static Ops) {
    let mut h = admitted(
        ops,
        vec![line(5, 0, METHOD_ANY, "/v1/messages", 0)],
        Script::default(),
        b"POST /v1/messages HTTP/1.1\r\nhost: busbar.test\r\ncontent-length: 100\r\n\r\nhello",
    );
    assert_eq!(h.heads_up(), 1, "{label}: h1: the request went up");
    assert_eq!(
        h.emit(
            1,
            b"content-type: application/json\r\ncontent-length: 4\r\n",
            false,
            413
        ),
        Outcome::Ready,
        "{label}: h1"
    );
    assert_eq!(h.emit(1, b"big!", true, 0), Outcome::Ready, "{label}: h1");
    let wire = String::from_utf8_lossy(&undated(h.out.clone())).into_owned();
    assert!(
        wire.starts_with("HTTP/1.1 413 Payload Too Large\r\n"),
        "{label}: h1: {wire:?}"
    );
    assert!(
        wire.ends_with("\r\n\r\nbig!"),
        "{label}: h1: the answer whole: {wire:?}"
    );
    assert!(
        h.ended,
        "{label}: h1: the connection closes once the answer is written"
    );
    let before = h.got.len();
    let _ = h.ingest(b"world");
    let late: Vec<u8> = h.got[before..]
        .iter()
        .flat_map(|g| g.1.iter().copied())
        .collect();
    assert!(
        !late.windows(5).any(|w| w == b"world"),
        "{label}: h1: no body byte goes up after the answer ended"
    );
    h.close();

    let mut h = AcceptHost::open_with(
        ops,
        vec![line(5, 0, METHOD_ANY, "/v1/messages", 0)],
        Script::default(),
    );
    let mut wire = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    wire.extend(h2_frame(4, 0, 0, &[]));
    let mut block = vec![0x83, 0x86, 0x04, 12];
    block.extend_from_slice(b"/v1/messages");
    block.extend_from_slice(&[0x01, 11]);
    block.extend_from_slice(b"busbar.test");
    wire.extend(h2_frame(1, 0x4, 1, &block));
    wire.extend(h2_frame(0, 0, 1, b"hello"));
    assert_eq!(h.ingest(&wire), Outcome::Ready, "{label}: h2");
    assert_eq!(
        h.words,
        vec![(1, b"POST".to_vec(), b"/v1/messages".to_vec())],
        "{label}: h2: the request went up"
    );
    assert_eq!(
        h.emit(
            1,
            b"content-type: application/json\r\ncontent-length: 4\r\n",
            false,
            413
        ),
        Outcome::Ready,
        "{label}: h2"
    );
    assert_eq!(h.emit(1, b"big!", true, 0), Outcome::Ready, "{label}: h2");
    let frames = h2_frames(&h.out);
    let ended_at = frames
        .iter()
        .position(|f| f.0 == 0 && f.2 == 1 && f.1 & 0x1 != 0)
        .unwrap_or_else(|| panic!("{label}: h2: the answer ends its side: {frames:?}"));
    let body: Vec<u8> = frames[..=ended_at]
        .iter()
        .filter(|f| f.0 == 0 && f.2 == 1)
        .flat_map(|f| f.3.clone())
        .collect();
    assert_eq!(
        body, b"big!",
        "{label}: h2: the answer's body whole: {frames:?}"
    );
    assert!(
        frames[ended_at..]
            .iter()
            .any(|f| f.0 == 3 && f.2 == 1 && f.3 == [0, 0, 0, 0]),
        "{label}: h2: the stream is reset NO_ERROR after the answer: {frames:?}"
    );
    assert!(
        frames.iter().all(|f| f.0 != 7),
        "{label}: h2: no GOAWAY: {frames:?}"
    );
    assert!(!h.ended, "{label}: h2: the connection is kept");
    h.close();
}

/// The protocol names an ALPN ProtocolNameList holds, in order.
fn alpn_names(list: &[u8]) -> Vec<Vec<u8>> {
    let mut names = Vec::new();
    let mut at = 0;
    while at < list.len() {
        let n = usize::from(list[at]);
        names.push(list[at + 1..at + 1 + n].to_vec());
        at += 1 + n;
    }
    names
}

/// The accepted side reports its negotiated protocol through `FramerYield::agreed`.
fn states_the_protocol_it_agreed(label: &str, ops: &'static Ops) {
    let offer = alpn_names(&accept_offer(ops));
    let position = |name: &[u8]| -> u32 {
        let i = offer
            .iter()
            .position(|n| n == name)
            .unwrap_or_else(|| panic!("{label}: the offer names {name:?}: {offer:?}"));
        u32::try_from(i + 1).expect("a short offer")
    };
    let h1: &[u8] = b"GET /v1/messages HTTP/1.1\r\nhost: busbar.test\r\n\r\n";
    let lines = || vec![line(5, 0, METHOD_ANY, "/v1/messages", 0)];

    let mut h = AcceptHost::open_on(
        ops,
        lines(),
        Script::default(),
        |f| f.agreed_protocol = s("h2"),
        SCHEME_SECURE,
    );
    assert_eq!(h.agreed, position(b"h2"), "{label}: ALPN h2, at begin");
    assert_eq!(
        h.ingest(&h2_requests(&[(1, "/v1/messages")])),
        Outcome::Ready
    );
    assert_eq!(h.agreed, position(b"h2"), "{label}: ALPN h2, on ingest");
    h.close();

    let mut h = AcceptHost::open_on(
        ops,
        lines(),
        Script::default(),
        |f| f.agreed_protocol = s("http/1.1"),
        SCHEME_SECURE,
    );
    assert_eq!(
        h.agreed,
        position(b"http/1.1"),
        "{label}: ALPN http/1.1, at begin"
    );
    assert_eq!(h.ingest(h1), Outcome::Ready);
    assert_eq!(
        h.agreed,
        position(b"http/1.1"),
        "{label}: ALPN http/1.1, on ingest"
    );
    h.close();

    let mut h = AcceptHost::open_with(ops, lines(), Script::default());
    assert_eq!(h.agreed, 0, "{label}: cleartext, no byte yet");
    assert_eq!(h.ingest(h1), Outcome::Ready);
    assert_eq!(h.agreed, position(b"http/1.1"), "{label}: cleartext h1");
    h.close();

    let mut h = AcceptHost::open_with(ops, lines(), Script::default());
    assert_eq!(
        h.ingest(&h2_requests(&[(1, "/v1/messages")])),
        Outcome::Ready
    );
    assert_eq!(h.agreed, position(b"h2"), "{label}: h2c by prior knowledge");
    h.close();
}

/// The door's accepting offer as `locate` answers it on instance `inst` (`LocateIn::accept`).
fn accepting_offer_on(ops: &'static Ops, inst: *mut c_void) -> Vec<u8> {
    let (mut auth, mut name, mut alpn) = (vec![0_u8; 256], vec![0_u8; 256], vec![0_u8; 256]);
    let mut li: LocateIn = z();
    li.accept = 1;
    li.authority_buf = auth.as_mut_ptr();
    li.authority_cap = auth.len();
    li.name_buf = name.as_mut_ptr();
    li.name_cap = name.len();
    li.alpn_buf = alpn.as_mut_ptr();
    li.alpn_cap = alpn.len();
    let mut lo: LocateOut = z();
    assert_eq!(
        // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
        // and the door instance for this synchronous call; the selected slot and index agree.
        unsafe { call(ops.locate, inst, &mut li, &mut lo, slot::LOCATE) },
        Outcome::Ready
    );
    alpn[..lo.alpn_written as usize].to_vec()
}

/// A NON-EMPTY ACCEPTING OFFER ON A CLEARTEXT LISTENER (busbar's framed worker asks the door for
fn a_cleartext_offer_changes_nothing_else(label: &str, ops: &'static Ops) {
    let mut h = AcceptHost::open(ops);
    let offer = alpn_names(&accepting_offer_on(ops, h.inst));
    assert!(
        !offer.is_empty(),
        "{label}: the accepting offer is not empty"
    );
    assert_eq!(h.agreed, 0, "{label}: no protocol before the first bytes");
    assert!(
        h.out.is_empty(),
        "{label}: no handshake bytes and no refusal"
    );
    assert!(!h.ended, "{label}: the connection is served");
    assert_eq!(
        h.ingest(
            b"POST /v1/messages HTTP/1.1\r\nhost: busbar.test\r\ncontent-length: 5\r\n\r\nhello"
        ),
        Outcome::Ready,
        "{label}"
    );
    assert_eq!(h.heads_up(), 1, "{label}: the request went up, not refused");
    let http1 = offer
        .iter()
        .position(|n| n == b"http/1.1")
        .map(|i| u32::try_from(i + 1).expect("a short offer"));
    assert_eq!(Some(h.agreed), http1, "{label}: http/1.1's position");
    assert_eq!(
        h.emit(
            1,
            b"content-type: text/plain\r\ncontent-length: 2\r\n",
            false,
            201
        ),
        Outcome::Ready
    );
    assert_eq!(h.emit(1, b"ok", true, 0), Outcome::Ready);
    assert_eq!(
        String::from_utf8_lossy(&undated(h.out.clone())),
        "HTTP/1.1 201 Created\r\ncontent-type: text/plain\r\ncontent-length: 2\r\n\r\nok",
        "{label}: plain HTTP/1.1, as v1.5.5's listener answered"
    );
    h.close();
}

/// A second connection on ONE instance whose listener's list differs from the first's in one
/// member only is framed under ITS list, not the copy the instance kept for the first: a stale
/// reuse would admit it under the old auth handle or body limit.
fn a_changed_list_is_not_reused(label: &str, ops: &'static Ops) {
    // The auth handle alone differs.
    let first = admitted(
        ops,
        vec![line(8, POINT_HEAD, METHOD_POST, "/v1/messages", 0)],
        Script::default(),
        POST_HELLO,
    );
    let mut other = line(8, POINT_HEAD, METHOD_POST, "/v1/messages", 0);
    other.auth = AuthRef { id: 555, mac: 7 };
    let mut second = AcceptHost::open_again(&first, vec![other]);
    assert_eq!(second.ingest(POST_HELLO), Outcome::Ready);
    let asked = first.asked();
    assert!(
        matches!(
            &asked[..],
            [
                Asked::Auth { auth: 108, .. },
                Asked::HandIn { auth: 108, .. },
                Asked::Auth { auth: 555, .. },
                Asked::HandIn { auth: 555, .. },
            ]
        ),
        "{label}: the second connection is called under its own handle: {asked:?}"
    );
    first.close();

    // The body limit alone differs: within it, then over it.
    let first = admitted(
        ops,
        vec![line(8, POINT_HEAD_BODY, METHOD_POST, "/v1/messages", 16)],
        Script::default(),
        POST_HELLO,
    );
    assert_eq!(first.heads_up(), 1, "{label}: within its limit it goes up");
    let mut second = AcceptHost::open_again(
        &first,
        vec![line(8, POINT_HEAD_BODY, METHOD_POST, "/v1/messages", 4)],
    );
    assert_eq!(second.ingest(POST_HELLO), Outcome::Ready);
    assert_eq!(
        second.heads_up(),
        0,
        "{label}: over the second list's limit, nothing goes up"
    );
    let asked = first.asked();
    assert!(
        matches!(
            asked.last(),
            Some(Asked::Refuse {
                cause: REFUSE_OVER_GATE,
                line: 8,
                ..
            })
        ),
        "{label}: refused at the second list's gate: {asked:?}"
    );
    first.close();

    // Every other compared member, one at a time: the first connection's list is kept by the
    // instance, the second's differs in that member only, and `POST /v1/messages` on the second is
    // framed under the SECOND list (what a stale reuse of the first's copy would not do).
    let no_route = |asked: &[Asked]| {
        matches!(
            asked,
            [Asked::Refuse {
                cause: REFUSE_NO_ROUTE,
                ..
            }]
        )
    };
    let post = |id: u32| line(id, POINT_HEAD, METHOD_POST, "/v1/messages", 0);
    let mut other_path = post(8);
    other_path.route.path = s("/v1/other");
    let mut other_methods = post(8);
    other_methods.route.methods = METHOD_GET;
    let mut base_form = post(8);
    base_form.route.path_form = PATH_PREFIX;
    base_form.route.path = s("/v1");
    let mut other_form = post(8);
    other_form.route.path = s("/v1");
    let mut base_points = post(8);
    base_points.points = 0;
    // Line 9 with line 8's auth handle: only the id differs.
    let mut renumbered = post(9);
    renumbered.auth = post(8).auth;
    let mut late = post(9);
    late.route.path = s("/v1/other");
    type Case = (
        &'static str,
        Vec<LineEntry>,
        Vec<LineEntry>,
        Box<dyn Fn(&[Asked]) -> bool>,
    );
    let cases: Vec<Case> = vec![
        ("path", vec![post(8)], vec![other_path], Box::new(no_route)),
        (
            "methods",
            vec![post(8)],
            vec![other_methods],
            Box::new(|a: &[Asked]| {
                matches!(
                    a,
                    [Asked::Refuse {
                        cause: REFUSE_METHOD_MISS,
                        ..
                    }]
                )
            }),
        ),
        (
            "path form",
            vec![base_form],
            vec![other_form],
            Box::new(no_route),
        ),
        (
            "line id",
            vec![post(8)],
            vec![renumbered],
            Box::new(|a: &[Asked]| {
                matches!(a, [Asked::Auth { .. }, Asked::HandIn { line: 9, .. }])
            }),
        ),
        (
            "points",
            vec![base_points],
            vec![post(8)],
            Box::new(|a: &[Asked]| {
                matches!(a, [Asked::Auth { auth: 108, .. }, Asked::HandIn { .. }])
            }),
        ),
        (
            "list length",
            vec![late],
            vec![late, post(9)],
            Box::new(|a: &[Asked]| {
                matches!(a, [Asked::Auth { .. }, Asked::HandIn { line: 9, .. }])
            }),
        ),
    ];
    // Predicate members, observed through whether the request matches. `rung` is not pinned here:
    // the door matches in table order and only carries the rung through, so no request can tell it.
    let pred = |id: u32, op: u32, name: &'static str, value: &'static str| {
        let preds: &'static [FieldPredicate] = Box::leak(Box::new([FieldPredicate {
            op,
            _reserved: 0,
            name: s(name),
            value: s(value),
        }]));
        let mut l = post(id);
        l.route.fields = preds.as_ptr();
        l.route.fields_len = preds.len();
        l
    };
    let tiered_pro = tiered_post("pro-1");
    let extra = [
        // The base requires `x-tier` to start `pro`, the alt has no predicate: a stale copy
        // would refuse a non-matching tier.
        (
            "predicate count",
            vec![tiered_line(8, "pro")],
            vec![post(8)],
            tiered_post("free"),
            true,
        ),
        (
            "predicate count (reverse)",
            vec![post(8)],
            vec![tiered_line(8, "pro")],
            tiered_post("free"),
            false,
        ),
        // Same value, other header name: the request carries `x-tier` only.
        (
            "predicate name",
            vec![tiered_line(8, "pro")],
            vec![pred(8, FIELD_VALUE_PREFIX, "x-other", "pro")],
            tiered_pro.clone(),
            false,
        ),
        // Same name: prefix needs `zzz`, presence needs only the header.
        (
            "predicate op",
            vec![pred(8, FIELD_VALUE_PREFIX, "x-tier", "zzz")],
            vec![pred(8, FIELD_PRESENT, "x-tier", "zzz")],
            tiered_pro.clone(),
            true,
        ),
    ];
    for (member, base, alt, req, alt_matches) in extra {
        let first = AcceptHost::open_with(ops, base, Script::default());
        let mut second = AcceptHost::open_again(&first, alt);
        let _ = second.ingest(&req);
        let asked = first.asked();
        let ok = if alt_matches {
            matches!(
                &asked[..],
                [Asked::Auth { .. }, Asked::HandIn { line: 8, .. }]
            )
        } else {
            matches!(
                &asked[..],
                [Asked::Refuse {
                    cause: REFUSE_NO_ROUTE,
                    ..
                }]
            )
        };
        assert!(
            ok,
            "{label}: a list differing in its {member} only is framed under its own list: {asked:?}"
        );
        first.close();
    }

    for (member, base, alt, expect) in cases {
        let first = AcceptHost::open_with(ops, base, Script::default());
        let mut second = AcceptHost::open_again(&first, alt);
        let _ = second.ingest(POST_HELLO);
        let asked = first.asked();
        assert!(
            expect(&asked),
            "{label}: a list differing in its {member} only is framed under its own list: {asked:?}"
        );
        first.close();
    }
}

/// [`line`] for `POST /v1/messages` that also needs the header `x-tier` to start with `prefix`.
fn tiered_line(id: u32, prefix: &'static str) -> LineEntry {
    let preds: &'static [FieldPredicate] = Box::leak(Box::new([FieldPredicate {
        op: FIELD_VALUE_PREFIX,
        _reserved: 0,
        name: s("x-tier"),
        value: s(prefix),
    }]));
    let mut l = line(id, POINT_HEAD, METHOD_POST, "/v1/messages", 0);
    l.route.fields = preds.as_ptr();
    l.route.fields_len = preds.len();
    l
}

/// `POST_HELLO` carrying `x-tier: tier`.
fn tiered_post(tier: &str) -> Vec<u8> {
    format!(
        "POST /v1/messages HTTP/1.1\r\nhost: busbar.test\r\nx-tier: {tier}\r\ncontent-length: 5\r\n\r\nhello"
    )
    .into_bytes()
}

/// A second connection on ONE instance whose list is identical to the first's is admitted under the
/// same handle (the kept copy serves it), and one whose predicate differs in its value alone is
/// matched under ITS predicate: a stale reuse would refuse it for want of a route.
fn an_identical_list_is_reused_and_a_field_change_is_not(label: &str, ops: &'static Ops) {
    let first = admitted(
        ops,
        vec![tiered_line(8, "a-")],
        Script::default(),
        &tiered_post("a-1"),
    );
    let mut same = AcceptHost::open_again(&first, vec![tiered_line(8, "a-")]);
    assert_eq!(same.ingest(&tiered_post("a-2")), Outcome::Ready);
    let mut other = AcceptHost::open_again(&first, vec![tiered_line(8, "b-")]);
    assert_eq!(other.ingest(&tiered_post("b-1")), Outcome::Ready);
    let asked = first.asked();
    assert!(
        matches!(
            &asked[..],
            [
                Asked::Auth { auth: 108, .. },
                Asked::HandIn { auth: 108, .. },
                Asked::Auth { auth: 108, .. },
                Asked::HandIn { auth: 108, .. },
                Asked::Auth { auth: 108, .. },
                Asked::HandIn { auth: 108, .. },
            ]
        ),
        "{label}: each connection matched under its own list: {asked:?}"
    );
    first.close();
}

/// Run `cell` through the linked door and the dropped-in one.
fn both(cell: fn(&str, &'static Ops)) {
    let (d, _lib) = dropped();
    for (label, ops) in [("linked", linked()), ("dropped", d)] {
        cell(label, ops);
    }
}

fn policy_blob(generation: u64, id: u32, points: u32, limit: u64) -> Vec<u8> {
    use busbar_contract::abi::{mechanism::extensions, transport::guest_policy};
    let value = guest_policy::encode(
        7,
        generation,
        &[guest_policy::GuestLine {
            line: id,
            points,
            auth: AuthRef {
                id: 100 + u64::from(id),
                mac: 7,
            },
            body_limit: limit,
            methods: METHOD_ANY,
            path_form: PATH_EXACT,
            path: "/v1/messages".into(),
            fields: Vec::new(),
            rung: 0,
        }],
    )
    .unwrap();
    extensions::encode(&[(guest_policy::EXT_GUEST_POLICY, &value)])
}

fn policy_before_auth(label: &str, ops: &'static Ops) {
    policy_before_auth_points(label, ops, POINT_HEAD);
}

fn policy_before_auth_points(label: &str, ops: &'static Ops, points: u32) {
    let initial = policy_blob(1, 1, 0, 0);
    let (mut h, began) = AcceptHost::open_on_policy(
        ops,
        vec![line(1, 0, METHOD_POST, "/v1/messages", 0)],
        Script {
            pend: 1,
            ..Script::default()
        },
        |_| {},
        SCHEME_PLAIN,
        &initial,
    );
    assert_eq!(began, Outcome::Ready, "{label}");
    let (result, request) = h.ingest_policy(POST_HELLO, &[], 0);
    if request.is_none() {
        h.close();
        panic!("{label}: a new stream was processed without asking for its policy");
    }
    assert_eq!(result, Outcome::Ready, "{label}");
    let request = request.unwrap();
    assert_eq!((request.stream, request.known_generation), (1, 1));
    assert!(
        h.asked().is_empty(),
        "{label}: no match/auth before the loan"
    );
    assert_eq!(h.heads_up(), 0);
    let reply = policy_blob(2, 9, points, 0);
    assert_eq!(
        h.ingest_policy(POST_HELLO, &reply, 0).0,
        Outcome::Pending,
        "{label}"
    );
    assert_eq!(h.heads_up(), 0);
    assert_eq!(
        h.ingest_policy(POST_HELLO, &reply, FLAG_RESUME).0,
        Outcome::Ready,
        "{label}"
    );
    let asked = h.asked();
    let auth_points: Vec<_> = asked
        .iter()
        .filter_map(|asked| match asked {
            Asked::Auth {
                auth: 109, point, ..
            } => Some(*point),
            _ => None,
        })
        .collect();
    assert_eq!(
        auth_points,
        if points & POINT_PEER != 0 {
            vec![POINT_PEER, POINT_PEER, POINT_HEAD]
        } else {
            vec![POINT_HEAD, POINT_HEAD]
        },
        "{label}: {asked:?}"
    );
    assert!(
        matches!(
            asked.last(),
            Some(Asked::HandIn {
                auth: 109,
                line: 9,
                ..
            })
        ),
        "{label}: {asked:?}"
    );
    assert_eq!(
        h.seqs()[0],
        h.seqs()[1],
        "{label}: resume retains completion identity"
    );
    assert_eq!(h.heads_up(), 1);
    assert_eq!(
        h.cancel(h.ticket),
        CANCEL_NOTHING_MOVED,
        "{label}: a later cancellation does not revoke a published request"
    );
    h.close();
}

fn opening_peer_pending(label: &str, ops: &'static Ops) {
    let policy = policy_blob(1, 6, POINT_PEER | POINT_HEAD, 0);
    let (mut h, began) = AcceptHost::open_on_policy(
        ops,
        vec![line(
            6,
            POINT_PEER | POINT_HEAD,
            METHOD_POST,
            "/v1/messages",
            0,
        )],
        Script {
            pend: 1,
            ..Script::default()
        },
        |_| {},
        SCHEME_PLAIN,
        &policy,
    );
    if began != Outcome::Pending {
        h.close();
        assert_eq!(
            began,
            Outcome::Pending,
            "{label}: Peer must run before Begin READY"
        );
        return;
    }
    assert_eq!(
        h.framing, 0,
        "{label}: no token published before peer completion"
    );
    assert!(matches!(
        &h.asked()[..],
        [Asked::Auth {
            point: POINT_PEER,
            ..
        }]
    ));
    assert_eq!(
        h.begin_policy_again(&policy, FLAG_RESUME),
        Outcome::Ready,
        "{label}"
    );
    assert_ne!(h.framing, 0);
    assert_eq!(
        h.seqs(),
        [1, 1],
        "{label}: resume reuses the provisional framing and peer call"
    );
    h.close();
}

fn opening_peer_cancel(label: &str, ops: &'static Ops) {
    let policy = policy_blob(1, 6, POINT_PEER, 0);
    let (mut h, began) = AcceptHost::open_on_policy(
        ops,
        vec![line(6, POINT_PEER, METHOD_POST, "/v1/messages", 0)],
        Script {
            pend: 2,
            ..Script::default()
        },
        |_| {},
        SCHEME_PLAIN,
        &policy,
    );
    if began != Outcome::Pending {
        h.close();
        assert_eq!(
            began,
            Outcome::Pending,
            "{label}: Peer must run during Begin"
        );
        return;
    }
    assert_eq!(h.cancel(h.ticket), CANCEL_PARTIAL, "{label}");
    assert_eq!(
        h.begin_policy_again(&policy, 0),
        Outcome::Pending,
        "{label}: cancellation removed the provisional opening"
    );
    assert_eq!(
        h.begin_policy_again(&policy, FLAG_RESUME),
        Outcome::Ready,
        "{label}"
    );
    assert_eq!(
        h.seqs(),
        [1, 1, 1],
        "{label}: a fresh framing after cancel then its resume"
    );
    h.close();
}

fn multiplexed_pending_policies(label: &str, ops: &'static Ops) {
    let initial = policy_blob(1, 1, 0, 0);
    let (mut h, began) = AcceptHost::open_on_policy(
        ops,
        vec![line(1, 0, METHOD_ANY, "/v1/messages", 0)],
        Script {
            pend: 1,
            ..Script::default()
        },
        |_| {},
        SCHEME_PLAIN,
        &initial,
    );
    assert_eq!(began, Outcome::Ready);
    let bytes = h2_requests(&[(1, "/v1/messages"), (3, "/v1/messages")]);
    let mut request = h.ingest_policy(&bytes, &[], 0).1;
    if request.is_none() {
        request = h.ingest_policy(&[], &[], 0).1;
    }
    if request.is_none() {
        h.close();
        panic!("{label}: multiplexed streams did not request host policy");
    }
    assert_eq!(request.unwrap().stream, 1);
    let old = policy_blob(2, 9, POINT_HEAD, 0);
    assert_eq!(h.ingest_policy(&[], &old, 0).0, Outcome::Pending);
    let first_ticket = h.ticket;
    h.ticket.slot += 1;
    let (result, second) = h.ingest_policy(&[], &[], 0);
    assert_eq!(result, Outcome::Ready);
    assert_eq!(second.unwrap().stream, 2);
    let new = policy_blob(3, 10, POINT_HEAD, 0);
    assert_eq!(h.ingest_policy(&[], &new, 0).0, Outcome::Ready);
    assert_eq!(
        h.heads_up(),
        1,
        "{label}: the sibling progresses while the first auth is pending"
    );
    h.ticket = first_ticket;
    assert_eq!(h.ingest_policy(&[], &old, FLAG_RESUME).0, Outcome::Ready);
    assert!(
        matches!(
            &h.asked()[..],
            [
                Asked::Auth { auth: 109, .. },
                Asked::Auth { auth: 110, .. },
                Asked::HandIn {
                    auth: 110,
                    line: 10,
                    ..
                },
                Asked::Auth { auth: 109, .. },
                Asked::HandIn {
                    auth: 109,
                    line: 9,
                    ..
                },
            ]
        ),
        "{label}: {:?}",
        h.asked()
    );
    assert_eq!(h.heads_up(), 2);
    h.close();
}

fn cancel_unpublished_heads(label: &str, ops: &'static Ops) {
    let policy = policy_blob(2, 9, POINT_HEAD_BODY, 8);
    let (mut h, began) = AcceptHost::open_on_policy(
        ops,
        vec![line(9, POINT_HEAD_BODY, METHOD_ANY, "/v1/messages", 8)],
        Script {
            pend_call: Some(2),
            ..Script::default()
        },
        |_| {},
        SCHEME_PLAIN,
        &policy,
    );
    assert_eq!(began, Outcome::Ready);
    let mut bytes = h2_requests(&[(1, "/v1/messages"), (3, "/v1/messages")]);

    let mut at = 24;
    while at + 9 <= bytes.len() {
        let len = (usize::from(bytes[at]) << 16)
            | (usize::from(bytes[at + 1]) << 8)
            | usize::from(bytes[at + 2]);
        if bytes[at + 3] == 1 {
            bytes[at + 4] &= !1;
        }
        at += 9 + len;
    }
    let mut request = h.ingest_policy(&bytes, &[], 0).1;
    if request.is_none() {
        request = h.ingest_policy(&[], &[], 0).1;
    }
    if request.is_none() {
        h.close();
        panic!("{label}: a gated body was processed without its host policy");
    }
    assert_eq!(request.unwrap().stream, 1);
    assert_eq!(h.ingest_policy(&[], &policy, 0).1.unwrap().stream, 2);
    assert_eq!(h.ingest_policy(&[], &policy, 0).0, Outcome::Ready);
    assert!(h.asked().is_empty());
    h.ticket.slot += 1;
    let mut body = h2_frame(0, 1, 1, b"aa");
    body.extend(h2_frame(0, 1, 3, b"bb"));
    assert_eq!(h.ingest_policy(&body, &[], 0).0, Outcome::Pending);
    assert_eq!(
        h.heads_up(),
        0,
        "{label}: PENDING did not publish the earlier sibling's queued head"
    );
    let asked = h.asked();
    let tags: Vec<_> = asked
        .iter()
        .map(|asked| match asked {
            Asked::Auth { .. } => "Auth",
            Asked::HandIn { .. } => "HandIn",
            Asked::Refuse { .. } => "Refuse",
        })
        .collect();
    assert!(
        matches!(
            &asked[..],
            [Asked::Auth { .. }, Asked::HandIn { .. }, Asked::Auth { .. }]
        ),
        "{label}: operation tags {tags:?}"
    );
    assert_eq!(h.cancel(h.ticket), CANCEL_PARTIAL);
    assert_eq!(h.ingest_policy(&[], &[], 0).0, Outcome::Ready);
    assert_eq!(
        h.heads_up(),
        0,
        "{label}: a cancelled operation cannot later publish its queued admission"
    );
    h.close();
}

fn multiplex_policy_progress(label: &str, ops: &'static Ops) {
    use busbar_contract::abi::{mechanism::extensions, transport::guest_policy};
    let initial = policy_blob(1, 1, 0, 0);
    let (mut h, began) = AcceptHost::open_on_policy(
        ops,
        vec![line(1, 0, METHOD_ANY, "/v1/messages", 0)],
        Script::default(),
        |_| {},
        SCHEME_PLAIN,
        &initial,
    );
    assert_eq!(began, Outcome::Ready);
    let requests: Vec<_> = (0..65).map(|n| (2 * n + 1, "/v1/messages")).collect();
    let bytes = h2_requests(&requests);
    let mut input = bytes.as_slice();
    let mut reply = Vec::new();
    let mut opened = std::collections::BTreeSet::new();
    let mut previous_heads = 0;
    let mut previous_wire = 0;
    for _ in 0..(requests.len() * 4) {
        let (result, request) = h.ingest_policy(input, &reply, 0);
        assert_eq!(result, Outcome::Ready, "{label}");
        input = &[];
        reply.clear();
        if let Some(request) = request {
            assert!(
                opened.insert(request.stream),
                "{label}: each stream opens once"
            );
            if opened.len() > 1 {
                assert!(
                    h.heads_up() > previous_heads || h.out.len() > previous_wire,
                    "{label}: flush progress between fresh policy requests"
                );
            }
            previous_heads = h.heads_up();
            previous_wire = h.out.len();
            reply = if request.known_generation == 2 {
                let ack = guest_policy::Identity {
                    listener: 7,
                    generation: 2,
                }
                .encode()
                .unwrap();
                extensions::encode(&[(guest_policy::EXT_GUEST_CURRENT, &ack)])
            } else {
                policy_blob(2, 9, 0, 0)
            };
        }
        if h.heads_up() == requests.len() {
            break;
        }
    }
    let heads = h.heads_up();
    h.close();
    assert_eq!(
        opened.len(),
        requests.len(),
        "{label}: every stream obtains a loan"
    );
    assert_eq!(
        heads,
        requests.len(),
        "{label}: all multiplexed requests progress"
    );
}

#[test]
fn a_stream_gets_its_policy_before_auth_linked_and_dropped_in() {
    both(policy_before_auth);
}

#[test]
fn a_reloaded_policy_completes_its_peer_verdict_before_head_auth_linked_and_dropped_in() {
    both(|label, ops| policy_before_auth_points(label, ops, POINT_PEER | POINT_HEAD));
}

#[test]
fn multiplexed_pending_streams_keep_distinct_policy_generations_linked_and_dropped_in() {
    both(multiplexed_pending_policies);
}

#[test]
fn cancelling_an_auth_operation_discards_its_unpublished_sibling_heads_linked_and_dropped_in() {
    both(cancel_unpublished_heads);
}

#[test]
fn peer_checks_run_during_begin_and_resume_the_same_opening_linked_and_dropped_in() {
    both(opening_peer_pending);
}

#[test]
fn cancelling_a_pending_begin_drops_its_provisional_framing_linked_and_dropped_in() {
    both(opening_peer_cancel);
}

#[test]
fn multiplexed_streams_flush_progress_between_policy_requests_linked_and_dropped_in() {
    both(multiplex_policy_progress);
}

#[test]
fn an_unrouted_request_is_the_kernels_no_route_refusal_and_nothing_goes_up() {
    both(no_route);
}

#[test]
fn a_path_no_line_admits_the_method_of_is_the_kernels_method_miss() {
    both(method_miss);
}

#[test]
fn a_head_auth_stop_is_the_kernels_refusal_with_the_unit() {
    both(head_stop);
}

#[test]
fn a_changed_guest_list_on_one_instance_is_not_served_from_the_kept_copy() {
    both(a_changed_list_is_not_reused);
}

#[test]
fn an_identical_guest_list_is_reused_and_a_changed_predicate_is_not() {
    both(an_identical_list_is_reused_and_a_field_change_is_not);
}

#[test]
fn a_held_body_over_its_limit_is_refused_before_any_auth_call() {
    both(over_gate);
}

#[test]
fn a_held_body_within_its_limit_is_shown_to_the_auth_then_goes_up() {
    both(head_body_within);
}

#[test]
fn what_the_auth_names_is_stripped_before_the_hand_in_and_before_anything_goes_up() {
    both(strips);
}

#[test]
fn a_hand_in_stop_is_the_kernels_check_failed_refusal() {
    both(hand_in_stop);
}

#[test]
fn a_none_line_is_handed_in_with_no_unit_and_goes_up() {
    both(none_line);
}

#[test]
fn the_unit_the_first_call_minted_is_carried_on_every_later_one() {
    both(unit_carried);
}

#[test]
fn a_failed_hand_in_never_reaches_the_plane() {
    both(hand_in_fails);
}

#[test]
fn a_failed_auth_call_never_reaches_the_plane() {
    both(auth_call_fails);
}

#[test]
fn a_failed_refusal_never_reaches_the_plane() {
    both(refusal_fails);
}

#[test]
fn a_percent_encoded_query_key_is_stripped_as_the_key_it_decodes_to() {
    both(strips_a_decoded_query_key);
}

#[test]
fn a_timer_never_calls_the_auth_handle_nor_pends() {
    both(timer_never_calls_the_auth);
}

#[test]
fn a_resumed_op_reissues_the_same_handle_and_takes_no_byte_twice() {
    both(a_resume_reissues_the_same_handle);
}

#[test]
fn a_cancel_of_a_parked_op_is_partial_and_lets_the_call_go() {
    both(cancel_of_a_parked_op);
}

#[test]
fn a_request_decoded_during_a_refuse_is_admitted_in_it() {
    both(a_request_decoded_during_refuse_is_admitted);
}

#[test]
fn a_refused_detach_hands_over_no_owed_byte_and_loses_none() {
    both(a_refused_detach_keeps_the_owed_bytes);
}

#[test]
fn a_resumed_emit_states_its_stream_full_linked_and_dropped_in() {
    both(a_resumed_emit_states_its_stream_full);
}

#[test]
fn a_cancel_meeting_a_held_framing_is_not_nothing_moved() {
    both(cancel_meeting_a_held_framing);
}

#[test]
fn pipelined_requests_are_each_answered_in_the_op_that_decoded_them() {
    both(pipelined_refusals);
}

#[test]
fn a_stream_refused_before_its_head_is_answered_with_the_refusal() {
    both(refuse_a_stream_before_its_head);
}

#[test]
fn a_stream_refused_after_its_head_ends_failed() {
    both(refuse_a_stream_after_its_head);
}

#[test]
fn a_connection_refused_whole_is_written_and_ends() {
    both(refuse_the_connection);
}

#[test]
fn the_auth_is_shown_the_scheme_the_connection_states() {
    both(shows_the_scheme);
}

#[test]
fn a_pending_auth_call_parks_only_its_own_stream_on_its_own_ticket() {
    both(parks_on_its_own_ticket);
}

#[test]
fn the_door_offers_the_peer_point_linked_and_dropped_in() {
    let (_, lib) = dropped();
    // SAFETY: the one exported symbol, a `DoorFn`.
    let dropped: libloading::Symbol<'_, extern "C" fn() -> *const Door> =
        unsafe { lib.get(DOOR_SYMBOL) }.expect("the door symbol");
    offers_the_peer_point("linked", busbar_transport_http_plugin::door::door());
    offers_the_peer_point("dropped", dropped());
}

#[test]
fn the_peer_point_is_called_once_per_connection_before_any_head() {
    both(peer_once_per_connection);
}

#[test]
fn a_peer_answer_naming_lines_is_refused_and_nothing_goes_up() {
    both(a_peer_answer_naming_lines_is_refused);
}

#[test]
fn an_alpn_h2_connection_is_served_as_h2() {
    both(alpn_h2_is_served_as_h2);
}

#[test]
fn a_pending_auth_call_parks_only_its_own_stream_and_others_flow() {
    both(a_pending_auth_parks_only_its_stream);
}

#[test]
fn unit_refuse_is_handed_the_request_it_refuses() {
    both(refusal_carries_the_request);
}

#[test]
fn a_kernel_refusal_keeps_its_fields_linked_and_dropped_in() {
    both(kernel_refusal_keeps_its_fields);
}

#[test]
fn a_101_upgrade_is_detached_unanswered_linked_and_dropped_in() {
    both(upgrade_detached_unanswered);
}

#[test]
fn a_head_request_is_answered_without_a_body_linked_and_dropped_in() {
    both(head_answered_without_a_body);
}

#[test]
fn the_header_read_bound_closes_a_trickled_head_linked_and_dropped_in() {
    both(header_read_bound);
}

#[test]
fn a_host_framed_refusal_arrives_byte_identical_linked_and_dropped_in() {
    both(host_framed_refusal_arrives_byte_identical);
}

#[test]
fn an_answer_ending_with_the_body_unread_ends_the_stream_as_hyper_did_linked_and_dropped_in() {
    both(answer_ends_with_the_body_unread);
}

#[test]
fn the_accepted_side_states_the_protocol_it_agreed_linked_and_dropped_in() {
    both(states_the_protocol_it_agreed);
}

#[test]
fn a_cleartext_accepting_offer_changes_nothing_else_linked_and_dropped_in() {
    both(a_cleartext_offer_changes_nothing_else);
}

#[test]
fn pump_until_returns_the_actual_framing_failure() {
    both(|label, ops| {
        let (to_server, _server) = mpsc::unbounded_channel();
        let (release, _release) = mpsc::channel(1);
        let sock = Arc::new(Socket {
            rx: Mutex::new((VecDeque::from(b"not a valid framing".to_vec()), true)),
            silent: AtomicBool::new(false),
            to_server,
            release,
        });
        let mut host = Host::open(ops, "{}", sock, ROOMY);

        let polls = std::cell::Cell::new(0);
        let result = host.pump_until(
            |_| {
                let before = polls.get();
                polls.set(before + 1);
                before != 0
            },
            &mut Vec::new(),
        );
        host.close();
        assert_eq!(
            result,
            Outcome::Failed,
            "{label}: propagate the real op failure"
        );
    });
}

impl AcceptHost {
    /// Copy reply metadata while the actual door's output lease is live, on PENDING as well as
    fn ingest_retained(&mut self, bytes: &[u8], flags: u32) -> (Outcome, Option<u64>, bool) {
        let mut i: IngestIn = z();
        i.head.ticket = self.ticket;
        i.head.flags = flags;
        i.framing = self.framing;
        i.bytes = bytes.as_ptr();
        i.len = bytes.len();
        i.sink = self.sink();
        let mut o: FramerOut = z();
        // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
        // and the door instance for this synchronous call; the selected slot and index agree.
        let result = unsafe { call(self.ops.ingest, self.inst, &mut i, &mut o, slot::INGEST) };
        // SAFETY: this door answer's lease has not been released; copy its reported bytes now.
        let ext = unsafe { bytes_of(o.head.extensions.ptr, o.head.extensions.len) };
        let retained =
            busbar_contract::abi::mechanism::extensions::get(&ext, "framer.retained_input")
                .map(|v| u64::from_le_bytes(v.try_into().expect("one copied numeric count")));
        let more = o.yielded.flags & YIELD_MORE != 0;
        let result = self.take(result, &o);
        if o.head.lease != 0 {
            let mut release: busbar_contract::abi::mechanism::lifecycle::ReleaseIn = z();
            release.lease = o.head.lease;
            let mut out: OutHead = z();
            assert_eq!(
                // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
                // and the door instance for this synchronous call; the selected slot and index agree.
                unsafe {
                    call(
                        self.ops.head.release,
                        self.inst,
                        &mut release,
                        &mut out,
                        life::RELEASE,
                    )
                },
                Outcome::Ready
            );
        }
        (result, retained, more)
    }

    fn drain_retained(&mut self, mut answer: (Outcome, Option<u64>, bool)) -> u64 {
        for _ in 0..256 {
            assert_eq!(answer.0, Outcome::Ready);
            if !answer.2 {
                return answer.1.expect("current retained-input report");
            }
            answer = self.ingest_retained(&[], 0);
        }
        panic!("finite buffered output must drain");
    }
}

fn pending_input_reports_pressure_and_resumes(label: &str, ops: &'static Ops) {
    const WINDOW: usize = 1024 * 1024;
    const CHUNK: usize = 16 * 1024;
    let body = vec![b'x'; 2 * WINDOW];
    let header = format!(
        "POST /v1/messages HTTP/1.1\r\nhost: busbar.test\r\ncontent-length: {}\r\n\r\n",
        body.len()
    );
    let mut h = AcceptHost::open_with(
        ops,
        vec![line(3, POINT_HEAD, METHOD_POST, "/v1/messages", 0)],
        Script {
            pend: 1,
            ..Script::default()
        },
    );
    let first = h.ingest_retained(header.as_bytes(), 0);
    assert_eq!(first.0, Outcome::Pending, "{label}");
    assert!(
        first.1.is_some(),
        "{label}: PENDING must report retained input too"
    );
    let pending = h.ticket;
    h.ticket.slot += 1;
    let mut sent = 0;
    let pressure = loop {
        assert!(
            sent < body.len(),
            "{label}: pending body never exerted receive pressure"
        );
        let answer = h.ingest_retained(&body[sent..sent + CHUNK], 0);
        sent += CHUNK;
        assert_eq!(answer.0, Outcome::Ready);
        assert!(!answer.2);
        let retained = answer.1.expect("fresh ingest reports what remains private");
        assert!(retained <= sent as u64, "input is not counted twice");
        if retained >= WINDOW as u64 {
            break retained;
        }
    };
    assert!(pressure < (WINDOW + CHUNK) as u64);
    assert_eq!(h.heads_up(), 0, "auth still prevents publication");
    h.ticket = pending;
    let resumed = h.ingest_retained(&[], FLAG_RESUME);
    assert_eq!(
        h.drain_retained(resumed),
        0,
        "{label}: all yielded bytes leave the private count"
    );
    for bytes in body[sent..].chunks(CHUNK) {
        let answer = h.ingest_retained(bytes, 0);
        assert_eq!(h.drain_retained(answer), 0);
    }
    assert_eq!(h.heads_up(), 1);
    let actual: Vec<u8> = h
        .got
        .iter()
        .filter(|g| g.2 & PIECE_FIELDS == 0)
        .flat_map(|g| g.1.iter().copied())
        .collect();
    assert_eq!(
        actual, body,
        "{label}: resume preserves the complete body exactly once"
    );
    let seqs = h.seqs();
    assert_eq!(seqs.len(), 2);
    assert_eq!(
        seqs[0], seqs[1],
        "auth resumes the original completion handle"
    );
    h.close();
}

fn head_body_larger_than_receive_window_keeps_progress(label: &str, ops: &'static Ops) {
    const WINDOW: usize = 1024 * 1024;
    let body = vec![b'z'; WINDOW + 32 * 1024];
    let header = format!(
        "POST /v1/messages HTTP/1.1\r\nhost: busbar.test\r\ncontent-length: {}\r\n\r\n",
        body.len()
    );
    let mut h = AcceptHost::open_with(
        ops,
        vec![line(
            3,
            POINT_HEAD_BODY,
            METHOD_POST,
            "/v1/messages",
            (2 * WINDOW) as u64,
        )],
        Script::default(),
    );
    let initial = h.ingest_retained(header.as_bytes(), 0);
    assert_eq!(h.drain_retained(initial), 0);
    for bytes in body.chunks(16 * 1024) {
        let answer = h.ingest_retained(bytes, 0);
        assert_eq!(
            h.drain_retained(answer),
            0,
            "{label}: policy-bound body collection must keep accepting input"
        );
    }
    assert!(h.asked().iter().any(|a| matches!(a,
        Asked::Auth { point: POINT_HEAD_BODY, body: Some(bytes), .. } if bytes == &body)));
    assert_eq!(h.heads_up(), 1);
    h.close();
}

#[test]
fn pending_auth_reports_receive_pressure_and_resumes_linked_and_dropped_in() {
    both(pending_input_reports_pressure_and_resumes);
}

#[test]
fn head_body_over_one_receive_window_completes_linked_and_dropped_in() {
    both(head_body_larger_than_receive_window_keeps_progress);
}

impl AcceptHost {
    fn emit_kind(
        &mut self,
        stream: u64,
        bytes: &[u8],
        end: bool,
        status: u32,
        kind_flags: u32,
        head_flags: u32,
    ) -> (Outcome, u32) {
        let mut input: EmitIn = z();
        input.head.ticket = self.ticket;
        input.head.flags = head_flags;
        input.framing = self.framing;
        input.stream = stream;
        input.bytes = bytes.as_ptr();
        input.len = bytes.len();
        input.end_of_frame = u32::from(end);
        input.status = status;
        input.flags = kind_flags;
        input.sink = self.sink();
        let mut out: FramerOut = z();
        // SAFETY: this fixture lends the matching concrete ABI frames and owns their nested buffers
        // and the door instance for this synchronous call; the selected slot and index agree.
        let result = unsafe { call(self.ops.emit, self.inst, &mut input, &mut out, slot::EMIT) };
        let flags = out.yielded.flags;
        (self.take(result, &out), flags)
    }
}

fn terminal_fields_on_the_actual_door(label: &str, ops: &'static Ops) {
    use busbar_contract::abi::transport::{EMIT_TEXT, EMIT_TRAILERS};
    for h2 in [false, true] {
        let mut host =
            AcceptHost::open_with(ops, vec![line(1, 0, METHOD_ANY, "/", 0)], Script::default());
        let request = if h2 {
            h2_requests(&[(1, "/")])
        } else {
            b"GET / HTTP/1.1\r\nhost: busbar.test\r\nte: trailers\r\n\r\n".to_vec()
        };
        assert_eq!(host.ingest(&request), Outcome::Ready, "{label}");
        assert_eq!(host.heads_up(), 1);
        let trailer = b"x-check: first\r\nx-check: second\r\n";
        assert_eq!(
            host.emit_kind(1, trailer, true, 0, EMIT_TRAILERS, 0).0,
            Outcome::Failed,
            "{label}: no trailer before head"
        );
        assert_eq!(
            host.emit(1, b"trailer: x-check\r\n", false, 201),
            Outcome::Ready
        );
        assert_eq!(host.emit(1, b"hello", false, 0), Outcome::Ready);
        for (fields, end, status, flags) in [
            (
                b"x-check: good\r\nbroken".as_slice(),
                true,
                0,
                EMIT_TRAILERS,
            ),
            (trailer.as_slice(), false, 0, EMIT_TRAILERS),
            (trailer.as_slice(), true, 200, EMIT_TRAILERS),
            (trailer.as_slice(), true, 0, EMIT_TRAILERS | EMIT_TEXT),
            (trailer.as_slice(), true, 0, 0x8000_0000),
        ] {
            assert_eq!(
                host.emit_kind(1, fields, end, status, flags, 0).0,
                Outcome::Failed,
                "{label}: malformed terminal emit is refused before mutation"
            );
        }
        host.wire.resize(7, 0);
        let (result, mut flags) = host.emit_kind(1, trailer, true, 0, EMIT_TRAILERS, 0);
        assert_eq!(
            result,
            Outcome::Ready,
            "{label}: valid trailer follows rejections"
        );
        for _ in 0..256 {
            if flags & YIELD_MORE == 0 {
                break;
            }
            let (result, next) = host.emit_kind(1, &[], false, 0, 0, 0);
            assert_eq!(result, Outcome::Ready);
            flags = next;
        }
        assert_eq!(flags & YIELD_MORE, 0, "{label}: finite trailer drains");
        assert_eq!(
            host.emit_kind(1, trailer, true, 0, EMIT_TRAILERS, 0).0,
            Outcome::Failed,
            "{label}: final fields are accepted once"
        );
        if h2 {
            let mut at = 0;
            let mut frames = Vec::new();
            while at + 9 <= host.out.len() {
                let len = (usize::from(host.out[at]) << 16)
                    | (usize::from(host.out[at + 1]) << 8)
                    | usize::from(host.out[at + 2]);
                assert!(
                    at + 9 + len <= host.out.len(),
                    "{label}: whole captured HTTP/2 frame"
                );
                let stream = u32::from_be_bytes(host.out[at + 5..at + 9].try_into().unwrap());
                if stream == 1 {
                    frames.push((host.out[at + 3], host.out[at + 4]));
                }
                at += 9 + len;
            }
            assert_eq!(at, host.out.len());
            assert_eq!(
                frames.iter().map(|frame| frame.0).collect::<Vec<_>>(),
                [1, 0, 1],
                "{label}: HEADERS, DATA, trailing HEADERS"
            );
            assert_eq!(
                frames.last().unwrap().1 & 1,
                1,
                "{label}: trailers end stream"
            );
        } else {
            assert!(
                host.out
                    .ends_with(b"5\r\nhello\r\n0\r\nx-check: first\r\nx-check: second\r\n\r\n"),
                "{label}: final fields follow the body exactly once: {:?}",
                String::from_utf8_lossy(&host.out)
            );
        }
        host.close();
    }
}

#[test]
fn final_fields_are_terminal_wire_fields_linked_and_dropped_in() {
    both(terminal_fields_on_the_actual_door);
}

fn pending_terminal_fields_are_consumed_once(label: &str, ops: &'static Ops) {
    use busbar_contract::abi::transport::EMIT_TRAILERS;
    for cancel in [false, true] {
        let mut host = AcceptHost::open_with(
            ops,
            vec![
                line(3, POINT_HEAD, METHOD_ANY, "/a", 0),
                line(5, 0, METHOD_ANY, "/b", 0),
            ],
            Script {
                pend: 1,
                ..Script::default()
            },
        );
        assert_eq!(
            host.ingest(&h2_requests(&[(1, "/a"), (3, "/b")])),
            Outcome::Pending
        );
        let first = host.ticket;
        host.ticket.slot = 2;
        assert_eq!(host.ingest(&[]), Outcome::Ready);
        let stream = host
            .words
            .iter()
            .find(|(_, _, path)| path == b"/b")
            .unwrap()
            .0;
        assert_eq!(host.emit(stream, b"", false, 200), Outcome::Ready);
        assert_eq!(host.emit(stream, b"hello", false, 0), Outcome::Ready);
        assert_eq!(host.cancel(first), CANCEL_PARTIAL);
        scripts().get_mut(&host.ctx).unwrap().pend = 1;
        host.ticket.slot = 3;
        host.wire.resize(7, 0);
        assert_eq!(
            host.emit_kind(stream, b"x-check: once\r\n", true, 0, EMIT_TRAILERS, 0)
                .0,
            Outcome::Pending,
            "{label}: final fields accepted before sibling auth parks"
        );
        let (result, mut flags) = if cancel {
            assert_eq!(host.cancel(host.ticket), CANCEL_PARTIAL);
            host.ticket.slot = 4;
            host.emit_kind(stream, &[], false, 0, 0, 0)
        } else {
            host.emit_kind(stream, &[], false, 0, 0, FLAG_RESUME)
        };
        assert_eq!(
            result,
            Outcome::Ready,
            "{label}: accepted trailer survives resume/cancel"
        );
        for _ in 0..256 {
            if flags & YIELD_MORE == 0 {
                break;
            }
            let (result, next) = host.emit_kind(stream, &[], false, 0, 0, 0);
            assert_eq!(result, Outcome::Ready);
            flags = next;
        }
        assert_eq!(flags & YIELD_MORE, 0, "{label}: finite wire drains");
        let (mut at, mut terminal_headers, mut data) = (0, 0, Vec::new());
        while at + 9 <= host.out.len() {
            let len = (usize::from(host.out[at]) << 16)
                | (usize::from(host.out[at + 1]) << 8)
                | usize::from(host.out[at + 2]);
            assert!(at + 9 + len <= host.out.len());
            let wire_stream = u32::from_be_bytes(host.out[at + 5..at + 9].try_into().unwrap());
            if wire_stream == 3 {
                if host.out[at + 3] == 1 && host.out[at + 4] & 1 != 0 {
                    terminal_headers += 1;
                }
                if host.out[at + 3] == 0 {
                    data.extend_from_slice(&host.out[at + 9..at + 9 + len]);
                }
            }
            at += 9 + len;
        }
        assert_eq!(at, host.out.len());
        assert_eq!(
            terminal_headers, 1,
            "{label}: accepted final fields are serialized once"
        );
        assert_eq!(data, b"hello", "{label}: fields never become body bytes");
        host.close();
    }
}

#[test]
fn pending_or_cancelled_final_emits_keep_accepted_wire_once_linked_and_dropped_in() {
    both(pending_terminal_fields_are_consumed_once);
}
