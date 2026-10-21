// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `http` DOOR'S CONFORMANCE: the same door, compiled in and dropped in, driven the same way.
//!
//! The test is the HOST. It holds the socket (an in-memory duplex to a real hyper server on a tokio
//! runtime of its own), the clock (a virtual monotonic clock it advances by hand) and the sink
//! buffers, and it calls the framer only through the transport kind's table: `begin`, `emit`,
//! `ingest`, `timer`. The framer is driven from the test's own thread, outside any runtime.
//!
//! Each scenario runs twice, through the linked door and through the cdylib `cargo test` built from
//! `src/lib.rs`, and both must print the same proof lines.

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
    LineEntry, RouteMatch, METHOD_ANY, METHOD_POST, PATH_EXACT,
};
use busbar_contract::abi::transport::{
    slot, BeginIn, ConnFacts, EmitIn, EncodeIn, FramePiece, FramerOut, FramerSink, FramingIn,
    HeadSlots, IngestIn, LocateIn, LocateOut, Ops, RefuseIn, CANCEL_NOTHING_MOVED, CANCEL_PARTIAL,
    PIECE_CONTINUED, PIECE_END, PIECE_END_OF_FRAME, PIECE_FIELDS, PIECE_HAS_CODE,
    PIECE_HAS_DECLARED_LEN, PIECE_STREAM_FAILED, SIDE_ACCEPT, SIDE_DIAL, YIELD_ENDED,
    YIELD_HAS_DEADLINE, YIELD_MORE,
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

// ── the far end: a real hyper server ─────────────────────────────────────────────────────────────

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
/// that drops the server's bytes on the floor (a far end gone silent).
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
                let got = http_body_util::BodyExt::collect(req.into_body())
                    .await
                    .expect("request body")
                    .to_bytes();
                let (tx, rx) = mpsc::channel(4);
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

// ── the host ─────────────────────────────────────────────────────────────────────────────────────

/// One frame piece as the host read it out of its sink.
#[derive(Debug, Clone)]
struct Got {
    stream: u64,
    bytes: Vec<u8>,
    flags: u16,
    code: u32,
    /// The body length the piece states its head declared (`PIECE_HAS_DECLARED_LEN`), if any.
    declared_len: Option<u64>,
}

struct Host {
    ops: &'static Ops,
    inst: *mut c_void,
    now: u64,
    framing: u64,
    sock: Arc<Socket>,
    wire_log: Vec<u8>,
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

fn call<I, O>(op: Option<Op>, inst: *mut c_void, i: &mut I, o: &mut O, index: u32) -> Outcome {
    // SAFETY: `I` leads with an `InHead`, `O` with an `OutHead` (the table's own structs).
    unsafe {
        let ih = std::ptr::from_mut(i).cast::<InHead>();
        (*ih).size = size_of::<I>() as u32;
        (*ih).op = index;
        let oh = std::ptr::from_mut(o).cast::<OutHead>();
        (*oh).size = size_of::<O>() as u32;
    }
    let raw = (op.expect("every slot is filled"))(
        inst,
        std::ptr::from_ref(i).cast(),
        std::ptr::from_mut(o).cast(),
    );
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
            now: 7 * SEC,
            framing: 0,
            sock,
            wire_log: Vec::new(),
            frame_log: Vec::new(),
            deadline: None,
            more: false,
            caps,
            // The encoded request is read out of `wire` too, so it is never smaller than a message.
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
                    call(self.ops.emit, self.inst, &mut i, &mut o, index)
                }
                slot::INGEST => {
                    let mut i: IngestIn = z();
                    i.framing = self.framing;
                    i.sink = self.sink();
                    call(self.ops.ingest, self.inst, &mut i, &mut o, index)
                }
                _ => {
                    let mut i: FramingIn = z();
                    i.framing = self.framing;
                    i.sink = self.sink();
                    call(self.ops.timer, self.inst, &mut i, &mut o, index)
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
        let r = call(self.ops.begin, self.inst, &mut i, &mut o, slot::BEGIN);
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
            // The length line the host states before the auth (THE DESIGN §6 step 5).
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
        // `encode` renders a whole message at once, so the host gives it the whole buffer.
        i.sink.wire_cap = self.wire.len();
        let mut o: FramerOut = z();
        assert_eq!(
            call(self.ops.encode, self.inst, &mut i, &mut o, slot::ENCODE),
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
        let r = call(self.ops.emit, self.inst, &mut i, &mut o, slot::EMIT);
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
        call(self.ops.encode, self.inst, &mut i, &mut o, slot::ENCODE)
    }

    /// Ingest whatever the far end has sent until it stays quiet for `quiet`; the first op that
    /// fails ends the pump with its outcome.
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
            let r = call(self.ops.ingest, self.inst, &mut i, &mut o, slot::INGEST);
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

    /// Move the clock to `at` and call `timer` if the framer asked for a deadline by then.
    fn advance(&mut self, at: u64, got: &mut Vec<Got>) -> Outcome {
        self.now = at;
        if self.deadline.is_some_and(|d| d <= at) {
            let mut i: FramingIn = z();
            i.framing = self.framing;
            i.sink = self.sink();
            let mut o: FramerOut = z();
            let r = call(self.ops.timer, self.inst, &mut i, &mut o, slot::TIMER);
            if self.take(r, &o, got) != Outcome::Ready {
                return r;
            }
            return self.drain(slot::TIMER, 0, got);
        }
        Outcome::Ready
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
        call(self.ops.head.close, self.inst, &mut i, &mut o, life::CLOSE);
    }
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

// ── the scenarios ────────────────────────────────────────────────────────────────────────────────

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
        host.pump(Duration::from_millis(300), &mut got),
        Outcome::Ready
    );
    let head = got
        .iter()
        .find(|g| g.flags & PIECE_HAS_CODE != 0)
        .expect("a head frame");
    println!("PROOF {label}: HEAD {}", head.code);
    assert_eq!((head.stream, head.code), (1, 200));
    // The head is ONE field block, flagged as one: no status line, no hop-by-hop field.
    assert_ne!(head.flags & PIECE_FIELDS, 0, "the head is a fields piece");
    // A streamed answer declares no body length, and its head piece states none: read at the
    // contract's 48-byte piece stride, the same on the linked and the dropped-in door.
    assert_eq!(head.declared_len, None, "{label}: no declared length");
    let block = String::from_utf8_lossy(&head.bytes).into_owned();
    assert!(!block.starts_with("HTTP/"), "{block}");
    // The reason phrase is a head slot, never a field: HTTP/1's exactly as sent, none on HTTP/2.
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
    host.pump(Duration::from_millis(300), &mut got);
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
/// request timeout (one clock per stream, send to body end), with a failure piece on its stream;
/// its sibling, which finished inside its own clock, is untouched and the connection lives.
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
        host.pump(Duration::from_millis(300), &mut got),
        Outcome::Ready
    );
    assert_eq!(text(&got, 3), "got=5;a", "the sibling answered");
    assert_eq!(host.advance(t0 + 4 * SEC, &mut got), Outcome::Ready);
    assert!(
        !got.iter().any(|g| g.flags & PIECE_STREAM_FAILED != 0),
        "not before 5s"
    );
    rt.block_on(sock.release.send(())).expect("release");
    host.pump(Duration::from_millis(300), &mut got);
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
    println!(
        "PROOF {label}: stream {} failed alone: {:?}",
        failed[0].stream,
        String::from_utf8_lossy(&failed[0].bytes)
    );
    assert_eq!(failed.len(), 1, "one stream failed");
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
    host.pump(Duration::from_millis(300), &mut got);
    rt.block_on(sock.release.send(())).expect("release");
    host.pump(Duration::from_millis(300), &mut got);
    assert!(ended(&got, 1), "the exchange completed");
    // A field block a small sink split mid-line says so on the piece that continues the line
    // (PIECE_CONTINUED); every other fields piece starts a line.
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
    // The server stamps its head with the second it answered in; that one field is not the
    // framer's, so it is taken out of both runs before they are compared.
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
    let out = (host.wire_log.clone(), frames);
    host.close();
    out
}

/// The re-call rule's check: an exchange collected through a sink so small that every op is
/// re-called must be the SAME bytes as one collected through a roomy sink. A framer that answered
/// anything twice on a re-call, or dropped anything, differs.
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
        // RED: a framer that answered the head frame's first piece twice is caught.
        let mut dup = tight.clone();
        let first = dup.1[..5].to_vec();
        dup.1.splice(5..5, first);
        assert!(
            recall_continues(&dup, &roomy).is_err(),
            "a duplicated piece is caught"
        );
    }
}

/// A field name that is not an RFC 9110 token (`authorization:x`) would be re-read as a second
/// `authorization` on the door's own reparse: through the whole door, `encode` fails it, linked
/// and dropped-in alike, while a token name still encodes.
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

// ── the accepted side (INBOUND-LISTEN) ───────────────────────────────────────────────────────────

/// One accepted connection driven through the table as the connector drives it: the host hands the
/// far side's raw bytes to `ingest`, reads the request's head and body out of its sink, and answers
/// through `emit`, the first emit its head with the status in `EmitIn::status`.
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
    /// `refuse` run on none, as the connector crosses them).
    ticket: Ticket,
    /// An answer said the connection is over (`YIELD_ENDED`).
    ended: bool,
    /// The host's monotonic clock, as the sink states it.
    now: u64,
}

impl AcceptHost {
    /// An accepted connection on a listener whose one line takes every `POST /v1/messages` with
    /// auth `none`, its hand-in answered CONTINUE: the request goes up as before.
    fn open(ops: &'static Ops) -> Self {
        Self::open_with(
            ops,
            vec![line(1, 0, METHOD_ANY, "/v1/messages", 0)],
            Script::default(),
        )
    }

    /// An accepted connection on a listener with guest list `lines`, the auth handle answered by
    /// `script` (`OpenIn::host`'s services table).
    fn open_with(ops: &'static Ops, lines: Vec<LineEntry>, script: Script) -> Self {
        Self::open_on(ops, lines, script, |_| {}, SCHEME_PLAIN)
    }

    /// [`AcceptHost::open_with`] on a connection whose `ConnFacts` `facts` fills, as the host's
    /// secure layer states them.
    fn open_on(
        ops: &'static Ops,
        lines: Vec<LineEntry>,
        script: Script,
        facts: fn(&mut ConnFacts),
        scheme: u8,
    ) -> Self {
        let state = facts;
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
        let mut h = Self {
            ops,
            inst: o.instance,
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
        };
        let mut facts: ConnFacts = z();
        facts.size = size_of::<ConnFacts>() as u32;
        state(&mut facts);
        let mut i: BeginIn = z();
        i.side = SIDE_ACCEPT;
        // The listener's scheme, as the host states it (busbar step 2, `BeginIn::scheme`).
        i.scheme = scheme;
        i.facts = &facts;
        i.lines = h.lines.as_ptr();
        i.lines_len = h.lines.len();
        i.sink = h.sink();
        let mut o: FramerOut = z();
        let r = call(ops.begin, h.inst, &mut i, &mut o, slot::BEGIN);
        h.framing = o.framing;
        assert_eq!(h.take(r, &o), Outcome::Ready, "begin on the accepted side");
        h
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
    /// PENDING, with the same bytes).
    fn ingest_with(&mut self, bytes: &[u8], flags: u32) -> Outcome {
        let mut i: IngestIn = z();
        i.head.ticket = self.ticket;
        i.head.flags = flags;
        i.framing = self.framing;
        i.bytes = bytes.as_ptr();
        i.len = bytes.len();
        i.sink = self.sink();
        let mut o: FramerOut = z();
        let r = call(self.ops.ingest, self.inst, &mut i, &mut o, slot::INGEST);
        self.take(r, &o)
    }

    fn emit(&mut self, stream: u64, bytes: &[u8], end: bool, status: u32) -> Outcome {
        let mut i: EmitIn = z();
        i.head.ticket = self.ticket;
        i.framing = self.framing;
        i.stream = stream;
        i.bytes = bytes.as_ptr();
        i.len = bytes.len();
        i.end_of_frame = u32::from(end);
        i.status = status;
        i.sink = self.sink();
        let mut o: FramerOut = z();
        let r = call(self.ops.emit, self.inst, &mut i, &mut o, slot::EMIT);
        self.take(r, &o)
    }

    /// `refuse`: `bytes` for `stream` (`None`: the whole connection), with the neutral `status`
    /// and `head_sent`, on no ticket (it never pends), re-called while it answers `YIELD_MORE`.
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
            let r = call(self.ops.refuse, self.inst, &mut i, &mut o, slot::REFUSE);
            let more = o.yielded.flags & YIELD_MORE != 0;
            let r = self.take(r, &o);
            if r != Outcome::Ready || !more {
                return r;
            }
            first = false;
        }
    }

    /// `detach`, on no ticket, re-called while it answers `YIELD_MORE`: its outcome and every
    /// frame byte it handed over (the bytes the adopting framer is given).
    fn detach(&mut self) -> (Outcome, Vec<u8>) {
        let mut handed = Vec::new();
        loop {
            let mut i: FramingIn = z();
            i.framing = self.framing;
            i.sink = self.sink();
            let mut o: FramerOut = z();
            let r = call(self.ops.detach, self.inst, &mut i, &mut o, slot::DETACH);
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
            call(
                self.ops.head.cancel,
                self.inst,
                &mut i,
                &mut o,
                life::CANCEL
            ),
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
        let r = call(self.ops.timer, self.inst, &mut i, &mut o, slot::TIMER);
        self.take(r, &o)
    }

    /// The tickets the door's `auth.call`s were issued under, in order.
    fn tickets(&self) -> Vec<Ticket> {
        SCRIPTS.lock().expect("scripts")[&self.ctx].tickets.clone()
    }

    /// The completion sequence numbers the door's `auth.call`s were issued under, in order.
    fn seqs(&self) -> Vec<u32> {
        SCRIPTS.lock().expect("scripts")[&self.ctx].seqs.clone()
    }

    /// Every call the door made on the auth handle, in order.
    fn asked(&self) -> Vec<Asked> {
        SCRIPTS.lock().expect("scripts")[&self.ctx].asked.clone()
    }

    /// The request head pieces that went up.
    fn heads_up(&self) -> usize {
        self.got.iter().filter(|g| g.2 & PIECE_FIELDS != 0).count()
    }

    fn close(self) {
        let mut i: InHead = z();
        let mut o: OutHead = z();
        call(self.ops.head.close, self.inst, &mut i, &mut o, life::CLOSE);
        SCRIPTS.lock().expect("scripts").remove(&self.ctx);
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
        "host: busbar.test\r\ncontent-type: application/json\r\n",
        "{label}: one field block, no content-length"
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

    // RED: an answer head with no status, and a status on an emit that carries no head.
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

/// The protocol offer the door answers for an ACCEPTING listener: `h2, http/1.1`, the owner's
/// signed change from v1.5.5's `http/1.1` alone (OWNER RULING Q137, BUSBAR-1.6.0.md l.5137-5138;
/// parity binding PB-69), not its dial offer.
fn accept_offer(ops: &'static Ops) -> Vec<u8> {
    let mut i: OpenIn = z();
    let mut o: OpenOut = z();
    call(
        ops.head.open,
        std::ptr::null_mut(),
        &mut i,
        &mut o,
        life::OPEN,
    );
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
        call(ops.locate, inst, &mut li, &mut lo, slot::LOCATE),
        Outcome::Ready
    );
    let mut ci: InHead = z();
    let mut co: OutHead = z();
    call(ops.head.close, inst, &mut ci, &mut co, life::CLOSE);
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

// ── the guest list and the auth handle (BUSBAR-1.6.0.md §6 "Auth points and guest lists") ──────

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
    /// Each `auth.call`'s completion sequence number.
    seqs: Vec<u32>,
    /// Each `auth.call`'s ticket.
    tickets: Vec<Ticket>,
    /// The request each `unit.refuse` was handed, in order.
    refused: Vec<View>,
    asked: Vec<Asked>,
    /// The fields `unit.refuse` answers, in order; empty: `content-type: application/json` alone.
    refusal_fields: Vec<(&'static str, &'static str)>,
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
    // SAFETY: the SDK wrapper hands a live `AuthCallIn`, its buffers and a live `out`.
    unsafe {
        let i = input.cast::<AuthCallIn>().read_unaligned();
        let mut scripts = SCRIPTS.lock().expect("scripts");
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
        // The loader's rule (THE DESIGN §11.12 l.1602): a may-pend service called with no ticket
        // is REFUSED.
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
        let mut scripts = SCRIPTS.lock().expect("scripts");
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

/// The kernel's refusal for `cause`: its status and body (1.5.5's no-route and size-gate bodies,
/// `http.crosscut__unknown-path__bare` and `http.crosscut__413__openai`), `content-type` its one
/// field.
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
/// field, the length hyper states for a body of known size (as v1.5.5's `Full` body), its body.
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
        let mut scripts = SCRIPTS.lock().expect("scripts");
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
        // The kernel's memory, valid past the call (the test leaks it).
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
/// the auth is never called (1.5.5 answered 413 before inbound SigV4, spec §6 item 4).
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
/// request goes up whole.
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
/// (named in another case: ASCII case-insensitive) and a query key (case-sensitive: `Key` stays).
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
/// request goes up.
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
/// then the head (no unit yet), and the hand-in carries the unit the head call minted.
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
/// wrote no answer of its own (coordinator ruling on #24 open question 4: a request never goes
/// upstream when the hand-in or the refusal fails).
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

/// A query key the far side percent-encoded is the key it decodes to, as v1.5.5 read every inbound
/// query key (`crates/busbar/src/auth/token.rs`:996-1003 `parse_query`, :1012-1035 `pct_decode`:
/// `%XX` and `+` decoded before the key is compared): `%6Bey` is `key`, stripped; `Key` is not.
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
/// the auth handle and never answers PENDING, even with a request parked on a pending `auth.call`
/// (Q128 reader A finding 2; THE DESIGN §11.12 l.1602-1604, Appendix A.4.6 l.3646).
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
    assert_ne!(h.timer(), Outcome::Pending, "{label}: a timer never pends");
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
    // The parked request was not dropped by the timer: the resume answers it (Q128 reader B
    // finding 1: no request is ever dropped without an answer).
    assert_eq!(
        h.ingest_with(POST_HELLO, FLAG_RESUME),
        Outcome::Ready,
        "{label}"
    );
    assert_eq!(h.heads_up(), 1, "{label}: the resumed request went up");
    h.close();
}

/// A pending `auth.call` parks the op; the host's resume re-issues the op with the same bytes and
/// `FLAG_RESUME`: the door takes no byte twice, re-issues the SAME completion handle, and the
/// request goes up once, whole (the transport contract: "the framer re-issues the same handle, and
/// the service answers its STORED result").
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
/// PARTIAL, and the parked call is let go (a later op calls afresh, under a new handle); a cancel
/// of a ticket nothing is parked on moved nothing (Q128 reader A finding 3).
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

/// Requests pipelined past any per-op bound are each answered in the op that decoded them: none is
/// left waiting for a wake that never comes (Q128 reader B finding 1).
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

/// THE ABI'S `refuse` ON AN ACCEPTED STREAM (Q128 reader B finding 2; ruling 22): a stream refused
/// before its answer head is answered with `bytes` at the mapped `status`, its length stated, as
/// v1.5.5's server answered a handler's error response.
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
/// closes with no terminating chunk, so the far side never reads a cut answer as whole.
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
/// (the connector's `unit0_refusal`), written as they are; the connection is over.
fn refuse_the_connection(label: &str, ops: &'static Ops) {
    let mut h = AcceptHost::open(ops);
    let bytes = b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\n\r\n";
    assert_eq!(h.refuse(None, bytes, 0, false), Outcome::Ready, "{label}");
    assert_eq!(h.out, bytes, "{label}");
    assert!(h.ended, "{label}: the connection is over");
    h.close();
}

/// THE SCHEME THE AUTH IS SHOWN (`HeadView::scheme`, busbar e858ecc: `0` is refused off the peer
/// point): the one the host states for the accepted connection, never `0`. Until `BeginIn` states
/// it, the host's statement is `BeginIn::facts` ("what connection security established"): a secure
/// layer presents the host's certificate and agrees a protocol; a cleartext connection has neither.
fn shows_the_scheme(label: &str, ops: &'static Ops) {
    // The scheme is the one the HOST states for the listener (busbar step 2, `BeginIn::scheme`:
    // "from the listener (whether the connector terminated connection security on it)"), never
    // inferred from the handshake's facts (Q128 r232 LOW 2's fix).
    let cases: [SchemeCase; 4] = [
        ("cleartext", |_| {}, SCHEME_PLAIN, SCHEME_PLAIN),
        // A TLS client offering no SNI, no ALPN and no certificate.
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
        // Facts the inference read as TLS, on a listener the host states cleartext.
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
/// contract: "a parked `ingest` holds nothing of the host's ... the framer holds back only the
/// stream whose auth it waits on"): a fresh op on another ticket never re-issues the parked handle
/// under its own ticket, and the resume on the parked ticket does, with the same handle.
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

/// THE DOOR OFFERS THE PEER POINT (Q128 reader B r212, coordinator ruling: POINT_PEER is served
/// under the Peer rule): its Statement's offered-points record (`EXT_OFFERED_POINTS`) states Peer,
/// Head and HeadBody, so the host boots a line whose auth needs Peer instead of refusing it.
fn offers_the_peer_point(label: &str, door: *const Door) {
    use busbar_contract::abi::auth::AuthPoints;
    use busbar_contract::abi::transport::check::check_offered_points;
    // SAFETY: the door's `'static` Statement and its `'static` extensions blob.
    let ext = unsafe {
        let st = &*(*door).statement;
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

/// THE PEER POINT, once per connection, before any request's head call (THE DESIGN §6 item 7):
/// two requests on one connection, one peer call, made first.
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
/// byte, on either side"): the peer call carries no request, and a peer answer that names a line to
/// strip is refused: the connection closes with no bytes and nothing goes up.
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
    h.close();
}

/// One scheme cell: its label, the handshake facts, the scheme the host states for the listener,
/// the scheme the auth must be shown.
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
/// `:method GET`, `:scheme http` static, `:path` and `:authority` literal, not indexed).
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

/// ALPN agreed `h2` (the accept offer's first, Q137): the connection is served as HTTP/2 from its
/// preface, its request admitted and gone up.
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

/// A PENDING `auth.call` PARKS ONLY ITS OWN STREAM (THE DESIGN §6 item 7, l.975-976; Q128 r231
/// finding 3): request A, on a line whose auth pends, does not hold back request B on a `none`
/// line on the same connection. B is admitted in the op A parked in, and its head goes up no later
/// than the next op, a fresh one on another ticket, while A stays parked.
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
/// as decoded ... Its `scheme` is the one the transport states for the connection"): `unit.refuse`
/// is handed the decoded request for every cause, the no-route and method-miss refusals included.
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
        let refused = SCRIPTS.lock().expect("scripts")[&h.ctx].refused.clone();
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
/// refusal, in the kernel's order, before the length hyper states for its body; nothing goes up.
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

/// AN UPGRADE THE LINE HANDS TO ANOTHER FRAMER IS NOT ANSWERED HERE (coordinator ruling, row 192):
/// the request is admitted through its line and goes up; the host answers nothing and detaches,
/// and the adopting framer is handed the upgrade request's head bytes and every byte after them,
/// as the far side sent them. This door writes no `101` and no other byte: the adopting framer
/// writes its own `101`.
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

/// A `HEAD` request is answered with its head alone, as v1.5.5's server (hyper) answered it: the
/// status and the fields the host emitted, and no body byte, whatever body the host emits.
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
    // The body the host emits for it is never written; whether the op takes it or answers the
    // stream over is hyper's, not the wire's.
    let _ = h.emit(1, b"hello", true, 0);
    let wire = String::from_utf8_lossy(&undated(h.out.clone())).into_owned();
    println!("PROOF {label}: head answer {wire:?}");
    assert!(wire.starts_with("HTTP/1.1 200 OK\r\n"), "{label}: {wire:?}");
    assert!(
        wire.contains("content-type: text/plain\r\n"),
        "{label}: {wire:?}"
    );
    assert!(
        wire.ends_with("\r\n\r\n"),
        "{label}: the head alone: {wire:?}"
    );
    assert!(!wire.contains("hello"), "{label}: no body byte: {wire:?}");
    h.close();
}

/// THE HEADER READ BOUND (v1.5.5 `hardened_conn_builder`, 30 s on the host's clock): a head the far
/// side trickles and never finishes ends the connection at the bound and not before it; nothing
/// goes up.
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

/// Run `cell` through the linked door and the dropped-in one.
fn both(cell: fn(&str, &'static Ops)) {
    let (d, _lib) = dropped();
    for (label, ops) in [("linked", linked()), ("dropped", d)] {
        cell(label, ops);
    }
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
