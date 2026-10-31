// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ENGINE: hyper's `client::conn` (HTTP/1.1 and HTTP/2) run as a sans-IO framer.
//!
//! One [`Framing`] is one connection. Its protocol machine is hyper's own, driven over the host's
//! bytes by the contract's sans-IO drive (`busbar_contract::hyper_io!`, expanded in `door`): an
//! in-memory pipe instead of a socket, the framing's own task list as hyper's executor, and the
//! host's clock as its timer. `ingest` appends what the far side sent to the pipe's read half, and
//! whatever hyper writes collects in its write half until the op hands it to the host as wire
//! bytes. Nothing here blocks, spawns a thread, opens a socket or reads a clock. A hyper `Pending`
//! means "more bytes from the far side, or a deadline": the op answers what it has and returns.
//! The earliest sleep still waiting becomes the op's `next_deadline_ns`.
//!
//! THE ONE REAL-CLOCK READ is the drive's (`HostIo::new`, at `begin`). h2 reads the real clock
//! itself for its reset-stream expiry (a bounded list of recently reset stream ids). That happens
//! inside the library and does not move this framing's clock.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

pub(crate) use super::hyper_io::field_block;
use super::hyper_io::{HeadWords, HostIo, Owed, Piece};
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::{Body, Incoming};
use hyper::client::conn::{http1, http2};
use hyper::rt::{Executor, Sleep};
use zeroize::Zeroizing;

use crate::raw::Head;
use crate::{complete_message, request_target, retry_after_secs, EgressHead};

/// Which HTTP a framing speaks, as connection security (or the operator's cleartext key) agreed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    /// HTTP/1.1.
    H1,
    /// HTTP/2.
    H2,
}

/// The connection posture 1.5.5's egress client used, carried to every framing.
#[derive(Debug, Clone, Copy)]
pub struct Posture {
    /// HTTP/2 keep-alive ping interval (`None` = no pings).
    pub keep_alive_interval: Option<Duration>,
    /// How long a keep-alive ping may go unanswered.
    pub keep_alive_timeout: Duration,
    /// HTTP/2 adaptive flow-control window.
    pub adaptive_window: bool,
    /// 1.5.5's `limits.upstream_request_timeout_secs`: ONE clock per attempt, from its start to the
    /// response body's end (reqwest's total timeout). Counted from a stream's first `emit` when the
    /// caller stamped no deadline of its own.
    pub request_timeout: Duration,
    /// The largest REQUEST body carried (its head has its own allowance). A response is not capped here: 1.5.5's incremental
    /// body path carried a body for as long as the far end sent one, and its buffered reads are
    /// the plane's.
    pub max_body_bytes: usize,
}

enum Sender {
    H1(http1::SendRequest<Full<Bytes>>),
    H2(http2::SendRequest<Full<Bytes>>),
}

type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// One exchange's stage. Every stage after `Writing` carries the attempt's ONE deadline sleep, so
/// the wait for the connection, the head and every byte of the body spend the same clock.
enum Stage {
    /// The request message, still arriving, and the attempt's deadline (host ns).
    /// The raw buffer is zeroed when it is dropped (the message refused, or the framing gone), and
    /// when it grows (`extend_wiped`); a whole message's head span is zeroed and its body
    /// handed on in place (`Framing::message`). The head is read in place from it
    /// (`EgressHead` keeps only its end and framing); the `http::Request` built from it still holds
    /// header values in ordinary memory, until credentials stop reaching the framer as plaintext.
    Writing(Zeroizing<Vec<u8>>, EgressHead, u64),
    /// A whole request, waiting for the connection to take it.
    Queued(http::Request<Full<Bytes>>, Pin<Box<dyn Sleep>>),
    /// Sent; waiting for the response head.
    Asked(
        BoxFut<hyper::Result<http::Response<Incoming>>>,
        Pin<Box<dyn Sleep>>,
    ),
    /// The response body, and where its last queued byte stands in the framing's queue
    /// (`Queue::pushed` just after it was queued).
    Body(Incoming, Pin<Box<dyn Sleep>>, u64),
    /// Refused partway through its request message (HTTP/2): the failure piece is out, and every
    /// later byte of THAT message is dropped until the host's end of it, so the rest is never read
    /// as a fresh request on the same stream (a head the auth never saw).
    Refused,
    /// Answered in full.
    Done,
}

/// The most a request's head (its request line and fields) may add to its body in one emitted
/// message: hyper's own HTTP/1 read-buffer ceiling (`8192 + 4096 * 100`), the largest head hyper
/// would read back.
pub(crate) const HEAD_MAX_BYTES: usize = 8192 + 4096 * 100;

/// How far an HTTP/2 stream's body may run ahead of the host: once this many queued bytes stand
/// ahead of (and including) its last one, its body is not polled again until the host has taken
/// them. Polling a body is what returns its flow-control credit to the far end (hyper releases a
/// data frame's capacity as the frame is polled), so a stream's window refills only as the host
/// drains it, as 1.5.5's body released credit only as its reader read. Two maximum-size HTTP/2
/// frames.
pub(crate) const BODY_HOLD: u64 = 32 * 1024;

/// The pieces waiting for the host, and how many piece bytes were ever queued: the difference with
/// what is still queued is what the host has taken (the sink fill drains the front, a piece
/// at a time or part of one).
#[derive(Default)]
struct Queue {
    pieces: VecDeque<Piece>,
    pushed: u64,
}

impl Queue {
    fn push(&mut self, p: Piece) {
        self.pushed += p.bytes.len() as u64;
        self.pieces.push_back(p);
    }

    /// The bytes ever queued that the host has taken.
    fn taken(&self) -> u64 {
        let queued: u64 = self.pieces.iter().map(|p| p.bytes.len() as u64).sum();
        self.pushed - queued
    }
}

type Task = Pin<Box<dyn Future<Output = ()> + Send>>;

/// A FRAMING'S OWN TASK LIST, hyper's executor, run once per round of the framing's drive. hyper
/// keeps a clone of its executor inside the tasks it spawns (HTTP/2's connection task, each
/// stream's task), so the executor holds the list only WEAKLY ([`Spawner`]): the framing alone owns
/// it, and the framing's drop drops every task in it. An executor holding its list strongly (the
/// SDK drive's own) would be held by its own tasks, and a framing dropped before they ended would
/// keep them, hyper's connection state and the pipe, for good.
#[derive(Default)]
pub(crate) struct Tasks(Arc<Mutex<Vec<Task>>>);

/// hyper's executor over a framing's [`Tasks`], holding it weakly: a task spawned once the framing
/// is gone is dropped unrun.
#[derive(Clone)]
pub(crate) struct Spawner(Weak<Mutex<Vec<Task>>>);

impl<F: Future<Output = ()> + Send + 'static> Executor<F> for Spawner {
    fn execute(&self, fut: F) {
        if let Some(list) = self.0.upgrade() {
            list.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(Box::pin(fut));
        }
    }
}

impl Tasks {
    /// The executor hyper is handed.
    pub(crate) fn spawner(&self) -> Spawner {
        Spawner(Arc::downgrade(&self.0))
    }

    /// Poll every task once; one that ends is dropped, one spawned meanwhile runs next round.
    pub(crate) fn run(&self, cx: &mut Context<'_>) {
        let mut tasks = std::mem::take(&mut *self.0.lock().unwrap_or_else(PoisonError::into_inner));
        tasks.retain_mut(|t| t.as_mut().poll(cx).is_pending());
        let mut list = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        tasks.append(&mut list);
        *list = tasks;
    }
}

/// Why a framing failed; the op that finds it answers FAILED with this text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure(pub String);

/// One connection's HTTP machine.
pub struct Framing {
    io: HostIo,
    /// hyper's executor ([`Tasks`]).
    tasks: Tasks,
    handshake: Option<BoxFut<hyper::Result<Sender>>>,
    sender: Option<Sender>,
    conn_err: Arc<Mutex<Option<String>>>,
    conn_done: Arc<AtomicBool>,
    dial: http::Uri,
    /// Whether this connection has carried a request yet: the dial's own path is its FIRST
    /// request's to inherit (when that request names no target), never a later one's
    /// (`crate::message::request_target`).
    carried: bool,
    proto: Proto,
    posture: Posture,
    exchanges: Vec<(u64, Stage)>,
    out: Queue,
    /// Whether the last drive left an HTTP/2 body unpolled for `BODY_HOLD`: the framing asks to
    /// be called again at once (`Owed::next_deadline`), so the body moves on once the host has
    /// taken what was queued.
    held: bool,
    failed: Option<Failure>,
    now_unix_ns: u64,
}

impl Framing {
    /// Open a dialled framing over `dial`, speaking `proto`, at host time `now_ns`.
    ///
    /// # Errors
    ///
    /// `dial` is not a URI.
    pub fn dial(dial: &str, proto: Proto, posture: Posture, now_ns: u64) -> Result<Self, Failure> {
        let dial = canonical_host(
            dial.parse()
                // The dial is not repeated: a target may carry a credential.
                .map_err(|_| Failure("the target is not a URL".into()))?,
        );
        // The one real-clock read: this framing's epoch (module docs).
        let io = HostIo::new(now_ns);
        let tasks = Tasks::default();
        let (exec, timer) = (tasks.spawner(), io.timer());
        let conn_err = Arc::new(Mutex::new(None));
        let conn_done = Arc::new(AtomicBool::new(false));
        let (ex, err, done) = (exec.clone(), conn_err.clone(), conn_done.clone());
        let shim = io.stream();
        let handshake: BoxFut<hyper::Result<Sender>> = match proto {
            Proto::H2 => {
                let mut b = http2::Builder::new(exec.clone());
                b.timer(timer.clone())
                    .adaptive_window(posture.adaptive_window);
                if let Some(every) = posture.keep_alive_interval {
                    b.keep_alive_interval(every)
                        .keep_alive_timeout(posture.keep_alive_timeout);
                }
                Box::pin(async move {
                    let (s, c) = b.handshake(shim).await?;
                    ex.execute(async move {
                        if let Err(e) = c.await {
                            *err.lock().unwrap_or_else(PoisonError::into_inner) =
                                Some(e.to_string());
                        }
                        done.store(true, Ordering::Release);
                    });
                    Ok(Sender::H2(s))
                })
            }
            Proto::H1 => Box::pin(async move {
                let (s, c) = http1::Builder::new().handshake(shim).await?;
                ex.execute(async move {
                    if let Err(e) = c.await {
                        *err.lock().unwrap_or_else(PoisonError::into_inner) = Some(e.to_string());
                    }
                    done.store(true, Ordering::Release);
                });
                Ok(Sender::H1(s))
            }),
        };
        Ok(Self {
            io,
            tasks,
            handshake: Some(handshake),
            sender: None,
            conn_err,
            conn_done,
            dial,
            carried: false,
            proto,
            posture,
            exchanges: Vec::new(),
            out: Queue::default(),
            held: false,
            failed: None,
            now_unix_ns: 0,
        })
    }

    /// The far side sent `bytes` (`end` = and then ended).
    pub fn ingest(&mut self, bytes: &[u8], end: bool) {
        self.io.ingest(bytes, end);
    }

    /// Bytes for `stream`: part of one HTTP/1.1 request message, rendered by `encode`; `end` is the
    /// host's end of that message (`EmitIn::end_of_frame`). A message still short of what its head
    /// declares at its end is refused.
    ///
    /// A message that cannot be sent fails its STREAM on HTTP/2 (a failure piece, its siblings
    /// untouched), and the framing on HTTP/1.1, where the connection carries one exchange.
    ///
    /// `deadline_ns` is the attempt's deadline as the caller stamped it at the attempt's start (the
    /// connect spent part of it); `0` counts the configured request timeout from `now_ns`. Only a
    /// stream's first `emit` reads it.
    ///
    /// # Errors
    ///
    /// HTTP/1.1 only: the message is malformed, over the body cap, or is not a request.
    pub fn emit(
        &mut self,
        stream: u64,
        bytes: &[u8],
        end: bool,
        now_ns: u64,
        deadline_ns: u64,
    ) -> Result<(), Failure> {
        // The rest of a refused message is dropped, never read; the host's end of it frees the
        // stream.
        if let Some(i) = self
            .exchanges
            .iter()
            .position(|(s, st)| *s == stream && matches!(st, Stage::Refused))
        {
            if end {
                self.exchanges.remove(i);
            }
            return Ok(());
        }
        // A re-call after `YIELD_MORE` carries no new bytes: nothing to add to any message.
        if bytes.is_empty() && !end {
            return Ok(());
        }
        let deadline = if deadline_ns != 0 {
            deadline_ns
        } else {
            now_ns.saturating_add(
                u64::try_from(self.posture.request_timeout.as_nanos()).unwrap_or(u64::MAX),
            )
        };
        let read = if bytes.is_empty() {
            Ok(())
        } else {
            self.message(stream, bytes, deadline)
        };
        // The host's end of a message still arriving: it ended short of what its head declared.
        let read = read.and_then(|()| {
            let short = self
                .exchanges
                .iter()
                .any(|(s, st)| *s == stream && matches!(st, Stage::Writing(..)));
            if end && short {
                Err(Failure(
                    "request message: it ended short of its stated length".into(),
                ))
            } else {
                Ok(())
            }
        });
        match read {
            Ok(()) => Ok(()),
            Err(f) if self.proto == Proto::H2 => {
                // Refused partway: the stream stays refused until the host's end of the message.
                let after = if end { Stage::Done } else { Stage::Refused };
                match self.exchanges.iter_mut().find(|(s, _)| *s == stream) {
                    Some(slot) => slot.1 = after,
                    None => self.exchanges.push((stream, after)),
                }
                self.exchanges.retain(|(_, s)| !matches!(s, Stage::Done));
                self.out.push(Piece::failure(stream, &f.0));
                Ok(())
            }
            Err(f) => {
                // HTTP/1.1: the connection carries one exchange, so its refusal is the framing's.
                // The half-written exchange and its buffered bytes go with it.
                self.exchanges.retain(|(s, _)| *s != stream);
                self.failed = Some(f.clone());
                Err(f)
            }
        }
    }

    fn message(&mut self, stream: u64, bytes: &[u8], deadline: u64) -> Result<(), Failure> {
        let max = self.posture.max_body_bytes;
        let idx = match self.exchanges.iter().position(|(s, _)| *s == stream) {
            Some(i) => i,
            None => {
                self.exchanges.push((
                    stream,
                    Stage::Writing(Zeroizing::default(), EgressHead::default(), deadline),
                ));
                self.exchanges.len() - 1
            }
        };
        let Stage::Writing(buf, head, deadline) = &mut self.exchanges[idx].1 else {
            return Err(Failure(format!(
                "stream {stream} already carries a request"
            )));
        };
        extend_wiped(buf, bytes);
        // The cap is the BODY's (`complete_message` holds the declared length to it); the head
        // `encode` rendered around it has its own allowance, hyper's HTTP/1 read buffer.
        if buf.len() > max.saturating_add(HEAD_MAX_BYTES) {
            return Err(Failure("request message over the body cap".into()));
        }
        let raw = complete_message(buf, head, max, HEAD_MAX_BYTES)
            .map_err(|e| Failure(format!("request message: {e}")))?;
        let Some(whole) = raw else { return Ok(()) };
        // Read once already (`complete_message`), so this second read of the same bytes is the
        // same head: the request is built from it in place, nothing copied out but by `http`.
        let parsed = Head::parse(&buf[..whole.head_end])
            .map_err(|e| Failure(format!("request message: {e}")))?;
        // The path is not repeated: a path (and its query) may carry a token.
        let target = request_target(&self.dial, parsed.path, !self.carried)
            .map_err(|e| Failure(format!("request target: {e}")))?;
        let mut b = http::Request::builder().method(parsed.method).uri(target);
        for (k, v) in parsed.fields() {
            // A chunked body was decoded by `complete_message`, so its coding describes the wire
            // it was written for, not the one going out: hyper frames the body by its length, as
            // 1.5.5's client sent a decoded body on (`crates/busbar/src/proxy/engine/walk.rs:592`).
            if k.eq_ignore_ascii_case(b"transfer-encoding") {
                continue;
            }
            // Every other line goes out as stated. The length line is the one the auth saw (THE
            // DESIGN §6 step 5): it goes out as stated, and hyper, handed it, adds none.
            b = b.header(k, v);
        }
        let body = match whole.decoded {
            Some(decoded) => Bytes::from(decoded),
            // The body goes on as it lies in the buffer, not copied. The head before it is the
            // span that carries credentials (an `authorization` field, a token in the target) and
            // it is in the request's own fields now: wiped where it was read. A decoded chunked
            // body leaves its framed bytes in `buf`, wiped whole as the stage goes.
            None => {
                let mut bytes = std::mem::take(&mut **buf);
                zeroize::Zeroize::zeroize(&mut bytes[..whole.head_end]);
                Bytes::from(bytes).slice(whole.head_end..)
            }
        };
        let mut req = b
            .body(Full::new(body))
            .map_err(|e| Failure(format!("request: {e}")))?;
        target_form(&mut req, self.proto)?;
        // Spent only by a request that was built: one the builder refuses leaves the dial path to
        // the next that names no target.
        self.carried = true;
        let wait = self.io.timer().sleep_until_ns(*deadline);
        self.exchanges[idx].1 = Stage::Queued(req, wait);
        Ok(())
    }

    /// Drive the connection at host time (`now_ns` monotonic, `now_unix_ns` wall) until nothing
    /// inside it has more to do. A framing failure with output still owed is also stated on each
    /// live stream (a failure piece after that output): the host never calls an ended connection
    /// again. With nothing owed no piece is pushed and the door answers the failure at once.
    pub fn drive(&mut self, now_ns: u64, now_unix_ns: u64) {
        self.io.set_time(now_ns);
        self.now_unix_ns = now_unix_ns;
        self.held = false;
        if self.failed.is_some() {
            return;
        }
        let io = self.io.clone();
        // What the host has taken of the queue is read ONCE per drive: the host takes nothing
        // between its rounds (the sink is filled after it), and a push moves `pushed` and the
        // queued bytes alike, so it stands for every round.
        let taken = (self.proto == Proto::H2).then(|| self.out.taken());
        if let Err(f) = io.rounds(|cx| {
            self.tasks.run(cx);
            self.step(cx, taken)
        }) {
            self.failed = Some(f);
            self.fail_streams();
            return;
        }
        let err = self
            .conn_err
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(e) = err {
            if self
                .exchanges
                .iter()
                .any(|(_, s)| !matches!(s, Stage::Refused))
            {
                self.failed = Some(Failure(e));
                self.fail_streams();
            }
        }
    }

    /// With output pending, state the recorded failure on every stream not already finished nor
    /// already told it failed (a `Refused` one's failure piece is out), then drop the exchanges (so
    /// a later call pushes nothing).
    fn fail_streams(&mut self) {
        if !(self.io.wire_pending() || !self.out.pieces.is_empty()) {
            return;
        }
        let Some(Failure(why)) = &self.failed else {
            return;
        };
        for (id, stage) in &self.exchanges {
            if !matches!(stage, Stage::Done | Stage::Refused) {
                self.out.push(Piece::failure(*id, why));
            }
        }
        self.exchanges.clear();
    }

    /// One round: the handshake, then every stream as far as it goes. A stream's own failure on
    /// HTTP/2 ends THAT stream (dropping its exchange resets it on the wire) with a failure piece;
    /// on HTTP/1.1, or once the connection itself has failed, it fails the framing.
    fn step(&mut self, cx: &mut Context<'_>, taken: Option<u64>) -> Result<(), Failure> {
        if let Some(h) = self.handshake.as_mut() {
            if let Poll::Ready(r) = h.as_mut().poll(cx) {
                self.handshake = None;
                self.sender = Some(r.map_err(|e| Failure(e.to_string()))?);
            }
        }
        let k = Knobs {
            now_unix_secs: self.now_unix_ns / 1_000_000_000,
            hold: taken,
        };
        for (id, stage) in &mut self.exchanges {
            let r = advance(*id, stage, &mut self.sender, &mut self.out, &k, cx);
            if let Err(f) = r.map(|held| self.held |= held) {
                let conn_dead = self
                    .conn_err
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .is_some();
                if self.proto == Proto::H1 || conn_dead || f.1 {
                    return Err(f.0);
                }
                *stage = Stage::Done;
                self.out.push(Piece::failure(*id, &f.0 .0));
            }
        }
        self.exchanges.retain(|(_, s)| !matches!(s, Stage::Done));
        Ok(())
    }

    /// Why this framing failed, once it has.
    #[must_use]
    pub fn failure(&self) -> Option<&Failure> {
        self.failed.as_ref()
    }
}

impl Owed for Framing {
    fn take_wire(&mut self, cap: usize) -> Vec<u8> {
        self.io.take_wire(cap)
    }
    fn wire_pending(&self) -> bool {
        self.io.wire_pending()
    }
    fn pieces(&mut self) -> &mut VecDeque<Piece> {
        &mut self.out.pieces
    }
    /// The earliest sleep still waiting, or NOW where a body was held back for the host: once the
    /// host has taken what was queued, the next call polls it on.
    fn next_deadline(&self) -> Option<u64> {
        let at = self.io.next_deadline();
        if !self.held {
            return at;
        }
        let now = self.io.timer().now_ns();
        Some(at.map_or(now, |d| d.min(now)))
    }
    fn ended(&self) -> bool {
        self.conn_done.load(Ordering::Acquire)
    }
}

/// THE ONE WIPE-ON-GROW RULE for a buffer of this door's own that may hold credential bytes (the
/// request message `emit` collects, the accepted side's hand-over copy, a held body): append
/// `bytes` to `buf`, never leaving a copy of what it held behind. Where it must grow, the bytes
/// move to a new allocation (at least double the old) and the one outgrown is zeroed before it is
/// freed (a `Vec`'s own growth frees the old allocation as it was).
pub(crate) fn extend_wiped(buf: &mut Vec<u8>, bytes: &[u8]) {
    let need = buf.len().saturating_add(bytes.len());
    if need > buf.capacity() {
        let mut grown = Vec::with_capacity(need.max(buf.capacity().saturating_mul(2)));
        grown.extend_from_slice(buf);
        zeroize::Zeroize::zeroize(buf);
        *buf = grown;
    }
    buf.extend_from_slice(bytes);
}

/// The dial target with its authority as 1.5.5's client sent it (its URL parser normalised the
/// host before the request was built): the host lower-cased, an IPv4 spelling written as the
/// dotted quad it names ([`super::offered_name`]; `https://127.1:4318/` went out as
/// `127.0.0.1:4318`), and the scheme's own port dropped. One string, so the request's
/// `:authority` (HTTP/2) and the `host` line the framer states (HTTP/1.1) agree.
fn canonical_host(dial: http::Uri) -> http::Uri {
    // An `sse` target is its `http` twin (`super::as_http`).
    let dial = super::as_http(dial);
    let Some(host) = dial.host() else {
        return dial;
    };
    let name = super::offered_name(&host.to_ascii_lowercase());
    let default_port = match dial.scheme_str() {
        Some("https") => Some(443),
        Some("http") => Some(80),
        _ => None,
    };
    let port = dial.port_u16().filter(|p| Some(*p) != default_port);
    let authority = match port {
        Some(p) => format!("{name}:{p}"),
        None => name,
    };
    if dial.authority().map(http::uri::Authority::as_str) == Some(authority.as_str()) {
        return dial;
    }
    let Ok(authority) = authority.parse::<http::uri::Authority>() else {
        return dial;
    };
    let mut parts = dial.clone().into_parts();
    parts.authority = Some(authority);
    http::Uri::from_parts(parts).unwrap_or(dial)
}

/// THE FRAMER'S OWN HEAD LINES for a request to `target`: the client defaults the http transport
/// owns (THE DESIGN §5: "When the caller sets none, the http door adds `accept: */*`, and on h1 the
/// host header and origin-form target: the http transport owns the client defaults"), in 1.5.5's
/// order: `accept: */*`, as reqwest added its default after the caller's fields, then hyper-util's
/// `host` (the port only when it is not the scheme's own). `locate` states them and the host adds
/// each the request does not carry BEFORE the auth signs the head (THE DESIGN §6 step 5, OWNER-
/// LOCKED: "Nothing is added to the head after the auth has run"); `encode` adds none. Field lines,
/// `name: value` CRLF each. On HTTP/2 the `host` line is the target's `:authority`, as there.
pub(crate) fn client_defaults(target: &http::Uri) -> String {
    let mut lines = String::from("accept: */*\r\n");
    // The host 1.5.5's client sent: an IPv4 spelling as the address it names.
    let target = canonical_host(target.clone());
    if let Some(host) = target.host() {
        let secure = matches!(target.scheme_str(), Some("https"));
        let value = match target.port_u16() {
            Some(443) if secure => host.to_owned(),
            Some(80) if !secure => host.to_owned(),
            Some(p) => format!("{host}:{p}"),
            None => host.to_owned(),
        };
        lines.push_str("host: ");
        lines.push_str(&value);
        lines.push_str("\r\n");
    }
    lines
}

/// The request's target form, and nothing added to its head: on HTTP/1.1 the target is rewritten
/// to origin form (the `host` line the host added carries the authority); on HTTP/2 it stays
/// absolute, becoming `:scheme`, `:authority` and `:path`, and a `host` line is that `:authority`,
/// not a field of its own (1.5.5's HTTP/2 requests carried none). The target's path is origin form
/// already (`request_target` refuses any other); one that is not fails the request rather than
/// going somewhere else (audit A1 F5).
fn target_form(req: &mut http::Request<Full<Bytes>>, proto: Proto) -> Result<(), Failure> {
    if proto == Proto::H2 {
        req.headers_mut().remove(http::header::HOST);
        return Ok(());
    }
    let uri = req.uri().clone();
    *req.uri_mut() = match uri.path_and_query() {
        Some(p) if p.as_str() != "/" => p
            .as_str()
            .parse()
            .map_err(|_| Failure("request target: not an origin-form target".into()))?,
        _ => http::Uri::default(),
    };
    Ok(())
}

/// What every stream's round reads.
struct Knobs {
    now_unix_secs: u64,
    /// HTTP/2 only: the queue bytes the host had taken when the round began, against which a
    /// body's [`BODY_HOLD`] is judged. `None` (HTTP/1.1): the connection carries one exchange and
    /// its bytes are already in the pipe, so a body is read as it arrives.
    hold: Option<u64>,
}

/// The failure a stream's deadline passing is.
fn timed_out() -> (Failure, bool) {
    (
        Failure("the request timeout passed before the response was whole".into()),
        false,
    )
}

/// Move one stream as far as it goes this round: `Ok(true)` = its body was held back for the
/// host (`BODY_HOLD`). `Err((why, true))` is the connection's failure (the sender refused),
/// `Err((why, false))` the stream's own.
fn advance(
    id: u64,
    stage: &mut Stage,
    sender: &mut Option<Sender>,
    out: &mut Queue,
    k: &Knobs,
    cx: &mut Context<'_>,
) -> Result<bool, (Failure, bool)> {
    let own = |e: hyper::Error| (Failure(e.to_string()), false);
    loop {
        match stage {
            Stage::Writing(..) | Stage::Refused | Stage::Done => return Ok(false),
            Stage::Queued(_, wait) => {
                if wait.as_mut().poll(cx).is_ready() {
                    return Err(timed_out());
                }
                let Some(s) = sender.as_mut() else {
                    return Ok(false);
                };
                let ready = match s {
                    Sender::H1(s) => s.poll_ready(cx),
                    Sender::H2(s) => s.poll_ready(cx),
                };
                match ready {
                    Poll::Pending => return Ok(false),
                    Poll::Ready(r) => r.map_err(|e| (Failure(e.to_string()), true))?,
                }
                let Stage::Queued(req, wait) = std::mem::replace(stage, Stage::Done) else {
                    unreachable!("matched above")
                };
                let f: BoxFut<_> = match s {
                    Sender::H1(s) => Box::pin(s.send_request(req)),
                    Sender::H2(s) => Box::pin(s.send_request(req)),
                };
                *stage = Stage::Asked(f, wait);
            }
            Stage::Asked(f, wait) => match f.as_mut().poll(cx) {
                Poll::Pending => {
                    if wait.as_mut().poll(cx).is_ready() {
                        return Err(timed_out());
                    }
                    return Ok(false);
                }
                Poll::Ready(r) => {
                    let r = r.map_err(own)?;
                    out.push(head_piece(id, &r, k.now_unix_secs));
                    let Stage::Asked(_, wait) = std::mem::replace(stage, Stage::Done) else {
                        unreachable!("matched above")
                    };
                    *stage = Stage::Body(r.into_body(), wait, out.pushed);
                }
            },
            Stage::Body(b, wait, last) => {
                // Held: the host has not yet taken enough of what this stream already queued.
                // The body stays unpolled (its credit unreturned) under the same one clock.
                if k.hold
                    .is_some_and(|taken| last.saturating_sub(taken) >= BODY_HOLD)
                {
                    if wait.as_mut().poll(cx).is_ready() {
                        return Err(timed_out());
                    }
                    return Ok(true);
                }
                match Pin::new(&mut *b).poll_frame(cx) {
                    Poll::Pending => {
                        if wait.as_mut().poll(cx).is_ready() {
                            return Err(timed_out());
                        }
                        return Ok(false);
                    }
                    Poll::Ready(Some(Err(e))) => return Err(own(e)),
                    // Data is carried as it arrives. A trailer section is not: 1.5.5's client read
                    // a response through reqwest, which yields data frames only, so trailers never
                    // reached what the layer above read, and they do not here either.
                    Poll::Ready(Some(Ok(fr))) => {
                        if let Ok(d) = fr.into_data() {
                            if !d.is_empty() {
                                out.push(Piece::data(id, d));
                                *last = out.pushed;
                            }
                        }
                    }
                    Poll::Ready(None) => {
                        // The end piece (`PIECE_END`) that says this stream's response is whole.
                        out.push(Piece::end(id));
                        *stage = Stage::Done;
                        return Ok(false);
                    }
                }
            }
        }
    }
}

/// The response head as the frame the layer above reads: ONE field block
/// (`busbar_contract::abi::transport::fields`) carrying the status and any `Retry-After`, framed
/// even when no field is left in it, so it always comes before the body. The head piece states the
/// body length the head declared (`Content-Length`, `PIECE_HAS_DECLARED_LEN`), where it declared
/// one: the host's pre-body download cap reads it before a body byte arrives. An answer that
/// carries no body (to a HEAD, a `204`, a `304`: hyper knows its body is empty) may name the length
/// a body WOULD have had (RFC 9110 8.6), which is no length of this answer's: it states none, save
/// a stated `0`.
fn head_piece(stream: u64, r: &http::Response<Incoming>, now_unix_secs: u64) -> Piece {
    let bodiless = r.body().is_end_stream();
    Piece {
        status: Some(r.status().as_u16()),
        retry_after_secs: retry_after_secs(r.headers(), now_unix_secs),
        declared_len: declared_len(r.headers()).filter(|n| *n == 0 || !bodiless),
        head: reason_phrase(r).map(HeadWords::reason),
        ..Piece::fields(stream, Bytes::from(field_block(r.headers(), &[])))
    }
}

/// The body length an answer's head declared: its `Content-Length`, where every value it names
/// (each line, each comma-list member) is the same `1*DIGIT` (RFC 9110 8.6). `None` where the head
/// carries a `Transfer-Encoding` (the coding frames the body), names none, or names one that is
/// not a single valid length (the field block never carries it, so a head without one states
/// nothing).
fn declared_len(headers: &http::HeaderMap) -> Option<u64> {
    // A coding overrides the length (RFC 9112 6.3): hyper frames such a body by the coding, so a
    // `Content-Length` beside it states a length the body does not have.
    if headers.contains_key(http::header::TRANSFER_ENCODING) {
        return None;
    }
    let mut one: Option<u64> = None;
    for v in headers.get_all(http::header::CONTENT_LENGTH) {
        for s in v.to_str().ok()?.split(',').map(str::trim) {
            if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let n = s.parse::<u64>().ok()?;
            if one.is_some_and(|m| m != n) {
                return None;
            }
            one = Some(n);
        }
    }
    one
}

/// An HTTP/1 answer's reason phrase exactly as sent: hyper keeps a phrase that differs from the
/// canonical one, and one it did not keep was the canonical phrase. HTTP/2 has none.
fn reason_phrase(r: &http::Response<Incoming>) -> Option<Bytes> {
    if r.version() >= http::Version::HTTP_2 {
        return None;
    }
    let phrase = r
        .extensions()
        .get::<hyper::ext::ReasonPhrase>()
        .map_or_else(
            || Bytes::from_static(r.status().canonical_reason().unwrap_or("").as_bytes()),
            |p| Bytes::copy_from_slice(p.as_bytes()),
        );
    (!phrase.is_empty()).then_some(phrase)
}

#[cfg(test)]
#[path = "tests/engine_tests.rs"]
mod tests;
