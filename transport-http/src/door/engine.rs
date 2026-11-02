// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ENGINE: hyper's `client::conn` (HTTP/1.1 and HTTP/2) run as a sans-IO framer.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

pub(crate) use super::hyper_io::field_block;
use super::hyper_io::{HeadWords, HostIo, Owed, Piece};
use busbar_contract::abi::transport::sensitive_fields::SensitiveFields;
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

enum Stage {
    /// The request message, still arriving, and the attempt's deadline (host ns).
    Writing(Zeroizing<Vec<u8>>, EgressHead, u64, SensitiveFields),
    /// A whole request, waiting for the connection to take it.
    Queued(http::Request<Full<Bytes>>, Pin<Box<dyn Sleep>>),
    /// Sent; waiting for the response head.
    Asked(
        BoxFut<hyper::Result<http::Response<Incoming>>>,
        Pin<Box<dyn Sleep>>,
    ),
    /// The response body, and where its last queued byte stands in the framing's queue
    Body(Incoming, Pin<Box<dyn Sleep>>, u64),
    /// Refused partway through its request message (HTTP/2): the failure piece is out, and every
    Refused,
    /// Answered in full.
    Done,
}

/// The most a request's head (its request line and fields) may add to its body in one emitted

pub(crate) const HEAD_MAX_BYTES: usize = 8192 + 4096 * 100;

/// How far an HTTP/2 stream's body may run ahead of the host: once this many queued bytes stand

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
        if !list.is_empty() {
            cx.waker().wake_by_ref();
        }
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
    carried: bool,
    proto: Proto,
    posture: Posture,
    exchanges: Vec<(u64, Stage)>,
    out: Queue,
    /// Whether the last drive left an HTTP/2 body unpolled for `BODY_HOLD`: the framing asks to
    held: bool,
    failed: Option<Failure>,
    now_unix_ns: u64,
}

impl Framing {
    /// Open a dialled framing over `dial`, speaking `proto`, at host time `now_ns`.

    pub fn dial(dial: &str, proto: Proto, posture: Posture, now_ns: u64) -> Result<Self, Failure> {
        let dial = canonical_host(
            dial.parse()
                .map_err(|_| Failure("the target is not a URL".into()))?,
        );

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

    pub fn emit(
        &mut self,
        stream: u64,
        bytes: &[u8],
        end: bool,
        now_ns: u64,
        deadline_ns: u64,
    ) -> Result<(), Failure> {
        self.emit_marked(stream, bytes, end, now_ns, deadline_ns, None)
    }

    /// Emit the first part of a request with its immutable host-owned header classification.
    pub fn emit_sensitive(
        &mut self,
        stream: u64,
        bytes: &[u8],
        end: bool,
        now_ns: u64,
        deadline_ns: u64,
        sensitive: SensitiveFields,
    ) -> Result<(), Failure> {
        self.emit_marked(stream, bytes, end, now_ns, deadline_ns, Some(sensitive))
    }

    fn emit_marked(
        &mut self,
        stream: u64,
        bytes: &[u8],
        end: bool,
        now_ns: u64,
        deadline_ns: u64,
        sensitive: Option<SensitiveFields>,
    ) -> Result<(), Failure> {
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

        if bytes.is_empty() && !end && sensitive.is_none() {
            return Ok(());
        }
        let deadline = if deadline_ns != 0 {
            deadline_ns
        } else {
            now_ns.saturating_add(
                u64::try_from(self.posture.request_timeout.as_nanos()).unwrap_or(u64::MAX),
            )
        };
        let read = if bytes.is_empty() && sensitive.is_none() {
            Ok(())
        } else {
            self.message(stream, bytes, deadline, sensitive)
        };

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
                self.exchanges.retain(|(s, _)| *s != stream);
                self.failed = Some(f.clone());
                Err(f)
            }
        }
    }

    fn message(
        &mut self,
        stream: u64,
        bytes: &[u8],
        deadline: u64,
        sensitive: Option<SensitiveFields>,
    ) -> Result<(), Failure> {
        let max = self.posture.max_body_bytes;
        let idx = match self.exchanges.iter().position(|(s, _)| *s == stream) {
            Some(i) => i,
            None => {
                self.exchanges.push((
                    stream,
                    Stage::Writing(
                        Zeroizing::default(),
                        EgressHead::default(),
                        deadline,
                        sensitive.clone().unwrap_or_default(),
                    ),
                ));
                self.exchanges.len() - 1
            }
        };
        let Stage::Writing(buf, head, deadline, marked) = &mut self.exchanges[idx].1 else {
            return Err(Failure(format!(
                "stream {stream} already carries a request"
            )));
        };
        if sensitive
            .as_ref()
            .is_some_and(|sensitive| sensitive != marked)
        {
            return Err(Failure(
                "request sensitivity changed during its head".into(),
            ));
        }
        extend_wiped(buf, bytes);

        if buf.len() > max.saturating_add(HEAD_MAX_BYTES) {
            return Err(Failure("request message over the body cap".into()));
        }
        let raw = complete_message(buf, head, max, HEAD_MAX_BYTES)
            .map_err(|e| Failure(format!("request message: {e}")))?;
        let Some(whole) = raw else { return Ok(()) };

        let parsed = Head::parse(&buf[..whole.head_end])
            .map_err(|e| Failure(format!("request message: {e}")))?;

        let target = request_target(&self.dial, parsed.path, !self.carried)
            .map_err(|e| Failure(format!("request target: {e}")))?;
        let mut b = http::Request::builder().method(parsed.method).uri(target);
        for (k, v) in parsed.fields() {
            if k.eq_ignore_ascii_case(b"transfer-encoding") {
                continue;
            }

            let mut value = http::HeaderValue::from_bytes(v)
                .map_err(|error| Failure(format!("request: {error}")))?;
            value.set_sensitive(marked.contains(k));
            b = b.header(k, value);
        }
        let body = match whole.decoded {
            Some(decoded) => {
                #[cfg(test)]
                crate::wipe_probe::watch("queued decoded body", &decoded);
                held_bytes(decoded)
            }

            None => {
                let mut bytes = std::mem::take(&mut **buf);
                zeroize::Zeroize::zeroize(&mut bytes[..whole.head_end]);
                #[cfg(test)]
                crate::wipe_probe::watch("queued request body", &bytes);
                held_bytes(Zeroizing::new(bytes)).slice(whole.head_end..)
            }
        };
        let mut req = b
            .body(Full::new(body))
            .map_err(|e| Failure(format!("request: {e}")))?;
        target_form(&mut req, self.proto)?;

        self.carried = true;
        let wait = self.io.timer().sleep_until_ns(*deadline);
        self.exchanges[idx].1 = Stage::Queued(req, wait);
        Ok(())
    }

    /// Drive the connection at host time (`now_ns` monotonic, `now_unix_ns` wall) until nothing

    pub fn drive(&mut self, now_ns: u64, now_unix_ns: u64) {
        self.io.set_time(now_ns);
        self.now_unix_ns = now_unix_ns;
        self.held = false;
        if self.failed.is_some() {
            return;
        }
        let io = self.io.clone();

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

/// Share an owned body without releasing its wiping owner before the last byte view is dropped.
pub(crate) fn held_bytes(bytes: Zeroizing<Vec<u8>>) -> Bytes {
    struct Held(Zeroizing<Vec<u8>>);
    impl AsRef<[u8]> for Held {
        fn as_ref(&self) -> &[u8] {
            self.0.as_slice()
        }
    }
    Bytes::from_owner(Held(bytes))
}

/// Normalize the dial authority as the 1.5.5 client's URL parser did.

fn canonical_host(dial: http::Uri) -> http::Uri {
    let dial = super::as_http(dial);
    let Some(host) = dial.host() else {
        return dial;
    };
    let name = match host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
    {
        Some(host) => format!("[{}]", super::offered_name(host)),
        None => super::offered_name(host),
    };
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

pub(crate) fn client_defaults(target: &http::Uri) -> String {
    let mut lines = String::from("accept: */*\r\n");

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

                    Poll::Ready(Some(Ok(fr))) => {
                        if let Ok(d) = fr.into_data() {
                            if !d.is_empty() {
                                out.push(Piece::data(id, d));
                                *last = out.pushed;
                            }
                        }
                    }
                    Poll::Ready(None) => {
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

fn declared_len(headers: &http::HeaderMap) -> Option<u64> {
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
