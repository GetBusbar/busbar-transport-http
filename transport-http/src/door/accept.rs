// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ACCEPTED SIDE: hyper's server, run as a sans-IO framer over a connection the connector
//! accepted (`BUSBAR-1.6.0.md` l.477-478: per accepted connection the connector runs the framer's
//! accept side, under the TLS server wrap when configured; the ALPN offer is the framer's).
//!
//! One [`Accepted`] is one connection, served exactly as v1.5.5's data listener served it: through
//! `hyper_util::server::conn::auto::Builder`, so a cleartext connection that opens with the HTTP/2
//! preface is HTTP/2 by prior knowledge and every other one is HTTP/1.1, with HTTP/1's header read
//! bounded at 30 s on the host's clock and upgrades enabled (v1.5.5 `crates/busbar/src/tls.rs`:
//! 560-566 `hardened_conn_builder`, 620 `serve_connection_with_upgrades`). The protocol machine is
//! hyper's own, so the bytes it writes are the bytes v1.5.5 wrote.
//!
//! Each request is a STREAM. Its head goes up as ONE field block with the request's method, target
//! and (where the caller named one) authority in the stream's head slots, then its body as data
//! pieces, then the empty piece that says the request is whole. The answer comes down through
//! `emit`: the FIRST emit on a stream is its head, a field block (`abi::transport::fields`) with the
//! status in `EmitIn::status`; every later emit is body bytes, the last one ending the frame. A head
//! that states `content-length` frames the body by it; one that does not is chunked (HTTP/1.1),
//! exactly as hyper framed an answer whose size it did not know.
//!
//! A `101` answer to a request that asked to upgrade switches the connection: hyper writes the
//! `101`, and `detach` hands the host every byte the far side sent after the request, for the
//! claimed upgrade framer to adopt.
//!
//! NO REQUEST GOES UP UNADMITTED (`BUSBAR-1.6.0.md` §6, "Auth points and guest lists", item 4,
//! l.938-962). The connection is framed under its listener's guest list ([`guest::Line`], lent at
//! `begin`). Each decoded head waits in [`Gate`] until [`Accepted::admit`] has run it through the
//! host auth handle ([`Kernel`]): matched against the lines in order (no line: `NO_ROUTE`; a path
//! with no method admitted: `METHOD_MISS`); the matched line's auth called at its points (`Peer`
//! once per connection before any request, l.953 item 7; `Head` with the head; `HeadBody` with the
//! whole body held up to the line's `body_limit`, over which the size gate refuses BEFORE any
//! verdict, l.940-942); what the auth names stripped (field lines ASCII case-insensitively, query
//! keys case-sensitively, l.943-945); then handed in with the line it matched (l.951-957). Only
//! then does its head go up, stripped. Every refusal is the KERNEL's (`unit.refuse`, l.958-961):
//! its status, fields and body framed verbatim by hyper as any answer, and nothing goes up. A
//! refusal the kernel cannot give leaves the stream unanswered: hyper ends it with no bytes, for
//! this transport writes no refusal bytes of its own.

use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use busbar_contract::abi::auth::{POINT_HEAD, POINT_HEAD_BODY, POINT_PEER};
use busbar_contract::abi::host::service::{
    AuthRef, UnitRef, FLOW_CONTINUE, LINE_NONE, REFUSE_CHECK_FAILED, REFUSE_METHOD_MISS,
    REFUSE_NO_ROUTE, REFUSE_OVER_GATE, REFUSE_STOPPED,
};
use busbar_contract::abi::sdk::services::{HeadViewArgs, Pend, Place, RefusalCopy, ServiceError};
use busbar_contract::abi::transport::fields;
use bytes::Bytes;
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper_util::server::conn::auto;
use zeroize::Zeroize;

use super::engine::Failure;
use super::guest::{self, Line, Matched};
use super::hyper_io::{field_block, HeadWords, HostIo, Owed, Piece};

/// v1.5.5's HTTP/1 header-read bound (`hardened_conn_builder`).
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// An answer body holds at most this many queued bytes before its `emit` answers the stream full.
pub const REPLY_HIGH_WATER: usize = 256 * 1024;
/// A stream answered full is writable again once its queue drains below this.
pub const REPLY_LOW_WATER: usize = 64 * 1024;

/// The status that switches protocols.
const SWITCHING_PROTOCOLS: u16 = 101;

/// What an HTTP/2 connection opens with (RFC 9113 §3.4).
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;
type ConnResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// One answer body's queue: what the host emitted and hyper has not taken.
#[derive(Default)]
struct ReplyQ {
    chunks: VecDeque<Bytes>,
    queued: usize,
    ended: bool,
    full: bool,
    waker: Option<Waker>,
}

/// An answer body fed by the host's emits. Its size is never stated here: a head that states
/// `content-length` frames it, any other is chunked. A kernel refusal's body is whole when it is
/// framed, so its size is stated (the second field), as v1.5.5's `Full` bodies stated theirs.
struct Reply(Arc<Mutex<ReplyQ>>, Option<u64>);

impl Body for Reply {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        let mut q = self.0.lock().expect("reply");
        if let Some(c) = q.chunks.pop_front() {
            q.queued -= c.len();
            return Poll::Ready(Some(Ok(Frame::data(c))));
        }
        if q.ended {
            return Poll::Ready(None);
        }
        q.waker = Some(cx.waker().clone());
        Poll::Pending
    }

    fn is_end_stream(&self) -> bool {
        let q = self.0.lock().expect("reply");
        q.ended && q.chunks.is_empty()
    }

    fn size_hint(&self) -> SizeHint {
        self.1.map_or_else(SizeHint::default, SizeHint::with_exact)
    }
}

/// One request's answer side.
struct Answer {
    /// Where the head goes, until the first emit.
    respond: Option<futures_channel::oneshot::Sender<http::Response<Reply>>>,
    /// The body queue, once the head went.
    reply: Option<Arc<Mutex<ReplyQ>>>,
    /// The request asked to upgrade: hyper's handle on the switched connection.
    upgrade: Option<hyper::upgrade::OnUpgrade>,
    /// The answer was a `101`.
    switched: bool,
    /// The request body, carried up as it arrives once admitted, or held for a `HeadBody` auth.
    body: Option<Incoming>,
    /// The request is whole (its last piece went up).
    asked: bool,
    /// The decoded head, held until it is admitted (stripped) or refused.
    parts: Option<http::request::Parts>,
    /// Where the request stands on its way through the guest list.
    gate: Gate,
    /// The body held for a `HeadBody` auth; zeroised once handed on.
    held: Vec<u8>,
    /// The held body is whole.
    held_whole: bool,
    /// The held body passed its line's `body_limit`.
    held_over: bool,
    /// The request's unit, as the kernel answered it.
    unit: UnitRef,
    /// A pending `auth.call`'s sequence number, re-issued on the next drive.
    parked: Option<u32>,
    /// The head went up to the host.
    up: bool,
}

/// Where a request stands on its way through the guest list (`BUSBAR-1.6.0.md` §6 item 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Gate {
    /// Decoded, not yet matched.
    Arrived,
    /// Matched line `.0`, whose auth needs `HeadBody`: the body is being held.
    Hold(usize),
    /// Matched line `.0`: its auth is called at its head point.
    Auth(usize),
    /// Matched line `.0`: handed in.
    HandIn(usize),
    /// Admitted: its head went up, its body follows.
    Admitted,
    /// The kernel's refusal was framed.
    Refused,
    /// Neither admitted nor refused: left unanswered, for hyper to end.
    Failed,
}

/// What the service and the framing share.
struct Shared {
    out: VecDeque<Piece>,
    next: u64,
    streams: HashMap<u64, Answer>,
    /// The streams not yet through the guest list, in arrival order.
    waiting: Vec<u64>,
}

/// What an inbound `auth.call` answers the accepted side: the flow (`FLOW_*`), the request's unit,
/// and the names to strip, each with its place.
pub type AuthCalled = (u32, UnitRef, Vec<(String, Place)>);

/// THE HOST AUTH HANDLE as the accepted side calls it (`abi::host::service`, `op::AUTH_CALL`,
/// `op::UNIT_HAND_IN`, `op::UNIT_REFUSE`), each call under completion sequence `seq` of the op's
/// ticket; the door's is the SDK's `Services` (`door::HostKernel`).
pub trait Kernel {
    /// `auth.call`: the flow, the request's unit and the names to strip.
    #[allow(clippy::too_many_arguments)]
    fn auth_call(
        &mut self,
        seq: u32,
        auth: AuthRef,
        unit: UnitRef,
        point: u32,
        stream: u64,
        request: &HeadViewArgs<'_>,
        body: Option<&[u8]>,
    ) -> Pend<AuthCalled>;
    /// `unit.hand_in`: the flow and the request's unit.
    ///
    /// # Errors
    ///
    /// The service's.
    #[allow(clippy::too_many_arguments)]
    fn hand_in(
        &mut self,
        seq: u32,
        auth: AuthRef,
        unit: UnitRef,
        line: u32,
        stream: u64,
        request: &HeadViewArgs<'_>,
    ) -> Result<(u32, UnitRef), ServiceError>;
    /// `unit.refuse`: the kernel's refusal, copied.
    ///
    /// # Errors
    ///
    /// The service's.
    fn refuse(
        &mut self,
        seq: u32,
        unit: UnitRef,
        cause: u32,
        line: u32,
        stream: u64,
    ) -> Result<RefusalCopy, ServiceError>;
}

/// What one [`Accepted::admit`] did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Admitted {
    /// Some request moved (up, refused or failed), or the peer point was decided.
    pub moved: bool,
    /// An `auth.call` is pending: its stream is parked until the next drive.
    pub parked: bool,
}

/// One accepted connection's HTTP machine.
pub struct Accepted {
    io: HostIo,
    conn: Option<BoxFut<ConnResult>>,
    shared: Arc<Mutex<Shared>>,
    out: VecDeque<Piece>,
    ended: bool,
    /// What the far side sent after a switched request, waiting for `detach`.
    leftover: Option<VecDeque<u8>>,
    /// Every byte the far side sent, kept until the connection's first answer: a connection
    /// nothing answered yet is handed over AS SENT, its upgrade request first, for the upgrade
    /// framer to answer itself (`adopt`). Zeroised when it is let go (it holds credential lines).
    raw: Option<Vec<u8>>,
    /// The listener's guest list, in match order.
    lines: Vec<Line>,
    /// The distinct auth handles the lines call at the peer point, in list order.
    peer_auths: Vec<AuthRef>,
    /// How many of them answered CONTINUE.
    peer_done: usize,
    /// A pending peer call's sequence number.
    peer_parked: Option<u32>,
    /// The last completion sequence number issued.
    seq: u32,
}

impl Drop for Accepted {
    fn drop(&mut self) {
        self.let_raw_go();
    }
}

impl Accepted {
    /// Serve an accepted connection at host time `now_ns`, under guest list `lines`.
    #[must_use]
    pub fn accept(now_ns: u64, lines: Vec<Line>) -> Self {
        let io = HostIo::new(now_ns);
        let shared = Arc::new(Mutex::new(Shared {
            out: VecDeque::new(),
            next: 1,
            streams: HashMap::new(),
            waiting: Vec::new(),
        }));
        let mut peer_auths: Vec<AuthRef> = Vec::new();
        for l in lines.iter().filter(|l| l.points & POINT_PEER != 0) {
            if !peer_auths.contains(&l.auth) {
                peer_auths.push(l.auth);
            }
        }
        let sh = shared.clone();
        let service =
            hyper::service::service_fn(move |req: http::Request<Incoming>| serve(sh.clone(), req));
        let mut builder = auto::Builder::new(io.exec());
        builder
            .http1()
            .timer(io.timer())
            .header_read_timeout(HEADER_READ_TIMEOUT);
        let conn = builder
            .serve_connection_with_upgrades(io.stream(), service)
            .into_owned();
        Self {
            io,
            conn: Some(Box::pin(conn)),
            shared,
            out: VecDeque::new(),
            ended: false,
            leftover: None,
            raw: Some(Vec::new()),
            lines,
            peer_auths,
            peer_done: 0,
            peer_parked: None,
            seq: 0,
        }
    }

    /// Let the bytes kept for a hand-over as sent go, zeroised.
    fn let_raw_go(&mut self) {
        if let Some(mut raw) = self.raw.take() {
            raw.zeroize();
        }
    }

    /// The next completion sequence number.
    fn next_seq(&mut self) -> u32 {
        self.seq = self.seq.wrapping_add(1);
        self.seq
    }

    /// The far side sent `bytes` (`end` = and then ended).
    pub fn ingest(&mut self, bytes: &[u8], end: bool) {
        if let Some(raw) = self.raw.as_mut() {
            raw.extend_from_slice(bytes);
        }
        self.io.ingest(bytes, end);
    }

    /// Whether `stream`'s next emit carries its answer's head.
    #[must_use]
    pub fn answers_head(&self, stream: u64) -> bool {
        self.shared
            .lock()
            .expect("shared")
            .streams
            .get(&stream)
            .is_some_and(|a| a.up && a.respond.is_some())
    }

    /// Bytes for `stream`'s answer: its head (a field block, with `status`) on the first emit,
    /// body bytes after it. Answers whether the stream's queue is now at its high-water mark.
    ///
    /// # Errors
    ///
    /// No such stream, a head no answer can carry, or bytes after the answer ended.
    pub fn emit(
        &mut self,
        stream: u64,
        bytes: &[u8],
        end: bool,
        status: u32,
    ) -> Result<bool, Failure> {
        let mut sh = self.shared.lock().expect("shared");
        // A stream the host was never handed (refused, or not yet admitted) is no request of its.
        let Some(a) = sh.streams.get_mut(&stream).filter(|a| a.up) else {
            return Err(Failure(format!("emit: no request on stream {stream}")));
        };
        if let Some(respond) = a.respond.take() {
            // The connection answers: it is no longer one to hand over as sent.
            if let Some(mut raw) = self.raw.take() {
                raw.zeroize();
            }
            let code = u16::try_from(status)
                .ok()
                .and_then(|s| http::StatusCode::from_u16(s).ok())
                .ok_or_else(|| Failure(format!("emit: {status} is not an HTTP status")))?;
            let mut b = http::Response::builder().status(code);
            for (name, value) in fields::lines(bytes) {
                b = b.header(name, value);
            }
            let q = Arc::new(Mutex::new(ReplyQ {
                ended: end,
                ..ReplyQ::default()
            }));
            let resp = b
                .body(Reply(q.clone(), None))
                .map_err(|e| Failure(format!("emit: the head is not an answer: {e}")))?;
            a.switched = code.as_u16() == SWITCHING_PROTOCOLS && a.upgrade.is_some();
            a.reply = Some(q);
            // The far side may have gone; its stream's end says so.
            let _ = respond.send(resp);
            return Ok(false);
        }
        let Some(q) = a.reply.as_ref() else {
            return Err(Failure(format!("emit: stream {stream} has no answer")));
        };
        let mut q = q.lock().expect("reply");
        if bytes.is_empty() && !end {
            // A re-call after `YIELD_MORE` carries nothing new.
            return Ok(q.full);
        }
        if q.ended {
            return Err(Failure(format!(
                "emit: stream {stream}'s answer already ended"
            )));
        }
        if !bytes.is_empty() {
            q.queued += bytes.len();
            q.chunks.push_back(Bytes::copy_from_slice(bytes));
        }
        q.ended |= end;
        if q.queued >= REPLY_HIGH_WATER {
            q.full = true;
        }
        if let Some(w) = q.waker.take() {
            w.wake();
        }
        Ok(q.full)
    }

    /// Drive the connection at host time `now_ns` until nothing inside it has more to do.
    pub fn drive(&mut self, now_ns: u64) {
        self.io.set_time(now_ns);
        let io = self.io.clone();
        let conn = &mut self.conn;
        let ended = &mut self.ended;
        let shared = &self.shared;
        let lines = &self.lines;
        let _ = io.rounds(|cx| {
            if let Some(c) = conn.as_mut() {
                if let Poll::Ready(_r) = c.as_mut().poll(cx) {
                    // The connection is over: closed by the far side, refused by hyper (it
                    // answered a malformed request itself, as v1.5.5's did), past its header-read
                    // bound, or switched.
                    *conn = None;
                    *ended = true;
                }
            }
            carry_bodies(&mut shared.lock().expect("shared"), lines, cx);
            Ok::<(), Failure>(())
        });
        let mut sh = self.shared.lock().expect("shared");
        if self.ended {
            // A request the far side abandoned before it was whole fails its stream.
            let open: Vec<u64> = sh
                .streams
                .iter()
                .filter(|(_, a)| a.up && !a.asked && !a.switched)
                .map(|(s, _)| *s)
                .collect();
            for s in open {
                if let Some(a) = sh.streams.get_mut(&s) {
                    a.asked = true;
                }
                sh.out.push_back(Piece::failure(
                    s,
                    "the connection ended before the request was whole",
                ));
            }
        }
        let mut writable = Vec::new();
        for (s, a) in &sh.streams {
            if let Some(q) = &a.reply {
                let mut q = q.lock().expect("reply");
                if q.full && q.queued < REPLY_LOW_WATER {
                    q.full = false;
                    writable.push(*s);
                }
            }
        }
        for s in writable {
            sh.out.push_back(Piece::writable(s));
        }
        let pieces: Vec<Piece> = sh.out.drain(..).collect();
        drop(sh);
        self.out.extend(pieces);
    }

    /// DETACH the connection for the upgrade framer to adopt, two ways:
    ///
    /// * a connection NOTHING ANSWERED yet goes AS SENT, its upgrade request first, for a framer
    ///   that answers the upgrade itself (ws's `adopt` takes the request it answers). An HTTP/2
    ///   connection (it opened with the preface) carries no upgrade and is not handed over;
    /// * a connection whose request the host answered `101` goes from the byte after that request.
    ///
    /// `None`: neither holds.
    ///
    /// # Errors
    ///
    /// The switch itself failed.
    pub fn detach(&mut self) -> Result<Option<&mut VecDeque<u8>>, Failure> {
        let switched = self
            .shared
            .lock()
            .expect("shared")
            .streams
            .values()
            .any(|a| a.switched);
        if self.leftover.is_none() && !switched {
            if let Some(raw) = self.raw.take() {
                if raw.starts_with(H2_PREFACE) {
                    return Ok(None);
                }
                // hyper is dropped unanswered: the far side's bytes are the upgrade framer's now.
                self.conn = None;
                self.leftover = Some(raw.into());
                self.ended = true;
            }
        }
        if self.leftover.is_none() {
            let mut up = {
                let mut sh = self.shared.lock().expect("shared");
                let Some(up) = sh
                    .streams
                    .values_mut()
                    .find(|a| a.switched)
                    .and_then(|a| a.upgrade.take())
                else {
                    return Ok(None);
                };
                up
            };
            let io = self.io.clone();
            let conn = &mut self.conn;
            let mut got = None;
            let _ = io.rounds(|cx| {
                if let Some(c) = conn.as_mut() {
                    if c.as_mut().poll(cx).is_ready() {
                        *conn = None;
                    }
                }
                if got.is_none() {
                    if let Poll::Ready(r) = Pin::new(&mut up).poll(cx) {
                        got = Some(r);
                    }
                }
                Ok::<(), Failure>(())
            });
            let Some(upgraded) = got else {
                return Err(Failure("detach: the switch has not completed".into()));
            };
            let mut upgraded =
                upgraded.map_err(|e| Failure(format!("detach: the switch failed: {e}")))?;
            // Read the switched connection dry: hyper's own read-ahead first, then the pipe.
            let mut rest = VecDeque::new();
            let waker = Waker::noop();
            let mut cx = Context::from_waker(waker);
            let mut buf = vec![0_u8; 16 * 1024];
            loop {
                let mut rb = hyper::rt::ReadBuf::new(&mut buf);
                match hyper::rt::Read::poll_read(Pin::new(&mut upgraded), &mut cx, rb.unfilled()) {
                    Poll::Ready(Ok(())) if !rb.filled().is_empty() => rest.extend(rb.filled()),
                    _ => break,
                }
            }
            self.leftover = Some(rest);
            self.ended = true;
        }
        Ok(self.leftover.as_mut())
    }
}

impl Owed for Accepted {
    fn take_wire(&mut self, cap: usize) -> Vec<u8> {
        self.io.take_wire(cap)
    }
    fn wire_pending(&self) -> bool {
        self.io.wire_pending()
    }
    fn pieces(&mut self) -> &mut VecDeque<Piece> {
        &mut self.out
    }
    fn next_deadline(&self) -> Option<u64> {
        self.io.next_deadline()
    }
    fn ended(&self) -> bool {
        self.ended
    }
}

/// One request, as hyper hands it to the service: it waits for [`Accepted::admit`] (its head goes up
/// once admitted, its body pumped up as it arrives), and the answer waits for the host's first emit
/// on its stream, or is the kernel's refusal.
fn serve(
    sh: Arc<Mutex<Shared>>,
    mut req: http::Request<Incoming>,
) -> BoxFut<Result<http::Response<Reply>, std::io::Error>> {
    let upgrade = req
        .headers()
        .contains_key(http::header::UPGRADE)
        .then(|| hyper::upgrade::on(&mut req));
    let (parts, body) = req.into_parts();
    let (tx, rx) = futures_channel::oneshot::channel();
    let stream = {
        let mut s = sh.lock().expect("shared");
        let id = s.next;
        s.next += 1;
        s.streams.insert(
            id,
            Answer {
                respond: Some(tx),
                reply: None,
                upgrade,
                switched: false,
                body: Some(body),
                asked: false,
                parts: Some(parts),
                gate: Gate::Arrived,
                held: Vec::new(),
                held_whole: false,
                held_over: false,
                unit: UnitRef::NONE,
                parked: None,
                up: false,
            },
        );
        s.waiting.push(id);
        id
    };
    let _ = stream;
    Box::pin(async move {
        rx.await.map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "the stream was given up before it was answered",
            )
        })
    })
}

/// Carry every ADMITTED request body up as far as it has arrived: data pieces, then the empty
/// piece that says the request is whole (or the failure piece of a body the far side broke off).
/// A body a `HeadBody` auth needs is held instead, up to its line's limit
/// ([`hold_body`]); any other waits, unread, for its request's admission.
fn carry_bodies(sh: &mut Shared, lines: &[Line], cx: &mut Context<'_>) {
    let Shared { out, streams, .. } = sh;
    for (id, a) in streams.iter_mut() {
        if let Gate::Hold(n) = a.gate {
            hold_body(a, lines[n].body_limit, cx);
            continue;
        }
        if a.gate != Gate::Admitted {
            continue;
        }
        let Some(body) = a.body.as_mut() else {
            continue;
        };
        loop {
            match Pin::new(&mut *body).poll_frame(cx) {
                Poll::Pending => break,
                // Data is carried as it arrives; a trailer section is not (v1.5.5's handlers
                // read data only).
                Poll::Ready(Some(Ok(f))) => {
                    if let Ok(d) = f.into_data() {
                        if !d.is_empty() {
                            out.push_back(Piece::data(*id, d));
                        }
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    out.push_back(Piece::failure(*id, &e.to_string()));
                    a.body = None;
                    a.asked = true;
                    break;
                }
                Poll::Ready(None) => {
                    out.push_back(Piece::end(*id));
                    a.body = None;
                    a.asked = true;
                    break;
                }
            }
        }
    }
}

/// Hold a `HeadBody` request's body as it arrives, up to `limit` bytes (THE DESIGN §6 item 4,
/// l.940-942: "`HeadBody`'s bound is the size gate's limit; over it is 413, answered before the
/// verdict"). Past the limit the body is let go (zeroised) and no more is read; whole, it waits for
/// the auth.
fn hold_body(a: &mut Answer, limit: u64, cx: &mut Context<'_>) {
    let Some(body) = a.body.as_mut() else {
        return;
    };
    loop {
        match Pin::new(&mut *body).poll_frame(cx) {
            Poll::Pending => return,
            Poll::Ready(Some(Ok(f))) => {
                if let Ok(d) = f.into_data() {
                    a.held.extend_from_slice(&d);
                }
                if a.held.len() as u64 > limit {
                    a.held.zeroize();
                    a.held_over = true;
                    a.body = None;
                    return;
                }
            }
            // A body the far side broke off is no request to judge: the stream is left to hyper.
            Poll::Ready(Some(Err(_))) => {
                a.held.zeroize();
                a.body = None;
                a.gate = Gate::Failed;
                a.respond = None;
                return;
            }
            Poll::Ready(None) => {
                a.held_whole = true;
                a.body = None;
                return;
            }
        }
    }
}

/// The request as the auth handle reads it (`HeadView`): the method, the target's path, the
/// authority (the target's own, else the `host` line, as HTTP/1.1 states it), the query, and the
/// head's field lines in order, as received. Borrowed from `parts` and `fields`.
fn head_view<'a>(
    parts: &'a http::request::Parts,
    fields: &'a [(&'a str, &'a [u8])],
) -> HeadViewArgs<'a> {
    let authority = parts.uri.authority().map_or_else(
        || {
            parts
                .headers
                .get(http::header::HOST)
                .and_then(|h| h.to_str().ok())
                .unwrap_or("")
        },
        http::uri::Authority::as_str,
    );
    HeadViewArgs {
        method: parts.method.as_str(),
        target: parts.uri.path(),
        authority,
        query: parts.uri.query(),
        fields,
    }
}

/// The head's field lines as `(name, value)`, in order.
fn field_lines(parts: &http::request::Parts) -> Vec<(&str, &[u8])> {
    parts
        .headers
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_bytes()))
        .collect()
}

/// Strip from `parts` what the auth named (THE DESIGN §6 item 4, l.943-945): every field line it
/// names (ASCII case-insensitively) and every query key (case-sensitively), the target rewritten
/// without those keys.
///
/// # Errors
///
/// The rewritten target is not one (it cannot be: a target with pairs taken out).
fn strip(parts: &mut http::request::Parts, names: &[(String, Place)]) -> Result<(), Failure> {
    let gone: Vec<http::HeaderName> = parts
        .headers
        .keys()
        .filter(|n| guest::strips_field(n.as_str(), names))
        .cloned()
        .collect();
    for n in gone {
        parts.headers.remove(&n);
    }
    if names.iter().any(|(_, p)| *p == Place::Query) {
        if let Some(q) = parts.uri.query() {
            let target = match guest::stripped_query(q, names) {
                Some(kept) => format!("{}?{kept}", parts.uri.path()),
                None => parts.uri.path().to_owned(),
            };
            let mut up = parts.uri.clone().into_parts();
            up.path_and_query = Some(
                http::uri::PathAndQuery::try_from(target)
                    .map_err(|e| Failure(format!("strip: {e}")))?,
            );
            parts.uri = http::Uri::from_parts(up).map_err(|e| Failure(format!("strip: {e}")))?;
        }
    }
    Ok(())
}

/// Frame the kernel's refusal on `a`'s stream, verbatim: its status, its fields in order, its body
/// at its stated size. `false`: it is no answer hyper can carry (the stream is left unanswered).
fn frame_refusal(a: &mut Answer, r: RefusalCopy) -> bool {
    let Some(respond) = a.respond.take() else {
        return false;
    };
    let mut b = http::Response::builder().status(r.status);
    for (name, value) in &r.fields {
        b = b.header(name.as_str(), value.as_slice());
    }
    let len = r.body.len() as u64;
    let q = Arc::new(Mutex::new(ReplyQ {
        ended: true,
        queued: r.body.len(),
        chunks: if r.body.is_empty() {
            VecDeque::new()
        } else {
            VecDeque::from([Bytes::from(r.body)])
        },
        ..ReplyQ::default()
    }));
    let Ok(resp) = b.body(Reply(q.clone(), Some(len))) else {
        return false;
    };
    a.reply = Some(q);
    // The far side may have gone; its stream's end says so.
    let _ = respond.send(resp);
    true
}

impl Accepted {
    /// ADMIT what the guest list holds (`BUSBAR-1.6.0.md` §6 item 4, l.938-962; item 7, l.952-956):
    /// the peer point first, once per connection, then every waiting request in arrival order, each
    /// as far as it can go now. A pending `auth.call` parks only its own stream (or, at the peer
    /// point, the connection's requests) until the next drive re-issues it.
    pub fn admit(&mut self, k: &mut dyn Kernel) -> Admitted {
        let mut did = Admitted::default();
        if self.ended && self.conn.is_none() {
            return did;
        }
        while self.peer_done < self.peer_auths.len() {
            let seq = self.peer_parked.take().unwrap_or_else(|| self.next_seq());
            let auth = self.peer_auths[self.peer_done];
            match k.auth_call(
                seq,
                auth,
                UnitRef::NONE,
                POINT_PEER,
                0,
                &HeadViewArgs::default(),
                None,
            ) {
                Poll::Pending => {
                    self.peer_parked = Some(seq);
                    did.parked = true;
                    return did;
                }
                Poll::Ready(Ok((FLOW_CONTINUE, ..))) => {
                    self.peer_done += 1;
                    did.moved = true;
                }
                // A `Peer` refusal (or no answer) closes the connection with no response bytes
                // (item 7, l.955-956).
                Poll::Ready(_) => {
                    self.conn = None;
                    self.ended = true;
                    did.moved = true;
                    return did;
                }
            }
        }
        let shared = self.shared.clone();
        let mut sh = shared.lock().expect("shared");
        let waiting = std::mem::take(&mut sh.waiting);
        for id in waiting {
            let Some(mut a) = sh.streams.remove(&id) else {
                continue;
            };
            let before = a.gate;
            self.admit_one(id, &mut a, &mut sh.out, k, &mut did);
            // A request that moved on (to holding its body, say) is driven again before the op
            // answers.
            did.moved |= a.gate != before;
            let done = matches!(a.gate, Gate::Admitted | Gate::Refused | Gate::Failed);
            if a.gate == Gate::Refused {
                // The connection answered: it is no longer one to hand over as sent.
                self.let_raw_go();
            }
            sh.streams.insert(id, a);
            if !done {
                sh.waiting.push(id);
            }
        }
        did
    }

    /// Take request `id` as far through the guest list as it can go now.
    fn admit_one(
        &mut self,
        id: u64,
        a: &mut Answer,
        out: &mut VecDeque<Piece>,
        k: &mut dyn Kernel,
        did: &mut Admitted,
    ) {
        loop {
            let Some(parts) = a.parts.as_ref() else {
                return;
            };
            match a.gate {
                Gate::Arrived => {
                    let fields = field_lines(parts);
                    let to = match guest::matched(
                        &self.lines,
                        parts.method.as_str(),
                        parts.uri.path(),
                        &fields,
                    ) {
                        Matched::NoRoute => {
                            return self.refuse(id, a, REFUSE_NO_ROUTE, LINE_NONE, k, did);
                        }
                        Matched::MethodMiss(n) => {
                            let line = self.lines[n].line;
                            return self.refuse(id, a, REFUSE_METHOD_MISS, line, k, did);
                        }
                        Matched::Line(n) => {
                            let points = self.lines[n].points;
                            if points & POINT_HEAD_BODY != 0 {
                                Gate::Hold(n)
                            } else if points & POINT_HEAD != 0 {
                                Gate::Auth(n)
                            } else {
                                Gate::HandIn(n)
                            }
                        }
                    };
                    a.gate = to;
                }
                Gate::Hold(n) => {
                    if a.held_over {
                        // The size gate, before any verdict.
                        let line = self.lines[n].line;
                        return self.refuse(id, a, REFUSE_OVER_GATE, line, k, did);
                    }
                    if !a.held_whole {
                        return;
                    }
                    a.gate = Gate::Auth(n);
                }
                Gate::Auth(n) => {
                    let l = &self.lines[n];
                    let (auth, line, body_point) =
                        (l.auth, l.line, l.points & POINT_HEAD_BODY != 0);
                    let seq = a.parked.take().unwrap_or_else(|| self.next_seq());
                    let fields = field_lines(parts);
                    let view = head_view(parts, &fields);
                    let (point, body) = if body_point {
                        (POINT_HEAD_BODY, Some(a.held.as_slice()))
                    } else {
                        (POINT_HEAD, None)
                    };
                    let answered = k.auth_call(seq, auth, a.unit, point, id, &view, body);
                    drop(fields);
                    match answered {
                        Poll::Pending => {
                            a.parked = Some(seq);
                            did.parked = true;
                            return;
                        }
                        Poll::Ready(Ok((flow, unit, names))) => {
                            a.unit = unit;
                            let stripped = a.parts.as_mut().map_or(Ok(()), |p| strip(p, &names));
                            if stripped.is_err() {
                                return fail(a, did);
                            }
                            if flow != FLOW_CONTINUE {
                                return self.refuse(id, a, REFUSE_STOPPED, line, k, did);
                            }
                            a.gate = Gate::HandIn(n);
                        }
                        Poll::Ready(Err(_)) => return fail(a, did),
                    }
                }
                Gate::HandIn(n) => {
                    let (auth, line) = (self.lines[n].auth, self.lines[n].line);
                    let seq = self.next_seq();
                    let fields = field_lines(parts);
                    let view = head_view(parts, &fields);
                    let handed = k.hand_in(seq, auth, a.unit, line, id, &view);
                    drop(fields);
                    match handed {
                        Ok((flow, unit)) => {
                            a.unit = unit;
                            if flow != FLOW_CONTINUE {
                                return self.refuse(id, a, REFUSE_CHECK_FAILED, line, k, did);
                            }
                            go_up(id, a, out);
                            did.moved = true;
                        }
                        Err(_) => return fail(a, did),
                    }
                }
                Gate::Admitted | Gate::Refused | Gate::Failed => return,
            }
        }
    }

    /// Ask the kernel for request `id`'s refusal (`cause`, `line`) and frame it verbatim; nothing
    /// goes up. No refusal from the kernel leaves the stream unanswered.
    fn refuse(
        &mut self,
        id: u64,
        a: &mut Answer,
        cause: u32,
        line: u32,
        k: &mut dyn Kernel,
        did: &mut Admitted,
    ) {
        let seq = self.next_seq();
        a.held.zeroize();
        // A request with no line has no unit (l.947: "A request that matches no line has no unit").
        let unit = if line == LINE_NONE {
            UnitRef::NONE
        } else {
            a.unit
        };
        let framed = k
            .refuse(seq, unit, cause, line, id)
            .is_ok_and(|r| frame_refusal(a, r));
        if !framed {
            return fail(a, did);
        }
        a.gate = Gate::Refused;
        a.parts = None;
        a.body = None;
        did.moved = true;
    }
}

/// Leave request `a` unanswered: its answer's sender dropped, hyper ends the stream (HTTP/2) or
/// the connection (HTTP/1.1) with no bytes of this transport's own.
fn fail(a: &mut Answer, did: &mut Admitted) {
    a.respond = None;
    a.parts = None;
    a.body = None;
    a.held.zeroize();
    a.gate = Gate::Failed;
    did.moved = true;
}

/// Request `id` is admitted: its stripped head goes up, then any body held for its auth (whole),
/// and the rest of its body follows as it arrives.
fn go_up(id: u64, a: &mut Answer, out: &mut VecDeque<Piece>) {
    let Some(parts) = a.parts.take() else {
        return;
    };
    out.push_back(head_piece(id, &parts));
    if !a.held.is_empty() {
        out.push_back(Piece::data(id, Bytes::copy_from_slice(&a.held)));
        a.held.zeroize();
    }
    if a.held_whole {
        out.push_back(Piece::end(id));
        a.asked = true;
    }
    a.up = true;
    a.gate = Gate::Admitted;
}

/// A request head as the frame the layer above reads: ONE field block (no pseudo-field, no
/// hop-by-hop field, no `content-length`: the pieces carry the body hyper unframed), the method,
/// target and named authority in its head slots.
fn head_piece(stream: u64, parts: &http::request::Parts) -> Piece {
    let target = parts
        .uri
        .path_and_query()
        .map_or_else(|| parts.uri.to_string(), |p| p.as_str().to_owned());
    let authority = parts
        .uri
        .authority()
        .map_or_else(String::new, |a| a.as_str().to_owned());
    Piece {
        head: Some(HeadWords {
            method: Bytes::copy_from_slice(parts.method.as_str().as_bytes()),
            target: Bytes::from(target),
            authority: Bytes::from(authority),
            reason: Bytes::new(),
        }),
        ..Piece::fields(stream, Bytes::from(field_block(&parts.headers, &[])))
    }
}

#[cfg(test)]
#[path = "tests/accept_tests.rs"]
mod tests;
