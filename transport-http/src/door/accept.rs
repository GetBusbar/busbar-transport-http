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
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use busbar_contract::abi::auth::{POINT_HEAD, POINT_HEAD_BODY, POINT_PEER};
use busbar_contract::abi::host::service::{
    AuthRef, UnitRef, FLOW_CONTINUE, LINE_NONE, REFUSE_CHECK_FAILED, REFUSE_METHOD_MISS,
    REFUSE_NO_ROUTE, REFUSE_OVER_GATE, REFUSE_STOPPED, SCHEME_PLAIN,
};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::services::{HeadViewArgs, Pend, Place, RefusalCopy, ServiceError};
use busbar_contract::abi::transport::fields;
use bytes::Bytes;
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper_util::server::conn::auto;
use zeroize::Zeroize;

use super::engine::{Failure, HEAD_MAX_BYTES};
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
    /// The host refused the stream after its head went (`RefuseIn::head_sent`): the answer ends
    /// failed, never as whole.
    broken: bool,
    /// hyper let the answer's body go ([`Reply`]'s drop): as it ended, or because the far side
    /// gave the stream up (an HTTP/2 reset) while the answer was still owed.
    gone: bool,
}

/// An answer body fed by the host's emits. Its size is never stated here: a head that states
/// `content-length` frames it, any other is chunked. A kernel refusal's body is whole when it is
/// framed, so its size is stated (the second field), as v1.5.5's `Full` bodies stated theirs.
struct Reply(Arc<Mutex<ReplyQ>>, Option<u64>);

/// hyper lets an answer's body go when it is whole, and when the far side gives its stream up
/// mid-answer (an HTTP/2 reset): either way the framing is told ([`ReplyQ::gone`]).
impl Drop for Reply {
    fn drop(&mut self) {
        if let Ok(mut q) = self.0.lock() {
            q.gone = true;
        }
    }
}

impl Body for Reply {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        let mut q = self.0.lock().expect("reply");
        if q.broken {
            // hyper ends the answer failed: HTTP/1.1 closes the connection with no terminating
            // chunk, HTTP/2 resets the stream.
            return Poll::Ready(Some(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "the host refused the stream after its head",
            ))));
        }
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
    /// The body held for a `HeadBody` auth; zeroised once handed on, and every allocation it
    /// outgrew zeroised as it grew ([`extend_wiped`]).
    held: Vec<u8>,
    /// The held body is whole.
    held_whole: bool,
    /// The held body passed its line's `body_limit`.
    held_over: bool,
    /// The request's unit, as the kernel answered it.
    unit: UnitRef,
    /// A pending `auth.call`'s handle, `(ticket, seq)`: re-issued only on that ticket's resume.
    parked: Option<(Ticket, u32)>,
    /// The head went up to the host.
    up: bool,
    /// The host was told the stream ended (its failure piece went), or ended it itself.
    told: bool,
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
    /// A request asking no upgrade was decoded: the connection can no longer be handed over as
    /// sent, so the copy kept for that goes.
    no_hand_over: bool,
}

/// What an inbound `auth.call` answers the accepted side: the flow (`FLOW_*`), the request's unit,
/// and the names to strip, each with its place.
pub type AuthCalled = (u32, UnitRef, Vec<(String, Place)>);

/// THE HOST AUTH HANDLE as the accepted side calls it (`abi::host::service`, `op::AUTH_CALL`,
/// `op::UNIT_HAND_IN`, `op::UNIT_REFUSE`), each call under completion sequence `seq` of the op's
/// ticket; the door's is the SDK's `Services` (`door::HostKernel`).
pub trait Kernel {
    /// The ticket of the op the calls are made on; a call that pends is parked on it.
    fn ticket(&self) -> Ticket {
        Ticket::NONE
    }

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
    #[allow(clippy::too_many_arguments)]
    fn refuse(
        &mut self,
        seq: u32,
        unit: UnitRef,
        cause: u32,
        line: u32,
        stream: u64,
        request: &HeadViewArgs<'_>,
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
    /// framer to answer itself (`adopt`). Zeroised when it is let go (it holds credential lines),
    /// and every allocation it outgrew zeroised as it grew ([`extend_wiped`]). The header values the
    /// strip removes are views into hyper's own read buffer, which is hyper's, as in v1.5.5.
    raw: Option<Vec<u8>>,
    /// The listener's guest list, in match order.
    lines: Vec<Line>,
    /// The distinct auth handles the lines call at the peer point, in list order.
    peer_auths: Vec<AuthRef>,
    /// How many of them answered CONTINUE.
    peer_done: usize,
    /// A pending peer call's handle, `(ticket, seq)`.
    peer_parked: Option<(Ticket, u32)>,
    /// The last completion sequence number issued.
    seq: u32,
    /// The upstream's scheme the auth handle is shown (`SCHEME_*`, never `0`), as the host stated
    /// it for the connection ([`Accepted::with_scheme`]).
    scheme: u8,
    /// The host refused the whole connection: its bytes are written, and nothing more is framed.
    refused_whole: bool,
    /// The connection opened with the HTTP/2 preface: it is HTTP/2.
    h2: bool,
    /// Bytes owed to the far side that are not hyper's: a whole-connection refusal's.
    owed: VecDeque<u8>,
}

impl Drop for Accepted {
    fn drop(&mut self) {
        self.let_raw_go();
        // A body held for a `HeadBody` auth when the framing is torn down mid-hold (Q128 r232).
        if let Ok(mut sh) = self.shared.lock() {
            for a in sh.streams.values_mut() {
                let_held_go(&mut a.held);
            }
        }
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
            no_hand_over: false,
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
            scheme: SCHEME_PLAIN,
            refused_whole: false,
            h2: false,
            owed: VecDeque::new(),
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
        let h2 = self.raw.as_mut().is_some_and(|raw| {
            extend_wiped(raw, bytes);
            raw.starts_with(H2_PREFACE)
        });
        // An HTTP/2 connection is never handed over (`detach`): it keeps no copy (Q128 reader A
        // finding 1).
        if h2 {
            self.h2 = true;
            self.let_raw_go();
        }
        self.io.ingest(bytes, end);
    }

    /// Bound the copy kept for a hand-over as sent (Q128 reader A finding 1; THE DESIGN §1
    /// l.199-201, a bound on live work is a refusal at admission): it goes once a request asking no
    /// upgrade, or one carrying a body, was decoded (no hand-over as sent is possible after it),
    /// and past the head limit hyper reads a head under (`engine::HEAD_MAX_BYTES`, all an upgrade
    /// request and what follows it may hold before it is answered) it goes too: the connection is
    /// served on, as v1.5.5's server served it (Q128 reader B finding 2).
    fn bound_raw(&mut self) {
        if std::mem::take(&mut self.shared.lock().expect("shared").no_hand_over) {
            self.let_raw_go();
        }
        if self.raw.as_ref().is_some_and(|r| r.len() > HEAD_MAX_BYTES) {
            self.let_raw_go();
        }
    }

    /// THE SCHEME the auth handle is shown for this connection's requests (`HeadView::scheme`,
    /// `SCHEME_PLAIN` or `SCHEME_SECURE`; `SCHEME_UNDECLARED` is refused off the peer point): the
    /// one the host states for the accepted connection (`door::Begin`).
    #[must_use]
    pub const fn with_scheme(mut self, scheme: u8) -> Self {
        self.scheme = scheme;
        self
    }

    /// CANCEL of the op on `ticket`: every `auth.call` parked on it is let go (a later op calls
    /// afresh, under a new handle), and `true` when there was one (the op's bytes were taken: the
    /// cancel is partial).
    pub fn cancel(&mut self, ticket: Ticket) -> bool {
        let mut any = false;
        if self.peer_parked.is_some_and(|(t, _)| t == ticket) {
            self.peer_parked = None;
            any = true;
        }
        for a in self.shared.lock().expect("shared").streams.values_mut() {
            if a.parked.is_some_and(|(t, _)| t == ticket) {
                a.parked = None;
                any = true;
            }
        }
        any
    }

    /// Whether the host refused the whole connection.
    #[must_use]
    pub const fn refused_whole(&self) -> bool {
        self.refused_whole
    }

    /// THE HOST'S REFUSAL (`refuse`, the transport ABI's `RefuseIn`; Q128 reader B finding 2,
    /// ruling 22):
    ///
    /// * for the WHOLE connection (`stream` `None`): `bytes` are the transport's whole envelope, as
    ///   the host rendered it (the connector's `unit0_refusal`), written as they are; hyper is let
    ///   go and the connection is over;
    /// * for a stream whose answer head has not gone, with a neutral `status`: `bytes` are its
    ///   answer's body, at `status` (`100..=599`, else `500`, the status v1.5.5's server gave a
    ///   handler's failure), its length stated, as v1.5.5's server answered a handler's error
    ///   response;
    /// * for such a stream with NO neutral status (`0`, "none stated": the connector's
    ///   `unit0_refusal`, whose bytes are the transport's whole envelope, D3): the host framed the
    ///   refusal whole, its status line and fields included, so `bytes` are written as they are and
    ///   the connection is over, as for the whole connection. An HTTP/2 connection carries no such
    ///   envelope on a stream: refused;
    /// * for a stream whose head went (`head_sent`): the answer ends failed (HTTP/1.1 closes the
    ///   connection with no terminating chunk, HTTP/2 resets the stream); `bytes` are not written.
    ///
    /// A re-call after `YIELD_MORE` carries no bytes and only drains what the first owed.
    ///
    /// # Errors
    ///
    /// No request the host was handed on `stream`, or one whose answer already went.
    pub fn refuse(
        &mut self,
        stream: Option<u64>,
        bytes: &[u8],
        status: u32,
        head_sent: bool,
    ) -> Result<(), Failure> {
        let Some(stream) = stream else {
            if !self.refused_whole {
                self.refused_whole = true;
                self.conn = None;
                self.ended = true;
                self.let_raw_go();
                self.owed.extend(bytes);
            }
            return Ok(());
        };
        // The re-call of a stream's whole envelope (below) after `YIELD_MORE` only drains it.
        if self.refused_whole && bytes.is_empty() {
            return Ok(());
        }
        let mut sh = self.shared.lock().expect("shared");
        let Some(a) = sh.streams.get_mut(&stream).filter(|a| a.up) else {
            return Err(Failure(format!("refuse: no request on stream {stream}")));
        };
        if head_sent {
            let Some(q) = a.reply.as_ref() else {
                return Err(Failure(format!("refuse: stream {stream} sent no head")));
            };
            let mut q = q.lock().expect("reply");
            // The answer ends failed and nothing more is owed on it: its record goes once hyper
            // let it go (Q128 reader A: the same release as a stream the far side gave up).
            q.broken = true;
            q.ended = true;
            q.chunks.clear();
            q.queued = 0;
            if let Some(w) = q.waker.take() {
                w.wake();
            }
            drop(q);
            a.told = true;
            return Ok(());
        }
        if a.respond.is_none() {
            // The re-call of a refusal already framed carries nothing new.
            if bytes.is_empty() && a.gate == Gate::Refused {
                return Ok(());
            }
            return Err(Failure(format!(
                "refuse: stream {stream}'s answer already went"
            )));
        }
        if status == 0 {
            // THE HOST'S WHOLE ENVELOPE (D3, row 192 ruling: `RefuseIn` carries bytes by design, and
            // the host frames the refusal, its fields included, before it calls `refuse`): written
            // byte for byte, nothing of this door's added; hyper is let go and the connection is
            // over. HTTP/2 frames every answer itself, so an HTTP/1.1 envelope has no place on one
            // of its streams.
            if self.h2 {
                return Err(Failure(format!(
                    "refuse: stream {stream}: an HTTP/1.1 envelope on an HTTP/2 connection"
                )));
            }
            a.respond = None;
            a.gate = Gate::Refused;
            a.told = true;
            drop(sh);
            self.refused_whole = true;
            self.conn = None;
            self.ended = true;
            self.let_raw_go();
            self.owed.extend(bytes);
            return Ok(());
        }
        let status = u16::try_from(status)
            .ok()
            .filter(|s| (100..=599).contains(s))
            .unwrap_or(500);
        let framed = frame_refusal(
            a,
            RefusalCopy {
                status,
                fields: Vec::new(),
                body: bytes.to_vec(),
            },
        );
        if !framed {
            return Err(Failure(format!("refuse: {status} is no answer")));
        }
        let_unread_body_go(a);
        a.gate = Gate::Refused;
        drop(sh);
        self.let_raw_go();
        Ok(())
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
            if end {
                let_unread_body_go(a);
            }
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
        let full = q.full;
        drop(q);
        if end {
            let_unread_body_go(a);
        }
        Ok(full)
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
                    a.told = true;
                }
                sh.out.push_back(Piece::failure(
                    s,
                    "the connection ended before the request was whole",
                ));
            }
        }
        // A stream the far side gave up (Q128 reader A, MEDIUM: an HTTP/2 reset, or the request
        // dropped before or during its answer): the host is told it ended, once (its failure
        // piece, which also ends any hold on a full stream), and the stream is over on both sides,
        // its queued answer let go, so its record goes below and a later emit on it is refused.
        let abandoned: Vec<u64> = sh
            .streams
            .iter()
            .filter(|(_, a)| given_up(a))
            .map(|(s, _)| *s)
            .collect();
        for s in abandoned {
            let Some(a) = sh.streams.get_mut(&s) else {
                continue;
            };
            let tell = a.up && !a.told;
            a.told = true;
            a.respond = None;
            a.body = None;
            a.asked = true;
            if let Some(q) = a.reply.as_ref() {
                let mut q = q.lock().expect("reply");
                q.chunks.clear();
                q.queued = 0;
                q.ended = true;
            }
            if !matches!(a.gate, Gate::Admitted | Gate::Refused) {
                a.gate = Gate::Failed;
            }
            let_held_go(&mut a.held);
            if tell {
                sh.out
                    .push_back(Piece::failure(s, "the far side gave the stream up"));
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
        let gone: Vec<u64> = sh
            .streams
            .iter()
            .filter(|(_, a)| finished(a))
            .map(|(s, _)| *s)
            .collect();
        for s in gone {
            if let Some(mut a) = sh.streams.remove(&s) {
                let_held_go(&mut a.held);
            }
        }
        let pieces: Vec<Piece> = sh.out.drain(..).collect();
        drop(sh);
        self.out.extend(pieces);
        self.bound_raw();
    }

    /// DETACH the connection for the upgrade framer to adopt, two ways:
    ///
    /// * a connection NOTHING ANSWERED yet goes AS SENT, its upgrade request first, for a framer
    ///   that answers the upgrade itself (its `adopt` takes the request it answers). An HTTP/2
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
        let mut wire = self.io.take_wire(cap);
        let room = cap.saturating_sub(wire.len()).min(self.owed.len());
        wire.extend(self.owed.drain(..room));
        wire
    }
    fn wire_pending(&self) -> bool {
        self.io.wire_pending() || !self.owed.is_empty()
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
    let asks_upgrade = req.headers().contains_key(http::header::UPGRADE);
    let upgrade = asks_upgrade.then(|| hyper::upgrade::on(&mut req));
    let (parts, body) = req.into_parts();
    let bodiless = body.is_end_stream();
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
                told: false,
            },
        );
        s.waiting.push(id);
        // The copy holds an upgrade request's HEAD only (Q128 reader B finding 2): a request that
        // asks no upgrade, or one that carries a body, ends any hand-over as sent.
        if !asks_upgrade || !bodiless {
            s.no_hand_over = true;
        }
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
                    a.told = true;
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
                    extend_wiped(&mut a.held, &d);
                }
                if a.held.len() as u64 > limit {
                    let_held_go(&mut a.held);
                    a.held_over = true;
                    a.body = None;
                    return;
                }
            }
            // A body the far side broke off is no request to judge: the stream is left to hyper.
            Poll::Ready(Some(Err(_))) => {
                let_held_go(&mut a.held);
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
    scheme: u8,
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
        scheme,
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
            // A peer call parked on another op's ticket is that op's to resume: no request is
            // admitted before the peer point decides (item 7).
            let seq = match self.peer_parked {
                Some((t, seq)) if t == k.ticket() => seq,
                Some(_) => return did,
                None => self.next_seq(),
            };
            self.peer_parked = None;
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
                    self.peer_parked = Some((k.ticket(), seq));
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
            // A request parked on this op's ticket parks only its own stream (THE DESIGN §6 item
            // 7, l.975-976; Q128 r231): every other waiting request is still matched, called and
            // handed in here, each under its own completion sequence. The op then answers PENDING
            // and yields nothing (the transport contract), so what the others produced goes to the
            // host with the op's resume or the next op on another ticket.
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
                            return self.kernel_refuse(id, a, REFUSE_NO_ROUTE, LINE_NONE, k, did);
                        }
                        Matched::MethodMiss(n) => {
                            let line = self.lines[n].line;
                            return self.kernel_refuse(id, a, REFUSE_METHOD_MISS, line, k, did);
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
                        return self.kernel_refuse(id, a, REFUSE_OVER_GATE, line, k, did);
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
                    // A call parked on another op's ticket is re-issued only on that ticket's
                    // resume, never under another (busbar e858ecc: a pending answer parks only its
                    // own stream).
                    let seq = match a.parked {
                        Some((t, seq)) if t == k.ticket() => seq,
                        Some(_) => return,
                        None => self.next_seq(),
                    };
                    a.parked = None;
                    let fields = field_lines(parts);
                    let view = head_view(parts, &fields, self.scheme);
                    let (point, body) = if body_point {
                        (POINT_HEAD_BODY, Some(a.held.as_slice()))
                    } else {
                        (POINT_HEAD, None)
                    };
                    let answered = k.auth_call(seq, auth, a.unit, point, id, &view, body);
                    drop(fields);
                    match answered {
                        Poll::Pending => {
                            a.parked = Some((k.ticket(), seq));
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
                                return self.kernel_refuse(id, a, REFUSE_STOPPED, line, k, did);
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
                    let view = head_view(parts, &fields, self.scheme);
                    let handed = k.hand_in(seq, auth, a.unit, line, id, &view);
                    drop(fields);
                    match handed {
                        Ok((flow, unit)) => {
                            a.unit = unit;
                            if flow != FLOW_CONTINUE {
                                return self.kernel_refuse(
                                    id,
                                    a,
                                    REFUSE_CHECK_FAILED,
                                    line,
                                    k,
                                    did,
                                );
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
    fn kernel_refuse(
        &mut self,
        id: u64,
        a: &mut Answer,
        cause: u32,
        line: u32,
        k: &mut dyn Kernel,
        did: &mut Admitted,
    ) {
        let seq = self.next_seq();
        let_held_go(&mut a.held);
        // A request with no line has no unit (l.947: "A request that matches no line has no unit").
        let unit = if line == LINE_NONE {
            UnitRef::NONE
        } else {
            a.unit
        };
        // The request being refused, as decoded (busbar step 2, `UnitRefuseIn::request`), with the
        // connection's scheme: for every cause, the no-route one included.
        let fields = a.parts.as_ref().map(field_lines).unwrap_or_default();
        let view = a.parts.as_ref().map_or_else(HeadViewArgs::default, |p| {
            head_view(p, &fields, self.scheme)
        });
        let answered = k.refuse(seq, unit, cause, line, id, &view);
        drop(fields);
        let framed = answered.is_ok_and(|r| frame_refusal(a, r));
        if !framed {
            return fail(a, did);
        }
        a.gate = Gate::Refused;
        a.parts = None;
        a.body = None;
        did.moved = true;
    }
}

/// Append `bytes` to `buf`, a buffer of the transport's own that may hold credential bytes: when
/// they do not fit, the bytes move to a new allocation and the one outgrown is zeroised before it
/// is freed, so no copy is freed unzeroised (Q128 reader B r212).
fn extend_wiped(buf: &mut Vec<u8>, bytes: &[u8]) {
    if buf.capacity() - buf.len() < bytes.len() {
        let want = (buf.len() + bytes.len()).max(buf.capacity().saturating_mul(2));
        let mut grown = Vec::with_capacity(want);
        grown.extend_from_slice(buf);
        buf.zeroize();
        *buf = grown;
    }
    buf.extend_from_slice(bytes);
}

/// THE REQUEST BODY AN ANSWER ENDED BEFORE (row 192): once the host's answer on `a`'s stream is
/// whole and its request body has not all arrived (the over-cap case: the host answers `413` while
/// the body is still coming), the body is let go unread, as 1.5.5's server let it go (axum's body
/// limit answered, and the handler dropped the request). hyper then ends the stream as it did then:
/// on HTTP/1.1 it closes the connection once the answer is written (it keeps no connection alive
/// past an unread body); on HTTP/2 the answer goes out whole and h2 resets the stream `NO_ERROR`
/// (RFC 9113 §8.1: a server done with a request it did not read whole asks the client to stop
/// sending it), the connection kept. The request side is over: no later body byte goes up.
fn let_unread_body_go(a: &mut Answer) {
    if a.asked {
        return;
    }
    if a.body.take().is_some() {
        a.asked = true;
        a.told = true;
    }
}

/// Let a held body go: zeroised, and its allocation freed, not kept for a record that may outlive
/// it (Q128 reader B finding 1).
fn let_held_go(held: &mut Vec<u8>) {
    held.zeroize();
    *held = Vec::new();
}

/// Whether request `a` is over on both sides and its record can go (Q128 reader B finding 1; THE
/// DESIGN §1 l.199-203, retention bounds only settled handles): its request side is done (refused,
/// failed, or admitted and whole) and its answer is done (no head owed, and any body hyper still
/// had to take taken). A request that asked to upgrade is kept while its answer is owed or it
/// switched, for `detach`. What stays is therefore what hyper itself holds live, bounded as
/// v1.5.5's server bounded it: one request at a time on HTTP/1.1, and hyper's HTTP/2 concurrent
/// stream limit (hyper 1.11.1 `proto/h2/server.rs`:69, `max_concurrent_streams: Some(200)`, which
/// v1.5.5's builder left as is, `crates/busbar/src/tls.rs`:559-566); past it hyper refuses the
/// stream itself.
fn finished(a: &Answer) -> bool {
    let request_done = match a.gate {
        Gate::Refused | Gate::Failed => true,
        Gate::Admitted => a.body.is_none(),
        _ => false,
    };
    let answer_done = a.respond.is_none()
        && a.reply.as_ref().is_none_or(|q| {
            let q = q.lock().expect("reply");
            q.ended && q.chunks.is_empty()
        });
    request_done && answer_done && !a.switched
}

/// Whether the far side gave request `a`'s stream up while something was still owed on it: the
/// answer's head was never taken (hyper dropped the service's receiver), or hyper let the answer's
/// body go before it was whole. A stream the host refused after its head is the host's own end.
fn given_up(a: &Answer) -> bool {
    let before_head = a
        .respond
        .as_ref()
        .is_some_and(futures_channel::oneshot::Sender::is_canceled);
    let mid_answer = a.reply.as_ref().is_some_and(|q| {
        let q = q.lock().expect("reply");
        q.gone && !q.broken && !(q.ended && q.chunks.is_empty())
    });
    !a.switched && (before_head || mid_answer)
}

/// Leave request `a` unanswered: its answer's sender dropped, hyper ends the stream (HTTP/2) or
/// the connection (HTTP/1.1) with no bytes of this transport's own.
fn fail(a: &mut Answer, did: &mut Admitted) {
    a.respond = None;
    a.parts = None;
    a.body = None;
    let_held_go(&mut a.held);
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
        let_held_go(&mut a.held);
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
