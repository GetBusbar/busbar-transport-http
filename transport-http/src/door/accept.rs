// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ACCEPTED SIDE: hyper's server, run as a sans-IO framer over a connection the connector

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use busbar_contract::abi::auth::{POINT_HEAD, POINT_HEAD_BODY, POINT_PEER};
use busbar_contract::abi::host::service::{
    AuthRef, UnitRef, FLOW_CONTINUE, LINE_NONE, REFUSE_CHECK_FAILED, REFUSE_METHOD_MISS,
    REFUSE_NO_ROUTE, REFUSE_OVER_GATE, REFUSE_STOPPED, SCHEME_PLAIN,
};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::services::{HeadViewArgs, Pend, Place, RefusalCopy, ServiceError};
use busbar_contract::abi::sdk::transport::policy::Loans;
use busbar_contract::abi::transport::fields;
use busbar_contract::abi::transport::guest_policy::Policy;
use bytes::Bytes;
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper_util::server::conn::auto;
use zeroize::Zeroize;

use super::engine::{extend_wiped, Failure, Tasks, HEAD_MAX_BYTES};
use super::guest::{self, Line, Matched};
use super::hyper_io::{HeadWords, HostIo, HostTimer, Owed, Piece};

/// v1.5.5's HTTP/1 header-read bound (`hardened_conn_builder`).
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// THE ACCEPTED SIDE'S TIME BOUNDS, on the host's clock: the bounds v1.5.5's data listener (busbar

pub const IDLE_TIMEOUT: Duration = HEADER_READ_TIMEOUT;
/// An idle connection is first asked to close gracefully (HTTP/2: GOAWAY); one that has not closed

pub const CLOSE_GRACE: Duration = Duration::from_secs(10);
/// A request body the framing reads (carried up, or held for a `HeadBody` auth) that delivers

pub const BODY_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Past this grace, a request body below [`MIN_BODY_BYTES_PER_SEC`] fails (v1.5.5's throughput

pub const BODY_THROUGHPUT_GRACE: Duration = Duration::from_secs(10);
/// The throughput floor a request body keeps past its grace.
pub const MIN_BODY_BYTES_PER_SEC: u64 = 1024;

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

/// hyper's served connection, which can be asked to close gracefully.
trait Served: Future<Output = ConnResult> + Send + Unpin {
    /// Start a graceful close (hyper-util's `graceful_shutdown`: before the protocol is read, it

    fn shut(&mut self);
}

/// A served connection `C` and how to close it gracefully.
struct Conn<C> {
    c: Pin<Box<C>>,
    shut: fn(Pin<&mut C>),
}

impl<C: Future<Output = ConnResult> + Send> Future for Conn<C> {
    type Output = ConnResult;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<ConnResult> {
        self.get_mut().c.as_mut().poll(cx)
    }
}

impl<C: Future<Output = ConnResult> + Send> Served for Conn<C> {
    fn shut(&mut self) {
        (self.shut)(self.c.as_mut());
    }
}

/// A sleep on the host's clock, and the host time it ends at.
type Deadline = (u64, Pin<Box<dyn hyper::rt::Sleep>>);

/// The host time `d` after `now`.
fn after(now: u64, d: Duration) -> u64 {
    now.saturating_add(u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

/// The clock on one request body the framing reads, from its first poll.
struct BodyClock {
    started: u64,
    last: u64,
    bytes: u64,
    /// The inter-frame bound's wake-up, re-armed on every data frame.
    _wake: Pin<Box<dyn hyper::rt::Sleep>>,
}

/// What a request body's bounds are judged against in one round.
struct Bounds<'a> {
    now: u64,
    timer: &'a HostTimer,
    /// The total a body may take: the body cap read at the throughput floor.
    total_ns: u64,
}

impl Bounds<'_> {
    fn wake(&self) -> Pin<Box<dyn hyper::rt::Sleep>> {
        self.timer
            .sleep_until_ns(after(self.now, BODY_READ_TIMEOUT))
    }

    /// `a`'s body was polled: `got` data bytes arrived (`None`: nothing yet). The bound it broke.
    fn polled(&self, a: &mut Answer, got: Option<usize>) -> Option<&'static str> {
        let c = a.clock.get_or_insert_with(|| BodyClock {
            started: self.now,
            last: self.now,
            bytes: 0,
            _wake: self.wake(),
        });
        if let Some(n) = got {
            c.bytes = c.bytes.saturating_add(n as u64);
            c.last = self.now;
            c._wake = self.wake();
        }
        let elapsed = self.now.saturating_sub(c.started);
        if elapsed > self.total_ns {
            return Some("the request body passed its total read deadline");
        }
        let grace = after(0, BODY_THROUGHPUT_GRACE);
        if elapsed > grace
            && c.bytes < MIN_BODY_BYTES_PER_SEC.saturating_mul(elapsed / 1_000_000_000)
        {
            return Some("the request body fell below the minimum throughput floor");
        }
        if got.is_none() && self.now.saturating_sub(c.last) >= after(0, BODY_READ_TIMEOUT) {
            return Some("the request body read timed out");
        }
        None
    }
}

/// One answer body's queue: what the host emitted and hyper has not taken.
#[derive(Default)]
struct ReplyQ {
    chunks: VecDeque<Bytes>,
    /// Final fields follow every queued data frame and precede the body's end.
    trailers: Option<http::HeaderMap>,
    /// HTTP/1 only writes names declared in the initial Trailer field.
    trailer_names: Option<HashSet<http::HeaderName>>,
    trailers_supported: bool,
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

struct Reply(Arc<Mutex<ReplyQ>>, Option<u64>);

/// hyper lets an answer's body go when it is whole, and when the far side gives its stream up

impl Drop for Reply {
    fn drop(&mut self) {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).gone = true;
    }
}

impl Body for Reply {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        let mut q = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if q.broken {
            return Poll::Ready(Some(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "the host refused the stream after its head",
            ))));
        }
        if let Some(c) = q.chunks.pop_front() {
            q.queued -= c.len();
            return Poll::Ready(Some(Ok(Frame::data(c))));
        }
        if let Some(trailers) = q.trailers.take() {
            return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
        }
        if q.ended {
            return Poll::Ready(None);
        }
        q.waker = Some(cx.waker().clone());
        Poll::Pending
    }

    fn is_end_stream(&self) -> bool {
        let q = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        q.ended && q.chunks.is_empty() && q.trailers.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        self.1.map_or_else(SizeHint::default, SizeHint::with_exact)
    }
}

/// An immutable stream loan and its once-decoded local route rows.
struct StreamPolicy {
    loan: Arc<Policy>,
    lines: Arc<[Line]>,
}

/// One request's answer side.
struct Answer {
    /// Hyper's HTTP/1 trailer negotiation is fixed by the original request, before auth strips.
    h1: bool,
    trailer_peer: bool,
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
    policy: Option<Arc<StreamPolicy>>,
    loan_ticket: Option<Ticket>,
    opened_on: Option<Ticket>,
    /// The body held for a `HeadBody` auth; zeroised once handed on, and every allocation it
    held: Vec<u8>,
    /// The held body is whole.
    held_whole: bool,
    /// The held body passed its line's `body_limit`.
    held_over: bool,
    /// The clock on the body this framing reads ([`Bounds`]).
    clock: Option<BodyClock>,
    /// The request's unit, as the kernel answered it.
    unit: UnitRef,
    /// A pending `auth.call`'s handle, `(ticket, seq)`: re-issued only on that ticket's resume.
    parked: Option<(Ticket, u32)>,
    /// The head went up to the host.
    up: bool,
    /// The host was told the stream ended (its failure piece went), or ended it itself.
    told: bool,
}

/// Where a request stands on its way through the guest list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Gate {
    /// Decoded, not yet matched.
    Arrived,
    /// The selected generation's matched auth has not completed its connection point.
    Peer(usize),
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

fn request_gate(points: u32, line: usize) -> Gate {
    if points & POINT_HEAD_BODY != 0 {
        Gate::Hold(line)
    } else if points & POINT_HEAD != 0 {
        Gate::Auth(line)
    } else {
        Gate::HandIn(line)
    }
}

/// What the service and the framing share.
struct Shared {
    out: VecDeque<Piece>,
    next: u64,
    streams: HashMap<u64, Answer>,
    /// The streams not yet through the guest list, in arrival order.
    waiting: Vec<u64>,
    /// A request asking no upgrade was decoded: the connection can no longer be handed over as
    no_hand_over: bool,
}

/// What an inbound `auth.call` answers the accepted side: the flow (`FLOW_*`), the request's unit,

pub type AuthCalled = (u32, UnitRef, Vec<(String, Place)>);

/// THE HOST AUTH HANDLE as the accepted side calls it (`abi::host::service`, `op::AUTH_CALL`,

pub trait Kernel {
    /// The ticket of the op the calls are made on; a call that pends is parked on it.

    fn ticket(&self) -> Ticket;

    /// Select a stream's immutable host policy before matching or reading its body.

    fn open_policy(
        &mut self,
        _loans: &mut Loans,
        _stream: u64,
    ) -> Result<Option<Arc<Policy>>, ServiceError> {
        Err(ServiceError::Unserved)
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
    /// The operation issued an empty `guest.open` yield.
    pub policy_requested: bool,
    /// A malformed policy reply cannot silently discard a host-granted stream.
    pub policy_failed: bool,
    /// Flush current progress before opening another waiting stream.
    pub more: bool,
}

/// One accepted connection's HTTP machine.
pub struct Accepted {
    io: HostIo,
    /// hyper's executor (`engine::Tasks`): held weakly by the tasks hyper spawns on it.
    tasks: Tasks,
    conn: Option<Pin<Box<dyn Served>>>,
    /// The idle period's end ([`IDLE_TIMEOUT`]), while no request is in flight, from the
    idle: Option<Deadline>,
    /// The far side has sent bytes.
    heard: bool,
    /// A graceful close's end ([`CLOSE_GRACE`]), once asked for.
    closing: Option<Deadline>,
    /// The total a request body may take ([`Bounds::total_ns`]); see [`Accepted::with_body_max`].
    body_total_ns: u64,
    /// Why hyper ended the connection, when it ended in an error (its own text: a header-read
    ended_by: Option<String>,
    shared: Arc<Mutex<Shared>>,
    out: VecDeque<Piece>,
    ended: bool,
    /// What the far side sent after a switched request, waiting for `detach`.
    leftover: Option<VecDeque<u8>>,
    /// Every byte the far side sent, kept until the connection's first answer: a connection
    raw: Option<Vec<u8>>,
    /// The listener's guest list, in match order.
    lines: Arc<[Line]>,
    loans: Option<Loans>,
    /// Operations whose original input was consumed before a policy roundtrip.
    policy_input: HashSet<Ticket>,
    last_policy: Option<Arc<StreamPolicy>>,
    /// Heads handed in but not yet completely copied to a READY answer.
    publishing: Vec<u64>,
    /// Unpublished stream custody held by active operations, absent on ordinary body chunks.
    claimed: Vec<(Ticket, u64)>,
    /// The distinct auth handles the lines call at the peer point, in list order.
    peer_auths: Vec<AuthRef>,
    /// How many of them answered CONTINUE.
    peer_done: usize,
    /// A pending peer call's handle, `(ticket, seq)`.
    peer_parked: Option<(Ticket, u32)>,
    /// Successful connection verdicts are reusable only for the exact sealed auth handle.
    checked_peers: Vec<AuthRef>,
    /// A generation's pending connection verdict belongs to one stream and operation.
    policy_peer_parked: Vec<(AuthRef, Ticket, u32, u64)>,
    /// The last completion sequence number issued.
    seq: u32,
    /// The upstream's scheme the auth handle is shown (`SCHEME_*`, never `0`), as the host stated
    scheme: u8,
    /// The host refused the whole connection: its bytes are written, and nothing more is framed.
    refused_whole: bool,
    /// The connection opened with the HTTP/2 preface: it is HTTP/2.
    h2: bool,
    /// The protocol the secure layer's handshake agreed (ALPN), as its position in the accepting
    alpn: u32,
    /// The protocol hyper serves, as its position in the accepting offer, once the connection's
    spoken: Option<u32>,
    /// The first bytes, held only until they show whether they open the HTTP/2 preface.
    lead: Vec<u8>,
    /// Bytes owed to the far side that are not hyper's: a whole-connection refusal's.
    owed: VecDeque<u8>,
}

impl Drop for Accepted {
    fn drop(&mut self) {
        self.let_raw_go();
        if let Some(rest) = self.leftover.as_mut() {
            rest.resize(rest.capacity(), 0);
            let (front, back) = rest.as_mut_slices();
            front.zeroize();
            back.zeroize();
        }

        if let Ok(mut sh) = self.shared.lock() {
            for a in sh.streams.values_mut() {
                let_held_go(&mut a.held);
            }
        }
    }
}

impl Accepted {
    /// Use host-selected per-stream policies when the initial Begin advertised them.
    #[must_use]
    pub fn with_policies(mut self, loans: Option<Loans>) -> Self {
        self.loans = loans;
        self
    }

    /// Serve an accepted connection at host time `now_ns`, under guest list `lines`.
    #[must_use]
    pub fn accept(now_ns: u64, lines: impl Into<Arc<[Line]>>) -> Self {
        let lines = lines.into();
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
        let tasks = Tasks::default();
        let mut builder = auto::Builder::new(tasks.spawner());
        builder
            .http1()
            .timer(io.timer())
            .header_read_timeout(HEADER_READ_TIMEOUT);
        let conn = builder
            .serve_connection_with_upgrades(io.stream(), service)
            .into_owned();
        let conn: Pin<Box<dyn Served>> = Box::pin(Conn {
            c: Box::pin(conn),
            shut: |c| c.graceful_shutdown(),
        });
        Self {
            io,
            tasks,
            conn: Some(conn),
            idle: None,
            heard: false,
            closing: None,
            body_total_ns: u64::MAX,
            ended_by: None,
            shared,
            out: VecDeque::new(),
            ended: false,
            leftover: None,
            raw: Some(Vec::new()),
            lines,
            loans: None,
            policy_input: HashSet::new(),
            last_policy: None,
            publishing: Vec::new(),
            claimed: Vec::new(),
            peer_auths,
            peer_done: 0,
            peer_parked: None,
            checked_peers: Vec::new(),
            policy_peer_parked: Vec::new(),
            seq: 0,
            scheme: SCHEME_PLAIN,
            refused_whole: false,
            h2: false,
            alpn: 0,
            spoken: None,
            lead: Vec::new(),
            owed: VecDeque::new(),
        }
    }

    /// The largest request body (`limits.request_body_max_bytes`): a body read at the throughput

    #[must_use]
    pub fn with_body_max(mut self, max: usize) -> Self {
        let secs = (max as u64) / MIN_BODY_BYTES_PER_SEC;
        self.body_total_ns = secs.saturating_mul(1_000_000_000);
        self
    }

    /// The idle bound, at the start of a drive at host time `now`: a graceful close once the idle

    fn close_when_idle(&mut self, now: u64) {
        if self.closing.as_ref().is_some_and(|(at, _)| *at <= now) {
            self.closing = None;
            if self.conn.take().is_some() {
                self.ended = true;
            }
        }
        if self.idle.as_ref().is_some_and(|(at, _)| *at <= now) {
            self.idle = None;
            if self.wire_pending() {
                return;
            }
            if let Some(c) = self.conn.as_mut() {
                c.shut();
                let at = after(now, CLOSE_GRACE);
                self.closing = Some((at, self.io.timer().sleep_until_ns(at)));
            }
        }
    }

    /// The idle bound, at the end of a drive at host time `now`: its period starts (once) when no

    fn arm_idle(&mut self, now: u64) {
        if self.conn.is_none() {
            self.idle = None;
            self.closing = None;
            return;
        }
        if self.closing.is_some() || !self.heard {
            return;
        }
        if !self
            .shared
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .streams
            .is_empty()
        {
            self.idle = None;
        } else if self.idle.is_none() {
            let at = after(now, IDLE_TIMEOUT);
            self.idle = Some((at, self.io.timer().sleep_until_ns(at)));
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

    /// THE PROTOCOL THE SECURE LAYER AGREED (`ConnFacts::agreed_protocol`, the ALPN result), when

    #[must_use]
    pub fn with_alpn(mut self, protocol: &[u8]) -> Self {
        self.alpn = offer_position(protocol);
        self
    }

    /// THE PROTOCOL AGREED (`FramerYield::agreed`): its 1-based position in the

    #[must_use]
    pub fn agreed(&self) -> u32 {
        self.spoken.unwrap_or(self.alpn)
    }

    /// Read the connection's first bytes until they show whether they open the HTTP/2 preface,

    fn note_lead(&mut self, bytes: &[u8]) {
        if self.spoken.is_some() {
            return;
        }
        let room = H2_PREFACE.len() - self.lead.len();
        self.lead.extend_from_slice(&bytes[..bytes.len().min(room)]);
        let spoken = if self.lead.starts_with(H2_PREFACE) {
            b"h2".as_slice()
        } else if H2_PREFACE.starts_with(&self.lead) {
            return;
        } else {
            b"http/1.1".as_slice()
        };
        self.spoken = Some(offer_position(spoken));
        self.lead.zeroize();
        self.lead = Vec::new();
    }

    /// The far side sent `bytes` (`end` = and then ended).
    pub fn ingest(&mut self, bytes: &[u8], end: bool) {
        self.heard |= !bytes.is_empty();
        self.note_lead(bytes);
        let h2 = self.raw.as_mut().is_some_and(|raw| {
            extend_wiped(raw, bytes);
            raw.starts_with(H2_PREFACE)
        });

        if h2 {
            self.h2 = true;
            self.let_raw_go();
        }
        self.io.ingest(bytes, end);
    }

    /// Bound the copy kept for a hand-over as sent (a bound on live work is a refusal at

    fn bound_raw(&mut self) {
        if std::mem::take(
            &mut self
                .shared
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .no_hand_over,
        ) {
            self.let_raw_go();
        }
        if self.raw.as_ref().is_some_and(|r| r.len() > HEAD_MAX_BYTES) {
            self.let_raw_go();
        }
    }

    /// THE SCHEME the auth handle is shown for this connection's requests (`HeadView::scheme`,

    #[must_use]
    pub const fn with_scheme(mut self, scheme: u8) -> Self {
        self.scheme = scheme;
        self
    }

    /// The initial connection policy's peer checks completed without ending the connection.
    pub fn peer_ready(&self) -> bool {
        self.peer_done == self.peer_auths.len() && !self.ended
    }

    /// A policy roundtrip recalls the operation with its original input, already consumed.
    pub fn policy_pending(&self, ticket: Ticket) -> bool {
        self.policy_input.contains(&ticket)
    }

    /// CANCEL of the op on `ticket`: every `auth.call` parked on it is let go (a later op calls

    pub fn cancel(&mut self, ticket: Ticket) -> bool {
        let mut any = self.policy_input.remove(&ticket);
        self.policy_peer_parked.retain(|(_, owner, _, _)| {
            if *owner == ticket {
                any = true;
                false
            } else {
                true
            }
        });
        if let Some(loans) = &mut self.loans {
            any |= loans.cancel(ticket).is_some();
        }
        if self.peer_parked.is_some_and(|(t, _)| t == ticket) {
            self.peer_parked = None;
            any = true;
        }
        let mut sh = self.shared.lock().unwrap_or_else(PoisonError::into_inner);
        let mut aborted = Vec::new();
        for (id, a) in &mut sh.streams {
            if a.loan_ticket == Some(ticket) || a.opened_on == Some(ticket) {
                aborted.push((*id, a.up));
                a.loan_ticket = None;
                a.opened_on = None;
                a.policy = None;
                a.parts = None;
                a.body = None;
                a.respond = None;
                a.asked = true;
                a.gate = Gate::Failed;
                let_held_go(&mut a.held);
                any = true;
            }
            if a.parked.is_some_and(|(t, _)| t == ticket) {
                a.parked = None;
                any = true;
            }
        }
        if !aborted.is_empty() {
            let aborted_stream = |id: u64| aborted.iter().any(|(stream, _)| *stream == id);
            sh.out.retain(|piece| !aborted_stream(piece.stream));
            self.out.retain(|piece| !aborted_stream(piece.stream));
            self.publishing.retain(|stream| !aborted_stream(*stream));
            self.claimed.retain(|(_, stream)| !aborted_stream(*stream));
            for (id, up) in aborted {
                if up {
                    self.out
                        .push_back(Piece::failure(id, "the opening operation was cancelled"));
                }
            }
        }
        any
    }

    /// Whether the host refused the whole connection.
    #[must_use]
    pub const fn refused_whole(&self) -> bool {
        self.refused_whole
    }

    /// THE HOST'S REFUSAL (`refuse`, the transport ABI's `RefuseIn`):

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

        if self.refused_whole && bytes.is_empty() {
            return Ok(());
        }
        let mut sh = self.shared.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(a) = sh.streams.get_mut(&stream).filter(|a| a.up) else {
            return Err(Failure(format!("refuse: no request on stream {stream}")));
        };
        if head_sent {
            let Some(q) = a.reply.as_ref() else {
                return Err(Failure(format!("refuse: stream {stream} sent no head")));
            };
            let mut q = q.lock().unwrap_or_else(PoisonError::into_inner);

            q.broken = true;
            q.ended = true;
            q.chunks.clear();
            q.queued = 0;
            if let Some(w) = q.waker.take() {
                w.wake();
            }
            drop(q);
            let_unread_body_go(a);
            a.told = true;
            return Ok(());
        }
        if a.respond.is_none() {
            if bytes.is_empty() && a.gate == Gate::Refused {
                return Ok(());
            }
            return Err(Failure(format!(
                "refuse: stream {stream}'s answer already went"
            )));
        }
        if status == 0 {
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

    /// Whether `stream`'s answer queue is at its high-water mark (its emits held until a

    #[must_use]
    pub fn stream_full(&self, stream: u64) -> bool {
        self.shared
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .streams
            .get(&stream)
            .and_then(|a| a.reply.as_ref())
            .is_some_and(|q| q.lock().unwrap_or_else(PoisonError::into_inner).full)
    }

    /// Whether `stream`'s next emit carries its answer's head.
    #[must_use]
    pub fn answers_head(&self, stream: u64) -> bool {
        self.shared
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .streams
            .get(&stream)
            .is_some_and(|a| a.up && a.respond.is_some())
    }

    /// Bytes for `stream`'s answer: its head (a field block, with `status`) on the first emit,

    pub fn emit(
        &mut self,
        stream: u64,
        bytes: &[u8],
        end: bool,
        status: u32,
    ) -> Result<bool, Failure> {
        if bytes.is_empty() && !end && status == 0 {
            return Ok(self.stream_full(stream));
        }
        let mut sh = self.shared.lock().unwrap_or_else(PoisonError::into_inner);

        let Some(a) = sh.streams.get_mut(&stream).filter(|a| a.up) else {
            return Err(Failure(format!("emit: no request on stream {stream}")));
        };
        if a.respond.is_some() {
            let code = u16::try_from(status)
                .ok()
                .filter(|s| (100..=599).contains(s))
                .and_then(|s| http::StatusCode::from_u16(s).ok())
                .ok_or_else(|| Failure(format!("emit: {status} is not an HTTP status")))?;
            let mut b = http::Response::builder().status(code);

            let mut read = 0;
            for (name, value) in fields::lines(bytes) {
                read += name.len() + fields::SEPARATOR.len() + value.len() + fields::LINE_END.len();
                b = b.header(name, value);
            }
            if read != bytes.len() {
                return Err(Failure(
                    "emit: the head is not an answer: a field line is not `name: value` CRLF"
                        .into(),
                ));
            }
            let q = Arc::new(Mutex::new(ReplyQ {
                ended: end,
                ..ReplyQ::default()
            }));
            let resp = b
                .body(Reply(q.clone(), None))
                .map_err(|e| Failure(format!("emit: the head is not an answer: {e}")))?;
            {
                let mut queue = q.lock().unwrap_or_else(PoisonError::into_inner);
                queue.trailers_supported = a.trailer_peer
                    && !code.is_informational()
                    && code != http::StatusCode::NO_CONTENT
                    && code != http::StatusCode::NOT_MODIFIED
                    && (!a.h1 || !resp.headers().contains_key(http::header::CONTENT_LENGTH));
                if a.h1 {
                    queue.trailer_names = Some(
                        resp.headers()
                            .get_all(http::header::TRAILER)
                            .iter()
                            .filter_map(|value| value.to_str().ok())
                            .flat_map(|value| value.split(','))
                            .filter_map(|name| {
                                http::HeaderName::from_bytes(name.trim().as_bytes()).ok()
                            })
                            .collect(),
                    );
                }
            }
            let Some(respond) = a.respond.take() else {
                unreachable!("checked above, under the same lock")
            };

            if let Some(mut raw) = self.raw.take() {
                raw.zeroize();
            }
            a.switched = code.as_u16() == SWITCHING_PROTOCOLS && a.upgrade.is_some();
            a.reply = Some(q);

            let _ = respond.send(resp);
            if end {
                let_unread_body_go(a);
            }
            return Ok(false);
        }
        let Some(q) = a.reply.as_ref() else {
            return Err(Failure(format!("emit: stream {stream} has no answer")));
        };
        let mut q = q.lock().unwrap_or_else(PoisonError::into_inner);
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

    /// Accept one whole terminal field block. Validation precedes mutation, so a malformed or

    pub fn emit_trailers(&mut self, stream: u64, bytes: &[u8]) -> Result<bool, Failure> {
        let mut trailers = http::HeaderMap::new();
        let mut read = 0;
        for (name, value) in fields::lines(bytes) {
            read += name.len() + fields::SEPARATOR.len() + value.len() + fields::LINE_END.len();
            let name = http::HeaderName::from_bytes(name)
                .map_err(|_| Failure("emit: invalid trailer field name".into()))?;
            let value = http::HeaderValue::from_bytes(value)
                .map_err(|_| Failure("emit: invalid trailer field value".into()))?;
            if fields::hop_by_hop(name.as_str(), std::iter::empty::<&[u8]>()) {
                return Err(Failure("emit: field cannot be carried in trailers".into()));
            }
            trailers.append(name, value);
        }
        if read != bytes.len() {
            return Err(Failure("emit: malformed terminal field block".into()));
        }
        let mut shared = self.shared.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(answer) = shared.streams.get_mut(&stream).filter(|answer| answer.up) else {
            return Err(Failure(format!("emit: no request on stream {stream}")));
        };
        if answer.respond.is_some() {
            return Err(Failure("emit: trailers precede the answer head".into()));
        }

        if answer.h1
            && trailers.keys().any(|name| {
                matches!(
                    name.as_str(),
                    "authorization"
                        | "cache-control"
                        | "content-encoding"
                        | "content-length"
                        | "content-range"
                        | "content-type"
                        | "host"
                        | "max-forwards"
                        | "set-cookie"
                        | "trailer"
                        | "transfer-encoding"
                        | "te"
                )
            })
        {
            return Err(Failure(
                "emit: field cannot be carried in HTTP/1 trailers".into(),
            ));
        }
        let Some(queue) = answer.reply.as_ref() else {
            return Err(Failure("emit: stream has no answer".into()));
        };
        let mut queue = queue.lock().unwrap_or_else(PoisonError::into_inner);
        if queue.ended || queue.gone || queue.broken {
            return Err(Failure("emit: trailers follow an ended answer".into()));
        }
        if !trailers.is_empty()
            && (!queue.trailers_supported
                || queue.trailer_names.as_ref().is_some_and(|names| {
                    names.is_empty() || trailers.keys().any(|name| !names.contains(name))
                }))
        {
            return Err(Failure(
                "emit: trailers were not negotiated and declared for this answer".into(),
            ));
        }
        queue.trailers = (!trailers.is_empty()).then_some(trailers);
        queue.ended = true;
        let full = queue.full;
        let wake = queue.waker.take();
        drop(queue);
        let_unread_body_go(answer);
        drop(shared);
        if let Some(wake) = wake {
            wake.wake();
        }
        Ok(full)
    }

    /// Undelivered carrier input plus pieces still waiting for the host's sink. Call after

    pub fn retained_input(&self) -> usize {
        let shared = self.shared.lock().unwrap_or_else(PoisonError::into_inner);
        self.out
            .iter()
            .chain(&shared.out)
            .fold(self.io.pending_input(), |n, p| {
                n.saturating_add(p.bytes.len())
            })
    }

    /// Drive the connection at host time `now_ns` until nothing inside it has more to do.
    pub fn drive(&mut self, now_ns: u64) {
        self.io.set_time(now_ns);
        self.close_when_idle(now_ns);
        let io = self.io.clone();
        let timer = io.timer();
        let bounds = Bounds {
            now: now_ns,
            timer: &timer,
            total_ns: self.body_total_ns,
        };
        let conn = &mut self.conn;
        let ended = &mut self.ended;
        let ended_by = &mut self.ended_by;
        let shared = &self.shared;
        let lines = &self.lines;
        let tasks = &self.tasks;
        let _ = io.rounds(|cx| {
            tasks.run(cx);
            if let Some(c) = conn.as_mut() {
                if let Poll::Ready(r) = c.as_mut().poll(cx) {
                    if let Err(e) = r {
                        *ended_by = Some(e.to_string());
                    }
                    *conn = None;
                    *ended = true;
                }
            }
            carry_bodies(
                &mut shared.lock().unwrap_or_else(PoisonError::into_inner),
                lines,
                &bounds,
                cx,
            );
            Ok::<(), Failure>(())
        });
        let mut sh = self.shared.lock().unwrap_or_else(PoisonError::into_inner);
        if self.ended {
            let open: Vec<u64> = sh
                .streams
                .iter()
                .filter(|(_, a)| a.up && !a.asked && !a.told && !a.switched)
                .map(|(s, _)| *s)
                .collect();
            for s in open {
                if let Some(a) = sh.streams.get_mut(&s) {
                    a.asked = true;
                    a.told = true;
                }
                sh.out.push_back(Piece::failure(
                    s,
                    &with_cause(
                        "the connection ended before the request was whole",
                        self.ended_by.as_deref(),
                    ),
                ));
            }
        }

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
            let tell = (a.up || a.policy.is_some() || a.loan_ticket.is_some()) && !a.told;
            a.told = true;
            a.respond = None;
            a.body = None;
            a.asked = true;
            if let Some(q) = a.reply.as_ref() {
                let mut q = q.lock().unwrap_or_else(PoisonError::into_inner);
                q.chunks.clear();
                q.queued = 0;
                q.ended = true;
            }
            if !matches!(a.gate, Gate::Admitted | Gate::Refused) {
                a.gate = Gate::Failed;
            }
            let_held_go(&mut a.held);
            if tell {
                sh.out.push_back(Piece::failure(
                    s,
                    &with_cause("the far side gave the stream up", self.ended_by.as_deref()),
                ));
            }
        }
        let mut writable = Vec::new();
        for (s, a) in &sh.streams {
            if let Some(q) = &a.reply {
                let mut q = q.lock().unwrap_or_else(PoisonError::into_inner);
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
                if let (Some(loans), Some(ticket)) = (&mut self.loans, a.loan_ticket) {
                    loans.cancel(ticket);
                }
                self.policy_peer_parked
                    .retain(|(_, _, _, stream)| *stream != s);
                self.claimed.retain(|(_, stream)| *stream != s);
                self.publishing.retain(|stream| *stream != s);
                let_held_go(&mut a.held);
            }
        }
        let pieces: Vec<Piece> = sh.out.drain(..).collect();
        drop(sh);
        self.out.extend(pieces);
        self.bound_raw();
        self.arm_idle(now_ns);
    }

    /// DETACH the connection for the upgrade framer to adopt, two ways:

    pub fn detach(&mut self) -> Result<Option<&mut VecDeque<u8>>, Failure> {
        if self
            .raw
            .as_ref()
            .is_some_and(|raw| !raw.is_empty() && H2_PREFACE.starts_with(raw.as_slice()))
        {
            return Ok(None);
        }
        let switched = self
            .shared
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .streams
            .values()
            .any(|a| a.switched);
        if self.leftover.is_none() && !switched {
            if let Some(raw) = self.raw.take() {
                let mut raw = zeroize::Zeroizing::new(raw);
                #[cfg(test)]
                crate::wipe_probe::watch("detach leftover", &raw);
                if raw.starts_with(H2_PREFACE) {
                    return Ok(None);
                }

                self.conn = None;
                self.leftover = Some(std::mem::take(&mut *raw).into());
                self.ended = true;
            }
        }
        if self.leftover.is_none() {
            let owed = self
                .shared
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .streams
                .values()
                .any(|a| a.switched && a.upgrade.is_some());
            if !owed {
                return Ok(None);
            }
            let io = self.io.clone();
            let conn = &mut self.conn;
            let tasks = &self.tasks;
            let shared = &self.shared;
            let mut got = None;
            let _ = io.rounds(|cx| {
                tasks.run(cx);
                if let Some(c) = conn.as_mut() {
                    if c.as_mut().poll(cx).is_ready() {
                        *conn = None;
                    }
                }
                if got.is_none() {
                    let mut sh = shared.lock().unwrap_or_else(PoisonError::into_inner);
                    if let Some(a) = sh.streams.values_mut().find(|a| a.switched) {
                        if let Some(up) = a.upgrade.as_mut() {
                            if let Poll::Ready(r) = Pin::new(up).poll(cx) {
                                a.upgrade = None;
                                got = Some(r);
                            }
                        }
                    }
                }
                Ok::<(), Failure>(())
            });
            let Some(upgraded) = got else {
                return Err(Failure("detach: the switch has not completed".into()));
            };
            let mut upgraded =
                upgraded.map_err(|e| Failure(format!("detach: the switch failed: {e}")))?;

            let mut rest = zeroize::Zeroizing::new(Vec::new());
            let waker = Waker::noop();
            let mut cx = Context::from_waker(waker);
            let mut buf = zeroize::Zeroizing::new(vec![0_u8; 16 * 1024]);
            #[cfg(test)]
            crate::wipe_probe::watch("detach read", &buf);
            loop {
                let mut rb = hyper::rt::ReadBuf::new(&mut buf);
                match hyper::rt::Read::poll_read(Pin::new(&mut upgraded), &mut cx, rb.unfilled()) {
                    Poll::Ready(Ok(())) if !rb.filled().is_empty() => {
                        extend_wiped(&mut rest, rb.filled());
                        #[cfg(test)]
                        crate::wipe_probe::watch("detach leftover", &rest);
                    }
                    _ => break,
                }
            }
            self.leftover = Some(std::mem::take(&mut *rest).into());
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

fn serve(
    sh: Arc<Mutex<Shared>>,
    mut req: http::Request<Incoming>,
) -> BoxFut<Result<http::Response<Reply>, std::io::Error>> {
    let h1 = req.version() != http::Version::HTTP_2;
    let trailer_peer = req.method() != http::Method::HEAD
        && req.method() != http::Method::CONNECT
        && (!h1
            || (req.version() == http::Version::HTTP_11
                && req.headers().get_all(http::header::TE).iter().any(|value| {
                    value.to_str().is_ok_and(|line| {
                        line.split(',')
                            .any(|token| token.trim().eq_ignore_ascii_case("trailers"))
                    })
                })));
    let asks_upgrade = req.headers().contains_key(http::header::UPGRADE);
    let upgrade = asks_upgrade.then(|| hyper::upgrade::on(&mut req));
    let (parts, body) = req.into_parts();
    let bodiless = body.is_end_stream();
    let (tx, rx) = futures_channel::oneshot::channel();
    let stream = {
        let mut s = sh.lock().unwrap_or_else(PoisonError::into_inner);
        let id = s.next;
        s.next += 1;
        s.streams.insert(
            id,
            Answer {
                h1,
                trailer_peer,
                respond: Some(tx),
                reply: None,
                upgrade,
                switched: false,
                body: Some(body),
                asked: false,
                parts: Some(parts),
                gate: Gate::Arrived,
                policy: None,
                loan_ticket: None,
                opened_on: None,
                held: Vec::new(),
                held_whole: false,
                held_over: false,
                clock: None,
                unit: UnitRef::NONE,
                parked: None,
                up: false,
                told: false,
            },
        );
        s.waiting.push(id);

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

fn carry_bodies(sh: &mut Shared, lines: &[Line], bounds: &Bounds<'_>, cx: &mut Context<'_>) {
    let Shared { out, streams, .. } = sh;
    for (id, a) in streams.iter_mut() {
        if let Gate::Hold(n) = a.gate {
            let limit = a
                .policy
                .as_ref()
                .map_or_else(|| lines[n].body_limit, |p| p.lines[n].body_limit);
            hold_body(a, limit, bounds, cx);
            continue;
        }
        if a.gate != Gate::Admitted {
            continue;
        }
        while let Some(body) = a.body.as_mut() {
            let broke = match Pin::new(&mut *body).poll_frame(cx) {
                Poll::Pending => match bounds.polled(a, None) {
                    Some(why) => why.to_owned(),
                    None => break,
                },

                Poll::Ready(Some(Ok(f))) => {
                    let mut got = 0;
                    if let Ok(d) = f.into_data() {
                        got = d.len();
                        if !d.is_empty() {
                            out.push_back(Piece::data(*id, d));
                        }
                    }
                    match bounds.polled(a, Some(got)) {
                        Some(why) => why.to_owned(),
                        None => continue,
                    }
                }
                Poll::Ready(Some(Err(e))) => e.to_string(),
                Poll::Ready(None) => {
                    out.push_back(Piece::end(*id));
                    a.body = None;
                    a.clock = None;
                    a.asked = true;
                    break;
                }
            };
            out.push_back(Piece::failure(*id, &broke));
            a.body = None;
            a.clock = None;
            a.asked = true;
            a.told = true;
        }
    }
}

/// Hold a `HeadBody` request's body as it arrives, up to `limit` bytes (the size gate's limit; over

fn hold_body(a: &mut Answer, limit: u64, bounds: &Bounds<'_>, cx: &mut Context<'_>) {
    while let Some(body) = a.body.as_mut() {
        match Pin::new(&mut *body).poll_frame(cx) {
            Poll::Pending => {
                if bounds.polled(a, None).is_none() {
                    return;
                }
            }
            Poll::Ready(Some(Ok(f))) => {
                let mut got = 0;
                if let Ok(d) = f.into_data() {
                    got = d.len();
                    extend_wiped(&mut a.held, &d);
                }
                if a.held.len() as u64 > limit {
                    let_held_go(&mut a.held);
                    a.held_over = true;
                    a.body = None;
                    a.clock = None;
                    return;
                }
                if bounds.polled(a, Some(got)).is_none() {
                    continue;
                }
            }
            Poll::Ready(Some(Err(_))) => {}
            Poll::Ready(None) => {
                a.held_whole = true;
                a.body = None;
                a.clock = None;
                return;
            }
        }

        let_held_go(&mut a.held);
        a.body = None;
        a.clock = None;
        a.gate = Gate::Failed;
        a.respond = None;
        return;
    }
}

/// The request as the auth handle reads it (`HeadView`): the method, the target's path, the

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

/// Strip from `parts` what the auth named: every field line it

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

    let _ = respond.send(resp);
    true
}

impl Accepted {
    /// Check the initial peer policy once, before any stream's admission. A pending peer call

    pub fn admit_peer(&mut self, k: &mut dyn Kernel) -> Admitted {
        let mut did = Admitted::default();
        if self.ended && self.conn.is_none() {
            return did;
        }
        while self.peer_done < self.peer_auths.len() {
            if k.ticket().is_none() {
                return did;
            }

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
                    if !self.checked_peers.contains(&auth) {
                        self.checked_peers.push(auth);
                    }
                    self.peer_done += 1;
                    did.moved = true;
                }

                Poll::Ready(_) => {
                    self.conn = None;
                    self.ended = true;
                    did.moved = true;
                    return did;
                }
            }
        }
        did
    }

    /// Admit decoded requests, retaining each selected policy through its last body byte.
    pub fn admit(&mut self, k: &mut dyn Kernel) -> Admitted {
        let mut did = self.admit_peer(k);
        if did.parked
            || self.peer_done < self.peer_auths.len()
            || (self.ended && self.conn.is_none())
        {
            return did;
        }
        let shared = self.shared.clone();
        let mut sh = shared.lock().unwrap_or_else(PoisonError::into_inner);
        let mut waiting = std::mem::take(&mut sh.waiting);
        if let Some(at) = waiting.iter().position(|id| {
            sh.streams
                .get(id)
                .is_some_and(|a| a.loan_ticket == Some(k.ticket()))
        }) {
            waiting.swap(0, at);
        }
        let mut waiting = waiting.into_iter();
        while let Some(id) = waiting.next() {
            let Some(mut a) = sh.streams.remove(&id) else {
                continue;
            };
            let before = a.gate;
            if a.gate == Gate::Arrived && a.policy.is_none() && self.loans.is_some() {
                if a.loan_ticket.is_some_and(|ticket| ticket != k.ticket()) {
                    sh.streams.insert(id, a);
                    sh.waiting.push(id);
                    continue;
                }

                if did.parked || self.wire_pending() || !self.out.is_empty() || !sh.out.is_empty() {
                    did.more = true;
                    sh.streams.insert(id, a);
                    sh.waiting.push(id);
                    continue;
                }
                let loans = self.loans.as_mut().expect("checked above");
                a.loan_ticket = Some(k.ticket());
                match k.open_policy(loans, id) {
                    Ok(Some(loan)) => {
                        let policy = match &self.last_policy {
                            Some(cached) if Arc::ptr_eq(&cached.loan, &loan) => Arc::clone(cached),
                            _ => {
                                let lines = loan.lines.iter().map(Line::from_policy).collect();
                                let policy = Arc::new(StreamPolicy { loan, lines });
                                self.last_policy = Some(Arc::clone(&policy));
                                policy
                            }
                        };
                        a.policy = Some(policy);
                        a.loan_ticket = None;
                        a.opened_on = Some(k.ticket());
                        self.claimed.push((k.ticket(), id));
                    }
                    Ok(None) => {
                        self.policy_input.insert(k.ticket());
                        did.policy_requested = true;
                        sh.streams.insert(id, a);
                        sh.waiting.push(id);
                        sh.waiting.extend(waiting);
                        return did;
                    }
                    Err(_) => {
                        self.policy_input.remove(&k.ticket());
                        loans.cancel(k.ticket());
                        a.loan_ticket = None;
                        fail(&mut a, &mut did);
                        did.policy_failed = true;
                    }
                }
                if did.policy_failed {
                    sh.streams.insert(id, a);
                    sh.waiting.extend(waiting);
                    return did;
                }
            }

            self.admit_one(id, &mut a, &mut sh.out, k, &mut did);

            did.moved |= a.gate != before;
            let done = matches!(a.gate, Gate::Admitted | Gate::Refused | Gate::Failed);
            if a.gate == Gate::Admitted && before != Gate::Admitted && a.opened_on.is_some() {
                self.publishing.push(id);
            }
            if a.gate == Gate::Refused {
                self.let_raw_go();
            }
            sh.streams.insert(id, a);
            if !done {
                sh.waiting.push(id);
            }
        }
        did
    }

    /// A completed operation no longer owns an unadmitted stream's cancellation.
    pub fn operation_done(&mut self, ticket: Ticket) {
        self.policy_input.remove(&ticket);
        if self.claimed.is_empty() {
            return;
        }
        let mut sh = self.shared.lock().unwrap_or_else(PoisonError::into_inner);
        self.claimed.retain(|(owner, stream)| {
            if *owner != ticket {
                return true;
            }
            if let Some(a) = sh.streams.get_mut(stream) {
                if a.opened_on == Some(ticket) {
                    a.opened_on = None;
                }
            }
            false
        });
    }

    /// A whole head copied into READY is no longer owned by the opening operation's cancel.
    pub fn published(&mut self) {
        if self.publishing.is_empty() {
            return;
        }
        let mut sh = self.shared.lock().unwrap_or_else(PoisonError::into_inner);
        let out = &self.out;
        self.publishing.retain(|stream| {
            let pending = out
                .iter()
                .chain(sh.out.iter())
                .any(|piece| piece.stream == *stream && piece.fields);
            if !pending {
                if let Some(a) = sh.streams.get_mut(stream) {
                    a.opened_on = None;
                }
            }
            pending
        });
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
        let policy = a.policy.clone();

        let default_lines = self.lines.clone();
        let lines = policy
            .as_ref()
            .map_or(default_lines.as_ref(), |p| p.lines.as_ref());
        loop {
            let Some(parts) = a.parts.as_ref() else {
                return;
            };
            match a.gate {
                Gate::Arrived => {
                    let fields = field_lines(parts);
                    let to = match guest::matched(
                        lines,
                        parts.method.as_str(),
                        parts.uri.path(),
                        &fields,
                    ) {
                        Matched::NoRoute => {
                            return self.kernel_refuse(id, a, REFUSE_NO_ROUTE, LINE_NONE, k, did);
                        }
                        Matched::MethodMiss(n) => {
                            let line = lines[n].line;
                            return self.kernel_refuse(id, a, REFUSE_METHOD_MISS, line, k, did);
                        }
                        Matched::Line(n) => {
                            let points = lines[n].points;
                            if points & POINT_PEER != 0
                                && !self.checked_peers.contains(&lines[n].auth)
                            {
                                Gate::Peer(n)
                            } else {
                                request_gate(points, n)
                            }
                        }
                    };
                    a.gate = to;
                }
                Gate::Peer(n) => {
                    let auth = lines[n].auth;
                    if self.checked_peers.contains(&auth) {
                        a.gate = request_gate(lines[n].points, n);
                        continue;
                    }
                    if k.ticket().is_none() {
                        return;
                    }
                    let pending = self
                        .policy_peer_parked
                        .iter()
                        .find(|(held, _, _, _)| *held == auth)
                        .copied();
                    let seq = match pending {
                        Some((_, ticket, seq, stream)) if ticket == k.ticket() && stream == id => {
                            seq
                        }
                        Some(_) => return,
                        None => self.next_seq(),
                    };
                    if a.opened_on != Some(k.ticket()) {
                        a.opened_on = Some(k.ticket());
                        self.claimed.push((k.ticket(), id));
                    }
                    a.parked = None;
                    let answer = k.auth_call(
                        seq,
                        auth,
                        UnitRef::NONE,
                        POINT_PEER,
                        id,
                        &HeadViewArgs::default(),
                        None,
                    );
                    self.policy_peer_parked
                        .retain(|(held, _, _, _)| *held != auth);
                    match answer {
                        Poll::Pending => {
                            self.policy_peer_parked.push((auth, k.ticket(), seq, id));
                            a.parked = Some((k.ticket(), seq));
                            did.parked = true;
                            return;
                        }
                        Poll::Ready(Ok((FLOW_CONTINUE, ..))) => {
                            self.checked_peers.push(auth);
                            a.gate = request_gate(lines[n].points, n);
                        }
                        Poll::Ready(Ok(_)) => {
                            return self.kernel_refuse(
                                id,
                                a,
                                REFUSE_STOPPED,
                                lines[n].line,
                                k,
                                did,
                            );
                        }
                        Poll::Ready(Err(_)) => return fail(a, did),
                    }
                }
                Gate::Hold(n) => {
                    if a.held_over {
                        let line = lines[n].line;
                        return self.kernel_refuse(id, a, REFUSE_OVER_GATE, line, k, did);
                    }
                    if !a.held_whole {
                        return;
                    }
                    a.gate = Gate::Auth(n);
                }
                Gate::Auth(n) => {
                    if k.ticket().is_none() {
                        return;
                    }
                    let l = &lines[n];
                    let (auth, line, body_point) =
                        (l.auth, l.line, l.points & POINT_HEAD_BODY != 0);

                    let seq = match a.parked {
                        Some((t, seq)) if t == k.ticket() => seq,
                        Some(_) => return,
                        None => self.next_seq(),
                    };
                    a.parked = None;
                    if a.policy.is_some() && a.opened_on != Some(k.ticket()) {
                        a.opened_on = Some(k.ticket());
                        self.claimed.push((k.ticket(), id));
                    }
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
                    let (auth, line) = (lines[n].auth, lines[n].line);
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

        let unit = if line == LINE_NONE {
            UnitRef::NONE
        } else {
            a.unit
        };

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

/// THE REQUEST BODY AN ANSWER ENDED BEFORE: once the host's answer on `a`'s stream is

fn let_unread_body_go(a: &mut Answer) {
    if a.asked {
        return;
    }
    if a.body.take().is_some() {
        a.asked = true;
        a.told = true;
    }
}

/// `protocol`'s 1-based position in the door's accepting offer (`super::ACCEPT_OFFER`, the

fn offer_position(protocol: &[u8]) -> u32 {
    let offer = super::ACCEPT_OFFER;
    let (mut at, mut position) = (0usize, 0u32);
    while at < offer.len() {
        let n = usize::from(offer[at]);
        let Some(name) = offer.get(at + 1..at + 1 + n) else {
            return 0;
        };
        position += 1;
        if !protocol.is_empty() && name == protocol {
            return position;
        }
        at += 1 + n;
    }
    0
}

/// Let a held body go: zeroised, and its allocation freed, not kept for a record that may outlive

fn let_held_go(held: &mut Vec<u8>) {
    held.zeroize();
    *held = Vec::new();
}

/// Whether request `a` is over on both sides and its record can go (retention bounds only settled

fn finished(a: &Answer) -> bool {
    let request_done = match a.gate {
        Gate::Refused | Gate::Failed => true,
        Gate::Admitted => a.body.is_none(),
        _ => false,
    };
    let answer_done = a.respond.is_none()
        && a.reply.as_ref().is_none_or(|q| {
            let q = q.lock().unwrap_or_else(PoisonError::into_inner);
            q.ended && q.chunks.is_empty()
        });
    request_done && answer_done && !a.switched
}

/// Whether the far side gave request `a`'s stream up while something was still owed on it: the

fn given_up(a: &Answer) -> bool {
    let before_head = a
        .respond
        .as_ref()
        .is_some_and(futures_channel::oneshot::Sender::is_canceled);
    let mid_answer = a.reply.as_ref().is_some_and(|q| {
        let q = q.lock().unwrap_or_else(PoisonError::into_inner);
        q.gone && !q.broken && !(q.ended && q.chunks.is_empty())
    });
    !a.switched && (before_head || mid_answer)
}

/// A stream's failure `words`, followed by why hyper ended the connection, where it ended in an

fn with_cause(words: &str, cause: Option<&str>) -> String {
    match cause {
        Some(cause) => format!("{words}: {cause}"),
        None => words.to_owned(),
    }
}

/// Leave request `a` unanswered: its answer's sender dropped, hyper ends the stream (HTTP/2) or

fn fail(a: &mut Answer, did: &mut Admitted) {
    a.respond = None;
    a.parts = None;
    a.body = None;
    let_held_go(&mut a.held);
    a.gate = Gate::Failed;
    did.moved = true;
}

/// Request `id` is admitted: its stripped head goes up, then any body held for its auth (whole),

fn go_up(id: u64, a: &mut Answer, out: &mut VecDeque<Piece>) {
    let Some(parts) = a.parts.take() else {
        return;
    };
    out.push_back(head_piece(id, &parts));
    if !a.held.is_empty() {
        let body = a.held.clone();
        #[cfg(test)]
        crate::wipe_probe::watch("admitted body", &body);
        out.push_back(Piece::data(
            id,
            super::engine::held_bytes(zeroize::Zeroizing::new(body)),
        ));
        let_held_go(&mut a.held);
    }
    if a.held_whole {
        out.push_back(Piece::end(id));
        a.asked = true;
    }
    a.up = true;
    a.gate = Gate::Admitted;
}

/// The accepted request keeps every decoded field left after the auth's declared stripping.

fn head_piece(stream: u64, parts: &http::request::Parts) -> Piece {
    let target = parts
        .uri
        .path_and_query()
        .map_or_else(|| parts.uri.to_string(), |p| p.as_str().to_owned());
    let authority = parts
        .uri
        .authority()
        .map_or_else(String::new, |a| a.as_str().to_owned());
    let mut block = Vec::new();
    for (name, value) in &parts.headers {
        block.extend_from_slice(name.as_str().as_bytes());
        block.extend_from_slice(fields::SEPARATOR);
        block.extend_from_slice(value.as_bytes());
        block.extend_from_slice(fields::LINE_END);
    }
    Piece {
        head: Some(HeadWords {
            method: Bytes::copy_from_slice(parts.method.as_str().as_bytes()),
            target: Bytes::from(target),
            authority: Bytes::from(authority),
            reason: Bytes::new(),
        }),
        ..Piece::fields(stream, Bytes::from(block))
    }
}

#[cfg(test)]
#[path = "tests/accept_tests.rs"]
mod tests;
