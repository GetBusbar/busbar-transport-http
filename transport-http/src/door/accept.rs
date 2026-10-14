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

use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use busbar_contract::abi::transport::fields;
use bytes::Bytes;
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper_util::server::conn::auto;

use super::engine::Failure;
use super::hyper_io::{field_block, HeadWords, HostIo, Owed, Piece};

/// v1.5.5's HTTP/1 header-read bound (`hardened_conn_builder`).
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// An answer body holds at most this many queued bytes before its `emit` answers the stream full.
pub const REPLY_HIGH_WATER: usize = 256 * 1024;
/// A stream answered full is writable again once its queue drains below this.
pub const REPLY_LOW_WATER: usize = 64 * 1024;

/// The status that switches protocols.
const SWITCHING_PROTOCOLS: u16 = 101;

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
/// `content-length` frames it, any other is chunked.
struct Reply(Arc<Mutex<ReplyQ>>);

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
        SizeHint::default()
    }
}

/// One request's answer side.
struct Answer {
    /// Where the head goes, until the first emit.
    respond: Option<futures::channel::oneshot::Sender<http::Response<Reply>>>,
    /// The body queue, once the head went.
    reply: Option<Arc<Mutex<ReplyQ>>>,
    /// The request asked to upgrade: hyper's handle on the switched connection.
    upgrade: Option<hyper::upgrade::OnUpgrade>,
    /// The answer was a `101`.
    switched: bool,
    /// The request body, carried up as it arrives.
    body: Option<Incoming>,
    /// The request is whole (its last piece went up).
    asked: bool,
}

/// What the service and the framing share.
struct Shared {
    out: VecDeque<Piece>,
    next: u64,
    streams: HashMap<u64, Answer>,
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
}

impl Accepted {
    /// Serve an accepted connection at host time `now_ns`.
    #[must_use]
    pub fn accept(now_ns: u64) -> Self {
        let io = HostIo::new(now_ns);
        let shared = Arc::new(Mutex::new(Shared {
            out: VecDeque::new(),
            next: 1,
            streams: HashMap::new(),
        }));
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
            conn: Some(Box::pin(async move { conn.await })),
            shared,
            out: VecDeque::new(),
            ended: false,
            leftover: None,
        }
    }

    /// The far side sent `bytes` (`end` = and then ended).
    pub fn ingest(&mut self, bytes: &[u8], end: bool) {
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
            .is_some_and(|a| a.respond.is_some())
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
        let Some(a) = sh.streams.get_mut(&stream) else {
            return Err(Failure(format!("emit: no request on stream {stream}")));
        };
        if let Some(respond) = a.respond.take() {
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
                .body(Reply(q.clone()))
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
            carry_bodies(&mut shared.lock().expect("shared"), cx);
            Ok::<(), Failure>(())
        });
        let mut sh = self.shared.lock().expect("shared");
        if self.ended {
            // A request the far side abandoned before it was whole fails its stream.
            let open: Vec<u64> = sh
                .streams
                .iter()
                .filter(|(_, a)| !a.asked && !a.switched)
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

    /// DETACH a switched connection: every byte the far side sent after the request that was
    /// answered `101`, for the upgrade framer to adopt. `None`: nothing is switched (yet).
    ///
    /// # Errors
    ///
    /// The switch itself failed.
    pub fn detach(&mut self) -> Result<Option<&mut VecDeque<u8>>, Failure> {
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

/// One request, as hyper hands it to the service: its head goes up at once, its body is pumped up
/// as it arrives, and the answer waits for the host's first emit on its stream.
fn serve(
    sh: Arc<Mutex<Shared>>,
    mut req: http::Request<Incoming>,
) -> BoxFut<Result<http::Response<Reply>, std::io::Error>> {
    let upgrade = req
        .headers()
        .contains_key(http::header::UPGRADE)
        .then(|| hyper::upgrade::on(&mut req));
    let (parts, body) = req.into_parts();
    let (tx, rx) = futures::channel::oneshot::channel();
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
            },
        );
        s.out.push_back(head_piece(id, &parts));
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

/// Carry every request body up as far as it has arrived: data pieces, then the empty piece that
/// says the request is whole (or the failure piece of a body the far side broke off).
fn carry_bodies(sh: &mut Shared, cx: &mut Context<'_>) {
    let Shared { out, streams, .. } = sh;
    for (id, a) in streams.iter_mut() {
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
                    out.push_back(Piece::data(*id, Bytes::new()));
                    a.body = None;
                    a.asked = true;
                    break;
                }
            }
        }
    }
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
