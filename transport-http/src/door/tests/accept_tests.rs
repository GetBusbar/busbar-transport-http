// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The accepted side against v1.5.5's data listener: the same request answered the same way must
//! put the same bytes on the wire as v1.5.5's server builder (`crates/busbar/src/tls.rs`:560-566,
//! hyper-util's auto builder, HTTP/1 header read bounded at 30 s) put there.

use super::*;
use http_body_util::BodyExt;
use std::convert::Infallible;

const SEC: u64 = 1_000_000_000;

/// The kernel a `none` line meets: every hand-in CONTINUE; no auth is called on it and nothing is
/// refused.
struct Open;

impl Kernel for Open {
    #[allow(clippy::too_many_arguments)]
    fn auth_call(
        &mut self,
        _: u32,
        _: AuthRef,
        _: UnitRef,
        _: u32,
        _: u64,
        _: &HeadViewArgs<'_>,
        _: Option<&[u8]>,
    ) -> Pend<AuthCalled> {
        Poll::Ready(Err(ServiceError::Unserved))
    }
    fn hand_in(
        &mut self,
        _: u32,
        _: AuthRef,
        _: UnitRef,
        _: u32,
        _: u64,
        _: &HeadViewArgs<'_>,
    ) -> Result<(u32, UnitRef), ServiceError> {
        Ok((FLOW_CONTINUE, UnitRef { id: 1, mac: 1 }))
    }
    fn refuse(
        &mut self,
        _: u32,
        _: UnitRef,
        _: u32,
        _: u32,
        _: u64,
        _: &HeadViewArgs<'_>,
    ) -> Result<RefusalCopy, ServiceError> {
        Err(ServiceError::Unserved)
    }
}

/// An accepted connection under one `none` line that takes every request.
fn accepted() -> Accepted {
    Accepted::accept(SEC, vec![Line::any(1)])
}

/// Drive the connection at `now`, admit what it decoded, and drive what the admission let move.
fn run(a: &mut Accepted, now: u64) {
    a.drive(now);
    a.admit(&mut Open);
    a.drive(now);
}

/// What the framing handed up, by stream: field blocks, body bytes, whether the request is whole.
#[derive(Debug, Default)]
struct Up {
    heads: Vec<(u64, HeadWords, Vec<u8>)>,
    body: Vec<u8>,
    whole: bool,
    failed: bool,
}

fn up(a: &mut Accepted) -> Up {
    let mut u = Up::default();
    for p in a.pieces().drain(..) {
        if p.fields {
            u.heads.push((
                p.stream,
                p.head.clone().unwrap_or_default(),
                p.bytes.to_vec(),
            ));
        } else if p.failed {
            u.failed = true;
        } else if p.end {
            u.whole = true;
        } else {
            u.body.extend_from_slice(&p.bytes);
        }
    }
    u
}

/// The wire bytes with the `date` line (the second the server answered in) taken out.
fn undated(mut wire: Vec<u8>) -> Vec<u8> {
    if let Some(at) = wire
        .windows(6)
        .position(|w| w.eq_ignore_ascii_case(b"date: "))
    {
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

/// v1.5.5's data listener answering `request` with `status`, `headers` and `body` (known size when
/// `sized`, else streamed): its wire bytes, over an in-memory socket.
fn v155(
    request: &[u8],
    status: u16,
    headers: &[(&str, &str)],
    body: &[u8],
    sized: bool,
) -> Vec<u8> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let headers: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    let body = Bytes::copy_from_slice(body);
    rt.block_on(async move {
        let (mut cli, srv) = tokio::io::duplex(1 << 20);
        let svc = hyper::service::service_fn(move |_req: http::Request<Incoming>| {
            let (headers, body) = (headers.clone(), body.clone());
            async move {
                let mut b = http::Response::builder().status(status);
                for (k, v) in &headers {
                    b = b.header(k.as_str(), v.as_str());
                }
                let body: http_body_util::combinators::BoxBody<Bytes, Infallible> = if sized {
                    http_body_util::Full::new(body).boxed()
                } else {
                    http_body_util::StreamBody::new(futures::stream::iter(vec![
                        Ok::<_, Infallible>(Frame::data(body)),
                    ]))
                    .boxed()
                };
                Ok::<_, Infallible>(b.body(body).expect("response"))
            }
        });
        let server = tokio::spawn(async move {
            let mut builder =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
            builder
                .http1()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(HEADER_READ_TIMEOUT);
            let _ = builder
                .serve_connection_with_upgrades(hyper_util::rt::TokioIo::new(srv), svc)
                .await;
        });
        // The request, and NO half-close: v1.5.5's builder leaves `half_close` off, so a read end
        // before the answer is written closes the connection with nothing written (both sides of
        // this comparison then read as empty and agree vacuously). The answer is read until the
        // connection goes quiet.
        cli.write_all(request).await.expect("request");
        let mut wire = Vec::new();
        let mut buf = [0_u8; 4096];
        while let Ok(Ok(n)) =
            tokio::time::timeout(std::time::Duration::from_millis(300), cli.read(&mut buf)).await
        {
            if n == 0 {
                break;
            }
            wire.extend_from_slice(&buf[..n]);
        }
        server.abort();
        wire
    })
}

/// The door's accepted side answering `request` the same way, as a host drives it: the head emit
/// (status, field block), then the body emits. A `sized` answer states its `content-length` as the
/// head's last field, as the host renders an answer whose size it knows.
fn door(
    request: &[u8],
    status: u16,
    headers: &[(&str, &str)],
    body: &[u8],
    sized: bool,
) -> Vec<u8> {
    let mut a = accepted();
    a.ingest(request, false);
    run(&mut a, SEC);
    let u = up(&mut a);
    assert_eq!(u.heads.len(), 1, "one request");
    let stream = u.heads[0].0;
    let mut block = Vec::new();
    for (k, v) in headers {
        block.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    if sized {
        block.extend_from_slice(format!("content-length: {}\r\n", body.len()).as_bytes());
    }
    assert!(a.answers_head(stream));
    a.emit(stream, &block, false, u32::from(status))
        .expect("head");
    assert!(!a.answers_head(stream), "the head went");
    a.emit(stream, body, true, 0).expect("body");
    // The answer goes out before any read end, as on the v1.5.5 side.
    run(&mut a, 2 * SEC);
    a.take_wire(usize::MAX)
}

const GET: &[u8] = b"GET /v1/models?x=1 HTTP/1.1\r\nhost: busbar.test\r\nuser-agent: t\r\n\r\n";

#[test]
fn a_request_goes_up_as_its_head_slots_one_field_block_and_its_body() {
    let mut a = accepted();
    a.ingest(
        b"POST /v1/messages HTTP/1.1\r\nhost: busbar.test\r\nconnection: keep-alive\r\ncontent-length: 5\r\ncontent-type: application/json\r\n\r\nhello",
        false,
    );
    run(&mut a, SEC);
    let u = up(&mut a);
    assert_eq!(u.heads.len(), 1);
    let (stream, words, block) = &u.heads[0];
    assert_eq!(*stream, 1);
    assert_eq!(&words.method[..], b"POST");
    assert_eq!(&words.target[..], b"/v1/messages");
    assert!(
        words.authority.is_empty(),
        "an origin-form request names no authority"
    );
    assert!(words.reason.is_empty());
    // No hop-by-hop field and no `content-length` in the block: the pieces carry the body.
    assert_eq!(
        String::from_utf8_lossy(block),
        "host: busbar.test\r\ncontent-type: application/json\r\n"
    );
    assert_eq!(u.body, b"hello");
    assert!(u.whole, "the request is whole");
}

#[test]
fn a_sized_answer_is_the_bytes_v155_wrote() {
    let headers = [
        ("content-type", "application/json"),
        ("x-request-id", "r-1"),
    ];
    let ours = undated(door(GET, 200, &headers, b"{\"ok\":true}", true));
    let theirs = undated(v155(GET, 200, &headers, b"{\"ok\":true}", true));
    assert!(
        theirs.starts_with(b"HTTP/1.1 200 OK\r\n"),
        "v1.5.5 answered"
    );
    assert_eq!(
        String::from_utf8_lossy(&ours),
        String::from_utf8_lossy(&theirs)
    );
}

#[test]
fn a_streamed_answer_is_the_chunked_bytes_v155_wrote() {
    let headers = [("content-type", "text/event-stream")];
    let ours = undated(door(GET, 200, &headers, b"data: x\n\n", false));
    let theirs = undated(v155(GET, 200, &headers, b"data: x\n\n", false));
    assert_eq!(
        String::from_utf8_lossy(&ours),
        String::from_utf8_lossy(&theirs)
    );
    assert!(ours.windows(26).any(|w| w == b"transfer-encoding: chunked"));
}

#[test]
fn an_error_answer_is_the_bytes_v155_wrote() {
    let headers = [("content-type", "application/json")];
    let body = br#"{"error":{"type":"not_found"}}"#;
    let ours = undated(door(GET, 404, &headers, body, true));
    let theirs = undated(v155(GET, 404, &headers, body, true));
    assert_eq!(ours, theirs);
    assert!(ours.starts_with(b"HTTP/1.1 404 Not Found\r\n"));
}

#[test]
fn a_header_read_past_30s_ends_the_connection_unanswered() {
    let mut a = accepted();
    a.ingest(b"GET / HTTP/1.1\r\nhost: slow", false);
    run(&mut a, SEC);
    assert!(a.next_deadline().is_some(), "the header read is bounded");
    run(&mut a, SEC + 29 * SEC);
    assert!(!a.ended(), "not before 30s");
    run(&mut a, SEC + 31 * SEC);
    assert!(a.ended(), "the bound ends the connection");
    assert!(up(&mut a).heads.is_empty(), "no request went up");
}

#[test]
fn a_status_on_a_stream_with_no_request_is_refused() {
    let mut a = accepted();
    assert!(a.emit(9, b"", true, 200).is_err());
}

#[test]
fn a_switched_connection_detaches_what_followed_its_request() {
    let mut a = accepted();
    a.ingest(
        b"GET /v1/session HTTP/1.1\r\nhost: busbar.test\r\nconnection: upgrade\r\nupgrade: x-test\r\n\r\n\x81\x05hello",
        false,
    );
    run(&mut a, SEC);
    let u = up(&mut a);
    let stream = u.heads[0].0;
    a.emit(
        stream,
        b"connection: upgrade\r\nupgrade: x-test\r\n",
        true,
        101,
    )
    .expect("101");
    run(&mut a, SEC);
    let rest = a.detach().expect("switched").expect("something switched");
    let rest: Vec<u8> = rest.drain(..).collect();
    assert_eq!(rest, b"\x81\x05hello", "the bytes after the request");
    let wire = a.take_wire(usize::MAX);
    assert!(
        wire.starts_with(b"HTTP/1.1 101 Switching Protocols\r\n"),
        "{}",
        String::from_utf8_lossy(&wire)
    );
    assert!(a.ended());
}

#[test]
fn an_unanswered_connection_detaches_as_sent_for_the_upgrade_framer_to_answer() {
    let request: &[u8] =
        b"GET /v1/session HTTP/1.1\r\nhost: busbar.test\r\nconnection: upgrade\r\nupgrade: x-test\r\n\r\n";
    let mut a = accepted();
    a.ingest(request, false);
    run(&mut a, SEC);
    assert_eq!(up(&mut a).heads.len(), 1, "the request went up");
    a.ingest(b"\x81\x02hi", false);
    let rest: Vec<u8> = a
        .detach()
        .expect("handed over")
        .expect("nothing answered")
        .drain(..)
        .collect();
    let mut sent = request.to_vec();
    sent.extend_from_slice(b"\x81\x02hi");
    assert_eq!(rest, sent, "the connection as the far side sent it");
    assert!(a.take_wire(usize::MAX).is_empty(), "nothing was answered");
    assert!(a.ended());
}

#[test]
fn an_answered_or_h2_connection_is_not_handed_over_as_sent() {
    let mut a = accepted();
    a.ingest(GET, false);
    run(&mut a, SEC);
    let stream = up(&mut a).heads[0].0;
    a.emit(stream, b"content-length: 0\r\n", true, 204)
        .expect("answered");
    run(&mut a, SEC);
    assert!(
        a.detach().expect("no failure").is_none(),
        "an answered connection"
    );

    let mut h2 = accepted();
    h2.ingest(H2_PREFACE, false);
    run(&mut h2, SEC);
    assert!(
        h2.detach().expect("no failure").is_none(),
        "an HTTP/2 connection"
    );
}

/// THE COPY KEPT FOR A HAND-OVER AS SENT is bounded and kept only while a hand-over is possible
/// (Q128 reader A finding 1; THE DESIGN §1 l.199-201, a bound on live work is a refusal at
/// admission): an HTTP/2 connection is never handed over, so it keeps none.
#[test]
fn an_h2_connection_keeps_no_copy_of_what_it_was_sent() {
    let mut a = accepted();
    a.ingest(H2_PREFACE, false);
    // An empty SETTINGS frame, then PINGs: frames that are answered by hyper, never by the host.
    a.ingest(b"\x00\x00\x00\x04\x00\x00\x00\x00\x00", false);
    for _ in 0..64 {
        a.ingest(b"\x00\x00\x08\x06\x00\x00\x00\x00\x00pingping", false);
    }
    run(&mut a, SEC);
    assert!(a.raw.is_none(), "an h2 connection keeps no copy");
}

/// A request admitted without an upgrade line makes a hand-over as sent impossible: the copy goes.
#[test]
fn an_admitted_request_that_asks_no_upgrade_lets_the_copy_go() {
    let mut a = accepted();
    a.ingest(GET, false);
    run(&mut a, SEC);
    assert_eq!(up(&mut a).heads.len(), 1, "the request went up");
    assert!(a.raw.is_none(), "no hand-over is possible: no copy is kept");
}

/// The copy is bounded at hyper's HTTP/1 head limit (`engine::HEAD_MAX_BYTES`, the one an upgrade
/// request's head is read under): past it no hand-over as sent is possible, so the copy goes, and
/// the connection is NOT cut (Q128 reader B finding 2, overriding reader A's earlier "refuse over
/// it": v1.5.5's server served such a connection on).
#[test]
fn a_copy_past_the_head_limit_is_let_go_and_the_connection_kept() {
    const HEAD_LIMIT: usize = 8192 + 4096 * 100;
    let mut a = accepted();
    a.ingest(
        b"GET /v1/session HTTP/1.1\r\nhost: busbar.test\r\nconnection: upgrade\r\nupgrade: x-test\r\n\r\n",
        false,
    );
    run(&mut a, SEC);
    assert_eq!(up(&mut a).heads.len(), 1, "the upgrade request went up");
    let chunk = vec![b'x'; 64 * 1024];
    for _ in 0..8 {
        a.ingest(&chunk, false);
        run(&mut a, SEC);
        assert!(
            a.raw.as_ref().map_or(0, Vec::len) <= HEAD_LIMIT,
            "the copy never grows past the head limit"
        );
    }
    assert!(a.raw.is_none(), "past the limit the copy is let go");
    assert!(!a.ended(), "the connection is not cut");
}

/// A kernel that refuses: every auth call and hand-in STOP, every refusal the kernel's 401.
struct Refusing;

impl Kernel for Refusing {
    #[allow(clippy::too_many_arguments)]
    fn auth_call(
        &mut self,
        _: u32,
        _: AuthRef,
        _: UnitRef,
        _: u32,
        _: u64,
        _: &HeadViewArgs<'_>,
        _: Option<&[u8]>,
    ) -> Pend<AuthCalled> {
        Poll::Ready(Ok((
            busbar_contract::abi::host::service::FLOW_STOP,
            UnitRef { id: 1, mac: 1 },
            Vec::new(),
        )))
    }
    fn hand_in(
        &mut self,
        _: u32,
        _: AuthRef,
        _: UnitRef,
        _: u32,
        _: u64,
        _: &HeadViewArgs<'_>,
    ) -> Result<(u32, UnitRef), ServiceError> {
        Ok((
            busbar_contract::abi::host::service::FLOW_STOP,
            UnitRef { id: 1, mac: 1 },
        ))
    }
    fn refuse(
        &mut self,
        _: u32,
        _: UnitRef,
        _: u32,
        _: u32,
        _: u64,
        _: &HeadViewArgs<'_>,
    ) -> Result<RefusalCopy, ServiceError> {
        Ok(RefusalCopy {
            status: 401,
            fields: vec![("content-type".into(), b"application/json".to_vec())],
            body: b"{}".to_vec(),
        })
    }
}

/// Drive, then admit through `k` and drive until nothing moves, as a ticketed op does.
fn run_with(a: &mut Accepted, now: u64, k: &mut dyn Kernel) {
    a.drive(now);
    while a.admit(k).moved {
        a.drive(now);
    }
}

/// THE CONNECTION FORGETS EVERY FINISHED REQUEST (Q128 reader B finding 1, HIGH; THE DESIGN §1
/// l.199-203): N requests refused before any verdict could hold their bodies, and N answered, leave
/// a record count bounded by the live requests, and no held body's allocation.
#[test]
fn a_connection_forgets_every_finished_request() {
    const N: usize = 50;
    let mut a = Accepted::accept(
        SEC,
        vec![Line::any_needing(
            1,
            busbar_contract::abi::auth::POINT_HEAD_BODY,
            64,
        )],
    );
    for _ in 0..N {
        a.ingest(
            b"POST /v1/x HTTP/1.1\r\nhost: busbar.test\r\ncontent-length: 5\r\n\r\nhello",
            false,
        );
        run_with(&mut a, SEC, &mut Refusing);
        let wire = a.take_wire(usize::MAX);
        assert!(
            wire.starts_with(b"HTTP/1.1 401 Unauthorized\r\n"),
            "{wire:?}"
        );
    }
    {
        let sh = a.shared.lock().expect("shared");
        assert!(sh.streams.len() <= 1, "{} records kept", sh.streams.len());
        assert!(
            sh.streams.values().all(|s| s.held.capacity() == 0),
            "no held body's allocation is kept"
        );
    }
    let mut a = accepted();
    for _ in 0..N {
        a.ingest(GET, false);
        run(&mut a, SEC);
        let stream = up(&mut a).heads[0].0;
        a.emit(stream, b"content-length: 0\r\n", true, 204)
            .expect("answered");
        run(&mut a, SEC);
        assert!(a
            .take_wire(usize::MAX)
            .starts_with(b"HTTP/1.1 204 No Content\r\n"));
    }
    let n = a.shared.lock().expect("shared").streams.len();
    assert!(n <= 1, "{n} records kept");
}

/// A request that carries an `Upgrade` line AND a body is served as any other: its body never fills
/// the hand-over copy, so the connection is not cut, and it gets its normal answer (Q128 reader B
/// finding 2: the copy holds an upgrade request's HEAD only).
#[test]
fn an_upgrade_request_with_a_large_body_gets_its_normal_answer() {
    let mut a = accepted();
    a.ingest(
        b"POST /v1/x HTTP/1.1\r\nhost: busbar.test\r\nconnection: upgrade\r\nupgrade: h2c\r\ncontent-length: 600000\r\n\r\n",
        false,
    );
    run(&mut a, SEC);
    let stream = up(&mut a).heads[0].0;
    let chunk = vec![b'x'; 60_000];
    let mut carried = 0;
    for _ in 0..10 {
        a.ingest(&chunk, false);
        run(&mut a, SEC);
        carried += up(&mut a).body.len();
    }
    assert_eq!(carried, 600_000, "the whole body went up");
    assert!(!a.ended(), "the connection is not cut");
    a.emit(stream, b"content-length: 2\r\n", false, 200)
        .expect("head");
    a.emit(stream, b"ok", true, 0).expect("body");
    run(&mut a, SEC);
    let wire = a.take_wire(usize::MAX);
    assert!(wire.starts_with(b"HTTP/1.1 200 OK\r\n"), "{wire:?}");
}

/// One HTTP/2 frame: its type, flags, stream and payload (RFC 9113 §4.1).
fn frame(ty: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len())
        .expect("a small frame")
        .to_be_bytes();
    let mut f = vec![len[1], len[2], len[3], ty, flags];
    f.extend_from_slice(&stream.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// An HTTP/2 connection with one whole `GET /` request on stream 1, admitted and gone up: the
/// accepted side and the request's stream.
fn h2_request() -> (Accepted, u64) {
    let mut a = accepted();
    a.ingest(H2_PREFACE, false);
    a.ingest(&frame(4, 0, 0, &[]), false);
    // HPACK: `:method GET`, `:scheme http`, `:path /` (static indices 2, 6, 4), `:authority`
    // (static name 1, literal value, no indexing).
    let mut block = vec![0x82, 0x86, 0x84, 0x01, 11];
    block.extend_from_slice(b"busbar.test");
    a.ingest(&frame(1, 0x5, 1, &block), false);
    run(&mut a, SEC);
    let u = up(&mut a);
    assert_eq!(u.heads.len(), 1, "the request went up");
    let _ = a.take_wire(usize::MAX);
    (a, u.heads[0].0)
}

/// The far side resets stream 1 (RST_STREAM, CANCEL).
fn reset(a: &mut Accepted) {
    a.ingest(&frame(3, 0, 1, &8u32.to_be_bytes()), false);
    run(a, SEC);
}

/// THE FAR SIDE ABANDONS AN ANSWER (Q128 reader A, MEDIUM; THE DESIGN §1 l.199-201, §6 item 6
/// l.971-973): the host is told the stream ended (its failure piece), the stream's record goes at
/// once, and a later emit on it is refused, never queued where nobody drains it.
#[test]
fn a_stream_the_far_side_resets_mid_answer_ends_failed_and_is_let_go() {
    let (mut a, stream) = h2_request();
    a.emit(stream, b"content-type: text/event-stream\r\n", false, 200)
        .expect("the head");
    a.emit(stream, b"data: 1\n\n", false, 0).expect("a chunk");
    run(&mut a, SEC);
    reset(&mut a);
    assert!(up(&mut a).failed, "the host is told the stream ended");
    assert!(
        !a.shared
            .lock()
            .expect("shared")
            .streams
            .contains_key(&stream),
        "the stream's record is let go"
    );
    assert!(
        a.emit(stream, b"data: 2\n\n", false, 0).is_err(),
        "a later emit is refused, not queued"
    );
}

/// The far side resets a request before its answer head went: the same.
#[test]
fn a_stream_the_far_side_resets_before_its_head_ends_failed_and_is_let_go() {
    let (mut a, stream) = h2_request();
    reset(&mut a);
    assert!(up(&mut a).failed, "the host is told the stream ended");
    assert!(
        !a.shared
            .lock()
            .expect("shared")
            .streams
            .contains_key(&stream),
        "the stream's record is let go"
    );
    assert!(
        a.emit(stream, b"content-length: 0\r\n", true, 200).is_err(),
        "a later emit is refused"
    );
}

/// A streaming answer held at its high-water mark, its stream reset: the host is woken (the
/// stream's failure piece ends its hold), not left waiting for a writable piece that never comes.
#[test]
fn a_full_stream_the_far_side_resets_is_woken_not_stalled() {
    let (mut a, stream) = h2_request();
    a.emit(
        stream,
        b"content-type: application/octet-stream\r\n",
        false,
        200,
    )
    .expect("the head");
    let chunk = vec![b'x'; 64 * 1024];
    let mut full = false;
    for _ in 0..16 {
        full = a.emit(stream, &chunk, false, 0).expect("a chunk");
        run(&mut a, SEC);
        if full {
            break;
        }
    }
    assert!(full, "the answer reached its high-water mark");
    let _ = up(&mut a);
    reset(&mut a);
    assert!(up(&mut a).failed, "the held stream is woken by its end");
    assert!(
        !a.shared
            .lock()
            .expect("shared")
            .streams
            .contains_key(&stream),
        "its record and queued bytes are let go"
    );
}
