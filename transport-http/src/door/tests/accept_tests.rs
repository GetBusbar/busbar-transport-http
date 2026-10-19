// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The accepted side against v1.5.5's data listener: the same request answered the same way must
//! put the same bytes on the wire as v1.5.5's server builder (`crates/busbar/src/tls.rs`:560-566,
//! hyper-util's auto builder, HTTP/1 header read bounded at 30 s) put there.

use super::*;
use http_body_util::BodyExt;

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
    let _ = a.ingest(H2_PREFACE, false);
    // An empty SETTINGS frame, then PINGs: frames that are answered by hyper, never by the host.
    let _ = a.ingest(b"\x00\x00\x00\x04\x00\x00\x00\x00\x00", false);
    for _ in 0..64 {
        let _ = a.ingest(b"\x00\x00\x08\x06\x00\x00\x00\x00\x00pingping", false);
    }
    run(&mut a, SEC);
    assert!(a.raw.is_none(), "an h2 connection keeps no copy");
}

/// A request admitted without an upgrade line makes a hand-over as sent impossible: the copy goes.
#[test]
fn an_admitted_request_that_asks_no_upgrade_lets_the_copy_go() {
    let mut a = accepted();
    let _ = a.ingest(GET, false);
    run(&mut a, SEC);
    assert_eq!(up(&mut a).heads.len(), 1, "the request went up");
    assert!(a.raw.is_none(), "no hand-over is possible: no copy is kept");
}

/// The copy is bounded at hyper's HTTP/1 head limit (`engine::HEAD_MAX_BYTES`, the one an upgrade
/// request's head is read under): past it the connection is refused, not grown.
#[test]
fn a_copy_past_the_head_limit_refuses_the_connection() {
    const HEAD_LIMIT: usize = 8192 + 4096 * 100;
    let mut a = accepted();
    let _ = a.ingest(
        b"GET /v1/session HTTP/1.1\r\nhost: busbar.test\r\nconnection: upgrade\r\nupgrade: x-test\r\n\r\n",
        false,
    );
    run(&mut a, SEC);
    assert_eq!(up(&mut a).heads.len(), 1, "the upgrade request went up");
    let chunk = vec![b'x'; 64 * 1024];
    for _ in 0..8 {
        let _ = a.ingest(&chunk, false);
    }
    run(&mut a, SEC);
    assert!(
        a.raw.as_ref().map_or(0, Vec::len) <= HEAD_LIMIT,
        "the copy never grows past the head limit"
    );
    assert!(a.ended(), "past the limit the connection is refused");
}
