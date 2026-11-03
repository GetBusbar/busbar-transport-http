// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Accepted HTTP requests are compared with the responses from the 1.5.5 data listener.

use super::*;
use http_body_util::BodyExt;
use std::convert::Infallible;

const SEC: u64 = 1_000_000_000;

/// The kernel a `none` line meets: every hand-in CONTINUE; no auth is called on it and nothing is
struct Open;

/// The ticket a test kernel's op runs on: a ticketed one, where `auth.call` may be made.
const OP_TICKET: Ticket = Ticket {
    slot: 1,
    generation: 1,
};

impl Kernel for Open {
    fn ticket(&self) -> Ticket {
        OP_TICKET
    }
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

fn selected_policy(generation: u64, line: u32, points: u32, body_limit: u64) -> Arc<Policy> {
    use busbar_contract::abi::transport::{guest_policy::GuestLine, route};
    Arc::new(Policy {
        listener: 7,
        generation,
        lines: vec![GuestLine {
            line,
            points,
            auth: AuthRef {
                id: generation,
                mac: generation,
            },
            body_limit,
            methods: route::METHOD_ANY,
            path_form: route::PATH_CONTAINS,
            path: "/".into(),
            fields: Vec::new(),
            rung: 0,
        }],
    })
}

struct Selecting {
    policy: Arc<Policy>,
    auths: Vec<u64>,
    handed: Vec<u32>,
    wait: bool,
    loan_wait: bool,
    points: Vec<u32>,
    completions: Vec<(u32, u32)>,
}

impl Kernel for Selecting {
    fn ticket(&self) -> Ticket {
        OP_TICKET
    }
    fn open_policy(&mut self, _: &mut Loans, _: u64) -> Result<Option<Arc<Policy>>, ServiceError> {
        Ok((!self.loan_wait).then(|| Arc::clone(&self.policy)))
    }
    fn auth_call(
        &mut self,
        seq: u32,
        auth: AuthRef,
        _: UnitRef,
        point: u32,
        _: u64,
        _: &HeadViewArgs<'_>,
        _: Option<&[u8]>,
    ) -> Pend<AuthCalled> {
        self.auths.push(auth.id);
        self.points.push(point);
        self.completions.push((point, seq));
        if self.wait {
            Poll::Pending
        } else {
            Poll::Ready(Ok((FLOW_CONTINUE, UnitRef { id: 1, mac: 1 }, Vec::new())))
        }
    }
    fn hand_in(
        &mut self,
        _: u32,
        _: AuthRef,
        _: UnitRef,
        line: u32,
        _: u64,
        _: &HeadViewArgs<'_>,
    ) -> Result<(u32, UnitRef), ServiceError> {
        self.handed.push(line);
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

fn selecting() -> (Accepted, Selecting) {
    use busbar_contract::abi::{mechanism::extensions, transport::guest_policy};
    let initial = guest_policy::encode(7, 1, &[]).unwrap();
    let initial = extensions::encode(&[(guest_policy::EXT_GUEST_POLICY, &initial)]);
    let a = accepted().with_policies(Loans::from_initial(&initial).unwrap());
    (
        a,
        Selecting {
            policy: selected_policy(2, 22, 0, 0),
            auths: Vec::new(),
            handed: Vec::new(),
            wait: false,
            loan_wait: false,
            points: Vec::new(),
            completions: Vec::new(),
        },
    )
}

#[test]
fn a_cancelled_policy_opening_hands_in_no_request_or_body() {
    let (mut a, mut kernel) = selecting();
    kernel.loan_wait = true;
    a.ingest(
        b"POST / HTTP/1.1\r\nhost: test\r\ncontent-length: 4\r\n\r\nabcd",
        false,
    );
    run_with(&mut a, SEC, &mut kernel);
    assert!(up(&mut a).heads.is_empty());
    assert!(kernel.handed.is_empty());
    assert!(
        a.cancel(OP_TICKET),
        "the policy-opening operation took its input"
    );
    kernel.loan_wait = false;
    run_with(&mut a, SEC, &mut kernel);
    let got = up(&mut a);
    assert!(got.heads.is_empty());
    assert!(got.body.is_empty());
    assert!(kernel.handed.is_empty());
}

#[test]
fn a_new_request_matches_the_hosts_selected_policy_before_hand_in() {
    let (mut a, mut kernel) = selecting();
    a.ingest(b"GET / HTTP/1.1\r\nhost: test\r\n\r\n", false);
    run_with(&mut a, SEC, &mut kernel);
    assert_eq!(kernel.handed, [22]);
    assert_eq!(up(&mut a).heads.len(), 1);
}

#[test]
fn a_new_generation_checks_peer_before_head_body_and_keeps_its_pending_handle() {
    let (mut a, mut kernel) = selecting();
    kernel.policy = selected_policy(2, 22, POINT_PEER | POINT_HEAD_BODY, 8);
    kernel.wait = true;
    a.ingest(
        b"POST / HTTP/1.1\r\nhost: test\r\ncontent-length: 4\r\n\r\nabcd",
        false,
    );
    run_with(&mut a, SEC, &mut kernel);
    assert_eq!(kernel.points, [POINT_PEER]);
    assert!(kernel.handed.is_empty());
    let got = up(&mut a);
    assert!(got.heads.is_empty() && got.body.is_empty());
    kernel.policy = selected_policy(3, 33, POINT_HEAD_BODY, 1);
    kernel.wait = false;
    run_with(&mut a, SEC, &mut kernel);
    assert_eq!(kernel.points, [POINT_PEER, POINT_PEER, POINT_HEAD_BODY]);
    assert_eq!(kernel.auths, [2, 2, 2]);
    assert_eq!(kernel.completions[0], kernel.completions[1]);
    assert_eq!(kernel.handed, [22]);
    assert_eq!(up(&mut a).body, b"abcd");
}

#[test]
fn a_peer_verdict_is_reused_for_its_exact_auth_handle_but_not_after_reload() {
    let (mut a, mut kernel) = selecting();
    kernel.policy = selected_policy(2, 22, POINT_PEER | POINT_HEAD, 0);
    for stream in 1..=3 {
        if stream == 3 {
            kernel.policy = selected_policy(3, 33, POINT_PEER | POINT_HEAD, 0);
        }
        a.ingest(b"GET / HTTP/1.1\r\nhost: test\r\n\r\n", false);
        run_with(&mut a, SEC, &mut kernel);
        assert_eq!(up(&mut a).heads.len(), 1);
        a.emit(stream, b"content-length: 0\r\n", true, 200).unwrap();
        a.drive(SEC);
        assert!(a.take_wire(usize::MAX).starts_with(b"HTTP/1.1 200 OK\r\n"));
    }
    assert_eq!(
        kernel.points,
        [POINT_PEER, POINT_HEAD, POINT_HEAD, POINT_PEER, POINT_HEAD]
    );
    assert_eq!(kernel.auths, [2, 2, 2, 3, 3]);
}

#[test]
fn a_pending_request_retains_its_auth_and_body_limit_across_a_new_policy() {
    let (mut a, mut kernel) = selecting();
    kernel.policy = selected_policy(2, 22, POINT_HEAD_BODY, 8);
    a.ingest(
        b"POST / HTTP/1.1\r\nhost: test\r\ncontent-length: 4\r\n\r\nab",
        false,
    );
    run_with(&mut a, SEC, &mut kernel);
    assert!(kernel.handed.is_empty());
    kernel.policy = selected_policy(3, 33, POINT_HEAD_BODY, 1);
    kernel.wait = true;
    a.ingest(b"cd", false);
    run_with(&mut a, SEC, &mut kernel);
    assert_eq!(kernel.auths, [2]);
    assert!(kernel.handed.is_empty());
    kernel.wait = false;
    run_with(&mut a, SEC, &mut kernel);
    assert_eq!(kernel.auths, [2, 2]);
    assert_eq!(kernel.handed, [22]);
    assert_eq!(up(&mut a).body, b"abcd");
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

/// Whether `wire` holds one whole HTTP/1.1 answer: its head, then the body its `content-length`
fn answer_whole(wire: &[u8]) -> bool {
    let Some(end) = wire.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    let head = String::from_utf8_lossy(&wire[..end]).to_ascii_lowercase();
    let body = &wire[end + 4..];
    if let Some(len) = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse::<usize>().ok())
    {
        return body.len() >= len;
    }
    if head.contains("transfer-encoding: chunked") {
        return body.ends_with(b"0\r\n\r\n");
    }
    true
}

/// Render the 1.5.5 data listener's answer to `request`, with a known body size when `sized`.
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

        cli.write_all(request).await.expect("request");
        let mut wire = Vec::new();
        let mut buf = [0_u8; 4096];
        while !answer_whole(&wire) {
            let n = tokio::time::timeout(std::time::Duration::from_secs(30), cli.read(&mut buf))
                .await
                .expect("v1.5.5's answer arrives whole")
                .expect("read");
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

    assert_eq!(
        String::from_utf8_lossy(block),
        "host: busbar.test\r\nconnection: keep-alive\r\ncontent-length: 5\r\ncontent-type: application/json\r\n"
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
fn a_detached_connection_as_sent_is_wiped_when_the_framing_goes() {
    let request: &[u8] = b"GET /ws HTTP/1.1\r\nhost: busbar.test\r\nconnection: upgrade\r\nupgrade: websocket\r\nauthorization: Bearer s3cret-token\r\n\r\n";
    let mut a = accepted();
    a.ingest(request, false);
    run(&mut a, SEC);
    a.detach().expect("handed over").expect("nothing answered");
    a.let_leftover_go();
    let (x, y) = a.leftover.as_ref().expect("still held").as_slices();
    assert!(
        x.len() + y.len() >= request.len(),
        "the leftover is wiped in place, not dropped early"
    );
    assert!(
        x.iter().chain(y).all(|b| *b == 0),
        "the credential line is still in the leftover"
    );
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
#[test]
fn an_h2_connection_keeps_no_copy_of_what_it_was_sent() {
    let mut a = accepted();
    a.ingest(H2_PREFACE, false);

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
#[test]
fn a_copy_past_the_head_limit_is_let_go_and_the_connection_kept() {
    const HEAD_LIMIT: usize = crate::door::engine::HEAD_MAX_BYTES;
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
    fn ticket(&self) -> Ticket {
        OP_TICKET
    }
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
    loop {
        let did = a.admit(k);
        if did.parked || !did.moved {
            break;
        }
        a.drive(now);
    }
}

/// Every finished request is removed from the connection's retained state.
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
fn h2_request() -> (Accepted, u64) {
    let mut a = accepted();
    a.ingest(H2_PREFACE, false);
    a.ingest(&frame(4, 0, 0, &[]), false);

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

/// One GET admitted on a fresh connection: the connection and its stream.
fn one_get() -> (Accepted, u64) {
    let mut a = accepted();
    a.ingest(GET, false);
    run(&mut a, SEC);
    let u = up(&mut a);
    assert_eq!(u.heads.len(), 1, "one request");
    (a, u.heads[0].0)
}

/// An invalid answer head is refused while retaining the stream for a valid answer.
#[test]
fn an_answer_head_that_cannot_be_one_is_refused_and_the_stream_kept() {
    let (mut a, stream) = one_get();
    for (status, block) in [
        (700, &b"content-type: text/plain\r\n"[..]),
        (999, b""),
        (99, b""),
        (200, b"x-bad: a\x01b\r\n"),
    ] {
        let r = a.emit(stream, block, true, status);
        assert!(r.is_err(), "status {status}: refused: {r:?}");
        assert!(a.answers_head(stream), "status {status}: still answerable");
    }
    assert!(
        a.emit(stream, b"content-type: text/plain\r\n", true, 599)
            .is_ok(),
        "the corrected head is the answer"
    );
    run(&mut a, 2 * SEC);
    let wire = a.take_wire(usize::MAX);
    assert!(
        wire.starts_with(b"HTTP/1.1 599 "),
        "{}",
        String::from_utf8_lossy(&wire)
    );
}

/// A malformed field line in an answer head is refused.
#[test]
fn an_answer_head_with_a_malformed_field_line_is_refused() {
    let (mut a, stream) = one_get();
    for block in [
        &b"content-type: text/plain\r\nx-frame-options: DENY"[..],
        b"content-type: text/plain\r\nno separator\r\nx-frame-options: DENY\r\n",
    ] {
        let r = a.emit(stream, block, true, 200);
        assert!(
            r.is_err(),
            "{:?}: refused, not cut short: {r:?}",
            String::from_utf8_lossy(block)
        );
        assert!(a.answers_head(stream), "still answerable");
    }
}

/// Dropping an HTTP/2 connection releases its in-flight stream state.
#[test]
fn a_dropped_h2_connection_with_a_stream_in_flight_frees_its_state() {
    let (a, stream) = h2_request();
    let respond = a
        .shared
        .lock()
        .expect("shared")
        .streams
        .get_mut(&stream)
        .and_then(|s| s.respond.take())
        .expect("the stream's answer is owed");
    assert!(!respond.is_canceled(), "the stream's task waits on it");
    drop(a);
    assert!(
        respond.is_canceled(),
        "the stream's task went with the framing"
    );
}

/// A detach attempted before the protocol switch completes can be retried.
#[test]
fn a_detach_before_the_switch_completes_can_be_made_again() {
    let mut a = accepted();
    let mut sent = GET.to_vec();
    sent.extend_from_slice(
        b"GET /v1/session HTTP/1.1\r\nhost: busbar.test\r\nconnection: upgrade\r\nupgrade: x-test\r\n\r\n\x81\x05hello",
    );
    a.ingest(&sent, false);
    run(&mut a, SEC);
    let first = up(&mut a).heads[0].0;

    let body = vec![b'x'; 300_000];
    a.emit(first, b"content-length: 300000\r\n", false, 200)
        .expect("head");
    a.emit(first, &body, true, 0).expect("body");
    run(&mut a, SEC);
    let stream = up(&mut a).heads[0].0;
    a.emit(
        stream,
        b"connection: upgrade\r\nupgrade: x-test\r\n",
        true,
        101,
    )
    .expect("101");
    run(&mut a, SEC);
    let early = a.detach().map(|r| r.map(|r| r.len()));
    assert!(
        early.is_err(),
        "the switch has not completed yet: {early:?}"
    );
    let _ = a.take_wire(usize::MAX);
    run(&mut a, SEC);
    let rest = a
        .detach()
        .expect("switched")
        .expect("the connection is handed over once the switch completes");
    let rest: Vec<u8> = rest.drain(..).collect();
    assert_eq!(rest, b"\x81\x05hello", "the bytes after the request");
}

/// A connection error reports its cause to the affected streams.
#[test]
fn a_connection_ended_by_an_error_tells_its_streams_the_cause() {
    let (mut a, stream) = h2_request();

    a.ingest(&frame(0, 0, 0, b"x"), false);
    run(&mut a, SEC);
    let told: Vec<String> = a
        .pieces()
        .drain(..)
        .filter(|p| p.failed && p.stream == stream)
        .map(|p| String::from_utf8_lossy(&p.bytes).into_owned())
        .collect();
    assert_eq!(told.len(), 1, "{told:?}");
    assert!(
        told[0].starts_with("the far side gave the stream up: ") && told[0].len() > 33,
        "the cause rides the words: {told:?}"
    );
}

/// A connection sending no request closes on the host's clock.
#[test]
fn a_connection_that_sends_no_request_is_closed_on_the_hosts_clock() {
    for (what, sent) in [
        ("part of the h2 preface", &b"PRI * HT"[..]),
        (
            "the h2 preface and no request",
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\0\0\0\x04\0\0\0\0\0",
        ),
    ] {
        let mut a = accepted();
        a.ingest(sent, false);
        run(&mut a, SEC);

        let _ = a.take_wire(usize::MAX);
        let at = a
            .next_deadline()
            .unwrap_or_else(|| panic!("{what}: a wake-up is asked for"));
        assert!(at <= SEC + 30 * SEC, "{what}: within the bound: {at}");
        run(&mut a, 31 * SEC);
        run(&mut a, 45 * SEC);
        assert!(a.ended(), "{what}: the connection is closed");
    }
}

/// The HTTP/2 frame types in `wire`, in order.
fn h2_types(wire: &[u8]) -> Vec<u8> {
    let (mut at, mut out) = (0, Vec::new());
    while at + 9 <= wire.len() {
        let len = usize::from(wire[at]) << 16
            | usize::from(wire[at + 1]) << 8
            | usize::from(wire[at + 2]);
        out.push(wire[at + 3]);
        at += 9 + len;
    }
    out
}

/// An idle HTTP/2 connection sends GOAWAY before closing; active work prevents idle closure.
#[test]
fn an_idle_h2_connection_is_closed_and_a_busy_one_is_not() {
    let (mut a, stream) = h2_request();
    run(&mut a, 40 * SEC);
    assert!(!a.ended(), "a request in flight keeps the connection");
    a.emit(stream, b"", true, 204).expect("answered");
    run(&mut a, 41 * SEC);
    let _ = a.take_wire(usize::MAX);
    run(&mut a, 60 * SEC);
    assert!(!a.ended(), "not yet idle for 30 s");
    run(&mut a, 72 * SEC);
    let wire = a.take_wire(usize::MAX);
    assert!(
        h2_types(&wire).contains(&7),
        "GOAWAY: {:?}",
        h2_types(&wire)
    );
    run(&mut a, 90 * SEC);
    assert!(a.ended(), "the idle connection is closed");
}

/// An admitted request whose body has stalled (nothing for 30 s), or trickles below 1 KiB/s once
#[test]
fn a_stalled_or_trickled_request_body_fails_its_stream() {
    let post =
        b"POST /v1/messages HTTP/1.1\r\nhost: busbar.test\r\ncontent-length: 100\r\n\r\nhello";
    let post0 = post;
    let failed = |a: &mut Accepted| a.pieces().drain(..).any(|p| p.failed);
    let mut a = accepted();
    a.ingest(post, false);
    run(&mut a, SEC);
    assert!(!failed(&mut a));
    assert!(
        a.next_deadline().is_some_and(|d| d <= 31 * SEC),
        "a wake-up is asked for the stalled body"
    );
    run(&mut a, 32 * SEC);
    assert!(failed(&mut a), "a body silent for 30 s fails its stream");

    let mut a = accepted();
    a.ingest(post, false);
    run(&mut a, SEC);
    let _ = failed(&mut a);
    a.ingest(b"x", false);
    run(&mut a, 13 * SEC);
    assert!(
        failed(&mut a),
        "a body under 1 KiB/s past 10 s fails its stream"
    );

    // The stall rule alone: a burst that keeps the rate above the floor for the whole stall, then
    // silence. Only the 30 s inter-frame bound can fail it (64 KiB over 31 s is 2 KiB/s).
    let len = 100_000;
    let post =
        format!("POST /v1/messages HTTP/1.1\r\nhost: busbar.test\r\ncontent-length: {len}\r\n\r\n");
    let mut a = accepted();
    let mut burst = post.into_bytes();
    burst.extend(vec![b'z'; 64 * 1024]);
    a.ingest(&burst, false);
    run(&mut a, SEC);
    let _ = failed(&mut a);
    run(&mut a, SEC + 30 * SEC - 1);
    assert!(
        !failed(&mut a),
        "a body silent for just under 30 s is not failed"
    );
    run(&mut a, SEC + 30 * SEC + 1);
    assert!(
        failed(&mut a),
        "a body silent for 30 s fails its stream while above the throughput floor"
    );

    // The grace: a body below the floor is not judged inside the first 10 s.
    let mut a = accepted();
    a.ingest(post0, false);
    run(&mut a, SEC);
    let _ = failed(&mut a);
    run(&mut a, SEC + 9 * SEC);
    assert!(
        !failed(&mut a),
        "a body under 1 KiB/s is not failed inside the 10 s grace"
    );

    // Negative control: a body arriving at 2 KiB/s is above the floor and survives past the grace.
    let len = 5 + 2048 * 15;
    let post = format!(
        "POST /v1/messages HTTP/1.1\r\nhost: busbar.test\r\ncontent-length: {len}\r\n\r\nhello"
    );
    let mut a = accepted();
    a.ingest(post.as_bytes(), false);
    run(&mut a, SEC);
    assert!(!failed(&mut a));
    let chunk = vec![b'y'; 2048];
    for n in 2..=16u64 {
        a.ingest(&chunk, false);
        run(&mut a, n * SEC);
        assert!(
            !failed(&mut a),
            "a body above 1 KiB/s survives at {n} s (past the 10 s grace from 11 s)"
        );
    }
    run(&mut a, 60 * SEC);
    assert!(
        !failed(&mut a),
        "a body that completed is not failed by the idle timer"
    );
}

/// RED (codeaudit r1-prod0-1): `Reply::drop` and `Accepted::drop` did nothing on a poisoned lock,
/// so a stream the peer gave up was never marked gone and a held body was freed unzeroised.
#[test]
fn a_poisoned_lock_does_not_stop_the_drops() {
    let q = Arc::new(Mutex::new(ReplyQ::default()));
    let q2 = q.clone();
    let _ = std::thread::spawn(move || {
        let _g = q2.lock().expect("lock");
        panic!("poison");
    })
    .join();
    assert!(q.is_poisoned());
    drop(Reply(q.clone(), None));
    assert!(
        q.lock().unwrap_or_else(PoisonError::into_inner).gone,
        "the reply is marked gone"
    );

    let (a, stream) = one_get();
    let shared = a.shared.clone();
    shared
        .lock()
        .expect("shared")
        .streams
        .get_mut(&stream)
        .expect("stream")
        .held = vec![7u8; 16];
    let s2 = shared.clone();
    let _ = std::thread::spawn(move || {
        let _g = s2.lock().expect("lock");
        panic!("poison");
    })
    .join();
    assert!(shared.is_poisoned());
    drop(a);
    let sh = shared.lock().unwrap_or_else(PoisonError::into_inner);
    assert!(
        sh.streams.values().all(|a| a.held.is_empty()),
        "the held body is let go"
    );
}

/// RED (codeaudit r1-prod0-2): a 1xx status was accepted as the final answer head (hyper then
/// rewrites it to a 500 and errors the connection); 101 is an answer only to an upgrade request.
#[test]
fn an_informational_final_head_is_refused_and_the_stream_kept() {
    let (mut a, stream) = one_get();
    for status in [100, 101, 102, 103] {
        let r = a.emit(stream, b"", true, status);
        assert!(r.is_err(), "status {status}: refused: {r:?}");
        assert!(a.answers_head(stream), "status {status}: still answerable");
    }
    assert!(a.emit(stream, b"", true, 200).is_ok());
}

/// r1-prod0-2: a host refusal of status 1xx is answered 500, as any out-of-range one is.
#[test]
fn a_refusal_with_an_informational_status_is_answered_500() {
    let (mut a, stream) = one_get();
    a.refuse(Some(stream), b"no", 103, false).expect("refused");
    run(&mut a, 2 * SEC);
    let wire = a.take_wire(usize::MAX);
    assert!(
        wire.starts_with(b"HTTP/1.1 500 "),
        "{}",
        String::from_utf8_lossy(&wire)
    );
}

/// RED (codeaudit r2-prod0-4): a refusal is never a switch; a 101 refusal of an upgrade request
/// was handed to hyper as a 101 that switches the connection.
#[test]
fn a_101_refusal_of_an_upgrade_request_is_answered_500() {
    let mut a = accepted();
    a.ingest(
        b"GET /ws HTTP/1.1\r\nhost: busbar.test\r\nconnection: upgrade\r\nupgrade: websocket\r\n\r\n",
        false,
    );
    run(&mut a, SEC);
    let stream = up(&mut a).heads[0].0;
    a.refuse(Some(stream), b"no", 101, false).expect("refused");
    run(&mut a, 2 * SEC);
    let wire = a.take_wire(usize::MAX);
    assert!(
        wire.starts_with(b"HTTP/1.1 500 "),
        "{}",
        String::from_utf8_lossy(&wire)
    );
}

/// RED (codeaudit r1-prod0-22): a `host` field present but not text was shown to the auth as an
/// empty authority, the same as a request with none. RFC 9112 3.2: an invalid host is refused;
/// the request is never handed in.
#[test]
fn a_request_with_a_non_text_host_is_never_handed_in() {
    let mut a = accepted();
    a.ingest(
        b"GET /v1/models HTTP/1.1\r\nhost: \xff\xfe\r\nuser-agent: t\r\n\r\n",
        false,
    );
    run(&mut a, SEC);
    let u = up(&mut a);
    assert!(u.heads.is_empty(), "nothing went up: {u:?}");
}

/// RED (codeaudit r2-prod0-2): an absolute-form target carrying userinfo (`user:pass@`) was
/// admitted and the credential bytes went up in the head's authority slot. RFC 9110 4.2.4: treat
/// it as an error; the request is never handed in and nothing carrying the credential goes up.
#[test]
fn an_absolute_form_target_with_userinfo_is_never_handed_in() {
    let mut a = accepted();
    a.ingest(
        b"GET http://alice:s3cret@api.example.com/v1/models HTTP/1.1\r\nhost: api.example.com\r\n\r\n",
        false,
    );
    run(&mut a, SEC);
    let u = up(&mut a);
    assert!(u.heads.is_empty(), "nothing went up: {u:?}");
}

#[test]
fn detached_unanswered_credentials_are_wiped_on_full_drain_and_abandonment() {
    use crate::wipe_probe::Probe;
    let request = b"GET /v1/session HTTP/1.1\r\nhost: busbar.test\r\nauthorization: Bearer detach-canary\r\nconnection: upgrade\r\nupgrade: x-test\r\n\r\n";
    for finish in [false, true] {
        let mut a = accepted();
        a.ingest(request, false);
        run(&mut a, SEC);
        assert_eq!(up(&mut a).heads.len(), 1);
        let probe = Probe::start();
        let mut handed = Vec::new();
        loop {
            let rest = a
                .detach()
                .expect("detaches")
                .expect("unanswered connection");
            let n = rest.len().min(7);
            if n == 0 {
                break;
            }
            let taken = crate::door::take_detached(rest, n);
            handed.extend_from_slice(&taken);
            drop(taken);
            if !finish {
                break;
            }
        }
        assert_eq!(
            handed,
            if finish {
                request.as_slice()
            } else {
                &request[..7]
            }
        );
        drop(a);
        probe
            .finish()
            .assert_wiped_on_linux(&["detach leftover", "detach taken"]);
    }
}

#[test]
fn switched_read_ahead_and_each_owned_detach_copy_are_wiped() {
    use crate::wipe_probe::Probe;
    let mut a = accepted();
    a.ingest(b"GET /v1/session HTTP/1.1\r\nhost: busbar.test\r\nconnection: upgrade\r\nupgrade: x-test\r\n\r\n", false);
    run(&mut a, SEC);
    let stream = up(&mut a).heads[0].0;
    a.emit(
        stream,
        b"connection: upgrade\r\nupgrade: x-test\r\n",
        true,
        101,
    )
    .unwrap();
    run(&mut a, SEC);

    let payload = b"switched-credential-canary".repeat(2000);
    a.ingest(&payload, false);
    let probe = Probe::start();
    let mut handed = Vec::new();
    loop {
        let rest = a
            .detach()
            .expect("switch completed")
            .expect("switched bytes");
        let n = rest.len().min(113);
        if n == 0 {
            break;
        }
        let taken = crate::door::take_detached(rest, n);
        handed.extend_from_slice(&taken);
        drop(taken);
    }
    assert_eq!(
        handed, payload,
        "every residual byte reaches the next framer unchanged"
    );
    drop(a);
    let report = probe.finish();
    assert!(
        report.allocations_for("detach leftover") >= 2,
        "growth freed an earlier residual allocation"
    );
    report.assert_wiped_on_linux(&["detach read", "detach leftover", "detach taken"]);
}

#[test]
fn a_host_refusal_is_not_reported_again_as_an_abandoned_request() {
    for head_sent in [false, true] {
        let mut a = accepted();
        a.ingest(
            b"POST /v1/messages HTTP/1.1\r\nhost: test\r\ncontent-length: 100\r\n\r\nprefix",
            false,
        );
        run(&mut a, SEC);
        let stream = up(&mut a).heads[0].0;
        if head_sent {
            a.emit(stream, b"content-type: text/plain\r\n", false, 200)
                .unwrap();
            run(&mut a, SEC);
            a.refuse(Some(stream), b"", 0, true).unwrap();
        } else {
            a.refuse(
                Some(stream),
                b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\n\r\n",
                0,
                false,
            )
            .unwrap();
        }
        run(&mut a, SEC);

        a.ingest(b"", true);
        run(&mut a, SEC);
        assert!(a.ended());
        assert!(
            !up(&mut a).failed,
            "the host already owns this refusal's end"
        );
    }
    let mut a = accepted();
    a.ingest(
        b"POST /v1/messages HTTP/1.1\r\nhost: test\r\ncontent-length: 100\r\n\r\nprefix",
        false,
    );
    run(&mut a, SEC);
    assert_eq!(up(&mut a).heads.len(), 1);
    a.ingest(b"", true);
    run(&mut a, SEC);
    assert!(up(&mut a).failed, "a genuine peer abandonment still fails");
    run(&mut a, SEC);
    assert!(!up(&mut a).failed, "the peer abandonment is reported once");
}

#[test]
fn a_partial_http2_preface_is_not_detached_as_an_http1_upgrade() {
    for split in 1..H2_PREFACE.len() {
        let mut a = accepted();
        a.ingest(&H2_PREFACE[..split], false);
        assert!(
            a.detach().unwrap().is_none(),
            "preface prefix length {split}"
        );
        assert!(!a.ended(), "an undecided protocol keeps its input");
        a.ingest(&H2_PREFACE[split..], false);
        assert_eq!(a.agreed(), offer_position(b"h2"));
        assert!(
            a.detach().unwrap().is_none(),
            "the completed h2 connection stays here"
        );
    }
    let mut a = accepted();
    let request = b"POST / HTTP/1.1\r\nhost: test\r\nconnection: upgrade\r\nupgrade: other\r\n\r\n";
    a.ingest(request, false);
    assert_eq!(
        a.detach()
            .unwrap()
            .unwrap()
            .iter()
            .copied()
            .collect::<Vec<_>>(),
        request
    );
}

#[test]
fn dropping_an_answer_recovers_its_poisoned_queue_and_records_the_end() {
    let queue = Arc::new(Mutex::new(ReplyQ::default()));
    let poison = Arc::clone(&queue);
    let _ = std::panic::catch_unwind(move || {
        let _guard = poison.lock().unwrap();
        panic!("the isolated test queue is poisoned");
    });
    drop(Reply(Arc::clone(&queue), None));
    assert!(queue.lock().unwrap_or_else(PoisonError::into_inner).gone);
}

#[test]
fn the_admitted_body_copy_keeps_wiping_custody_until_the_host_takes_it() {
    struct BodyOpen;

    impl Kernel for BodyOpen {
        fn ticket(&self) -> Ticket {
            OP_TICKET
        }

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
            Poll::Ready(Ok((FLOW_CONTINUE, UnitRef { id: 1, mac: 1 }, Vec::new())))
        }

        fn hand_in(
            &mut self,
            seq: u32,
            auth: AuthRef,
            unit: UnitRef,
            line: u32,
            stream: u64,
            head: &HeadViewArgs<'_>,
        ) -> Result<(u32, UnitRef), ServiceError> {
            Open.hand_in(seq, auth, unit, line, stream, head)
        }

        fn refuse(
            &mut self,
            seq: u32,
            unit: UnitRef,
            cause: u32,
            line: u32,
            stream: u64,
            head: &HeadViewArgs<'_>,
        ) -> Result<RefusalCopy, ServiceError> {
            Open.refuse(seq, unit, cause, line, stream, head)
        }
    }

    let mut a = Accepted::accept(
        SEC,
        vec![Line::any_needing(
            1,
            busbar_contract::abi::auth::POINT_HEAD_BODY,
            1024,
        )],
    );
    let probe = crate::wipe_probe::Probe::start();
    a.ingest(
        b"POST / HTTP/1.1\r\nhost: test\r\ncontent-length: 14\r\n\r\nrequest-secret",
        false,
    );
    run_with(&mut a, SEC, &mut BodyOpen);
    assert!(a
        .pieces()
        .iter()
        .any(|piece| piece.bytes.as_ref() == b"request-secret"));
    drop(a);
    probe.finish().assert_wiped_on_linux(&["admitted body"]);
}

#[test]
fn final_fields_follow_data_on_the_actual_http1_wire_and_keep_repeated_values() {
    let mut a = accepted();
    a.ingest(
        b"GET / HTTP/1.1\r\nhost: test\r\nte: trailers\r\n\r\n",
        false,
    );
    run(&mut a, SEC);
    let stream = up(&mut a).heads[0].0;
    a.emit(stream, b"trailer: x-check\r\n", false, 201).unwrap();
    a.emit(stream, b"hello", false, 0).unwrap();
    a.emit_trailers(stream, b"x-check: first\r\nx-check: second\r\n")
        .unwrap();
    run(&mut a, SEC);
    let wire = undated(a.take_wire(usize::MAX));
    assert!(wire.starts_with(b"HTTP/1.1 201 Created\r\n"));
    assert!(
        wire.ends_with(b"5\r\nhello\r\n0\r\nx-check: first\r\nx-check: second\r\n\r\n"),
        "the fields terminate chunk framing, never appear as body data: {:?}",
        String::from_utf8_lossy(&wire)
    );
    assert!(a.emit_trailers(stream, b"x-check: twice\r\n").is_err());
    assert!(a.emit(stream, b"after", true, 0).is_err());
}

#[test]
fn a_rejected_terminal_field_block_leaves_the_answer_correctable() {
    let (mut a, stream) = h2_request();
    assert!(a.emit_trailers(stream, b"x-check: before\r\n").is_err());
    assert!(a.answers_head(stream));
    a.emit(stream, b"", false, 200).unwrap();
    a.emit(stream, b"hello", false, 0).unwrap();
    for malformed in [
        b"x-check: good\r\nbroken".as_slice(),
        b"x-check: a\0b\r\n",
        b"bad name: value\r\n",
        b"connection: close\r\n",
    ] {
        assert!(a.emit_trailers(stream, malformed).is_err());
        let shared = a.shared.lock().unwrap();
        let queue = shared.streams[&stream]
            .reply
            .as_ref()
            .unwrap()
            .lock()
            .unwrap();
        assert!(
            !queue.ended && queue.trailers.is_none(),
            "no malformed prefix accepted"
        );
    }
    a.emit_trailers(stream, b"x-check: valid\r\n").unwrap();
    run(&mut a, SEC);
    assert_eq!(
        h2_types(&a.take_wire(usize::MAX)),
        [1, 0, 1],
        "HEADERS, DATA, terminal HEADERS"
    );
}

#[test]
fn http1_refuses_trailers_that_hyper_cannot_deliver() {
    for (request, head) in [
        (
            b"GET / HTTP/1.1\r\nhost: test\r\n\r\n".as_slice(),
            b"trailer: x-check\r\n".as_slice(),
        ),
        (b"GET / HTTP/1.1\r\nhost: test\r\nte: trailers\r\n\r\n", b""),
        (
            b"GET / HTTP/1.1\r\nhost: test\r\nte: trailers\r\n\r\n",
            b"trailer: x-check\r\ncontent-length: 5\r\n",
        ),
        (
            b"HEAD / HTTP/1.1\r\nhost: test\r\nte: trailers\r\n\r\n",
            b"trailer: x-check\r\n",
        ),
    ] {
        let mut a = accepted();
        a.ingest(request, false);
        run(&mut a, SEC);
        let stream = up(&mut a).heads[0].0;
        a.emit(stream, head, false, 200).unwrap();
        assert!(a.emit_trailers(stream, b"x-check: value\r\n").is_err());
    }
}

#[test]
fn an_http2_client_decodes_the_actual_trailer_wire_as_fields_after_the_body() {
    let (mut a, stream) = h2_request();
    a.emit(stream, b"", false, 201).unwrap();
    a.emit(stream, b"hello", false, 0).unwrap();
    a.emit_trailers(
        stream,
        b"grpc-status: 0\r\nx-check: first\r\nx-check: second\r\n",
    )
    .unwrap();
    run(&mut a, SEC);
    let mut wire = frame(4, 0, 0, &[]);
    wire.extend(a.take_wire(usize::MAX));
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(5), async {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let (client, mut peer) = tokio::io::duplex(64 * 1024);
                let (mut sender, connection) = h2::client::handshake(client).await.unwrap();
                let task = tokio::spawn(connection);
                let request = http::Request::builder()
                    .uri("http://busbar.test/")
                    .body(())
                    .unwrap();
                let (response, _) = sender.send_request(request, true).unwrap();

                let mut preface = [0; 24];
                peer.read_exact(&mut preface).await.unwrap();
                assert_eq!(&preface, H2_PREFACE);
                let mut sent = false;
                for _ in 0..16 {
                    let mut head = [0; 9];
                    peer.read_exact(&mut head).await.unwrap();
                    let len = (usize::from(head[0]) << 16)
                        | (usize::from(head[1]) << 8)
                        | usize::from(head[2]);
                    let mut payload = vec![0; len];
                    peer.read_exact(&mut payload).await.unwrap();
                    if head[3] == 1 && u32::from_be_bytes(head[5..9].try_into().unwrap()) == 1 {
                        sent = true;
                        break;
                    }
                }
                assert!(sent, "the client opened the response's stream");
                peer.write_all(&wire).await.unwrap();
                let response = tokio::time::timeout(Duration::from_secs(5), response)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(response.status(), 201);
                let mut body = response.into_body();
                let mut data = Vec::new();
                while let Some(chunk) = body.data().await {
                    data.extend_from_slice(&chunk.unwrap());
                }
                assert_eq!(data, b"hello");
                let trailers = body.trailers().await.unwrap().unwrap();
                assert_eq!(trailers["grpc-status"], "0");
                let repeated: Vec<_> = trailers
                    .get_all("x-check")
                    .iter()
                    .map(|value| value.as_bytes())
                    .collect();
                assert_eq!(repeated, [b"first".as_slice(), b"second".as_slice()]);
                task.abort();
            })
            .await
            .expect("the complete body and trailers arrive within the bound");
        });
}

#[test]
fn http1_trailer_negotiation_matches_hypers_comma_and_repeated_te_fields() {
    for te in ["te: gzip, Trailers\r\n", "te: gzip\r\nte: trailers\r\n"] {
        let mut a = accepted();
        a.ingest(
            format!("GET / HTTP/1.1\r\nhost: test\r\n{te}\r\n").as_bytes(),
            false,
        );
        run(&mut a, SEC);
        let stream = up(&mut a).heads[0].0;
        a.emit(stream, b"trailer: X-Check\r\n", false, 200).unwrap();
        a.emit_trailers(stream, b"x-check: kept\r\n").unwrap();
        run(&mut a, SEC);
        assert!(a
            .take_wire(usize::MAX)
            .ends_with(b"0\r\nx-check: kept\r\n\r\n"));
    }
}

#[derive(Default)]
struct CapturedAdmission {
    auth: Vec<(String, Vec<u8>)>,
    handed: Vec<(String, Vec<u8>)>,
}

impl Kernel for CapturedAdmission {
    fn ticket(&self) -> Ticket {
        OP_TICKET
    }

    fn auth_call(
        &mut self,
        _: u32,
        _: AuthRef,
        _: UnitRef,
        _: u32,
        _: u64,
        request: &HeadViewArgs<'_>,
        _: Option<&[u8]>,
    ) -> Pend<AuthCalled> {
        self.auth = request
            .fields
            .iter()
            .map(|(name, value)| ((*name).to_owned(), value.to_vec()))
            .collect();
        Poll::Ready(Ok((
            FLOW_CONTINUE,
            UnitRef { id: 1, mac: 1 },
            vec![("authorization".into(), Place::Field)],
        )))
    }

    fn hand_in(
        &mut self,
        _: u32,
        _: AuthRef,
        _: UnitRef,
        _: u32,
        _: u64,
        request: &HeadViewArgs<'_>,
    ) -> Result<(u32, UnitRef), ServiceError> {
        self.handed = request
            .fields
            .iter()
            .map(|(name, value)| ((*name).to_owned(), value.to_vec()))
            .collect();
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

/// The actual accepted-side parser, auth call, hand-in and emitted frame must agree. A filter
#[test]
fn an_accepted_request_preserves_the_exact_head_handed_in_after_auth() {
    for (wire, body) in [
        (b"GET /healthz HTTP/1.1\r\nhost: busbar.test\r\nconnection: close\r\ncontent-length: 0\r\nauthorization: signed-credential\r\n\r\n".as_slice(), b"".as_slice()),
        (b"POST /signed?x=1 HTTP/1.1\r\nhost: busbar.test\r\nconnection: close, x-signed\r\nx-signed: first\r\nx-signed: second\r\ncontent-length: 3\r\nauthorization: signed-credential\r\n\r\nabc".as_slice(), b"abc".as_slice()),
    ] {
        for authenticated in [false, true] {
            let line = if authenticated {
                Line::any_needing(1, busbar_contract::abi::auth::POINT_HEAD, 0)
            } else { Line::any(1) };
            let mut a = Accepted::accept(SEC, vec![line]);
            let mut kernel = CapturedAdmission::default();
            a.ingest(wire, false);
            run_with(&mut a, SEC, &mut kernel);
            let emitted = up(&mut a);
            assert_eq!(emitted.heads.len(), 1);
            let fields: Vec<_> = fields::lines(&emitted.heads[0].2)
                .map(|(name, value)| (std::str::from_utf8(name).unwrap().to_owned(), value.to_vec()))
                .collect();
            assert_eq!(fields, kernel.handed, "the host's strict claim sees the admitted fields");
            assert!(fields.iter().any(|(name, value)| name == "connection" && value.starts_with(b"close")));
            assert!(fields.iter().any(|(name, _)| name == "content-length"));
            assert_eq!(emitted.body, body);
            assert!(emitted.whole);
            if authenticated {
                assert!(kernel.auth.iter().any(|(name, value)| name == "authorization" && value == b"signed-credential"));
                assert!(kernel.auth.iter().any(|(name, _)| name == "connection"));
                assert!(kernel.auth.iter().any(|(name, _)| name == "content-length"));
                assert!(!fields.iter().any(|(name, _)| name == "authorization"));
                let original_without_credential: Vec<_> = kernel.auth.into_iter()
                    .filter(|(name, _)| name != "authorization").collect();
                assert_eq!(fields, original_without_credential);
            } else {
                assert!(kernel.auth.is_empty(), "a none line calls no auth");
            }
        }
        let mut refused = Accepted::accept(SEC, vec![Line::any_needing(
            1, busbar_contract::abi::auth::POINT_HEAD, 0)]);
        refused.ingest(wire, false);
        run_with(&mut refused, SEC, &mut Refusing);
        assert!(up(&mut refused).heads.is_empty(), "rejected auth emits no accepted request");
        assert!(refused.take_wire(usize::MAX).starts_with(b"HTTP/1.1 401 Unauthorized\r\n"));
    }
}

#[test]
fn a_write_half_close_preserves_a_complete_request_parked_on_auth() {
    let (mut a, mut kernel) = selecting();
    kernel.policy = selected_policy(2, 22, POINT_HEAD, 8);
    kernel.wait = true;
    a.ingest(
        b"POST / HTTP/1.1\r\nhost: test\r\ncontent-length: 4\r\n\r\nabcd",
        false,
    );
    run_with(&mut a, SEC, &mut kernel);
    assert!(up(&mut a).heads.is_empty());
    a.ingest(b"", true);
    run_with(&mut a, SEC, &mut kernel);
    assert!(!a.ended(), "read EOF cannot abandon pending admission");
    assert!(!up(&mut a).failed);
    kernel.wait = false;
    run_with(&mut a, SEC, &mut kernel);
    let got = up(&mut a);
    assert_eq!(got.heads.len(), 1);
    assert_eq!(got.body, b"abcd");
    assert!(got.whole);
    assert!(!got.failed);
    a.emit(got.heads[0].0, b"content-length: 4\r\n", false, 200)
        .expect("answer head after EOF");
    a.emit(got.heads[0].0, b"done", true, 0)
        .expect("answer body after EOF");
    a.drive(SEC);
    let wire = a.take_wire(usize::MAX);
    assert!(wire.windows(4).any(|part| part == b"done"));
}

#[test]
fn a_write_half_close_still_fails_an_incomplete_request_body() {
    let mut a = accepted();
    a.ingest(
        b"POST / HTTP/1.1\r\nhost: test\r\ncontent-length: 4\r\n\r\nab",
        false,
    );
    run(&mut a, SEC);
    let first = up(&mut a);
    assert_eq!(first.heads.len(), 1);
    assert!(!first.whole);
    a.ingest(b"", true);
    run(&mut a, SEC);
    let tail = up(&mut a);
    assert!(
        tail.failed,
        "EOF cannot turn a truncated body into a whole request"
    );
    assert!(!tail.whole);
}

#[test]
fn a_fixed_length_wire_end_still_accepts_the_hosts_empty_logical_end() {
    let mut a = accepted();
    a.ingest(b"GET /first HTTP/1.1\r\nhost: test\r\n\r\nGET /second HTTP/1.1\r\nhost: test\r\n\r\n", true);
    run(&mut a, SEC);
    let first = up(&mut a).heads[0].0;
    a.emit(first, b"content-length: 2\r\n", false, 200).unwrap();
    a.emit(first, b"hi", false, 0).unwrap();
    run(&mut a, SEC);
    let next = up(&mut a);
    assert!(!next.failed, "exact wire length is not peer abandonment");
    assert_eq!(next.heads.len(), 1);
    assert!(a.shared.lock().unwrap().streams.contains_key(&first), "logical End is still owed");
    assert!(a.emit(first, b"extra", true, 0).is_err(), "wire completion cannot accept extra bytes");
    assert!(a.emit_trailers(first, b"x-late: no\r\n").is_err(), "fixed-length completion cannot accept trailers");
    a.emit(first, b"", true, 0).expect("empty logical End after wire completion");
    assert!(a.emit(first, b"", true, 0).is_err(), "logical End is accepted exactly once");
    a.emit(next.heads[0].0, b"content-length: 4\r\n", false, 200).unwrap();
    a.emit(next.heads[0].0, b"done", true, 0).unwrap();
    run(&mut a, SEC);
    assert!(!up(&mut a).failed);
    let wire = a.take_wire(usize::MAX);
    assert_eq!(wire.windows(15).filter(|w| *w == b"HTTP/1.1 200 OK").count(), 2);
    assert!(wire.windows(4).any(|w| w == b"done"));
}

#[test]
fn a_reset_before_the_declared_answer_length_still_fails() {
    let (mut a, stream) = h2_request();
    a.emit(stream, b"content-length: 4\r\n", false, 200).unwrap();
    a.emit(stream, b"hi", false, 0).unwrap();
    run(&mut a, SEC);
    reset(&mut a);
    assert!(up(&mut a).failed, "a truncated declared-length answer is abandoned");
    assert!(a.emit(stream, b"", true, 0).is_err());
}


#[test]
fn an_http1_consumer_drop_before_the_declared_response_length_fails() {
    let mut a = accepted();
    a.ingest(b"GET / HTTP/1.1\r\nhost: test\r\n\r\n", false);
    run(&mut a, SEC);
    let stream = up(&mut a).heads[0].0;
    a.emit(stream, b"content-length: 4\r\n", false, 200).unwrap();
    a.emit(stream, b"hi", false, 0).unwrap();
    run(&mut a, SEC);
    {
        let sh = a.shared.lock().unwrap();
        let q = sh.streams[&stream].reply.as_ref().unwrap().lock().unwrap();
        assert_eq!(q.declared, Some(4));
        assert_eq!(q.delivered, 2);
        assert!(!q.ended);
    }
    // Drop the real Hyper consumer while the response remains incomplete.
    a.conn = None;
    run(&mut a, SEC);
    assert!(up(&mut a).failed);
    assert!(a.emit(stream, b"", true, 0).is_err());
}

#[test]
fn conflicting_transfer_encoding_and_length_cannot_claim_wire_completion() {
    let mut a = accepted();
    a.ingest(b"GET / HTTP/1.1\r\nhost: test\r\n\r\n", false);
    run(&mut a, SEC);
    let stream = up(&mut a).heads[0].0;
    a.emit(stream, b"content-length: 0\r\ntransfer-encoding: chunked\r\n", false, 200).unwrap();
    {
        let sh = a.shared.lock().unwrap();
        let q = sh.streams[&stream].reply.as_ref().unwrap().lock().unwrap();
        assert_eq!(q.declared, None);
        assert!(!wire_body_complete(&q));
    }
    run(&mut a, SEC);
    assert!(up(&mut a).failed, "invalid response framing is not a completed body");
    assert!(a.emit(stream, b"", true, 0).is_err());
}
