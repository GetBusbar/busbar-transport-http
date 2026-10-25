// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The engine against hand-written far ends: what 1.5.5's client (reqwest 0.12) did with a
//! response's trailers and with its one request timeout.

use super::*;

const SEC: u64 = 1_000_000_000;

fn posture(timeout_secs: u64) -> Posture {
    Posture {
        keep_alive_interval: Some(Duration::from_secs(30)),
        keep_alive_timeout: Duration::from_secs(10),
        adaptive_window: true,
        request_timeout: Duration::from_secs(timeout_secs),
        max_body_bytes: 32 * 1024 * 1024,
    }
}

/// A framing with one GET sent on stream 1, the far end not yet heard from.
fn asked(proto: Proto, timeout_secs: u64) -> Framing {
    let mut f = Framing::dial("http://127.0.0.1:9", proto, posture(timeout_secs), 0).expect("dial");
    // `begin` drives the handshake in its own op, before any request exists (as the door does).
    f.drive(0, 0);
    f.emit(1, b"GET /x HTTP/1.1\r\n\r\n", 0, 0).expect("emit");
    f.drive(0, 0);
    let sent = f.take_wire(usize::MAX);
    assert!(!sent.is_empty(), "the request went out");
    f
}

/// Every body byte handed up on stream 1 (the head piece and failure pieces excluded), and whether
/// the stream ended whole.
fn body(f: &mut Framing) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut whole = false;
    for p in f.pieces().drain(..) {
        if p.stream != 1 || p.status.is_some() || p.failed {
            continue;
        }
        if p.bytes.is_empty() {
            whole = true;
        }
        out.extend_from_slice(&p.bytes);
    }
    (out, whole)
}

fn failed(f: &mut Framing) -> bool {
    f.failure().is_some() || f.pieces().iter().any(|p| p.failed)
}

/// One HTTP/2 frame.
fn h2(ty: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let n = payload.len();
    let mut v = vec![(n >> 16) as u8, (n >> 8) as u8, n as u8, ty, flags];
    v.extend_from_slice(&stream.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// A literal header field, new name, without indexing, no Huffman.
fn literal(name: &str, value: &str) -> Vec<u8> {
    let mut v = vec![0x00, name.len() as u8];
    v.extend_from_slice(name.as_bytes());
    v.push(value.len() as u8);
    v.extend_from_slice(value.as_bytes());
    v
}

/// 1.5.5 read a response body through reqwest, which yields data frames only: a chunked
/// response's trailer section never reached the body.
#[test]
fn an_h1_trailer_section_is_not_body() {
    let mut f = asked(Proto::H1, 300);
    f.ingest(
        b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\ntrailer: x-t\r\n\r\n\
          5\r\nhello\r\n0\r\nx-t: 1\r\n\r\n",
        false,
    );
    f.drive(SEC, 0);
    let (b, whole) = body(&mut f);
    assert_eq!(
        String::from_utf8_lossy(&b),
        "hello",
        "the body is the payload only"
    );
    assert!(whole, "the response ended whole");
}

/// The same on HTTP/2: a trailing HEADERS frame is not body.
#[test]
fn an_h2_trailer_block_is_not_body() {
    let mut f = asked(Proto::H2, 300);
    let mut far = h2(4, 0, 0, &[]);
    far.extend(h2(1, 0x4, 1, &[0x88]));
    far.extend(h2(0, 0, 1, b"hello"));
    far.extend(h2(1, 0x4 | 0x1, 1, &literal("grpc-status", "0")));
    f.ingest(&far, false);
    f.drive(SEC, 0);
    let (b, whole) = body(&mut f);
    assert_eq!(
        String::from_utf8_lossy(&b),
        "hello",
        "the body is the payload only"
    );
    assert!(whole, "the response ended whole");
}

/// What stream 1's head piece states as the answer's declared body length (`None`: no head yet).
fn declared(f: &mut Framing) -> Option<Option<u64>> {
    f.pieces()
        .iter()
        .find(|p| p.stream == 1 && p.fields)
        .map(|p| p.declared_len)
}

/// The head piece states the body length the answer's head declared (`Content-Length`, busbar
/// #1032's `PIECE_HAS_DECLARED_LEN`), on HTTP/1.1 and on HTTP/2, so the host's pre-body download
/// cap reads it before a body byte; a head that declares none (a chunked answer) states none.
#[test]
fn the_head_piece_states_the_body_length_the_head_declared() {
    let mut f = asked(Proto::H1, 300);
    f.ingest(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello", false);
    f.drive(SEC, 0);
    assert_eq!(declared(&mut f), Some(Some(5)), "h1: the declared length");

    let mut f = asked(Proto::H1, 300);
    f.ingest(
        b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        false,
    );
    f.drive(SEC, 0);
    assert_eq!(declared(&mut f), Some(None), "h1 chunked: none declared");

    let mut f = asked(Proto::H2, 300);
    let mut block = vec![0x88];
    block.extend(literal("content-length", "5"));
    let mut far = h2(4, 0, 0, &[]);
    far.extend(h2(1, 0x4, 1, &block));
    far.extend(h2(0, 0x1, 1, b"hello"));
    f.ingest(&far, false);
    f.drive(SEC, 0);
    assert_eq!(declared(&mut f), Some(Some(5)), "h2: the declared length");
}

/// The length a head declares is read whole or not at all: identical duplicates are one length,
/// and a disagreeing or malformed value declares none.
#[test]
fn a_declared_length_is_one_valid_content_length() {
    let head = |values: &[&str]| {
        let mut h = http::HeaderMap::new();
        for v in values {
            h.append(
                http::header::CONTENT_LENGTH,
                http::HeaderValue::from_str(v).expect("value"),
            );
        }
        declared_len(&h)
    };
    assert_eq!(head(&[]), None);
    assert_eq!(head(&["12"]), Some(12));
    assert_eq!(head(&["12, 12"]), Some(12));
    assert_eq!(head(&["12", "12"]), Some(12));
    assert_eq!(head(&["12", "13"]), None);
    assert_eq!(head(&["+12"]), None);
    assert_eq!(head(&[""]), None);
    assert_eq!(head(&["99999999999999999999999"]), None);
}

/// 1.5.5's `upstream_request_timeout_secs` was reqwest's TOTAL timeout: one clock from the send
/// to the body's end (reqwest 0.12 wraps the response body in the same sleep). A response still
/// arriving at the deadline is cut there, on HTTP/1.1 ...
#[test]
fn a_body_still_arriving_at_the_request_timeout_is_cut_h1() {
    let mut f = asked(Proto::H1, 5);
    f.ingest(
        b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n",
        false,
    );
    f.drive(SEC, 0);
    assert_eq!(body(&mut f).0, b"hello");
    assert_eq!(
        f.next_deadline(),
        Some(5 * SEC),
        "the body wait is bounded by the one request clock"
    );
    f.drive(5 * SEC - 1, 0);
    assert!(!failed(&mut f), "not before the deadline");
    f.drive(5 * SEC, 0);
    assert!(failed(&mut f), "cut at the request timeout");
}

/// ... and on HTTP/2, where it ends that stream alone.
#[test]
fn a_body_still_arriving_at_the_request_timeout_is_cut_h2() {
    let mut f = asked(Proto::H2, 5);
    let mut far = h2(4, 0, 0, &[]);
    far.extend(h2(1, 0x4, 1, &[0x88]));
    far.extend(h2(0, 0, 1, b"hello"));
    f.ingest(&far, false);
    f.drive(SEC, 0);
    assert_eq!(body(&mut f).0, b"hello");
    f.drive(5 * SEC - 1, 0);
    assert!(!failed(&mut f), "not before the deadline");
    f.drive(5 * SEC, 0);
    assert!(
        f.pieces().iter().any(|p| p.stream == 1 && p.failed),
        "the stream is cut at the request timeout"
    );
}

/// 1.5.5 put no transport cap on a RESPONSE: a streamed body ran as long as the far end sent it
/// (the plane's own buffered reads were capped, the incremental path was not). One larger than
/// `limits.request_body_max_bytes` (32 MiB) passes through whole.
#[test]
fn a_streamed_response_past_the_request_body_cap_passes_through() {
    let mut f = asked(Proto::H1, 300);
    f.ingest(
        b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n",
        false,
    );
    f.drive(SEC, 0);
    let chunk = vec![b'x'; 1024 * 1024];
    let mut seen = 0usize;
    for _ in 0..33 {
        let mut wire = format!("{:x}\r\n", chunk.len()).into_bytes();
        wire.extend_from_slice(&chunk);
        wire.extend_from_slice(b"\r\n");
        f.ingest(&wire, false);
        f.drive(SEC, 0);
        assert!(!failed(&mut f), "cut after {seen} bytes");
        seen += body(&mut f).0.len();
    }
    f.ingest(b"0\r\n\r\n", false);
    f.drive(SEC, 0);
    let (rest, whole) = body(&mut f);
    seen += rest.len();
    assert_eq!(seen, 33 * 1024 * 1024);
    assert!(whole);
}

/// The clock is the ATTEMPT's, stamped before the dial: a connect that took 200s leaves the
/// exchange 100s of a 300s timeout, so a body still arriving at 300s from the attempt's start is
/// cut there, not 300s after the request went out.
#[test]
fn a_slow_connect_and_a_slow_body_share_one_attempt_clock() {
    let connected = 200 * SEC;
    let mut f =
        Framing::dial("http://127.0.0.1:9", Proto::H1, posture(300), connected).expect("dial");
    f.drive(connected, 0);
    f.emit(1, b"GET /x HTTP/1.1\r\n\r\n", connected, 300 * SEC)
        .expect("emit");
    f.drive(connected, 0);
    assert!(!f.take_wire(usize::MAX).is_empty(), "the request went out");
    f.ingest(
        b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n",
        false,
    );
    f.drive(connected + SEC, 0);
    assert_eq!(body(&mut f).0, b"hello");
    f.drive(300 * SEC - 1, 0);
    assert!(!failed(&mut f), "not before the attempt's deadline");
    f.drive(300 * SEC, 0);
    assert!(
        failed(&mut f),
        "cut at 300s from the attempt's start, not from the send"
    );
}

/// The request bytes one emitted message puts on the wire, on HTTP/1.1.
fn h1_wire(message: &[u8]) -> String {
    let mut f = Framing::dial("http://127.0.0.1:9", Proto::H1, posture(30), 0).expect("dial");
    f.drive(0, 0);
    f.emit(1, message, 0, 0).expect("emit");
    f.drive(0, 0);
    String::from_utf8_lossy(&f.take_wire(usize::MAX)).into_owned()
}

/// RED (THE DESIGN §5 l.722: "When the caller sets none, the http door adds `accept: */*`, and on
/// h1 the host header and origin-form target: the http transport owns the client defaults
/// (owner-agreed 2026-09-28)"): a request naming no `accept` leaves with 1.5.5's client default,
/// after the caller's fields and before `host`, as reqwest wrote it; a request naming one leaves
/// with exactly that one.
#[test]
fn the_door_adds_accept_when_the_caller_sets_none() {
    let bare = h1_wire(b"GET /x HTTP/1.1\r\nx-a: 1\r\n\r\n");
    assert!(bare.starts_with("GET /x HTTP/1.1\r\n"), "{bare:?}");
    assert!(
        bare.to_ascii_lowercase()
            .contains("x-a: 1\r\naccept: */*\r\nhost: 127.0.0.1:9\r\n"),
        "{bare:?}"
    );
    let named = h1_wire(b"GET /x HTTP/1.1\r\naccept: application/json\r\n\r\n");
    let lower = named.to_ascii_lowercase();
    assert_eq!(lower.matches("accept:").count(), 1, "{named:?}");
    assert!(lower.contains("accept: application/json\r\n"), "{named:?}");
}

/// What one emit of `message` on `stream` puts on the wire.
fn sent(f: &mut Framing, stream: u64, message: &[u8]) -> String {
    f.emit(stream, message, 0, 0).expect("emit");
    f.drive(0, 0);
    String::from_utf8_lossy(&f.take_wire(usize::MAX)).into_owned()
}

/// The far end answers the request in flight, whole, so the line is free for the next one.
fn answered(f: &mut Framing) {
    f.ingest(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok", false);
    f.drive(0, 0);
    f.pieces().clear();
}

/// RED (busbar ruling (T), the pooled line's request target): a stated target always wins, `/`
/// included; only a request naming NO target inherits the dial's path, and only as the
/// connection's first. A line dialled to `http://h/card` by one exchange is lent, pooled by
/// authority, to the next exchange to the same place: that exchange's stated `POST /` goes to `/`,
/// never to `/card` (at 9e0d6fee15 it went to `/card`, the far end answered 405, and the breaker
/// counted a fault the far end never had). A later request naming no target goes to `/`.
#[test]
fn a_pooled_lines_later_request_goes_where_it_says_not_where_the_line_was_dialled() {
    let mut f = Framing::dial("http://127.0.0.1:9/card", Proto::H1, posture(30), 0).expect("dial");
    f.drive(0, 0);
    let unnamed = crate::transport::render_envelope(&[("method", b"GET".as_slice())], b"").unwrap();
    let first = sent(&mut f, 1, &unnamed);
    assert!(
        first.starts_with("GET /card HTTP/1.1\r\n"),
        "the first request names no target: the dial's own path: {first:?}"
    );
    answered(&mut f);
    let root = crate::transport::render_envelope(
        &[("method", b"POST".as_slice()), ("path", b"/".as_slice())],
        b"{}",
    )
    .unwrap();
    let second = sent(&mut f, 2, &root);
    assert!(
        second.starts_with("POST / HTTP/1.1\r\n"),
        "a stated `/` on the pooled line goes to `/`: {second:?}"
    );
    answered(&mut f);
    let third = sent(&mut f, 3, &unnamed);
    assert!(
        third.starts_with("GET / HTTP/1.1\r\n"),
        "a later request naming no target goes to `/`, not the dial's path: {third:?}"
    );
}

/// RED (busbar ARCHITECT ruling on busbar#780 (2), 1.5.5 parity): a target whose host is an IPv4
/// spelling goes out naming the address it spells, as 1.5.5's client sent it (its URL parser
/// canonicalized the host before the request was built): `host: 127.0.0.1:9` for `127.1`,
/// `2130706433` and `0x7f000001`, `host: 1.2.3.4:9` for `16909060`. A name and a dotted quad go out
/// as written. RED on the framing that wrote the spelling into the `host` field.
#[test]
fn an_ipv4_spelling_goes_out_as_the_address_it_names() {
    for (dial, host) in [
        ("http://127.1:9", "127.0.0.1:9"),
        ("http://2130706433:9", "127.0.0.1:9"),
        ("http://0x7f000001:9", "127.0.0.1:9"),
        ("http://16909060:9", "1.2.3.4:9"),
        ("http://localhost:9", "localhost:9"),
        ("http://127.0.0.1:9", "127.0.0.1:9"),
    ] {
        let mut f = Framing::dial(dial, Proto::H1, posture(30), 0).expect("dial");
        f.drive(0, 0);
        f.emit(1, b"GET /x HTTP/1.1\r\n\r\n", 0, 0).expect("emit");
        f.drive(0, 0);
        let wire = String::from_utf8_lossy(&f.take_wire(usize::MAX)).to_ascii_lowercase();
        assert!(
            wire.contains(&format!("host: {host}\r\n")),
            "{dial}: {wire:?}"
        );
    }
}

/// RED: 1.5.5's client lowercased a DNS host, so an h1 request dialled at a mixed-case name
/// carries the lower-case `host`.
#[test]
fn a_dns_host_goes_out_lower_case() {
    let mut f =
        Framing::dial("http://API.Example.com:8080/x", Proto::H1, posture(30), 0).expect("dial");
    f.drive(0, 0);
    f.emit(1, b"GET /x HTTP/1.1\r\n\r\n", 0, 0).expect("emit");
    f.drive(0, 0);
    let wire = String::from_utf8_lossy(&f.take_wire(usize::MAX)).into_owned();
    assert!(wire.contains("host: api.example.com:8080\r\n"), "{wire:?}");
}

/// What one emit of an envelope rendered by `encode` does on a fresh HTTP/1.1 framing whose body
/// cap is `cap`: the emit's answer and the bytes the connection wrote.
fn rendered_and_sent(
    cap: usize,
    fields: &[(&str, &[u8])],
    body: &[u8],
) -> (Result<(), Failure>, Vec<u8>) {
    let capped = Posture {
        max_body_bytes: cap,
        ..posture(30)
    };
    let mut f = Framing::dial("http://127.0.0.1:9", Proto::H1, capped, 0).expect("dial");
    f.drive(0, 0);
    let message = crate::transport::render_envelope(fields, body).expect("render");
    let r = f.emit(1, &message, 0, 0);
    f.drive(0, 0);
    (r, f.take_wire(usize::MAX))
}

/// RED (THE DESIGN §2 "A port keeps 1.5.5's surface"; `limits.request_body_max_bytes` is a BODY
/// size): the cap bounds the request's body, never its rendered head. A body exactly at the cap
/// leaves whole with its head; one byte over is refused. RED on the framing that counted the
/// request line and every field against the body's cap.
#[test]
fn a_request_body_at_the_cap_goes_out_with_its_head() {
    let fields: &[(&str, &[u8])] = &[
        ("method", b"POST"),
        ("path", b"/v1/x"),
        ("content-type", b"application/json"),
    ];
    let (r, wire) = rendered_and_sent(16, fields, &[b'x'; 16]);
    assert!(r.is_ok(), "a body at the cap is carried: {r:?}");
    let wire = String::from_utf8_lossy(&wire).into_owned();
    assert!(wire.starts_with("POST /v1/x HTTP/1.1\r\n"), "{wire:?}");
    assert!(wire.ends_with("\r\n\r\nxxxxxxxxxxxxxxxx"), "{wire:?}");
    let (r, _) = rendered_and_sent(16, fields, &[b'x'; 17]);
    assert!(r.is_err(), "a body one byte over the cap is refused");
}

/// RED (THE DESIGN §2 l.393-397; `limits.request_body_max_bytes` is "the largest request body
/// carried"): a CHUNKED request body is held to the cap as a declared one is. Its decoded body at
/// the cap is carried; one byte over is refused, never carried for being inside the head allowance.
/// RED on the framing that compared only a Content-Length against the cap.
#[test]
fn a_chunked_request_body_is_held_to_the_cap() {
    let chunked = |n: usize| {
        let mut m = b"POST /v1/x HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n".to_vec();
        m.extend_from_slice(format!("{n:x}\r\n").as_bytes());
        m.extend(std::iter::repeat_n(b'x', n));
        m.extend_from_slice(b"\r\n0\r\n\r\n");
        m
    };
    let send = |message: &[u8]| {
        let capped = Posture {
            max_body_bytes: 16,
            ..posture(30)
        };
        let mut f = Framing::dial("http://127.0.0.1:9", Proto::H1, capped, 0).expect("dial");
        f.drive(0, 0);
        let r = f.emit(1, message, 0, 0);
        f.drive(0, 0);
        r
    };
    let at = send(&chunked(16));
    assert!(at.is_ok(), "a chunked body at the cap is carried: {at:?}");
    let over = send(&chunked(17));
    assert!(
        over.is_err(),
        "a chunked body one byte over the cap is refused"
    );
}

/// RED (THE DESIGN §2 and §5: the wire bytes are hyper's, as 1.5.5's were): a field value is
/// carried byte for byte. 1.5.5's client took a value as `http::HeaderValue`, which holds obs-text
/// (0x80-0xFF), and sent it as given; the door's re-read of its own rendered message required UTF-8
/// and refused the whole request for it.
#[test]
fn an_obs_text_field_value_goes_out_byte_for_byte() {
    let (r, wire) = rendered_and_sent(
        1024,
        &[
            ("method", b"GET"),
            ("path", b"/x"),
            ("x-name", b"caf\xe9 \x80\xff"),
        ],
        b"",
    );
    assert!(r.is_ok(), "an obs-text value is carried: {r:?}");
    let needle = b"x-name: caf\xe9 \x80\xff\r\n";
    assert!(
        wire.windows(needle.len()).any(|w| w == needle),
        "{:?}",
        String::from_utf8_lossy(&wire)
    );
}

/// RED (audit A1 F3; this method's own contract: a message that cannot be sent fails "the framing
/// on HTTP/1.1, where the connection carries one exchange"): an HTTP/1.1 `emit` that is refused
/// (here, a body over the cap) fails the FRAMING, so the next op answers FAILED, and keeps nothing
/// of the refused message. RED on the framing that answered the error but kept the line usable
/// with the dead buffer held for the connection's life.
#[test]
fn a_refused_h1_emit_fails_the_framing_and_keeps_nothing() {
    let capped = Posture {
        max_body_bytes: 4,
        ..posture(30)
    };
    let mut f = Framing::dial("http://127.0.0.1:9", Proto::H1, capped, 0).expect("dial");
    f.drive(0, 0);
    let r = f.emit(
        1,
        b"POST /x HTTP/1.1\r\ncontent-length: 9\r\n\r\n123456789",
        0,
        0,
    );
    assert!(r.is_err(), "a body over the cap is refused");
    assert!(
        f.failure().is_some(),
        "the refusal fails the HTTP/1.1 framing"
    );
    assert!(
        f.exchanges.is_empty(),
        "nothing of the refused message is kept"
    );
}

/// RED (audit A1 F4; RFC 9110 §6.5.1: a trailer field is not merged into the header section; THE
/// DESIGN §5 refuses a trailer piece on the transport ABI): the trailer section of a chunked
/// request never leaves as header fields. A trailer `host` would be a second `Host` (a 400 on
/// HTTP/1.1), a trailer `connection` would change the line's semantics. They are discarded, as RFC
/// 9110 §6.5.1 lets a recipient that removes the chunked coding do. RED on the reader that appended
/// every trailer to the head.
#[test]
fn a_request_trailer_never_joins_the_header_section() {
    let wire = h1_wire(
        b"POST /x HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n\
          3\r\nabc\r\n0\r\nhost: elsewhere\r\nconnection: close\r\nx-t: 1\r\n\r\n",
    );
    let lower = wire.to_ascii_lowercase();
    assert!(lower.starts_with("post /x http/1.1\r\n"), "{wire:?}");
    assert_eq!(lower.matches("\r\nhost:").count(), 1, "{wire:?}");
    assert!(lower.contains("host: 127.0.0.1:9\r\n"), "{wire:?}");
    assert!(!lower.contains("elsewhere"), "{wire:?}");
    assert!(!lower.contains("connection: close"), "{wire:?}");
    assert!(!lower.contains("x-t:"), "{wire:?}");
    assert!(lower.ends_with("\r\n\r\nabc"), "{wire:?}");
}

/// RED (audit A1 F5; THE DESIGN §5 l.722-723: the http door sends "on h1 the host header and
/// origin-form target"): a stated target that is not origin form (`/...`) is refused, never
/// rewritten. `?a=1` (a query with no path, which `http`'s path parser takes) went out as `/` on
/// HTTP/1.1, the query dropped, and as `:path: ?a=1` on HTTP/2. A relative `v1/chat`, an
/// absolute-form `http://other/x` and the asterisk form fail too, the HTTP/1.1 framing or the
/// HTTP/2 stream, and put no request on the wire; an origin-form target still goes out as stated.
#[test]
fn a_target_not_in_origin_form_is_refused_not_rewritten() {
    for target in ["?a=1", "#f", "v1/chat", "http://other/x", "*"] {
        let message = format!("GET {target} HTTP/1.1\r\n\r\n");
        let mut f = Framing::dial("http://127.0.0.1:9", Proto::H1, posture(30), 0).expect("dial");
        f.drive(0, 0);
        let r = f.emit(1, message.as_bytes(), 0, 0);
        f.drive(0, 0);
        let wire = String::from_utf8_lossy(&f.take_wire(usize::MAX)).into_owned();
        assert!(r.is_err(), "h1 {target}: refused: {wire:?}");
        assert!(
            !wire.contains("HTTP/1.1"),
            "h1 {target}: nothing sent: {wire:?}"
        );

        let mut f = Framing::dial("http://127.0.0.1:9", Proto::H2, posture(30), 0).expect("dial");
        f.drive(0, 0);
        f.emit(1, message.as_bytes(), 0, 0)
            .expect("h2 answers per stream");
        assert!(
            f.pieces().iter().any(|p| p.stream == 1 && p.failed),
            "h2 {target}: the stream fails at its emit"
        );
        assert!(f.exchanges.is_empty(), "h2 {target}: nothing kept");
    }
    let ok = h1_wire(b"GET /v1/chat?a=1 HTTP/1.1\r\n\r\n");
    assert!(ok.starts_with("GET /v1/chat?a=1 HTTP/1.1\r\n"), "{ok:?}");
}

/// The body bytes queued in `out` on stream 1.
fn queued(f: &mut Framing) -> usize {
    f.pieces()
        .iter()
        .filter(|p| p.stream == 1 && !p.fields)
        .map(|p| p.bytes.len())
        .sum()
}

/// RED (audit A1 F7; THE DESIGN §5 *Proven by*: 2,000 concurrent streams on bounded resources;
/// 1.5.5's hyper body released a stream's HTTP/2 credit only as its consumer read): a stream's
/// body is pulled from the connection only as far as the host has taken what was already handed
/// up. The far end may send a whole window; the framer queues about one sink's worth, asks to be
/// called again once the host has taken it, and the whole body still arrives. RED on the round
/// that pulled every frame into an unbounded queue (and returned the window as it did).
#[test]
fn an_h2_body_is_pulled_only_as_far_as_the_host_has_taken() {
    let mut f = asked(Proto::H2, 300);
    let frame = vec![b'x'; 16_000];
    let mut far = h2(4, 0, 0, &[]);
    far.extend(h2(1, 0x4, 1, &[0x88]));
    for _ in 0..4 {
        far.extend(h2(0, 0, 1, &frame));
    }
    f.ingest(&far, false);
    f.drive(SEC, 0);
    let held = queued(&mut f);
    // The hold (32 KiB) plus the one frame polled to reach it.
    assert!(
        held <= 48 * 1024,
        "{held} body bytes queued for a host that has taken none"
    );
    let mut seen = 0;
    for _ in 0..16 {
        seen += body(&mut f).0.len();
        if seen == 4 * 16_000 {
            break;
        }
        assert!(
            f.next_deadline().is_some(),
            "a held stream asks to be called again once the host has taken its bytes"
        );
        f.drive(SEC, 0);
    }
    assert_eq!(seen, 4 * 16_000, "the whole body arrives");
}

/// A framing that fails in the same drive that queued output (a body shorter than its declared
/// length, the far end closing) states the failure on the stream after what was handed up: the
/// host never calls a connection again once it ended, so the failure text rides a piece.
#[test]
fn a_framing_failing_with_output_owed_fails_each_live_stream_after_it() {
    let mut f = asked(Proto::H1, 300);
    f.ingest(b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\nhello", true);
    f.drive(0, 0);
    let why = f.failure().expect("the framing failed").0.clone();
    assert!(why.contains("error reading a body"), "{why}");
    let ps: Vec<_> = f.pieces().iter().filter(|p| p.stream == 1).collect();
    let last = ps.last().expect("pieces on stream 1");
    assert!(last.failed, "the last piece is the failure");
    assert!(
        String::from_utf8_lossy(&last.bytes).contains("error reading a body"),
        "the failure piece carries the text"
    );
    assert!(ps.iter().all(|p| !p.end), "the stream did not end whole");
    assert_eq!(ps.iter().filter(|p| p.failed).count(), 1, "stated once");
    assert_eq!(body(&mut f).0, b"hello", "the body went up before it");
}

/// The request timeout firing in the drive that queued body data does the same.
#[test]
fn a_request_timeout_with_body_queued_fails_the_stream_after_it() {
    let mut f = asked(Proto::H1, 1);
    f.ingest(b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\nhello", false);
    f.drive(2 * SEC, 0);
    assert!(f.failure().is_some(), "the framing failed");
    let ps: Vec<_> = f.pieces().iter().filter(|p| p.stream == 1).collect();
    let last = ps.last().expect("pieces on stream 1");
    assert!(last.failed, "the last piece is the failure");
    assert!(ps.iter().all(|p| !p.end));
}

/// With nothing owed, no piece is pushed: the door answers FAILED at once.
#[test]
fn a_framing_failing_with_nothing_owed_pushes_no_failure_piece() {
    let mut f = asked(Proto::H1, 5);
    f.ingest(
        b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n",
        false,
    );
    f.drive(SEC, 0);
    assert_eq!(body(&mut f).0, b"hello");
    f.drive(5 * SEC, 0);
    assert!(f.failure().is_some(), "the framing failed");
    assert!(
        f.pieces().iter().all(|p| !p.failed),
        "no failure piece: nothing was owed"
    );
}

/// RED (codeaudit D1; THE DESIGN: every refusal explained): a refused request message names its
/// cause. A `Content-Length` over `limits.request_body_max_bytes` and a target not in origin form
/// each fail with text an operator can act on, not the bare word "Framing".
#[test]
fn a_refused_request_message_names_its_cause() {
    let capped = Posture {
        max_body_bytes: 4,
        ..posture(30)
    };
    let mut f = Framing::dial("http://127.0.0.1:9", Proto::H1, capped, 0).expect("dial");
    f.drive(0, 0);
    let over = f
        .emit(
            1,
            b"POST /x HTTP/1.1\r\ncontent-length: 9\r\n\r\n123456789",
            0,
            0,
        )
        .expect_err("a body over the cap is refused");
    assert!(over.0.contains("body cap"), "{over:?}");

    let mut f = Framing::dial("http://127.0.0.1:9", Proto::H1, posture(30), 0).expect("dial");
    f.drive(0, 0);
    let target = f
        .emit(1, b"GET v1/chat HTTP/1.1\r\n\r\n", 0, 0)
        .expect_err("a target not in origin form is refused");
    assert!(target.0.contains("origin form"), "{target:?}");
    assert!(target.0.contains("v1/chat"), "{target:?}");
}

/// RED (codeaudit D2): the first-request inheritance of the dial URI's path is spent only by a
/// request that was built. On HTTP/2 a first request whose builder refuses (a field value carrying
/// byte 0x01, which the raw reader takes and `http` does not) fails its own stream; the next
/// request naming no target is still the connection's first sent, so it goes to the dial's path,
/// not `/`. The wire of that request equals the wire of the same request sent first on a fresh
/// connection (same HPACK state, same frames), so no header block need be decoded.
#[test]
fn a_first_request_that_fails_to_build_keeps_the_dial_path_for_the_next() {
    let unnamed = crate::transport::render_envelope(&[("method", b"GET".as_slice())], b"").unwrap();
    let dial = || {
        let mut f =
            Framing::dial("http://127.0.0.1:9/card", Proto::H2, posture(30), 0).expect("dial");
        f.drive(0, 0);
        f.take_wire(usize::MAX);
        f
    };

    let mut reference = dial();
    reference.emit(3, &unnamed, 0, 0).expect("emit");
    reference.drive(0, 0);
    let expected = reference.take_wire(usize::MAX);
    assert!(!expected.is_empty(), "the reference request went out");

    let mut f = dial();
    f.emit(1, b"GET /x HTTP/1.1\r\nx-a: \x01\r\n\r\n", 0, 0)
        .expect("h2 answers per stream");
    assert!(
        f.pieces().iter().any(|p| p.stream == 1 && p.failed),
        "the first request fails to build"
    );
    f.emit(3, &unnamed, 0, 0).expect("emit");
    f.drive(0, 0);
    assert_eq!(
        f.take_wire(usize::MAX),
        expected,
        "the next request naming no target goes to the dial's path"
    );
}

/// RED (codeaudit D3; RFC 9112 6.3: a `Transfer-Encoding` overrides `Content-Length`): an h1
/// answer carrying both is framed chunked by hyper, so its `Content-Length` states a length the
/// body does not have. The head piece states none, as 1.5.5's `content_length()` was `None` for a
/// chunked body; the host's pre-body download cap must not read a length the body is not.
#[test]
fn a_transfer_encoding_answer_states_no_declared_length() {
    let mut f = asked(Proto::H1, 300);
    f.ingest(
        b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\ncontent-length: 50000000\r\n\r\n\
          5\r\nhello\r\n0\r\n\r\n",
        false,
    );
    f.drive(SEC, 0);
    assert_eq!(declared(&mut f), Some(None), "chunked beats content-length");
}

/// RED (codeaudit D4): the head allowance bounds the head itself, not only the buffer a body
/// shares with it. A message whose header block runs past `HEAD_MAX_BYTES` is refused, whether its
/// terminator has arrived or not, rather than parsed into millions of fields and handed to hyper.
#[test]
fn a_request_head_over_its_allowance_is_refused() {
    let mut head = b"GET /x HTTP/1.1\r\n".to_vec();
    while head.len() <= HEAD_MAX_BYTES {
        head.extend_from_slice(b"x-pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
    }
    let mut open = head.clone();
    let mut whole = head;
    whole.extend_from_slice(b"\r\n");

    for (what, message) in [("terminated", &mut whole), ("unterminated", &mut open)] {
        let mut f = Framing::dial("http://127.0.0.1:9", Proto::H1, posture(30), 0).expect("dial");
        f.drive(0, 0);
        let r = f.emit(1, message, 0, 0).expect_err(what);
        assert!(
            r.0.contains("request head over its allowance"),
            "{what}: {r:?}"
        );
        assert!(
            f.failure().is_some(),
            "{what}: the refusal fails the framing"
        );
    }
}
