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

/// RED (THE DESIGN §6 step 5, OWNER-LOCKED: "Nothing is added to the head after the auth has
/// run"): the framer writes the head it is handed and adds no field line of its own at `encode`;
/// its own lines (`accept`, `host`) are stated at `locate` and added by the host before the auth.
/// RED on the framer that added them after the auth.
#[test]
fn the_door_adds_no_line_to_the_head_it_is_handed() {
    let bare = h1_wire(b"GET /x HTTP/1.1\r\nx-a: 1\r\n\r\n");
    let lower = bare.to_ascii_lowercase();
    assert!(
        lower.starts_with("get /x http/1.1\r\nx-a: 1\r\n"),
        "{bare:?}"
    );
    assert!(!lower.contains("accept:"), "no accept was handed: {bare:?}");
    assert!(!lower.contains("host:"), "no host was handed: {bare:?}");
    let handed = h1_wire(b"GET /x HTTP/1.1\r\nx-a: 1\r\naccept: */*\r\nhost: 127.0.0.1:9\r\n\r\n");
    assert!(
        handed
            .to_ascii_lowercase()
            .contains("x-a: 1\r\naccept: */*\r\nhost: 127.0.0.1:9\r\n"),
        "the handed head, as handed: {handed:?}"
    );
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
        &[
            ("method", b"POST".as_slice()),
            ("path", b"/".as_slice()),
            ("content-length", b"2".as_slice()),
        ],
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
/// as written. RED on the framing that wrote the spelling into the `host` field. The `host` line is
/// the one the framer states at `locate` ([`client_defaults`]).
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
        // The `host` line is the framer's own, stated at `locate` (THE DESIGN §6 step 5).
        let stated = client_defaults(&dial.parse().expect("a URL"));
        assert!(
            stated.contains(&format!("host: {host}\r\n")),
            "{dial}: {stated:?}"
        );
    }
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
    // The length line the host states before the auth.
    let len = body.len().to_string();
    let mut stated = fields.to_vec();
    if !body.is_empty() {
        stated.push(("content-length", len.as_bytes()));
    }
    let message = crate::transport::render_envelope(&stated, body).expect("render");
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

/// RED (THE DESIGN §6 step 5; Q128 transport-http, chunked request message, ruling (b)): a request
/// message framed by a transfer coding is refused at emit and nothing of it reaches the wire. The
/// host states the length line before the auth and no host path renders a `transfer-encoding`
/// (core-connector's `head_is_refused` refuses any open whose fields carry one), so a chunked
/// request has no 1.5.5 counterpart: carrying it would put a framing on the wire the auth never
/// saw. Refused whatever its size, at the cap or under it, and whatever the coding. RED on the
/// framing that decoded a chunked request and sent its body.
#[test]
fn a_chunked_request_message_is_refused_and_nothing_goes_out() {
    let chunked = |coding: &str, n: usize| {
        let mut m =
            format!("POST /v1/x HTTP/1.1\r\ntransfer-encoding: {coding}\r\n\r\n").into_bytes();
        m.extend_from_slice(format!("{n:x}\r\n").as_bytes());
        m.extend(std::iter::repeat_n(b'x', n));
        m.extend_from_slice(b"\r\n0\r\n\r\n");
        m
    };
    for (coding, n) in [
        ("chunked", 3),
        ("chunked", 16),
        ("Chunked", 1),
        ("gzip, chunked", 3),
    ] {
        let capped = Posture {
            max_body_bytes: 16,
            ..posture(30)
        };
        let mut f = Framing::dial("http://127.0.0.1:9", Proto::H1, capped, 0).expect("dial");
        f.drive(0, 0);
        let r = f.emit(1, &chunked(coding, n), 0, 0);
        f.drive(0, 0);
        assert!(
            r.is_err(),
            "a request framed by `transfer-encoding: {coding}` is refused at emit: {r:?}"
        );
        let wire = f.take_wire(usize::MAX);
        assert!(
            wire.is_empty(),
            "nothing of a refused chunked request reaches the wire: {:?}",
            String::from_utf8_lossy(&wire)
        );
    }
}

/// RED (Q128 transport-http, bytes past the declared length): an emitted message whose bytes run
/// past its stated `content-length` is refused at emit and nothing of it reaches the wire. RED on
/// the framing that sent the declared prefix and dropped the rest.
#[test]
fn bytes_past_the_stated_length_are_refused_and_nothing_goes_out() {
    let mut f = Framing::dial("http://127.0.0.1:9", Proto::H1, posture(30), 0).expect("dial");
    f.drive(0, 0);
    let r = f.emit(
        1,
        b"POST /x HTTP/1.1\r\ncontent-length: 2\r\n\r\nhiEXTRA",
        0,
        0,
    );
    f.drive(0, 0);
    let wire = f.take_wire(usize::MAX);
    assert!(
        r.is_err(),
        "bytes past the stated length are refused: {r:?}"
    );
    assert!(
        wire.is_empty(),
        "nothing of the refused message reaches the wire: {:?}",
        String::from_utf8_lossy(&wire)
    );
}

/// The HTTP/2 frame types in `wire` (no connection preface): what a connection wrote.
fn h2_frame_types(wire: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 9 <= wire.len() {
        let len =
            usize::from(wire[i]) << 16 | usize::from(wire[i + 1]) << 8 | usize::from(wire[i + 2]);
        out.push(wire[i + 3]);
        i += 9 + len;
    }
    out
}

/// RED (Q128 transport-http, the refused h2 stream): a stream refused partway through its request
/// message stays refused until the host's end of that message. The rest of the message, arriving
/// in later emits, is never read as a fresh request on the same stream: a fresh request there
/// would go upstream with a head the auth never saw. RED on the framing that forgot the refused
/// stream and parsed its remaining bytes as a new message.
#[test]
fn a_refused_h2_stream_reads_no_fresh_request_from_the_rest_of_its_message() {
    let mut f = Framing::dial("http://127.0.0.1:9", Proto::H2, posture(30), 0).expect("dial");
    f.drive(0, 0);
    // The far end's SETTINGS: the connection is up, so a request handed to it goes out.
    f.ingest(&h2(4, 0, 0, &[]), false);
    f.drive(0, 0);
    let _preface = f.take_wire(usize::MAX);
    // Refused partway: bytes past the stated length.
    let r = f.emit(1, b"POST /x HTTP/1.1\r\ncontent-length: 2\r\n\r\nhiX", 0, 0);
    f.drive(0, 0);
    assert!(
        r.is_ok(),
        "an h2 stream's refusal is a failure piece: {r:?}"
    );
    assert!(
        f.pieces().iter().any(|p| p.stream == 1 && p.failed),
        "stream 1 is refused"
    );
    f.pieces().clear();
    // The rest of the same message, shaped like a request of its own.
    let _ = f.emit(
        1,
        b"GET /never-authed HTTP/1.1\r\nx-injected: 1\r\n\r\n",
        0,
        0,
    );
    f.drive(0, 0);
    let wire = f.take_wire(usize::MAX);
    assert!(
        !h2_frame_types(&wire).contains(&1),
        "no HEADERS frame goes out for the rest of a refused message: {:?}",
        String::from_utf8_lossy(&wire)
    );
    // The control: a request on a fresh stream does go out, as a HEADERS frame this reading sees.
    f.emit(3, b"GET /ok HTTP/1.1\r\n\r\n", 0, 0).expect("emit");
    f.drive(0, 0);
    assert!(
        h2_frame_types(&f.take_wire(usize::MAX)).contains(&1),
        "a fresh stream's request goes out"
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

/// RED (1.5.5 parity, Q128 transport-http LOW): the dial's authority is the one 1.5.5's URL parser
/// (WHATWG, reqwest 0.12) sent: the host lower-cased and the scheme's own port dropped, so
/// `:authority` on HTTP/2 and the stated `host` line on HTTP/1.1 are one string. RED on the
/// normalisation that only rewrote IPv4 spellings.
#[test]
fn the_dial_authority_is_normalised_as_1_5_5_normalised_it() {
    for (dial, authority) in [
        ("http://API.Example.COM:80/x", "api.example.com"),
        ("https://API.Example.COM:443/x", "api.example.com"),
        ("https://API.Example.COM:8443/x", "api.example.com:8443"),
        ("http://127.1:80/x", "127.0.0.1"),
        ("http://Peer.Test:8080/x", "peer.test:8080"),
    ] {
        let uri = canonical_host(dial.parse().expect("a URL"));
        assert_eq!(
            uri.authority().map(http::uri::Authority::as_str),
            Some(authority),
            "{dial}"
        );
        assert!(
            client_defaults(&dial.parse().expect("a URL"))
                .contains(&format!("host: {authority}\r\n")),
            "{dial}: the host line is the same string"
        );
    }
}

/// RED (THE DESIGN §6 step 5, OWNER-LOCKED, length among the transport's own lines; ruling (A)
/// 2026-10-19): the head the auth saw is the head on the wire. The host states the length before
/// the auth (last, after the framer's own lines, as 1.5.5's goldens order it); the framer renders
/// exactly that head, one length line and no other, and the connection sends it unchanged. A
/// non-empty body with no stated length cannot be framed without a line the auth never saw, so it
/// is refused. RED on the framer that appended its own length line to every request.
#[test]
fn the_wire_head_is_the_head_the_auth_saw() {
    let seen: &[(&str, &[u8])] = &[
        ("method", b"POST"),
        ("path", b"/v1/x"),
        ("content-type", b"application/json"),
        ("accept", b"*/*"),
        ("host", b"127.0.0.1:9"),
        ("content-length", b"2"),
    ];
    let message = crate::transport::render_envelope(seen, b"hi").expect("render");
    let text = String::from_utf8_lossy(&message).to_ascii_lowercase();
    assert_eq!(text.matches("content-length:").count(), 1, "{text:?}");
    let wire = h1_wire(&message);
    let head: Vec<&str> = wire
        .split("\r\n\r\n")
        .next()
        .expect("a head")
        .split("\r\n")
        .skip(1)
        .collect();
    assert_eq!(
        head,
        [
            "content-type: application/json",
            "accept: */*",
            "host: 127.0.0.1:9",
            "content-length: 2"
        ],
        "the wire head is the head the auth saw: {wire:?}"
    );
    assert!(
        crate::transport::render_envelope(&seen[..5], b"hi").is_err(),
        "a body with no stated length is refused"
    );
    // An empty body states no length, and none goes out (1.5.5's client sent none).
    let get: &[(&str, &[u8])] = &[
        ("method", b"GET"),
        ("path", b"/x"),
        ("host", b"127.0.0.1:9"),
    ];
    let bare = h1_wire(&crate::transport::render_envelope(get, b"").expect("render"));
    assert!(
        !bare.to_ascii_lowercase().contains("content-length"),
        "{bare:?}"
    );
}

/// RED (THE DESIGN §6 step 5: nothing joins the head after the auth): a chunked request's trailer
/// section is not folded into the head and sent as header fields; a request carrying trailers is
/// refused, with the chunked framing that carries them, and no trailer reaches the wire. RED on the
/// framing that appended the trailers to the head.
#[test]
fn a_request_with_trailers_is_refused_not_folded_into_its_head() {
    let mut f = Framing::dial("http://127.0.0.1:9", Proto::H1, posture(30), 0).expect("dial");
    f.drive(0, 0);
    let r = f.emit(
        1,
        b"POST /x HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\nx-late: 1\r\n\r\n",
        0,
        0,
    );
    f.drive(0, 0);
    let wire = String::from_utf8_lossy(&f.take_wire(usize::MAX)).to_ascii_lowercase();
    assert!(r.is_err(), "a request with trailers is refused: {wire:?}");
    assert!(!wire.contains("x-late"), "{wire:?}");
}
