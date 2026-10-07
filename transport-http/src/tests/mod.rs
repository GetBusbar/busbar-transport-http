// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The crate's own battery: the HTTP/1.1 message an `emit` accumulates (one parse and one chunked
//! decode per message, the smuggling pair refused), the request envelope `encode` renders, the
//! start-line check, and the `Retry-After` reading a response head carries. The framer's own ops
//! are proven in `door/tests` and the crate's integration tests.

use super::*;
use busbar_contract::transport::wire::TransportError;

/// Both RFC 9110 forms, and nothing else. A value nobody can read is a value nobody asked for.
#[test]
fn retry_after_parses_both_normative_forms() {
    // delay-seconds, which ignores `now` entirely.
    assert_eq!(crate::message::parse_retry_after("7", 1_000), Some(7));
    assert_eq!(
        crate::message::parse_retry_after("  120 ", 9_999),
        Some(120)
    );
    assert_eq!(crate::message::parse_retry_after("0", 0), Some(0));

    // IMF-fixdate. 06 Nov 1994 08:49:37 GMT is 784_111_777 in Unix seconds.
    assert_eq!(
        crate::message::parse_retry_after("Sun, 06 Nov 1994 08:49:37 GMT", 784_111_777 - 30),
        Some(30)
    );
    // Already past: floored at zero rather than wrapping into a lifetime of suppression.
    assert_eq!(
        crate::message::parse_retry_after("Sun, 06 Nov 1994 08:49:37 GMT", 784_111_777 + 90),
        Some(0)
    );

    // Neither form.
    assert_eq!(crate::message::parse_retry_after("", 0), None);
    assert_eq!(crate::message::parse_retry_after("soon", 0), None);
    assert_eq!(crate::message::parse_retry_after("-5", 0), None);
    assert_eq!(crate::message::parse_retry_after("7.5", 0), None);
    // An obsolete HTTP-date form: parsed by nobody here, so it is absent rather than guessed.
    assert_eq!(
        crate::message::parse_retry_after("Sunday, 06-Nov-94 08:49:37 GMT", 0),
        None
    );
    // Right length, wrong month.
    assert_eq!(
        crate::message::parse_retry_after("Sun, 06 Xxx 1994 08:49:37 GMT", 0),
        None
    );
}

/// The egress header block is parsed once per message, not once per `write` call.
///
/// `write` accumulates, and it asks "is this message whole yet?" on every chunk. Answering that
/// used to re-run the whole header parse over the same unchanged prefix each time — a fresh Vec and
/// two Strings per header, allocated and dropped, for every chunk of the body. Same standard the
/// crate holds its chunked decoding to, now applied here.
#[test]
fn the_egress_header_block_is_parsed_once_across_many_write_calls() {
    let mut buffered = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n".to_vec();
    let mut cache = EgressHead::default();

    for i in 0..100 {
        buffered.push(b'a');
        let done = complete_message(&buffered, &mut cache, usize::MAX).unwrap();
        assert_eq!(
            done.is_some(),
            i == 99,
            "the exchange runs at the declared length and not one call before it"
        );
    }
    assert_eq!(
        cache.parses, 1,
        "one header block, one parse, however many calls the body arrived in"
    );

    // And the cache is spent with the message: the next one parses its own headers.
    assert!(
        cache.head.is_none(),
        "a completed message leaves no stale head"
    );
}

/// The egress chunked body is decoded once, not once per `write` call.
///
/// The sibling of the header-parse cell above, and the same standard: `write` accumulates and asks
/// "is this message whole yet?" on every chunk, and answering that with a FRESH decoder re-decoded
/// every byte received so far — quadratic in the body, with a full re-allocation of the decoded
/// chunks each time. The ingress reader already keeps one decoder across reads. This drives the
/// production `complete_message` and counts the bytes it actually feeds a decoder.
#[test]
fn the_egress_chunked_body_is_decoded_once_across_many_write_calls() {
    let mut buffered = b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    let mut cache = EgressHead::default();
    assert!(complete_message(&buffered, &mut cache, usize::MAX)
        .unwrap()
        .is_none());

    const CALLS: usize = 200;
    const PIECE: &[u8] = b"10\r\naaaaaaaaaaaaaaaa\r\n";
    let mut wire_bytes = 0_usize;
    for _ in 0..CALLS {
        buffered.extend_from_slice(PIECE);
        wire_bytes += PIECE.len();
        assert!(
            complete_message(&buffered, &mut cache, usize::MAX)
                .unwrap()
                .is_none(),
            "no terminal chunk yet, so the message is not whole"
        );
    }
    buffered.extend_from_slice(b"0\r\n\r\n");
    wire_bytes += 5;
    let done = complete_message(&buffered, &mut cache, usize::MAX)
        .unwrap()
        .expect("the terminal chunk completes the message");
    assert_eq!(
        done.body.len(),
        CALLS * 16,
        "the body is decoded byte-exact"
    );

    let fed = cache.feeds;
    assert!(
        fed <= 2 * wire_bytes,
        "a {wire_bytes}-byte chunked body arriving in {CALLS} calls cost {fed} bytes of decoding; \
         one decoder across the calls makes that O(n), a fresh one per call makes it O(n^2)"
    );

    // And the decoder is spent with the message: the next one decodes its own body.
    assert!(
        cache.head.is_none() && cache.decoder.is_none(),
        "a completed message leaves no stale decoder"
    );
}

/// The egress mirror of `a_message_with_both_a_transfer_encoding_and_a_content_length_is_refused`,
/// the ingress reader's own refusal.
///
/// Two headers naming two different lengths for one body is the canonical request-smuggling
/// primitive. Before this was wired, `complete_message` only refused a `Transfer-Encoding` it
/// could not read at all (anything but `chunked`); a body that was validly `chunked` AND carried a
/// `Content-Length` fell through to the chunked branch, was decoded, and was handed back as a
/// message with both framing headers stripped — a quiet disambiguation forwarded to the next hop,
/// which may resolve the same ambiguity the other way. This refuses the pair outright, mirroring
/// the ingress reader's identical check and identical error.
///
/// The second half proves this is not an over-refusal: a normal chunked body with no
/// `Content-Length` beside it — the exact shape every other egress chunked cell in this file
/// exercises — still completes.
#[test]
fn egress_refuses_a_chunked_body_declared_with_a_content_length() {
    let smuggled = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
    let mut cache = EgressHead::default();
    assert_eq!(
        complete_message(smuggled, &mut cache, usize::MAX).unwrap_err(),
        TransportError::Framing,
        "a chunked body naming a Content-Length beside it is the smuggling shape, refused rather \
         than silently disambiguated and forwarded"
    );

    let clean =
        b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
    let mut clean_cache = EgressHead::default();
    let done = complete_message(clean, &mut clean_cache, usize::MAX)
        .unwrap()
        .expect(
            "a normal chunked body with no Content-Length still completes — this refuses the \
                 smuggling PAIR, not chunked encoding on its own",
        );
    assert_eq!(
        done.body, b"abc",
        "the clean chunked body still decodes byte-exact"
    );
}

/// Every request line names its version. Without the check any two words followed by a space parse
/// as a request, so a blob that is not HTTP at all is read as one and its first two words become a
/// method and a path this transport goes on to act on.
#[test]
fn a_start_line_with_no_http_version_is_not_a_message() {
    assert!(
        raw::parse_message(b"GET /\r\nHost: x\r\n\r\n").is_none(),
        "a request line with no version token is not a request line"
    );
    assert!(
        raw::parse_message(b"NOT A REQUEST\r\nHost: x\r\n\r\n").is_none(),
        "an arbitrary first line is not a request line"
    );
    assert!(
        raw::parse_message(b"GET / HTTP/2\r\nHost: x\r\n\r\n").is_none(),
        "a version this reader does not frame is refused, not read with 1.x's rules"
    );
    assert!(
        raw::parse_message(b"HTTP/2 200 OK\r\n\r\n").is_none(),
        "and the same on the status side"
    );
    assert!(raw::parse_message(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").is_some());
    assert!(raw::parse_message(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n").is_some());
    assert!(raw::parse_message(b"HTTP/1.1 200 OK\r\n\r\n").is_some());
}

/// The envelope's bytes are an HTTP message, because that is what this wire is.
///
/// The egress unit used to write a neutral layout — every field as `name: value`, a blank line, the
/// body — and hand it to `write` as if it were a request. It ran the lane cross-check over the same
/// buffer, so the check was honest about there being ONE buffer and wrong about what was in it. The
/// layout is the transport's, and this is the transport.
#[test]
fn the_envelope_encodes_as_an_http_message() {
    let bytes = crate::transport::render_envelope(
        &[
            ("method", b"POST".as_slice()),
            ("path", b"/v1/messages".as_slice()),
            ("authorization", b"Token substituted".as_slice()),
        ],
        b"{\"model\":\"m\"}",
    )
    .unwrap();
    let text = String::from_utf8(bytes.clone()).unwrap();

    assert!(
        text.starts_with("POST /v1/messages HTTP/1.1\r\n"),
        "the method and the path are the request line, not headers: {text:?}"
    );
    assert!(text.contains("authorization: Token substituted\r\n"));
    assert!(
        text.contains("content-length: 13\r\n"),
        "the length is a fact about the bytes below, stated by the transport"
    );
    assert!(text.ends_with("\r\n\r\n{\"model\":\"m\"}"));

    // And the message this transport wrote is one this transport can read back.
    let parsed = raw::parse_message(&bytes).expect("a message it can read");
    assert_eq!(
        parsed.start,
        raw::RawStartLine::Request {
            method: "POST".to_string(),
            path: Some("/v1/messages".to_string())
        }
    );
    assert_eq!(parsed.body, b"{\"model\":\"m\"}");
}

/// An envelope naming NO path is not one that named `/`: it renders an empty target word and reads
/// back as no target at all, while a stated `/` reads back as `/` (the framing decides where each
/// goes, `crate::message::request_target`).
#[test]
fn no_target_named_and_a_stated_root_stay_distinct() {
    let unnamed = crate::transport::render_envelope(&[("method", b"GET".as_slice())], b"").unwrap();
    assert!(unnamed.starts_with(b"GET  HTTP/1.1\r\n"), "{unnamed:?}");
    assert_eq!(
        raw::parse_message(&unnamed).expect("readable").start,
        raw::RawStartLine::Request {
            method: "GET".to_string(),
            path: None
        }
    );
    let root = crate::transport::render_envelope(
        &[("method", b"GET".as_slice()), ("path", b"/".as_slice())],
        b"",
    )
    .unwrap();
    assert_eq!(
        raw::parse_message(&root).expect("readable").start,
        raw::RawStartLine::Request {
            method: "GET".to_string(),
            path: Some("/".to_string())
        }
    );
}

/// A CR or an LF in a field is not data on this wire: it ENDS the line. A caller that can put one
/// in a value chooses where this transport's header block ends and what stands after it — a second
/// header, a body boundary, a whole second request. NUL is refused with them: nothing on this wire
/// carries one, and a reader that stops at it reads a different message than the one written.
#[test]
fn a_field_cannot_smuggle_a_line_ending_into_the_header_block() {
    let poisoned: &[(&str, &[u8])] = &[
        ("x-note", b"ok\r\nauthorization: token stolen".as_slice()),
        ("x-note", b"ok\nauthorization: token stolen".as_slice()),
        ("x-note", b"ok\rmore".as_slice()),
        ("x-note", b"ok\0more".as_slice()),
        ("bad\r\nname", b"ok".as_slice()),
        ("method", b"GET / HTTP/1.1\r\nHost: elsewhere".as_slice()),
        ("path", b"/a\r\nHost: elsewhere".as_slice()),
    ];
    for field in poisoned {
        let err = crate::transport::render_envelope(std::slice::from_ref(field), b"body")
            .expect_err("a field carrying a line ending is not encodable");
        assert_eq!(
            err,
            busbar_contract::transport::wire::Encode::Unrepresentable,
            "field {:?} was written through",
            field.0
        );
    }
    // And an ordinary envelope beside them still encodes, so the check refuses injection rather
    // than refusing headers.
    crate::transport::render_envelope(&[("x-note", b"ok".as_slice())], b"body")
        .expect("a clean field still encodes");
}
