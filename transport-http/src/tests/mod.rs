// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The crate's own battery: the HTTP/1.1 message an `emit` accumulates (one parse per message, a
//! transfer coding refused at its head, the smuggling pair with it), the request envelope `encode` renders, the
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
/// two Strings per header, allocated and dropped, for every chunk of the body.
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

/// A request framed by a transfer coding is refused at its head, before a byte of its body is read
/// (Q128 transport-http, ruling (b)).
///
/// The host states the length line before the auth (THE DESIGN §6 step 5) and no host path renders
/// a `transfer-encoding`, so a chunked request has no 1.5.5 counterpart. The refusal comes from the
/// head alone: a message whose body has not arrived is refused as one whose body has, so no body
/// is buffered for a request that will never go out, and no head is left cached for the next.
#[test]
fn egress_refuses_a_chunked_request_at_its_head() {
    let head = b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n";
    let mut cache = EgressHead::default();
    assert_eq!(
        complete_message(head, &mut cache, usize::MAX).unwrap_err(),
        TransportError::Framing,
        "a chunked head is refused before its body arrives"
    );
    assert!(cache.head.is_none(), "a refused head is never cached");

    let whole =
        b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
    let mut cache = EgressHead::default();
    assert_eq!(
        complete_message(whole, &mut cache, usize::MAX).unwrap_err(),
        TransportError::Framing,
        "a whole chunked message is refused, never decoded and carried"
    );
}

/// The egress smuggling pair: a `Transfer-Encoding` beside a `Content-Length` is refused, as any
/// transfer coding is, and the `Content-Length` alone still completes. The second half proves the
/// refusal is the coding's, not the length's.
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

    let clean = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc";
    let mut clean_cache = EgressHead::default();
    let done = complete_message(clean, &mut clean_cache, usize::MAX)
        .unwrap()
        .expect("a stated length with no coding beside it completes");
    assert_eq!(done.body, b"abc", "the stated body goes out byte-exact");
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
    assert!(
        raw::parse_message(b"HTTP/1.1 200 OK\r\n\r\n").is_none(),
        "a status line is not a request: the envelope `emit` reads always is one"
    );
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
            ("content-length", b"13".as_slice()),
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
        "the length the head states, rendered where it was stated"
    );
    assert!(text.ends_with("\r\n\r\n{\"model\":\"m\"}"));

    // And the message this transport wrote is one this transport can read back.
    let parsed = raw::parse_message(&bytes).expect("a message it can read");
    assert_eq!(
        parsed.start,
        raw::RawStartLine {
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
        raw::RawStartLine {
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
        raw::RawStartLine {
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
        let err = crate::transport::render_envelope(std::slice::from_ref(field), b"")
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
    crate::transport::render_envelope(
        &[
            ("x-note", b"ok".as_slice()),
            ("content-length", b"4".as_slice()),
        ],
        b"body",
    )
    .expect("a clean field still encodes");
}

/// A field name is an RFC 9110 token. A `:` in one is re-read as a different field when the door
/// re-parses its own rendered message (`authorization:x` + `v` becomes `authorization` = `x: v`),
/// which slips past the kernel's same-name auth replacement: refused, nothing rendered.
#[test]
fn a_field_name_that_is_not_a_token_is_refused() {
    for name in [
        "authorization:x",
        "a b",
        "",
        "x\u{e9}",
        "a(b",
        "a/b",
        "a\"b",
        "a\tb",
    ] {
        let err = crate::transport::render_envelope(&[(name, b"v".as_slice())], b"")
            .expect_err("a non-token field name is not encodable");
        assert_eq!(
            err,
            busbar_contract::transport::wire::Encode::Unrepresentable,
            "name {name:?} was written through"
        );
    }
    let ok = crate::transport::render_envelope(
        &[
            ("authorization", b"Bearer a".as_slice()),
            ("x-a.b_c~1!#$%&'*+^`|", b"v".as_slice()),
        ],
        b"",
    )
    .expect("token names still encode");
    let text = String::from_utf8(ok).unwrap();
    assert_eq!(text.matches("authorization").count(), 1);
}

/// RED (Q128 transport-http, bytes past the declared length): a message whose bytes run past the
/// `Content-Length` its head declares is refused (`Framing`), never cut to the length and the rest
/// silently dropped. The length is the one the host stated before the auth; bytes past it are
/// bytes the head does not describe. RED on the reader that sent the declared prefix and threw the
/// remainder away.
#[test]
fn egress_refuses_bytes_past_the_declared_length() {
    let over = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabcEXTRA";
    let mut cache = EgressHead::default();
    assert_eq!(
        complete_message(over, &mut cache, usize::MAX).unwrap_err(),
        TransportError::Framing,
        "bytes past the declared length are refused, not dropped"
    );
    let empty_over = b"GET / HTTP/1.1\r\nHost: x\r\n\r\nX";
    let mut cache = EgressHead::default();
    assert_eq!(
        complete_message(empty_over, &mut cache, usize::MAX).unwrap_err(),
        TransportError::Framing,
        "a head that declares no length carries no body byte"
    );
    let exact = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc";
    let mut cache = EgressHead::default();
    let done = complete_message(exact, &mut cache, usize::MAX)
        .unwrap()
        .expect("exactly the declared length completes");
    assert_eq!(done.body, b"abc");
}

/// RED (Q128 transport-http, the non-token method): `encode` refuses a method that is not an RFC 9110
/// token, and a target carrying a space, as `Unrepresentable`, never answering READY with a request
/// line its own `emit` then refuses. RED on the encode that checked only for line-ending bytes.
#[test]
fn encode_refuses_a_request_line_its_emit_could_not_read() {
    let refused = |method: &[u8], path: &[u8]| {
        crate::transport::render_envelope(&[("method", method), ("path", path)], b"").is_err()
    };
    assert!(refused(b"GE T", b"/x"), "a space in the method");
    assert!(refused(b"G(T", b"/x"), "a separator in the method");
    assert!(refused(b"", b"/x"), "an empty method");
    assert!(refused(b"GET", b"/a b"), "a space in the target");
    assert!(
        !refused(b"GET", b"/x"),
        "a token method and a clean target render"
    );
    assert!(!refused(b"M-SEARCH", b"/x"), "any token method renders");
}
