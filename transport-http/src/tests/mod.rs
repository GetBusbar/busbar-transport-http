// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The crate's own battery: the HTTP/1.1 message an `emit` accumulates (one parse and one chunked
//! decode per message, the smuggling pair refused), the request envelope `encode` renders, the
//! start-line check, and the `Retry-After` reading a response head carries. The framer's own ops
//! are proven in `door/tests` and the crate's integration tests.

use super::*;

impl crate::message::Whole {
    /// The body, where it lies: decoded, or the rest of the buffered bytes.
    fn body<'b>(&'b self, buffered: &'b [u8]) -> &'b [u8] {
        self.decoded
            .as_deref()
            .unwrap_or(&buffered[self.head_end..])
    }
}

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
    // RED (codeaudit conformance L message.rs:38, tests-A L tests/mod.rs:45): delay-seconds is
    // 1*DIGIT, so a sign is no wait (Rust's integer parse takes a leading `+`).
    assert_eq!(crate::message::parse_retry_after("+7", 0), None);
    // Right length, wrong month.
    assert_eq!(
        crate::message::parse_retry_after("Sun, 06 Xxx 1994 08:49:37 GMT", 0),
        None
    );
}

/// RFC 9110 5.6.7: a recipient MUST accept all three HTTP-date forms, and a date with an
/// out-of-range field is no date at all (1.5.5 parsed with `httpdate` and read it the same way).
#[test]
fn retry_after_reads_every_http_date_form() {
    let now = 784_111_777 - 120;
    for form in [
        "Sun, 06 Nov 1994 08:49:37 GMT",
        "Sunday, 06-Nov-94 08:49:37 GMT",
        "Sun Nov  6 08:49:37 1994",
    ] {
        assert_eq!(
            crate::message::parse_retry_after(form, now),
            Some(120),
            "{form}"
        );
    }
    assert_eq!(
        crate::message::parse_retry_after("Sun, 06 Nov 1994 99:99:99 GMT", now),
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
        let done = complete_message(&buffered, &mut cache, usize::MAX, usize::MAX).unwrap();
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
    assert!(
        complete_message(&buffered, &mut cache, usize::MAX, usize::MAX)
            .unwrap()
            .is_none()
    );

    const CALLS: usize = 200;
    const PIECE: &[u8] = b"10\r\naaaaaaaaaaaaaaaa\r\n";
    let mut wire_bytes = 0_usize;
    for _ in 0..CALLS {
        buffered.extend_from_slice(PIECE);
        wire_bytes += PIECE.len();
        assert!(
            complete_message(&buffered, &mut cache, usize::MAX, usize::MAX)
                .unwrap()
                .is_none(),
            "no terminal chunk yet, so the message is not whole"
        );
    }
    buffered.extend_from_slice(b"0\r\n\r\n");
    wire_bytes += 5;
    let done = complete_message(&buffered, &mut cache, usize::MAX, usize::MAX)
        .unwrap()
        .expect("the terminal chunk completes the message");
    assert_eq!(
        done.body(&buffered).len(),
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
        complete_message(smuggled, &mut cache, usize::MAX, usize::MAX).unwrap_err(),
        "transfer-encoding with content-length",
        "a chunked body naming a Content-Length beside it is the smuggling shape, refused rather \
         than silently disambiguated and forwarded"
    );

    let clean =
        b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
    let mut clean_cache = EgressHead::default();
    let done = complete_message(clean, &mut clean_cache, usize::MAX, usize::MAX)
        .unwrap()
        .expect(
            "a normal chunked body with no Content-Length still completes — this refuses the \
                 smuggling PAIR, not chunked encoding on its own",
        );
    assert_eq!(
        done.body(clean),
        b"abc",
        "the clean chunked body still decodes byte-exact"
    );
}

/// Every request line names its version. Without the check any two words followed by a space parse
/// as a request, so a blob that is not HTTP at all is read as one and its first two words become a
/// method and a path this transport goes on to act on.
#[test]
fn a_start_line_with_no_http_version_is_not_a_message() {
    assert!(
        raw::Head::parse(b"GET /\r\nHost: x\r\n\r\n").is_err(),
        "a request line with no version token is not a request line"
    );
    assert!(
        raw::Head::parse(b"NOT A REQUEST\r\nHost: x\r\n\r\n").is_err(),
        "an arbitrary first line is not a request line"
    );
    assert!(
        raw::Head::parse(b"GET / HTTP/2\r\nHost: x\r\n\r\n").is_err(),
        "a version this reader does not frame is refused, not read with 1.x's rules"
    );
    assert!(
        raw::Head::parse(b"HTTP/2 200 OK\r\n\r\n").is_err(),
        "and the same on the status side"
    );
    assert!(raw::Head::parse(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").is_ok());
    assert!(raw::Head::parse(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n").is_ok());
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
    let mut cache = EgressHead::default();
    let whole = complete_message(&bytes, &mut cache, usize::MAX, usize::MAX)
        .unwrap()
        .expect("a message it can read");
    let parsed = raw::Head::parse(&bytes[..whole.head_end]).expect("a head it can read");
    assert_eq!((parsed.method, parsed.path), ("POST", Some("/v1/messages")));
    assert_eq!(whole.body(&bytes), b"{\"model\":\"m\"}");
}

/// An envelope naming NO path is not one that named `/`: it renders an empty target word and reads
/// back as no target at all, while a stated `/` reads back as `/` (the framing decides where each
/// goes, `crate::message::request_target`).
#[test]
fn no_target_named_and_a_stated_root_stay_distinct() {
    let unnamed = crate::transport::render_envelope(&[("method", b"GET".as_slice())], b"").unwrap();
    assert!(unnamed.starts_with(b"GET  HTTP/1.1\r\n"), "{unnamed:?}");
    let head = raw::Head::parse(&unnamed).expect("readable");
    assert_eq!((head.method, head.path), ("GET", None));
    let root = crate::transport::render_envelope(
        &[("method", b"GET".as_slice()), ("path", b"/".as_slice())],
        b"",
    )
    .unwrap();
    let head = raw::Head::parse(&root).expect("readable");
    assert_eq!((head.method, head.path), ("GET", Some("/")));
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

/// `encode` refuses a method that is not an RFC 9110 token, and a target carrying a space, as
/// `Unrepresentable`, never answering READY with a request line its own `emit` then refuses.
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

/// RED (audit A1 F10; `limits.request_body_max_bytes` is the BODY's cap, held to a `Content-Length`
/// body already): a chunked request body is held to the same cap, by its decoded length. A body at
/// the cap completes; one byte over is refused, and refused as soon as the decoded bytes pass the
/// cap, before its terminal chunk. RED on the reader that bounded a chunked body only by the whole
/// buffer (the cap plus the head's allowance).
#[test]
fn a_chunked_request_body_is_held_to_the_body_cap() {
    let whole =
        b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
    let mut cache = EgressHead::default();
    let done = complete_message(whole, &mut cache, 5, usize::MAX)
        .unwrap()
        .expect("a body at the cap is whole");
    assert_eq!(done.body(whole), b"abcde");
    let mut cache = EgressHead::default();
    assert_eq!(
        complete_message(whole, &mut cache, 4, usize::MAX).unwrap_err(),
        "decoded chunked body over the body cap",
        "one byte over the cap"
    );
    let open = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n";
    let mut cache = EgressHead::default();
    assert_eq!(
        complete_message(open, &mut cache, 4, usize::MAX).unwrap_err(),
        "decoded chunked body over the body cap",
        "refused once the decoded bytes pass the cap, before the terminal chunk"
    );
}

/// RED (audit A1 F11): bytes an `emit` carries past the end of its message (past the declared
/// `Content-Length`, or past the terminal chunk and its trailer section) are a mis-framed writer's,
/// refused loudly rather than dropped. A message that ends exactly where its bytes end completes.
#[test]
fn bytes_past_the_end_of_a_request_message_are_refused() {
    let past_length = b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabcX";
    let mut cache = EgressHead::default();
    assert_eq!(
        complete_message(past_length, &mut cache, usize::MAX, usize::MAX).unwrap_err(),
        "bytes past the end of the message",
        "a byte past the declared length"
    );
    let past_chunks =
        b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\nX";
    let mut cache = EgressHead::default();
    assert_eq!(
        complete_message(past_chunks, &mut cache, usize::MAX, usize::MAX).unwrap_err(),
        "bytes past the end of the message",
        "a byte past the terminal chunk"
    );
    let past_head = b"GET / HTTP/1.1\r\nHost: x\r\n\r\nX";
    let mut cache = EgressHead::default();
    assert_eq!(
        complete_message(past_head, &mut cache, usize::MAX, usize::MAX).unwrap_err(),
        "bytes past the end of the message",
        "a byte after a message that declares no body"
    );
    let exact = b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc";
    let mut cache = EgressHead::default();
    assert!(complete_message(exact, &mut cache, usize::MAX, usize::MAX)
        .unwrap()
        .is_some());
}

/// RED (audit A1 F12): a head arriving across many `emit` calls is searched for its end once, each
/// call resuming where the last stopped (`find_header_end_from`), not rescanned from its first byte
/// every call: linear in the head, never quadratic up to the head's allowance. RED on the search
/// that restarted at offset 0 on every call.
#[test]
fn the_egress_header_search_resumes_where_it_stopped() {
    let mut head = b"POST / HTTP/1.1\r\nHost: x\r\nX-Long: ".to_vec();
    head.extend(std::iter::repeat_n(b'a', 4096));
    head.extend_from_slice(b"\r\nContent-Length: 0\r\n\r\n");
    let mut cache = EgressHead::default();
    let mut buffered = Vec::new();
    for (i, b) in head.iter().enumerate() {
        buffered.push(*b);
        let done = complete_message(&buffered, &mut cache, usize::MAX, usize::MAX).unwrap();
        assert_eq!(done.is_some(), i == head.len() - 1);
    }
    let scanned = cache.scanned;
    assert!(
        scanned <= 4 * head.len(),
        "a {}-byte head arriving a byte per call cost {scanned} bytes of searching",
        head.len()
    );
}

/// A `Content-Length` that does not name exactly one valid length is unrecoverable framing: a list
/// whose members disagree, two lines that disagree, a sign, non-digits. Each is refused, never read
/// as a body-less message.
#[test]
fn a_content_length_that_names_no_single_length_is_refused() {
    for head in [
        "Content-Length: 3, 4\r\n",
        "Content-Length: 3\r\nContent-Length: 4\r\n",
        "Content-Length: +5\r\n",
        "Content-Length: abc\r\n",
    ] {
        // With no body yet and with a body a lenient reader would accept: neither is a message.
        for body in ["", "abc"] {
            let msg = format!("POST / HTTP/1.1\r\n{head}\r\n{body}");
            let mut cache = EgressHead::default();
            assert!(
                complete_message(msg.as_bytes(), &mut cache, 1024, usize::MAX).is_err(),
                "{head:?} with body {body:?}"
            );
        }
    }
}

/// A `Transfer-Encoding` that is not (only) `chunked` is a coding this transport cannot frame; the
/// message is refused rather than read by its `Content-Length`.
#[test]
fn a_transfer_encoding_other_than_chunked_is_refused() {
    for te in ["gzip", "chunked, gzip"] {
        let msg = format!("POST / HTTP/1.1\r\ntransfer-encoding: {te}\r\n\r\n");
        let mut cache = EgressHead::default();
        assert!(
            complete_message(msg.as_bytes(), &mut cache, 1024, usize::MAX).is_err(),
            "{te:?}"
        );
    }
}

/// RED (codeaudit correctness L transport.rs:91, conformance NIT transport.rs:95): `encode`
/// promises to refuse what the framing's own reading of its message refuses, rather than answer
/// READY and fail at `emit`, but it judged the length by the FIRST `content-length` alone (read as
/// a `usize`, so `+5` passed), never looked at `transfer-encoding`, and let through value bytes
/// `emit`'s request builder refuses. Each is refused at encode now.
#[test]
fn encode_refuses_what_emit_would_refuse() {
    let refused = |fields: &[(&str, &[u8])], body: &[u8], what: &str| {
        assert_eq!(
            crate::transport::render_envelope(fields, body).err(),
            Some(busbar_contract::transport::wire::Encode::Unrepresentable),
            "{what}"
        );
    };
    refused(
        &[("content-length", b"5"), ("content-length", b"6")],
        b"hello",
        "two lengths that disagree",
    );
    refused(&[("content-length", b"+5")], b"hello", "a signed length");
    refused(
        &[("transfer-encoding", b"gzip")],
        b"",
        "a coding this framing does not read",
    );
    refused(
        &[("transfer-encoding", b"chunked"), ("content-length", b"0")],
        b"",
        "a coding beside a length",
    );
    refused(&[("x-note", b"a\x01b")], b"", "a control byte in a value");
    refused(&[("x-note", b"a\x7fb")], b"", "DEL in a value");
    // What the framing reads, encode still renders.
    for (fields, body) in [
        (&[("content-length", &b"5"[..])][..], &b"hello"[..]),
        (&[("content-length", b"5"), ("content-length", b"5")], b"hello"),
        (&[("x-note", b"tab\there obs-\xe9")], b""),
        (&[], b""),
    ] {
        crate::transport::render_envelope(fields, body).expect("still encodes");
    }
}
