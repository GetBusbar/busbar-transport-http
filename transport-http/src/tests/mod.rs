// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The crate's own battery: the HTTP/1.1 message an `emit` accumulates (one parse and one chunked

use super::*;

impl crate::message::Whole {
    /// The body, where it lies: decoded, or the rest of the buffered bytes.
    fn body<'b>(&'b self, buffered: &'b [u8]) -> &'b [u8] {
        self.decoded
            .as_ref()
            .map(|body| body.as_slice())
            .unwrap_or(&buffered[self.head_end..])
    }
}

/// Both RFC 9110 forms, and nothing else. A value nobody can read is a value nobody asked for.
#[test]
fn retry_after_parses_both_normative_forms() {
    assert_eq!(crate::message::parse_retry_after("7", 1_000), Some(7));
    assert_eq!(
        crate::message::parse_retry_after("  120 ", 9_999),
        Some(120)
    );
    assert_eq!(crate::message::parse_retry_after("0", 0), Some(0));

    assert_eq!(
        crate::message::parse_retry_after("Sun, 06 Nov 1994 08:49:37 GMT", 784_111_777 - 30),
        Some(30)
    );

    assert_eq!(
        crate::message::parse_retry_after("Sun, 06 Nov 1994 08:49:37 GMT", 784_111_777 + 90),
        Some(0)
    );

    assert_eq!(crate::message::parse_retry_after("", 0), None);
    assert_eq!(crate::message::parse_retry_after("soon", 0), None);
    assert_eq!(crate::message::parse_retry_after("-5", 0), None);
    assert_eq!(crate::message::parse_retry_after("7.5", 0), None);

    assert_eq!(crate::message::parse_retry_after("+7", 0), None);

    assert_eq!(
        crate::message::parse_retry_after("Sun, 06 Xxx 1994 08:49:37 GMT", 0),
        None
    );
}

/// RFC 9110 5.6.7: a recipient MUST accept all three HTTP-date forms, and a date with an
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

    assert!(
        cache.head.is_none(),
        "a completed message leaves no stale head"
    );
}

/// The egress chunked body is decoded once, not once per `write` call.
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

    assert!(
        cache.head.is_none() && cache.decoder.is_none(),
        "a completed message leaves no stale decoder"
    );
}

/// The egress mirror of `a_message_with_both_a_transfer_encoding_and_a_content_length_is_refused`,
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

    let mut cache = EgressHead::default();
    let whole = complete_message(&bytes, &mut cache, usize::MAX, usize::MAX)
        .unwrap()
        .expect("a message it can read");
    let parsed = raw::Head::parse(&bytes[..whole.head_end]).expect("a head it can read");
    assert_eq!((parsed.method, parsed.path), ("POST", Some("/v1/messages")));
    assert_eq!(whole.body(&bytes), b"{\"model\":\"m\"}");
}

/// An envelope naming NO path is not one that named `/`: it renders an empty target word and reads
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

/// A chunked request body is held to the configured body cap.
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

/// Bytes emitted past the end of a request message are refused.
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

/// Egress header searches resume where the preceding emit stopped.
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
#[test]
fn a_content_length_that_names_no_single_length_is_refused() {
    for head in [
        "Content-Length: 3, 4\r\n",
        "Content-Length: 3\r\nContent-Length: 4\r\n",
        "Content-Length: +5\r\n",
        "Content-Length: abc\r\n",
    ] {
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
#[test]
fn a_transfer_encoding_other_than_chunked_is_refused() {
    for te in ["gzip", "chunked, gzip", "gzip, chunked"] {
        let msg = format!("POST / HTTP/1.1\r\ntransfer-encoding: {te}\r\n\r\n");
        let mut cache = EgressHead::default();
        assert!(
            complete_message(msg.as_bytes(), &mut cache, 1024, usize::MAX).is_err(),
            "{te:?}"
        );
    }
}

/// Encoding refuses the same invalid messages as emit.
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

    for (fields, body) in [
        (&[("content-length", &b"5"[..])][..], &b"hello"[..]),
        (
            &[("content-length", b"5"), ("content-length", b"5")],
            b"hello",
        ),
        (&[("x-note", b"tab\there obs-\xe9")], b""),
        (&[], b""),
    ] {
        crate::transport::render_envelope(fields, body).expect("still encodes");
    }
}

/// The `linked` entry's `SESSION` is what every claim row the door states says (sibling alignment
#[test]
fn linked_session_is_every_claim_rows_session() {
    let session = crate::linked::SESSION;
    assert!(!session);
    assert!(crate::door::CLAIMS
        .iter()
        .all(|c| (c.session != 0) == crate::linked::SESSION));
}

#[test]
fn chunk_decoding_wipes_owned_lines_and_each_body_allocation_on_abandonment_or_completion() {
    for complete in [false, true] {
        let probe = crate::wipe_probe::Probe::start();
        let mut decoder = crate::raw::ChunkedDecoder::default();
        let line = b"4000;credential=chunk-line-secret";
        decoder.feed(line).unwrap();
        decoder.feed(b"\r\n").unwrap();
        for _ in 0..16 {
            decoder.feed(&[b'x'; 1024]).unwrap();
        }
        assert_eq!(decoder.body_len(), 16 * 1024);
        if complete {
            decoder
                .feed(b"\r\n0\r\nx-secret: trailer-secret\r\n\r\n")
                .unwrap();
            assert!(decoder.is_done());
            let body = decoder.take();
            assert_eq!(body.as_slice(), &[b'x'; 16 * 1024]);
            drop(body);
        } else {
            drop(decoder);
        }
        probe
            .finish()
            .assert_wiped_on_linux(&["chunk decoded", "chunk line"]);
    }
}
