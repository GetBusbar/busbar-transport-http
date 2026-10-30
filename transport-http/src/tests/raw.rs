//! Tests for `raw.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;

/// A head's framing, or its refusal.
fn framing(head: &str) -> Result<BodyFraming, &'static str> {
    Head::parse(head.as_bytes())?.framing()
}

#[test]
fn parses_a_request_line_and_headers() {
    let raw = b"GET /v1/models HTTP/1.1\r\nHost: example\r\nContent-Length: 3\r\n\r\nabc";
    let head = Head::parse(raw).unwrap();
    assert_eq!(head.method, "GET");
    assert_eq!(head.path, Some("/v1/models"));
    let fields: Vec<_> = head.fields().collect();
    assert_eq!(fields[0], (&b"Host"[..], &b"example"[..]));
    assert_eq!(fields.len(), 2, "the body is not a field");
    assert_eq!(head.framing(), Ok(BodyFraming::Length(3)));
}

#[test]
fn a_chunked_body_survives_arriving_one_byte_at_a_time() {
    // The boundary that matters: a size line, a chunk's data, the CRLF after it and the
    // trailer section are all free to be split by the network wherever it likes.
    let wire = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Checksum: 7\r\n\r\n";
    let mut decoder = ChunkedDecoder::default();
    for byte in wire {
        assert!(!decoder.is_done());
        decoder.feed(&[*byte]).unwrap();
    }
    assert!(decoder.is_done());
    assert_eq!(decoder.take(), b"Wikipedia");
}

#[test]
fn a_chunked_body_with_no_trailers_ends_at_the_terminal_chunk() {
    let mut decoder = ChunkedDecoder::default();
    decoder.feed(b"3\r\nabc\r\n0\r\n\r\n").unwrap();
    assert!(decoder.is_done());
    assert_eq!(decoder.take(), b"abc");
}

/// A trailer line is read for its grammar, though its content is discarded.
#[test]
fn a_trailer_line_with_no_colon_is_a_framing_error() {
    let mut decoder = ChunkedDecoder::default();
    assert_eq!(
        decoder.feed(b"3\r\nabc\r\n0\r\nno colon\r\n\r\n"),
        Err(ChunkedMalformed)
    );
}

/// What follows the end of the message is not taken.
#[test]
fn the_decoder_stops_at_the_end_of_the_message() {
    let mut decoder = ChunkedDecoder::default();
    assert_eq!(decoder.feed(b"3\r\nabc\r\n0\r\n\r\nXY"), Ok(13));
    assert!(decoder.is_done());
}

#[test]
fn a_size_line_that_is_not_hexadecimal_is_a_framing_error() {
    let mut decoder = ChunkedDecoder::default();
    assert_eq!(decoder.feed(b"zz\r\n"), Err(ChunkedMalformed));
}

/// RED: the size is `1*HEXDIG` (RFC 9112 7.1): no sign, no surrounding whitespace.
#[test]
fn a_signed_or_padded_chunk_size_is_a_framing_error() {
    for line in [
        &b"+5\r\nhello\r\n0\r\n\r\n"[..],
        b" 5\r\nhello\r\n0\r\n\r\n",
        b"5 \r\nhello\r\n0\r\n\r\n",
        b"\r\n",
    ] {
        let mut decoder = ChunkedDecoder::default();
        assert_eq!(decoder.feed(line), Err(ChunkedMalformed), "{line:?}");
    }
}

#[test]
fn chunk_extensions_are_ignored_rather_than_read() {
    let mut decoder = ChunkedDecoder::default();
    decoder.feed(b"3;name=value\r\nabc\r\n0\r\n\r\n").unwrap();
    assert!(decoder.is_done());
    assert_eq!(decoder.take(), b"abc");
}

#[test]
fn the_declared_length_and_coding_are_read_whatever_the_header_casing() {
    assert_eq!(
        framing("POST / HTTP/1.1\r\nCONTENT-length:  12 \r\n\r\n"),
        Ok(BodyFraming::Length(12))
    );
    assert_eq!(
        framing("POST / HTTP/1.1\r\nTransfer-Encoding: gzip, Chunked\r\n\r\n"),
        Ok(BodyFraming::Chunked)
    );
    assert_eq!(
        framing("POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n"),
        Err("unsupported transfer coding")
    );
}

/// Whitespace between a field name and its colon is refused, not normalised away.
///
/// RFC 9112 is explicit that a server MUST reject such a message: the historical divergence in
/// how intermediaries handled it is a request-smuggling surface, and trimming the name turns a
/// header no compliant peer would honour into one this transport does.
#[test]
fn whitespace_before_the_colon_is_refused_rather_than_trimmed() {
    assert!(Head::parse(b"GET / HTTP/1.1\r\nContent-Length : 5\r\n\r\n").is_err());
    assert!(Head::parse(b"GET / HTTP/1.1\r\nTransfer-Encoding\t: chunked\r\n\r\n").is_err());
    // The legal shape still parses, value whitespace and all.
    let ok = Head::parse(b"GET / HTTP/1.1\r\nContent-Length:  5 \r\n\r\n").unwrap();
    assert_eq!(ok.fields().next().unwrap().1, b"5");
}

/// `chunked` is the LAST coding or the message is not chunked at all.
///
/// A sender that applies any other coding must apply `chunked` as the final one, precisely so
/// the message stays framable; a `Transfer-Encoding` where it is not final leaves the body
/// length undeterminable, and a reader that took it for chunked anyway would be decoding a
/// framing the sender never wrote.
#[test]
fn chunked_counts_only_as_the_final_transfer_coding() {
    assert_eq!(
        framing("POST / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"),
        Ok(BodyFraming::Chunked)
    );
    // And a coding list that names one at all is still a declared coding, chunked or not: it is
    // refused, never read by a `Content-Length` (or as no body).
    assert_eq!(
        framing("POST / HTTP/1.1\r\nTransfer-Encoding: chunked, gzip\r\n\r\n"),
        Err("unsupported transfer coding")
    );
    assert_eq!(
        framing("POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\n"),
        Ok(BodyFraming::Length(5))
    );
}

/// The list is the whole field across every line carrying it (RFC 9110 5.3): `chunked` on one
/// line and `gzip` on the next is `chunked, gzip`, and `chunked` twice is a body wrapped twice.
#[test]
fn a_coding_list_spans_every_line_of_the_field() {
    for te in [
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\n",
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
        "Transfer-Encoding: chunked, chunked\r\n",
    ] {
        assert_eq!(
            framing(&format!("POST / HTTP/1.1\r\n{te}\r\n")),
            Err("unsupported transfer coding"),
            "{te:?}"
        );
    }
    assert_eq!(
        framing("POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n"),
        Ok(BodyFraming::Chunked)
    );
    assert_eq!(
        framing("POST / HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\n"),
        Ok(BodyFraming::Length(3)),
        "identical duplicates are one length (RFC 9110 8.6)"
    );
}

/// A status line is not a request.
#[test]
fn a_status_line_is_refused() {
    assert_eq!(
        Head::parse(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").err(),
        Some("a status line is not a request")
    );
}

/// RFC 9112 7.1.1: `chunk-ext = *( BWS ";" chunk-ext-name [ BWS "=" BWS chunk-ext-val ] )`, so a
/// size may be followed by whitespace before its extensions (codeaudit review of D8).
#[test]
fn whitespace_before_a_chunk_extension_is_allowed() {
    let mut decoder = ChunkedDecoder::default();
    decoder
        .feed(b"3 \t;name=value\r\nabc\r\n0\r\n\r\n")
        .unwrap();
    assert!(decoder.is_done());
    assert_eq!(decoder.take(), b"abc");
}

/// RED (codeaudit correctness L raw.rs:255): the decoder deleted EVERY CR in a size or trailer
/// line, so `1\r0` read as the size `10`, and took any run of CRs after a chunk's data. RFC 9112
/// 7.1: a line ends in CRLF; a CR anywhere else makes it malformed, and a chunk's data is closed
/// by one CRLF. (A bare LF ending a line is still read, RFC 9112 2.2.)
#[test]
fn a_cr_that_does_not_end_a_line_is_malformed() {
    for wire in [
        &b"1\r0\r\n0123456789abcdef\r\n0\r\n\r\n"[..],
        b"5\r\nhello\r\r\r\n0\r\n\r\n",
        b"5\r\nhello\r\n0\r\nx-t: a\rb\r\n\r\n",
        b"5\r\r\nhello\r\n0\r\n\r\n",
    ] {
        let mut decoder = ChunkedDecoder::default();
        assert_eq!(
            decoder.feed(wire),
            Err(ChunkedMalformed),
            "{:?}",
            String::from_utf8_lossy(wire)
        );
    }
    // Split anywhere, the CRLF still reads as one line end.
    let whole = b"5\r\nhello\r\n0\r\n\r\n";
    for at in 0..whole.len() {
        let mut decoder = ChunkedDecoder::default();
        decoder.feed(&whole[..at]).expect("the first part");
        decoder.feed(&whole[at..]).expect("the rest");
        assert!(decoder.is_done(), "split at {at}");
        assert_eq!(decoder.take(), b"hello");
    }
    let mut decoder = ChunkedDecoder::default();
    decoder.feed(b"5\nhello\n0\n\n").expect("bare LFs");
    assert_eq!(decoder.take(), b"hello");
}
