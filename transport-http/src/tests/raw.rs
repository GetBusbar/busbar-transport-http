//! Tests for `raw.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;

#[test]
fn parses_a_request_line_and_headers() {
    let raw = b"GET /v1/models HTTP/1.1\r\nHost: example\r\nContent-Length: 3\r\n\r\nabc";
    let msg = parse_message(raw).unwrap();
    assert_eq!(
        msg.start,
        RawStartLine {
            method: "GET".to_string(),
            path: Some("/v1/models".to_string())
        }
    );
    assert_eq!(msg.headers[0], ("Host".to_string(), b"example".to_vec()));
    assert_eq!(msg.body, b"abc");
}

#[test]
fn the_declared_length_and_coding_are_read_whatever_the_header_casing() {
    let headers = vec![
        ("CONTENT-length".to_string(), b" 12 ".to_vec()),
        ("Transfer-Encoding".to_string(), b"gzip, Chunked".to_vec()),
    ];
    assert_eq!(content_length(&headers), Ok(Some(12)));
    assert!(has_transfer_encoding(&headers));
    assert!(has_transfer_encoding(&[(
        "transfer-ENCODING".to_string(),
        b"gzip".to_vec()
    )]));
}

/// Whitespace between a field name and its colon is refused, not normalised away.
///
/// RFC 9112 is explicit that a server MUST reject such a message: the historical divergence in
/// how intermediaries handled it is a request-smuggling surface, and trimming the name turns a
/// header no compliant peer would honour into one this transport does.
#[test]
fn whitespace_before_the_colon_is_refused_rather_than_trimmed() {
    assert_eq!(
        parse_message(b"GET / HTTP/1.1\r\nContent-Length : 5\r\n\r\n"),
        None
    );
    assert_eq!(
        parse_message(b"GET / HTTP/1.1\r\nTransfer-Encoding\t: chunked\r\n\r\n"),
        None
    );
    // The legal shape still parses, value whitespace and all.
    let ok = parse_message(b"GET / HTTP/1.1\r\nContent-Length:  5 \r\n\r\n").unwrap();
    assert_eq!(ok.headers[0].1, b"5");
}

/// Any coding, on any line, is a declared coding: the question `complete_message` refuses on.
///
/// A coding list split across lines is one field (RFC 9110 5.3), so a second line naming
/// `chunked` after a first naming `gzip` is still a coding; and a message naming only a length
/// declares none.
#[test]
fn a_transfer_coding_on_any_line_is_a_declared_coding() {
    for list in [
        &b"chunked"[..],
        b"chunked, gzip",
        b"gzip, chunked",
        b"identity",
    ] {
        assert!(has_transfer_encoding(&[(
            "Transfer-Encoding".to_string(),
            list.to_vec()
        )]));
    }
    assert!(has_transfer_encoding(&[
        ("Content-Length".to_string(), b"5".to_vec()),
        ("Transfer-Encoding".to_string(), b"gzip".to_vec()),
        ("transfer-encoding".to_string(), b"chunked".to_vec()),
    ]));
    assert!(!has_transfer_encoding(&[(
        "Content-Length".to_string(),
        b"5".to_vec()
    )]));
}

/// A status line is not a request: the envelope `emit` is handed always is one, so a message that
/// opens with a status line does not parse (and `complete_message` refuses it as framing).
#[test]
fn a_status_line_is_not_a_request() {
    assert_eq!(
        parse_message(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"),
        None
    );
}
