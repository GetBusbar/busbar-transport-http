// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A minimal HTTP/1.1 message reader: just enough to split the envelope the door's `emit` is handed
//! (request line, headers, blank line, body) into its parts and read its framing fields. Not a
//! general-purpose parser — no header folding, and no transfer coding is read: a message that
//! names one is refused by `complete_message`, since the host states the length line before the
//! auth (THE DESIGN §6 step 5). The door's responses are read by hyper, never by this.

/// The message's request line, `METHOD path HTTP/version`: the only start line this reader takes.
/// The envelope `emit` is handed is a request; a status line is not one and does not parse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawStartLine {
    /// The request method.
    pub method: String,
    /// The request target the message STATED; `None` = it named none (an empty target word,
    /// `METHOD  HTTP/version`). A stated `/` is `Some("/")`: it is a target like any other.
    pub path: Option<String>,
}

/// One parsed message: its start line, its headers in wire order, and its body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawMessage {
    /// The request line.
    pub start: RawStartLine,
    /// Header name/value pairs, in the order they appeared. A value is its bytes as sent (obs-text
    /// included), without the optional whitespace around it.
    pub headers: Vec<(String, Vec<u8>)>,
    /// Everything after the blank line.
    pub body: Vec<u8>,
}

/// Split `bytes` into a start line, headers and body. `bytes` may end exactly at the header
/// terminator (body empty) or carry the body already appended. Returns `None` on anything that
/// does not look like an HTTP/1.x message (no CRLF-terminated start line, a header line with no
/// colon, or whitespace between a field name and its colon — which the wire forbids outright).
#[must_use]
pub fn parse_message(bytes: &[u8]) -> Option<RawMessage> {
    let text_end = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 2) // keep the final lone CRLF as the header block's own terminator
        .unwrap_or(bytes.len());
    let header_block = &bytes[..text_end];
    let body = if text_end + 2 <= bytes.len() {
        bytes[text_end + 2..].to_vec()
    } else {
        Vec::new()
    };

    // The start line and every field name are text; a field VALUE is bytes (RFC 9110 5.5: obs-text
    // is a value's, and 1.5.5's client carried such a value as given).
    let mut lines = header_block
        .split(|b| *b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .filter(|l| !l.is_empty());
    let start = parse_start_line(std::str::from_utf8(lines.next()?).ok()?)?;

    let mut headers = Vec::new();
    for line in lines {
        let colon = line.iter().position(|b| *b == b':')?;
        let name = std::str::from_utf8(&line[..colon]).ok()?;
        // No whitespace is allowed between a field name and its colon. Trimming it here would
        // normalise a header no compliant peer would honour into one this transport does, and the
        // disagreement that opens between an intermediary and its upstream is exactly the
        // request-smuggling surface the rule exists to close. So: refuse the message.
        if name != name.trim() {
            return None;
        }
        headers.push((name.to_string(), ows_trimmed(&line[colon + 1..]).to_vec()));
    }

    Some(RawMessage {
        start,
        headers,
        body,
    })
}

/// `value` without the optional whitespace (SP, HTAB) a field line may carry around it (RFC 9112
/// 5.1); every other byte stays.
fn ows_trimmed(value: &[u8]) -> &[u8] {
    let ows = |b: &u8| *b == b' ' || *b == b'\t';
    let start = value.iter().position(|b| !ows(b)).unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|b| !ows(b))
        .map_or(start, |at| at + 1);
    &value[start..end]
}

fn parse_start_line(line: &str) -> Option<RawStartLine> {
    let mut parts = line.splitn(3, ' ');
    let a = parts.next()?;
    let b = parts.next()?;
    let c = parts.next().unwrap_or("");
    // A status line (`HTTP/version code reason`) is not a request: refused here, as the line it is.
    if a.starts_with("HTTP/") {
        return None;
    }
    // Otherwise: `METHOD path HTTP/version`. The version token is REQUIRED. Without the check a
    // two-word first line — anything at all, followed by a space — parses as a request, so a blob
    // that is not HTTP is read as one and its first two words become a method and a path this
    // transport then acts on. The wire says every request line names its version; a line that does
    // not is not a request line.
    let version = c.strip_prefix("HTTP/")?;
    if !is_http1(version) {
        return None;
    }
    Some(RawStartLine {
        method: a.to_string(),
        path: (!b.is_empty()).then(|| b.to_string()),
    })
}

/// Whether a version token names the HTTP/1.x this reader frames.
///
/// The framing rules below — `Content-Length`, `Transfer-Encoding`, a CRLF-terminated header
/// block — are 1.x's. A `2` or a `3` names a wire made of frames this reader has never seen, and
/// reading one with 1.x's rules would produce a message nobody sent.
fn is_http1(version: &str) -> bool {
    matches!(version, "1.0" | "1.1")
}

/// Find a header's value, case-insensitively, as the wire allows any casing.
#[must_use]
pub fn header<'a>(headers: &'a [(String, Vec<u8>)], name: &str) -> Option<&'a [u8]> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_slice())
}

/// A field's WHOLE value: every line carrying that name, joined with `", "`, or `None` when no
/// line carries it.
///
/// RFC 9110 5.3 makes this the definition of a repeated field: a sender may split a comma-separated
/// list across several lines, and the meaning is the one line those values would have made. Reading
/// only the first line therefore reads a different field than the one that was sent — and for the
/// framing fields below that is not a cosmetic difference, it is a body length. `Transfer-Encoding:
/// chunked` followed by `Transfer-Encoding: gzip` is the list `chunked, gzip`, whose final coding is
/// not `chunked` and whose length RFC 9112 6.1 leaves undeterminable; a reader that saw only the
/// first line would frame a body the sender never described.
#[must_use]
pub fn field_list(headers: &[(String, Vec<u8>)], name: &str) -> Option<String> {
    let mut out: Option<String> = None;
    for (_, v) in headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case(name)) {
        // A framing field is ASCII; a byte that is not reads as U+FFFD, which no coding or length
        // matches, so such a value is refused rather than guessed at.
        let v = String::from_utf8_lossy(v);
        match &mut out {
            Some(acc) => {
                acc.push_str(", ");
                acc.push_str(v.trim());
            }
            None => out = Some(v.trim().to_string()),
        }
    }
    out
}

/// Whether a header block declares a transfer coding at all, on any of its lines and in any case.
///
/// The question `complete_message` refuses on: a request framed by any coding, `chunked` included,
/// is a framing the host never states, and telling it apart from a message that names none is what
/// lets the door refuse the first without refusing the second.
#[must_use]
pub fn has_transfer_encoding(headers: &[(String, Vec<u8>)]) -> bool {
    field_list(headers, "transfer-encoding").is_some()
}

/// The declared body length, where the message declares one.
///
/// `Ok(None)` when no `Content-Length` header is present. `Err(())` when one is present and is not
/// exactly `1*DIGIT` fitting a `usize` — a leading sign, a non-decimal digit, an overflowing value,
/// or a second `Content-Length` disagreeing with the first. RFC 9112 6.3: an unparsable
/// `Content-Length` with no `Transfer-Encoding` is unrecoverable framing, never a body-less
/// message. RFC 9110 8.6 allows treating identical duplicate values as one, which this does.
///
/// # Errors
///
/// Returns `Err(())` when the header is present but does not name a single valid body length.
pub fn content_length(headers: &[(String, Vec<u8>)]) -> Result<Option<usize>, ()> {
    // The whole field, however many lines it was spelled across: a second `Content-Length` line is
    // the same list a comma would have made, and reading only the first would take a message that
    // declares two lengths for one that declares one.
    let Some(list) = field_list(headers, "content-length") else {
        return Ok(None);
    };
    let mut values = list.split(',').map(str::trim);
    let Some(first) = values.next() else {
        return Ok(None);
    };
    for other in values {
        if other != first {
            return Err(());
        }
    }
    if first.is_empty() || !first.bytes().all(|b| b.is_ascii_digit()) {
        return Err(());
    }
    first.parse::<usize>().map(Some).map_err(|_| ())
}

#[cfg(test)]
#[path = "tests/raw.rs"]
mod tests;
