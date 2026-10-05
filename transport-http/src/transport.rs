// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The framer entry's own message rendering, as the kind's entry file (`BUSBAR-1.6.0.md` THE
//! DESIGN, §2): an outbound envelope rendered as the one HTTP/1.1 request message the door's
//! `encode` answers, the bytes the egress cross-check reads. The framing itself is the door's
//! (`crate::door::engine`).

/// Render an outbound envelope (`fields`, post-decoration) and `body` as one HTTP/1.1 request
/// message: the bytes the egress cross-check reads, whichever door rendered them.
///
/// # Errors
///
/// A CR, LF or NUL in the method, the path, a field name or a value: `Encode::Unrepresentable`.
pub(crate) fn render_envelope(
    fields: &[(&str, &[u8])],
    body: &[u8],
) -> Result<Vec<u8>, busbar_contract::transport::wire::Encode> {
    let field = |name: &str| {
        fields
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| *v)
    };
    let method = field("method").unwrap_or(b"POST");
    let path = field("path").unwrap_or(b"/");

    // A CR, an LF or a NUL anywhere in a name, a value, the method or the path is a byte that
    // ENDS a line on this wire. Writing one through means the caller chooses where this
    // transport's header block ends and what comes after it: a value of
    // `x\r\nauthorization: bearer ...` is not a header value, it is a second header, injected.
    // The check is before the first byte is written, so nothing half-built ever reaches the
    // arena.
    let clean = |v: &[u8]| !v.iter().any(|b| matches!(b, b'\r' | b'\n' | 0));
    if !clean(method) || !clean(path) {
        return Err(busbar_contract::transport::wire::Encode::Unrepresentable);
    }
    for (name, value) in fields {
        if !clean(name.as_bytes()) || !clean(value) {
            return Err(busbar_contract::transport::wire::Encode::Unrepresentable);
        }
    }

    let mut out = Vec::with_capacity(body.len() + 128);
    out.extend_from_slice(method);
    out.push(b' ');
    out.extend_from_slice(path);
    out.extend_from_slice(b" HTTP/1.1\r\n");
    for (name, value) in fields {
        if name.eq_ignore_ascii_case("method") || name.eq_ignore_ascii_case("path") {
            continue;
        }
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value);
        out.extend_from_slice(b"\r\n");
    }
    // The length is this transport's to state: it is a fact about the bytes below, not
    // something an envelope gets to disagree with.
    out.extend_from_slice(format!("content-length: {}\r\n", body.len()).as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    Ok(out)
}
