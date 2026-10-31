// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The framer entry's own message rendering: an outbound envelope rendered as the one HTTP/1.1
//! request message the door's `encode` answers, the bytes the egress cross-check reads. The framing
//! itself is the door's (`crate::door::engine`).

use zeroize::Zeroizing;

/// An RFC 9110 `token`: one or more `tchar`. A field name is one; anything else (a `:`, a space,
/// a control byte, a non-ASCII byte) is not a name this wire can carry back out unchanged.
fn is_token(name: &[u8]) -> bool {
    !name.is_empty()
        && name.iter().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// Render the head of the one HTTP/1.1 request message an outbound envelope (`fields`,
/// post-decoration) with a `body_len`-byte body makes: the request line and the fields (the
/// `content-length` among them, as the host stated it), through the blank line. The body follows it on the wire
/// as it is, so `encode` writes the head and then the body straight into the wire buffer. The head
/// carries the credential fields: it is wiped as it drops.
///
/// # Errors
///
/// A CR, LF or NUL in the method, the path, a field name or a value, a field name that is not an
/// RFC 9110 token (a `:` in a name would be re-read as a different field on the door's own
/// reparse), or a value `emit`'s request builder refuses (a control byte): `Encode::Unrepresentable`.
/// So is a head whose framing the door's own reading (`raw::Head::framing`, the one `emit` reads
/// it by) does not take as exactly `body_len` bytes: a `content-length` other than `body_len`, two
/// that disagree, a signed one, any `transfer-encoding`, or a non-empty body with no length stated.
/// The length is one of the transport's own lines the host states BEFORE the auth: this renders it
/// where the host put it and adds no line of its own.
pub(crate) fn render_head(
    fields: &[(&str, &[u8])],
    body_len: usize,
) -> Result<Zeroizing<Vec<u8>>, busbar_contract::transport::wire::Encode> {
    let field = |name: &str| {
        fields
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| *v)
    };
    let method = field("method").unwrap_or(b"POST");
    // NO TARGET NAMED is not a stated `/`: it renders as an empty target word, which the framing
    // reads back as `None` (the dial's own path, on the connection's first request only), while a
    // stated `/` goes to `/` (`crate::message::request_target`).
    let path = field("path").unwrap_or(b"");

    // A CR, an LF or a NUL anywhere in a name, a value, the method or the path is a byte that
    // ENDS a line on this wire. Writing one through means the caller chooses where this
    // transport's header block ends and what comes after it: a value of
    // `x\r\nauthorization: bearer ...` is not a header value, it is a second header, injected.
    // The check is before the first byte is written, so nothing half-built ever reaches the
    // arena.
    let clean = |v: &[u8]| !v.iter().any(|b| matches!(b, b'\r' | b'\n' | 0));
    // The request line is `METHOD SP target SP version`: a method that is not an RFC 9110 token, or
    // a target with a space in it, is a line the framing's own reading of it refuses, so it is
    // refused here, before anything is rendered, not answered READY and refused at `emit`.
    if !is_token(method) || !clean(path) || path.contains(&b' ') {
        return Err(busbar_contract::transport::wire::Encode::Unrepresentable);
    }
    let mut size = method.len() + path.len() + 64;
    for (name, value) in fields {
        // A value is what `emit`'s request builder takes as one (`http::HeaderValue`: visible
        // bytes, SP, HTAB and obs-text, RFC 9110 5.5), judged here, not there.
        if !is_token(name.as_bytes())
            || !clean(value)
            || http::HeaderValue::from_bytes(value).is_err()
        {
            return Err(busbar_contract::transport::wire::Encode::Unrepresentable);
        }
        size += name.len() + value.len() + 4;
    }

    let mut out = Zeroizing::new(Vec::with_capacity(size));
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
    out.extend_from_slice(b"\r\n");

    // THE LENGTH is a fact about the bytes below, stated in the head the auth saw: it must frame
    // them exactly, and an empty body states none (1.5.5's client sent none for one on HTTP/1.1;
    // on HTTP/2 its framing added `content-length: 0` for a payload method, as this door's does:
    // the one exception `meta::TAIL` names). It is judged by the reading `emit` frames the message
    // by, so the two never disagree.
    let framed = crate::raw::Head::parse(&out)
        .ok()
        .and_then(|h| h.framing().ok())
        == Some(crate::raw::BodyFraming::Length(body_len));
    if !framed {
        return Err(busbar_contract::transport::wire::Encode::Unrepresentable);
    }
    Ok(out)
}

/// The whole message, head and body, for a test to read back.
#[cfg(test)]
pub(crate) fn render_envelope(
    fields: &[(&str, &[u8])],
    body: &[u8],
) -> Result<Vec<u8>, busbar_contract::transport::wire::Encode> {
    let mut out = render_head(fields, body.len())?.to_vec();
    out.extend_from_slice(body);
    Ok(out)
}
