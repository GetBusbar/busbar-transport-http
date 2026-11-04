// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The framer entry's own message rendering: an outbound envelope rendered as the one HTTP/1.1
//! request message the door's `encode` answers, the bytes the egress cross-check reads.

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
/// `content-length` among them, as the host stated it), through the blank line.
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

    let path = field("path").unwrap_or(b"");

    let clean = |v: &[u8]| !v.iter().any(|b| matches!(b, b'\r' | b'\n' | 0));

    if !is_token(method) || !clean(path) || path.contains(&b' ') {
        return Err(busbar_contract::transport::wire::Encode::Unrepresentable);
    }
    let mut size = method.len() + path.len() + 64;
    for (name, value) in fields {
        if name.eq_ignore_ascii_case("method") || name.eq_ignore_ascii_case("path") {
            continue;
        }
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
