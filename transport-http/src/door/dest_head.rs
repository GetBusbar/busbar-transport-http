// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The request target as the URL parser serialises it: a space in a model name goes out as `%20`,
//! never refused.

/// Why a target cannot be written.
pub const REFUSED: &str = "a request target holds CR, LF or NUL";

fn hex(out: &mut Vec<u8>, b: u8) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    out.extend_from_slice(&[b'%', HEX[usize::from(b >> 4)], HEX[usize::from(b & 15)]]);
}

fn in_path_set(b: u8) -> bool {
    b <= 0x20 || b >= 0x7f || matches!(b, b'"' | b'<' | b'>' | b'`' | b'{' | b'}')
}

fn in_query_set(b: u8) -> bool {
    b <= 0x20 || b >= 0x7f || matches!(b, b'"' | b'#' | b'<' | b'>' | b'\'')
}

fn is_dot(seg: &[u8]) -> bool {
    seg == b"." || seg.eq_ignore_ascii_case(b"%2e")
}

fn is_dot_dot(seg: &[u8]) -> bool {
    matches!(seg.len(), 2 | 4 | 6)
        && [&b".."[..], b".%2e", b"%2e.", b"%2e%2e"]
            .iter()
            .any(|d| seg.eq_ignore_ascii_case(d))
}

/// `target` as written on the request line.  # Errors  [`REFUSED`]: the target holds CR, LF or
/// NUL.
pub fn encode_target(target: &[u8]) -> Result<Vec<u8>, &'static str> {
    if target.iter().any(|b| matches!(b, b'\r' | b'\n' | 0)) {
        return Err(REFUSED);
    }

    let start = target
        .iter()
        .position(|b| *b > 0x20)
        .unwrap_or(target.len());
    let end = target
        .iter()
        .rposition(|b| *b > 0x20)
        .map_or(start, |at| at + 1);
    let mut filtered = zeroize::Zeroizing::new(Vec::with_capacity(end - start));
    filtered.extend(target[start..end].iter().copied().filter(|b| *b != b'\t'));
    let target = filtered;
    #[cfg(test)]
    crate::wipe_probe::watch("target filtered", &target);
    let target = target
        .iter()
        .position(|b| *b == b'#')
        .map_or(&target[..], |at| &target[..at]);
    let (path, query) = match target.iter().position(|b| *b == b'?') {
        Some(at) => (&target[..at], Some(&target[at + 1..])),
        None => (target, None),
    };

    let mut absolute = zeroize::Zeroizing::new(Vec::with_capacity(path.len().saturating_add(1)));
    if path.first().is_none_or(|b| *b != b'/' && *b != b'\\') {
        absolute.push(b'/');
    }
    absolute.extend(path.iter().map(|b| if *b == b'\\' { b'/' } else { *b }));
    let path = absolute;
    #[cfg(test)]
    crate::wipe_probe::watch("target path", &path);
    let mut segments: Vec<&[u8]> = Vec::new();
    let raw: Vec<&[u8]> = path.split(|b| *b == b'/').skip(1).collect();
    let last = raw.len().saturating_sub(1);
    for (i, seg) in raw.iter().enumerate() {
        if is_dot_dot(seg) {
            segments.pop();
            if i == last {
                segments.push(b"");
            }
        } else if is_dot(seg) {
            if i == last {
                segments.push(b"");
            }
        } else {
            segments.push(seg);
        }
    }

    let mut out = zeroize::Zeroizing::new(Vec::with_capacity(
        target.len().saturating_mul(3).saturating_add(1),
    ));
    if segments.is_empty() {
        out.push(b'/');
    }
    for seg in segments {
        out.push(b'/');
        for &b in seg {
            #[cfg(test)]
            crate::wipe_probe::watch("target encoded", &out);
            if in_path_set(b) {
                hex(&mut out, b);
            } else {
                out.push(b);
            }
        }
    }
    if let Some(query) = query {
        out.push(b'?');
        for &b in query {
            #[cfg(test)]
            crate::wipe_probe::watch("target encoded", &out);
            if in_query_set(b) {
                hex(&mut out, b);
            } else {
                out.push(b);
            }
        }
    }
    #[cfg(test)]
    crate::wipe_probe::watch("target encoded", &out);
    Ok(std::mem::take(&mut *out))
}
