// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The HTTP/2 frame reader the wire tests share.

/// One HTTP/2 frame: `(type, flags, stream, payload)`.
pub type H2Frame = (u8, u8, u32, Vec<u8>);

/// The connection preface and every frame of `b`, the WHOLE wire: bytes past the last whole frame
/// (a stray tail, or a frame cut short) fail the cell in words rather than going uncompared.
///
/// # Panics
/// `b` does not end on a frame boundary.
pub fn h2_frames(b: &[u8]) -> (Vec<u8>, Vec<H2Frame>) {
    let mut out = Vec::new();
    let mut i = 24.min(b.len());
    while i + 9 <= b.len() {
        let len = usize::from(b[i]) << 16 | usize::from(b[i + 1]) << 8 | usize::from(b[i + 2]);
        let stream = u32::from_be_bytes([b[i + 5], b[i + 6], b[i + 7], b[i + 8]]) & 0x7fff_ffff;
        let Some(payload) = b.get(i + 9..i + 9 + len) else {
            break;
        };
        out.push((b[i + 3], b[i + 4], stream, payload.to_vec()));
        i += 9 + len;
    }
    assert_eq!(
        i,
        b.len(),
        "{} bytes past the last whole frame: {:?}",
        b.len() - i,
        &b[i..]
    );
    (b[..24.min(b.len())].to_vec(), out)
}

/// Whether `b` (a client's bytes) holds a whole request: on HTTP/2 a frame on a stream that ends
/// it (END_STREAM); on HTTP/1.1 the head and the body its `content-length` states.
#[allow(dead_code)] // `h2_parity`'s; `wire_golden` reads recorded captures.
pub fn request_whole(b: &[u8], h2: bool) -> bool {
    if h2 {
        let mut i = 24;
        while i + 9 <= b.len() {
            let len = usize::from(b[i]) << 16 | usize::from(b[i + 1]) << 8 | usize::from(b[i + 2]);
            if i + 9 + len > b.len() {
                return false;
            }
            let stream = u32::from_be_bytes([b[i + 5], b[i + 6], b[i + 7], b[i + 8]]) & 0x7fff_ffff;
            if stream != 0 && matches!(b[i + 3], 0 | 1) && b[i + 4] & 1 != 0 {
                return true;
            }
            i += 9 + len;
        }
        return false;
    }
    let Some(end) = b.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    let head = String::from_utf8_lossy(&b[..end]).to_ascii_lowercase();
    let len = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    b.len() >= end + 4 + len
}

pub fn frame_name(t: u8) -> &'static str {
    match t {
        0 => "DATA",
        1 => "HEADERS",
        2 => "PRIORITY",
        3 => "RST_STREAM",
        4 => "SETTINGS",
        5 => "PUSH_PROMISE",
        6 => "PING",
        7 => "GOAWAY",
        8 => "WINDOW_UPDATE",
        9 => "CONTINUATION",
        _ => "OTHER",
    }
}
