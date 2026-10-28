// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The HTTP/2 frame reader the wire tests share.

/// One HTTP/2 frame: `(type, flags, stream, payload)`.
pub type H2Frame = (u8, u8, u32, Vec<u8>);

pub fn h2_frames(b: &[u8]) -> (Vec<u8>, Vec<H2Frame>) {
    let mut out = Vec::new();
    let mut i = 24.min(b.len());
    while i + 9 <= b.len() {
        let len = usize::from(b[i]) << 16 | usize::from(b[i + 1]) << 8 | usize::from(b[i + 2]);
        let stream = u32::from_be_bytes([b[i + 5], b[i + 6], b[i + 7], b[i + 8]]) & 0x7fff_ffff;
        out.push((b[i + 3], b[i + 4], stream, b[i + 9..i + 9 + len].to_vec()));
        i += 9 + len;
    }
    (b[..24.min(b.len())].to_vec(), out)
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
