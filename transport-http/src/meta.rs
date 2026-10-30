// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What this transport declares about itself: the schemes it claims, how each is framed, and the
//! transport kind's tail its door states. Read once at registration and sealed, so it is data, held
//! apart from the framing code it describes.

use busbar_contract::abi::transport::{
    TransportTail, FRAME_PIECE_SIZE, FRAMING_STREAM, ROLE_FRAMER,
};

/// The `http` claim: the entry's first claim and the row's key.
pub const KEY: &str = "http";

/// The `sse` claim's key: an HTTP response body read as a stream of events, framed as `http` is.
pub(crate) const SSE_KEY: &str = "sse";

/// The secured form of the scheme: an `https` target is an `http` one whose bytes the connector
/// secures before they leave.
pub(crate) const SECURE_KEY: &str = "https";

/// The layers this framer is built over: none. The carrier is the connector's choice from the
/// target's scheme; no transport names another.
pub(crate) const COMPOSES_OVER: &[&str] = &[];

pub(crate) const TAIL: TransportTail = TransportTail {
    role: ROLE_FRAMER,
    framing: FRAMING_STREAM,
    // Nothing is added to the head after the auth has run: the framer's own lines (`accept`,
    // `host`) are stated at `locate` and the length line by the host, all before the auth, and the
    // framer renders exactly that head (`the_head_on_the_wire_is_every_line_the_auth_saw`). The one
    // exception is 1.5.5's: HTTP/2, a payload method, an empty body gets `content-length: 0` at
    // send, as hyper's client did (`set_content_length_if_missing`); no auth style signs that line
    // (`tests/h2_parity.rs`).
    //
    // The ops this door serves: it dials; it serves the accepted side (`begin` on `SIDE_ACCEPT`,
    // `door::accept`); and it detaches an upgrade line, which the upgrade's transport adopts. It
    // does not adopt: nothing hands a connection to http.
    facts: busbar_contract::abi::transport::FACT_DIALS
        | busbar_contract::abi::transport::FACT_ACCEPTS
        | busbar_contract::abi::transport::FACT_DETACHES,
    frame_piece_size: FRAME_PIECE_SIZE,
    claim_rows: crate::door::CLAIMS.as_ptr(),
    claim_rows_len: crate::door::CLAIMS.len(),
    status_rows: crate::door::STATUS_ROWS.as_ptr(),
    status_rows_len: crate::door::STATUS_ROWS.len(),
    settings: crate::door::SETTINGS.as_ptr(),
    settings_len: crate::door::SETTINGS.len(),
    fault_rows: crate::door::FAULT_ROWS.as_ptr(),
    fault_rows_len: crate::door::FAULT_ROWS.len(),
    ..TransportTail::EMPTY
};
