// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What this transport declares about itself, as the kind's own file (`BUSBAR-1.6.0.md` THE
//! DESIGN, §2): the schemes it claims, how each is framed, and the transport kind's tail its door
//! states. Read once at registration and sealed, so it is data, held apart from the framing code it
//! describes.

use busbar_contract::abi::transport::{
    TransportTail, FRAME_PIECE_SIZE, FRAMING_STREAM, ROLE_FRAMER,
};

/// The `http` claim: the entry's first claim and the row's key.
pub const KEY: &str = "http";

/// The `sse` claim: an HTTP response body read as a stream of events, framed as `http` is.
pub mod sse {
    /// The `sse` claim's key.
    pub const KEY: &str = "sse";
}

/// The `sse` claim's key, by its own name.
pub(crate) const SSE_KEY: &str = sse::KEY;

/// The secured form of the scheme: an `https` target is an `http` one whose bytes the connector
/// secures before they leave (THE DESIGN §5: "http claims `http`, `https` and `sse`").
pub(crate) const SECURE_KEY: &str = "https";

pub(crate) const TAIL: TransportTail = {
    // No transport names another: the carrier is the connector's choice from the target's scheme.
    let mut t = TransportTail::EMPTY
        .with_claim_rows(crate::door::CLAIMS)
        .with_status_rows(crate::door::STATUS_ROWS)
        .with_settings(crate::door::SETTINGS)
        .with_fault_rows(crate::door::FAULT_ROWS);
    t.role = ROLE_FRAMER;
    t.framing = FRAMING_STREAM;
    t.frame_piece_size = FRAME_PIECE_SIZE;
    t
};
