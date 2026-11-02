// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What this transport declares about itself: the schemes it claims, how each is framed, and the

use busbar_contract::abi::transport::{
    TransportTail, FRAME_PIECE_SIZE, FRAMING_STREAM, ROLE_FRAMER,
};

/// The `http` claim: the entry's first claim and the row's key.
pub const KEY: &str = "http";

/// The `sse` claim's key: an HTTP response body read as a stream of events, framed as `http` is.
pub(crate) const SSE_KEY: &str = "sse";

/// The secured form of the scheme: an `https` target is an `http` one whose bytes the connector
pub(crate) const SECURE_KEY: &str = "https";

/// The layers this framer is built over: none. The carrier is the connector's choice from the
pub(crate) const COMPOSES_OVER: &[&str] = &[];

/// Whether this transport carries sessions: no (each claim row states `session` 0).
pub(crate) const SESSION: bool = false;

pub(crate) const TAIL: TransportTail = TransportTail {
    role: ROLE_FRAMER,
    framing: FRAMING_STREAM,

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
