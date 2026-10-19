// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What this transport declares about itself, as the kind's own file (`BUSBAR-1.6.0.md` THE
//! DESIGN, §2): the schemes it claims, how each is framed, and the transport kind's tail its door
//! states. Read once at registration and sealed, so it is data, held apart from the framing code it
//! describes.

use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::abi::mechanism::door::KindTailHead;
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

/// The layers this framer is built over: none. The carrier is the connector's choice from the
/// target's scheme; no transport names another (`BUSBAR-1.6.0.md` TRANSPORT-STACK (2)).
pub(crate) const COMPOSES_OVER: &[&str] = &[];

/// Neither claim carries a session.
pub(crate) const SESSION: bool = false;

pub(crate) const NONE: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

pub(crate) const TAIL: TransportTail = TransportTail {
    head: KindTailHead {
        size: std::mem::size_of::<TransportTail>() as u32,
        _reserved: 0,
    },
    role: ROLE_FRAMER,
    framing: FRAMING_STREAM,
    // THE FACT, PRECISELY: nothing an auth could sign is added after the auth (THE DESIGN §6 step
    // 5). The framer's own lines (`accept`, `host`) are stated at `locate` and the length line for
    // a non-empty body is stated by the host, all before the auth runs; the framer renders exactly
    // that head and adds no line at `encode` or `emit`.
    //
    // THE ONE EXCEPTION, scoped exactly (Q128 transport-http, ruling (D)): HTTP/2, a payload
    // method (hyper's `method_has_defined_payload_semantics`: any but GET, HEAD, DELETE and
    // CONNECT), an EMPTY body. The host states no length for an empty body (1.5.5's HTTP/1.1 wire
    // carries none), and the h2 framing adds `content-length: 0` at send, exactly as 1.5.5's client
    // (reqwest 0.12 over hyper 1.11.0, v1.5.5 Cargo.lock) did: hyper `src/proto/h2/client.rs`
    // l.710-713, `set_content_length_if_missing` when the body's exact size is 0 and
    // `method_has_defined_payload_semantics`. A 1.5.5 parity exception, recorded as the
    // coordinator's ruling (D) on Q128 transport-http. That line is added after the auth, and it is not one an
    // auth could sign: the only fleet style handed the head (`STYLE_NEEDS_HEADERS`, sigv4) signs a
    // fixed set that never names `content-length`, and every other style is handed no head at all.
    // Pinned: `tests/h2_parity.rs` (both wires against 1.5.5's client), and busbar-auth-sigv4's
    // `no_length_line_is_ever_signed`.
    facts: busbar_contract::abi::transport::FACT_SIGNS_NOTHING_AFTER_AUTH,
    handshake_max_steps: 0,
    frame_piece_size: FRAME_PIECE_SIZE,
    _reserved: 0,
    // No transport names another: the carrier is the connector's choice from the target's scheme.
    composes_over: std::ptr::null(),
    composes_over_len: 0,
    claim_rows: crate::door::CLAIMS.as_ptr(),
    claim_rows_len: crate::door::CLAIMS.len(),
    upgrades_to: std::ptr::null(),
    upgrades_to_len: 0,
    handoff_from: NONE,
    handoff_to: NONE,
    handoff_binding_fact: NONE,
    handshake_frame_kind: NONE,
    status_rows: crate::door::STATUS_ROWS.as_ptr(),
    status_rows_len: crate::door::STATUS_ROWS.len(),
    settings: crate::door::SETTINGS.as_ptr(),
    settings_len: crate::door::SETTINGS.len(),
    fault_rows: crate::door::FAULT_ROWS.as_ptr(),
    fault_rows_len: crate::door::FAULT_ROWS.len(),
};
