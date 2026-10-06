// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What this transport declares about itself, as the kind's own file (`BUSBAR-1.6.0.md` THE
//! DESIGN, §2): the schemes it claims, how each is framed, and the transport kind's tail its door
//! states. Read once at registration and sealed, so it is data, held apart from the framing code it
//! describes.

use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::abi::mechanism::door::KindTailHead;
use busbar_contract::abi::transport::{TransportTail, FRAMING_STREAM, ROLE_FRAMER};

/// The `http` claim: the entry's first claim and the row's key.
pub const KEY: &str = "http";

/// The `sse` claim: an HTTP response body read as a stream of events, framed as `http` is.
pub mod sse {
    /// The `sse` claim's key.
    pub const KEY: &str = "sse";
}

/// The `sse` claim's key, by its own name.
pub(crate) const SSE_KEY: &str = sse::KEY;

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
    facts: 0,
    handshake_max_steps: 0,
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
