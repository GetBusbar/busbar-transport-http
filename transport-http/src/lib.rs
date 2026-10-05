// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `http` transport: ONE framer entry, claiming the `http` and `sse` schemes.
//!
//! A plugin exports one entry and its schemes are its claims (`BUSBAR-1.6.0.md` TRANSPORT-STACK,
//! ARCHITECT correction 2026-09-27: "ONE ENTRY PER PLUGIN"). This crate's entry is its memory-ABI
//! [`door`], a sans-IO framer: no socket, no waker, no clock of its own. The connector owns the
//! socket and connection security and chooses the carrier from the target's scheme, so the framer
//! composes over nothing (`COMPOSES_OVER` is empty: no transport names another). An `sse` stream is
//! an HTTP response body, so the `sse` claim is framed exactly as `http` is; a plane reads the event
//! boundaries in the body it is handed ([`sse::reframe`] is the shape a plane may re-frame it in).
//! gRPC is its own transport plugin (OWNER 2026-09-29), not a claim of this one.
//!
//! `http` carries no session and its status class rides the first response frame: the
//! kernel-derived leg of the fee decision the design's settlement table reads.
//!
//! The in-process `impl Transport` rows (`HttpTransport`, `SseTransport`) and their ingress reader
//! are gone: they were built only for the boot seal and carried no byte. The root folds this row
//! from the door's Statement on the transport-door axis.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

// THE KIND'S SKELETON (`BUSBAR-1.6.0.md` THE DESIGN, §2): what it declares (`meta`), what it claims
// (`claims`), the entry's own message rendering (`transport`), and the door that states them.
mod claims;
// THE ABI BOUNDARY: the door reads and writes the host's C buffers through the SDK's safe surface
// (`busbar_contract::abi::sdk::{SafeSlot, Lent, HostBuf}`), so it holds no `unsafe` either.
pub mod door;
mod message;
mod meta;
mod raw;
mod transport;

pub mod mount;

/// SSE as a plane may re-frame an HTTP response body (the `sse` claim is framed as `http`).
pub mod sse;

pub use raw::{RawMessage, RawStartLine};

pub(crate) use message::{complete_message, request_target, retry_after_secs, EgressHead};

/// The settings a composition root resolves off the deployment's `limits:`: the contract's
/// [`TransportSettings`](busbar_contract::transport::TransportSettings), named here too so this
/// crate's own callers read the name they always did.
pub use busbar_contract::transport::TransportSettings as ClientSettings;
pub use busbar_contract::transport::{
    DEFAULT_REQUEST_BODY_MAX_BYTES, DEFAULT_REQUEST_TIMEOUT_SECS,
};

/// THE TRANSPORT AXIS ENTRY (#3, #30): what the composition root folds for this row: its key, the
/// layers it declares (none: the carrier is the connector's choice) and its door. The root names
/// none of them. The door's Statement claims `http` and `sse`; the root registers both from it.
pub mod linked {
    /// The row's registry key: the entry's first claim.
    pub const KEY: &str = crate::meta::KEY;
    /// The layers this framer declares it is built over: none. The connector chooses the carrier
    /// from the target's scheme (`BUSBAR-1.6.0.md`: "no transport names another").
    pub const COMPOSES_OVER: &[&str] = crate::meta::COMPOSES_OVER;
    /// Whether this wire carries sessions.
    pub const SESSION: bool = crate::meta::SESSION;

    /// The `http` framer's memory-ABI door: the one entry, linked here and exported by the
    /// dropped-in build alike.
    pub use crate::door::door;
}

#[cfg(test)]
mod tests;
