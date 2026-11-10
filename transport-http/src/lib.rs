// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `http` transport: ONE framer entry, claiming the `http`, `https` and `sse` schemes.  A
//! plugin exports one entry and its schemes are its claims.

#![cfg_attr(not(test), forbid(unsafe_code))]
#![deny(unsafe_code)]
#![deny(missing_docs)]

mod claims;

mod door;

/// The validated ABI entry and generated registration constant.
pub use door::{door, MACRO_DOOR};
mod message;
mod meta;
mod raw;
mod transport;

pub(crate) use message::{complete_message, request_target, retry_after_secs, EgressHead};

/// THE TRANSPORT AXIS ENTRY: what the composition root folds for this row: its key, the layers it
/// declares (none: the carrier is the connector's choice) and its door.
pub mod linked {
    /// The row's registry key: the entry's first claim.
    pub const KEY: &str = crate::meta::KEY;
    /// The layers this framer declares it is built over: none. The connector chooses the carrier
    /// from the target's scheme: no transport names another.
    pub const COMPOSES_OVER: &[&str] = crate::meta::COMPOSES_OVER;
    /// Whether this transport carries sessions: no, as every claim row states.
    pub const SESSION: bool = crate::meta::SESSION;

    /// The `http` framer's memory-ABI door: the one entry, linked here and exported by the
    /// dropped-in build alike.
    pub use crate::door::{door, MACRO_DOOR};
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/wipe_probe.rs"]
mod wipe_probe;

// Source-owned integration tests are compiled only by the assembling host test harness.
