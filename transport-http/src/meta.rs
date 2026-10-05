// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What this transport declares about itself, as the kind's own file (`BUSBAR-1.6.0.md` THE
//! DESIGN, §2): the schemes it claims and how each is framed. Read once at registration and sealed,
//! so it is data, held apart from the framing code it describes; the door's Statement states it.

/// The `http` claim: the entry's first claim and the row's key.
pub(crate) const KEY: &str = "http";

/// The `sse` claim: an HTTP response body read as a stream of events, framed as `http` is.
pub(crate) const SSE_KEY: &str = "sse";

/// The layers this framer is built over: none. The carrier is the connector's choice from the
/// target's scheme; no transport names another (`BUSBAR-1.6.0.md` TRANSPORT-STACK (2)).
pub(crate) const COMPOSES_OVER: &[&str] = &[];

/// Neither claim carries a session.
pub(crate) const SESSION: bool = false;
