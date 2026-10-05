// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SSE as a plane may re-frame an HTTP response body.
//!
//! `sse` is a claim of this crate's one framer entry ([`crate::door`]), framed exactly as `http` is:
//! an event stream is an HTTP response body, handed up as the body pieces it arrived in. The
//! in-process `SseTransport` that re-segmented those bytes at each event's blank line was built
//! only for the boot seal and carried no byte; it is gone with the other in-process rows. What
//! remains is [`reframe`]: the shape a plane may present a buffered result in as an event stream.

#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod reframe;
