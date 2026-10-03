// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **`http` transport as a droppable busbar plugin**: the `cdylib` a signed tarball of the wire
//! carries (`kind: transport`, key `http`). The logic crate is re-exported whole, and its door
//! (`busbar_transport_http::door::door`) is exported as this image's ONE symbol,
//! `busbar_plugin_door` (`export_door!`), so the library carries exactly the door a busbar build links.
//!
//! This crate is `deny`, not `forbid`: the export macro's `#[unsafe(no_mangle)]` is the one
//! reviewed exemption. No other `unsafe` exists here.

#![deny(unsafe_code)]

pub use busbar_transport_http::*;

/// The exported door, behind `dropped-in` (the cdylib build only): the macro's `#[no_mangle]` symbol is
/// the one exemption.
#[cfg(feature = "dropped-in")]
#[allow(unsafe_code)]
mod exported {
    busbar_contract::export_door!(busbar_transport_http::door::door);
}
