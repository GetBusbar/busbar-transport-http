// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The claim shapes this transport declares.  A transport's claim is a SELECTOR FORM: the shape
//! of question a plane may ask of arriving bytes on this wire.

use busbar_contract::SelectorForm;

/// The forms an INGRESS claim over this wire may take.  `http` carries a request line and
/// headers, so a claim on this wire can be about either.
pub(crate) const SELECTOR_FORMS: &[SelectorForm] = &[
    SelectorForm::ExactPath,
    SelectorForm::PrefixOneLevel,
    SelectorForm::PathPattern,
    SelectorForm::HeaderPresent,
    SelectorForm::HeaderPrefix,
    SelectorForm::PathSuffix,
    SelectorForm::PathContains,
];

/// The forms an INGRESS claim on the `sse` scheme may take: none. The request that opens an event
/// stream is an `http` request, and the claim that reads it is the `http` one.
pub(crate) const SSE_SELECTOR_FORMS: &[SelectorForm] = &[];
