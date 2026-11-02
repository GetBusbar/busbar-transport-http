// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The claim shapes this transport declares.

use busbar_contract::SelectorForm;

/// The forms an INGRESS claim over this wire may take.

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

pub(crate) const SSE_SELECTOR_FORMS: &[SelectorForm] = &[];
