// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The claim shapes this transport declares, as the kind's own file (`BUSBAR-1.6.0.md` THE DESIGN, §2).
//!
//! A transport's claim is a SELECTOR FORM: the shape of question a plane may ask of arriving bytes
//! on this wire. It is a declaration and nothing else — data read once at registration — which is
//! why it lives beside `meta.rs` rather than inside the connection code that never reads it.

use busbar_contract::SelectorForm;

/// The forms an INGRESS claim over this wire may take.
///
/// `http` carries a request line and headers, so a claim on this wire can be about either. The
/// accepted side honours EXACTLY these (`door::accept`, `door::guest`): a claim becomes a guest-list
/// line whose route the door matches in the contract's one route vocabulary
/// (`abi::transport::route`; `BUSBAR-1.6.0.md` §6 "Auth points and guest lists" item 3, l.906-910:
/// "The match vocabulary is defined once in `abi/transport`"), so a form is declared here only
/// where that vocabulary spells it: the five path forms (`PATH_EXACT`, `PATH_PREFIX`,
/// `PATH_PATTERN`, `PATH_SUFFIX`, `PATH_CONTAINS`) and the two field predicates (`FIELD_PRESENT`,
/// `FIELD_VALUE_PREFIX`). `HeaderExact` is not declared: no route predicate spells an exact value,
/// so the door could never honour a claim in it.
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
