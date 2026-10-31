// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `http` DOOR: this transport as a FRAMER on the transport kind's table
//! (`busbar_contract::abi::transport`), compiled in or dropped in through the one door. It is the
//! crate's ONE entry and claims three schemes, `http`, `https` (an `http` target the connector
//! secures) and `sse` (an event stream is an HTTP response body), all framed alike; it composes
//! over nothing, the carrier being the connector's choice.
//!
//! A framer frames; it does not dial. The connector owns the socket and connection security; the
//! protocol offer is this framer's (`locate` answers it), the connector makes it in the handshake
//! and tells this framer what was agreed in [`ConnFacts::agreed_protocol`]. A cleartext connection
//! has no handshake: it speaks HTTP/2 under the prior-knowledge key (offering `h2` alone, which the
//! connector hands back as agreed) and HTTP/1.1 otherwise. From there each op is one step of
//! [`engine::Framing`]:
//!
//! * `locate` reads a target URL: its authority, the name offered to the far end, and whether it
//!   asks for connection security (`https`);
//! * `begin` opens a dialled framing speaking the agreed protocol, and hands the host the bytes the
//!   far end is owed first (the HTTP/2 connection preface and settings);
//! * `encode` renders an envelope as ONE HTTP/1.1 request message, the bytes the egress
//!   cross-check reads; `emit` takes that message on a stream and sends it on the connection as
//!   whichever HTTP the connection speaks;
//! * `ingest` takes what the far end sent; `timer` is the host's clock reaching a deadline the
//!   framer asked for. Each answers the wire bytes owed and the frame pieces completed.
//!
//! A response arrives as frames on its stream: the HEAD frame (one field block, flagged
//! `PIECE_FIELDS` and carrying the status code, its class and any `Retry-After`; framed even when
//! no field is left in it), one frame per body chunk, and then an EMPTY frame that says the
//! response is whole. The field block is `busbar_contract::abi::transport::fields`' rendering:
//! lower-case names, hyper's (1.5.5's) order, a repeated field on its own lines, hop-by-hop fields
//! dropped here. A trailer section is not handed up: 1.5.5's client read a response through
//! reqwest, which yields data only.
//!
//! `locate` also answers this framer's protocol offer for a secured connection (ALPN, most
//! preferred first): `h2, http/1.1`, `http/1.1` alone under the http1-only key, or `h2` alone under
//! the prior-knowledge key, exactly as 1.5.5's client offered. The connector offers it and hands
//! back what was agreed. On a cleartext target the offer is `h2` alone under the prior-knowledge
//! key (the protocol spoken by prior knowledge) and none otherwise.
//!
//! One clock bounds each exchange, as 1.5.5's `limits.upstream_request_timeout_secs` did: from the
//! attempt's start (the deadline the caller stamps on `emit`) to the response body's end.
//!
//! An op that has nothing more to do answers what it has, with the next instant it must be called
//! at when hyper is waiting on a timer. The one op that may wait is the accepted side's call on the
//! host auth handle (below): a pending `auth.call` answers the op PENDING under the SDK's `Pend`
//! contract, and the op, re-entered with `FLAG_RESUME`, takes no input twice and re-issues the same
//! completion handle.
//!
//! Every slot is a `SafeSlot` on the SDK's safe surface: the instance is the SDK's typed
//! `sdk::Instance<Held<Instance>>`, host-lent bytes and host buffers go through `Lent` and
//! `HostBuf`, and this crate holds no `unsafe`.
//!
//! THE ACCEPTED SIDE IS THIS DOOR'S TOO: per accepted connection the connector runs this framer's
//! accept side, under the TLS server wrap when configured, and the ALPN offer is the framer's.
//! `begin` on [`SIDE_ACCEPT`] serves the connection as v1.5.5's data listener did ([`accept`]):
//! hyper's auto server, HTTP/2 by prior knowledge when the far side opens with its preface and
//! HTTP/1.1 otherwise, HTTP/1's header read bounded at 30 s, upgrades on (v1.5.5
//! `crates/busbar/src/tls.rs`:560-566, :620). Its TLS offer is `h2, http/1.1` ([`ACCEPT_OFFER`]),
//! the owner's signed change from v1.5.5's `http/1.1` alone. Each request goes up as a stream (its
//! head a field block with its method, target and authority in the head slots, then its body); its
//! answer comes down through `emit`, the first emit its head with the status in `EmitIn::status`,
//! the later ones its body. `detach` hands the connection to the claimed upgrade framer: as the far
//! side sent it while nothing has been answered (the upgrade framer answers the upgrade itself), or
//! from the byte after a request the host answered `101`. `refuse` answers the host's refusal of an
//! accepted stream or connection ([`Accepted::refuse`]); `adopt` and every carrier op are refused.
//!
//! THE ACCEPTED SIDE GOES THROUGH THE GUEST LIST. `begin` on [`SIDE_ACCEPT`] keeps the listener's
//! lines (`BeginIn::lines`, [`guest`]); after every drive, each decoded request is matched, its
//! line's auth called at its points, what the auth names stripped, and the request handed in, all
//! through the host auth handle the instance was opened with (`OpenIn::host`'s services:
//! `auth.call`, `unit.hand_in`, `unit.refuse`, [`HostKernel`]). Only an admitted request goes up; a
//! refused one is answered with the kernel's bytes, framed verbatim ([`accept`]).

pub(crate) mod accept;
pub(crate) mod dest_head;
pub(crate) mod engine;
mod framings;
pub(crate) mod guest;

// This crate's own seal over what the auth handle answers (`Services::auth_call`): an accepting
// side's answer names what to strip and carries no secret of its own.
busbar_contract::own_seal!(Own);

// The sans-IO `hyper` drive (pipe, executor, host-clock timer, sink fill), from the contract's SDK,
// expanded over this crate's own `hyper` and `bytes`.
busbar_contract::hyper_io!(::bytes::Bytes);

use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use std::task::Poll;

use busbar_contract::abi::host::service::{AuthRef, UnitRef};
use busbar_contract::abi::mechanism::call::{AbiStr, InHead, OutHead, Outcome, FLAG_RESUME};
use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
use busbar_contract::abi::mechanism::lifecycle::{CancelIn, CancelOut, RefreshIn};
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::life::{self, Held as Opened, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::services::{
    HeadViewArgs, Pend, RefusalCopy, ServiceError, Services,
};
use busbar_contract::abi::sdk::transport::{form_codes, settings_reading, DEFAULT_BODY_MAX};
use busbar_contract::abi::sdk::{self as sdk, Lent, Out, Safe, SafeSlot};
use busbar_contract::abi::transport::{
    AcceptIn, AcceptOut, AdoptIn, ArrivalIn, ArrivalOut, BeginIn, Claim, ConnIn, ConnOut, DialIn,
    EmitIn, EncodeIn, FaultRow, FinishIn, FramerOut, FramerSink, FramingIn, IngestIn, IoOut,
    ListenIn, ListenOut, LocateIn, LocateOut, Ops, ReadIn, RefuseIn, SettingDecl, ShutIn,
    StatusRow, TransportTail, WriteIn, CANCEL_NOTHING_MOVED, CANCEL_PARTIAL, EXT_OFFERED_POINTS,
    FAULT_CALLER, FAULT_HARD, FAULT_NONE, FAULT_TRANSIENT, SETTING_COUNT, SETTING_FLAG,
    SIDE_ACCEPT, SIDE_DIAL, STATUS_AT_FIRST_FRAME, STATUS_CALLER_FAULT, STATUS_FAR_END_FAULT,
    STATUS_OTHER, STATUS_SUCCESS, YIELD_ENDED, YIELD_MORE,
};
use busbar_contract::transport::registry::{facts as tfacts, status_ns};

use accept::{Accepted, AuthCalled, Kernel};
use busbar_contract::abi::mechanism::check::{fault, Fault, Rule};
use engine::{Framing, Posture, Proto};
use framings::{Framings, Held};
#[cfg(test)]
use hyper_io::field_cut;
use hyper_io::{fill, mark_stream_full, Owed};

// ── the statement ────────────────────────────────────────────────────────────────────────────────

/// The settings this transport reads, at their 1.5.5 paths.
pub mod setting {
    /// Force cleartext HTTP/2 prior knowledge.
    pub const H2_PRIOR_KNOWLEDGE: &str = "advanced.upstream_h2_prior_knowledge";
    /// Pin the connection to HTTP/1.1.
    pub const HTTP1_ONLY: &str = "advanced.upstream_http1_only";
    /// The ceiling on one exchange, from the attempt's start to the response body's end, in seconds.
    pub const REQUEST_TIMEOUT_SECS: &str = "limits.upstream_request_timeout_secs";
    /// The largest request body carried, in bytes (a response body is not capped here).
    pub const BODY_MAX_BYTES: &str = "limits.request_body_max_bytes";
}

const SELECTOR_CODES: [u8; crate::claims::SELECTOR_FORMS.len()] =
    form_codes(crate::claims::SELECTOR_FORMS);
const SSE_SELECTOR_CODES: [u8; crate::claims::SSE_SELECTOR_FORMS.len()] =
    form_codes(crate::claims::SSE_SELECTOR_FORMS);

const FACTS: &[AbiStr] = &[
    abi_str(tfacts::PATH),
    abi_str(tfacts::METHOD),
    abi_str(tfacts::AUTHORITY),
    abi_str(tfacts::PEER),
];

const fn bytes_str(b: &'static [u8]) -> AbiStr {
    AbiStr {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}

/// The schemes this ONE entry claims, by name: the Statement's `claims`, the one place they are
/// stated. `http`, `sse` (an HTTP response body read as events) and `https` (an `http` target the
/// connector secures), framed alike.
const CLAIM_NAMES: &[AbiStr] = &[
    abi_str(crate::meta::KEY),
    abi_str(crate::meta::SSE_KEY),
    abi_str(crate::meta::SECURE_KEY),
];

/// The `http` claim's row; `https` is the same wire, so it carries the same row.
const HTTP_ROW: Claim = Claim {
    selector_forms: bytes_str(&SELECTOR_CODES),
    egress_selector_forms: abi_str(""),
    facts: FACTS.as_ptr(),
    facts_len: FACTS.len(),
    status_namespace: abi_str(status_ns::HTTP),
    status_at: STATUS_AT_FIRST_FRAME,
    ..Claim::ZERO
};

/// Each claimed scheme's row, by index into [`CLAIM_NAMES`]. The `sse` row reads no request facts
/// and no selector of its own (the request that opens a stream is an `http` one); its status leg is
/// `http`'s, at the first frame.
pub(crate) const CLAIMS: &[Claim] = &[
    HTTP_ROW,
    Claim {
        selector_forms: bytes_str(&SSE_SELECTOR_CODES),
        egress_selector_forms: abi_str(""),
        status_namespace: abi_str(status_ns::HTTP),
        status_at: STATUS_AT_FIRST_FRAME,
        ..Claim::ZERO
    },
    HTTP_ROW,
];

/// HTTP's status classes, read alike on every claim.
const HTTP_CLASSES: [(u32, u32, u32); 3] = [
    (200, 299, STATUS_SUCCESS as u32),
    (400, 499, STATUS_CALLER_FAULT as u32),
    (500, 599, STATUS_FAR_END_FAULT as u32),
];

/// Each claim's status classes, by claim index: `sse` and `https` read `http`'s.
pub(crate) const STATUS_ROWS: &[StatusRow] = &status_rows();

const fn status_rows() -> [StatusRow; FAULT_CLAIMS * HTTP_CLASSES.len()] {
    let mut out = [StatusRow {
        claim: 0,
        lo: 0,
        hi: 0,
        class: 0,
    }; FAULT_CLAIMS * HTTP_CLASSES.len()];
    let mut i = 0;
    while i < out.len() {
        let (lo, hi, class) = HTTP_CLASSES[i % HTTP_CLASSES.len()];
        out[i] = StatusRow {
            claim: (i / HTTP_CLASSES.len()) as u32,
            lo,
            hi,
            class,
        };
        i += 1;
    }
    out
}

/// What each answer means to the BREAKER, in HTTP's numbering: the fault table, beside the status
/// table and never folded into it (the status class is the fee decision's leg). A refused
/// credential (`401`, `403`) takes the destination down for every caller. A timed-out or throttled
/// request (`408`, `429`) and every `5xx` (`529`, a provider's overloaded answer, among them) is the
/// destination's transient fault, its `Retry-After` the cooldown floor. Every other `4xx` is the
/// caller's own. A status off the table (`2xx`, `3xx`) states no reading. This is 1.5.5's breaker
/// table exactly, on the wire that owns the numbering.
const HTTP_FAULTS: [(u32, u32, u8); 10] = [
    (400, 400, FAULT_CALLER),
    (401, 401, FAULT_HARD),
    (402, 402, FAULT_CALLER),
    (403, 403, FAULT_HARD),
    (404, 407, FAULT_CALLER),
    (408, 408, FAULT_TRANSIENT),
    (409, 428, FAULT_CALLER),
    (429, 429, FAULT_TRANSIENT),
    (430, 499, FAULT_CALLER),
    (500, 599, FAULT_TRANSIENT),
];

/// How many claims the status and fault tables cover, by claim index: every claim.
const FAULT_CLAIMS: usize = CLAIM_NAMES.len();

/// The fault table, by claim index: `sse` and `https` read `http`'s.
pub(crate) const FAULT_ROWS: &[FaultRow] = &fault_rows();

const fn fault_rows() -> [FaultRow; FAULT_CLAIMS * HTTP_FAULTS.len()] {
    let mut out = [FaultRow {
        claim: 0,
        lo: 0,
        hi: 0,
        fault: 0,
    }; FAULT_CLAIMS * HTTP_FAULTS.len()];
    let mut i = 0;
    while i < out.len() {
        let (lo, hi, fault) = HTTP_FAULTS[i % HTTP_FAULTS.len()];
        out[i] = FaultRow {
            claim: (i / HTTP_FAULTS.len()) as u32,
            lo,
            hi,
            fault: fault as u32,
        };
        i += 1;
    }
    out
}

/// Each setting this framer reads: its path, its kind and the default it declares. The ONE source
/// of each default: the declarations below render from it and `read_settings` applies it.
const SETTING_ROWS: [(&str, u32, &str); 4] = [
    (setting::H2_PRIOR_KNOWLEDGE, SETTING_FLAG, "false"),
    (setting::HTTP1_ONLY, SETTING_FLAG, "false"),
    (setting::REQUEST_TIMEOUT_SECS, SETTING_COUNT, "300"),
    (setting::BODY_MAX_BYTES, SETTING_COUNT, DEFAULT_BODY_MAX),
];

/// [`SETTING_ROWS`] as the Statement's setting declarations.
const fn setting_decls() -> [SettingDecl; SETTING_ROWS.len()] {
    let mut out = [SettingDecl {
        path: abi_str(""),
        kind: 0,
        _reserved: 0,
        default: abi_str(""),
    }; SETTING_ROWS.len()];
    let mut i = 0;
    while i < SETTING_ROWS.len() {
        let (path, kind, default) = SETTING_ROWS[i];
        out[i] = SettingDecl {
            path: abi_str(path),
            kind,
            _reserved: 0,
            default: abi_str(default),
        };
        i += 1;
    }
    out
}

pub(crate) const SETTINGS: &[SettingDecl] = &setting_decls();

/// THE AUTH POINTS THIS DOOR OFFERS: `Peer` (once per connection, before any head: the call
/// carries no request and its answer no field or name, `door::accept`), `Head` and `HeadBody`.
/// With no record the host reads `{Head, HeadBody}` and refuses at boot a line whose auth needs
/// `Peer`.
const OFFERED_POINTS: [u8; 4] = (busbar_contract::abi::auth::POINT_PEER
    | busbar_contract::abi::auth::POINT_HEAD
    | busbar_contract::abi::auth::POINT_HEAD_BODY)
    .to_le_bytes();

busbar_contract::statement_extensions!(
    /// The Statement's extensions: this plugin's whole `declares` document, and the auth points
    /// it offers.
    EXTENSIONS: [
        (
            busbar_contract::abi::mechanism::extensions::EXT_DECLARES,
            include_bytes!("../../declares.json")
        ),
        (EXT_OFFERED_POINTS, &OFFERED_POINTS),
    ]
);

/// The door's Statement: the `http` framer, claiming `http`, `https` and `sse`.
pub const STATEMENT: Statement = Statement {
    kind_tail: (&crate::meta::TAIL as *const TransportTail).cast::<KindTailHead>(),
    claims: CLAIM_NAMES.as_ptr(),
    claims_len: CLAIM_NAMES.len(),
    extensions: EXTENSIONS,
    ..statement(crate::meta::KEY, env!("CARGO_PKG_VERSION"), 64)
};

// ── the instance ─────────────────────────────────────────────────────────────────────────────────

/// What `open` read from the settings (and the last good `refresh` replaced), and the framings it
/// holds.
pub struct Instance {
    settings: Mutex<Settings>,
    framings: Framings,
    /// The listeners' guest lists, shared by the connections each accepts.
    guests: guest::Lists,
}

/// Every slot's state: the SDK's held instance over [`Instance`], with the host tables `open` was
/// handed (the auth handle an accepted side admits its requests through).
type State = Opened<Instance>;

/// The settings as read: the posture every framing begun under them carries, and the two keys
/// that choose the protocol offer.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Settings {
    posture: Posture,
    prior_knowledge: bool,
    http1_only: bool,
}

impl Instance {
    /// The settings in force: what `open` read, or the last good `refresh`. Held only to copy them,
    /// by `locate` and `begin` (per connection, never per chunk).
    fn settings(&self) -> Settings {
        *self.settings.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The default the count setting `path` declares ([`SETTING_ROWS`]).
///
/// # Panics
/// When `path` is not a declared count with a numeric default: a fault in this file, which the
/// settings tests reach on every count.
fn declared_count(path: &str) -> u64 {
    SETTING_ROWS
        .iter()
        .find(|(p, kind, _)| *p == path && *kind == SETTING_COUNT)
        .and_then(|(_, _, default)| default.parse().ok())
        .expect("a declared count setting with a numeric default")
}

/// What a bad value of the count setting `path` is told (zero is a bad value).
fn bad_count(path: &str) -> &'static str {
    if path == setting::BODY_MAX_BYTES {
        "settings: limits.request_body_max_bytes must be a count of bytes above 0"
    } else {
        "settings: limits.upstream_request_timeout_secs must be a count of seconds above 0"
    }
}

/// The settings blob's bytes, parsed (`validate`, `open` and `refresh` alike); `Err` is the first
/// thing wrong with it, in the words the settings texts share: a blob that is not a JSON object, a
/// key this transport does not declare, a value its declaration refuses. An absent blob reads as
/// `{}`.
fn read_settings(bytes: &[u8]) -> Result<(Posture, bool, bool), Refusal> {
    let v = settings_reading(bytes, &SETTING_ROWS.map(|(p, _, _)| p))?;
    let flag = |k: &'static str| match v.get(k) {
        None => Ok(false),
        Some(x) => x
            .as_bool()
            .ok_or_else(|| Refusal::failed(format!("settings: {k} must be true or false"))),
    };
    // An absent count reads as the default its declaration states (`SETTINGS`): one source.
    let count = |k: &'static str| match v.get(k) {
        None => Ok(declared_count(k)),
        Some(x) => x
            .as_u64()
            .filter(|n| *n > 0)
            .ok_or_else(|| Refusal::failed(bad_count(k))),
    };
    let prior = flag(setting::H2_PRIOR_KNOWLEDGE)?;
    let h1 = flag(setting::HTTP1_ONLY)?;
    let secs = count(setting::REQUEST_TIMEOUT_SECS)?;
    let max = count(setting::BODY_MAX_BYTES)?;
    Ok((
        Posture {
            // 1.5.5's egress client: keep-alive ping every 30s, 10s to answer, adaptive window on.
            keep_alive_interval: Some(Duration::from_secs(30)),
            keep_alive_timeout: Duration::from_secs(10),
            adaptive_window: true,
            request_timeout: Duration::from_secs(secs),
            max_body_bytes: usize::try_from(max).unwrap_or(usize::MAX),
        },
        prior,
        h1,
    ))
}

/// [`read_settings`], as the instance holds them.
fn settings_of(bytes: &[u8]) -> Result<Settings, Refusal> {
    read_settings(bytes).map(|(posture, prior_knowledge, http1_only)| Settings {
        posture,
        prior_knowledge,
        http1_only,
    })
}

impl Life for Instance {
    /// Unread: `cancel` is this door's own slot ([`Cancel`]).
    const CANCEL: u32 = CANCEL_NOTHING_MOVED;

    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        read_settings(settings).map(|_| ())
    }

    fn open(settings: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Self {
            settings: Mutex::new(settings_of(settings)?),
            framings: Framings::default(),
            guests: guest::Lists::default(),
        })
    }

    /// The new settings, read with `validate`'s texts. A bad blob is FAILED and the settings in
    /// force stay; good ones apply to every framing begun after it (a framing already begun keeps
    /// the posture it began under).
    fn refresh(&self, settings: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        let s = settings_of(settings)?;
        *self.settings.lock().unwrap_or_else(PoisonError::into_inner) = s;
        Ok(Refreshed::default())
    }
}

/// One slot body on the SDK's safe surface, over this framer's [`State`].
macro_rules! slot {
    ($(#[$doc:meta])* $name:ident, $in:ty, $out:ty,
     |$inst:pat_param, $input:pat_param, $o:ident| $body:block) => {
        $(#[$doc])*
        pub struct $name;
        impl SafeSlot for $name {
            type In = $in;
            type Out = $out;
            type State = State;
            fn call(
                $inst: sdk::Instance<'_, State>,
                $input: Lent<'_, $in>,
                #[allow(unused_mut)] mut $o: Out<'_, $out>,
            ) -> Outcome $body
        }
    };
}

// ── the lifecycle: the SDK's slots over [`Instance`] but these two ───────────────────────────────

slot!(
    /// `refresh`: [`Instance::refresh`]; with no open instance, FAILED in words.
    Refresh, RefreshIn, OutHead, |instance, i, o| {
        let Some(h) = instance.get() else {
            return o.fail(Refusal::failed("refresh: no open instance"));
        };
        match h.life().refresh(i.field(|x| &x.settings).bytes(), &[], i.generation) {
            Ok(_) => Outcome::Ready,
            Err(e) => o.fail(e),
        }
    }
);

slot!(
    /// `cancel`: the one framer op in flight is one parked on a pending `auth.call` (`begin`,
    /// `ingest` or `emit` on the accepted side; the transport contract's "a framer pends only on a
    /// ticketed auth call"). Its bytes were taken, so its cancel is PARTIAL, and the parked call is
    /// let go ([`Accepted::cancel`]): a later op calls afresh, under a new handle. A ticket nothing
    /// is parked on moved nothing. A framing another op holds right now cannot be looked at (it is
    /// never waited for): with nothing found elsewhere the cancel is FAILED, the framing busy, so
    /// the host cancels again rather than read NOTHING_MOVED.
    Cancel, CancelIn, CancelOut, |instance, i, o| {
        let ticket = i.ticket;
        // The parked op answered PENDING and holds no framing, so every framing a parked call
        // sits on is visited ([`framings::Framings::each`]); none is waited for.
        let mut partial = false;
        let mut skipped = false;
        if let Some(h) = instance.get() {
            skipped = h.life().framings.each(|h| {
                if let Held::Accept(a) = h {
                    partial |= a.cancel(ticket);
                }
            });
        }
        if skipped && !partial {
            return o.fail(Refusal::failed(format!(
                "cancel: {}",
                framings::Reach::Busy.why()
            )));
        }
        o.set(
            |x| &x.disposition,
            if partial {
                CANCEL_PARTIAL
            } else {
                CANCEL_NOTHING_MOVED
            },
        );
        Outcome::Ready
    }
);

busbar_contract::not_served! {
    state: State, role: "http framer";
    /// `listen`: REFUSED.
    Listen(ListenIn => ListenOut) "listen";
    /// `accept`: REFUSED.
    Accept(AcceptIn => AcceptOut) "accept";
    /// `dial`: REFUSED.
    Dial(DialIn => ConnOut) "dial";
    /// `read`: REFUSED.
    Read(ReadIn => IoOut) "read";
    /// `write`: REFUSED.
    Write(WriteIn => IoOut) "write";
    /// `flush`: REFUSED.
    Flush(ConnIn => OutHead) "flush";
    /// `shut`: REFUSED.
    Shut(ShutIn => OutHead) "shut";
    /// `arrival`: REFUSED.
    Arrival(ArrivalIn => ArrivalOut) "arrival";
    /// `adopt`: REFUSED.
    Adopt(AdoptIn => FramerOut) "adopt";
}

/// `refuse`: THE HOST'S REFUSAL on an ACCEPTED connection (the transport ABI's `RefuseIn`), for a
/// stream the host was handed or the whole connection
/// ([`Accepted::refuse`]). The kernel's refusal of a request before its hand-in stays
/// `unit.refuse`'s, framed inside the accepted side; this op is the host's, after it. It never
/// pends: a request its drive decodes goes through the guest list's steps that never pend
/// ([`with`]). A dialled connection is refused by its far end, never here.
pub(crate) struct Refuse;
impl SafeSlot for Refuse {
    type In = RefuseIn;
    type Out = FramerOut;
    type State = State;
    fn call(
        p: sdk::Instance<'_, State>,
        i: Lent<'_, RefuseIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        // The framing's own slot, let go before `with` reaches it again.
        let dialled = p.get().map(Opened::life).and_then(|inst| {
            let mut slot = inst.framings.reach(i.framing).ok()?;
            Some(matches!(slot.held(), Held::Dial(_)))
        });
        if dialled == Some(true) {
            o.error("refuse: a dialled http connection is refused by its far end");
            return Outcome::Refused;
        }
        let bytes = i.bytes();
        let stream = (i.has_stream != 0).then_some(i.stream);
        let (status, head_sent) = (i.status, i.head_sent != 0);
        with(
            REFUSE,
            &p,
            i.head,
            i.framing,
            i.field(|x| &x.sink),
            &mut o,
            |h, resumed| match h {
                // `refuse` never pends, so it is never resumed.
                Held::Accept(a) if !resumed => a.refuse(stream, bytes, status, head_sent),
                _ => Ok(()),
            },
        )
    }
}

// ── the framer ───────────────────────────────────────────────────────────────────────────────────

/// THE ACCEPTED SIDE'S PROTOCOL OFFER (ALPN) under connection security, in the handshake's
/// ProtocolNameList encoding: `h2, http/1.1`, most preferred first (1.5.5: `http/1.1` alone, a
/// signed customer-visible change). A client that offers
/// `http/1.1` alone, or no ALPN, is served HTTP/1.1 exactly as v1.5.5's listener served it; one that
/// agrees `h2` opens with the HTTP/2 preface, which hyper's auto server reads ([`accept`]). A
/// cleartext connection has no handshake: HTTP/2 there is the far side's prior knowledge, read off
/// its preface.
pub const ACCEPT_OFFER: &[u8] = b"\x02h2\x08http/1.1";

/// 1.5.5's client's protocol offer (ALPN), in the handshake's ProtocolNameList encoding: the
/// accepting offer's own list, spelled once.
const OFFER_H2_H1: &[u8] = ACCEPT_OFFER;
/// The same under the http1-only key.
const OFFER_H1: &[u8] = b"\x08http/1.1";
/// The same under the prior-knowledge key: h2 alone.
const OFFER_H2: &[u8] = b"\x02h2";

/// The protocol offer `locate` answers, 1.5.5's by its keys. 1.5.5's client (reqwest 0.12) offered
/// by its version preference, and each key SET that preference, the one applied last winning: `h2`
/// alone under prior knowledge, `http/1.1` alone under http1-only (applied after prior knowledge,
/// so it wins when both are set), `h2, http/1.1` otherwise. In the clear there is no handshake:
/// the offer is `h2` alone under prior knowledge (the one protocol offered there is the one spoken
/// by prior knowledge, `LocateOut::alpn_written`, so the connector knows the connection is h2c and
/// shares it as 1.5.5 did), and none otherwise (HTTP/1.1).
fn offer_for(secure: bool, prior_knowledge: bool, http1_only: bool) -> &'static [u8] {
    match (secure, prior_knowledge, http1_only) {
        (true, _, true) => OFFER_H1,
        (_, true, false) => OFFER_H2,
        (true, false, false) => OFFER_H2_H1,
        (false, _, _) => &[],
    }
}

/// AN `sse` TARGET AS ITS `http` TWIN, framed exactly as `http`. An `sse`
/// stream is an HTTP response body read as events (`crate` docs), so its target is the `http` one
/// with the same authority, path and query: plain, the scheme's own port 80, the same request
/// target, `host` line and protocol offer, and on HTTP/2 an `http` `:scheme`. v1.5.5 had no `sse`
/// target (its one `sse` reading was an `http(s)` request's `alt=sse` query), so nothing it sent
/// moves. Any other target is returned as it is.
pub(crate) fn as_http(uri: http::Uri) -> http::Uri {
    if uri.scheme_str() != Some(crate::meta::SSE_KEY) {
        return uri;
    }
    let mut parts = uri.clone().into_parts();
    parts.scheme = Some(http::uri::Scheme::HTTP);
    http::Uri::from_parts(parts).unwrap_or(uri)
}

/// What `locate` answers for `target`: whether it is secured, the authority to dial (the host as
/// the URL writes it, so the connector's destination guard judges the spelling the operator wrote),
/// and the name offered to and verified against the far end ([`offered_name`]).
fn located(target: &[u8]) -> Result<(bool, String, String), &'static str> {
    let Some(uri) = std::str::from_utf8(target)
        .ok()
        .and_then(|t| t.parse::<http::Uri>().ok())
        .map(as_http)
    else {
        return Err("locate: the target is not a URL");
    };
    if carries_userinfo(&uri) {
        return Err("locate: the target carries userinfo; credentials never ride a URL");
    }
    let secure = match uri.scheme_str() {
        Some("https") => true,
        Some("http") => false,
        _ => return Err("locate: the target's scheme is not http or https"),
    };
    let Some(host) = uri.host() else {
        return Err("locate: the target names no host");
    };
    let port = uri.port_u16().unwrap_or(if secure { 443 } else { 80 });
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let authority = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    Ok((secure, authority, offered_name(host)))
}

/// Whether `uri`'s authority carries userinfo (`user:pass@`): a credential, which never rides a
/// URL, so `locate` and `begin` refuse it rather than drop it.
fn carries_userinfo(uri: &http::Uri) -> bool {
    uri.authority().is_some_and(|a| a.as_str().contains('@'))
}

/// THE NAME OFFERED TO THE FAR END AND VERIFIED AGAINST ITS CERTIFICATE, as 1.5.5's client had it:
/// its URL parser (WHATWG, reqwest 0.12) turned every IPv4 spelling into the dotted quad before it
/// connected, so `https://127.1/` was verified against `127.0.0.1` and `https://16909060/` against
/// `1.2.3.4`, each as an IP address, never as the name written. The spellings are the resolver's
/// (`inet_aton`: decimal, `0x` hex, leading-zero octal, fewer than four parts;
/// `busbar_contract::net::expand_alternate_ipv4`), and a trailing root dot on an IPv4 literal is
/// dropped, as WHATWG drops it. Any other host (a DNS name, an IPv6 literal) is offered ASCII
/// lower-cased, as WHATWG lower-cases it (`https://API.Example.com/` went out as `api.example.com`).
fn offered_name(host: &str) -> String {
    let bare = host.strip_suffix('.').unwrap_or(host);
    if let Ok(v4) = bare.parse::<sdk::net::Ipv4Addr>() {
        return v4.to_string();
    }
    sdk::net::expand_alternate_ipv4(bare)
        .map_or_else(|| host.to_ascii_lowercase(), |v4| v4.to_string())
}

/// `locate`.
pub struct Locate;
impl SafeSlot for Locate {
    type In = LocateIn;
    type Out = LocateOut;
    type State = State;
    fn call(
        p: sdk::Instance<'_, State>,
        i: Lent<'_, LocateIn>,
        mut o: Out<'_, LocateOut>,
    ) -> Outcome {
        let (secure, authority, name, offer) = if i.accept == 1 {
            // An ACCEPTING listener's offer (`LocateIn::accept`): v1.5.5's TLS listener's, whatever
            // the target (a listener names no far end, so none is read).
            (true, String::new(), String::new(), ACCEPT_OFFER)
        } else {
            let (secure, authority, name) = match located(i.field(|x| &x.target).bytes()) {
                Ok(l) => l,
                Err(why) => {
                    o.error(why);
                    return Outcome::Failed;
                }
            };
            // The offer exists only where a handshake does: on a secured connection.
            let offer = p
                .get()
                .map(Opened::life)
                .map_or(offer_for(secure, false, false), |x| {
                    let s = x.settings();
                    offer_for(secure, s.prior_knowledge, s.http1_only)
                });
            (secure, authority, name, offer)
        };
        o.set(|x| &x.secure, u32::from(secure));
        o.set(|x| &x.has_name, u32::from(!name.is_empty()));
        // THE FRAMER'S OWN HEAD LINES (THE DESIGN §6 step 5): stated here, added by the host
        // before the auth signs the head, never by `encode`. An accepting listener names no far
        // end, so it states none.
        let defaults = if i.accept == 1 {
            String::new()
        } else {
            i.field(|x| &x.target)
                .as_str()
                .ok()
                .and_then(|t| t.parse::<http::Uri>().ok())
                .map(|u| engine::client_defaults(&u))
                .unwrap_or_default()
        };
        let (mut a, mut n, mut l) = (i.authority_buf(), i.name_buf(), i.alpn_buf());
        let mut d = i.defaults_buf();
        a.extend(authority.as_bytes());
        n.extend(name.as_bytes());
        l.extend(offer);
        d.extend(defaults.as_bytes());
        // One short answer for every buffer, each at its full size. The framer's own lines are owed
        // to every request, so a defaults buffer too small for them, an unlent one included, is a
        // short answer, never READY with no lines (an h1 request would go out with no `host`).
        let short = !(a.fits() && n.fits() && l.fits() && d.fits());
        let (aw, and) = a.settle(short);
        let (nw, nnd) = n.settle(short);
        let (lw, lnd) = l.settle(short);
        let (dw, dnd) = d.settle(short);
        o.set(|x| &x.authority_written, aw as u64);
        o.set(|x| &x.authority_needed, and as u64);
        o.set(|x| &x.name_written, nw as u64);
        o.set(|x| &x.name_needed, nnd as u64);
        o.set(|x| &x.alpn_written, lw as u64);
        o.set(|x| &x.alpn_needed, lnd as u64);
        // The length line is the host's to state, before the auth: for a fixed, non-empty body,
        // last, after these lines. `encode` renders it and adds none.
        o.set(|x| &x.states_length, 1u8);
        o.set(|x| &x.defaults_written, dw as u64);
        o.set(|x| &x.defaults_needed, dnd as u64);
        if short {
            o.error("locate: a host buffer is too small");
            return Outcome::Failed;
        }
        Outcome::Ready
    }
}

/// `begin`.
pub struct Begin;
impl SafeSlot for Begin {
    type In = BeginIn;
    type Out = FramerOut;
    type State = State;
    fn call(
        p: sdk::Instance<'_, State>,
        i: Lent<'_, BeginIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        let Some(inst) = p.get().map(Opened::life) else {
            o.error("begin: no open instance");
            return Outcome::Failed;
        };
        let settings = inst.settings();
        if i.side == SIDE_ACCEPT {
            // The accepted side serves whichever HTTP the far side opens with, as v1.5.5's data
            // listener did (`accept`): no agreed protocol is read here. It is framed under the
            // listener's guest list, in the kernel's match order (`BeginIn::lines`).
            // The listener's list, copied once and shared by every connection it accepts.
            let lent = i.lines();
            let lines = inst.guests.shared(
                |kept| {
                    kept.len() == lent.len() && kept.iter().zip(lent.iter()).all(|(k, l)| k.same(l))
                },
                || lent.iter().map(guest::Line::of).collect(),
            );
            let Some(lines) = lines else {
                o.error("begin: a guest-list line's route is not text");
                return Outcome::Failed;
            };
            // As on the dialled side: the framing joins the table only once its first step is
            // READY, so a failed begin leaves no entry the host holds no token for. Nothing is
            // admitted at `begin` (no request is decoded yet); the peer point is called on the
            // connection's first drive with bytes, before any request is admitted.
            // The listener's scheme, as the HOST states it (`BeginIn::scheme`): copied into every
            // request view the auth is shown, never inferred from the handshake's facts. The host
            // refuses a `begin` stating none.
            let scheme = i.scheme;
            // The protocol the secure layer's handshake agreed (ALPN), when it ran one: the one
            // the connection speaks until its first bytes show hyper's own choice.
            let alpn = i
                .facts()
                .map_or(&[][..], |f| f.field(|x| &x.agreed_protocol).bytes());
            let mut h = Held::Accept(
                Accepted::accept(i.sink.now_monotonic_ns, lines)
                    .with_body_max(settings.posture.max_body_bytes)
                    .with_scheme(scheme)
                    .with_alpn(alpn),
            );
            let r = step(&mut h, i.field(|x| &x.sink), &mut o, None, |_| Ok(()));
            if r != Outcome::Ready {
                return r;
            }
            let Some(token) = inst.framings.insert_held(h) else {
                o.error("begin: every framing slot is in use");
                return Outcome::Failed;
            };
            o.set(|x| &x.framing, token);
            return r;
        }
        if i.side != SIDE_DIAL {
            o.error("begin: http frames whole connections, accepted or dialled");
            return Outcome::Refused;
        }
        let agreed = i
            .facts()
            .map_or(&[][..], |f| f.field(|x| &x.agreed_protocol).bytes());
        let proto = match agreed {
            b"h2" => Proto::H2,
            b"http/1.1" => Proto::H1,
            b"" if settings.prior_knowledge && !settings.http1_only => Proto::H2,
            b"" => Proto::H1,
            _ => {
                o.error("begin: the agreed protocol is not http/1.1 or h2");
                return Outcome::Refused;
            }
        };
        let Ok(target) = std::str::from_utf8(i.field(|x| &x.target).bytes()) else {
            o.error("begin: the target is not text");
            return Outcome::Failed;
        };
        if target
            .parse::<http::Uri>()
            .is_ok_and(|u| carries_userinfo(&u))
        {
            o.error("begin: the target carries userinfo; credentials never ride a URL");
            return Outcome::Failed;
        }
        let Ok(framing) = Framing::dial(target, proto, settings.posture, i.sink.now_monotonic_ns)
        else {
            o.error("begin: the target is not a URL");
            return Outcome::Failed;
        };
        // The framing joins the instance's table only once its first step is READY: a begin that
        // fails hands the host no token, so nothing would ever release an entry it left behind.
        let mut h = Held::Dial(framing);
        let r = step(&mut h, i.field(|x| &x.sink), &mut o, None, |_| Ok(()));
        if r != Outcome::Ready {
            return r;
        }
        let Some(token) = inst.framings.insert_held(h) else {
            o.error("begin: every framing slot is in use");
            return Outcome::Failed;
        };
        o.set(|x| &x.framing, token);
        r
    }
}

/// `ingest`.
pub struct Ingest;
impl SafeSlot for Ingest {
    type In = IngestIn;
    type Out = FramerOut;
    type State = State;
    fn call(
        p: sdk::Instance<'_, State>,
        i: Lent<'_, IngestIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        let bytes = i.bytes();
        with(
            INGEST,
            &p,
            i.head,
            i.framing,
            i.field(|x| &x.sink),
            &mut o,
            |h, resumed| {
                // A resumed op took its bytes whole the first time.
                match h {
                    _ if resumed => {}
                    Held::Dial(f) => f.ingest(bytes, i.end != 0),
                    Held::Accept(a) => a.ingest(bytes, i.end != 0),
                }
                Ok(())
            },
        )
    }
}

/// `emit`.
pub struct Emit;
impl SafeSlot for Emit {
    type In = EmitIn;
    type Out = FramerOut;
    type State = State;
    fn call(
        p: sdk::Instance<'_, State>,
        i: Lent<'_, EmitIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        let bytes = i.bytes();
        let (now, deadline) = (i.sink.now_monotonic_ns, i.deadline_ns);
        let mut full = false;
        let r = with(
            EMIT,
            &p,
            i.head,
            i.framing,
            i.field(|x| &x.sink),
            &mut o,
            |h, resumed| match h {
                // A resumed op took its bytes whole the first time.
                Held::Dial(_) if resumed => Ok(()),
                Held::Dial(f) => {
                    // A dialled stream's emits carry a request: no answer's status rides them.
                    check_emit_status(&i, false).map_err(refused_status)?;
                    f.emit(i.stream, bytes, i.end_of_frame != 0, now, deadline)
                }
                Held::Accept(a) if resumed => {
                    // Its answer states the stream's queue as it stands: the first run's
                    // fullness was answered PENDING, never to the host.
                    full = a.stream_full(i.stream);
                    Ok(())
                }
                Held::Accept(a) => {
                    // The first emit on an accepted stream is its answer's head, with its status;
                    // every other carries none.
                    check_emit_status(&i, a.answers_head(i.stream)).map_err(refused_status)?;
                    full = a.emit(i.stream, bytes, i.end_of_frame != 0, i.status)?;
                    Ok(())
                }
            },
        );
        if full && r == Outcome::Ready {
            mark_stream_full(&mut o);
        }
        r
    }
}

/// `timer`.
pub struct Timer;
impl SafeSlot for Timer {
    type In = FramingIn;
    type Out = FramerOut;
    type State = State;
    fn call(
        p: sdk::Instance<'_, State>,
        i: Lent<'_, FramingIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        with(
            TIMER,
            &p,
            i.head,
            i.framing,
            i.field(|x| &x.sink),
            &mut o,
            |h, _| {
                // A connection the host refused whole is over: no deadline of it is owed.
                match h {
                    Held::Accept(a) if a.refused_whole() => {
                        Err(engine::Failure("timer: the connection was refused".into()))
                    }
                    _ => Ok(()),
                }
            },
        )
    }
}

/// `detach`: hand an accepted connection to the claimed upgrade framer, in `frame` (any wire bytes
/// still owed first). A connection nothing answered yet goes AS SENT, its upgrade request first,
/// for an upgrade framer that answers the upgrade itself (its `adopt`); one whose request was
/// answered `101` goes from the byte after that request. The framing has ended. A connection
/// neither holds for, or a dialled one, has nothing to detach.
pub(crate) struct Detach;
impl SafeSlot for Detach {
    type In = FramingIn;
    type Out = FramerOut;
    type State = State;
    fn call(
        p: sdk::Instance<'_, State>,
        i: Lent<'_, FramingIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        let Some(inst) = p.get().map(Opened::life) else {
            o.error("detach: no open instance");
            return Outcome::Failed;
        };
        let mut slot = match inst.framings.reach(i.framing) {
            Ok(slot) => slot,
            Err(why) => return failed(&mut o, format!("detach: {}", why.why())),
        };
        let Held::Accept(a) = slot.held() else {
            o.error("detach: a dialled http connection does not switch");
            return Outcome::Refused;
        };
        let sink = i.field(|x| &x.sink);
        a.drive(sink.now_monotonic_ns);
        let agreed = a.agreed();
        // Whether the connection goes, decided BEFORE a wire byte is taken: a detach that is not
        // READY hands the host nothing, so the bytes still owed to the far side stay owed (the
        // next op hands them over), never taken into a buffer the host does not read.
        match a.detach() {
            Ok(Some(_)) => {}
            Ok(None) => {
                o.error("detach: nothing on this connection switched protocols");
                return Outcome::Refused;
            }
            Err(e) => return failed(&mut o, e.0),
        }
        let mut wire_buf = sink.wire();
        let wire = a.take_wire(wire_buf.cap());
        wire_buf.extend(&wire);
        let wire_pending = a.wire_pending();
        // The connection went above: this answers what it handed over, and moves nothing.
        let Ok(Some(rest)) = a.detach() else {
            return failed(&mut o, "detach: the switch has not completed".into());
        };
        let mut frame = sink.frame();
        let n = rest.len().min(frame.cap());
        let taken: Vec<u8> = rest.drain(..n).collect();
        frame.extend(&taken);
        let mut y = o.get().yielded;
        y.wire_len = wire_buf.written() as u64;
        y.frame_len = frame.written() as u64;
        y.agreed = agreed;
        y.flags = if wire_pending || !rest.is_empty() {
            YIELD_MORE
        } else {
            YIELD_ENDED
        };
        o.set(|x| &x.yielded, y);
        Outcome::Ready
    }
}

/// `finish`.
pub struct Finish;
impl SafeSlot for Finish {
    type In = FinishIn;
    type Out = FramerOut;
    type State = State;
    fn call(
        p: sdk::Instance<'_, State>,
        i: Lent<'_, FinishIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        let Some(inst) = p.get().map(Opened::life) else {
            o.error("finish: no open instance");
            return Outcome::Failed;
        };
        match inst.framings.remove(i.framing) {
            Ok(()) => {
                o.set(|x| &x.yielded.flags, YIELD_ENDED);
                Outcome::Ready
            }
            Err(why) => failed(&mut o, format!("finish: {}", why.why())),
        }
    }
}

/// `encode`: one HTTP/1.1 request message into the wire buffer.
pub struct Encode;
impl SafeSlot for Encode {
    type In = EncodeIn;
    type Out = FramerOut;
    type State = State;
    fn call(
        _: sdk::Instance<'_, State>,
        i: Lent<'_, EncodeIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        let fields = i.fields();
        let mut pairs = Vec::with_capacity(fields.len() + 2);
        // The head words, where the host states them, ARE the request line: they lead, so they win
        // over any same-named envelope field.
        let method = i.field(|x| &x.method).bytes();
        let word = i.field(|x| &x.target).bytes();
        let envelope_path = fields.iter().find_map(|f| {
            let name = f.field(|x| &x.name).bytes();
            name.eq_ignore_ascii_case(b"path")
                .then(|| f.field(|x| &x.value).bytes())
        });
        // The target goes out as 1.5.5's client wrote it: percent-encoded, never refused for a
        // space (`dest_head::encode_target`).
        let target = match (word, envelope_path) {
            (w, _) if !w.is_empty() => Some(w),
            (_, p) => p,
        }
        .map(dest_head::encode_target)
        .transpose();
        let Ok(target) = target else {
            return failed(&mut o, format!("encode: {}", dest_head::REFUSED));
        };
        if !method.is_empty() {
            pairs.push(("method", method));
        }
        if let Some(target) = target.as_deref() {
            pairs.push(("path", target));
        }
        for f in fields.iter() {
            let Ok(name) = f.field(|x| &x.name).as_str() else {
                o.error("encode: a field name is not text");
                return Outcome::Failed;
            };
            pairs.push((name, f.field(|x| &x.value).bytes()));
        }
        let body = i.body();
        let Ok(head) = crate::transport::render_head(&pairs, body.len()) else {
            o.error("encode: the envelope cannot be expressed on this wire");
            return Outcome::Failed;
        };
        let mut wire = i.field(|x| &x.sink).wire();
        if head.len().saturating_add(body.len()) > wire.cap() {
            o.error("encode: the rendered message is larger than the wire buffer");
            return Outcome::Failed;
        }
        // The head, then the body straight from the host's own buffer: the one copy is the wire's.
        wire.extend(&head);
        wire.extend(body);
        o.set(|x| &x.yielded.wire_len, wire.written() as u64);
        Outcome::Ready
    }
}

/// A framer op [`with`] runs: its name, which every failure text leads with, and its static
/// no-instance text (with no instance there is nowhere to keep an owned one).
#[derive(Clone, Copy)]
struct FramerOp {
    /// The op's name.
    name: &'static str,
    /// `<op>: no open instance`.
    no_instance: &'static str,
}

/// One [`FramerOp`], its texts spelled from its name once.
macro_rules! framer_op {
    ($(#[$doc:meta])* $const:ident, $name:literal) => {
        $(#[$doc])*
        const $const: FramerOp = FramerOp {
            name: $name,
            no_instance: concat!($name, ": no open instance"),
        };
    };
}

framer_op!(
    /// `ingest`.
    INGEST, "ingest"
);
framer_op!(
    /// `emit`.
    EMIT, "emit"
);
framer_op!(
    /// `refuse`.
    REFUSE, "refuse"
);
framer_op!(
    /// `timer`.
    TIMER, "timer"
);

/// Run `f` on framing `token`, then drive it and fill the sink; a failure text leads with the op's
/// name. `f` is told whether the op was re-entered with `FLAG_RESUME` (it answered PENDING on a
/// parked `auth.call`): such an op took its input whole the first time and takes none again, but
/// what it answers is read afresh.
fn with(
    op: FramerOp,
    p: &sdk::Instance<'_, State>,
    head: InHead,
    token: u64,
    sink: Lent<'_, FramerSink>,
    o: &mut Out<'_, FramerOut>,
    f: impl FnOnce(&mut Held, bool) -> Result<(), engine::Failure>,
) -> Outcome {
    let Some(held) = p.get() else {
        o.error(op.no_instance);
        return Outcome::Failed;
    };
    let inst = held.life();
    let services = held.host().and_then(|h| h.services());
    let mut kernel = HostKernel {
        services: services.as_ref(),
        ticket: head.ticket,
        conn: token,
    };
    // GUEST-LIST ADMISSION RUNS ON EVERY OP THAT DRIVES: a drive may decode a request (a
    // pipelined HTTP/1.1 request is read as soon as the answer before it is written, in whichever
    // op wrote it), and no later op is owed to it. On an op with no ticket (`timer`, `refuse`, a
    // re-call) the may-pend `auth.call` is never made ([`Accepted::admit`]): a request whose line's
    // auth must be called waits for the next ticketed op; every other step (the match, the
    // kernel's refusals, the size gate, the hand-in) runs.
    let kernel = Some(&mut kernel);
    // Reached by its token alone; a framing another op holds is answered at once.
    let mut slot = match inst.framings.reach(token) {
        Ok(slot) => slot,
        Err(why) => return failed(o, format!("{}: {}", op.name, why.why())),
    };
    let resumed = head.flags & FLAG_RESUME != 0;
    step(slot.held(), sink, o, kernel, |h| f(h, resumed))
}

/// Run `f` on `h`'s framing, drive it and fill the sink. A framing's failure is answered in the
/// system's or the far end's words alone, never led by the op's name: a plane passes it on to its
/// caller (a far end that closed unanswered is "connection closed before message completed", as
/// 1.5.5's client said it), and this door has no log or audit channel to keep the op name in; the
/// host knows which op it crossed. The door's own refusals (no open instance, no such framing) keep
/// their op-named words.
fn step(
    h: &mut Held,
    sink: Lent<'_, FramerSink>,
    o: &mut Out<'_, FramerOut>,
    kernel: Option<&mut HostKernel<'_>>,
    f: impl FnOnce(&mut Held) -> Result<(), engine::Failure>,
) -> Outcome {
    if let Err(e) = f(h) {
        return failed(o, e.0);
    }
    match h {
        Held::Dial(framing) => {
            framing.drive(sink.now_monotonic_ns, sink.now_unix_ns);
            let pending = framing.wire_pending() || !framing.pieces().is_empty();
            if let Some(e) = framing.failure().cloned() {
                if !pending {
                    return failed(o, e.0);
                }
            }
            fill(framing, sink, o, class_of, fault_of);
        }
        Held::Accept(a) => {
            a.drive(sink.now_monotonic_ns);
            if let Some(k) = kernel {
                // Admit until nothing moves: every request decoded in this op is answered, admitted
                // or parked in it, never left waiting for a wake no op owes it. Each round moves a
                // request on or ends the loop, and the requests are the ones the bytes already
                // taken hold.
                loop {
                    let did = a.admit(k);
                    if did.parked {
                        // A pending `auth.call` (the SDK's `Pend`, on this ticketed op): the op
                        // yields nothing until the host's wake re-issues it on the same ticket
                        // (the transport contract's "a framer pends only on a ticketed auth call").
                        // The parked call holds its own `(ticket, seq)`: only that ticket's resume
                        // re-issues it, and a fresh op on another ticket flows past it.
                        return Outcome::Pending;
                    }
                    if !did.moved {
                        break;
                    }
                    a.drive(sink.now_monotonic_ns);
                }
            }
            fill(a, sink, o, class_of, fault_of);
            // The protocol this accepted connection speaks, as its position in the accepting offer
            // (`FramerYield::agreed`), on every accepting yield.
            o.set(|x| &x.yielded.agreed, a.agreed());
        }
    }
    Outcome::Ready
}

/// THE HOST AUTH HANDLE as the accepted side calls it: the SDK's `Services` wrappers, each call
/// under the op's ticket and the completion sequence the framing issued
/// (`abi::mechanism::ticket::CompletionHandle`), on connection `conn` (the framing's token).
pub(crate) struct HostKernel<'a> {
    services: Option<&'a Services>,
    ticket: Ticket,
    conn: u64,
}

impl HostKernel<'_> {
    const fn handle(&self, seq: u32) -> CompletionHandle {
        CompletionHandle {
            ticket: self.ticket,
            seq,
            _reserved: 0,
        }
    }
}

impl Kernel for HostKernel<'_> {
    fn ticket(&self) -> Ticket {
        self.ticket
    }

    #[allow(clippy::too_many_arguments)]
    fn auth_call(
        &mut self,
        seq: u32,
        auth: AuthRef,
        unit: UnitRef,
        point: u32,
        stream: u64,
        request: &HeadViewArgs<'_>,
        body: Option<&[u8]>,
    ) -> Pend<AuthCalled> {
        let Some(s) = self.services else {
            return Poll::Ready(Err(ServiceError::Unserved));
        };
        s.auth_call::<Own>(
            self.handle(seq),
            auth,
            unit,
            point,
            self.conn,
            stream,
            request,
            body,
        )
        .map(|r| r.map(|c| (c.flow, c.unit, c.names)))
    }

    #[allow(clippy::too_many_arguments)]
    fn hand_in(
        &mut self,
        seq: u32,
        auth: AuthRef,
        unit: UnitRef,
        line: u32,
        stream: u64,
        request: &HeadViewArgs<'_>,
    ) -> Result<(u32, UnitRef), ServiceError> {
        let s = self.services.ok_or(ServiceError::Unserved)?;
        s.unit_hand_in(
            self.handle(seq),
            auth,
            unit,
            line,
            self.conn,
            stream,
            request,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn refuse(
        &mut self,
        seq: u32,
        unit: UnitRef,
        cause: u32,
        line: u32,
        stream: u64,
        request: &HeadViewArgs<'_>,
    ) -> Result<RefusalCopy, ServiceError> {
        let s = self.services.ok_or(ServiceError::Unserved)?;
        s.unit_refuse(
            self.handle(seq),
            unit,
            cause,
            line,
            self.conn,
            stream,
            request,
        )
    }
}

/// An `emit`'s status ([`EmitIn::status`]): stated on the emit that carries an accepted stream's
/// answer head (`answers_head`), and on no other.
fn check_emit_status(i: &EmitIn, answers_head: bool) -> Result<(), Fault> {
    if i._status_reserved != 0 {
        return Err(fault(Rule::UnknownCode, "emit._status_reserved"));
    }
    match (answers_head, i.status) {
        (true, 0) => Err(fault(Rule::Missing, "emit.status")),
        (false, s) if s != 0 => Err(fault(Rule::Contradiction, "emit.status")),
        _ => Ok(()),
    }
}

/// An emit whose status breaks [`check_emit_status`], as the failure its op answers.
fn refused_status(f: Fault) -> engine::Failure {
    engine::Failure(format!(
        "emit: the status breaks {:?} at {}",
        f.rule, f.field
    ))
}

fn failed(o: &mut Out<'_, FramerOut>, text: String) -> Outcome {
    o.fail(Refusal::failed(text))
}

/// The status class of `code`, from the classes the status rows state ([`HTTP_CLASSES`]);
/// `STATUS_OTHER` off them.
fn class_of(code: u16) -> u8 {
    let code = u32::from(code);
    HTTP_CLASSES
        .iter()
        .find(|(lo, hi, _)| (*lo..=*hi).contains(&code))
        .and_then(|(_, _, class)| u8::try_from(*class).ok())
        .unwrap_or(STATUS_OTHER)
}

/// The breaker's reading of `code`, from the fault table (`FAULT_NONE` off it).
fn fault_of(code: u16) -> u8 {
    FAULT_ROWS
        .iter()
        .find(|r| r.claim == 0 && (r.lo..=r.hi).contains(&u32::from(code)))
        .map_or(FAULT_NONE, |r| r.fault as u8)
}

busbar_contract::plugin_door! {
    ops: Ops,
    statement: STATEMENT,
    lifecycle: {
        validate: Safe<life::Validate<Instance>>,
        open: Safe<life::Open<Instance>>,
        refresh: Safe<Refresh>,
        retire: Safe<life::Retire<Instance>>,
        tick: Safe<life::Tick<Instance>>,
        drive: Safe<life::Drive<Instance>>,
        cancel: Safe<Cancel>,
        release: Safe<life::Release<Instance>>,
        close: Safe<life::Close<Instance>>,
    },
    kind_ops: {
        listen: Safe<Listen>,
        accept: Safe<Accept>,
        dial: Safe<Dial>,
        read: Safe<Read>,
        write: Safe<Write>,
        flush: Safe<Flush>,
        shut: Safe<Shut>,
        arrival: Safe<Arrival>,
        locate: Safe<Locate>,
        begin: Safe<Begin>,
        ingest: Safe<Ingest>,
        emit: Safe<Emit>,
        encode: Safe<Encode>,
        refuse: Safe<Refuse>,
        finish: Safe<Finish>,
        detach: Safe<Detach>,
        adopt: Safe<Adopt>,
        timer: Safe<Timer>,
    },
}

#[cfg(test)]
#[path = "tests/door_tests.rs"]
mod tests;
