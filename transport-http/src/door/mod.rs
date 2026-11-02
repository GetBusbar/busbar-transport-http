// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `http` DOOR: this transport as a FRAMER on the transport kind's table

pub(crate) mod accept;
pub(crate) mod dest_head;
pub(crate) mod engine;
mod framings;
pub(crate) mod guest;

busbar_contract::own_seal!(Own);

busbar_contract::hyper_io!(::bytes::Bytes);

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use std::task::Poll;

use busbar_contract::abi::host::service::{AuthRef, UnitRef};
use busbar_contract::abi::mechanism::call::{AbiStr, InHead, OutHead, Outcome, FLAG_RESUME};
use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
use busbar_contract::abi::mechanism::lifecycle::{CancelIn, CancelOut};
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::life::{self, Held as Opened, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::services::{
    HeadViewArgs, Pend, RefusalCopy, ServiceError, Services,
};
use busbar_contract::abi::sdk::transport::policy::Loans;
use busbar_contract::abi::sdk::transport::{
    form_codes, settings_reading, SettingRow, DEFAULT_BODY_MAX,
};
use busbar_contract::abi::sdk::{self as sdk, Lent, Out, Safe, SafeSlot};
use busbar_contract::abi::transport::check::check_emit_flags;
use busbar_contract::abi::transport::sensitive_fields::SensitiveFields;
use busbar_contract::abi::transport::{
    AcceptIn, AcceptOut, AdoptIn, ArrivalIn, ArrivalOut, BeginIn, Claim, ConnIn, ConnOut, DialIn,
    EmitIn, EncodeIn, FaultRow, FinishIn, FramerOut, FramerSink, FramingIn, IngestIn, IoOut,
    ListenIn, ListenOut, LocateIn, LocateOut, Ops, ReadIn, RefuseIn, SettingDecl, ShutIn,
    StatusRow, TransportTail, WriteIn, CANCEL_NOTHING_MOVED, CANCEL_PARTIAL, EMIT_TRAILERS,
    EXT_OFFERED_POINTS, FAULT_CALLER, FAULT_HARD, FAULT_NONE, FAULT_TRANSIENT, SETTING_COUNT,
    SETTING_FLAG, SIDE_ACCEPT, SIDE_DIAL, STATUS_AT_FIRST_FRAME, STATUS_CALLER_FAULT,
    STATUS_FAR_END_FAULT, STATUS_OTHER, STATUS_SUCCESS, YIELD_ENDED, YIELD_MORE,
};
use busbar_contract::transport::registry::{facts as tfacts, status_ns};

use accept::{Accepted, AuthCalled, Kernel};
use busbar_contract::abi::mechanism::check::{fault, Fault, Rule};
use engine::{Framing, Posture, Proto};
use framings::{Framings, Held};
#[cfg(test)]
use hyper_io::field_cut;
use hyper_io::{fill, mark_stream_full, Owed};

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

/// What `open` read from the settings (and the last good `refresh` replaced), and the framings it
pub struct Instance {
    settings: Mutex<Settings>,
    framings: Framings,
    /// The listeners' guest lists, shared by the connections each accepts.
    guests: guest::Lists,
    /// A pending Begin's provisional framing; only its owning ticket may resume it.
    opening: Mutex<HashMap<Ticket, u64>>,
}

/// Every slot's state: the SDK's held instance over [`Instance`], with the host tables `open` was
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
    fn settings(&self) -> Settings {
        *self.settings.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The default the count setting `path` declares ([`SETTING_ROWS`]).
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
fn read_settings(bytes: &[u8]) -> Result<(Posture, bool, bool), Refusal> {
    let rows = SETTING_ROWS.map(|(path, kind, default)| SettingRow {
        path,
        kind,
        default,
    });
    let v = settings_reading(bytes, &rows).map_err(|refusal| {
        for row in rows.iter().filter(|row| row.kind == SETTING_COUNT) {
            if refusal.text()
                == Some(format!("settings: {} must be a count above 0", row.path).as_str())
            {
                return Refusal::failed(bad_count(row.path));
            }
        }
        refusal
    })?;
    let flag = |k: &'static str| match v.get(k) {
        None => Ok(false),
        Some(x) => x
            .as_bool()
            .ok_or_else(|| Refusal::failed(format!("settings: {k} must be true or false"))),
    };

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
            opening: Mutex::new(HashMap::new()),
        })
    }

    /// The new settings, read with `validate`'s texts. A bad blob is FAILED and the settings in
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
            let opening = h.life().opening.lock().unwrap_or_else(PoisonError::into_inner).get(&ticket).copied();
            if let Some(token) = opening {
                match h.life().framings.reach(token) {
                    Ok(slot) => drop(slot),
                    Err(framings::Reach::Busy) => return o.fail(Refusal::failed("cancel: framing busy")),
                    Err(framings::Reach::Gone) => {}
                }
                h.life().opening.lock().unwrap_or_else(PoisonError::into_inner).remove(&ticket);
                let _ = h.life().framings.remove(token);
                partial = true;
            }
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
            i.field(|x| &x.head),
            i.framing,
            i.field(|x| &x.sink),
            &mut o,
            |h, resumed| match h {
                Held::Accept(a) if !resumed => a.refuse(stream, bytes, status, head_sent),
                _ => Ok(()),
            },
        )
    }
}

/// THE ACCEPTED SIDE'S PROTOCOL OFFER (ALPN) under connection security, in the handshake's
pub const ACCEPT_OFFER: &[u8] = b"\x02h2\x08http/1.1";

/// The 1.5.5 client's ALPN offer in handshake ProtocolNameList encoding.
const OFFER_H2_H1: &[u8] = ACCEPT_OFFER;
/// The same under the http1-only key.
const OFFER_H1: &[u8] = b"\x08http/1.1";
/// The same under the prior-knowledge key: h2 alone.
const OFFER_H2: &[u8] = b"\x02h2";

/// Select the same protocol offer as the 1.5.5 reqwest client under these settings.
fn offer_for(secure: bool, prior_knowledge: bool, http1_only: bool) -> &'static [u8] {
    match (secure, prior_knowledge, http1_only) {
        (true, _, true) => OFFER_H1,
        (_, true, false) => OFFER_H2,
        (true, false, false) => OFFER_H2_H1,
        (false, _, _) => &[],
    }
}

/// AN `sse` TARGET AS ITS `http` TWIN, framed exactly as `http`. An `sse`
pub(crate) fn as_http(uri: http::Uri) -> http::Uri {
    if uri.scheme_str() != Some(crate::meta::SSE_KEY) {
        return uri;
    }
    let mut parts = uri.clone().into_parts();
    parts.scheme = Some(http::uri::Scheme::HTTP);
    http::Uri::from_parts(parts).unwrap_or(uri)
}

/// What `locate` answers for `target`: whether it is secured, the authority to dial (the host as
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
fn carries_userinfo(uri: &http::Uri) -> bool {
    uri.authority().is_some_and(|a| a.as_str().contains('@'))
}

/// Normalize the peer name for the handshake and certificate check as the 1.5.5 client did.
fn offered_name(host: &str) -> String {
    if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        use std::fmt::Write;
        let pieces = v6.segments();
        let (mut start, mut longest, mut at) = (0, 0, 0);
        while at < pieces.len() {
            if pieces[at] != 0 {
                at += 1;
                continue;
            }
            let first = at;
            while at < pieces.len() && pieces[at] == 0 {
                at += 1;
            }
            if at - first > longest && at - first >= 2 {
                start = first;
                longest = at - first;
            }
        }
        let mut out = String::new();
        let mut at = 0;
        while at < pieces.len() {
            if longest != 0 && at == start {
                out.push_str("::");
                at += longest;
            } else {
                if !out.is_empty() && !out.ends_with(':') {
                    out.push(':');
                }
                let _ = write!(out, "{:x}", pieces[at]);
                at += 1;
            }
        }
        return out;
    }
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
            (true, String::new(), String::new(), ACCEPT_OFFER)
        } else {
            let (secure, authority, name) = match located(i.field(|x| &x.target).bytes()) {
                Ok(l) => l,
                Err(why) => {
                    o.error(why);
                    return Outcome::Failed;
                }
            };

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
            let opening = inst
                .opening
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(&i.head.ticket)
                .copied();
            if let Some(token) = opening {
                if i.head.flags & FLAG_RESUME == 0 {
                    return failed(
                        &mut o,
                        "begin: the opening operation must be resumed".into(),
                    );
                }
                return begin_peer(
                    &p,
                    i.field(|x| &x.head),
                    token,
                    i.field(|x| &x.sink),
                    &mut o,
                );
            }
            let loans = match Loans::from_initial(i.field(|x| &x.head.extensions).bytes()) {
                Ok(loans) => loans,
                Err(why) => return failed(&mut o, format!("begin: {why}")),
            };
            let selected = loans.is_some();

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

            let scheme = i.scheme;

            let alpn = i
                .facts()
                .map_or(&[][..], |f| f.field(|x| &x.agreed_protocol).bytes());
            let mut accepting = Accepted::accept(i.sink.now_monotonic_ns, lines)
                .with_policies(loans)
                .with_body_max(settings.posture.max_body_bytes)
                .with_scheme(scheme)
                .with_alpn(alpn);
            if selected {
                let Some(token) = inst
                    .framings
                    .insert_with(|| Held::Accept(Box::new(accepting)))
                else {
                    return failed(&mut o, "begin: every framing slot is in use".into());
                };
                inst.opening
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert(i.head.ticket, token);
                return begin_peer(
                    &p,
                    i.field(|x| &x.head),
                    token,
                    i.field(|x| &x.sink),
                    &mut o,
                );
            }
            let r = step_prepared(
                Prepared::Accept(&mut accepting),
                i.field(|x| &x.sink),
                &mut o,
                None,
            );
            if r != Outcome::Ready {
                return r;
            }
            let Some(token) = inst
                .framings
                .insert_with(|| Held::Accept(Box::new(accepting)))
            else {
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
        let Ok(mut framing) =
            Framing::dial(target, proto, settings.posture, i.sink.now_monotonic_ns)
        else {
            o.error("begin: the target is not a URL");
            return Outcome::Failed;
        };

        let r = step_prepared(
            Prepared::Dial(&mut framing),
            i.field(|x| &x.sink),
            &mut o,
            None,
        );
        if r != Outcome::Ready {
            return r;
        }
        let Some(token) = inst.framings.insert_with(|| Held::Dial(Box::new(framing))) else {
            o.error("begin: every framing slot is in use");
            return Outcome::Failed;
        };
        o.set(|x| &x.framing, token);
        r
    }
}

fn begin_peer(
    p: &sdk::Instance<'_, State>,
    head: Lent<'_, InHead>,
    token: u64,
    sink: Lent<'_, FramerSink>,
    o: &mut Out<'_, FramerOut>,
) -> Outcome {
    let Some(held) = p.get() else {
        return failed(o, "begin: no open instance".into());
    };
    let inst = held.life();
    let services = held.host().and_then(|h| h.services());
    let mut slot = match inst.framings.reach(token) {
        Ok(slot) => slot,
        Err(why) => return failed(o, format!("begin: {}", why.why())),
    };
    let Held::Accept(a) = slot.held() else {
        return failed(o, "begin: the opening framing is not accepting".into());
    };
    let did = a.admit_peer(&mut HostKernel {
        services: services.as_ref(),
        ticket: head.ticket,
        conn: token,
        policy: PolicyCall {
            extensions: head.field(|x| &x.extensions).bytes(),
            leases: held.leases(),
            out: &mut *o,
        },
    });
    if did.parked {
        return Outcome::Pending;
    }
    let ready = a.peer_ready();
    if ready {
        a.drive(sink.now_monotonic_ns);
        fill(a.as_mut(), sink, o, class_of, fault_of);
        o.set(|x| &x.yielded.agreed, a.agreed());
        o.set(|x| &x.framing, token);
    }
    drop(slot);
    inst.opening
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(&head.ticket);
    if ready {
        Outcome::Ready
    } else {
        let _ = inst.framings.remove(token);
        o.error("begin: the opening peer policy was refused");
        Outcome::Refused
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
            i.field(|x| &x.head),
            i.framing,
            i.field(|x| &x.sink),
            &mut o,
            |h, resumed| {
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
        let sensitive =
            match SensitiveFields::from_extensions(i.field(|x| &x.head.extensions).bytes()) {
                Ok(sensitive) => sensitive,
                Err(error) => return failed(&mut o, format!("emit: {error}")),
            };
        let mut full = false;
        let r = with(
            EMIT,
            &p,
            i.field(|x| &x.head),
            i.framing,
            i.field(|x| &x.sink),
            &mut o,
            |h, resumed| match h {
                Held::Dial(_) if resumed => Ok(()),
                Held::Dial(f) => {
                    check_emit_flags(&i, SIDE_DIAL, false).map_err(refused_status)?;
                    check_emit_status(&i, false).map_err(refused_status)?;
                    if let Some(sensitive) = sensitive {
                        f.emit_sensitive(
                            i.stream,
                            bytes,
                            i.end_of_frame != 0,
                            now,
                            deadline,
                            sensitive,
                        )
                    } else {
                        f.emit(i.stream, bytes, i.end_of_frame != 0, now, deadline)
                    }
                }
                Held::Accept(a) if resumed => {
                    full = a.stream_full(i.stream);
                    Ok(())
                }
                Held::Accept(a) => {
                    let answers_head = a.answers_head(i.stream);
                    check_emit_flags(&i, SIDE_ACCEPT, answers_head).map_err(refused_status)?;
                    check_emit_status(&i, answers_head).map_err(refused_status)?;
                    full = if i.flags & EMIT_TRAILERS != 0 {
                        a.emit_trailers(i.stream, bytes)?
                    } else {
                        a.emit(i.stream, bytes, i.end_of_frame != 0, i.status)?
                    };
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
            i.field(|x| &x.head),
            i.framing,
            i.field(|x| &x.sink),
            &mut o,
            |h, _| match h {
                Held::Accept(a) if a.refused_whole() => {
                    Err(engine::Failure("timer: the connection was refused".into()))
                }
                _ => Ok(()),
            },
        )
    }
}

/// `detach`: hand an accepted connection to the claimed upgrade framer, in `frame` (any wire bytes
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

        let Ok(Some(rest)) = a.detach() else {
            return failed(&mut o, "detach: the switch has not completed".into());
        };
        let mut frame = sink.frame();
        let n = rest.len().min(frame.cap());
        let taken = take_detached(rest, n);
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

fn take_detached(
    rest: &mut std::collections::VecDeque<u8>,
    n: usize,
) -> zeroize::Zeroizing<Vec<u8>> {
    let taken = zeroize::Zeroizing::new(rest.range(..n).copied().collect::<Vec<_>>());
    for byte in rest.range_mut(..n) {
        zeroize::Zeroize::zeroize(byte);
    }
    rest.drain(..n);
    #[cfg(test)]
    crate::wipe_probe::watch("detach taken", &taken);
    taken
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

        let method = i.field(|x| &x.method).bytes();
        let word = i.field(|x| &x.target).bytes();
        let envelope_path = fields.iter().find_map(|f| {
            let name = f.field(|x| &x.name).bytes();
            name.eq_ignore_ascii_case(b"path")
                .then(|| f.field(|x| &x.value).bytes())
        });

        let target = match (word, envelope_path) {
            (w, _) if !w.is_empty() => Some(w),
            (_, p) => p,
        }
        .map(dest_head::encode_target)
        .transpose();
        let Ok(target) = target else {
            return failed(&mut o, format!("encode: {}", dest_head::REFUSED));
        };
        let target = target.map(zeroize::Zeroizing::new);
        if !method.is_empty() {
            pairs.push(("method", method));
        }
        if let Some(target) = target.as_ref() {
            pairs.push(("path", target.as_slice()));
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

        wire.extend(&head);
        wire.extend(body);
        o.set(|x| &x.yielded.wire_len, wire.written() as u64);
        Outcome::Ready
    }
}

/// A framer op [`with`] runs: its name, which only the door's own refusals (no open instance, no
/// such framing) lead with, and its static no-instance text (with no instance there is nowhere to keep an owned one).
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

/// Run `f` on framing `token`, then drive it and fill the sink; only the door's own refusals
/// (no open instance, no such framing) lead with the op's name. A framing's failure is passed
/// through unchanged, as [`step`] documents. `f` is told whether the op was re-entered with
/// `FLAG_RESUME` (it answered PENDING on a parked `auth.call`): such an op took its input whole the
/// first time and takes none again, but what it answers is read afresh.
fn with(
    op: FramerOp,
    p: &sdk::Instance<'_, State>,
    head: Lent<'_, InHead>,
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
    let kernel = KernelContext {
        services: services.as_ref(),
        ticket: head.ticket,
        conn: token,
        extensions: head.field(|x| &x.extensions).bytes(),
        leases: held.leases(),
    };

    let kernel = Some(kernel);

    let mut slot = match inst.framings.reach(token) {
        Ok(slot) => slot,
        Err(why) => return failed(o, format!("{}: {}", op.name, why.why())),
    };
    let h = slot.held();
    let resumed = head.flags & FLAG_RESUME != 0
        || matches!(&*h, Held::Accept(a) if a.policy_pending(head.ticket));
    step(h, sink, o, kernel, |h| f(h, resumed))
}

/// A mutable payload view usable before and after the table owns its allocation.
enum Prepared<'a> {
    Dial(&'a mut Framing),
    Accept(&'a mut Accepted),
}

/// Run the operation, then drive and fill the same framing without changing its ownership.
/// A failed operation returns its failure before driving or filling; successful operations
/// share the same borrowed step as an initial payload that the table does not yet own.
fn step(
    h: &mut Held,
    sink: Lent<'_, FramerSink>,
    o: &mut Out<'_, FramerOut>,
    kernel: Option<KernelContext<'_>>,
    f: impl FnOnce(&mut Held) -> Result<(), engine::Failure>,
) -> Outcome {
    if let Err(e) = f(h) {
        return failed(o, e.0);
    }
    let prepared = match h {
        Held::Dial(framing) => Prepared::Dial(framing),
        Held::Accept(accepting) => Prepared::Accept(accepting),
    };
    step_prepared(prepared, sink, o, kernel)
}

fn step_prepared(
    prepared: Prepared<'_>,
    sink: Lent<'_, FramerSink>,
    o: &mut Out<'_, FramerOut>,
    kernel: Option<KernelContext<'_>>,
) -> Outcome {
    match prepared {
        Prepared::Dial(framing) => {
            framing.drive(sink.now_monotonic_ns, sink.now_unix_ns);
            let pending = framing.wire_pending() || !framing.pieces().is_empty();
            if let Some(e) = framing.failure().cloned() {
                if !pending {
                    return failed(o, e.0);
                }
            }
            fill(framing, sink, o, class_of, fault_of);
        }
        Prepared::Accept(a) => {
            a.drive(sink.now_monotonic_ns);
            let mut more = false;
            if let Some(context) = kernel {
                loop {
                    let did = a.admit(&mut HostKernel {
                        services: context.services,
                        ticket: context.ticket,
                        conn: context.conn,
                        policy: PolicyCall {
                            extensions: context.extensions,
                            leases: context.leases,
                            out: &mut *o,
                        },
                    });
                    if did.policy_requested {
                        o.set(|x| &x.yielded.agreed, a.agreed());
                        return Outcome::Ready;
                    }
                    if did.policy_failed {
                        return failed(o, "the host stream policy reply was invalid".into());
                    }
                    if did.parked {
                        report_receive(a, context, o);
                        return Outcome::Pending;
                    }
                    if !did.moved {
                        more = did.more;
                        break;
                    }
                    a.drive(sink.now_monotonic_ns);
                }
            }
            fill(a, sink, o, class_of, fault_of);
            a.published();
            if let Some(context) = kernel {
                report_receive(a, context, o);
            }
            if more {
                let flags = o.get().yielded.flags | YIELD_MORE;
                o.set(|x| &x.yielded.flags, flags);
            }
            if o.get().yielded.flags & YIELD_MORE == 0 {
                if let Some(context) = kernel {
                    a.operation_done(context.ticket);
                }
            }

            o.set(|x| &x.yielded.agreed, a.agreed());
        }
    }
    Outcome::Ready
}

/// The output lease owns this numeric snapshot through READY or PENDING. Policy-open control
fn report_receive(a: &Accepted, context: KernelContext<'_>, out: &mut Out<'_, FramerOut>) {
    let bytes = busbar_contract::abi::sdk::transport::receive::encode(a.retained_input() as u64);
    out.lease(
        |o| &o.head.extensions,
        context.leases,
        bytes,
        busbar_contract::abi::mechanism::call::BLOB_OCTETS,
    );
}

/// THE HOST AUTH HANDLE as the accepted side calls it: the SDK's `Services` wrappers, each call
/// under the op's ticket and the completion sequence the framing issued
/// (`abi::mechanism::ticket::CompletionHandle`), on connection `conn` (the framing's token).
#[derive(Clone, Copy)]
struct KernelContext<'a> {
    services: Option<&'a Services>,
    ticket: Ticket,
    conn: u64,
    extensions: &'a [u8],
    leases: &'a busbar_contract::abi::sdk::life::Leases,
}

struct PolicyCall<'a, 'o, 'f> {
    extensions: &'a [u8],
    leases: &'a busbar_contract::abi::sdk::life::Leases,
    out: &'o mut Out<'f, FramerOut>,
}

pub(crate) struct HostKernel<'a, 'o, 'f> {
    services: Option<&'a Services>,
    ticket: Ticket,
    conn: u64,
    policy: PolicyCall<'a, 'o, 'f>,
}

impl HostKernel<'_, '_, '_> {
    const fn handle(&self, seq: u32) -> CompletionHandle {
        CompletionHandle {
            ticket: self.ticket,
            seq,
            _reserved: 0,
        }
    }
}

impl Kernel for HostKernel<'_, '_, '_> {
    fn ticket(&self) -> Ticket {
        self.ticket
    }

    fn open_policy(
        &mut self,
        loans: &mut Loans,
        stream: u64,
    ) -> Result<
        Option<std::sync::Arc<busbar_contract::abi::transport::guest_policy::Policy>>,
        ServiceError,
    > {
        loans
            .open(
                self.ticket,
                stream,
                self.policy.extensions,
                self.policy.out,
                self.policy.leases,
            )
            .map_err(|_| ServiceError::Unserved)
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
        refresh: Safe<life::Refresh<Instance>>,
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
