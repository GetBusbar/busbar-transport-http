// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE GUEST LIST an accepted connection is framed under (`BUSBAR-1.6.0.md` §6, "Auth points and
//! guest lists", items 3 and 4, l.904-962): the listener's lines as `begin` lent them
//! (`BeginIn::lines`, in the kernel's match order), owned for the framing's life; the match of a
//! decoded head against them in the contract's ONE route vocabulary
//! (`abi::transport::route::RouteView`: `path_and_fields_match`, then `admits`); and the strip of
//! what a line's auth named (item 4, l.943-945: "the transport strips both, so the plane never
//! sees a credential").

use busbar_contract::abi::host::service::AuthRef;
use busbar_contract::abi::sdk::services::Place;
use busbar_contract::abi::sdk::Lent;
use busbar_contract::abi::transport::route::{LineEntry, RouteView};

/// One guest-list line, owned: what the door matches against and calls the auth handle with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// The kernel's id for the line.
    pub line: u32,
    /// `POINT_*`: the points its auth needs; `0` for a `none` line.
    pub points: u32,
    /// Its auth handle.
    pub auth: AuthRef,
    /// The size gate's limit at the body point; `0` without it.
    pub body_limit: u64,
    methods: u32,
    path_form: u32,
    path: String,
    fields: Vec<(u32, String, Vec<u8>)>,
    rung: u32,
}

impl Line {
    /// The line the host lent, copied out; `None` when its route's path or a predicate name is not
    /// UTF-8 (`Lent::<LineEntry>::route_view`).
    #[must_use]
    pub fn of(l: Lent<'_, LineEntry>) -> Option<Self> {
        let e = *l.get();
        let v = l.route_view()?;
        Some(Self {
            line: e.line,
            points: e.points,
            auth: e.auth,
            body_limit: e.body_limit,
            methods: v.methods,
            path_form: v.path_form,
            path: v.path.to_owned(),
            fields: v
                .fields
                .iter()
                .map(|(op, n, val)| (*op, (*n).to_owned(), val.to_vec()))
                .collect(),
            rung: v.rung,
        })
    }

    /// A `none` line taking every method on every path (a path holds `/`), for the accepted side's
    /// own cells.
    #[cfg(test)]
    #[must_use]
    pub fn any(line: u32) -> Self {
        use busbar_contract::abi::transport::route::{METHOD_ANY, PATH_CONTAINS};
        Self {
            line,
            points: 0,
            auth: AuthRef { id: 1, mac: 1 },
            body_limit: 0,
            methods: METHOD_ANY,
            path_form: PATH_CONTAINS,
            path: "/".to_owned(),
            fields: Vec::new(),
            rung: 0,
        }
    }

    /// The line's route in the contract's vocabulary.
    fn view(&self) -> RouteView<'_> {
        RouteView {
            methods: self.methods,
            path_form: self.path_form,
            path: &self.path,
            fields: self
                .fields
                .iter()
                .map(|(op, n, v)| (*op, n.as_str(), v.as_slice()))
                .collect(),
            rung: self.rung,
        }
    }
}

/// What the guest list says of one request head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Matched {
    /// The first line, in list order, whose path and predicates hold and whose methods admit the
    /// method: its index.
    Line(usize),
    /// No line admits the method, and this one (the first in list order) has its path and
    /// predicates hold: `REFUSE_METHOD_MISS` on it.
    MethodMiss(usize),
    /// No line's path and predicates hold: `REFUSE_NO_ROUTE`.
    NoRoute,
}

/// Match `method`, `path` and the head's field lines against `lines`, in list order (item 4,
/// l.939: the transport "matches the route on its guest list").
#[must_use]
pub fn matched(lines: &[Line], method: &str, path: &str, fields: &[(&str, &[u8])]) -> Matched {
    let mut miss = None;
    for (n, l) in lines.iter().enumerate() {
        let v = l.view();
        if !v.path_and_fields_match(path, fields) {
            continue;
        }
        if v.admits(method) {
            return Matched::Line(n);
        }
        miss.get_or_insert(n);
    }
    miss.map_or(Matched::NoRoute, Matched::MethodMiss)
}

/// `query` without every key `names` lists as a query key ([`Place::Query`]); the pairs kept, in
/// order and as the far side spelled them. A key is compared as it percent-decodes, exactly as
/// v1.5.5 read every inbound query key (`crates/busbar/src/auth/token.rs`:996-1003 `parse_query`,
/// :1012-1035 `pct_decode`: `%XX` and `+` decoded, a malformed `%` kept as written), and
/// case-sensitively: `%6Bey` is the key `key`, `Key` is not. v1.5.5 itself read no credential from
/// an inbound query (its token carriers were header lines only, `crates/busbar/src/auth/mod.rs`
/// :593-615), so its one inbound query reader is the rule. `None` when nothing is left.
#[must_use]
pub fn stripped_query(query: &str, names: &[(String, Place)]) -> Option<String> {
    let kept: Vec<&str> = query
        .split('&')
        .filter(|pair| {
            let key = decoded(pair.split_once('=').map_or(*pair, |(k, _)| k));
            !names
                .iter()
                .any(|(n, place)| *place == Place::Query && n.as_bytes() == key.as_slice())
        })
        .collect();
    let kept = kept.join("&");
    (!kept.is_empty()).then_some(kept)
}

/// A query component percent-decoded as v1.5.5's `pct_decode` did (`auth/token.rs`:1012-1035):
/// `+` is a space, `%` with two hex digits is their byte, any other `%` is itself.
fn decoded(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                match (
                    char::from(b[i + 1]).to_digit(16),
                    char::from(b[i + 2]).to_digit(16),
                ) {
                    (Some(h), Some(l)) => {
                        out.extend(u8::try_from(h * 16 + l));
                        i += 2;
                    }
                    _ => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    out
}

/// Whether field line `name` is one `names` lists as a field line ([`Place::Field`]), compared
/// ASCII case-insensitively.
#[must_use]
pub fn strips_field(name: &str, names: &[(String, Place)]) -> bool {
    names
        .iter()
        .any(|(n, place)| *place == Place::Field && n.eq_ignore_ascii_case(name))
}

#[cfg(test)]
#[path = "tests/guest_tests.rs"]
mod tests;
