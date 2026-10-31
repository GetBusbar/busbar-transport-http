// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE GUEST LIST an accepted connection is framed under: the listener's lines as `begin` lent them
//! (`BeginIn::lines`, in the kernel's match order), owned for the framing's life; the match of a
//! decoded head against them in the contract's ONE route vocabulary
//! (`abi::transport::route::RouteView`: `path_and_fields_match`, then `admits`); and the strip of
//! what a line's auth named, so the plane never sees a credential.

use std::sync::{Arc, Mutex, PoisonError};

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

    /// [`Line::any`] whose auth needs `points`, holding a body to `body_limit` at the body point,
    /// for the accepted side's own cells.
    #[cfg(test)]
    #[must_use]
    pub fn any_needing(line: u32, points: u32, body_limit: u64) -> Self {
        Self {
            points,
            body_limit,
            ..Self::any(line)
        }
    }

    /// Whether the line the host lent is this one, read in place (nothing copied but the route
    /// view's predicate list).
    #[must_use]
    pub fn same(&self, l: Lent<'_, LineEntry>) -> bool {
        let e = *l.get();
        let Some(v) = l.route_view() else {
            return false;
        };
        e.line == self.line
            && e.points == self.points
            && e.auth == self.auth
            && e.body_limit == self.body_limit
            && v.methods == self.methods
            && v.path_form == self.path_form
            && v.path == self.path
            && v.rung == self.rung
            && v.fields.len() == self.fields.len()
            && v.fields
                .iter()
                .zip(&self.fields)
                .all(|((op, n, val), (o, name, value))| op == o && n == name && *val == &value[..])
    }

    /// The line's route in the contract's vocabulary; its predicate list built only where it has
    /// one (an empty list allocates nothing).
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

    /// The line's route without its predicates: whether its path holds, at no allocation.
    fn path_view(&self) -> RouteView<'_> {
        RouteView {
            methods: self.methods,
            path_form: self.path_form,
            path: &self.path,
            fields: Vec::new(),
            rung: self.rung,
        }
    }
}

/// How many listeners' guest lists an instance keeps copied.
const LISTS_KEPT: usize = 16;

/// THE GUEST LISTS AN INSTANCE HAS COPIED, one per listener, shared by every connection it
/// accepts: `begin` compares the lent list with these in place and copies it only when it is new
/// (a listener's list is the same for every connection; a changed one is copied afresh).
#[derive(Default)]
pub struct Lists(Mutex<Vec<Arc<[Line]>>>);

impl Lists {
    /// The list `same` recognises, else the one `copy` makes (kept for the next `begin`); `None`
    /// when `copy` answers none.
    pub fn shared(
        &self,
        same: impl Fn(&[Line]) -> bool,
        copy: impl FnOnce() -> Option<Vec<Line>>,
    ) -> Option<Arc<[Line]>> {
        let mut kept = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(at) = kept.iter().position(|l| same(l)) {
            let l = kept.remove(at);
            kept.push(l.clone());
            return Some(l);
        }
        let l: Arc<[Line]> = copy()?.into();
        if kept.len() == LISTS_KEPT {
            kept.remove(0);
        }
        kept.push(l.clone());
        Some(l)
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

/// Match `method`, `path` and the head's field lines against `lines`, in list order.
#[must_use]
pub fn matched(lines: &[Line], method: &str, path: &str, fields: &[(&str, &[u8])]) -> Matched {
    let mut miss = None;
    for (n, l) in lines.iter().enumerate() {
        // The path first, with no predicate list built; the list only for a line whose path holds.
        if !l.path_view().path_and_fields_match(path, &[]) {
            continue;
        }
        let v = if l.fields.is_empty() {
            l.path_view()
        } else {
            l.view()
        };
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
