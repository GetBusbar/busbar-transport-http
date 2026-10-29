// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::transport::route::{
    FIELD_PRESENT, METHOD_GET, METHOD_POST, PATH_EXACT, PATH_PREFIX,
};

fn line(id: u32, methods: u32, form: u32, path: &str, fields: &[(u32, &str)]) -> Line {
    Line {
        line: id,
        points: 0,
        auth: AuthRef { id: 1, mac: 1 },
        body_limit: 0,
        methods,
        path_form: form,
        path: path.to_owned(),
        fields: fields
            .iter()
            .map(|(op, n)| (*op, (*n).to_owned(), Vec::new()))
            .collect(),
        rung: 0,
    }
}

/// The first line in list order whose route holds and whose methods admit wins; a predicate line
/// that does not hold is passed over; a path that holds with no method admitted is a miss on the
/// first such line; nothing holding is no route.
#[test]
fn the_guest_list_matches_in_order() {
    let lines = [
        line(
            1,
            METHOD_POST,
            PATH_EXACT,
            "/v1/messages",
            &[(FIELD_PRESENT, "x-api-key")],
        ),
        line(2, METHOD_POST, PATH_EXACT, "/v1/messages", &[]),
        line(3, METHOD_GET, PATH_PREFIX, "/v1", &[]),
    ];
    let key: &[(&str, &[u8])] = &[("X-Api-Key", b"k")];
    assert_eq!(
        matched(&lines, "POST", "/v1/messages", key),
        Matched::Line(0)
    );
    assert_eq!(
        matched(&lines, "POST", "/v1/messages", &[]),
        Matched::Line(1)
    );
    assert_eq!(
        matched(&lines, "GET", "/v1/messages", key),
        Matched::Line(2)
    );
    assert_eq!(
        matched(&lines, "DELETE", "/v1/messages", &[]),
        Matched::MethodMiss(1)
    );
    assert_eq!(matched(&lines, "GET", "/nope", &[]), Matched::NoRoute);
    assert_eq!(matched(&[], "GET", "/", &[]), Matched::NoRoute);
}

/// A query key is stripped case-sensitively, as spelled, with or without a value; a field name
/// ASCII case-insensitively; a name in one place never strips the other.
#[test]
fn the_strip_reads_each_place_by_its_own_rule() {
    let names = vec![
        ("key".to_owned(), Place::Query),
        ("X-Api-Key".to_owned(), Place::Field),
    ];
    assert_eq!(
        stripped_query("a=1&key=s&Key=k&key&b", &names).as_deref(),
        Some("a=1&Key=k&b")
    );
    assert_eq!(stripped_query("key=s", &names), None);
    assert!(strips_field("x-api-key", &names));
    assert!(!strips_field("key", &names));
    assert_eq!(
        stripped_query("x-api-key=1", &names).as_deref(),
        Some("x-api-key=1")
    );
}

/// A query key is compared as the key it percent-decodes to, as v1.5.5 read every inbound query
/// key (`crates/busbar/src/auth/token.rs`:996-1003 `parse_query`, :1012-1035 `pct_decode`: `%XX`
/// and `+` decoded, a malformed `%` kept as written): `%6Bey` and `k%65y` are `key`; `ke+y` is
/// `ke y`; the comparison after decoding stays case-sensitive.
#[test]
fn a_query_key_is_compared_as_it_decodes() {
    let names = vec![("key".to_owned(), Place::Query)];
    assert_eq!(
        stripped_query("a=1&%6Bey=s&k%65y&Key=k&ke+y=x&%zzkey=y", &names).as_deref(),
        Some("a=1&Key=k&ke+y=x&%zzkey=y")
    );
    let spaced = vec![("a b".to_owned(), Place::Query)];
    assert_eq!(
        stripped_query("a+b=1&a%20b=2&c=3", &spaced).as_deref(),
        Some("c=3")
    );
}
