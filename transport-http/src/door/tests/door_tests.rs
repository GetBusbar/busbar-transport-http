// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

/// A settings blob's bytes, as `validate`/`open` read them off the lent blob.
fn blob(s: &'static str) -> &'static [u8] {
    s.as_bytes()
}

/// The settings default to 1.5.5's posture, and a value of the wrong kind is refused by name.
#[test]
fn the_settings_read_at_their_paths_and_refuse_the_wrong_kind() {
    let (p, prior, h1) = read_settings(blob("{}")).expect("defaults");
    assert_eq!(p.keep_alive_interval, Some(Duration::from_secs(30)));
    assert_eq!(p.keep_alive_timeout, Duration::from_secs(10));
    assert!(p.adaptive_window);
    assert_eq!(p.request_timeout, Duration::from_secs(300));
    assert!(!prior && !h1);
    let (p, prior, h1) = read_settings(blob(
        r#"{"advanced.upstream_h2_prior_knowledge":true,"advanced.upstream_http1_only":true,
            "limits.upstream_request_timeout_secs":7,"limits.request_body_max_bytes":9}"#,
    ))
    .expect("set");
    assert!(prior && h1);
    assert_eq!(
        (p.request_timeout, p.max_body_bytes),
        (Duration::from_secs(7), 9)
    );
    let refused = |s: &'static str| {
        read_settings(blob(s))
            .err()
            .and_then(|e| e.text().map(str::to_owned))
    };
    assert_eq!(
        refused(r#"{"advanced.upstream_http1_only":"yes"}"#).as_deref(),
        Some("settings: advanced.upstream_http1_only must be true or false")
    );
    assert_eq!(
        refused(r#"{"limits.request_body_max_bytes":-1}"#).as_deref(),
        Some("settings: limits.request_body_max_bytes must be a count of bytes above 0")
    );
    assert_eq!(
        refused("[").as_deref(),
        Some("settings: must be a JSON object")
    );
}

/// Settings refuse undeclared keys, zero limits, and invalid values with canonical explanations.
#[test]
fn the_settings_refuse_undeclared_keys_zero_limits_and_bad_values_in_the_canons_words() {
    let refused = |s: &'static str| {
        read_settings(blob(s))
            .err()
            .and_then(|e| e.text().map(str::to_owned))
    };
    assert_eq!(
        refused(r#"{"advanced.upstream_h2_prior_knowledge":false,"limits.nope":1}"#).as_deref(),
        Some("settings: limits.nope is not a setting this transport reads")
    );
    assert_eq!(
        refused(r#"{"limits.request_body_max_bytes":0}"#).as_deref(),
        Some("settings: limits.request_body_max_bytes must be a count of bytes above 0")
    );
    assert_eq!(
        refused(r#"{"limits.upstream_request_timeout_secs":0}"#).as_deref(),
        Some("settings: limits.upstream_request_timeout_secs must be a count of seconds above 0")
    );
    assert_eq!(
        refused(r#"{"limits.upstream_request_timeout_secs":"7"}"#).as_deref(),
        Some("settings: limits.upstream_request_timeout_secs must be a count of seconds above 0")
    );
    assert_eq!(
        refused(r#"{"advanced.upstream_h2_prior_knowledge":1}"#).as_deref(),
        Some("settings: advanced.upstream_h2_prior_knowledge must be true or false")
    );
}

/// `locate` lowercases DNS and IPv6 names as the 1.5.5 URL parser did.
#[test]
fn locate_offers_a_dns_name_lower_cased() {
    let (_, authority, name) = located(b"https://API.Example.com/").expect("located");
    assert_eq!(name, "api.example.com");
    assert_eq!(authority, "API.Example.com:443");
    let (_, _, name) = located(b"https://[FE80::1]:4318/").expect("located");
    assert_eq!(name, "fe80::1");
}

/// A settings blob that is not a JSON object reads nothing, so it is refused, not defaulted.
#[test]
fn a_settings_blob_that_is_not_an_object_is_refused() {
    for s in ["null", "[]", "\"x\"", "5", "true"] {
        let r = read_settings(blob(s))
            .err()
            .and_then(|e| e.text().map(str::to_owned));
        assert_eq!(r.as_deref(), Some("settings: must be a JSON object"), "{s}");
    }
    assert!(read_settings(blob("")).is_ok());
}

/// The defaults the settings declare are the host's own (`transport::registry`), so the door and
/// the host read one figure for each.
#[test]
fn the_declared_defaults_are_the_hosts() {
    use busbar_contract::transport::registry::{
        DEFAULT_REQUEST_BODY_MAX_BYTES, DEFAULT_REQUEST_TIMEOUT_SECS,
    };
    assert_eq!(
        declared_count(setting::REQUEST_TIMEOUT_SECS),
        DEFAULT_REQUEST_TIMEOUT_SECS
    );
    assert_eq!(
        declared_count(setting::BODY_MAX_BYTES),
        DEFAULT_REQUEST_BODY_MAX_BYTES as u64
    );
}

/// Each status band lands in its class; anything outside the three bands is other.
#[test]
fn a_status_code_maps_to_its_class() {
    assert_eq!(class_of(200), STATUS_SUCCESS);
    assert_eq!(class_of(429), STATUS_CALLER_FAULT);
    assert_eq!(class_of(503), STATUS_FAR_END_FAULT);
    assert_eq!(class_of(101), STATUS_OTHER);

    for (code, class) in [
        (199, STATUS_OTHER),
        (200, STATUS_SUCCESS),
        (299, STATUS_SUCCESS),
        (300, STATUS_OTHER),
        (399, STATUS_OTHER),
        (400, STATUS_CALLER_FAULT),
        (499, STATUS_CALLER_FAULT),
        (500, STATUS_FAR_END_FAULT),
        (599, STATUS_FAR_END_FAULT),
        (600, STATUS_OTHER),
    ] {
        assert_eq!(class_of(code), class, "status {code}");
    }
}

/// Response status codes retain their 1.5.5 breaker fault classifications.
#[test]
fn a_status_code_maps_to_the_breakers_fault_reading() {
    let expect: &[(u16, u8)] = &[
        (200, FAULT_NONE),
        (204, FAULT_NONE),
        (301, FAULT_NONE),
        (399, FAULT_NONE),
        (400, FAULT_CALLER),
        (401, FAULT_HARD),
        (402, FAULT_CALLER),
        (403, FAULT_HARD),
        (404, FAULT_CALLER),
        (407, FAULT_CALLER),
        (408, FAULT_TRANSIENT),
        (409, FAULT_CALLER),
        (413, FAULT_CALLER),
        (422, FAULT_CALLER),
        (428, FAULT_CALLER),
        (429, FAULT_TRANSIENT),
        (430, FAULT_CALLER),
        (499, FAULT_CALLER),
        (500, FAULT_TRANSIENT),
        (503, FAULT_TRANSIENT),
        (529, FAULT_TRANSIENT),
        (599, FAULT_TRANSIENT),
        (600, FAULT_NONE),
    ];
    for (code, fault) in expect {
        assert_eq!(fault_of(*code), *fault, "status {code}");
    }
}

/// Every claim that classes its answers reads them for the breaker too, with the same table, and
/// the tail the door states passes the host's load checks for both tables.
#[test]
fn every_classed_claim_has_the_fault_table() {
    use busbar_contract::abi::transport::check::{
        check_fault_cover, check_fault_rows, check_status_rows,
    };
    let claims = FAULT_CLAIMS as u64;
    assert_eq!(check_status_rows(STATUS_ROWS, claims), Ok(()));
    assert_eq!(check_fault_rows(FAULT_ROWS, claims), Ok(()));
    assert_eq!(check_fault_cover(STATUS_ROWS, FAULT_ROWS), Ok(()));
    for claim in 0..FAULT_CLAIMS as u32 {
        let rows: Vec<(u32, u32, u32)> = FAULT_ROWS
            .iter()
            .filter(|r| r.claim == claim)
            .map(|r| (r.lo, r.hi, r.fault))
            .collect();
        let want: Vec<(u32, u32, u32)> = HTTP_FAULTS
            .iter()
            .map(|&(lo, hi, fault)| (lo, hi, fault as u32))
            .collect();
        assert_eq!(rows, want, "claim {claim}: the fault table's rows");
        let classes: Vec<(u32, u32, u32)> = STATUS_ROWS
            .iter()
            .filter(|r| r.claim == claim)
            .map(|r| (r.lo, r.hi, r.class))
            .collect();
        assert_eq!(classes, HTTP_CLASSES, "claim {claim}: the status rows");
    }
}

/// `locate` offers the same ALPN protocols as the 1.5.5 reqwest 0.12 client.
#[test]
fn locate_offers_what_1_5_5_offered_in_the_handshake() {
    let keys = |s: &'static str| {
        let (_, prior, h1) = read_settings(blob(s)).expect("settings");
        (prior, h1)
    };
    let offer = |secure, s| {
        let (prior, h1) = keys(s);
        offer_for(secure, prior, h1)
    };
    assert_eq!(offer(true, "{}"), b"\x02h2\x08http/1.1");
    assert_eq!(
        offer(true, r#"{"advanced.upstream_http1_only":true}"#),
        b"\x08http/1.1"
    );
    assert_eq!(
        offer(true, r#"{"advanced.upstream_h2_prior_knowledge":true}"#),
        b"\x02h2"
    );
    assert_eq!(
        offer(
            true,
            r#"{"advanced.upstream_h2_prior_knowledge":true,"advanced.upstream_http1_only":true}"#
        ),
        b"\x08http/1.1"
    );

    assert_eq!(offer(false, "{}"), b"");
    assert_eq!(
        offer(false, r#"{"advanced.upstream_h2_prior_knowledge":true}"#),
        b"\x02h2"
    );
    assert_eq!(
        offer(
            false,
            r#"{"advanced.upstream_h2_prior_knowledge":true,"advanced.upstream_http1_only":true}"#
        ),
        b""
    );
    assert_eq!(offer_for(false, false, true), b"");
}

#[test]
fn locate_offers_the_address_an_ipv4_spelling_names() {
    for (target, authority, name) in [
        ("https://127.1:4318/v1/traces", "127.1:4318", "127.0.0.1"),
        ("https://2130706433/", "2130706433:443", "127.0.0.1"),
        ("https://0x7f000001:8443/", "0x7f000001:8443", "127.0.0.1"),
        ("https://017700000001/", "017700000001:443", "127.0.0.1"),
        ("https://16909060/", "16909060:443", "1.2.3.4"),
        ("https://0x1020304/x", "0x1020304:443", "1.2.3.4"),
        ("https://1.2.772/", "1.2.772:443", "1.2.3.4"),
        ("https://127.0.0.1./", "127.0.0.1.:443", "127.0.0.1"),
        (
            "https://collector.example.com/",
            "collector.example.com:443",
            "collector.example.com",
        ),
        ("https://localhost:4318/", "localhost:4318", "localhost"),
        ("https://[::1]:4318/", "[::1]:4318", "::1"),
        (
            "https://93.184.216.34/",
            "93.184.216.34:443",
            "93.184.216.34",
        ),
        ("http://127.1:4318/", "127.1:4318", "127.0.0.1"),
    ] {
        let (_, a, n) = located(target.as_bytes()).expect(target);
        assert_eq!((a.as_str(), n.as_str()), (authority, name), "{target}");
    }
    assert_eq!(located(b"https://127.1/").map(|l| l.0), Ok(true));
    assert_eq!(located(b"http://127.1/").map(|l| l.0), Ok(false));
    assert!(located(b"ftp://127.1/").is_err());
}

/// The field block preserves hyper's 1.5.5 order and duplicates while dropping hop-by-hop fields.
#[test]
fn the_field_block_keeps_order_and_duplicates_and_drops_hop_by_hop() {
    let mut h = http::HeaderMap::new();
    for (n, v) in [
        ("X-B", "1"),
        ("Connection", "keep-alive, X-Hop"),
        ("x-a", "v: w"),
        ("Keep-Alive", "timeout=5"),
        ("x-b", "2"),
        ("X-Hop", "secret"),
        ("TE", "trailers"),
        ("Upgrade", "h2c"),
        ("Transfer-Encoding", "chunked"),
        ("Content-Length", "5"),
        ("X-Session-Id", "s1"),
    ] {
        h.append(
            http::header::HeaderName::from_bytes(n.as_bytes()).unwrap(),
            http::HeaderValue::from_static(v),
        );
    }
    assert_eq!(
        String::from_utf8(engine::field_block(&h, &[])).unwrap(),
        "x-b: 1\r\nx-b: 2\r\nx-a: v: w\r\nx-session-id: s1\r\n"
    );
    assert!(engine::field_block(&http::HeaderMap::new(), &[]).is_empty());
}

/// A field block is cut only at a line's start or inside a value, never inside a name: the host
/// refuses any continuation that does not extend a value.
#[test]
fn a_field_block_is_cut_only_where_a_continuation_extends_a_value() {
    let block = b"date: Mon\r\nx-a: 1\r\n";
    assert_eq!(field_cut(block, 64, false), block.len());

    assert_eq!(field_cut(block, 3, false), 0);
    assert_eq!(field_cut(block, 5, false), 5);

    assert_eq!(field_cut(block, 13, false), 11);

    assert_eq!(field_cut(b"on\r\nx: 1\r\n", 5, true), 4);
}

/// The request target uses the same percent encoding as the 1.5.5 client.
#[test]
fn a_target_is_percent_encoded_as_1_5_5_wrote_it() {
    let enc = |t: &str| String::from_utf8(dest_head::encode_target(t.as_bytes()).unwrap()).unwrap();
    assert_eq!(
        enc("/v1beta/models/my model:generateContent"),
        "/v1beta/models/my%20model:generateContent"
    );
    assert_eq!(enc("/v1/a%20b"), "/v1/a%20b");
    for bad in ["/a\rb", "/a\nb", "/a\0b"] {
        assert_eq!(
            dest_head::encode_target(bad.as_bytes()),
            Err(dest_head::REFUSED),
            "{bad:?}"
        );
    }
}

/// Target encoding matches the URL parser used by the 1.5.5 client.
#[test]
fn the_target_encoder_matches_the_url_parser_1_5_5_used() {
    let table = [
        "/v1/chat/completions",
        "/v1/models/my model:generateContent",
        "/v1/a%20b",
        "/v1/a%zz",
        "/v1/x?alt=sse",
        "/v1/x?q=a b&c=\"d\"",
        "/v1/x?q='quoted'",
        "/v1/x?q=<tag>#frag",
        "/v1/x#frag",
        "/v1/\"quoted\"/path",
        "/v1/<angle>",
        "/v1/`tick`",
        "/v1/{brace}",
        "/v1/pipe|caret^",
        "/v1/ümlaut/日本",
        "/v1/./a/../b",
        "/v1/%2e/a/%2E%2e/b",
        "/v1/a/..",
        "/v1/a/.",
        "/..",
        "",
        "/",
        "//double//slash",
        "\\v1\\back",
        "v1/relative",
        "/v1/ta\tb",
        "/v1/del\u{7f}",
        "/v1/ctl\u{1}",
        "/v1/x?",
        "/v1/x??y",
    ];
    for t in table {
        let absolute = if t.starts_with('/') || t.starts_with('\\') {
            t.to_owned()
        } else {
            format!("/{t}")
        };
        let url = url::Url::parse(&format!("http://h{absolute}")).unwrap();
        let want = &url[url::Position::BeforePath..url::Position::AfterQuery];
        let got = dest_head::encode_target(t.as_bytes()).unwrap();
        assert_eq!(String::from_utf8(got).unwrap(), want, "{t:?}");
    }
}

/// The entry claims `http`, `https`, and `sse`.
#[test]
fn the_entry_claims_http_https_and_sse() {
    let names: Vec<usize> = CLAIM_NAMES.iter().map(|c| c.len).collect();
    assert_eq!(names, [4, 3, 5]);
    assert_eq!(CLAIMS.len(), names.len());
    // `https` is the same wire as `http`: its claim row is `http`'s, field by field.
    let (h, s) = (&CLAIMS[0], &CLAIMS[2]);
    let strs = |a: &AbiStr| (a.ptr, a.len);
    assert_eq!(strs(&s.selector_forms), strs(&h.selector_forms));
    assert!(s.selector_forms.len > 0, "https states selector forms");
    assert_eq!(
        strs(&s.egress_selector_forms),
        strs(&h.egress_selector_forms)
    );
    assert_eq!((s.facts, s.facts_len), (h.facts, h.facts_len));
    assert!(s.facts_len > 0, "https states its facts");
    assert_eq!(strs(&s.status_namespace), strs(&h.status_namespace));
    assert!(
        s.status_namespace.len > 0,
        "https states a status namespace"
    );
    assert_eq!(s.status_at, h.status_at);
    assert_eq!(s.session, h.session);
    assert_eq!(s.session_bound, h.session_bound);
    assert_eq!(s.unit0_trigger, h.unit0_trigger);
    let https: Vec<(u32, u32, u32)> = STATUS_ROWS
        .iter()
        .filter(|r| r.claim == 2)
        .map(|r| (r.lo, r.hi, r.class))
        .collect();
    let http: Vec<(u32, u32, u32)> = STATUS_ROWS
        .iter()
        .filter(|r| r.claim == 0)
        .map(|r| (r.lo, r.hi, r.class))
        .collect();
    assert_eq!(https, http);
}

/// The tail states exactly the ops this door serves: dialling, the accepted side (`begin` on
/// `SIDE_ACCEPT`), and `detach` on an upgrade line.
#[test]
fn the_tail_states_the_ops_the_door_serves() {
    use busbar_contract::abi::transport::{FACT_ACCEPTS, FACT_ADOPTS, FACT_DETACHES, FACT_DIALS};
    assert_eq!(
        crate::meta::TAIL.facts,
        FACT_DIALS | FACT_ACCEPTS | FACT_DETACHES
    );
    assert_eq!(
        crate::meta::TAIL.facts & FACT_ADOPTS,
        0,
        "adopt stays declined"
    );
}

/// Every declared inbound selector form is supported by guest-list routing.
#[test]
fn every_declared_inbound_form_is_one_a_guest_list_route_carries() {
    use busbar_contract::abi::transport::route::{
        FIELD_PRESENT, FIELD_VALUE_PREFIX, PATH_CONTAINS, PATH_EXACT, PATH_PATTERN, PATH_PREFIX,
        PATH_SUFFIX,
    };
    use busbar_contract::SelectorForm;
    let spelled = |f: SelectorForm| match f {
        SelectorForm::ExactPath => Some(PATH_EXACT),
        SelectorForm::PrefixOneLevel => Some(PATH_PREFIX),
        SelectorForm::PathPattern => Some(PATH_PATTERN),
        SelectorForm::PathSuffix => Some(PATH_SUFFIX),
        SelectorForm::PathContains => Some(PATH_CONTAINS),
        SelectorForm::HeaderPresent => Some(FIELD_PRESENT),
        SelectorForm::HeaderPrefix => Some(FIELD_VALUE_PREFIX),
        _ => None,
    };
    let unspelled: Vec<SelectorForm> = crate::claims::SELECTOR_FORMS
        .iter()
        .copied()
        .filter(|f| spelled(*f).is_none())
        .collect();
    assert_eq!(
        unspelled,
        Vec::<SelectorForm>::new(),
        "a declared inbound form no guest-list route spells"
    );
    assert!(crate::claims::SSE_SELECTOR_FORMS.is_empty());
}

/// An `sse` target locates like its `http` equivalent.
#[test]
fn an_sse_target_locates_as_its_http_twin() {
    for (sse, http) in [
        ("sse://peer.test/x", "http://peer.test/x"),
        (
            "sse://peer.test:8080/x?alt=sse",
            "http://peer.test:8080/x?alt=sse",
        ),
        ("sse://127.1/x", "http://127.1/x"),
    ] {
        assert_eq!(located(sse.as_bytes()), located(http.as_bytes()), "{sse}");
        assert!(located(sse.as_bytes()).is_ok(), "{sse}");
        let defaults = |t: &str| engine::client_defaults(&t.parse::<http::Uri>().expect("a URI"));
        assert_eq!(defaults(sse), defaults(http), "{sse}");
    }
}

#[test]
fn every_owned_target_buffer_is_wiped_after_normalization_and_percent_expansion() {
    let target = format!(
        "\t /discard/../credential-{}?key={}#discard \t",
        " ".repeat(1024),
        "target-secret".repeat(100)
    );
    let probe = crate::wipe_probe::Probe::start();
    let encoded = zeroize::Zeroizing::new(dest_head::encode_target(target.as_bytes()).unwrap());
    assert!(encoded.windows(3).any(|part| part == b"%20"));
    assert!(!encoded.contains(&b'#'));
    drop(encoded);
    probe
        .finish()
        .assert_wiped_on_linux(&["target filtered", "target path", "target encoded"]);
}

#[test]
fn locate_rejects_explicit_invalid_ports_without_defaulting() {
    for target in [
        b"http://example.com:65536/".as_slice(),
        b"https://[::1]:99999/",
        b"http://example.com:abc/",
    ] {
        assert!(located(target).is_err());
    }
    assert_eq!(located(b"http://example.com/").unwrap().1, "example.com:80");
    assert_eq!(located(b"https://[::1]:443/").unwrap().1, "[::1]:443");
}
