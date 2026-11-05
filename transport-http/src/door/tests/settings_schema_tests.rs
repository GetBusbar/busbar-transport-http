// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[path = "../../../../testing/settings/integer_token.rs"]
mod settings_profile;

use super::*;
use busbar_contract::abi::sdk::life::Life;

#[test]
fn settings_schema_matches_lifecycle() {
    let schema: serde_json::Value = serde_json::from_slice(SETTINGS_SCHEMA).unwrap();
    assert_eq!(
        schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(
        STATEMENT.settings_schema.fmt,
        busbar_contract::abi::mechanism::call::BLOB_JSON
    );
    assert_eq!(STATEMENT.settings_schema.len(), SETTINGS_SCHEMA.len());
    let validator = settings_profile::validator(&schema).unwrap();
    for (text, accepted) in [
        ("{}", true),
        ("null", false),
        ("[]", false),
        ("true", false),
        ("{\"unknown\":1}", false),
        ("{\"advanced.upstream_h2_prior_knowledge\":true}", true),
        ("{\"advanced.upstream_h2_prior_knowledge\":false}", true),
        ("{\"advanced.upstream_h2_prior_knowledge\":1}", false),
        ("{\"advanced.upstream_h2_prior_knowledge\":\"true\"}", false),
        ("{\"advanced.upstream_h2_prior_knowledge\":null}", false),
        ("{\"advanced.upstream_http1_only\":true}", true),
        ("{\"advanced.upstream_http1_only\":false}", true),
        ("{\"advanced.upstream_http1_only\":1}", false),
        ("{\"advanced.upstream_http1_only\":\"true\"}", false),
        ("{\"advanced.upstream_http1_only\":null}", false),
        ("{\"limits.upstream_request_timeout_secs\":1}", true),
        (
            "{\"limits.upstream_request_timeout_secs\":18446744073709551615}",
            true,
        ),
        ("{\"limits.upstream_request_timeout_secs\":0}", false),
        ("{\"limits.upstream_request_timeout_secs\":-1}", false),
        ("{\"limits.upstream_request_timeout_secs\":1.5}", false),
        ("{\"limits.upstream_request_timeout_secs\":\"1\"}", false),
        ("{\"limits.upstream_request_timeout_secs\":true}", false),
        ("{\"limits.upstream_request_timeout_secs\":null}", false),
        ("{\"limits.request_body_max_bytes\":1}", true),
        (
            "{\"limits.request_body_max_bytes\":18446744073709551615}",
            true,
        ),
        ("{\"limits.request_body_max_bytes\":0}", false),
        ("{\"limits.request_body_max_bytes\":-1}", false),
        ("{\"limits.request_body_max_bytes\":1.5}", false),
        ("{\"limits.request_body_max_bytes\":\"1\"}", false),
        ("{\"limits.request_body_max_bytes\":true}", false),
        ("{\"limits.request_body_max_bytes\":null}", false),
    ] {
        let value: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(validator.is_valid(&value), accepted, "schema: {text}");
        assert_eq!(
            Instance::validate(text.as_bytes()).is_ok(),
            accepted,
            "lifecycle: {text}"
        );
    }
    assert!(Instance::validate(b"").is_ok());
    assert!(Instance::validate(b" ").is_err());
}

#[test]
fn settings_schema_matches_declared_rows() {
    let schema: serde_json::Value = serde_json::from_slice(SETTINGS_SCHEMA).unwrap();
    let properties = schema["properties"].as_object().unwrap();
    let rows = SETTING_ROWS.map(|(path, kind, default)| SettingRow {
        path,
        kind,
        default,
    });
    assert_eq!(properties.len(), rows.len());
    assert!(schema.get("required").is_none());
    for row in rows {
        let property = &properties[row.path];
        let default: serde_json::Value = serde_json::from_str(row.default).unwrap();
        assert_eq!(property["default"], default);
        if row.kind == busbar_contract::abi::transport::SETTING_FLAG {
            assert_eq!(property["type"], "boolean");
        } else {
            assert_eq!(row.kind, busbar_contract::abi::transport::SETTING_COUNT);
            assert_eq!(property["type"], "integer");
            assert_eq!(property["minimum"], 1);
            assert_eq!(property["maximum"].as_u64(), Some(u64::MAX));
        }
    }
}

#[test]
fn settings_schema_integer_tokens_match_native_parser() {
    let schema: serde_json::Value = serde_json::from_slice(SETTINGS_SCHEMA).unwrap();
    let profile = settings_profile::validator(&schema).unwrap();
    let standard = jsonschema::validator_for(&schema).unwrap();
    assert_eq!(schema["x-busbar-settings-profile"], "integer-token-v1");
    for (pointer, template, integer, kind) in [
        (
            r#"/properties/limits.upstream_request_timeout_secs"#,
            r#"{"limits.upstream_request_timeout_secs":TOKEN}"#,
            "1",
            "unsigned",
        ),
        (
            r#"/properties/limits.request_body_max_bytes"#,
            r#"{"limits.request_body_max_bytes":TOKEN}"#,
            "1",
            "unsigned",
        ),
    ] {
        assert_eq!(
            schema.pointer(pointer).unwrap()["x-busbar-integer-token"],
            kind
        );
        for (token, accepted) in [
            (integer.to_string(), true),
            (format!("{integer}.0"), false),
            (format!("{integer}e0"), false),
            (format!("{integer}E+0"), false),
        ] {
            let text = template.replace("TOKEN", &token);
            let value: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert!(
                standard.is_valid(&value),
                "standard mathematical integer: {text}"
            );
            assert_eq!(profile.is_valid(&value), accepted, "profile: {text}");
            assert_eq!(
                Instance::validate(text.as_bytes()).is_ok(),
                accepted,
                "native: {text}"
            );
        }
        // Do not infer signed negative-zero behavior from a regular expression:
        // the profile must agree with the actual lifecycle parser.
        for token in [
            "null",
            "0",
            "-0",
            "-0.0",
            "0e0",
            "-1",
            "18446744073709551616",
        ] {
            let text = template.replace("TOKEN", token);
            let value: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(
                profile.is_valid(&value),
                Instance::validate(text.as_bytes()).is_ok(),
                "native sign/range: {text}"
            );
        }
    }
}
