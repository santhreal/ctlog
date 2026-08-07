//! Unit + property tests for the `ctlog` parse and URL layers.
//!
//! The fetch layer (`discover_subdomains_ct[_with]`) is an HTTP round-trip
//! exercised by each consumer's integration tests against its own
//! transport; here we pin the pure, deterministic core: URL canonicality
//! and the normalization contract, including the three bugs folding karyx
//! onto this crate fixes.

use super::*;
use proptest::prelude::*;

// ── parse_crtsh_subdomains: core behavior ──────────────────────────────

#[test]
fn parses_valid_crtsh_json() {
    let json = r#"[
        {"name_value": "api.example.com"},
        {"name_value": "www.example.com\nmail.example.com"},
        {"name_value": "*.example.com"},
        {"name_value": "example.com"}
    ]"#;
    let result = parse_crtsh_subdomains(json, "example.com").unwrap();
    // apex and apex-wildcard both excluded; rest sorted+deduped.
    assert_eq!(
        result,
        ["api.example.com", "mail.example.com", "www.example.com"]
    );
}

#[test]
fn deduplicates_subdomains() {
    let json = r#"[
        {"name_value": "api.example.com"},
        {"name_value": "api.example.com"},
        {"name_value": "API.EXAMPLE.COM"}
    ]"#;
    let result = parse_crtsh_subdomains(json, "example.com").unwrap();
    assert_eq!(result, ["api.example.com"]);
}

#[test]
fn handles_empty_json_array() {
    assert!(parse_crtsh_subdomains("[]", "example.com")
        .unwrap()
        .is_empty());
}

#[test]
fn rejects_invalid_json() {
    assert!(parse_crtsh_subdomains("not json", "example.com").is_err());
    assert!(matches!(
        parse_crtsh_subdomains("not json", "example.com"),
        Err(CtError::Parse(_))
    ));
}

#[test]
fn handles_multiline_name_values() {
    let json = r#"[{"name_value": "a.example.com\nb.example.com\nc.example.com"}]"#;
    let result = parse_crtsh_subdomains(json, "example.com").unwrap();
    assert_eq!(result, ["a.example.com", "b.example.com", "c.example.com"]);
}

#[test]
fn trims_whitespace_in_entries() {
    let json = r#"[
        {"name_value": "  api.example.com  "},
        {"name_value": "\n  www.example.com \n"}
    ]"#;
    let result = parse_crtsh_subdomains(json, "example.com").unwrap();
    assert_eq!(result, ["api.example.com", "www.example.com"]);
}

// ── strip-and-keep: the superset behavior the drop-the-entry copies lost ─

#[test]
fn wildcard_subdomain_is_stripped_and_kept() {
    // A `*.api.example.com` SAN proves `api.example.com` exists. The old
    // wafrift/scald/karyx copies dropped the whole entry and lost it.
    let json = r#"[{"name_value": "*.api.example.com"}]"#;
    let result = parse_crtsh_subdomains(json, "example.com").unwrap();
    assert_eq!(result, ["api.example.com"]);
}

#[test]
fn apex_wildcard_collapses_to_apex_and_is_excluded() {
    let json = r#"[{"name_value": "*.example.com"}]"#;
    // strip "*." -> "example.com" -> equals apex -> excluded.
    assert!(parse_crtsh_subdomains(json, "example.com")
        .unwrap()
        .is_empty());
    // but it IS present in the apex-inclusive hostname view.
    assert_eq!(parse_crtsh_hostnames(json).unwrap(), ["example.com"]);
}

#[test]
fn bare_wildcard_label_is_dropped() {
    // "*." alone strips to "" and is filtered; "*" with no dot still
    // contains '*' and is filtered.
    let json = r#"[{"name_value": "*.\n*\nok.example.com"}]"#;
    assert_eq!(
        parse_crtsh_subdomains(json, "example.com").unwrap(),
        ["ok.example.com"]
    );
}

/// REGRESSION: before 2026-07-31 the normalization pipeline only dropped
/// empties and residual wildcards, so a `name_value` with interior
/// whitespace or control characters (a tab inside a label, an ANSI escape
/// from a hostile mirror) flowed into the returned host list and from
/// there into scanner target queues. Such strings can never be DNS names,
/// so they are now dropped at extraction time. Leading/trailing whitespace
/// is still trimmed (that is well-formed crt.sh output); only interior
/// junk disqualifies the name.
#[test]
fn names_with_interior_whitespace_or_controls_are_dropped() {
    let json = r#"[
        {"name_value": "bad name.example.com"},
        {"name_value": "tab\tsep.example.com"},
        {"name_value": "escape\u001b[0m.example.com"},
        {"name_value": "good.example.com"}
    ]"#;
    assert_eq!(
        parse_crtsh_subdomains(json, "example.com").unwrap(),
        ["good.example.com"]
    );
}

#[test]
fn multiple_multiline_entries_flatten_trim_normalize_and_dedup() {
    // Exercises the fused per-entry walk (no intermediate Vec): several entries,
    // each packing multiple newline-joined SANs with mixed case, whitespace, and
    // wildcard labels, must flatten to one sorted+deduped set.
    let json = r#"[
        {"name_value": "  API.example.com \n*.api.example.com"},
        {"name_value": "www.example.com\nexample.com"},
        {"name_value": "*.\n*\nMAIL.example.com\napi.example.com"}
    ]"#;
    let result = parse_crtsh_hostnames(json).unwrap();
    assert_eq!(
        result,
        [
            "api.example.com",
            "example.com",
            "mail.example.com",
            "www.example.com",
        ]
    );
}

// ── parse_crtsh_hostnames: apex inclusion for origin discovery ──────────

#[test]
fn hostnames_includes_apex() {
    let json = r#"[{"name_value": "example.com\napi.example.com"}]"#;
    assert_eq!(
        parse_crtsh_hostnames(json).unwrap(),
        ["api.example.com", "example.com"]
    );
}

#[test]
fn hostnames_keeps_offdomain_sans() {
    // A multi-SAN cert can certify unrelated apexes; origin discovery
    // resolves them all (matches the legacy ssl_cert behavior).
    let json = r#"[{"name_value": "example.com\nexample.net"}]"#;
    assert_eq!(
        parse_crtsh_hostnames(json).unwrap(),
        ["example.com", "example.net"]
    );
}

// ── karyx regression: mixed-case apex must never leak ───────────────────

#[test]
fn mixed_case_domain_excludes_base() {
    let json = r#"[{"name_value": "sub.example.com"},{"name_value": "example.com"}]"#;
    let result = parse_crtsh_subdomains(json, "Example.COM").unwrap();
    assert_eq!(result, ["sub.example.com"]);
    assert!(!result.contains(&"example.com".to_string()));
}

#[test]
fn all_caps_domain_excludes_base() {
    let json = r#"[{"name_value": "EXAMPLE.COM"},{"name_value": "api.example.com"}]"#;
    assert_eq!(
        parse_crtsh_subdomains(json, "EXAMPLE.COM").unwrap(),
        ["api.example.com"]
    );
}

#[test]
fn camel_case_domain_excludes_base() {
    let json = r#"[{"name_value": "mail.ExAmPlE.cOm"},{"name_value": "ExAmPlE.cOm"}]"#;
    assert_eq!(
        parse_crtsh_subdomains(json, "ExAmPlE.cOm").unwrap(),
        ["mail.example.com"]
    );
}

#[test]
fn mixed_case_domain_empty_when_only_base() {
    let json = r#"[{"name_value": "Example.COM"}]"#;
    assert!(parse_crtsh_subdomains(json, "Example.COM")
        .unwrap()
        .is_empty());
}

#[test]
fn domain_with_surrounding_whitespace_excludes_base() {
    let json = r#"[{"name_value": "example.com"},{"name_value": "x.example.com"}]"#;
    assert_eq!(
        parse_crtsh_subdomains(json, "  example.com  ").unwrap(),
        ["x.example.com"]
    );
}

// ── crtsh_query_url: wildcard prefix + encoding (karyx URL bug) ──────────

#[test]
fn url_has_wildcard_prefix_for_subdomain_coverage() {
    // The missing "%." prefix was the bug that made karyx blind to
    // subdomains - only the apex cert came back.
    let url = crtsh_query_url("example.com");
    assert!(url.starts_with("https://crt.sh/?q=%."), "got {url}");
    assert!(url.ends_with("&output=json"));
    assert!(url.contains("%.example.com"));
}

#[test]
fn url_percent_encodes_hostile_domain() {
    // A target containing query-delimiters must not break out of the
    // `q=` component.
    let url = crtsh_query_url("evil.com&foo=bar baz");
    assert!(!url.contains(' '));
    assert!(url.contains("evil.com%26foo%3Dbar%20baz"));
    assert!(url.ends_with("&output=json"));
}

#[test]
fn url_trims_domain() {
    assert_eq!(
        crtsh_query_url("  example.com  "),
        "https://crt.sh/?q=%.example.com&output=json"
    );
}

#[test]
fn apex_query_url_targets_the_apex_identity() {
    assert_eq!(
        crtsh_apex_query_url("Example.com"),
        "https://crt.sh/?q=Example.com&output=json"
    );
    assert_eq!(
        crtsh_apex_query_url("  example.com  "),
        "https://crt.sh/?q=example.com&output=json"
    );
}

#[test]
fn parse_subdomains_includes_apex_only_cert_subdomains() {
    // A certificate that lists the apex plus one concrete subdomain, but no
    // wildcard. The `%.` query would miss this; the apex query must surface it.
    let body = r#"[
        {"name_value": "example.com"},
        {"name_value": "api.example.com"}
    ]"#;
    let subs = parse_crtsh_subdomains(body, "example.com").unwrap();
    assert_eq!(subs, ["api.example.com"]);
}
#[test]
fn cleans_input_domain_wildcard_and_dots() {
    assert_eq!(clean_domain("  *.example.com.  "), "example.com");
    assert_eq!(clean_domain(".sub.example.com"), "sub.example.com");
    assert_eq!(clean_domain("example.com."), "example.com");
}

#[test]
fn url_strips_leading_wildcard_from_input_domain() {
    assert_eq!(
        crtsh_query_url("*.example.com"),
        "https://crt.sh/?q=%.example.com&output=json"
    );
    assert_eq!(
        crtsh_apex_query_url("*.example.com"),
        "https://crt.sh/?q=example.com&output=json"
    );
}

#[test]
fn parse_subdomains_excludes_apex_when_queried_with_wildcard_domain() {
    let body = r#"[
        {"name_value": "example.com"},
        {"name_value": "api.example.com"}
    ]"#;
    let subs = parse_crtsh_subdomains(body, "*.example.com").unwrap();
    assert_eq!(subs, ["api.example.com"]);
}

#[test]
fn SAN_normalization_strips_trailing_dots() {
    let body = r#"[
        {"name_value": "api.example.com.\nwww.example.com."}
    ]"#;
    let names = parse_crtsh_hostnames(body).unwrap();
    assert_eq!(names, ["api.example.com", "www.example.com"]);
}
#[test]
fn cleans_domain_with_multiple_wildcards_and_dots() {
    assert_eq!(clean_domain("*.*.example.com.."), "example.com");
    assert_eq!(clean_domain("..sub.example.com."), "sub.example.com");
    assert_eq!(clean_domain("*..example.com.."), "example.com");
    assert_eq!(clean_domain("*."), "");
    assert_eq!(clean_domain(".."), "");
}

#[test]
fn san_normalization_handles_multiple_trailing_dots_and_invalid_chars() {
    let body = r#"[
        {"name_value": "api.example.com..\n..\nhttp://bad.example.com\nuser@example.com\nfoo..bar.example.com\napi.example.com:443"}
    ]"#;
    let names = parse_crtsh_hostnames(body).unwrap();
    assert_eq!(names, ["api.example.com"]);
}

#[test]
fn parse_handles_empty_body_and_whitespace() {
    assert_eq!(parse_crtsh_hostnames("").unwrap(), Vec::<String>::new());
    assert_eq!(
        parse_crtsh_subdomains("   \n\t ", "example.com").unwrap(),
        Vec::<String>::new()
    );
}

// ── properties ──────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn parse_never_panics_on_arbitrary_input(s in ".*") {
        let _ = parse_crtsh_subdomains(&s, "example.com");
        let _ = parse_crtsh_hostnames(&s);
    }

    #[test]
    fn url_builder_never_panics(d in ".*") {
        let url = crtsh_query_url(&d);
        prop_assert!(url.starts_with("https://crt.sh/?q=%."));
        prop_assert!(url.ends_with("&output=json"));
    }

    #[test]
    fn subdomains_never_contain_queried_apex(
        labels in proptest::collection::vec("[a-z]{1,8}", 0..6)
    ) {
        // Build a valid crt.sh body whose entries include the apex in a
        // random case; the apex must never survive into the subdomain list.
        let domain = "example.com";
        let mut values = vec!["EXAMPLE.com".to_string(), "example.COM".to_string()];
        for l in &labels {
            values.push(format!("{l}.example.com"));
        }
        let entries: Vec<String> = values
            .iter()
            .map(|v| format!("{{\"name_value\": {}}}", serde_json::to_string(v).unwrap()))
            .collect();
        let body = format!("[{}]", entries.join(","));
        let subs = parse_crtsh_subdomains(&body, domain).unwrap();
        prop_assert!(!subs.iter().any(|s| s == domain));
        // output is sorted + deduped
        let mut sorted = subs.clone();
        sorted.sort();
        sorted.dedup();
        prop_assert_eq!(subs, sorted);
    }
}


#[cfg(feature = "fetch")]
mod fetch_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use wiremock::{matchers::*, Mock, MockServer, ResponseTemplate};

    fn sample_body() -> String {
        serde_json::to_string(&[
            CrtShEntry {
                name_value: "api.example.com\nexample.com".into(),
            },
        ])
        .unwrap()
    }

    #[tokio::test]
    async fn retries_502_then_succeeds() {
        let server = MockServer::start().await;
        let body = sample_body();
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_clone = Arc::clone(&attempts);

        let responder = move |_: &wiremock::Request| {
            let n = attempts_clone.fetch_add(1, Ordering::SeqCst);
            if n < 2 {
                ResponseTemplate::new(502)
            } else {
                ResponseTemplate::new(200).set_body_string(body.clone())
            }
        };

        Mock::given(method("GET")).and(path("/")).respond_with(responder).mount(&server).await;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let url = format!("{}?q=%25.example.com&output=json", server.uri());
        let names = discover_subdomains_ct_with_url(&client, &url, "example.com", &CtOptions::default())
            .await
            .expect("should retry 502 and succeed");
        assert_eq!(names, vec!["api.example.com"]);
        assert!(attempts.load(Ordering::SeqCst) >= 3, "expected at least 3 attempts");
    }

    #[tokio::test]
    async fn rejects_invalid_utf8_response() {
        let server = MockServer::start().await;

        // A single invalid UTF-8 byte inside the JSON string. Lossy
        // replacement would let it through as a bogus hostname; we want a
        // parse error instead.
        let body = b"[{\"name_value\": \"bad\xffvalue.example.com\"}]";
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.as_slice()))
            .mount(&server)
            .await;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let url = format!("{}?q=%25.utf8.example&output=json", server.uri());
        let err = discover_subdomains_ct_with_url(&client, &url, "utf8.example", &CtOptions::default())
            .await
            .expect_err("should reject invalid UTF-8");
        assert!(matches!(err, CtError::Parse(_)), "expected Parse error, got {err:?}");
    }

    #[tokio::test]
    async fn aborts_body_beyond_32mib_cap() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(vec![b'{'; CT_RESPONSE_MAX_BYTES + 1]),
            )
            .mount(&server)
            .await;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let url = format!("{}?q=%25.huge.example&output=json", server.uri());
        let err = discover_subdomains_ct_with_url(&client, &url, "huge.example", &CtOptions::default())
            .await
            .expect_err("should abort oversized response");
        match err {
            CtError::ResponseTooLarge { limit, got } => {
                assert_eq!(limit, CT_RESPONSE_MAX_BYTES);
                assert!(got > CT_RESPONSE_MAX_BYTES);
            }
            other => panic!("expected ResponseTooLarge, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn options_response_byte_cap_is_overridable() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(b"[]"))
            .mount(&server)
            .await;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let url = format!("{}?q=%25.example.com&output=json", server.uri());

        let small_cap = CtOptions {
            max_response_bytes: 1,
            ..CtOptions::default()
        };
        let err = discover_subdomains_ct_with_url(&client, &url, "example.com", &small_cap)
            .await
            .expect_err("custom byte cap should abort");
        match err {
            CtError::ResponseTooLarge { limit, got } => {
                assert_eq!(limit, 1, "limit should come from CtOptions");
                assert!(got > limit, "reported size should exceed custom cap");
            }
            other => panic!("expected ResponseTooLarge, got {other:?}"),
        }

        let large_cap = CtOptions {
            max_response_bytes: 1024,
            ..CtOptions::default()
        };
        let names = discover_subdomains_ct_with_url(&client, &url, "example.com", &large_cap)
            .await
            .expect("larger cap should allow the empty JSON array");
        assert!(names.is_empty(), "empty JSON array yields no subdomains");
    }


    #[tokio::test]
    async fn fetch_unions_wildcard_and_apex_query_results() {
        let server = wiremock::MockServer::start().await;

        // Wildcard query returns the apex only (no concrete subdomains).
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/"))
            .and(wiremock::matchers::query_param("q", "%.example.com"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(r#"[
                {"name_value": "example.com"}
            ]"#))
            .mount(&server)
            .await;

        // Apex query returns a cert that lists the apex plus a concrete subdomain.
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/"))
            .and(wiremock::matchers::query_param("q", "example.com"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(r#"[
                {"name_value": "example.com"},
                {"name_value": "api.example.com"}
            ]"#))
            .mount(&server)
            .await;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();

        let options = CtOptions {
            base_url: server.uri(),
            ..CtOptions::default()
        };
        let names = discover_subdomains_ct_with_options(&client, "example.com", options)
            .await
            .expect("union of wildcard + apex queries should succeed");
        assert_eq!(names, ["api.example.com"]);
    }
    #[tokio::test]
    async fn retries_html_gateway_error_then_succeeds() {
        let server = MockServer::start().await;
        let body = sample_body();
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_clone = Arc::clone(&attempts);

        let responder = move |_: &wiremock::Request| {
            let n = attempts_clone.fetch_add(1, Ordering::SeqCst);
            if n < 2 {
                ResponseTemplate::new(200)
                    .set_body_string("<html><head><title>504 Gateway Time-out</title></head></html>")
            } else {
                ResponseTemplate::new(200).set_body_string(body.clone())
            }
        };

        Mock::given(method("GET")).and(path("/")).respond_with(responder).mount(&server).await;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let url = format!("{}?q=%25.example.com&output=json", server.uri());
        let names = discover_subdomains_ct_with_url(&client, &url, "example.com", &CtOptions::default())
            .await
            .expect("should retry HTML gateway 200 response and succeed");
        assert_eq!(names, vec!["api.example.com"]);
        assert!(attempts.load(Ordering::SeqCst) >= 3, "expected at least 3 attempts");
    }

    #[tokio::test]
    async fn discover_subdomains_ct_empty_domain_short_circuits() {
        let client = reqwest::Client::new();
        let options = CtOptions::default();
        let res = discover_subdomains_ct_with_options(&client, "  *.  ", options).await.unwrap();
        assert!(res.is_empty(), "empty or wildcard-only domain should short-circuit to empty list");
    }

    #[tokio::test]
    async fn fetch_resilient_to_partial_query_failure() {
        let server = MockServer::start().await;

        // Wildcard query succeeds with api.example.com
        Mock::given(method("GET"))
            .and(path("/"))
            .and(query_param("q", "%.example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"[
                {"name_value": "api.example.com"}
            ]"#))
            .mount(&server)
            .await;

        // Apex query fails with 502
        Mock::given(method("GET"))
            .and(path("/"))
            .and(query_param("q", "example.com"))
            .respond_with(ResponseTemplate::new(502))
            .mount(&server)
            .await;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();

        let options = CtOptions {
            base_url: server.uri(),
            ..CtOptions::default()
        };

        let names = discover_subdomains_ct_with_options(&client, "example.com", options)
            .await
            .expect("should succeed with wildcard results even if apex query fails");
        assert_eq!(names, ["api.example.com"]);
    }

}