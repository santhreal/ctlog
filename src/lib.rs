//! # ctlog - canonical Certificate Transparency (crt.sh) client
//!
//! Single source of truth for *"query a Certificate Transparency log for
//! every name ever certified under a domain, and turn the response into a
//! clean, deduplicated host list"* across the Santh fleet.
//!
//! Before this crate existed, the crt.sh query+parse was reimplemented in
//! at least five places with divergent behavior:
//!
//! - `wafrift_recon` - bounded chunked read, 30s timeout, typed errors,
//!   case-normalized, sorted+deduped. The most defensive copy.
//! - `gossan` subdomain `ct` source and `origin` `ssl_cert` scanner -
//!   bounded read via their own helpers, `*.` stripped, lowercased.
//! - `scald` subdomain discovery - retry/backoff, URL expansion.
//! - `karyx` origin-discovery `certificate` - **unbounded** `Response::json`
//!   (OOM on a hostile mirror), **no wildcard** in the query URL (so it
//!   only saw apex certs and missed every subdomain), and **no case
//!   normalization** (a mixed-case base domain leaked into results).
//!
//! Folding them onto this crate removes the duplication and fixes karyx's
//! three latent bugs in one move. The crate is split into two layers so
//! consumers that already own a transport stack don't pay for one they
//! won't use:
//!
//! - **Pure layer** ([`crtsh_query_url`], [`parse_crtsh_hostnames`],
//!   [`parse_crtsh_subdomains`], [`CrtShEntry`]) - JSON + a defensive URL
//!   encoder, no async/HTTP. Consumed by gossan (its `ScanClient` +
//!   governor rate-limiter) and scald (its retry/backoff client), which
//!   feed an already-fetched body in.
//! - **Fetch layer** ([`discover_subdomains_ct`],
//!   [`discover_subdomains_ct_with`], behind the `fetch` feature) - the
//!   chunk-bounded, timeout-guarded read wafrift hardened. Consumed by
//!   wafrift and karyx, which have no bespoke crt.sh transport.
//!
//! ## Normalization contract
//!
//! [`parse_crtsh_hostnames`] / [`parse_crtsh_subdomains`] apply the union
//! of every consumer's normalization, which is also the most complete:
//!
//! 1. Split each `name_value` on `\n` (crt.sh packs the full SAN set of a
//!    cert into one newline-joined field).
//! 2. Trim surrounding whitespace.
//! 3. Strip a leading wildcard label `*.` so `*.api.example.com` still
//!    yields the concrete `api.example.com` host - a real subdomain the
//!    drop-the-whole-entry copies (wafrift, scald, karyx) silently lost.
//! 4. Lowercase (ASCII) so a mixed-case apex compares equal to the
//!    queried domain and doesn't leak into a subdomain list.
//! 5. Drop empty strings and anything still containing `*`.
//! 6. Sort and deduplicate.
//!
//! ## Safe defaults
//!
//! - **Input size (parse):** bounded by the caller - the parse functions
//!   take an in-memory `&str` the caller already size-limited. The fetch
//!   layer enforces [`CT_RESPONSE_MAX_BYTES`] itself.
//! - **Outbound network:** none in the pure layer; the fetch layer makes
//!   exactly one GET to crt.sh under [`CT_QUERY_TIMEOUT`].
//! - **Process spawning / filesystem writes / credential exposure:** none.

#![warn(missing_docs)]
#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::todo,
        clippy::unimplemented,
        clippy::panic
    )
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_errors_doc
)]

use serde::{Deserialize, Serialize};

/// One row of a crt.sh `output=json` response.
///
/// crt.sh returns far more fields (issuer, serial, `not_before`, …); only
/// `name_value` - the newline-joined CN+SAN set - is load-bearing for name
/// discovery, and unknown fields are ignored by serde, so this stays
/// deliberately minimal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrtShEntry {
    /// Newline-separated common-name + subject-alternative-name set.
    pub name_value: String,
}

/// Errors returned by the `ctlog` parse and fetch layers.
#[derive(Debug, thiserror::Error)]
pub enum CtError {
    /// The crt.sh body was not the expected `Vec<CrtShEntry>` JSON shape.
    #[error("failed to parse crt.sh response: {0}")]
    Parse(#[from] serde_json::Error),

    /// The outbound crt.sh request failed at the transport layer (DNS,
    /// TCP, TLS, or the [`CT_QUERY_TIMEOUT`] elapsed).
    #[cfg(feature = "fetch")]
    #[error("crt.sh request failed: {0}")]
    Transport(#[from] reqwest::Error),

    /// crt.sh answered with a non-success status (502 when overloaded,
    /// 403 when rate-limiting the caller's IP are the common ones).
    #[cfg(feature = "fetch")]
    #[error("crt.sh returned status {0}")]
    BadStatus(reqwest::StatusCode),

    /// The streamed response exceeded [`CT_RESPONSE_MAX_BYTES`]; buffering
    /// was aborted rather than letting a hostile/runaway mirror OOM the
    /// scanner.
    #[cfg(feature = "fetch")]
    #[error("crt.sh response exceeded {limit} byte cap (got {got}+ bytes) - refusing to buffer")]
    ResponseTooLarge {
        /// The configured byte cap.
        limit: usize,
        /// The size reached when the cap was tripped.
        got: usize,
    },
}

/// Build the canonical crt.sh JSON query URL for `domain`.
///
/// Uses the SQL-`LIKE` wildcard prefix `%.` so the query returns every
/// name certified *under* the domain, not just apex certs - the missing
/// wildcard was the bug that made karyx's origin discovery blind to
/// subdomains. The domain itself is percent-encoded so a hostile or
/// malformed target (spaces, `&`, `#`) can't break out of the query
/// component.
///
/// ```
/// assert_eq!(
///     ctlog::crtsh_query_url("Example.com"),
///     "https://crt.sh/?q=%.Example.com&output=json",
/// );
/// ```
pub fn crtsh_query_url(domain: &str) -> String {
    format!(
        "https://crt.sh/?q=%.{}&output=json",
        urlencoding::encode(domain.trim())
    )
}

/// Build a crt.sh query URL that matches certificates for the apex `domain`.
///
/// This is the companion to [`crtsh_query_url`]; an apex-only certificate
/// that never lists a wildcard or subdomain SAN is missed by the `%.` query,
/// but its subdomains (if any) still appear here. The two result sets are
/// unioned by the fetch layer.
///
/// ```
/// assert_eq!(
///     ctlog::crtsh_apex_query_url("Example.com"),
///     "https://crt.sh/?q=Example.com&output=json",
/// );
/// ```
pub fn crtsh_apex_query_url(domain: &str) -> String {
    format!(
        "https://crt.sh/?q={}&output=json",
        urlencoding::encode(domain.trim())
    )
}

/// Parse a crt.sh `output=json` body into the full set of normalized
/// host names, *including* the queried apex.
///
/// Applies the [normalization contract](crate#normalization-contract).
/// Use this for origin discovery, where the apex resolving to a non-CDN
/// address is itself a candidate worth probing.
///
/// ```
/// let body = r#"[
///     {"name_value": "*.api.example.com\nexample.com"},
///     {"name_value": "WWW.example.com"}
/// ]"#;
/// let names = ctlog::parse_crtsh_hostnames(body).unwrap();
/// assert_eq!(names, ["api.example.com", "example.com", "www.example.com"]);
/// ```
pub fn parse_crtsh_hostnames(body: &str) -> Result<Vec<String>, CtError> {
    normalized_names(body)
}

/// Parse a crt.sh `output=json` body into normalized *subdomains*,
/// excluding the queried `domain` itself.
///
/// Applies the [normalization contract](crate#normalization-contract)
/// then drops the apex. Use this for subdomain enumeration, where the
/// queried domain is already known and only newly discovered names
/// matter.
///
/// ```
/// let body = r#"[
///     {"name_value": "api.example.com\n*.example.com"},
///     {"name_value": "Example.COM"}
/// ]"#;
/// // The apex (in any case) and the apex-wildcard are both excluded.
/// let subs = ctlog::parse_crtsh_subdomains(body, "example.com").unwrap();
/// assert_eq!(subs, ["api.example.com"]);
/// ```
pub fn parse_crtsh_subdomains(body: &str, domain: &str) -> Result<Vec<String>, CtError> {
    let domain_lower = domain.trim().to_ascii_lowercase();
    let mut names = normalized_names(body)?;
    names.retain(|n| *n != domain_lower);
    Ok(names)
}

/// The shared normalization core behind both public parse functions.
fn normalized_names(body: &str) -> Result<Vec<String>, CtError> {
    let entries: Vec<CrtShEntry> = serde_json::from_str(body)?;

    // Push directly into the result. The previous `flat_map` collected each
    // entry's names into a throwaway `Vec<String>` before flattening (one heap
    // Vec per CT-log entry, of which a busy domain has thousands) (Law 7); a
    // plain nested loop keeps `e.name_value` alive across the inner iteration
    // without that intermediate allocation, and fuses the filter into the walk.
    let mut names: Vec<String> = Vec::new();
    for e in entries {
        for raw in e.name_value.split('\n') {
            let trimmed = raw.trim();
            // Strip a single leading wildcard label so the concrete host under
            // it survives; an entry that is *only* `*.` collapses to empty.
            let normalized = trimmed
                .strip_prefix("*.")
                .unwrap_or(trimmed)
                .to_ascii_lowercase();
            // Drop anything that can never be a DNS name: empties, residual
            // wildcards, and names with interior whitespace or control
            // characters. A hostile or misbehaving CT mirror can pack junk
            // (spaces, tabs, ANSI escapes) into `name_value`; without this
            // filter that junk flows into target lists downstream.
            if !normalized.is_empty()
                && !normalized.contains('*')
                && !normalized
                    .chars()
                    .any(|c| c.is_whitespace() || c.is_control())
            {
                names.push(normalized);
            }
        }
    }

    names.sort();
    names.dedup();
    Ok(names)
}

#[cfg(feature = "fetch")]
mod fetch_impl {
    use super::{parse_crtsh_subdomains, CtError};
    use serde::de::Error as _;
    use std::time::Duration;

    /// Timeout for outbound CT-log queries. crt.sh routinely takes
    /// 10-20s and occasionally hangs entirely; without a cap a discovery
    /// run would be a DoS-on-self for every blocked-up upstream.
    pub const CT_QUERY_TIMEOUT: Duration = Duration::from_secs(30);

    /// Hard cap on crt.sh response body size. A real CT-log JSON for a
    /// busy domain is a few MB at most; an adversarial / misbehaving
    /// mirror that streams multi-GB nonsense would otherwise OOM the
    /// scanner before the JSON parser ever ran.
    pub const CT_RESPONSE_MAX_BYTES: usize = 32 * 1024 * 1024; // 32 MiB

    /// Maximum retry attempts for the fetch layer. crt.sh commonly returns
    /// 502 when overloaded; a single transient failure should not kill a
    /// discovery run.
    pub const CT_MAX_RETRIES: u32 = 3;

    /// Base backoff between retries. Grows linearly with the attempt.
    pub const CT_RETRY_BACKOFF: Duration = Duration::from_millis(500);

    /// Tunable options for the CT fetch layer.
    ///
    /// Callers that need a different endpoint, timeout (via the `reqwest`
    /// client), or byte cap can override the defaults here.
    #[derive(Debug, Clone)]
    pub struct CtOptions {
        /// Hard cap on the buffered crt.sh response body in bytes.
        ///
        /// Defaults to [`CT_RESPONSE_MAX_BYTES`] (32 MiB).
        pub max_response_bytes: usize,
        /// Base URL for crt.sh-style queries.
        ///
        /// Defaults to `https://crt.sh/` and must not include a trailing
        /// slash. Override this in tests that drive a local mock server.
        pub base_url: String,
    }

    // `CtOptions::default()` resolves through this trait impl (`Default` is
    // in the prelude); there is deliberately no inherent `default()` method,
    // which `clippy::should_implement_trait` flags as shadowing the trait.
    impl Default for CtOptions {
        fn default() -> Self {
            Self {
                max_response_bytes: CT_RESPONSE_MAX_BYTES,
                base_url: String::from("https://crt.sh"),
            }
        }
    }

    /// Query crt.sh for `domain` over a fresh default client and return
    /// the deduplicated subdomains.
    ///
    /// Convenience wrapper over [`discover_subdomains_ct_with`] for callers
    /// that have no client to share; it builds one with
    /// [`CT_QUERY_TIMEOUT`] applied.
    ///
    /// # Single-source risk
    ///
    /// The default endpoint is `https://crt.sh/`. If crt.sh is down or
    /// rate-limits the caller, there is no built-in fallback aggregator
    /// (certspotter, Censys, etc.). Use [`discover_subdomains_ct_with_options`]
    /// and point [`CtOptions::base_url`] at an alternate crt.sh-compatible
    /// mirror to distribute the dependency.
    pub async fn discover_subdomains_ct(domain: &str) -> Result<Vec<String>, CtError> {
        let client = reqwest::Client::builder()
            .timeout(CT_QUERY_TIMEOUT)
            .build()?;
        discover_subdomains_ct_with(&client, domain).await
    }

    /// Query crt.sh for `domain` reusing the caller's `client` (and its
    /// connection pool / proxy / UA config) and return the deduplicated
    /// subdomains.
    ///
    /// Retries transient failures (5xx, 429, transport errors) up to
    /// [`CT_MAX_RETRIES`] with a linear [`CT_RETRY_BACKOFF`]. The body is
    /// read chunk-by-chunk and aborted past [`CT_RESPONSE_MAX_BYTES`]
    /// rather than buffered whole, so a hostile mirror cannot OOM the
    /// caller regardless of its advertised `Content-Length`.
    ///
    /// See [`discover_subdomains_ct`] for the single-source risk note.
    pub async fn discover_subdomains_ct_with(
        client: &reqwest::Client,
        domain: &str,
    ) -> Result<Vec<String>, CtError> {
        discover_subdomains_ct_with_options(client, domain, CtOptions::default()).await
    }

    /// Query crt.sh for `domain` reusing the caller's `client` and tunable
    /// [`CtOptions`].
    ///
    /// Behaves like [`discover_subdomains_ct_with`] but lets the caller
    /// override the response size cap.
    pub async fn discover_subdomains_ct_with_options(
        client: &reqwest::Client,
        domain: &str,
        options: CtOptions,
    ) -> Result<Vec<String>, CtError> {
        let base = options.base_url.trim_end_matches('/');
        let encoded = urlencoding::encode(domain.trim());
        let wildcard_url = format!("{base}/?q=%.{encoded}&output=json");
        let apex_url = format!("{base}/?q={encoded}&output=json");

        let mut names = discover_subdomains_ct_with_url(client, &wildcard_url, domain, &options).await?;
        let mut apex_names = discover_subdomains_ct_with_url(client, &apex_url, domain, &options).await?;
        names.append(&mut apex_names);
        names.sort_unstable();
        names.dedup();
        Ok(names)
    }

    /// Internal test seam: query an explicit `url` so `fetch` tests can
    /// drive a local `wiremock` server rather than the real `crt.sh` endpoint.
    pub(crate) async fn discover_subdomains_ct_with_url(
        client: &reqwest::Client,
        url: &str,
        domain: &str,
        options: &CtOptions,
    ) -> Result<Vec<String>, CtError> {
        tracing::debug!(domain, "querying crt.sh for CT logs");

        let mut last_err: Option<CtError> = None;
        for attempt in 0..CT_MAX_RETRIES {
            if attempt > 0 {
                let delay = CT_RETRY_BACKOFF * attempt;
                tracing::warn!(attempt, domain, "crt.sh query retry after {delay:?}");
                tokio::time::sleep(delay).await;
            }

            match try_query(client, url, domain, options).await {
                Ok(names) => return Ok(names),
                Err(e) if is_retryable(&e) => {
                    tracing::warn!(attempt, error = %e, "crt.sh query failed; will retry if attempts remain");
                    last_err = Some(e);
                }
                Err(e) => return Err(e),
            }
        }

        Err(last_err.unwrap_or_else(|| CtError::BadStatus(reqwest::StatusCode::SERVICE_UNAVAILABLE)))
    }

    async fn try_query(
        client: &reqwest::Client,
        url: &str,
        domain: &str,
        options: &CtOptions,
    ) -> Result<Vec<String>, CtError> {
        let max_response_bytes = options.max_response_bytes;
        let mut res = client.get(url).send().await?;
        if !res.status().is_success() {
            return Err(CtError::BadStatus(res.status()));
        }

        let mut body = Vec::with_capacity(64 * 1024);
        while let Some(chunk) = res.chunk().await? {
            if body.len() + chunk.len() > max_response_bytes {
                return Err(CtError::ResponseTooLarge {
                    limit: max_response_bytes,
                    got: body.len() + chunk.len(),
                });
            }
            body.extend_from_slice(&chunk);
        }

        // crt.sh emits UTF-8 JSON. A stray invalid byte is not silently
        // lossy-replaced (which could create bogus hostnames with U+FFFD);
        // instead it becomes a parse error so the caller knows the response
        // was corrupted.
        let text = String::from_utf8(body).map_err(|e| {
            CtError::Parse(serde_json::Error::custom(format!(
                "CT response contained invalid UTF-8: {e}"
            )))
        })?;
        let names = parse_crtsh_subdomains(&text, domain)?;
        tracing::debug!(found = names.len(), "discovered subdomains via CT logs");
        Ok(names)
    }

    pub(crate) fn is_retryable(err: &CtError) -> bool {
        match err {
            CtError::Transport(_) => true,
            CtError::BadStatus(status) => {
                status.is_server_error() || *status == reqwest::StatusCode::TOO_MANY_REQUESTS
            }
            _ => false,
        }
    }
}

#[cfg(feature = "fetch")]
pub use fetch_impl::{
    discover_subdomains_ct, discover_subdomains_ct_with, discover_subdomains_ct_with_options,
    CtOptions, CT_MAX_RETRIES, CT_QUERY_TIMEOUT, CT_RESPONSE_MAX_BYTES, CT_RETRY_BACKOFF,
};
// Only the feature-gated `fetch_tests` module uses this, so it must be gated on
// `feature = "fetch"` too - otherwise `cargo test` (default features) fails to
// compile with `unresolved import fetch_impl` (the module only exists under the
// `fetch` feature).
#[cfg(all(test, feature = "fetch"))]
pub(crate) use fetch_impl::discover_subdomains_ct_with_url;

#[cfg(test)]
mod tests;
