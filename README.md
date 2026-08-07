# ctlog

Canonical Certificate Transparency (crt.sh) client and name-extraction
parser for the Santh scanner fleet, the single source of truth for
*"query a CT log for every name certified under a domain and turn the
response into a clean, deduplicated host list."*

It replaces five divergent in-tree copies (wafrift recon, gossan
subdomain + origin, scald subdomain, karyx origin-discovery) and fixes the
karyx copy's three latent bugs along the way: an unbounded response read
(OOM), a query URL with no wildcard (blind to subdomains), and no
case-normalization (apex leaking into subdomain results).

## Layers

- **Pure** (no features): `crtsh_query_url`, `parse_crtsh_hostnames`,
  `parse_crtsh_subdomains`, `CrtShEntry`. JSON + a defensive URL encoder,
  no async/HTTP. For consumers that own their transport (gossan's
  `ScanClient` + rate limiter, scald's retry/backoff client).
- **`fetch`**: `discover_subdomains_ct[_with]`: a chunk-bounded,
  timeout-guarded crt.sh read. For consumers without bespoke crt.sh
  transport (wafrift, karyx). `discover_subdomains_ct_with` reuses a
  caller-supplied `reqwest::Client` so its connection pool / proxy / UA
  config are honored.

```rust,no_run
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
// Pure parse over a body you already fetched + size-limited:
let body = r#"[{"name_value": "api.example.com\n*.example.com"}]"#;
let subs = ctlog::parse_crtsh_subdomains(body, "example.com")?;

// Or let the fetch layer do the bounded round-trip (feature = "fetch"):
#[cfg(feature = "fetch")]
let subs = ctlog::discover_subdomains_ct("example.com").await?;
# Ok(())
# }
```

## Normalization contract

Split `name_value` on `\n` → trim → strip a leading `*.` wildcard label
(so `*.api.example.com` yields `api.example.com`) → ASCII-lowercase → drop
empties and anything still containing `*` → sort → dedup.
`parse_crtsh_subdomains` additionally drops the queried apex;
`parse_crtsh_hostnames` keeps it (origin discovery resolves the apex too).

## Scope

CT-log name discovery only. IP classification belongs in
[`bogon`](../bogon); CDN/WAF edge-range filtering lives with its sole
consumer in `wafrift_recon::is_edge_ip`.
