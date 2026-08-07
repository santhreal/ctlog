# santh-ctlog - Technical Specification

`santh-ctlog` (lib name `ctlog`) is the canonical Certificate Transparency (crt.sh) query client and name-extraction parser for the Santh scanner fleet.

## Status

`package.metadata.santh.status = "beta"`

## Architecture

The crate is structured into two decoupled layers:

1. **Pure Parse & URL Layer** (`default` feature, no async/HTTP dependencies):
   - `crtsh_query_url(domain: &str) -> String`: Builds the canonical crt.sh query URL (`q=%.domain&output=json`).
   - `crtsh_apex_query_url(domain: &str) -> String`: Builds the apex-matching query URL (`q=domain&output=json`).
   - `parse_crtsh_hostnames(body: &str) -> Result<Vec<String>, CtError>`: Parses a crt.sh JSON body into deduplicated hostnames, including the apex.
   - `parse_crtsh_subdomains(body: &str, domain: &str) -> Result<Vec<String>, CtError>`: Parses a crt.sh JSON body into deduplicated subdomains, excluding the queried domain apex.
   - `CrtShEntry`: Minimally serde-deserializable representation of crt.sh JSON rows (`name_value`).

2. **Fetch Layer** (`fetch` feature, requires `reqwest`, `tokio`, `tracing`):
   - `discover_subdomains_ct(domain: &str) -> Result<Vec<String>, CtError>`: Bounded, timeout-guarded query over default reqwest client.
   - `discover_subdomains_ct_with(client: &reqwest::Client, domain: &str) -> Result<Vec<String>, CtError>`: Reuses caller client configuration.
   - `discover_subdomains_ct_with_options(client: &reqwest::Client, domain: &str, options: CtOptions) -> Result<Vec<String>, CtError>`: Tunable endpoint, response size cap, and retry execution.

## Invariants & Contracts

### Input Domain Sanitization
Before URL formatting or subdomain exclusion filtering, the target domain is sanitized (`clean_domain`):
- Leading/trailing whitespace is trimmed.
- Leading `*.` or `.` is stripped.
- Trailing `.` is stripped.

### Normalization Pipeline
All raw SAN values returned in `name_value` (newline-separated) undergo strict normalization:
1. Split on `\n`.
2. Trim whitespace.
3. Strip leading `*.` wildcard label (preserving the concrete host).
4. Strip trailing dot (`.`).
5. Convert ASCII to lowercase.
6. Filter out empty strings, residual wildcard characters (`*`), and strings with interior whitespace or control characters.
7. Sort and deduplicate.

### Fetch Hardening & Resource Protection
- **Chunk-bounded buffering**: Responses are read chunk-by-chunk and aborted if the accumulated body exceeds `CtOptions::max_response_bytes` (default `CT_RESPONSE_MAX_BYTES` = 32 MiB). Returns `CtError::ResponseTooLarge`.
- **Query timeout**: Default `CT_QUERY_TIMEOUT` is 30 seconds.
- **Retry behavior**: Up to `CT_MAX_RETRIES` (3 attempts) with linear `CT_RETRY_BACKOFF` (500ms) on transient failures (`5xx`, `429`, or transport errors).
- **Dual Query Union**: Subdomain discovery queries both `%.domain` (wildcard prefix) and `domain` (apex identity) to capture subdomains listed on apex-only certs.
- **Strict UTF-8**: Invalid UTF-8 body bytes trigger a `CtError::Parse` error rather than lossy substitution.

## Error Handling

`CtError` represents all failure modes:
- `Parse(serde_json::Error)`: JSON deserialization failure or invalid UTF-8 payload.
- `Transport(reqwest::Error)`: Network layer, timeout, or TLS error.
- `BadStatus(reqwest::StatusCode)`: Non-2xx HTTP status from crt.sh.
- `ResponseTooLarge { limit, got }`: Response payload exceeded configured byte cap.
