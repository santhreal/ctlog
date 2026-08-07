# Changelog

All notable changes to `santh-ctlog` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.4] - 2026-08-07

### Fixed
- Multi-label wildcard/dot input cleaning: `clean_domain` iteratively strips multiple leading `*.` prefixes and leading/trailing dots (e.g. `*.*.example.com..` -> `example.com`).
- SAN normalization hardening: `normalized_names` iteratively strips all leading `*.` prefixes and surrounding dots, drops empty/dot-only strings (`..`, `.`), filters consecutive interior dots (`..`), handles empty/whitespace bodies, and drops hostnames with invalid characters/schemes (`http://`, `user@`, `:port`, `/path`).
- HTML 200 OK gateway timeout retry: Catch HTML error responses from crt.sh/proxies (body starting with `<`) in `try_query` and convert them to `CtError::BadStatus(SERVICE_UNAVAILABLE)` so the fetch retry loop executes instead of failing on JSON parse.
- Empty domain short-circuit: `discover_subdomains_ct_with_options` returns an empty host vector immediately if `clean_domain(domain)` is empty, avoiding wasted queries `q=%.` and `q=`.
- Partial query resilience: `discover_subdomains_ct_with_options` now succeeds and logs a warning if one query (wildcard or apex) succeeds while the other fails with a non-fatal error, returning discovered subdomains instead of failing completely.
- Updated Cargo.toml author metadata strictly to `Santh <64453045+santhreal@users.noreply.github.com>`.
## [0.1.3] - 2026-08-07

### Fixed
- Domain input sanitization: `crtsh_query_url`, `crtsh_apex_query_url`, and `parse_crtsh_subdomains` now clean input domains by stripping leading `*.`, leading/trailing dots, and surrounding whitespace. This fixes wildcard query formation (preventing `q=%.%2A.example.com`) and ensures apex subdomains are properly excluded when wildcard domain strings like `*.example.com` are passed.
- SAN normalization: Trailing dots are now stripped from certificate SAN entries during normalization.

### Added
- Comprehensive `SPEC.md` detailing the pure parse, fetch hardening, normalization contract, and error guarantees.
- `package.metadata.santh.status = "beta"` declaration in `Cargo.toml`.
- Repository/homepage metadata pointed at `santhreal/ctlog`.

## [0.1.2] - 2026-07-31

### Changed
- Refactored `normalized_names` to use a zero-intermediate-allocation nested loop, removing throwaway per-entry `Vec` allocations in hot parse loops.

### Fixed
- UTF-8 validation: Replaced lossy UTF-8 decoding with strict `String::from_utf8`, returning `CtError::Parse` on invalid bytes instead of introducing `U+FFFD` into hostname outputs.
- Build coherence: Fixed default feature compilation when test suite is built without `--features fetch`.

## [0.1.1] - 2026-07-14

### Added
- `CtOptions` struct allowing custom `max_response_bytes` and `base_url` for mirror/mock testing and tunable size caps.
- Apex query union in `discover_subdomains_ct_with_options`: issues both wildcard (`%.domain`) and apex (`domain`) queries and unions results to catch subdomains on apex-only certificates.
- Retries with linear backoff for transient HTTP `5xx`, `429`, and transport failures in `discover_subdomains_ct_with`.
- `crtsh_apex_query_url` helper in pure parse layer.

### Fixed
- Wiremock coverage added for 32 MiB response cap abort (`CtError::ResponseTooLarge`).

## [0.1.0] - 2026-05-20

### Added
- Initial release of `santh-ctlog`: canonical Certificate Transparency client and name-extraction parser for Santh scanners.
