# Design: Migrate KAS client to ConnectRPC with well-known discovery

**Status:** Draft for review
**Date:** 2026-05-28
**Tracking issue:** [#85](https://github.com/arkavo-org/opentdf-rs/issues/85)
**Related:** [#46](https://github.com/arkavo-org/opentdf-rs/issues/46) (OIDC auth), [#43](https://github.com/arkavo-org/opentdf-rs/issues/43) (WASM ZTDF decrypt)

## Motivation

The opentdf-platform Go server serves KAS over ConnectRPC at `/kas.AccessService/{Rewrap,PublicKey}`. Issue #85 states the platform "no longer ships" the legacy `/kas/v2/*` REST gateway, though `platform.arkavo.net` currently exposes both surfaces. The Rust client (`src/kas.rs`, `src/kas_key.rs`) is REST-only today and will fail against any deployment that drops the gateway.

The platform's `/.well-known/opentdf-configuration` endpoint advertises both transports side by side:

```json
"kas": {
  "algorithms": ["ec:secp256r1", "rsa:2048"],
  "connect_public_key_url": "https://platform.arkavo.net/kas.AccessService/PublicKey",
  "connect_rewrap_url":     "https://platform.arkavo.net/kas.AccessService/Rewrap",
  "public_key_url":         "https://platform.arkavo.net/kas/v2/kas_public_key",
  "rewrap_url":             "https://platform.arkavo.net/kas/v2/rewrap",
  "uri":                    "https://platform.arkavo.net"
}
```

This lets the client prefer Connect when advertised and fall back to REST otherwise — backward-compat answered by the server, not by client feature flags.

## Scope (first cut)

- **In:** Native (`src/kas.rs`, `src/kas_key.rs`) ConnectRPC transport + well-known discovery + CWT-as-bearer support (server-side validation will fail until platform CWT lands; acceptable).
- **Out:** WASM mirror (`crates/wasm/src/kas.rs`), client-side CWT signing/verification, OIDC auth provider, removal of legacy REST mock routes.

The CWT-bearer aspect of the work is intentionally minimal on the client side: `oauth_token` is an opaque passthrough string. The caller decides whether they're providing a JWT or a base64url-encoded CWT. The Rust client puts whatever they pass after `Authorization: Bearer ` and lets the server validate. Expected end state on `platform.arkavo.net`: rewrap returns HTTP 401 with a Connect `unauthenticated` error envelope. That confirms transport plumbing is correct.

## Non-goals

- Switching to Connect's binary `application/proto` codec. JSON envelope wins on debuggability and zero new dependencies; size savings (~25% on response wrapped-key bytes only) are sub-MTU on a latency-bound path.
- Code-gen via `prost`/`tonic`/`connect-codegen`. Two unary RPCs don't justify the dep weight.
- Caching the well-known response between `KasClient` instances. Callers cache `OpentdfConfiguration` themselves if they want; the discovery function is one HTTP GET and the result is plain data.

## Architecture

New module: `src/kas_discovery.rs`. Owns:

- `OpentdfConfiguration` — deserializes the well-known JSON shape.
- `KasConfig`, `IdpConfig` — sub-structs (`IdpConfig` deserialized but unused; reserved for #46).
- `KasEndpoints` — resolved URLs after applying the Connect-preferred / REST-fallback rule, plus a `KasTransport` enum for logging.
- `fetch_well_known(platform_url, &http_client)` — async, one GET request.
- `OpentdfConfiguration::for_kas_connect(base_url)` — synthesize a config from a KAS base URL using Connect paths.
- `OpentdfConfiguration::for_kas_legacy_rest(base_url)` — escape hatch for pre-Connect deployments.

`src/kas.rs` changes:

- `KasClient` struct: new `endpoints: KasEndpoints` field replaces internal use of `base_url` for URL construction. `base_url` retained for backwards-compat field access.
- `KasClient::new(config: &OpentdfConfiguration, oauth_token)` — synchronous; reads URLs from the resolved endpoints, applies existing HTTPS/SSRF validation to those URLs, generates RSA-2048 signing key as before. **Breaking change** from current `new(base_url, oauth_token)`.
- `send_rewrap_request` — POSTs to `endpoints.rewrap_url` instead of `format!("{}/kas/v2/rewrap", base_url)`. Adds Connect error envelope parsing.

`src/kas_key.rs` changes:

- New `fetch_kas_public_key_connect(public_key_url, &http_client)` — POSTs to a pre-resolved URL with empty JSON body `{}`. No path mangling (the URL is already resolved by discovery or builder).
- New `fetch_kas_ec_public_key_connect` mirror.
- Existing `fetch_kas_public_key` / `fetch_kas_ec_public_key` marked `#[deprecated]` with a hint to use the Connect variants.

## API surface

```rust
// src/kas_discovery.rs

#[derive(Debug, Clone, Deserialize)]
pub struct OpentdfConfiguration {
    pub kas: Option<KasConfig>,
    pub idp: Option<IdpConfig>,
    pub platform_issuer: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct KasConfig {
    pub uri: String,
    pub algorithms: Vec<String>,
    pub public_key_url: Option<String>,
    pub rewrap_url: Option<String>,
    pub connect_public_key_url: Option<String>,
    pub connect_rewrap_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IdpConfig {
    pub issuer: String,
    pub jwks_uri: Option<String>,
    pub cose_keys_uri: Option<String>,
    pub token_endpoint: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub userinfo_endpoint: Option<String>,
    pub access_token_format: Option<String>,
    pub id_token_signing_alg_values_supported: Option<Vec<String>>,
    pub response_types_supported: Option<Vec<String>>,
    pub subject_types_supported: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KasTransport { Connect, LegacyRest }

#[derive(Debug, Clone)]
pub struct KasEndpoints {
    pub rewrap_url: String,
    pub public_key_url: String,
    pub transport: KasTransport,
}

impl OpentdfConfiguration {
    pub fn for_kas_connect(base_url: impl Into<String>) -> Self;
    pub fn for_kas_legacy_rest(base_url: impl Into<String>) -> Self;
}

impl KasEndpoints {
    pub fn from_config(cfg: &OpentdfConfiguration) -> Result<Self, KasError>;
}

pub async fn fetch_well_known(
    platform_url: &str,
    http_client: &reqwest::Client,
) -> Result<OpentdfConfiguration, KasError>;
```

```rust
// src/kas.rs

impl KasClient {
    pub fn new(
        config: &OpentdfConfiguration,
        oauth_token: impl Into<String>,
    ) -> Result<Self, KasError>;
}
```

```rust
// src/kas_key.rs

pub async fn fetch_kas_public_key_connect(
    public_key_url: &str,
    http_client: &reqwest::Client,
) -> Result<KasPublicKeyResponse, KasKeyError>;

pub async fn fetch_kas_ec_public_key_connect(
    public_key_url: &str,
    http_client: &reqwest::Client,
) -> Result<KasEcPublicKeyResponse, KasKeyError>;
```

## Caller patterns

```rust
// Production: discover, then construct
let http = reqwest::Client::new();
let cfg = fetch_well_known("https://platform.arkavo.net", &http).await?;
let kas = KasClient::new(&cfg, bearer_token)?;

// Connect, no discovery
let cfg = OpentdfConfiguration::for_kas_connect("https://kas.example.com");
let kas = KasClient::new(&cfg, bearer_token)?;

// REST escape hatch
let cfg = OpentdfConfiguration::for_kas_legacy_rest("https://kas.example.com");
let kas = KasClient::new(&cfg, bearer_token)?;
```

## Data flow

### Construction (discovery path)
1. Caller constructs `reqwest::Client`.
2. `fetch_well_known(platform_url, &http)` → GET `/.well-known/opentdf-configuration` → `OpentdfConfiguration`.
3. `KasClient::new(&cfg, token)`:
   - `KasEndpoints::from_config(&cfg)` resolves URLs: prefer `connect_*_url`, fall back to `*_url`. Error if both absent.
   - Apply existing HTTPS / SSRF / scheme validation to resolved URLs.
   - Generate ephemeral RSA-2048 signing key (unchanged).

### Rewrap (Standard TDF)
1. Generate ephemeral RSA-2048 keypair (unchanged).
2. Build `UnsignedRewrapRequest` from manifest (unchanged).
3. Sign with internal signing key → `signed_request_token` (RS256 JWT, unchanged). **This is the rewrap-request signature, not the access token.**
4. POST `endpoints.rewrap_url`:
   - `content-type: application/json`
   - `authorization: Bearer {oauth_token}` (opaque passthrough — JWT or base64url-CBOR CWT)
   - body: `{"signed_request_token": "..."}` (Connect proto JSON, unchanged shape)
5. Handle response:
   - 401 → `KasError::AuthenticationFailed { reason }` (reason includes Connect `code: message` when parseable)
   - 403 → `KasError::AccessDenied`
   - Other 4xx/5xx → `KasError::HttpError`
   - 200 with empty `responses` and parseable Connect error → `KasError::HttpError` (defensive)
   - 200 → parse `RewrapResponse` (unchanged shape).
6. Extract wrapped key, unwrap via RSA-OAEP (unchanged).

### PublicKey fetch
1. POST `endpoints.public_key_url`:
   - `content-type: application/json`
   - body: `{}` (Connect requires a JSON body even for empty request types)
2. 200 → parse `KasPublicKeyResponse` (struct already uses `#[serde(rename = "publicKey")]`, matches Connect's protojson camelCase).
3. Non-200 → `KasKeyError::HttpError` with parsed Connect detail when available.

## Bearer encoding rationale

`Authorization: Bearer <base64url(CWT_bytes)>`:

- **Standards-conformant:** RFC 6750 requires bearer tokens to be visible ASCII, so raw CBOR cannot go directly in the header. Base64url is the same encoding JWT uses (compact serialization) and matches the platform's own `examples/pep_check.rs` convention (commit `85b8b05`), which decodes access tokens as base64url with optional CWT tag #61 strip.
- **Performant:** Base64url is byte-shifting (sub-microsecond); the ~33% size inflation on a ~300-byte CWT puts the header well under any reasonable limit and dwarfs nothing in the TLS-handshake-dominated request lifecycle.
- **JWT/CWT distinguishable server-side without protocol changes:** CBOR bytes have distinct leading bytes from `eyJ...` (JWT). The server inspects.

## Error mapping

Connect unary-JSON returns errors with shape:
```json
{ "code": "unauthenticated", "message": "missing bearer token" }
```

Implementation: small helper struct + parser. Map Connect-status codes to existing `KasError` variants via the HTTP status code (Connect spec defines the mapping — `unauthenticated` → 401, `permission_denied` → 403, etc.). Surface the Connect `code: message` as the `reason` field of the resulting `KasError` variant. **No new `KasError` variants required.**

## Testing strategy

### Unit tests

- `kas_discovery::tests`:
  - `from_config_picks_connect_when_present`
  - `from_config_falls_back_to_rest_when_connect_absent`
  - `from_config_errors_when_neither_present`
  - `for_kas_connect_constructs_expected_urls` (`https://kas.example.com` → `/kas.AccessService/{Rewrap,PublicKey}`)
  - `for_kas_legacy_rest_constructs_expected_urls`
  - `parse_connect_error_with_valid_body` / `parse_connect_error_with_garbage`

- `kas_discovery::tests` for `fetch_well_known` (mockito):
  - Happy path returns platform's JSON shape.
  - 404 → `KasError::HttpError`.
  - Garbled JSON → parse error.

- `kas::tests::url_validation_tests`: existing SSRF / HTTPS coverage adapted to new constructor signature.

### Mock-server tests (`tests/kas_mock.rs`)

- Update all six mock routes from `/kas/v2/rewrap` to `/kas.AccessService/Rewrap`.
- New test for Connect 401 envelope: mock returns 401 with `{"code":"unauthenticated","message":"bad token"}`, assert `KasError::AuthenticationFailed { reason }` contains `"unauthenticated"`.
- New test for the Connect public-key fetch via mock POST to `/kas.AccessService/PublicKey`.

### Live integration tests (`tests/platform_integration.rs`, `#[ignore]`)

Gated by `KAS_INTEGRATION_TESTS=1`:

- `well_known_endpoint_returns_kas_config` — fetch against `platform.arkavo.net`, assert kas block has both Connect and REST URLs.
- `connect_public_key_returns_pem` — fetch via Connect transport, assert valid PEM.
- `connect_rewrap_fails_with_jwt_bearer_returns_401` — expected-failure test: attempt rewrap with a fake JWT bearer, assert HTTP 401 with Connect `unauthenticated` code in reason. **Validates transport works end-to-end.**
- `connect_rewrap_with_cwt_bearer_also_returns_401_for_now` — companion test documenting intended end state; also expected to fail until platform-side CWT validation lands.

### Examples

- `examples/kas_sanity_test.rs`: hardcoded REST URL → discovery or `for_kas_connect`.
- `examples/create_tdf_platform.rs`, `examples/cross_sdk_test.rs`, `examples/xtest_cli.rs`: two-line constructor migration each.
- `examples/mock_kas_server.rs`: add Connect routes (`/kas.AccessService/Rewrap`, `/kas.AccessService/PublicKey`) alongside existing REST routes — multi-profile mock.

## Migration impact

**Breaking change:** `KasClient::new(base_url, token)` → `KasClient::new(&config, token)`. Justifies a `0.12.x` → `0.13.0` minor bump (pre-1.0).

All in-repo callers (examples, tests) migrate in this same PR. Two-line change per site:

```rust
// before
let kas = KasClient::new("https://kas.example.com", token)?;

// after
let cfg = OpentdfConfiguration::for_kas_connect("https://kas.example.com");
let kas = KasClient::new(&cfg, token)?;
```

CHANGELOG entry calls this out and points downstream consumers at the same one-liner.

## Acceptance criteria

- `KasClient::rewrap_*` and `fetch_kas_*public_key_connect` use the resolved Connect URLs against a platform that advertises them.
- `cargo test --all-features` passes with mocks updated to Connect routes.
- Connect error envelope (`{code, message}`) parsed into `KasError` reason strings; mock 401 test passes.
- `cargo test --all-features --ignored` against `KAS_INTEGRATION_TESTS=1`:
  - well-known fetch succeeds against `platform.arkavo.net`.
  - Connect `PublicKey` fetch succeeds.
  - Connect `Rewrap` returns HTTP 401 with Connect `unauthenticated` in the reason (expected failure, documents next blocker).
- `cargo clippy --all-targets --all-features -- -D warnings` clean.
- `cargo fmt --all --check` clean.
- `RUSTFLAGS="-D warnings" cargo build --all-features` clean.
- All examples compile; `kas_sanity_test.rs` runs against the new transport (or is updated to be skipped without the env var, matching existing convention).
- README + module-level doc-comments updated to reference Connect endpoints and well-known discovery.

## Open follow-ups (not this PR)

- **#43 / WASM mirror:** apply the same transport switch to `crates/wasm/src/kas.rs` using `web_sys::Fetch`. Re-use `KasEndpoints` and `OpentdfConfiguration` from the protocol crate or a wasm-compatible discovery module.
- **#46 / OIDC auth:** consume the `idp` block from `OpentdfConfiguration` to wire token acquisition. The deserialized `IdpConfig` is already in place for this.
- **CWT client-side:** add CWT verification helpers (COSE_Sign1 over ES256 + COSE Key Set fetch from `cose_keys_uri`) once the platform validates CWT bearers on KAS.
- **Remove legacy REST routes** from `examples/mock_kas_server.rs` once no in-repo example targets them.
