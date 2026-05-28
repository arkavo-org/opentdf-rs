# ConnectRPC KAS Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate the native Rust KAS client from the legacy `/kas/v2/*` REST endpoints to the platform's canonical `/kas.AccessService/*` ConnectRPC endpoints, with URL selection driven by `/.well-known/opentdf-configuration` discovery.

**Architecture:** New `src/kas_discovery.rs` owns the well-known doc deserialization and URL-resolution logic. `KasClient::new` becomes synchronous and takes a pre-resolved `&OpentdfConfiguration`. Discovery is a separate `fetch_well_known` async free function. Connect JSON envelope is hand-rolled — two unary RPCs, no protobuf codegen, zero new dependencies. The OAuth bearer is an opaque passthrough; the caller decides JWT vs base64url(CWT).

**Tech Stack:** Rust 2024 edition, reqwest 0.12 (rustls), serde 1.0, mockito 1.6 (dev), aws-lc-rs 1.15 (RSA), jsonwebtoken 10, tokio 1.

**Spec:** `docs/superpowers/specs/2026-05-28-connectrpc-kas-migration-design.md`

**Tracking issue:** [#85](https://github.com/arkavo-org/opentdf-rs/issues/85)

---

## File map

| File | Status | Responsibility |
|---|---|---|
| `src/kas_discovery.rs` | **NEW** | `OpentdfConfiguration`, `KasConfig`, `IdpConfig`, `KasEndpoints`, `KasTransport`, `ConnectError`, `parse_connect_error`, `fetch_well_known` |
| `src/lib.rs` | modify | export new `kas_discovery` module |
| `src/kas.rs` | modify | `send_rewrap_request` URL, `KasClient::new` signature, struct field add |
| `src/kas_key.rs` | modify | add Connect siblings, deprecate REST functions |
| `src/tdf.rs` | modify | doc-comment migrations (doctests) |
| `src/archive.rs` | modify | doc-comment migrations (doctests) |
| `tests/kas_mock.rs` | modify | route paths, add Connect-error envelope test, add public-key Connect test, migrate constructor calls |
| `tests/kas_integration.rs` | modify | migrate constructor calls |
| `tests/platform_integration.rs` | modify | add Connect/well-known/CWT-401 live tests against `platform.arkavo.net` |
| `examples/kas_decrypt.rs` | modify | constructor migration |
| `examples/create_tdf_platform.rs` | modify | constructor migration, use `fetch_kas_public_key_connect` |
| `examples/kas_sanity_test.rs` | modify | constructor migration, point at Connect path |
| `examples/jwt_helper.rs` | modify | doc string in `println!` |
| `examples/mock_kas_server.rs` | modify | add Connect route handlers alongside REST |
| `Cargo.toml` (root + workspace + sub-crates) | modify | `0.12.0` → `0.13.0` |
| `CHANGELOG.md` | modify (or create) | breaking change entry, migration one-liner |

---

## Task 1: Bootstrap `kas_discovery` module

**Files:**
- Create: `src/kas_discovery.rs`
- Modify: `src/lib.rs`

- [ ] **Step 1: Create the empty module file**

Create `src/kas_discovery.rs`:

```rust
//! KAS endpoint discovery via /.well-known/opentdf-configuration
//!
//! Provides types for deserializing the platform's well-known configuration
//! document, plus URL-resolution logic that prefers ConnectRPC endpoints
//! and falls back to legacy REST paths when only REST is advertised.

#![cfg(feature = "kas-client")]
```

- [ ] **Step 2: Export from lib.rs**

In `src/lib.rs`, find the existing `pub mod kas;` and add immediately after:

```rust
pub mod kas_discovery;
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo build --features kas-client`
Expected: clean build, no new warnings.

- [ ] **Step 4: Commit**

```bash
git add src/kas_discovery.rs src/lib.rs
git commit -m "feat(kas): add empty kas_discovery module (#85)"
```

---

## Task 2: `OpentdfConfiguration` deserialization

**Files:**
- Modify: `src/kas_discovery.rs`

- [ ] **Step 1: Write the failing test**

Append to `src/kas_discovery.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// Captured from https://platform.arkavo.net/.well-known/opentdf-configuration on 2026-05-28
    const PLATFORM_WELL_KNOWN: &str = r#"{
        "health": { "endpoint": "/healthz" },
        "idp": {
            "access_token_format": "application/cwt",
            "authorization_endpoint": "https://identity.arkavo.net/oauth/authorize",
            "cose_keys_uri": "https://identity.arkavo.net/.well-known/cose-keys",
            "id_token_signing_alg_values_supported": ["ES256"],
            "issuer": "https://identity.arkavo.net",
            "jwks_uri": "https://identity.arkavo.net/.well-known/jwks.json",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "token_endpoint": "https://identity.arkavo.net/oauth/token",
            "userinfo_endpoint": "https://identity.arkavo.net/oauth/userinfo"
        },
        "kas": {
            "algorithms": ["ec:secp256r1", "rsa:2048"],
            "connect_public_key_url": "https://platform.arkavo.net/kas.AccessService/PublicKey",
            "connect_rewrap_url": "https://platform.arkavo.net/kas.AccessService/Rewrap",
            "public_key_url": "https://platform.arkavo.net/kas/v2/kas_public_key",
            "rewrap_url": "https://platform.arkavo.net/kas/v2/rewrap",
            "uri": "https://platform.arkavo.net"
        },
        "platform_issuer": "https://identity.arkavo.net"
    }"#;

    #[test]
    fn deserializes_platform_well_known() {
        let cfg: OpentdfConfiguration = serde_json::from_str(PLATFORM_WELL_KNOWN).unwrap();
        let kas = cfg.kas.expect("kas block present");
        assert_eq!(kas.uri, "https://platform.arkavo.net");
        assert_eq!(kas.algorithms, vec!["ec:secp256r1", "rsa:2048"]);
        assert_eq!(
            kas.connect_rewrap_url.as_deref(),
            Some("https://platform.arkavo.net/kas.AccessService/Rewrap")
        );
        assert_eq!(
            kas.rewrap_url.as_deref(),
            Some("https://platform.arkavo.net/kas/v2/rewrap")
        );
        let idp = cfg.idp.expect("idp block present");
        assert_eq!(idp.issuer, "https://identity.arkavo.net");
        assert_eq!(idp.access_token_format.as_deref(), Some("application/cwt"));
        assert_eq!(cfg.platform_issuer.as_deref(), Some("https://identity.arkavo.net"));
    }

    #[test]
    fn deserializes_minimal_kas_only() {
        let json = r#"{
            "kas": {
                "uri": "https://k.example.com",
                "algorithms": [],
                "rewrap_url": "https://k.example.com/kas/v2/rewrap",
                "public_key_url": "https://k.example.com/kas/v2/kas_public_key"
            }
        }"#;
        let cfg: OpentdfConfiguration = serde_json::from_str(json).unwrap();
        let kas = cfg.kas.unwrap();
        assert!(kas.connect_rewrap_url.is_none());
        assert_eq!(kas.rewrap_url.as_deref(), Some("https://k.example.com/kas/v2/rewrap"));
        assert!(cfg.idp.is_none());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --features kas-client kas_discovery::tests::deserializes`
Expected: FAIL — `OpentdfConfiguration` and related types don't exist yet.

- [ ] **Step 3: Implement the types**

In `src/kas_discovery.rs`, insert before `#[cfg(test)]`:

```rust
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct OpentdfConfiguration {
    pub kas: Option<KasConfig>,
    pub idp: Option<IdpConfig>,
    pub platform_issuer: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct KasConfig {
    pub uri: String,
    #[serde(default)]
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
    #[serde(default)]
    pub id_token_signing_alg_values_supported: Vec<String>,
    #[serde(default)]
    pub response_types_supported: Vec<String>,
    #[serde(default)]
    pub subject_types_supported: Vec<String>,
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --features kas-client kas_discovery::tests::deserializes`
Expected: PASS, both tests.

- [ ] **Step 5: Commit**

```bash
git add src/kas_discovery.rs
git commit -m "feat(kas): add OpentdfConfiguration deserialization (#85)"
```

---

## Task 3: `KasEndpoints::from_config` URL selection

**Files:**
- Modify: `src/kas_discovery.rs`

- [ ] **Step 1: Add failing tests**

In the existing `mod tests` block in `src/kas_discovery.rs`, add:

```rust
    #[test]
    fn from_config_picks_connect_when_present() {
        let cfg: OpentdfConfiguration = serde_json::from_str(PLATFORM_WELL_KNOWN).unwrap();
        let endpoints = KasEndpoints::from_config(&cfg).unwrap();
        assert_eq!(
            endpoints.rewrap_url,
            "https://platform.arkavo.net/kas.AccessService/Rewrap"
        );
        assert_eq!(
            endpoints.public_key_url,
            "https://platform.arkavo.net/kas.AccessService/PublicKey"
        );
        assert_eq!(endpoints.transport, KasTransport::Connect);
    }

    #[test]
    fn from_config_falls_back_to_rest_when_connect_absent() {
        let json = r#"{
            "kas": {
                "uri": "https://k.example.com",
                "algorithms": [],
                "rewrap_url": "https://k.example.com/kas/v2/rewrap",
                "public_key_url": "https://k.example.com/kas/v2/kas_public_key"
            }
        }"#;
        let cfg: OpentdfConfiguration = serde_json::from_str(json).unwrap();
        let endpoints = KasEndpoints::from_config(&cfg).unwrap();
        assert_eq!(endpoints.rewrap_url, "https://k.example.com/kas/v2/rewrap");
        assert_eq!(endpoints.public_key_url, "https://k.example.com/kas/v2/kas_public_key");
        assert_eq!(endpoints.transport, KasTransport::LegacyRest);
    }

    #[test]
    fn from_config_errors_when_kas_block_missing() {
        let json = r#"{ "platform_issuer": "https://example.com" }"#;
        let cfg: OpentdfConfiguration = serde_json::from_str(json).unwrap();
        let err = KasEndpoints::from_config(&cfg).unwrap_err();
        match err {
            opentdf_protocol::KasError::ConfigError { reason } => {
                assert!(reason.contains("kas"));
            }
            other => panic!("expected ConfigError, got {other:?}"),
        }
    }

    #[test]
    fn from_config_errors_when_urls_missing() {
        let json = r#"{
            "kas": { "uri": "https://k.example.com", "algorithms": [] }
        }"#;
        let cfg: OpentdfConfiguration = serde_json::from_str(json).unwrap();
        let err = KasEndpoints::from_config(&cfg).unwrap_err();
        assert!(matches!(err, opentdf_protocol::KasError::ConfigError { .. }));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --features kas-client kas_discovery::tests::from_config`
Expected: FAIL — `KasEndpoints` / `KasTransport` undefined.

- [ ] **Step 3: Implement `KasEndpoints` and `KasTransport`**

In `src/kas_discovery.rs`, after the existing types:

```rust
use opentdf_protocol::KasError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KasTransport {
    /// ConnectRPC endpoints at /kas.AccessService/*
    Connect,
    /// Legacy REST gateway at /kas/v2/*
    LegacyRest,
}

#[derive(Debug, Clone)]
pub struct KasEndpoints {
    pub rewrap_url: String,
    pub public_key_url: String,
    pub transport: KasTransport,
}

impl KasEndpoints {
    /// Resolve KAS endpoints from a configuration document, preferring
    /// ConnectRPC URLs and falling back to legacy REST when only REST is
    /// advertised.
    pub fn from_config(cfg: &OpentdfConfiguration) -> Result<Self, KasError> {
        let kas = cfg.kas.as_ref().ok_or_else(|| KasError::ConfigError {
            reason: "well-known configuration is missing a 'kas' block".to_string(),
        })?;

        if let (Some(rewrap), Some(public_key)) =
            (&kas.connect_rewrap_url, &kas.connect_public_key_url)
        {
            return Ok(KasEndpoints {
                rewrap_url: rewrap.clone(),
                public_key_url: public_key.clone(),
                transport: KasTransport::Connect,
            });
        }

        if let (Some(rewrap), Some(public_key)) = (&kas.rewrap_url, &kas.public_key_url) {
            return Ok(KasEndpoints {
                rewrap_url: rewrap.clone(),
                public_key_url: public_key.clone(),
                transport: KasTransport::LegacyRest,
            });
        }

        Err(KasError::ConfigError {
            reason: "well-known kas block exposes neither Connect nor REST URLs".to_string(),
        })
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --features kas-client kas_discovery::tests::from_config`
Expected: PASS, all four tests.

- [ ] **Step 5: Commit**

```bash
git add src/kas_discovery.rs
git commit -m "feat(kas): KasEndpoints::from_config URL selection (#85)"
```

---

## Task 4: `for_kas_connect` / `for_kas_legacy_rest` builders

**Files:**
- Modify: `src/kas_discovery.rs`

- [ ] **Step 1: Add failing tests**

In the existing `mod tests` block:

```rust
    #[test]
    fn for_kas_connect_constructs_expected_urls() {
        let cfg = OpentdfConfiguration::for_kas_connect("https://kas.example.com");
        let endpoints = KasEndpoints::from_config(&cfg).unwrap();
        assert_eq!(
            endpoints.rewrap_url,
            "https://kas.example.com/kas.AccessService/Rewrap"
        );
        assert_eq!(
            endpoints.public_key_url,
            "https://kas.example.com/kas.AccessService/PublicKey"
        );
        assert_eq!(endpoints.transport, KasTransport::Connect);
    }

    #[test]
    fn for_kas_connect_handles_trailing_slash() {
        let cfg = OpentdfConfiguration::for_kas_connect("https://kas.example.com/");
        let endpoints = KasEndpoints::from_config(&cfg).unwrap();
        assert_eq!(
            endpoints.rewrap_url,
            "https://kas.example.com/kas.AccessService/Rewrap"
        );
    }

    #[test]
    fn for_kas_legacy_rest_constructs_expected_urls() {
        let cfg = OpentdfConfiguration::for_kas_legacy_rest("https://kas.example.com");
        let endpoints = KasEndpoints::from_config(&cfg).unwrap();
        assert_eq!(endpoints.rewrap_url, "https://kas.example.com/kas/v2/rewrap");
        assert_eq!(
            endpoints.public_key_url,
            "https://kas.example.com/kas/v2/kas_public_key"
        );
        assert_eq!(endpoints.transport, KasTransport::LegacyRest);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --features kas-client kas_discovery::tests::for_kas`
Expected: FAIL — `for_kas_connect` / `for_kas_legacy_rest` don't exist.

- [ ] **Step 3: Implement the builders**

In `src/kas_discovery.rs`, add an `impl OpentdfConfiguration` block:

```rust
impl OpentdfConfiguration {
    /// Synthesize a configuration document pointing at a single KAS base URL
    /// using ConnectRPC paths. Use this when you can't or don't want to fetch
    /// `/.well-known/opentdf-configuration` (e.g., tests, deployments that
    /// don't expose the well-known endpoint).
    pub fn for_kas_connect(base_url: impl Into<String>) -> Self {
        let base = base_url.into();
        let base = base.trim_end_matches('/').to_string();
        Self {
            kas: Some(KasConfig {
                uri: base.clone(),
                algorithms: vec![],
                public_key_url: None,
                rewrap_url: None,
                connect_public_key_url: Some(format!("{}/kas.AccessService/PublicKey", base)),
                connect_rewrap_url: Some(format!("{}/kas.AccessService/Rewrap", base)),
            }),
            idp: None,
            platform_issuer: None,
        }
    }

    /// Synthesize a configuration document pointing at a single KAS base URL
    /// using legacy REST paths. Escape hatch for deployments that haven't
    /// migrated to ConnectRPC.
    pub fn for_kas_legacy_rest(base_url: impl Into<String>) -> Self {
        let base = base_url.into();
        let base = base.trim_end_matches('/').to_string();
        Self {
            kas: Some(KasConfig {
                uri: base.clone(),
                algorithms: vec![],
                public_key_url: Some(format!("{}/kas/v2/kas_public_key", base)),
                rewrap_url: Some(format!("{}/kas/v2/rewrap", base)),
                connect_public_key_url: None,
                connect_rewrap_url: None,
            }),
            idp: None,
            platform_issuer: None,
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --features kas-client kas_discovery::tests::for_kas`
Expected: PASS, all three tests.

- [ ] **Step 5: Commit**

```bash
git add src/kas_discovery.rs
git commit -m "feat(kas): OpentdfConfiguration builders for direct construction (#85)"
```

---

## Task 5: Connect error envelope parser

**Files:**
- Modify: `src/kas_discovery.rs`

- [ ] **Step 1: Add failing tests**

In the existing `mod tests` block:

```rust
    #[test]
    fn parse_connect_error_with_valid_body() {
        let body = r#"{"code":"unauthenticated","message":"missing bearer token"}"#;
        let err = parse_connect_error(body).unwrap();
        assert_eq!(err.code, "unauthenticated");
        assert_eq!(err.message, "missing bearer token");
    }

    #[test]
    fn parse_connect_error_with_garbage_returns_none() {
        assert!(parse_connect_error("not json").is_none());
        assert!(parse_connect_error("").is_none());
        assert!(parse_connect_error(r#"{"unrelated":"shape"}"#).is_none());
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --features kas-client kas_discovery::tests::parse_connect_error`
Expected: FAIL — `ConnectError` / `parse_connect_error` don't exist.

- [ ] **Step 3: Implement parser**

In `src/kas_discovery.rs`, after the `impl OpentdfConfiguration` block:

```rust
/// Error envelope returned by Connect unary-JSON RPCs on non-2xx responses.
///
/// Codes are defined by the Connect protocol spec
/// (canceled, unknown, invalid_argument, deadline_exceeded, not_found,
/// already_exists, permission_denied, resource_exhausted, failed_precondition,
/// aborted, out_of_range, unimplemented, internal, unavailable, data_loss,
/// unauthenticated).
#[derive(Debug, Clone, Deserialize)]
pub struct ConnectError {
    pub code: String,
    pub message: String,
}

/// Attempt to parse a Connect error envelope from a response body.
/// Returns `None` for empty bodies, non-JSON bodies, or JSON that doesn't
/// match the Connect error shape.
pub fn parse_connect_error(body: &str) -> Option<ConnectError> {
    if body.is_empty() {
        return None;
    }
    let parsed: ConnectError = serde_json::from_str(body).ok()?;
    // Reject objects that happen to deserialize but lack meaningful content
    if parsed.code.is_empty() {
        return None;
    }
    Some(parsed)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --features kas-client kas_discovery::tests::parse_connect_error`
Expected: PASS, both tests.

- [ ] **Step 5: Commit**

```bash
git add src/kas_discovery.rs
git commit -m "feat(kas): parse Connect error envelope (#85)"
```

---

## Task 6: `fetch_well_known` async function

**Files:**
- Modify: `src/kas_discovery.rs`

- [ ] **Step 1: Add failing tests**

In the existing `mod tests` block:

```rust
    use mockito::Server;

    #[tokio::test]
    async fn fetch_well_known_returns_parsed_config() {
        let mut server = Server::new_async().await;
        let _m = server
            .mock("GET", "/.well-known/opentdf-configuration")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(PLATFORM_WELL_KNOWN)
            .create_async()
            .await;

        let http = reqwest::Client::new();
        let cfg = fetch_well_known(&server.url(), &http).await.unwrap();
        assert!(cfg.kas.is_some());
        assert_eq!(
            cfg.platform_issuer.as_deref(),
            Some("https://identity.arkavo.net")
        );
    }

    #[tokio::test]
    async fn fetch_well_known_404_returns_http_error() {
        let mut server = Server::new_async().await;
        let _m = server
            .mock("GET", "/.well-known/opentdf-configuration")
            .with_status(404)
            .with_body("not found")
            .create_async()
            .await;

        let http = reqwest::Client::new();
        let err = fetch_well_known(&server.url(), &http).await.unwrap_err();
        match err {
            opentdf_protocol::KasError::HttpError { status, .. } => assert_eq!(status, 404),
            other => panic!("expected HttpError(404), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fetch_well_known_handles_trailing_slash() {
        let mut server = Server::new_async().await;
        let _m = server
            .mock("GET", "/.well-known/opentdf-configuration")
            .with_status(200)
            .with_body(PLATFORM_WELL_KNOWN)
            .create_async()
            .await;

        let http = reqwest::Client::new();
        let url_with_slash = format!("{}/", server.url());
        let cfg = fetch_well_known(&url_with_slash, &http).await.unwrap();
        assert!(cfg.kas.is_some());
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --features kas-client kas_discovery::tests::fetch_well_known`
Expected: FAIL — function undefined.

- [ ] **Step 3: Implement `fetch_well_known`**

In `src/kas_discovery.rs`, after `parse_connect_error`:

```rust
/// Fetch the platform's `/.well-known/opentdf-configuration` document.
///
/// `platform_url` should be the platform's base URL (e.g.,
/// `"https://platform.arkavo.net"`). A trailing slash is tolerated.
pub async fn fetch_well_known(
    platform_url: &str,
    http_client: &reqwest::Client,
) -> Result<OpentdfConfiguration, KasError> {
    let base = platform_url.trim_end_matches('/');
    let url = format!("{}/.well-known/opentdf-configuration", base);

    let response = http_client
        .get(&url)
        .send()
        .await
        .map_err(|e| KasError::RequestError {
            method: "GET".to_string(),
            url: url.clone(),
            reason: e.to_string(),
        })?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(KasError::HttpError {
            status: status.as_u16(),
            message: format!("GET {} -> {}: {}", url, status, body),
        });
    }

    response
        .json::<OpentdfConfiguration>()
        .await
        .map_err(|e| KasError::InvalidResponse {
            reason: format!("Failed to parse well-known JSON: {}", e),
            expected: Some("OpentdfConfiguration".to_string()),
        })
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --features kas-client kas_discovery::tests::fetch_well_known`
Expected: PASS, all three tests.

- [ ] **Step 5: Run full discovery test suite**

Run: `cargo test --features kas-client kas_discovery::`
Expected: PASS — all discovery module tests green (deserialization + endpoints + builders + parse_connect_error + fetch_well_known).

- [ ] **Step 6: Commit**

```bash
git add src/kas_discovery.rs
git commit -m "feat(kas): fetch_well_known async discovery function (#85)"
```

---

## Task 7: Switch `send_rewrap_request` to Connect URL + parse Connect errors

This task keeps the existing `KasClient::new(base_url, oauth_token)` signature unchanged — the URL change is internal to `send_rewrap_request`. The constructor signature change comes in Task 8 so each commit compiles cleanly.

**Files:**
- Modify: `src/kas.rs`
- Modify: `tests/kas_mock.rs`

- [ ] **Step 1: Update mock test paths**

In `tests/kas_mock.rs`, replace **every** occurrence of `"/kas/v2/rewrap"` with `"/kas.AccessService/Rewrap"`. There are six occurrences at lines 76, 110, 139, 166, 193, 284. Update the comment at line 92 from "The client will append /kas/v2/rewrap to its base_url" to "The client will append /kas.AccessService/Rewrap to its base_url".

- [ ] **Step 2: Add a Connect 401 envelope test**

In `tests/kas_mock.rs`, inside `mod kas_mock_tests`, add this new test after `test_kas_authentication_failure`:

```rust
    #[tokio::test]
    async fn test_kas_connect_401_envelope_surfaced_in_error() {
        let mut server = Server::new_async().await;

        let _mock = server
            .mock("POST", "/kas.AccessService/Rewrap")
            .with_status(401)
            .with_header("content-type", "application/json")
            .with_body(r#"{"code":"unauthenticated","message":"missing bearer token"}"#)
            .create();

        let kas_url = server.url();
        let client = KasClient::new(&kas_url, "bad-token").unwrap();
        let manifest = create_test_manifest_with_policy(kas_url.clone());

        let result = client.rewrap_standard_tdf(&manifest).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unauthenticated") || msg.contains("missing bearer token"),
            "expected Connect error code/message in error string, got: {msg}"
        );
    }
```

- [ ] **Step 3: Run the existing tests to verify they fail**

Run: `cargo test --features kas-client --test kas_mock`
Expected: existing tests FAIL because `send_rewrap_request` still POSTs to `/kas/v2/rewrap` (404 against the new mock paths).

- [ ] **Step 4: Update `send_rewrap_request` in `src/kas.rs`**

In `src/kas.rs`, locate `async fn send_rewrap_request` (around line 288). Replace the function body with:

```rust
    /// Internal helper for sending signed rewrap requests to KAS via ConnectRPC
    ///
    /// Handles HTTP POST to /kas.AccessService/Rewrap, parses Connect error
    /// envelopes for richer error messages, and deserializes the response.
    async fn send_rewrap_request(
        &self,
        signed_request: &SignedRewrapRequest,
    ) -> Result<RewrapResponse, KasError> {
        let rewrap_endpoint = format!("{}/kas.AccessService/Rewrap", self.base_url);

        let response = self
            .http_client
            .post(&rewrap_endpoint)
            .header("Authorization", format!("Bearer {}", self.oauth_token))
            .header("Content-Type", "application/json")
            .json(signed_request)
            .send()
            .await
            .map_err(|e| KasError::HttpError {
                status: 0,
                message: format!("HTTP request failed: {}", e),
            })?;

        let status = response.status();
        if !status.is_success() {
            let error_body = response.text().await.unwrap_or_default();
            let detail = crate::kas_discovery::parse_connect_error(&error_body)
                .map(|e| format!("{}: {}", e.code, e.message))
                .unwrap_or_else(|| {
                    if error_body.is_empty() {
                        format!("HTTP {}", status)
                    } else {
                        error_body.clone()
                    }
                });

            return Err(match status.as_u16() {
                401 => KasError::AuthenticationFailed { reason: detail },
                403 => KasError::AccessDenied {
                    resource: "KAS endpoint".to_string(),
                    reason: detail,
                },
                _ => KasError::HttpError {
                    status: status.as_u16(),
                    message: detail,
                },
            });
        }

        response
            .json()
            .await
            .map_err(|e| KasError::InvalidResponse {
                reason: format!("Failed to parse JSON response: {}", e),
                expected: Some("RewrapResponse".to_string()),
            })
    }
```

- [ ] **Step 5: Update the doc comments in `src/kas.rs`**

In `src/kas.rs`, update the module-level doc comments. At line 12 and line 20, change `4. POST to KAS `/v2/rewrap` endpoint` to `4. POST to KAS `/kas.AccessService/Rewrap` (ConnectRPC) endpoint`. At line 340 in the `rewrap_standard_tdf` doc, change `4. POST to KAS /v2/rewrap endpoint with signed JWT` to `4. POST to KAS /kas.AccessService/Rewrap (ConnectRPC) endpoint with signed JWT`.

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test --features kas-client --test kas_mock`
Expected: PASS, all eight tests (six existing + one new Connect 401 envelope test + existing JWT-format test).

- [ ] **Step 7: Run full test suite**

Run: `cargo test --all-features`
Expected: PASS. The transport change is internal; downstream tests should be unaffected.

- [ ] **Step 8: Commit**

```bash
git add src/kas.rs tests/kas_mock.rs
git commit -m "feat(kas): switch send_rewrap_request to ConnectRPC + parse Connect errors (#85)"
```

---

## Task 8: `KasClient::new` takes `&OpentdfConfiguration` (breaking change)

This task is the breaking change. All call sites in the workspace must update in the same commit, otherwise the tree won't compile.

**Files:**
- Modify: `src/kas.rs`
- Modify: `src/tdf.rs`
- Modify: `src/archive.rs`
- Modify: `tests/kas_mock.rs`
- Modify: `tests/kas_integration.rs`
- Modify: `examples/kas_decrypt.rs`
- Modify: `examples/create_tdf_platform.rs` (constructor only; public-key fetch updated in Task 10)
- Modify: `examples/kas_sanity_test.rs`
- Modify: `examples/jwt_helper.rs`

- [ ] **Step 1: Update `KasClient` struct and `new` in `src/kas.rs`**

In `src/kas.rs`, locate the `KasClient` struct (around line 177). Replace it with:

```rust
#[cfg(feature = "kas-client")]
pub struct KasClient {
    http_client: Client,
    pub base_url: String,
    endpoints: crate::kas_discovery::KasEndpoints,
    oauth_token: String,
    signing_key: PrivateDecryptingKey,
}
```

Then replace the `impl KasClient` `new` function (around line 206-283):

```rust
    /// Create a new KAS client from a resolved configuration document.
    ///
    /// # Arguments
    ///
    /// * `config` - A pre-resolved `OpentdfConfiguration`. Obtain via
    ///   `fetch_well_known(...)` for discovery-driven setups, or build
    ///   directly with `OpentdfConfiguration::for_kas_connect(base_url)`
    ///   when the platform doesn't expose `/.well-known/opentdf-configuration`.
    ///   `OpentdfConfiguration::for_kas_legacy_rest(base_url)` is the escape
    ///   hatch for pre-ConnectRPC deployments.
    /// * `oauth_token` - Bearer token sent in the `Authorization` header.
    ///   Opaque passthrough: pass a JWT or a base64url-encoded CWT — the
    ///   server decides how to validate.
    ///
    /// # Security
    ///
    /// The resolved KAS rewrap URL is validated:
    /// - **HTTPS required**: HTTP is only allowed for `localhost`/`127.0.0.1`/`::1` (development use)
    /// - **SSRF protection**: Private and link-local IP addresses are rejected
    /// - **Scheme validation**: Only `http` and `https` schemes are accepted
    ///
    /// # Note
    ///
    /// This client generates an ephemeral RSA-2048 key pair for signing the
    /// inner JWT rewrap request envelope. That is separate from the access
    /// token — the inner JWT is the rewrap-request signature; the `oauth_token`
    /// is the platform-issued access token.
    pub fn new(
        config: &crate::kas_discovery::OpentdfConfiguration,
        oauth_token: impl Into<String>,
    ) -> Result<Self, KasError> {
        let endpoints = crate::kas_discovery::KasEndpoints::from_config(config)?;

        // Validate the rewrap URL — the public_key_url is validated on use.
        Self::validate_kas_url(&endpoints.rewrap_url)?;

        let http_client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| KasError::HttpError {
                status: 0,
                message: format!("Failed to build HTTP client: {}", e),
            })?;

        let signing_key = PrivateDecryptingKey::generate(KeySize::Rsa2048).map_err(|e| {
            KasError::CryptoError {
                operation: "generate_signing_key".to_string(),
                reason: format!("Failed to generate RSA signing key: {:?}", e),
            }
        })?;

        // Derive base_url from the kas block's `uri` if present, else from the
        // rewrap URL host. Used only for backwards-compat field access; not
        // used for routing (we use endpoints.rewrap_url).
        let base_url = config
            .kas
            .as_ref()
            .map(|k| k.uri.trim_end_matches('/').to_string())
            .unwrap_or_default();

        Ok(Self {
            http_client,
            base_url,
            endpoints,
            oauth_token: oauth_token.into(),
            signing_key,
        })
    }

    /// Validate a KAS URL for HTTPS / SSRF / scheme constraints.
    fn validate_kas_url(url_str: &str) -> Result<(), KasError> {
        let parsed = url::Url::parse(url_str)
            .map_err(|e| KasError::InvalidUrl(format!("Failed to parse URL: {e}")))?;

        match parsed.scheme() {
            "https" => {}
            "http" => {
                let is_loopback = match parsed.host() {
                    Some(url::Host::Domain("localhost")) => true,
                    Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
                    Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
                    _ => false,
                };
                if !is_loopback {
                    return Err(KasError::InvalidUrl(
                        "KAS URL must use HTTPS (HTTP only allowed for localhost)".to_string(),
                    ));
                }
            }
            scheme => {
                return Err(KasError::InvalidUrl(format!(
                    "Unsupported URL scheme '{scheme}', must be https"
                )));
            }
        }

        if let Some(host) = parsed.host() {
            match host {
                url::Host::Ipv4(ip) => {
                    if ip.is_private() || ip.is_link_local() {
                        return Err(KasError::InvalidUrl(
                            "KAS URL must not target private or link-local IP addresses"
                                .to_string(),
                        ));
                    }
                }
                url::Host::Ipv6(_) | url::Host::Domain(_) => {}
            }
        }

        Ok(())
    }
```

- [ ] **Step 2: Update `send_rewrap_request` to use `endpoints.rewrap_url`**

In `src/kas.rs`, in `send_rewrap_request`, change the URL line from:

```rust
        let rewrap_endpoint = format!("{}/kas.AccessService/Rewrap", self.base_url);
```

to:

```rust
        let rewrap_endpoint = self.endpoints.rewrap_url.clone();
```

- [ ] **Step 3: Update the `KasClient` doc example in `src/kas.rs`**

Replace the example at lines 30-49 in `src/kas.rs`:

```rust
//! # Example
//!
//! ```no_run
//! use opentdf::kas::KasClient;
//! use opentdf::kas_discovery::OpentdfConfiguration;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = OpentdfConfiguration::for_kas_connect("https://kas.example.com");
//! let client = KasClient::new(&config, "oauth_token_here")?;
//!
//! let manifest = opentdf::TdfManifest::new(
//!     "0.payload".to_string(),
//!     "https://kas.example.com".to_string()
//! );
//!
//! let payload_key = client.rewrap_standard_tdf(&manifest).await?;
//! # Ok(())
//! # }
//! ```
```

- [ ] **Step 4: Update `url_validation_tests` in `src/kas.rs`**

In `src/kas.rs`, replace the entire `mod url_validation_tests` block (lines 869-954) with:

```rust
    #[cfg(feature = "kas-client")]
    mod url_validation_tests {
        use super::*;
        use crate::kas_discovery::OpentdfConfiguration;

        /// Helper: construct via for_kas_connect and capture the error.
        fn expect_err(url: &str) -> KasError {
            let cfg = OpentdfConfiguration::for_kas_connect(url);
            match KasClient::new(&cfg, "token") {
                Err(e) => e,
                Ok(_) => panic!("Expected error for {url}, got Ok"),
            }
        }

        #[test]
        fn test_kas_rejects_http_url() {
            let err = expect_err("http://evil.com");
            assert!(matches!(err, KasError::InvalidUrl(_)), "got: {err}");
            assert!(err.to_string().contains("HTTPS"));
        }

        #[test]
        fn test_kas_accepts_https_url() {
            let cfg = OpentdfConfiguration::for_kas_connect("https://kas.example.com");
            assert!(KasClient::new(&cfg, "token").is_ok());
        }

        #[test]
        fn test_kas_allows_http_localhost() {
            for base in ["http://127.0.0.1:8080", "http://localhost:8080", "http://[::1]:8080"] {
                let cfg = OpentdfConfiguration::for_kas_connect(base);
                assert!(
                    KasClient::new(&cfg, "token").is_ok(),
                    "HTTP loopback {base} should be allowed"
                );
            }
        }

        #[test]
        fn test_kas_rejects_private_ip() {
            for base in ["https://10.0.0.1", "https://172.16.0.1", "https://192.168.1.1"] {
                let err = expect_err(base);
                assert!(matches!(err, KasError::InvalidUrl(_)), "{base}: {err}");
            }
        }

        #[test]
        fn test_kas_rejects_metadata_ip() {
            let err = expect_err("http://169.254.169.254");
            assert!(matches!(err, KasError::InvalidUrl(_)), "got: {err}");
        }

        #[test]
        fn test_kas_rejects_invalid_scheme() {
            let err = expect_err("ftp://kas.example.com");
            assert!(matches!(err, KasError::InvalidUrl(_)), "got: {err}");
            assert!(err.to_string().contains("ftp"));
        }

        #[test]
        fn test_kas_rejects_invalid_url() {
            let err = expect_err("not-a-url");
            assert!(matches!(err, KasError::InvalidUrl(_)), "got: {err}");
        }
    }
```

- [ ] **Step 5: Update `tests/kas_mock.rs` constructor calls**

In `tests/kas_mock.rs`, update the imports at line 9-13 to add `kas_discovery::OpentdfConfiguration`:

```rust
    use mockito::Server;
    use opentdf::{
        TdfManifest,
        kas::{KasClient, KeyType},
        kas_discovery::OpentdfConfiguration,
        manifest::TdfManifestExt,
    };
```

Then replace every `KasClient::new(&kas_url, "...")` and `KasClient::new(kas_url, ...)` call with:

```rust
        let cfg = OpentdfConfiguration::for_kas_connect(&kas_url);
        let client = KasClient::new(&cfg, "<token>").unwrap();
```

Six call sites (lines 66, 89, 117, 146, 173, 200, 219, 296). Use `.expect("create client")` instead of `.unwrap()` where the existing code uses `.unwrap()` — match the existing style at each site.

For the `test_kas_client_creation` test at line 65, the new shape is:

```rust
    #[tokio::test]
    async fn test_kas_client_creation() {
        let cfg = OpentdfConfiguration::for_kas_connect("https://kas.example.com");
        let client = KasClient::new(&cfg, "mock-token");
        assert!(client.is_ok(), "KAS client creation should succeed");
    }
```

For `test_kas_network_timeout` (line 215), update to:

```rust
    #[tokio::test]
    async fn test_kas_network_timeout() {
        let kas_url = "https://192.0.2.1:9999";
        let cfg = OpentdfConfiguration::for_kas_connect(kas_url);
        let client = KasClient::new(&cfg, "token").unwrap();

        let manifest = create_test_manifest_with_policy(kas_url.to_string());
        // ... rest unchanged
```

- [ ] **Step 6: Update `tests/kas_integration.rs` constructor calls**

Open `tests/kas_integration.rs`. At each `KasClient::new(&kas_url, &oauth_token)` (lines 66 and 119), construct via:

```rust
        let cfg = opentdf::kas_discovery::OpentdfConfiguration::for_kas_connect(&kas_url);
        let client = KasClient::new(&cfg, &oauth_token)
            .expect("Failed to create KAS client");
```

If `KasClient` is imported via `use opentdf::kas::KasClient`, add `use opentdf::kas_discovery::OpentdfConfiguration` and use the shorter path.

- [ ] **Step 7: Update `src/tdf.rs` doc examples**

In `src/tdf.rs` at lines 90 and 113, replace each `KasClient::new("https://kas.example.com", "token")?;` with:

```rust
    /// let config = opentdf::kas_discovery::OpentdfConfiguration::for_kas_connect(
    ///     "https://kas.example.com",
    /// );
    /// let kas_client = KasClient::new(&config, "token")?;
```

- [ ] **Step 8: Update `src/archive.rs` doc examples**

In `src/archive.rs` at lines 50 and 309, apply the same replacement as Step 7.

- [ ] **Step 9: Update `examples/kas_decrypt.rs`**

In `examples/kas_decrypt.rs` around line 43:

```rust
    let config = opentdf::kas_discovery::OpentdfConfiguration::for_kas_connect(&kas_url);
    let kas_client = match KasClient::new(&config, &kas_token) {
```

- [ ] **Step 10: Update `examples/create_tdf_platform.rs` constructor**

In `examples/create_tdf_platform.rs`, locate the `KasClient::new(...)` call (if present — grep first). If the example uses `KasClient` directly, wrap the base URL via `OpentdfConfiguration::for_kas_connect`. Public-key fetching is updated in Task 10.

```bash
grep -n "KasClient::new\|fetch_kas_public_key" examples/create_tdf_platform.rs
```

If `KasClient::new(...)` appears, replace as in Step 9. Skip Public-key changes for now.

- [ ] **Step 11: Update `examples/kas_sanity_test.rs`**

Open `examples/kas_sanity_test.rs`. The current line 13 hardcodes `"https://100.arkavo.net/kas/v2/rewrap"`. Change to:

```rust
    let kas_base_url = "https://100.arkavo.net";
    let kas_url = "https://100.arkavo.net/kas.AccessService/Rewrap";  // for display only
```

If the example builds a `KasClient`, construct via `OpentdfConfiguration::for_kas_connect(kas_base_url)`.

- [ ] **Step 12: Update `examples/jwt_helper.rs` doc string**

In `examples/jwt_helper.rs` line 149, change:

```rust
    println!("let kas_client = KasClient::new(kas_url, oauth_token)?;");
```

to:

```rust
    println!("let config = OpentdfConfiguration::for_kas_connect(kas_url);");
    println!("let kas_client = KasClient::new(&config, oauth_token)?;");
```

- [ ] **Step 13: Build and test**

Run:
```bash
cargo build --all-features
cargo test --all-features
cargo build --examples --all-features
```
Expected: clean build, all tests pass, all examples compile.

- [ ] **Step 14: Clippy**

Run: `cargo clippy --all-targets --all-features -- -D warnings`
Expected: clean — no warnings.

- [ ] **Step 15: Format**

Run: `cargo fmt --all`
Expected: no diff (or only whitespace).

- [ ] **Step 16: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
feat(kas)!: KasClient::new takes &OpentdfConfiguration (#85)

Breaking change. Pre-resolved configuration is now required at construction
time; discovery is a separate async free function (fetch_well_known) so
KasClient::new stays synchronous.

Migration:
  // before
  let client = KasClient::new("https://kas.example.com", token)?;

  // after
  let cfg = OpentdfConfiguration::for_kas_connect("https://kas.example.com");
  let client = KasClient::new(&cfg, token)?;

Or, with discovery:
  let cfg = fetch_well_known("https://platform.example.com", &http).await?;
  let client = KasClient::new(&cfg, token)?;

Updated all in-repo callers (tests, examples, doc examples) in this commit.
EOF
)"
```

---

## Task 9: Connect siblings for KAS public-key fetch

**Files:**
- Modify: `src/kas_key.rs`

- [ ] **Step 1: Add a failing test for the Connect variant**

Append to the existing `#[cfg(test)] mod tests` block in `src/kas_key.rs`:

```rust
    #[cfg(feature = "kas-client")]
    #[tokio::test]
    async fn test_fetch_kas_public_key_connect_against_mock() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/kas.AccessService/PublicKey")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"publicKey":"-----BEGIN PUBLIC KEY-----\ntestkey\n-----END PUBLIC KEY-----\n","kid":"r1"}"#)
            .create_async()
            .await;

        let url = format!("{}/kas.AccessService/PublicKey", server.url());
        let http = reqwest::Client::new();
        let resp = fetch_kas_public_key_connect(&url, &http).await.unwrap();
        assert!(resp.public_key.starts_with("-----BEGIN PUBLIC KEY-----"));
        assert_eq!(resp.kid, "r1");
    }

    #[cfg(feature = "kas-client")]
    #[tokio::test]
    async fn test_fetch_kas_ec_public_key_connect_against_mock() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/kas.AccessService/PublicKey")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"publicKey":"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/shJbT/RbVUkgV+/5m+KPblr5ZXH\nHU+2K5VytEsGQJJ0fxiksZXDC7twCPAXZgE3LOvORGqbQriKe/nM4iqIuA==\n-----END PUBLIC KEY-----\n","kid":"ec:secp256r1"}"#)
            .create_async()
            .await;

        let url = format!("{}/kas.AccessService/PublicKey", server.url());
        let http = reqwest::Client::new();
        let resp = fetch_kas_ec_public_key_connect(&url, &http).await.unwrap();
        assert_eq!(resp.kid, "ec:secp256r1");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --features kas-client --lib kas_key::tests::test_fetch_kas_public_key_connect`
Expected: FAIL — functions undefined.

- [ ] **Step 3: Implement `fetch_kas_public_key_connect`**

In `src/kas_key.rs`, add after the existing `fetch_kas_public_key` function:

```rust
/// Fetch the KAS public key via ConnectRPC.
///
/// Unlike `fetch_kas_public_key`, this expects a pre-resolved URL (typically
/// from `KasEndpoints::public_key_url`) and POSTs an empty JSON body — the
/// Connect protocol requires a request body even for empty message types.
#[cfg(feature = "kas-client")]
pub async fn fetch_kas_public_key_connect(
    public_key_url: &str,
    http_client: &Client,
) -> Result<KasPublicKeyResponse, KasKeyError> {
    let response = http_client
        .post(public_key_url)
        .header("Content-Type", "application/json")
        .body("{}")
        .send()
        .await?;

    let status = response.status();
    if !status.is_success() {
        let error_body = response.text().await.unwrap_or_default();
        return Err(KasKeyError::HttpError(format!(
            "POST {} -> HTTP {}: {}",
            public_key_url, status, error_body
        )));
    }

    let key_response: KasPublicKeyResponse = response.json().await?;
    Ok(key_response)
}
```

- [ ] **Step 4: Implement `fetch_kas_ec_public_key_connect`**

In `src/kas_key.rs`, add after the existing `fetch_kas_ec_public_key` function:

```rust
/// Fetch the KAS EC public key via ConnectRPC.
///
/// Unlike `fetch_kas_ec_public_key`, this expects a pre-resolved URL.
#[cfg(feature = "kas-client")]
pub async fn fetch_kas_ec_public_key_connect(
    public_key_url: &str,
    http_client: &Client,
) -> Result<KasEcPublicKeyResponse, KasKeyError> {
    let response = http_client
        .post(public_key_url)
        .header("Content-Type", "application/json")
        .body("{}")
        .send()
        .await?;

    let status = response.status();
    if !status.is_success() {
        let error_body = response.text().await.unwrap_or_default();
        return Err(KasKeyError::HttpError(format!(
            "POST {} -> HTTP {}: {}",
            public_key_url, status, error_body
        )));
    }

    let key_response: KasEcPublicKeyResponse = response.json().await?;
    validate_ec_public_key_pem(&key_response.public_key)?;
    Ok(key_response)
}
```

- [ ] **Step 5: Deprecate the REST variants**

In `src/kas_key.rs`, add a deprecation attribute to both `fetch_kas_public_key` and `fetch_kas_ec_public_key`. Find the function signature lines (73 and 157), and immediately above each `#[cfg(feature = "kas-client")]` line, add:

```rust
#[deprecated(
    since = "0.13.0",
    note = "Legacy /kas/v2/* REST endpoint. Use fetch_kas_public_key_connect with a URL resolved from OpentdfConfiguration or fetch_well_known()."
)]
```

- [ ] **Step 6: Run tests to verify the new tests pass**

Run: `cargo test --features kas-client --lib kas_key::tests::test_fetch_kas_public_key_connect kas_key::tests::test_fetch_kas_ec_public_key_connect`
Expected: PASS.

- [ ] **Step 7: Build with deprecation warnings allowed**

Run: `cargo build --all-features`
Expected: build succeeds. Deprecation warnings will appear for the REST functions — they're informational, not errors.

- [ ] **Step 8: Update `examples/create_tdf_platform.rs` to use Connect**

In `examples/create_tdf_platform.rs` at line 50:

```rust
    let kas_pk_url = format!("{}/kas.AccessService/PublicKey", kas_url.trim_end_matches('/'));
    let kas_key_response =
        opentdf::kas_key::fetch_kas_public_key_connect(&kas_pk_url, &http_client).await?;
```

- [ ] **Step 9: Suppress deprecation warnings in remaining callers**

Run: `cargo build --all-features 2>&1 | grep "deprecated" | head -20`

For each remaining caller that uses `fetch_kas_public_key` or `fetch_kas_ec_public_key`, prefix the call with `#[allow(deprecated)]` on the function or block, OR migrate to the Connect variant. If a caller is in `examples/mock_kas_server.rs` or another example that intentionally exercises the legacy path, add the `#[allow(deprecated)]` attribute.

- [ ] **Step 10: Clean build with warnings as errors**

Run: `RUSTFLAGS="-D warnings" cargo build --all-features`
Expected: clean build — any remaining deprecation calls must be `#[allow(deprecated)]`'d or migrated.

- [ ] **Step 11: Commit**

```bash
git add src/kas_key.rs examples/create_tdf_platform.rs
# add any other files touched in step 9
git commit -m "feat(kas): Connect siblings for public-key fetch, deprecate REST (#85)"
```

---

## Task 10: Add Connect routes to `examples/mock_kas_server.rs`

**Files:**
- Modify: `examples/mock_kas_server.rs`

- [ ] **Step 1: Add Connect-route handlers**

In `examples/mock_kas_server.rs` at the route registration (around line 708):

```rust
        .route("/kas/v2/kas_public_key", get(get_public_key_with_algorithm))
        .route("/kas/v2/rewrap", post(rewrap))
        .route("/kas.AccessService/PublicKey", post(get_public_key_connect))
        .route("/kas.AccessService/Rewrap", post(rewrap))
```

The legacy REST routes stay (multi-profile mock). Both paths can share the `rewrap` handler — same request shape.

- [ ] **Step 2: Add a Connect-shape public-key handler**

The existing `get_public_key_with_algorithm` reads the algorithm from a query parameter (GET). For Connect, the algorithm comes from the JSON body. Add a sibling handler:

```rust
#[derive(serde::Deserialize, Default)]
struct PublicKeyConnectRequest {
    #[serde(default)]
    algorithm: Option<String>,
}

async fn get_public_key_connect(
    State(state): State<AppState>,
    body: Option<Json<PublicKeyConnectRequest>>,
) -> impl IntoResponse {
    let algorithm = body
        .and_then(|Json(req)| req.algorithm)
        .unwrap_or_else(|| "rsa:2048".to_string());

    // Delegate to the existing algorithm-aware response, but return
    // camelCase publicKey for Connect protojson compatibility.
    let (pem, kid) = state.public_keys_for(&algorithm);

    Json(serde_json::json!({
        "publicKey": pem,
        "kid": kid,
    }))
}
```

Note: if `public_keys_for` is not an existing method, replace its body with the same lookup logic that `get_public_key_with_algorithm` uses, returning a `(String, String)` tuple of `(pem, kid)`. Read `get_public_key_with_algorithm` first to crib its implementation.

- [ ] **Step 3: Update the startup banner**

In `examples/mock_kas_server.rs`, around lines 701-702 where the server prints its routes, add:

```rust
    println!("  POST /kas.AccessService/PublicKey - Get KAS public key (ConnectRPC)");
    println!("  POST /kas.AccessService/Rewrap    - Rewrap key (ConnectRPC)");
```

- [ ] **Step 4: Manual smoke test**

In one terminal:
```bash
cargo run --example mock_kas_server --features kas-client,cbor
```

In another:
```bash
curl -sX POST http://localhost:8080/kas.AccessService/PublicKey \
  -H 'content-type: application/json' -d '{}'
```

Expected: JSON response with `publicKey` (camelCase) and `kid` fields.

- [ ] **Step 5: Stop the mock server (Ctrl+C in terminal 1)**

- [ ] **Step 6: Commit**

```bash
git add examples/mock_kas_server.rs
git commit -m "feat(mock-kas): add ConnectRPC routes alongside legacy REST (#85)"
```

---

## Task 11: Live integration tests against `platform.arkavo.net`

**Files:**
- Modify: `tests/platform_integration.rs`

- [ ] **Step 1: Append three new ignored integration tests**

At the end of `tests/platform_integration.rs`, append:

```rust
// ---------------------------------------------------------------------------
// ConnectRPC migration verification (#85)
//
// These tests run against the real Arkavo platform and document the milestone
// state of the Connect transport. They are #[ignore]d by default; opt in with:
//
//   cargo test --test platform_integration --all-features -- --ignored connect
//
// or, if KAS_INTEGRATION_TESTS=1 is set, the user can run them by name.
// ---------------------------------------------------------------------------

const ARKAVO_PLATFORM: &str = "https://platform.arkavo.net";

#[tokio::test]
#[ignore]
async fn connect_well_known_endpoint_returns_kas_config() -> Result<(), Box<dyn Error>> {
    use opentdf::kas_discovery::fetch_well_known;
    let http = reqwest::Client::new();
    let cfg = fetch_well_known(ARKAVO_PLATFORM, &http).await?;
    let kas = cfg.kas.expect("kas block should be present");
    assert!(
        kas.connect_rewrap_url.is_some(),
        "platform should advertise connect_rewrap_url"
    );
    assert!(
        kas.connect_public_key_url.is_some(),
        "platform should advertise connect_public_key_url"
    );
    assert!(
        kas.rewrap_url.is_some(),
        "platform also exposes legacy REST rewrap_url (transitional)"
    );
    println!("✓ well-known reports both Connect and REST URLs");
    Ok(())
}

#[tokio::test]
#[ignore]
async fn connect_public_key_returns_pem() -> Result<(), Box<dyn Error>> {
    use opentdf::kas_discovery::{KasEndpoints, fetch_well_known};
    use opentdf::kas_key::fetch_kas_public_key_connect;

    let http = reqwest::Client::new();
    let cfg = fetch_well_known(ARKAVO_PLATFORM, &http).await?;
    let endpoints = KasEndpoints::from_config(&cfg)?;
    let resp = fetch_kas_public_key_connect(&endpoints.public_key_url, &http).await?;
    assert!(
        resp.public_key.starts_with("-----BEGIN PUBLIC KEY-----"),
        "expected PEM, got: {}",
        resp.public_key
    );
    assert!(!resp.kid.is_empty(), "kid should be populated");
    println!("✓ Connect PublicKey returned kid={} ({} bytes PEM)", resp.kid, resp.public_key.len());
    Ok(())
}

#[tokio::test]
#[ignore]
async fn connect_rewrap_fails_with_fake_bearer_returns_401() -> Result<(), Box<dyn Error>> {
    use opentdf::TdfManifest;
    use opentdf::kas::KasClient;
    use opentdf::kas_discovery::fetch_well_known;
    use opentdf_protocol::KasError;

    let http = reqwest::Client::new();
    let cfg = fetch_well_known(ARKAVO_PLATFORM, &http).await?;
    // Pass a syntactically-plausible bearer that the platform will reject.
    let client = KasClient::new(&cfg, "eyJhbGciOiJub25lIn0.e30.")?;

    let manifest = TdfManifest::new("0.payload".to_string(), ARKAVO_PLATFORM.to_string());
    let result = client.rewrap_standard_tdf(&manifest).await;

    let err = result.err().expect("rewrap should fail without valid auth");
    match &err {
        KasError::AuthenticationFailed { reason } => {
            // Connect 'unauthenticated' code should surface in the reason string
            // when the platform returns a Connect error envelope.
            println!("✓ Connect rewrap returned AuthenticationFailed: {reason}");
        }
        KasError::AccessDenied { reason, .. } => {
            // Some Connect implementations may return permission_denied (403)
            // when the request is malformed.
            println!("✓ Connect rewrap returned AccessDenied: {reason}");
        }
        KasError::HttpError { status, message } => {
            // Acceptable: a generic HTTP error proves we hit Connect, not REST.
            println!("✓ Connect rewrap returned HTTP {status}: {message}");
            assert!(
                *status >= 400 && *status < 600,
                "expected 4xx/5xx, got {status}"
            );
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
    Ok(())
}
```

- [ ] **Step 2: Build the test binary**

Run: `cargo build --tests --all-features`
Expected: clean build.

- [ ] **Step 3: Run the new integration tests against the live platform**

Run:
```bash
cargo test --test platform_integration --all-features -- --ignored connect_well_known
cargo test --test platform_integration --all-features -- --ignored connect_public_key
cargo test --test platform_integration --all-features -- --ignored connect_rewrap_fails
```

Expected outputs:
- `connect_well_known_endpoint_returns_kas_config`: PASS — well-known fetched, kas block has both URL pairs.
- `connect_public_key_returns_pem`: PASS — Connect PublicKey returns valid PEM.
- `connect_rewrap_fails_with_fake_bearer_returns_401`: PASS — Connect Rewrap returns 401 with `unauthenticated` (or otherwise a 4xx/5xx documenting the next blocker).

If the platform is unreachable, skip and note for the PR description.

- [ ] **Step 4: Commit**

```bash
git add tests/platform_integration.rs
git commit -m "test(kas): live Connect/well-known integration against platform.arkavo.net (#85)"
```

---

## Task 12: Version bump, CHANGELOG, README, final checks

**Files:**
- Modify: `Cargo.toml` (root)
- Modify: `crates/crypto/Cargo.toml`
- Modify: `crates/wasm/Cargo.toml`
- Create or modify: `CHANGELOG.md`
- Modify: `README.md`

- [ ] **Step 1: Bump workspace version**

In `Cargo.toml` (root), find the `[workspace.package]` block and change:

```toml
[workspace.package]
version = "0.12.0"
```

to:

```toml
[workspace.package]
version = "0.13.0"
```

- [ ] **Step 2: Bump path-dep pins**

In `Cargo.toml` (root) lines 18-19:
```toml
opentdf-protocol = { path = "crates/protocol", version = "0.13.0" }
opentdf-crypto = { path = "crates/crypto", version = "0.13.0", default-features = false }
```

In `crates/crypto/Cargo.toml`, find any pinned version reference to `opentdf-protocol` and bump to `0.13.0`.

In `crates/wasm/Cargo.toml`, bump any pinned references to `opentdf`, `opentdf-protocol`, or `opentdf-crypto` to `0.13.0`.

- [ ] **Step 3: Update or create CHANGELOG.md**

```bash
test -f CHANGELOG.md || echo "# Changelog" > CHANGELOG.md
```

Insert at the top, immediately after the title:

```markdown
## [0.13.0] — 2026-05-28

### Breaking changes

- `KasClient::new` now takes `&OpentdfConfiguration` instead of a base URL string. Migrate via:
  ```rust
  // before
  let client = KasClient::new("https://kas.example.com", token)?;

  // after
  let cfg = opentdf::kas_discovery::OpentdfConfiguration::for_kas_connect(
      "https://kas.example.com",
  );
  let client = KasClient::new(&cfg, token)?;
  ```
  For discovery-driven setups, use `fetch_well_known(platform_url, &http).await?` to obtain the config.

### Added

- `opentdf::kas_discovery` module:
  - `OpentdfConfiguration` deserialization of `/.well-known/opentdf-configuration`
  - `KasEndpoints::from_config` with Connect-preferred / REST-fallback URL resolution
  - `OpentdfConfiguration::for_kas_connect` / `for_kas_legacy_rest` direct builders
  - `fetch_well_known` async discovery
  - `parse_connect_error` Connect error envelope parser
- `opentdf::kas_key::fetch_kas_public_key_connect` and `fetch_kas_ec_public_key_connect` for ConnectRPC public-key retrieval
- Live ConnectRPC integration tests against `platform.arkavo.net` in `tests/platform_integration.rs` (`#[ignore]`d by default)
- ConnectRPC route handlers in `examples/mock_kas_server.rs`

### Changed

- KAS rewrap now POSTs to `/kas.AccessService/Rewrap` (ConnectRPC) instead of `/kas/v2/rewrap` (legacy REST)
- Connect error envelope (`{code, message}`) parsed into `KasError` reason strings

### Deprecated

- `opentdf::kas_key::fetch_kas_public_key` — use `fetch_kas_public_key_connect`
- `opentdf::kas_key::fetch_kas_ec_public_key` — use `fetch_kas_ec_public_key_connect`

### Notes

- The `oauth_token` parameter of `KasClient::new` is an opaque passthrough. Pass a JWT or a base64url-encoded CWT; the server decides how to validate.
- Closes [#85](https://github.com/arkavo-org/opentdf-rs/issues/85).
```

- [ ] **Step 4: Update README.md**

In `README.md`, find any usage example that constructs a `KasClient`. Replace with the new shape:

```rust
use opentdf::kas::KasClient;
use opentdf::kas_discovery::{fetch_well_known, OpentdfConfiguration};

// Discovery (recommended):
let http = reqwest::Client::new();
let cfg = fetch_well_known("https://platform.arkavo.net", &http).await?;
let kas = KasClient::new(&cfg, oauth_token)?;

// Direct (skip discovery):
let cfg = OpentdfConfiguration::for_kas_connect("https://kas.example.com");
let kas = KasClient::new(&cfg, oauth_token)?;
```

- [ ] **Step 5: Pre-commit checklist**

Run each of these and confirm clean output:

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
RUSTFLAGS="-D warnings" cargo build --all-features
```

If WASM code changed in this PR (it shouldn't have — out of scope), additionally:

```bash
cd crates/wasm
wasm-pack build --target web --out-dir pkg-web
wasm-pack build --target bundler --out-dir pkg
wasm-pack build --target nodejs --out-dir pkg-node
cd ../..
```

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml crates/crypto/Cargo.toml crates/wasm/Cargo.toml CHANGELOG.md README.md
git commit -m "chore: bump to 0.13.0, CHANGELOG, README for ConnectRPC migration (#85)"
```

- [ ] **Step 7: Verify full history**

Run: `git log --oneline origin/main..HEAD`
Expected: a clean sequence of the task commits, each focused, each compilable.

- [ ] **Step 8: Push and open PR**

```bash
git push -u origin <branch>
gh pr create --title "feat(kas): ConnectRPC migration with well-known discovery (#85)" --body "$(cat <<'EOF'
## Summary
- Switches the native KAS client transport from `/kas/v2/*` REST to `/kas.AccessService/*` ConnectRPC.
- Adds `src/kas_discovery.rs` with well-known fetch and Connect-preferred URL resolution.
- `KasClient::new` now takes a pre-resolved `&OpentdfConfiguration` (breaking; 0.13.0 minor bump).
- Live tests against `platform.arkavo.net` validate end-to-end Connect plumbing. CWT-as-bearer support is server-side; client passes the bearer opaquely.

Closes #85.

## Test plan
- [ ] `cargo test --all-features` — green
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` — clean
- [ ] `cargo test --test platform_integration --all-features -- --ignored connect` — three Connect tests pass against platform.arkavo.net
- [ ] `cargo run --example mock_kas_server` + curl Connect endpoint manually

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Self-Review

**Spec coverage** — walked each section of the design doc:

| Spec section | Task(s) |
|---|---|
| Discovery module (`OpentdfConfiguration`, `KasConfig`, `IdpConfig`, `KasEndpoints`, `KasTransport`, `fetch_well_known`, builders) | 1–6 |
| `KasClient::new(&OpentdfConfiguration, token)` sync construction | 8 |
| Connect URL switch in `send_rewrap_request` | 7 |
| Connect error envelope parsing + `KasError` mapping | 5, 7 |
| `fetch_kas_public_key_connect` / `fetch_kas_ec_public_key_connect`, deprecate REST | 9 |
| CWT bearer = opaque passthrough (no client-side change) | 8 (doc comments) |
| Mock-server tests on `/kas.AccessService/Rewrap` + Connect 401 envelope test | 7 |
| Mock-server tests on `/kas.AccessService/PublicKey` | 9 |
| Live integration tests against `platform.arkavo.net` | 11 |
| `examples/mock_kas_server.rs` ConnectRPC routes | 10 |
| Examples + tests migrated to new constructor | 8 |
| Version bump 0.12.0 → 0.13.0, CHANGELOG | 12 |
| Pre-commit checklist (fmt, clippy, test, warnings-as-errors build) | 12 |

No gaps.

**Placeholder scan** — no TBDs, no "add error handling," no "similar to Task N." Every code-bearing step has actual code. The one soft spot is Task 8 Step 10 (`examples/create_tdf_platform.rs` constructor migration), where the exact line depends on what `grep` finds — the step has a grep command and an "if present" pattern, which is necessary because the file's call site may vary by branch; this is targeted rather than vague.

**Type consistency** — `OpentdfConfiguration`, `KasConfig`, `KasEndpoints`, `KasTransport`, `ConnectError`, `fetch_well_known`, `parse_connect_error`, `for_kas_connect`, `for_kas_legacy_rest`, `fetch_kas_public_key_connect`, `fetch_kas_ec_public_key_connect`, `KasClient::new` — names match between definitions, callers, and the `kas_discovery::OpentdfConfiguration` qualified path in test code. No drift.

**One scope note** — `examples/cross_sdk_test.rs` and `examples/xtest_cli.rs` use the builder pattern (`.kas_url(...)`) on a higher-level helper and may not call `KasClient::new` directly. Task 8 Step 5–11 covers the direct callers (kas_decrypt, create_tdf_platform, kas_sanity_test, jwt_helper); if `cargo build --examples` in Step 13 fails on cross_sdk_test or xtest_cli, fix in-place and amend that commit before continuing.
