//! KAS endpoint discovery via /.well-known/opentdf-configuration
//!
//! Provides types for deserializing the platform's well-known configuration
//! document, plus URL-resolution logic that prefers ConnectRPC endpoints
//! and falls back to legacy REST paths when only REST is advertised.

#![cfg(feature = "kas-client")]

use opentdf_protocol::KasError;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KasTransport {
    /// ConnectRPC endpoints at /kas.AccessService/*
    Connect,
    /// Legacy REST gateway at /kas/v2/*
    LegacyRest,
}

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
    ///
    /// Both resolved URLs are validated for HTTPS / scheme / SSRF constraints
    /// (see [`validate_kas_url`]). This matters because the URLs may originate
    /// from a remotely-fetched well-known document — a hostile document must
    /// not be able to redirect the rewrap request (which carries the OAuth
    /// bearer) at an internal target.
    pub fn from_config(cfg: &OpentdfConfiguration) -> Result<Self, KasError> {
        let kas = cfg.kas.as_ref().ok_or_else(|| KasError::ConfigError {
            reason: "well-known configuration is missing a 'kas' block".to_string(),
        })?;

        let endpoints = if let (Some(rewrap), Some(public_key)) =
            (&kas.connect_rewrap_url, &kas.connect_public_key_url)
        {
            KasEndpoints {
                rewrap_url: rewrap.clone(),
                public_key_url: public_key.clone(),
                transport: KasTransport::Connect,
            }
        } else if let (Some(rewrap), Some(public_key)) = (&kas.rewrap_url, &kas.public_key_url) {
            KasEndpoints {
                rewrap_url: rewrap.clone(),
                public_key_url: public_key.clone(),
                transport: KasTransport::LegacyRest,
            }
        } else {
            return Err(KasError::ConfigError {
                reason: "well-known kas block exposes neither Connect nor REST URLs".to_string(),
            });
        };

        validate_kas_url(&endpoints.rewrap_url)?;
        validate_kas_url(&endpoints.public_key_url)?;

        Ok(endpoints)
    }
}

/// Validate a KAS URL for HTTPS / SSRF / scheme constraints.
///
/// - **Scheme**: only `http` and `https` are accepted.
/// - **HTTPS required**: plain `http` is allowed only for loopback hosts
///   (`localhost`, `127.0.0.0/8`, `::1`) for local development.
/// - **SSRF protection**: private and link-local addresses are rejected,
///   covering IPv4 (`10/8`, `172.16/12`, `192.168/16`, `169.254/16`), IPv6
///   unique-local (`fc00::/7`) and link-local (`fe80::/10`), and IPv4-mapped
///   IPv6 literals (e.g. `::ffff:169.254.169.254`), which are folded back to
///   their IPv4 form before the check.
pub fn validate_kas_url(url_str: &str) -> Result<(), KasError> {
    use std::net::IpAddr;

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

    // Fold any IPv4-mapped IPv6 literal back to IPv4 so `::ffff:169.254.169.254`
    // can't bypass the IPv4 metadata/private-range checks.
    let ip = match parsed.host() {
        Some(url::Host::Ipv4(v4)) => Some(IpAddr::V4(v4)),
        Some(url::Host::Ipv6(v6)) => Some(IpAddr::V6(v6).to_canonical()),
        _ => None,
    };

    if let Some(ip) = ip
        && is_blocked_ip(&ip)
    {
        return Err(KasError::InvalidUrl(
            "KAS URL must not target private or link-local IP addresses".to_string(),
        ));
    }

    Ok(())
}

/// True if `ip` is in a private or link-local range that must never be a KAS
/// target (SSRF guard). Loopback is intentionally *not* blocked here — the
/// scheme check above already gates loopback to HTTP-only dev use.
fn is_blocked_ip(ip: &std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            // Unique-local fc00::/7 or unicast link-local fe80::/10.
            (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
        }
    }
}

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

/// Fetch the platform's `/.well-known/opentdf-configuration` document.
///
/// `platform_url` should be the platform's base URL (e.g.,
/// `"https://platform.arkavo.net"`). A trailing slash is tolerated.
///
/// The request is issued on the caller-provided `http_client` and inherits its
/// configuration. Because this function applies no timeout of its own, the
/// caller should build the client with a `.timeout(..)` so discovery cannot
/// hang indefinitely against an unresponsive endpoint.
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
        assert_eq!(
            cfg.platform_issuer.as_deref(),
            Some("https://identity.arkavo.net")
        );
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
        assert_eq!(
            kas.rewrap_url.as_deref(),
            Some("https://k.example.com/kas/v2/rewrap")
        );
        assert!(cfg.idp.is_none());
    }

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
        assert_eq!(
            endpoints.public_key_url,
            "https://k.example.com/kas/v2/kas_public_key"
        );
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
        assert!(matches!(
            err,
            opentdf_protocol::KasError::ConfigError { .. }
        ));
    }

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
        assert_eq!(
            endpoints.rewrap_url,
            "https://kas.example.com/kas/v2/rewrap"
        );
        assert_eq!(
            endpoints.public_key_url,
            "https://kas.example.com/kas/v2/kas_public_key"
        );
        assert_eq!(endpoints.transport, KasTransport::LegacyRest);
    }

    #[test]
    fn validate_kas_url_accepts_https_and_loopback_http() {
        assert!(validate_kas_url("https://kas.example.com/kas.AccessService/Rewrap").is_ok());
        assert!(validate_kas_url("http://localhost:8080/x").is_ok());
        assert!(validate_kas_url("http://127.0.0.1:8080/x").is_ok());
        assert!(validate_kas_url("http://[::1]:8080/x").is_ok());
    }

    #[test]
    fn validate_kas_url_rejects_non_loopback_http_and_bad_scheme() {
        assert!(matches!(
            validate_kas_url("http://evil.com/x"),
            Err(KasError::InvalidUrl(_))
        ));
        assert!(matches!(
            validate_kas_url("ftp://kas.example.com/x"),
            Err(KasError::InvalidUrl(_))
        ));
    }

    #[test]
    fn validate_kas_url_rejects_ipv4_private_and_link_local() {
        for url in [
            "https://10.0.0.1/x",
            "https://172.16.0.1/x",
            "https://192.168.1.1/x",
            "https://169.254.169.254/x",
        ] {
            assert!(
                matches!(validate_kas_url(url), Err(KasError::InvalidUrl(_))),
                "{url} should be rejected"
            );
        }
    }

    #[test]
    fn validate_kas_url_rejects_ipv6_ula_and_link_local() {
        for url in [
            "https://[fd00::1]/x", // unique-local fc00::/7
            "https://[fc00::1]/x", // unique-local fc00::/7
            "https://[fe80::1]/x", // link-local fe80::/10
        ] {
            assert!(
                matches!(validate_kas_url(url), Err(KasError::InvalidUrl(_))),
                "{url} should be rejected"
            );
        }
    }

    #[test]
    fn validate_kas_url_rejects_ipv4_mapped_metadata_address() {
        // ::ffff:169.254.169.254 must fold back to IPv4 and be rejected,
        // not slip through as an unchecked IPv6 literal.
        assert!(matches!(
            validate_kas_url("https://[::ffff:169.254.169.254]/x"),
            Err(KasError::InvalidUrl(_))
        ));
        assert!(matches!(
            validate_kas_url("https://[::ffff:10.0.0.1]/x"),
            Err(KasError::InvalidUrl(_))
        ));
    }

    #[test]
    fn from_config_rejects_hostile_connect_url() {
        // A well-known document that points the Connect rewrap URL at an
        // internal address must be rejected at resolution time.
        let json = r#"{
            "kas": {
                "uri": "https://platform.example.com",
                "algorithms": [],
                "connect_rewrap_url": "https://169.254.169.254/kas.AccessService/Rewrap",
                "connect_public_key_url": "https://platform.example.com/kas.AccessService/PublicKey"
            }
        }"#;
        let cfg: OpentdfConfiguration = serde_json::from_str(json).unwrap();
        assert!(matches!(
            KasEndpoints::from_config(&cfg),
            Err(KasError::InvalidUrl(_))
        ));
    }

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
}
