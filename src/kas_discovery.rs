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
}
