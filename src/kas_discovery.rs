//! KAS endpoint discovery via /.well-known/opentdf-configuration
//!
//! Provides types for deserializing the platform's well-known configuration
//! document, plus URL-resolution logic that prefers ConnectRPC endpoints
//! and falls back to legacy REST paths when only REST is advertised.

#![cfg(feature = "kas-client")]

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
}
