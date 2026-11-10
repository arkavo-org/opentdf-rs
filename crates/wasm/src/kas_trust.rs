//! Trust decisions for the KAS URL named by a TDF manifest
//!
//! A TDF is untrusted input, and its manifest names the KAS that holds the
//! key. Decrypting means sending the caller's OAuth bearer token to that KAS,
//! so the manifest must never be allowed to choose where the token goes. The
//! caller supplies the KAS origins it trusts, and the manifest's URL is used
//! only when its origin is one of them.
//!
//! Everything here is pure (no `web_sys`), so it is unit-tested on the host.

use opentdf::TdfManifest;
use thiserror::Error;
use url::{Host, Url};

/// Why a TDF's KAS could not be trusted with the caller's credentials
#[derive(Debug, Error, PartialEq, Eq)]
pub enum KasTrustError {
    /// The manifest has no key access entry, so it names no KAS
    #[error("TDF manifest has no key access entries")]
    NoKeyAccess,

    /// The caller supplied no trusted KAS, which trusts nothing
    #[error("No trusted KAS URLs were supplied; refusing to contact the KAS named by the TDF")]
    EmptyAllowlist,

    /// An entry of the caller's allowlist is not a usable KAS URL
    #[error("Invalid trusted KAS URL '{entry}': {reason}")]
    InvalidAllowlistEntry { entry: String, reason: String },

    /// The manifest's KAS URL is not a usable KAS URL
    #[error("Invalid KAS URL in TDF manifest: {reason}")]
    InvalidManifestUrl { reason: String },

    /// The manifest's KAS URL is well formed but its origin is not allowlisted
    #[error("KAS origin '{origin}' named by the TDF manifest is not in the trusted KAS list")]
    UntrustedKas { origin: String },
}

/// A rewrap endpoint on an allowlisted KAS origin
///
/// Only [`trusted_rewrap_endpoint`] constructs this, so a function that takes
/// one can only send to a KAS the caller trusts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedRewrapEndpoint(String);

impl TrustedRewrapEndpoint {
    /// The absolute URL of the rewrap endpoint
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Scheme, host and port of a KAS URL, with the default port filled in
#[derive(Debug, PartialEq, Eq)]
struct KasOrigin {
    scheme: String,
    host: Host<String>,
    port: u16,
}

/// Resolve the rewrap endpoint for a TDF, or refuse
///
/// The KAS URL is read from the manifest's first key access entry and is
/// accepted only if its origin (scheme, host and port, with default ports
/// filled in) equals the origin of an entry of `allowed_kas_urls`. The
/// comparison is made on parsed URLs, never on string prefixes.
///
/// Both the manifest URL and every allowlist entry must use `https`; `http`
/// is accepted only for loopback hosts (`localhost`, `127.0.0.0/8`, `::1`).
/// URLs carrying userinfo are rejected, as is a manifest URL with a query or
/// fragment. An empty allowlist rejects every TDF.
///
/// Only the origin of an allowlist entry is compared; its path is ignored, and
/// the path of the manifest URL is kept.
pub fn trusted_rewrap_endpoint(
    manifest: &TdfManifest,
    allowed_kas_urls: &[String],
) -> Result<TrustedRewrapEndpoint, KasTrustError> {
    let allowed = parse_allowlist(allowed_kas_urls)?;

    let key_access = manifest
        .encryption_information
        .key_access
        .first()
        .ok_or(KasTrustError::NoKeyAccess)?;

    let kas_url = Url::parse(&key_access.url).map_err(|e| KasTrustError::InvalidManifestUrl {
        reason: e.to_string(),
    })?;
    let origin =
        kas_origin(&kas_url).map_err(|reason| KasTrustError::InvalidManifestUrl { reason })?;

    // The rewrap path is appended to the URL's path, so a query or fragment
    // would swallow it.
    if kas_url.query().is_some() || kas_url.fragment().is_some() {
        return Err(KasTrustError::InvalidManifestUrl {
            reason: "must not contain a query or fragment".to_string(),
        });
    }

    if !allowed.contains(&origin) {
        return Err(KasTrustError::UntrustedKas {
            origin: kas_url.origin().ascii_serialization(),
        });
    }

    Ok(TrustedRewrapEndpoint(rewrap_endpoint(&kas_url)))
}

/// Parse every allowlist entry into an origin, failing on the first bad one
///
/// A malformed entry is an error rather than a skipped entry: it is a
/// configuration mistake the caller should hear about.
fn parse_allowlist(allowed_kas_urls: &[String]) -> Result<Vec<KasOrigin>, KasTrustError> {
    if allowed_kas_urls.is_empty() {
        return Err(KasTrustError::EmptyAllowlist);
    }

    allowed_kas_urls
        .iter()
        .map(|entry| {
            let invalid = |reason: String| KasTrustError::InvalidAllowlistEntry {
                entry: entry.clone(),
                reason,
            };
            let url = Url::parse(entry).map_err(|e| invalid(e.to_string()))?;
            kas_origin(&url).map_err(invalid)
        })
        .collect()
}

/// Extract the origin of a KAS URL, enforcing the scheme and userinfo rules
///
/// Mirrors the scheme rule of `validate_kas_url` in the native client: `https`
/// always, `http` only for loopback hosts.
fn kas_origin(url: &Url) -> Result<KasOrigin, String> {
    let host = url
        .host()
        .ok_or_else(|| "URL has no host".to_string())?
        .to_owned();

    match url.scheme() {
        "https" => {}
        "http" => {
            let is_loopback = match &host {
                Host::Domain(domain) => domain == "localhost",
                Host::Ipv4(ip) => ip.is_loopback(),
                Host::Ipv6(ip) => ip.is_loopback(),
            };
            if !is_loopback {
                return Err("must use HTTPS (HTTP is only allowed for localhost)".to_string());
            }
        }
        scheme => return Err(format!("unsupported URL scheme '{scheme}', must be https")),
    }

    if !url.username().is_empty() || url.password().is_some() {
        return Err("must not contain a username or password".to_string());
    }

    let port = url
        .port_or_known_default()
        .ok_or_else(|| "URL has no port".to_string())?;

    Ok(KasOrigin {
        scheme: url.scheme().to_string(),
        host,
        port,
    })
}

/// Append the rewrap path to a KAS base URL
///
/// The endpoint is serialized from the parsed URL, not from the string that
/// was in the manifest, so the URL that is fetched is the URL that was checked.
fn rewrap_endpoint(kas_url: &Url) -> String {
    let mut endpoint = kas_url.clone();
    let path = format!("{}/v2/rewrap", kas_url.path().trim_end_matches('/'));
    endpoint.set_path(&path);
    endpoint.into()
}

// Each test carries both attributes so it runs under `cargo test` on the host
// and under `wasm-pack test`, which only collects `wasm_bindgen_test`s.
#[cfg(test)]
mod tests {
    use super::*;

    const KAS: &str = "https://kas.example.com";

    fn manifest_for(kas_url: &str) -> TdfManifest {
        TdfManifest::new("0.payload".to_string(), kas_url.to_string())
    }

    fn allow(urls: &[&str]) -> Vec<String> {
        urls.iter().map(|u| u.to_string()).collect()
    }

    fn resolve(kas_url: &str, allowed: &[&str]) -> Result<String, KasTrustError> {
        trusted_rewrap_endpoint(&manifest_for(kas_url), &allow(allowed))
            .map(|endpoint| endpoint.as_str().to_string())
    }

    fn assert_untrusted(kas_url: &str, allowed: &[&str]) {
        let result = resolve(kas_url, allowed);
        assert!(
            matches!(result, Err(KasTrustError::UntrustedKas { .. })),
            "{kas_url} against {allowed:?} should be untrusted, got {result:?}"
        );
    }

    fn assert_invalid_manifest_url(kas_url: &str, allowed: &[&str]) {
        let result = resolve(kas_url, allowed);
        assert!(
            matches!(result, Err(KasTrustError::InvalidManifestUrl { .. })),
            "{kas_url} against {allowed:?} should be an invalid manifest URL, got {result:?}"
        );
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn exact_origin_match_is_trusted() {
        assert_eq!(
            resolve("https://kas.example.com", &[KAS]).unwrap(),
            "https://kas.example.com/v2/rewrap"
        );
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn rewrap_path_is_appended_to_the_manifest_path() {
        for (kas_url, expected) in [
            (
                "https://kas.example.com",
                "https://kas.example.com/v2/rewrap",
            ),
            (
                "https://kas.example.com/",
                "https://kas.example.com/v2/rewrap",
            ),
            (
                "https://kas.example.com/kas",
                "https://kas.example.com/kas/v2/rewrap",
            ),
            (
                "https://kas.example.com/kas/",
                "https://kas.example.com/kas/v2/rewrap",
            ),
        ] {
            assert_eq!(resolve(kas_url, &[KAS]).unwrap(), expected, "{kas_url}");
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn allowlist_entry_path_is_ignored() {
        assert_eq!(
            resolve(
                "https://kas.example.com/kas",
                &["https://kas.example.com/other/"]
            )
            .unwrap(),
            "https://kas.example.com/kas/v2/rewrap"
        );
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn any_allowlist_entry_may_match() {
        assert_eq!(
            resolve(
                "https://kas-b.example.com/kas",
                &["https://kas-a.example.com", "https://kas-b.example.com"]
            )
            .unwrap(),
            "https://kas-b.example.com/kas/v2/rewrap"
        );
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn default_ports_are_normalized() {
        assert!(resolve("https://kas.example.com:443/kas", &[KAS]).is_ok());
        assert!(
            resolve(
                "https://kas.example.com/kas",
                &["https://kas.example.com:443"]
            )
            .is_ok()
        );
        assert!(resolve("http://localhost:80", &["http://localhost"]).is_ok());
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn port_mismatch_is_untrusted() {
        assert_untrusted("https://kas.example.com:8443/kas", &[KAS]);
        assert_untrusted(
            "https://kas.example.com/kas",
            &["https://kas.example.com:8443"],
        );
        assert_untrusted("http://localhost:8081", &["http://localhost:8080"]);
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn scheme_mismatch_is_untrusted() {
        assert_untrusted("http://localhost:8080", &["https://localhost:8080"]);
        assert_untrusted("https://localhost:8080", &["http://localhost:8080"]);
        // Same host, but http defaults to port 80 and https to 443.
        assert_untrusted("https://localhost", &["http://localhost"]);
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn lookalike_hosts_are_untrusted() {
        for kas_url in [
            // The allowlisted origin as a string prefix of the attacker's host.
            "https://kas.example.com.evil.com",
            "https://kas.example.com.evil.com/kas",
            "https://kas.example.comevil.com",
            // The allowlisted host as a suffix of the attacker's host.
            "https://evilkas.example.com",
            "https://evil.kas.example.com",
            "https://evil.com/kas.example.com",
            "https://evil.com/https://kas.example.com",
            // A parent domain, and a trailing-dot variant, are different origins.
            "https://example.com",
            "https://kas.example.com.",
        ] {
            assert_untrusted(kas_url, &[KAS]);
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn userinfo_cannot_disguise_the_host() {
        // The host here is evil.com; everything before '@' is userinfo.
        assert_invalid_manifest_url("https://kas.example.com@evil.com", &[KAS]);
        assert_invalid_manifest_url("https://kas.example.com:443@evil.com/kas", &[KAS]);
        assert_invalid_manifest_url("https://kas.example.com%2Fkas@evil.com", &[KAS]);
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn userinfo_is_rejected_even_on_an_allowlisted_origin() {
        assert_invalid_manifest_url("https://user@kas.example.com", &[KAS]);
        assert_invalid_manifest_url("https://user:pass@kas.example.com/kas", &[KAS]);
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn backslash_and_control_characters_do_not_confuse_the_host() {
        // A backslash is a path separator in http(s) URLs, so the host is
        // kas.example.com and the rest is path.
        assert_eq!(
            resolve("https://kas.example.com\\@evil.com", &[KAS]).unwrap(),
            "https://kas.example.com/@evil.com/v2/rewrap"
        );
        // Here the host is evil.com.
        assert_untrusted("https://evil.com\\@kas.example.com", &[KAS]);
        // Tabs and newlines are stripped before parsing.
        assert_untrusted("https://kas.example.com\t.evil.com", &[KAS]);
        assert_untrusted("https://kas.example.com\n.evil.com", &[KAS]);
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn dot_segments_cannot_escape_the_origin() {
        assert_eq!(
            resolve("https://kas.example.com/a/../../kas", &[KAS]).unwrap(),
            "https://kas.example.com/kas/v2/rewrap"
        );
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn host_comparison_is_case_insensitive() {
        assert_eq!(
            resolve("HTTPS://KAS.Example.COM/kas", &[KAS]).unwrap(),
            "https://kas.example.com/kas/v2/rewrap"
        );
        assert!(resolve("https://kas.example.com/kas", &["https://KAS.EXAMPLE.COM"]).is_ok());
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn non_loopback_http_is_rejected() {
        assert_invalid_manifest_url("http://kas.example.com", &[KAS]);
        assert_invalid_manifest_url("http://192.168.1.10:8080", &[KAS]);
        assert_invalid_manifest_url("http://localhost.evil.com", &["http://localhost"]);
        assert_invalid_manifest_url("http://localhost.", &["http://localhost"]);
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn non_loopback_http_cannot_be_allowlisted() {
        let result = resolve("http://kas.example.com", &["http://kas.example.com"]);
        assert!(
            matches!(result, Err(KasTrustError::InvalidAllowlistEntry { .. })),
            "got {result:?}"
        );
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn loopback_http_is_allowed_when_allowlisted() {
        for kas_url in [
            "http://localhost:8080/kas",
            "http://127.0.0.1:8080/kas",
            "http://[::1]:8080/kas",
        ] {
            let allowed = kas_url.trim_end_matches("/kas");
            assert_eq!(
                resolve(kas_url, &[allowed]).unwrap(),
                format!("{kas_url}/v2/rewrap")
            );
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn loopback_hosts_are_distinct_origins() {
        assert_untrusted("http://127.0.0.1:8080", &["http://localhost:8080"]);
        assert_untrusted("http://[::1]:8080", &["http://127.0.0.1:8080"]);
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn loopback_is_not_trusted_unless_allowlisted() {
        assert_untrusted("http://localhost:8080/kas", &[KAS]);
        assert_untrusted("http://127.0.0.1:8080/kas", &[KAS]);
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn alternate_ipv4_spellings_are_normalized() {
        // All of these are 127.0.0.1 once parsed.
        for kas_url in [
            "http://0x7f.0.0.1:8080",
            "http://2130706433:8080",
            "http://127.1:8080",
        ] {
            assert!(
                resolve(kas_url, &["http://127.0.0.1:8080"]).is_ok(),
                "{kas_url}"
            );
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn unsupported_schemes_are_rejected() {
        for kas_url in [
            "ftp://kas.example.com",
            "ws://kas.example.com",
            "wss://kas.example.com",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/plain,kas.example.com",
        ] {
            assert_invalid_manifest_url(kas_url, &[KAS]);
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn unparseable_manifest_urls_are_rejected() {
        for kas_url in [
            "",
            "kas.example.com",
            "//kas.example.com",
            "/kas",
            "https://",
        ] {
            assert_invalid_manifest_url(kas_url, &[KAS]);
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn query_and_fragment_are_rejected() {
        assert_invalid_manifest_url("https://kas.example.com/kas?next=", &[KAS]);
        assert_invalid_manifest_url("https://kas.example.com/kas#", &[KAS]);
        assert_invalid_manifest_url("https://kas.example.com?", &[KAS]);
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn empty_allowlist_rejects_everything() {
        assert_eq!(
            resolve("https://kas.example.com", &[]),
            Err(KasTrustError::EmptyAllowlist)
        );
        assert_eq!(
            resolve("http://localhost:8080", &[]),
            Err(KasTrustError::EmptyAllowlist)
        );
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn invalid_allowlist_entries_are_errors() {
        for entry in [
            "",
            "*",
            "kas.example.com",
            "https://",
            "ftp://kas.example.com",
            "https://user:pass@kas.example.com",
        ] {
            let result = resolve("https://kas.example.com", &[KAS, entry]);
            assert!(
                matches!(result, Err(KasTrustError::InvalidAllowlistEntry { .. })),
                "allowlist entry {entry:?} should be invalid, got {result:?}"
            );
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn empty_key_access_is_an_error() {
        let mut manifest = manifest_for(KAS);
        manifest.encryption_information.key_access.clear();
        assert_eq!(
            trusted_rewrap_endpoint(&manifest, &allow(&[KAS])),
            Err(KasTrustError::NoKeyAccess)
        );
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn only_the_first_key_access_entry_selects_the_kas() {
        use opentdf::manifest::KeyAccess;

        let mut manifest = manifest_for("https://evil.com");
        manifest
            .encryption_information
            .key_access
            .push(KeyAccess::new(KAS.to_string()));
        assert!(matches!(
            trusted_rewrap_endpoint(&manifest, &allow(&[KAS])),
            Err(KasTrustError::UntrustedKas { .. })
        ));
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn untrusted_error_names_the_parsed_origin() {
        assert_eq!(
            resolve("https://kas.example.com.evil.com/kas", &[KAS]),
            Err(KasTrustError::UntrustedKas {
                origin: "https://kas.example.com.evil.com".to_string()
            })
        );
        assert_eq!(
            resolve("https://kas.example.com:8443/kas", &[KAS]),
            Err(KasTrustError::UntrustedKas {
                origin: "https://kas.example.com:8443".to_string()
            })
        );
    }
}
