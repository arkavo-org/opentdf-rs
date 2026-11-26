//! Integration tests verifying that `opentdf` composes cleanly with
//! [`crypto-profile-awslc4`](https://github.com/crypto-profile/crypto-profile)
//! over AWS-LC FIPS 4.x with no `ring` or stock `rustls` providers.

use crypto_profile_awslc4 as crypto;
use opentdf::KasError;
use opentdf::kas::KasClient;
use opentdf::kas_discovery::OpentdfConfiguration;

/// Build a [`KasClient`] whose TLS transport is governed by a `crypto-profile`
/// [`crypto::rustls::ClientConfig`].
pub fn kas_client_with_tls(
    config: &OpentdfConfiguration,
    oauth_token: impl Into<String>,
    tls_config: crypto::rustls::ClientConfig,
    extra: impl FnOnce(reqwest::ClientBuilder) -> reqwest::ClientBuilder,
) -> Result<KasClient, KasError> {
    let builder = extra(reqwest::Client::builder().use_preconfigured_tls(tls_config));
    KasClient::with_http_client_builder(config, oauth_token, builder)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::rustls::pki_types::CertificateDer;
    use crypto::rustls::sign::SingleCertAndKey;
    use crypto::rustls::{ClientConfig, NamedGroup, ProtocolVersion, RootCertStore, ServerConfig};
    use crypto::{Options, Profile, SignatureAlgorithm, admit, fips, resolve, signature, tls};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    struct TestPki {
        roots: RootCertStore,
        chain: Vec<CertificateDer<'static>>,
        leaf_key: tls::CertificateKey,
    }

    fn generate_localhost_pki(resolved: &crypto::Resolved) -> TestPki {
        let admitted = admit(Profile::Preferred, Options::default());
        let ca_key = signature::KeyPair::generate(&admitted, SignatureAlgorithm::EcdsaP384Sha384)
            .expect("generate P-384 CA key");
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA params");
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "opentdf crypto-profile test CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign CA");
        let issuer = rcgen::Issuer::new(ca_params, &ca_key);

        let leaf_key = tls::CertificateKey::generate(resolved, SignatureAlgorithm::EcdsaP384Sha384)
            .expect("generate P-384 TLS leaf key");
        let leaf_der = leaf_key.to_pkcs8_der().expect("export leaf PKCS#8");
        let rcgen_leaf = signature::KeyPair::from_pkcs8_der(
            &admitted,
            SignatureAlgorithm::EcdsaP384Sha384,
            &leaf_der,
        )
        .expect("import leaf key for cert issuance");
        let leaf_cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("leaf params")
            .signed_by(&rcgen_leaf, &issuer)
            .expect("sign leaf cert");

        let mut roots = RootCertStore::empty();
        roots.add(ca_cert.der().clone()).expect("add CA root");

        TestPki {
            roots,
            chain: vec![leaf_cert.der().clone(), ca_cert.der().clone()],
            leaf_key,
        }
    }

    fn build_tls_pair() -> (ClientConfig, ServerConfig) {
        let mut options = Options::default();
        options.pq_key_exchange_required = true;
        let resolved = resolve(Profile::Preferred, options).expect("resolve Preferred profile");
        let pki = generate_localhost_pki(&resolved);

        let certified = resolved
            .certified_key(pki.chain, &pki.leaf_key)
            .expect("build certified key");
        let server_config = tls::server_builder(&resolved.tls)
            .expect("server builder")
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));
        fips::assert_fips_server_config(&server_config).expect("server config is FIPS-classified");

        let client_config = tls::client_builder(&resolved.tls)
            .expect("client builder")
            .with_root_certificates(pki.roots)
            .with_no_client_auth();
        fips::assert_fips_client_config(&client_config).expect("client config is FIPS-classified");

        (client_config, server_config)
    }

    async fn spawn_https_once(
        server_config: ServerConfig,
        http_response: String,
    ) -> (
        SocketAddr,
        tokio::task::JoinHandle<(Option<ProtocolVersion>, bool)>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback listener");
        let addr = listener.local_addr().expect("local addr");
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let handle = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept TCP");
            let mut tls_stream = acceptor.accept(tcp).await.expect("TLS handshake");
            let version = tls_stream.get_ref().1.protocol_version();
            let negotiated_kx = tls_stream
                .get_ref()
                .1
                .negotiated_key_exchange_group()
                .map(|g| g.name());
            let is_pq = matches!(
                negotiated_kx,
                Some(
                    NamedGroup::MLKEM1024
                        | NamedGroup::Unknown(0x11ED)
                        | NamedGroup::X25519MLKEM768
                        | NamedGroup::secp256r1MLKEM768
                )
            );

            // Read HTTP request headers + body (small single-shot JSON POST).
            let mut buf = vec![0u8; 8192];
            let _ = tls_stream.read(&mut buf).await.expect("read request");
            tls_stream
                .write_all(http_response.as_bytes())
                .await
                .expect("write response");
            tls_stream.shutdown().await.expect("TLS shutdown");
            (version, is_pq)
        });

        (addr, handle)
    }

    #[test]
    fn fips_module_is_active_in_process() {
        fips::assert_fips_module().expect("AWS-LC FIPS module must be active");
    }

    #[tokio::test]
    async fn kas_client_rewraps_over_crypto_profile_tls13_pq() {
        fips::assert_fips_module().expect("AWS-LC FIPS module must be active");
        let (client_config, server_config) = build_tls_pair();

        const BODY: &str = r#"{"responses":[{"policyId":"p","results":[{"keyAccessObjectId":"kao-0","status":"permit","entityWrappedKey":"AQIDBA=="}]}]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            BODY.len(),
            BODY
        );
        let (addr, server_handle) = spawn_https_once(server_config, response).await;

        let kas_url = format!("https://localhost:{}", addr.port());
        let cfg = OpentdfConfiguration::for_kas_connect(&kas_url);
        let client = kas_client_with_tls(&cfg, "token", client_config, |b| {
            b.resolve("localhost", addr)
        })
        .expect("build KasClient with crypto-profile TLS");

        let dek = client
            .rewrap_nanotdf(b"header", &kas_url)
            .await
            .expect("rewrap over TLS 1.3 + PQ");
        assert_eq!(dek, vec![1, 2, 3, 4]);

        let (version, is_pq) = server_handle.await.expect("server task");
        assert_eq!(version, Some(ProtocolVersion::TLSv1_3));
        assert!(
            is_pq,
            "expected post-quantum key exchange under Preferred profile"
        );
    }

    #[tokio::test]
    async fn kas_client_builder_refuses_redirects_over_crypto_profile_https() {
        let (client_config, server_config) = build_tls_pair();
        let (addr, server_handle) = spawn_https_once(
            server_config,
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: https://evil.example/steal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_string(),
        )
        .await;

        let kas_url = format!("https://localhost:{}", addr.port());
        let cfg = OpentdfConfiguration::for_kas_connect(&kas_url);
        let client = kas_client_with_tls(&cfg, "token", client_config, |b| {
            b.resolve("localhost", addr)
                .redirect(reqwest::redirect::Policy::limited(5))
        })
        .expect("build KasClient");

        let err = client
            .rewrap_nanotdf(b"header", &kas_url)
            .await
            .expect_err("307 redirect must be refused");
        assert!(
            matches!(err, KasError::HttpError { status: 307, .. }),
            "expected HTTP 307 refusal, got: {err:?}"
        );

        let (version, _) = server_handle.await.expect("server task");
        assert_eq!(version, Some(ProtocolVersion::TLSv1_3));
    }
}
