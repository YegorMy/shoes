use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

pub(crate) fn create_shadowtls_client_config(
    verify_platform: bool,
    fingerprints: Vec<String>,
    enable_sni: bool,
) -> rustls::ClientConfig {
    if !verify_platform {
        return super::create_client_config(
            false,
            fingerprints,
            Vec::new(),
            enable_sni,
            None,
            true,
        );
    }

    let provider = super::get_crypto_provider();
    let verifier = PlatformTrustVerifier {
        platform: rustls_platform_verifier::Verifier::new(provider.clone()),
        fingerprints: super::process_fingerprints(&fingerprints).unwrap(),
    };
    config_with_platform(verifier, enable_sni)
}

fn config_with_platform(verifier: PlatformTrustVerifier, enable_sni: bool) -> rustls::ClientConfig {
    let mut config = rustls::ClientConfig::builder_with_provider(super::get_crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    config.enable_sni = enable_sni;
    config
}

struct PlatformTrustVerifier {
    platform: Result<rustls_platform_verifier::Verifier, rustls::Error>,
    fingerprints: BTreeSet<Vec<u8>>,
}

impl fmt::Debug for PlatformTrustVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PlatformTrustVerifier { .. }")
    }
}

impl PlatformTrustVerifier {
    fn platform(&self) -> Result<&rustls_platform_verifier::Verifier, rustls::Error> {
        self.platform.as_ref().map_err(|_| {
            rustls::Error::General("platform certificate verifier unavailable".to_owned())
        })
    }
}

impl ServerCertVerifier for PlatformTrustVerifier {
    fn verify_server_cert(
        &self,
        certificate: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let verified =
            self.platform()?
                .verify_server_cert(certificate, intermediates, name, ocsp, now)?;
        if !self.fingerprints.is_empty() {
            let digest =
                aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, certificate.as_ref());
            if !self.fingerprints.contains(digest.as_ref()) {
                return Err(rustls::Error::General(
                    "unknown server fingerprint".to_owned(),
                ));
            }
        }
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.platform()?
            .verify_tls12_signature(message, certificate, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.platform()?
            .verify_tls13_signature(message, certificate, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        match self.platform.as_ref() {
            Ok(verifier) => verifier.supported_verify_schemes(),
            Err(_) => super::get_supported_algorithms().supported_schemes(),
        }
    }
}

#[cfg(test)]
pub(crate) fn create_shadowtls_test_config(
    root: CertificateDer<'static>,
    fingerprints: Vec<String>,
) -> rustls::ClientConfig {
    config_with_platform(
        PlatformTrustVerifier {
            platform: rustls_platform_verifier::Verifier::new_with_extra_roots(
                [root],
                super::get_crypto_provider(),
            ),
            fingerprints: super::process_fingerprints(&fingerprints).unwrap(),
        },
        true,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_platform_verifier_refuses_without_fallback_or_private_details() {
        let verifier = PlatformTrustVerifier {
            platform: Err(rustls::Error::General("private platform diagnostic".into())),
            fingerprints: BTreeSet::new(),
        };
        let error = verifier
            .verify_server_cert(
                &CertificateDer::from(vec![]),
                &[],
                &ServerName::try_from("handshake.test").unwrap(),
                &[],
                UnixTime::now(),
            )
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "unexpected error: platform certificate verifier unavailable"
        );
        assert!(!format!("{verifier:?}").contains("private platform diagnostic"));
    }
}
