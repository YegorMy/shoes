#[cfg(any(windows, target_vendor = "apple"))]
use std::sync::Arc;

#[cfg(all(
    any(unix, target_arch = "wasm32"),
    not(target_os = "android"),
    not(target_vendor = "apple"),
))]
mod others;

#[cfg(all(
    any(unix, target_arch = "wasm32"),
    not(target_os = "android"),
    not(target_vendor = "apple"),
))]
pub use others::Verifier;

#[cfg(target_vendor = "apple")]
mod apple;

#[cfg(target_vendor = "apple")]
pub use apple::Verifier;

#[cfg(target_os = "android")]
pub(crate) mod android;

#[cfg(target_os = "android")]
pub use android::Verifier;

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::Verifier;

/// An EKU was invalid for the use case of verifying a server certificate.
///
/// This error is used primarily for tests.
#[cfg_attr(windows, allow(dead_code))] // not used by windows verifier
#[derive(Debug, PartialEq)]
pub(crate) struct EkuError;

impl std::fmt::Display for EkuError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("certificate had invalid extensions")
    }
}

impl std::error::Error for EkuError {}

// Shoes: a bounded description of a verification failure for diagnostics.
// Error text can carry the server name, certificate names or platform
// messages that quote them, so only the error category is logged.
pub(crate) fn failure_category(error: &rustls::Error) -> &'static str {
    use rustls::CertificateError as C;
    match error {
        rustls::Error::InvalidCertificate(error) => match error {
            C::BadEncoding => "invalid certificate: bad encoding",
            C::Expired | C::ExpiredContext { .. } => "invalid certificate: expired",
            C::NotValidYet | C::NotValidYetContext { .. } => {
                "invalid certificate: not valid yet"
            }
            C::Revoked => "invalid certificate: revoked",
            C::UnhandledCriticalExtension => "invalid certificate: unhandled critical extension",
            C::UnknownIssuer => "invalid certificate: unknown issuer",
            C::UnknownRevocationStatus => "invalid certificate: unknown revocation status",
            C::ExpiredRevocationList | C::ExpiredRevocationListContext { .. } => {
                "invalid certificate: expired revocation list"
            }
            C::BadSignature
            | C::UnsupportedSignatureAlgorithmContext { .. }
            | C::UnsupportedSignatureAlgorithmForPublicKeyContext { .. } => {
                "invalid certificate: bad signature"
            }
            C::NotValidForName | C::NotValidForNameContext { .. } => {
                "invalid certificate: not valid for name"
            }
            C::InvalidPurpose | C::InvalidPurposeContext { .. } => {
                "invalid certificate: invalid purpose"
            }
            C::InvalidOcspResponse => "invalid certificate: invalid OCSP response",
            C::ApplicationVerificationFailure => {
                "invalid certificate: application verification failure"
            }
            _ => "invalid certificate: other",
        },
        rustls::Error::InvalidCertRevocationList(_) => "invalid revocation list",
        rustls::Error::General(_) => "general",
        _ => "other",
    }
}

// Log the certificate we are verifying so that we can try and find what may be wrong with it
// if we need to debug a user's situation.
fn log_server_cert(_end_entity: &rustls::pki_types::CertificateDer<'_>) {
    #[cfg(feature = "cert-logging")]
    {
        use base64::Engine;
        log::debug!(
            "verifying certificate: {}",
            base64::engine::general_purpose::STANDARD.encode(_end_entity.as_ref())
        );
    }
}

// Unknown certificate error shorthand. Used when we need to construct an "Other" certificate
// error with a platform specific error message.
#[cfg(any(windows, target_vendor = "apple"))]
fn invalid_certificate(reason: impl Into<String>) -> rustls::Error {
    rustls::Error::InvalidCertificate(rustls::CertificateError::Other(rustls::OtherError(
        Arc::from(Box::from(reason.into())),
    )))
}

/// List of EKUs that one or more of that *must* be in the end-entity certificate.
///
/// Legacy server-gated crypto OIDs are assumed to no longer be in use.
///
/// Currently supported:
/// - id-kp-serverAuth
// TODO: Chromium also allows for `OID_ANY_EKU` on Android.
#[cfg(target_os = "windows")]
// XXX: Windows requires that we NUL terminate EKU strings.
// See https://github.com/rustls/rustls-platform-verifier/issues/126#issuecomment-2306232794.
const ALLOWED_EKUS: &[windows_sys::core::PCSTR] =
    &[windows_sys::Win32::Security::Cryptography::szOID_PKIX_KP_SERVER_AUTH];
#[cfg(target_os = "android")]
pub const ALLOWED_EKUS: &[&std::ffi::CStr] = &[c"1.3.6.1.5.5.7.3.1"];
