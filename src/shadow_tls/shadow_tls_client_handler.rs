use std::io::Cursor;
use std::sync::Arc;

use async_trait::async_trait;
use subtle::ConstantTimeEq;
use tokio::io::AsyncWriteExt;

use crate::address::ResolvedLocation;
use crate::async_stream::AsyncMessageStream;
use crate::async_stream::AsyncStream;
use crate::rustls_connection_util::feed_rustls_client_connection;
use crate::shadow_tls::shadow_tls_hmac::ShadowTlsHmac;
use crate::shadow_tls::shadow_tls_stream::ShadowTlsStream;
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_handler::{TcpClientHandler, TcpClientSetupResult};
use crate::util::{allocate_vec, write_all};

use super::shadow_tls_server_handler::parse_validated_server_hello;

// Constants from shadow_tls_server_handler
// TODO: deduplicate consts
const TLS_HEADER_LEN: usize = 5;
const TLS_FRAME_MAX_LEN: usize = TLS_HEADER_LEN + 65535;
const CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;
const CONTENT_TYPE_ALERT: u8 = 0x15;

// Handshake message types
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;

struct ShadowTlsXorContext(aws_lc_rs::digest::Context);

impl std::fmt::Debug for ShadowTlsXorContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[ShadowTlsXorContext]")
    }
}

#[derive(Debug)]
pub struct ShadowTlsClientHandler {
    initial_hmac: ShadowTlsHmac,
    initial_xor_context: ShadowTlsXorContext,
    client_config: Arc<rustls::ClientConfig>,
    server_name: rustls::pki_types::ServerName<'static>,
    handler: Box<dyn TcpClientHandler>,
}

impl ShadowTlsClientHandler {
    pub fn new(
        password: String,
        client_config: Arc<rustls::ClientConfig>,
        server_name: rustls::pki_types::ServerName<'static>,
        handler: Box<dyn TcpClientHandler>,
    ) -> Self {
        let password_bytes = password.into_bytes();
        let hmac_key = aws_lc_rs::hmac::Key::new(
            aws_lc_rs::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            &password_bytes,
        );
        let initial_hmac = ShadowTlsHmac::new(&hmac_key);
        let mut initial_xor_context = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
        initial_xor_context.update(&password_bytes);
        let mut client_config = (*client_config).clone();
        let hello_hmac = initial_hmac.clone();
        client_config.set_client_hello_session_id_generator(move |hello| {
            signed_session_id(hello, &hello_hmac)
        });
        Self {
            initial_hmac,
            initial_xor_context: ShadowTlsXorContext(initial_xor_context),
            client_config: Arc::new(client_config),
            server_name,
            handler,
        }
    }

    async fn setup_client_stream_common(
        &self,
        mut client_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<ShadowTlsStream> {
        let mut client_conn =
            rustls::ClientConnection::new(self.client_config.clone(), self.server_name.clone())
                .map_err(|e| {
                    std::io::Error::other(format!("Failed to create ClientConnection: {e}"))
                })?;

        let mut client_hello_buf = Vec::with_capacity(512); // Typical ClientHello
        if client_conn.wants_write() {
            client_conn.write_tls(&mut Cursor::new(&mut client_hello_buf))?;
        }
        if client_hello_buf.is_empty() {
            return Err(std::io::Error::other(
                "rustls::ClientConnection did not produce ClientHello",
            ));
        }

        write_all(&mut client_stream, &client_hello_buf).await?;
        client_stream.flush().await?;

        let mut remote_reader = StreamReader::new_with_buffer_size(TLS_FRAME_MAX_LEN * 2);

        let mut frame_buf = allocate_vec(TLS_FRAME_MAX_LEN);

        let server_hello_frame =
            read_tls_frame(&mut remote_reader, &mut client_stream, &mut frame_buf).await?;

        let parsed_server_hello = parse_validated_server_hello(server_hello_frame)?;
        if !parsed_server_hello.is_tls13 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ShadowTLS requires TLS 1.3",
            ));
        }

        feed_rustls_client_connection(&mut client_conn, server_hello_frame)?;
        client_conn.process_new_packets().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to process ServerHello frame: {e}"),
            )
        })?;

        let mut hmac_server_random = self.initial_hmac.clone();
        hmac_server_random.update(&parsed_server_hello.server_random);

        let mut hmac_client_data = hmac_server_random.clone();
        hmac_client_data.update(b"C");

        let mut hmac_server_data = hmac_server_random.clone();
        hmac_server_data.update(b"S");
        let server_app_data_xor = {
            let mut context = self.initial_xor_context.0.clone();
            context.update(&parsed_server_hello.server_random);
            context.finish()
        };
        let mut authenticated_server = false;

        while client_conn.is_handshaking() {
            if client_conn.wants_write() {
                let mut cursor = Cursor::new(&mut frame_buf[..]);
                match client_conn.write_tls(&mut cursor) {
                    Ok(n) if n > 0 => {
                        write_all(&mut client_stream, &frame_buf[..n]).await?;
                        client_stream.flush().await?;
                    }
                    Ok(_) => { /* wrote 0 bytes */ }
                    Err(e) => {
                        return Err(std::io::Error::other(format!(
                            "rustls write_tls error: {e}"
                        )));
                    }
                }
                continue;
            }

            let server_frame =
                read_tls_frame(&mut remote_reader, &mut client_stream, &mut frame_buf).await?;
            let content_type = server_frame[0];

            if content_type == CONTENT_TYPE_APPLICATION_DATA {
                let payload_len = u16::from_be_bytes([server_frame[3], server_frame[4]]) as usize;
                if payload_len < 4 + 1 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "app data record too short for handshake data",
                    ));
                }

                let received_hmac = &server_frame[TLS_HEADER_LEN..TLS_HEADER_LEN + 4];
                let data_after_hmac =
                    &server_frame[TLS_HEADER_LEN + 4..TLS_HEADER_LEN + payload_len];

                hmac_server_random.update(data_after_hmac);
                if !bool::from(hmac_server_random.digest().as_slice().ct_eq(received_hmac)) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid HMAC for handshake data",
                    ));
                }

                authenticated_server = true;
                let mut tls_frame = Vec::with_capacity(server_frame.len() - 4);
                tls_frame.extend_from_slice(&server_frame[..TLS_HEADER_LEN]);
                tls_frame[3..5].copy_from_slice(&((payload_len - 4) as u16).to_be_bytes());
                tls_frame.extend(
                    data_after_hmac
                        .iter()
                        .zip(server_app_data_xor.as_ref().iter().cycle())
                        .map(|(byte, key)| byte ^ key),
                );
                feed_rustls_client_connection(&mut client_conn, &tls_frame)?;
                client_conn.process_new_packets().map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("ShadowTLS certificate handshake failed: {e}"),
                    )
                })?;
                continue;
            }

            if content_type == CONTENT_TYPE_ALERT {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unexpected alert frame from ShadowTLS server during handshake",
                ));
            }

            feed_rustls_client_connection(&mut client_conn, server_frame)?;
            client_conn.process_new_packets().map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("failed to process handshake frame of type {content_type}: {e}"),
                )
            })?;
        }

        if !authenticated_server {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ShadowTLS server authentication missing",
            ));
        }
        // Certificate/Finished validation precedes inner traffic; forward our
        // Finished even when rustls has already left its handshaking state.
        while client_conn.wants_write() {
            let mut pending = Vec::new();
            client_conn.write_tls(&mut pending)?;
            write_all(&mut client_stream, &pending).await?;
        }
        client_stream.flush().await?;

        let mut shadow_tls_stream = ShadowTlsStream::new(
            client_stream,
            &[],
            hmac_server_data,
            hmac_client_data,
            Some(hmac_server_random),
        )?;

        // Feeds any unconsumed data from StreamReader from handshake phase
        let unparsed_handshake_data = remote_reader.unparsed_data();
        if !unparsed_handshake_data.is_empty() {
            shadow_tls_stream.feed_initial_read_data(unparsed_handshake_data)?;
        }

        Ok(shadow_tls_stream)
    }
}

#[async_trait]
impl TcpClientHandler for ShadowTlsClientHandler {
    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let shadow_tls_stream = self.setup_client_stream_common(client_stream).await?;
        self.handler
            .setup_client_tcp_stream(Box::new(shadow_tls_stream), remote_location)
            .await
    }

    fn supports_udp_over_tcp(&self) -> bool {
        self.handler.supports_udp_over_tcp()
    }

    async fn setup_client_udp_bidirectional(
        &self,
        client_stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        let shadow_tls_stream = self.setup_client_stream_common(client_stream).await?;
        self.handler
            .setup_client_udp_bidirectional(Box::new(shadow_tls_stream), target)
            .await
    }
}

// Sign the handshake bytes before rustls records them in its transcript.
fn signed_session_id(
    client_hello: &[u8],
    initial_hmac: &ShadowTlsHmac,
) -> Result<[u8; 32], rustls::Error> {
    const SESSION_ID_START: usize = 39;
    const SESSION_ID_END: usize = SESSION_ID_START + 32;
    const TAG_START: usize = SESSION_ID_END - 4;
    if client_hello.len() < SESSION_ID_END
        || client_hello[0] != HANDSHAKE_TYPE_CLIENT_HELLO
        || client_hello[4..6] != [3, 3]
        || client_hello[SESSION_ID_START - 1] != 32
        || u32::from_be_bytes([0, client_hello[1], client_hello[2], client_hello[3]]) as usize
            != client_hello.len() - 4
    {
        return Err(rustls::Error::General(
            "unsupported ShadowTLS ClientHello".into(),
        ));
    }
    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&client_hello[SESSION_ID_START..SESSION_ID_END]);
    let mut hmac = initial_hmac.clone();
    hmac.update(&client_hello[..TAG_START]);
    hmac.update(&[0; 4]);
    hmac.update(&client_hello[SESSION_ID_END..]);
    session_id[28..].copy_from_slice(&hmac.finalized_digest());
    Ok(session_id)
}

#[inline]
async fn read_tls_frame<'a>(
    reader: &mut StreamReader,
    stream: &mut Box<dyn AsyncStream>,
    read_buf: &'a mut [u8],
) -> std::io::Result<&'a [u8]> {
    let header_bytes = reader.read_slice(stream, TLS_HEADER_LEN).await?;

    let payload_len = u16::from_be_bytes([header_bytes[3], header_bytes[4]]) as usize;
    if payload_len > TLS_FRAME_MAX_LEN - TLS_HEADER_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "TLS frame payload too large",
        ));
    }

    read_buf[0..TLS_HEADER_LEN].copy_from_slice(header_bytes);

    let payload_bytes = reader.read_slice(stream, payload_len).await?;
    read_buf[TLS_HEADER_LEN..TLS_HEADER_LEN + payload_len].copy_from_slice(payload_bytes);

    Ok(&read_buf[..TLS_HEADER_LEN + payload_len])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ClientProxyConfig, Config, create_server_configs};
    use crate::resolver::{NativeResolver, Resolver};
    use crate::tcp::tcp_client_handler_factory::create_tcp_client_handler;
    use crate::tcp::tcp_server::start_servers;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    async fn trusted_handshake(
        cert_name: &str,
        platform: bool,
        mismatch_pin: bool,
    ) -> std::io::Result<ShadowTlsStream> {
        let password = "webpki-flight-test-password";
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(vec!["test-ca".into()]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = rcgen::CertificateParams::new(vec![cert_name.into()])
            .unwrap()
            .signed_by(&leaf_key, &rcgen::Issuer::from_params(&ca_params, &ca_key))
            .unwrap();
        let indent = |pem: &str| {
            pem.lines()
                .map(|line| format!("            {line}\n"))
                .collect::<String>()
        };
        let reservation = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let yaml = format!(
            "- address: \"127.0.0.1:{port}\"\n  protocol:\n    type: tls\n    shadowtls_targets:\n      handshake.test:\n        password: \"{password}\"\n        handshake:\n          cert: |\n{}          key: |\n{}        protocol:\n          type: shadowsocks\n          cipher: aes-128-gcm\n          password: inner-test-password\n",
            indent(&leaf.pem()),
            indent(&leaf_key.serialize_pem())
        );
        let configs: Vec<Config> = serde_yaml::from_str(&yaml).unwrap();
        let config = create_server_configs(configs).unwrap().configs.remove(0);
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let handles = start_servers(config, resolver.clone()).await.unwrap();
        let config = if platform {
            crate::rustls_config_util::create_shadowtls_test_config(
                ca.der().clone(),
                if mismatch_pin {
                    vec!["00".repeat(32)]
                } else {
                    Vec::new()
                },
            )
        } else {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(ca.der().clone()).unwrap();
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth()
        };
        let inner: ClientProxyConfig = serde_yaml::from_str(
            "type: shadowsocks\ncipher: aes-128-gcm\npassword: inner-test-password\n",
        )
        .unwrap();
        let handler = ShadowTlsClientHandler::new(
            password.into(),
            Arc::new(config),
            "handshake.test".try_into().unwrap(),
            create_tcp_client_handler(inner, None, resolver),
        );
        let ready_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let stream = loop {
            match tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await {
                Ok(stream) => break stream,
                Err(error)
                    if error.kind() == std::io::ErrorKind::ConnectionRefused
                        && tokio::time::Instant::now() < ready_deadline =>
                {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => panic!("local engine listener failed to bind: {error}"),
            }
        };
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            handler.setup_client_stream_common(Box::new(stream)),
        )
        .await
        .expect("local certificate flight must terminate");
        for handle in handles {
            handle.abort();
        }
        result
    }

    #[tokio::test]
    async fn shadowtls_webpki_verifies_the_actual_ca_signed_certificate_flight() {
        assert!(
            trusted_handshake("handshake.test", false, false)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn shadowtls_webpki_rejects_wrong_name_in_the_actual_trusted_flight() {
        let result = trusted_handshake("other.test", false, false).await;
        let error = match result {
            Ok(_) => panic!("wrong certificate identity was accepted"),
            Err(e) => e,
        };
        assert!(
            error.to_string().contains("certificate not valid for name"),
            "{error}"
        );
        assert!(!error.to_string().contains("webpki-flight-test-password"));
    }

    #[tokio::test]
    async fn shadowtls_platform_verifies_the_actual_ca_signed_certificate_flight() {
        assert!(
            trusted_handshake("handshake.test", true, false)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn shadowtls_platform_rejects_wrong_name_in_the_actual_trusted_flight() {
        let error = match trusted_handshake("other.test", true, false).await {
            Ok(_) => panic!("wrong certificate identity was accepted"),
            Err(error) => error,
        };
        let message = error.to_string();
        assert!(
            message.contains("NotValidForName")
                || message.contains("certificate not valid for name"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn shadowtls_platform_and_pin_both_apply_in_the_actual_trusted_flight() {
        let error = match trusted_handshake("handshake.test", true, true).await {
            Ok(_) => panic!("platform trust bypassed the mismatching pin"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("unknown server fingerprint"),
            "{error}"
        );
    }
}
