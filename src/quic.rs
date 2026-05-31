//! quiche transport + TLS configuration shared by the proxy server and client.
//!
//! Both ends build a `boring::ssl::SslContextBuilder` first — that is the only
//! place ECH keys (server) or the client-side ECH config list (client) can be
//! installed — then hand it to `quiche::Config::with_boring_ssl_ctx_builder`.
//! quiche layers its own ALPN (`h3`) and QUIC transport parameters on top.

use std::path::Path;

use anyhow::{Context, Result, anyhow};
use boring::ssl::{
    SslContextBuilder, SslEchKeys, SslInfoCallbackMode, SslMethod, SslRef, SslVerifyMode,
    SslVersion,
};
use foreign_types_shared::ForeignTypeRef;

use crate::ech::key::EchKeySet;

/// ALPN protocol list quiche offers/selects: HTTP/3 only.
const ALPN_H3: &[&[u8]] = &[b"h3"];
/// Increased initial packet size so tunnelled QUIC (min MTU 1200) fits.
const MAX_UDP_PAYLOAD: usize = 1350;
const IDLE_TIMEOUT_MS: u64 = 30_000;
const DGRAM_QUEUE_LEN: usize = 65536;

/// Apply the QUIC transport parameters common to client and server.
fn apply_transport_params(config: &mut quiche::Config) -> Result<()> {
    config
        .set_application_protos(ALPN_H3)
        .context("setting ALPN h3")?;
    config.set_max_idle_timeout(IDLE_TIMEOUT_MS);
    config.set_max_recv_udp_payload_size(MAX_UDP_PAYLOAD);
    config.set_max_send_udp_payload_size(MAX_UDP_PAYLOAD);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(2_000_000);
    config.set_initial_max_stream_data_bidi_remote(2_000_000);
    config.set_initial_max_stream_data_uni(2_000_000);
    config.set_initial_max_streams_bidi(128);
    config.set_initial_max_streams_uni(128);
    config.set_disable_active_migration(true);
    // HTTP/3 datagrams ride on QUIC DATAGRAM frames.
    config.enable_dgram(true, DGRAM_QUEUE_LEN, DGRAM_QUEUE_LEN);
    Ok(())
}

/// Install ECH keys (server-side termination) onto a context builder. Each pair
/// is advertised as a retry config so stale clients are sent fresh configs.
pub(crate) fn install_ech_keys(builder: &mut SslContextBuilder, ech: &EchKeySet) -> Result<()> {
    let mut keys = SslEchKeys::builder().map_err(|e| anyhow!("SSL_ECH_KEYS_new failed: {e}"))?;
    for pair in &ech.pairs {
        // BoringSSL's only X25519 HPKE constructor is misnamed `dhkem_p256...`;
        // its body uses EVP_hpke_x25519_hkdf_sha256, matching our keygen suite.
        let key = boring::hpke::HpkeKey::dhkem_p256_sha256(&pair.private_key).map_err(|e| {
            anyhow!(
                "invalid ECH HPKE key (config_id 0x{:02x}): {e}",
                pair.config.config_id
            )
        })?;
        keys.add_key(true, &pair.config.encode(), key)
            .map_err(|e| {
                anyhow!(
                    "SSL_ECH_KEYS_add failed (config_id 0x{:02x}): {e}",
                    pair.config.config_id
                )
            })?;
    }
    builder
        .set_ech_keys(&keys.build())
        .map_err(|e| anyhow!("SSL_CTX_set1_ech_keys failed: {e}"))?;
    Ok(())
}

/// Build the server-side quiche config from a cert/key PEM pair, optionally
/// terminating ECH with the supplied key set.
pub fn build_server_config(
    cert_path: &Path,
    key_path: &Path,
    ech: Option<&EchKeySet>,
) -> Result<quiche::Config> {
    let mut builder =
        SslContextBuilder::new(SslMethod::tls()).context("creating BoringSSL server context")?;
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .context("min TLS version")?;
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .context("max TLS version")?;
    builder
        .set_certificate_chain_file(cert_path)
        .with_context(|| format!("loading cert chain {}", cert_path.display()))?;
    builder
        .set_private_key_file(key_path, boring::ssl::SslFiletype::PEM)
        .with_context(|| format!("loading private key {}", key_path.display()))?;
    builder.check_private_key().with_context(|| {
        format!(
            "certificate/key mismatch: {} and {}",
            cert_path.display(),
            key_path.display()
        )
    })?;
    if let Some(ech) = ech {
        install_ech_keys(&mut builder, ech)?;
    }

    let mut config = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, builder)
        .map_err(|e| anyhow!("quiche server config: {e}"))?;
    apply_transport_params(&mut config)?;
    Ok(config)
}

/// How the client verifies the proxy's certificate.
pub enum Verify {
    /// Verify against the system trust store plus an optional extra CA file.
    Roots { ca_file: Option<std::path::PathBuf> },
    /// Skip verification (testing only).
    Insecure,
}

/// Build the client-side quiche config. When `ech_config_list` is set, the
/// client offers Encrypted Client Hello: a context info-callback installs the
/// config list on each fresh `SSL` at handshake start (quiche exposes no
/// per-connection SSL accessor, so this is the injection point — see
/// `quiche-client-ech-via-info-callback` memory).
pub fn build_client_config(
    verify: &Verify,
    ech_config_list: Option<Vec<u8>>,
) -> Result<quiche::Config> {
    let mut builder =
        SslContextBuilder::new(SslMethod::tls()).context("creating BoringSSL client context")?;
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .context("min TLS version")?;
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .context("max TLS version")?;

    match verify {
        Verify::Insecure => builder.set_verify(SslVerifyMode::NONE),
        Verify::Roots { ca_file } => {
            builder.set_verify(SslVerifyMode::PEER);
            if let Some(ca) = ca_file {
                builder
                    .set_ca_file(ca)
                    .with_context(|| format!("loading CA file {}", ca.display()))?;
            }
        }
    }

    if let Some(list) = ech_config_list {
        install_client_ech(&mut builder, list);
    }

    let mut config = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, builder)
        .map_err(|e| anyhow!("quiche client config: {e}"))?;
    apply_transport_params(&mut config)?;
    Ok(config)
}

/// Install the client-side ECH offering: a handshake-start info callback that
/// sets the ECH config list on each fresh `SSL` before its ClientHello is
/// serialized. quiche exposes no per-connection SSL accessor, so this CTX-level
/// callback is the injection point. Shared by `build_client_config` and the
/// end-to-end ECH test so both exercise the same code.
pub(crate) fn install_client_ech(builder: &mut SslContextBuilder, list: Vec<u8>) {
    builder.set_info_callback(move |ssl: &SslRef, mode: SslInfoCallbackMode, _| {
        if mode == SslInfoCallbackMode::HANDSHAKE_START {
            // Reconstruct a &mut SslRef from the live pointer to offer ECH.
            // Sound here: the callback holds the only reference to this SSL
            // during the call.
            let ssl_mut = unsafe { SslRef::from_ptr_mut(ssl.as_ptr()) };
            if let Err(e) = ssl_mut.set_ech_config_list(&list) {
                log::warn!("failed to install client ECH config list: {e}");
            }
        }
    });
}

/// Build the shared HTTP/3 config. Extended CONNECT is advertised so peers may
/// issue CONNECT-UDP requests against us.
pub fn build_h3_config() -> Result<quiche::h3::Config> {
    let mut h3 = quiche::h3::Config::new().map_err(|e| anyhow!("h3 config: {e}"))?;
    h3.enable_extended_connect(true);
    Ok(h3)
}
