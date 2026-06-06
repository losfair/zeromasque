//! quiche transport + TLS configuration shared by the proxy server and client.
//!
//! Both ends build a `boring::ssl::SslContextBuilder` first — that is the only
//! place ECH keys (server) or the client-side ECH config list (client) can be
//! installed — then hand it to `quiche::Config::with_boring_ssl_ctx_builder`.
//! quiche layers its own ALPN (`h3`) and QUIC transport parameters on top.

use std::path::Path;

use anyhow::{Context, Result, anyhow};
use boring::ssl::{
    NameType, SelectCertError, SslContextBuilder, SslEchKeys, SslInfoCallbackMode, SslMethod,
    SslRef, SslVerifyMode, SslVersion,
};
use foreign_types_shared::ForeignTypeRef;

use crate::ech::key::EchKeySet;

/// ALPN protocol list quiche offers/selects: HTTP/3 only.
const ALPN_H3: &[&[u8]] = &[b"h3"];
/// Outer (client<->proxy) QUIC packet size ceiling. Sized so a full 1280-MTU
/// inner datagram survives the trip: a 1280-byte IPv6 packet inside WireGuard is
/// a 1312-byte UDP payload (16B header + 16B tag), plus our 2B HTTP-datagram
/// prefix = 1314B that must fit in one QUIC DATAGRAM frame (which cannot be
/// fragmented). The binding direction is proxy->client, whose short header
/// carries the client's 20-byte connection ID; at 1400 the writable datagram is
/// ~1358B, clearing 1314 with margin. The underlying client<->proxy path must
/// therefore carry ~1450-byte IP packets unfragmented (and quiche's DPLPMTUD
/// must probe up to this ceiling); where it cannot, oversize flows are dropped
/// and warned about at the send sites. 1280-MTU inner tunnels (e.g. IPv6
/// WireGuard) cannot go lower, so the budget has to absorb them here.
pub(crate) const MAX_UDP_PAYLOAD: usize = 1400;

/// Output buffer size for `conn.send()`. MUST be at least [`MAX_UDP_PAYLOAD`]
/// (the configured `max_send_udp_payload_size`): quiche admits a DATAGRAM into
/// its send queue based on `dgram_max_writable_len()` (derived from
/// `max_send_udp_payload_size`), but can only serialize it into a packet that
/// fits this buffer. A smaller buffer lets quiche queue a datagram it can never
/// emit — it sticks at the head of the FIFO datagram queue and silently blocks
/// every datagram behind it forever (only a reconnect clears it). So size the
/// buffer to the payload ceiling.
pub(crate) const MAX_DATAGRAM_SIZE: usize = MAX_UDP_PAYLOAD;

/// Structured-field value `?1` (Boolean true) for the `capsule-protocol` header
/// carried on every CONNECT-UDP request and response.
pub(crate) const CAPSULE_PROTOCOL_TRUE: &[u8] = b"?1";

const IDLE_TIMEOUT_MS: u64 = 10_000;
const DGRAM_QUEUE_LEN: usize = 65536;

/// Size requested (per direction) for every UDP socket's kernel buffers.
///
/// The whole tunnel is one QUIC connection; on a high-RTT path its
/// bandwidth-delay product is large (e.g. 20 Mbit/s × 270 ms ≈ 675 KB). The
/// default socket buffer (~208 KB on stock Linux) is far smaller, so an
/// in-flight burst overflows it and packets are dropped. Because CONNECT-UDP
/// rides *unreliable* QUIC DATAGRAMs (no retransmission), every such drop
/// surfaces as loss to the tunnelled protocol — and at high RTT even a few
/// percent loss collapses an inner TCP flow (Mathis: BW ≈ MSS/(RTT·√p)). Sizing
/// the buffers to absorb the BDP is the single biggest throughput lever.
///
/// NOTE: the kernel clamps the effective size to `net.core.rmem_max` /
/// `wmem_max`. On stock Linux those default to ~208 KB, which would silently cap
/// this request — operators on high-RTT links must raise them (see README).
const SOCKET_BUFFER_BYTES: libc::c_int = 8 * 1024 * 1024;

/// Set a C-`int`-valued socket option via `setsockopt(2)`. Shared by the buffer
/// sizing, `SO_MARK`, and `IP_TRANSPARENT` paths.
#[cfg(unix)]
pub(crate) fn set_sockopt_int(
    fd: std::os::fd::RawFd,
    level: libc::c_int,
    optname: libc::c_int,
    value: libc::c_int,
) -> std::io::Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            optname,
            &value as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Enlarge a UDP socket's send and receive buffers to [`SOCKET_BUFFER_BYTES`]
/// (best effort; failures are logged, not fatal). Call right after binding.
#[cfg(unix)]
pub(crate) fn enlarge_udp_buffers(sock: &impl std::os::fd::AsRawFd) {
    let fd = sock.as_raw_fd();
    for (opt, name) in [
        (libc::SO_RCVBUF, "SO_RCVBUF"),
        (libc::SO_SNDBUF, "SO_SNDBUF"),
    ] {
        if let Err(e) = set_sockopt_int(fd, libc::SOL_SOCKET, opt, SOCKET_BUFFER_BYTES) {
            log::debug!("setsockopt {name} failed: {e}");
        }
    }
}

#[cfg(not(unix))]
pub(crate) fn enlarge_udp_buffers(_sock: &impl std::os::fd::AsRawFd) {}

/// Enable Linux UDP GRO on a socket, so the kernel can merge adjacent packets
/// from the same flow. Receive code must split by the returned segment size.
#[cfg(target_os = "linux")]
pub(crate) fn enable_udp_gro(sock: &impl std::os::fd::AsRawFd) {
    let fd = sock.as_raw_fd();
    if let Err(e) = set_sockopt_int(fd, libc::SOL_UDP, libc::UDP_GRO, 1) {
        log::debug!("setsockopt UDP_GRO failed: {e}");
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn enable_udp_gro(_sock: &impl std::os::fd::AsRawFd) {}

/// Apply the QUIC transport parameters common to client and server.
fn apply_transport_params(config: &mut quiche::Config) -> Result<()> {
    config
        .set_application_protos(ALPN_H3)
        .context("setting ALPN h3")?;
    config.set_max_idle_timeout(IDLE_TIMEOUT_MS);
    // The whole tunnel is one QUIC connection and every UDP payload rides an
    // (unreliable but still congestion-controlled — RFC 9221 §5) DATAGRAM frame.
    // The default CUBIC is a poor outer controller for a tunnel over a high-RTT,
    // sporadically-lossy path: it treats any loss as congestion and backs off
    // multiplicatively, and recovery at high RTT is glacial — so path loss
    // collapses the tunnel, which then starves the (already loss-based) inner
    // protocol. BBRv2 is rate/model-based, tolerates non-congestive loss, and
    // presents a smoother, higher-bandwidth pipe to whatever is tunnelled.
    config
        .set_cc_algorithm_name("bbr2_gcongestion")
        .context("selecting BBRv2 congestion control")?;
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

/// Reject handshakes whose ClientHello SNI is missing or not one of the
/// configured proxy endpoint hosts. With ECH accepted, BoringSSL exposes the
/// protected inner SNI here; without ECH this checks the ordinary SNI.
pub(crate) fn install_sni_guard(builder: &mut SslContextBuilder, allowed_hosts: Vec<String>) {
    builder.set_select_certificate_callback(move |client_hello| {
        let Some(sni) = client_hello.servername(NameType::HOST_NAME) else {
            log::debug!("rejecting TLS ClientHello without SNI");
            return Err(SelectCertError::ERROR);
        };
        if allowed_hosts.iter().any(|h| h.eq_ignore_ascii_case(sni)) {
            return Ok(());
        }
        log::debug!("rejecting TLS ClientHello with unmatched SNI {sni:?}");
        Err(SelectCertError::ERROR)
    });
}

/// Build the server-side quiche config from a cert/key PEM pair, optionally
/// terminating ECH with the supplied key set.
pub fn build_server_config(
    cert_path: &Path,
    key_path: &Path,
    ech: Option<&EchKeySet>,
    allowed_sni_hosts: Vec<String>,
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
    install_sni_guard(&mut builder, allowed_sni_hosts);

    let mut config = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, builder)
        .map_err(|e| anyhow!("quiche server config: {e}"))?;
    apply_transport_params(&mut config)?;
    Ok(config)
}

/// Common system CA bundle locations, in probe order. BoringSSL's compiled-in
/// default paths are unreliable across distros, so we also look here.
const CA_BUNDLE_PATHS: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu/Alpine
    "/etc/pki/tls/certs/ca-bundle.crt",   // RHEL/Fedora
    "/etc/ssl/cert.pem",                  // BSD/macOS (Homebrew)/some musl
    "/etc/ssl/ca-bundle.pem",             // openSUSE
];

/// Load system trust anchors into the client context (best effort): BoringSSL's
/// compiled-in default paths plus the first known CA bundle that exists.
fn load_system_roots(builder: &mut SslContextBuilder) {
    let _ = builder.set_default_verify_paths();
    for path in CA_BUNDLE_PATHS {
        if std::path::Path::new(path).exists() && builder.set_ca_file(path).is_ok() {
            log::debug!("loaded system CA bundle {path}");
            return;
        }
    }
    log::warn!(
        "no system CA bundle found ({CA_BUNDLE_PATHS:?}); server certificate \
         verification may fail (use --ca or --insecure)"
    );
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
            // BoringSSL's trust store starts empty, so without this every real
            // server certificate fails to verify. Load the system trust anchors.
            load_system_roots(&mut builder);
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
