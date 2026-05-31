//! MASQUE CONNECT-UDP client (RFC 9298) over monoio + quiche.
//!
//! Opens a QUIC/HTTP3 connection to the proxy, issues an Extended CONNECT
//! request for the requested target, then tunnels UDP payloads as HTTP
//! datagrams. The CLI front-end performs a request/response probe: it sends one
//! message through the tunnel and prints datagrams received back.

use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use monoio::net::udp::UdpSocket;
use quiche::h3::NameValue;

use crate::dgram;
use crate::quic::{self, Verify};
use crate::template::Template;

const MAX_DATAGRAM_SIZE: usize = 1350;
const RECV_BUF: usize = 65535;
const CAPSULE_PROTOCOL_TRUE: &[u8] = b"?1";
/// The CONNECT request is the first client-initiated bidi stream (id 0), so its
/// HTTP datagram flow id (quarter-stream-id) is 0.
const FLOW_ID: u64 = 0;

pub struct ClientOptions {
    pub template: Template,
    pub target_host: String,
    pub target_port: u16,
    /// Optional override for the proxy UDP address; the template host is still
    /// used for SNI / `:authority`.
    pub proxy_addr: Option<SocketAddr>,
    pub verify: Verify,
    pub ech_config_list: Option<Vec<u8>>,
    pub message: Vec<u8>,
    /// How long to wait for tunnelled responses before exiting.
    pub response_window: Duration,
}

/// Run a single CONNECT-UDP probe: connect, tunnel one message, print replies.
pub async fn run(opts: ClientOptions) -> Result<()> {
    let mut config = quic::build_client_config(opts.verify, opts.ech_config_list)?;

    let proxy_addr = match opts.proxy_addr {
        Some(addr) => addr,
        None => resolve_authority(&opts.template.authority)?,
    };
    let server_name = host_of(&opts.template.authority);

    let bind: SocketAddr = if proxy_addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let socket = UdpSocket::bind(bind).context("binding client UDP socket")?;
    let local_addr = socket.local_addr().context("client local addr")?;

    let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
    rand::Rng::fill(&mut rand::thread_rng(), &mut scid[..]);
    let scid = quiche::ConnectionId::from_ref(&scid);

    let mut conn = quiche::connect(
        Some(&server_name),
        &scid,
        local_addr,
        proxy_addr,
        &mut config,
    )
    .map_err(|e| anyhow!("quiche::connect: {e}"))?;

    log::info!(
        "connecting to proxy {proxy_addr} (sni={server_name}) for target {}:{}",
        opts.target_host,
        opts.target_port
    );

    let h3_config = quic::build_h3_config()?;
    let mut http3: Option<quiche::h3::Connection> = None;
    let mut request_sent = false;
    let mut connected = false;
    let mut message_sent = false;
    let mut got_response = false;
    let mut deadline: Option<Instant> = None;

    flush(&socket, &mut conn, proxy_addr).await?;

    loop {
        // Wait for inbound packets or the next QUIC timer.
        let timeout = conn.timeout();
        let buf = vec![0u8; RECV_BUF];
        let mut received = None;
        monoio::select! {
            recv = socket.recv_from(buf) => {
                let (res, buf) = recv;
                let (len, from) = res.context("client recv")?;
                received = Some((buf, len, from));
            }
            _ = sleep_opt(timeout) => {
                conn.on_timeout();
            }
        }

        if let Some((mut buf, len, from)) = received {
            let info = quiche::RecvInfo {
                to: local_addr,
                from,
            };
            if let Err(e) = conn.recv(&mut buf[..len], info) {
                log::debug!("conn.recv: {e}");
            }
        }

        if conn.is_closed() {
            log::info!("connection closed: {:?}", conn.stats());
            break;
        }

        // Bring up HTTP/3 and send the CONNECT request once established.
        if (conn.is_established() || conn.is_in_early_data()) && http3.is_none() {
            if let Some(der) = conn.peer_cert() {
                let fp = boring::sha::sha256(der);
                log::info!("proxy certificate sha256: {}", hex(&fp));
            }
            http3 = Some(
                quiche::h3::Connection::with_transport(&mut conn, &h3_config)
                    .map_err(|e| anyhow!("h3 with_transport: {e}"))?,
            );
        }

        if let Some(h3) = http3.as_mut() {
            if !request_sent {
                let path = opts.template.expand(&opts.target_host, opts.target_port);
                let headers = [
                    quiche::h3::Header::new(b":method", b"CONNECT"),
                    quiche::h3::Header::new(b":protocol", b"connect-udp"),
                    quiche::h3::Header::new(b":scheme", b"https"),
                    quiche::h3::Header::new(b":authority", opts.template.authority.as_bytes()),
                    quiche::h3::Header::new(b":path", path.as_bytes()),
                    quiche::h3::Header::new(b"capsule-protocol", CAPSULE_PROTOCOL_TRUE),
                ];
                match h3.send_request(&mut conn, &headers, false) {
                    Ok(stream_id) => {
                        log::info!("sent CONNECT-UDP request on stream {stream_id}");
                        request_sent = true;
                    }
                    Err(quiche::h3::Error::StreamBlocked) => {
                        // Retry next loop once the stream has capacity.
                    }
                    Err(e) => bail!("send_request failed: {e}"),
                }
            }

            loop {
                match h3.poll(&mut conn) {
                    Ok((_stream_id, quiche::h3::Event::Headers { list, .. })) => {
                        let status = status_of(&list);
                        match status {
                            Some(s) if (200..300).contains(&s) => {
                                log::info!("proxy accepted CONNECT-UDP (status {s})");
                                connected = true;
                            }
                            Some(s) => bail!("proxy rejected CONNECT-UDP with status {s}"),
                            None => bail!("response missing :status"),
                        }
                    }
                    Ok((_, quiche::h3::Event::Data)) => {}
                    Ok((_, quiche::h3::Event::Finished)) => {}
                    Ok((_, _)) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(e) => bail!("h3 poll: {e}"),
                }
            }

            // Drain tunnelled datagrams from the proxy.
            let mut dbuf = vec![0u8; RECV_BUF];
            loop {
                match conn.dgram_recv(&mut dbuf) {
                    Ok(len) => {
                        if let Some(p) = dgram::decode(&dbuf[..len])
                            && p.context_id == dgram::CONTEXT_ID_UDP
                        {
                            got_response = true;
                            print_payload(p.payload);
                        }
                    }
                    Err(quiche::Error::Done) => break,
                    Err(e) => {
                        log::debug!("dgram_recv: {e}");
                        break;
                    }
                }
            }
        }

        if connected && !message_sent {
            let datagram = dgram::encode(FLOW_ID, &opts.message);
            match conn.dgram_send(&datagram) {
                Ok(()) => {
                    log::info!("tunnelled {} bytes to target", opts.message.len());
                    message_sent = true;
                    deadline = Some(Instant::now() + opts.response_window);
                }
                Err(quiche::Error::Done) => {} // queue full; retry next loop
                Err(e) => bail!("dgram_send: {e}"),
            }
        }

        flush(&socket, &mut conn, proxy_addr).await?;

        if let Some(dl) = deadline
            && (got_response || Instant::now() >= dl)
        {
            conn.close(true, 0x00, b"done").ok();
            flush(&socket, &mut conn, proxy_addr).await?;
            break;
        }
    }

    if message_sent && !got_response {
        bail!("no response received within {:?}", opts.response_window);
    }
    Ok(())
}

async fn flush(socket: &UdpSocket, conn: &mut quiche::Connection, _peer: SocketAddr) -> Result<()> {
    loop {
        let mut out = vec![0u8; MAX_DATAGRAM_SIZE];
        match conn.send(&mut out) {
            Ok((n, info)) => {
                out.truncate(n);
                let (res, _) = socket.send_to(out, info.to).await;
                res.context("client udp send")?;
            }
            Err(quiche::Error::Done) => break,
            Err(e) => bail!("conn.send: {e}"),
        }
    }
    Ok(())
}

fn print_payload(payload: &[u8]) {
    match std::str::from_utf8(payload) {
        Ok(s) => println!("recv {} bytes: {s}", payload.len()),
        Err(_) => println!("recv {} bytes (binary): {:02x?}", payload.len(), payload),
    }
}

fn status_of(headers: &[quiche::h3::Header]) -> Option<u16> {
    headers
        .iter()
        .find(|h| h.name() == b":status")
        .and_then(|h| std::str::from_utf8(h.value()).ok())
        .and_then(|s| s.parse().ok())
}

fn host_of(authority: &str) -> String {
    // Strip the optional :port; handle bracketed IPv6 literals.
    if let Some(rest) = authority.strip_prefix('[')
        && let Some(end) = rest.find(']')
    {
        return rest[..end].to_string();
    }
    authority
        .rsplit_once(':')
        .map(|(h, _)| h.to_string())
        .unwrap_or_else(|| authority.to_string())
}

fn resolve_authority(authority: &str) -> Result<SocketAddr> {
    authority
        .to_socket_addrs()
        .with_context(|| format!("resolving proxy authority {authority}"))?
        .next()
        .ok_or_else(|| anyhow!("no addresses for proxy authority {authority}"))
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

async fn sleep_opt(timeout: Option<Duration>) {
    match timeout {
        Some(d) => monoio::time::sleep(d).await,
        None => std::future::pending::<()>().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_of_strips_port_and_brackets() {
        assert_eq!(host_of("localhost:4433"), "localhost");
        assert_eq!(host_of("example.com"), "example.com");
        assert_eq!(host_of("[2001:db8::1]:443"), "2001:db8::1");
    }
}
