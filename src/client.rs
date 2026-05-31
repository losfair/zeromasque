//! MASQUE CONNECT-UDP client (RFC 9298) over monoio + quiche.
//!
//! Opens a QUIC/HTTP3 connection to the proxy and issues Extended CONNECT
//! requests, tunnelling UDP payloads as HTTP datagrams. [`run_proxy`] binds a
//! local UDP socket and acts as a UDP→CONNECT-UDP proxy, opening one flow per
//! local source address and relaying both directions.

use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::rc::Rc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use futures::StreamExt;
use futures::channel::{mpsc, oneshot};
use monoio::net::udp::UdpSocket;
use quiche::h3::NameValue;

use crate::dgram;
use crate::endpoint::Endpoint;
use crate::io;
use crate::quic::{self, CAPSULE_PROTOCOL_TRUE, Verify};
use crate::util::{CHANNEL_CAP, RECV_BUF, hex, sleep_opt};

/// Keepalive cadence; keeps the tunnel from idling out between bursts and lets a
/// dead path be detected quickly.
const KEEPALIVE: Duration = Duration::from_secs(1);
/// Per-source bound on datagrams buffered before the flow's request is sent.
const MAX_PENDING: usize = 32;
/// Reconnect backoff bounds. The client never gives up; it keeps redialing the
/// proxy, backing off on repeated failures and resetting once a tunnel comes up.
const RECONNECT_MIN: Duration = Duration::from_millis(100);
const RECONNECT_MAX: Duration = Duration::from_secs(5);

/// Connection parameters for the proxy client.
pub struct ConnectParams {
    pub endpoint: Endpoint,
    /// Override for the proxy UDP address; the endpoint host is still used for
    /// SNI / `:authority`.
    pub proxy_addr: Option<SocketAddr>,
    pub verify: Verify,
    pub ech_config_list: Option<Vec<u8>>,
}

pub struct ProxyOptions {
    pub conn: ConnectParams,
    pub listen: SocketAddr,
}

/// A connected (but not yet HTTP/3-established) QUIC connection to the proxy.
struct Dialed {
    socket: Rc<UdpSocket>,
    conn: quiche::Connection,
    local_addr: SocketAddr,
    /// The `:path` to send on CONNECT requests (same for every flow).
    path: String,
    authority: String,
}

fn dial(p: &ConnectParams) -> Result<Dialed> {
    let mut config = quic::build_client_config(&p.verify, p.ech_config_list.clone())?;

    let proxy_addr = match p.proxy_addr {
        Some(addr) => addr,
        None => resolve_authority(&p.endpoint.authority)?,
    };
    let server_name = host_of(&p.endpoint.authority);
    let path = p.endpoint.path.clone();

    let bind: SocketAddr = if proxy_addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let socket = UdpSocket::bind(bind).context("binding client UDP socket")?;
    quic::enlarge_udp_buffers(&socket);
    let local_addr = socket.local_addr().context("client local addr")?;

    let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
    rand::Rng::fill(&mut rand::thread_rng(), &mut scid[..]);
    let scid = quiche::ConnectionId::from_ref(&scid);

    let conn = quiche::connect(
        Some(&server_name),
        &scid,
        local_addr,
        proxy_addr,
        &mut config,
    )
    .map_err(|e| anyhow!("quiche::connect: {e}"))?;

    log::info!("connecting to proxy {proxy_addr} (sni={server_name})");
    Ok(Dialed {
        socket: Rc::new(socket),
        conn,
        local_addr,
        path,
        authority: p.endpoint.authority.clone(),
    })
}

/// CONNECT-UDP request headers for `authority`/`path`.
fn connect_headers<'a>(authority: &'a str, path: &'a str) -> [quiche::h3::Header; 6] {
    [
        quiche::h3::Header::new(b":method", b"CONNECT"),
        quiche::h3::Header::new(b":protocol", b"connect-udp"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", authority.as_bytes()),
        quiche::h3::Header::new(b":path", path.as_bytes()),
        quiche::h3::Header::new(b"capsule-protocol", CAPSULE_PROTOCOL_TRUE),
    ]
}

// ===================== proxy =====================

/// One local source's flow state.
struct FlowState {
    /// Quarter-stream id, set once the CONNECT request has been sent.
    flow_id: Option<u64>,
    /// Set once the proxy answers 200. Datagrams must not be sent before this:
    /// the server only creates the flow when it processes the CONNECT request,
    /// and a datagram can otherwise overtake the request and be dropped.
    established: bool,
    /// Datagrams buffered until the flow is established.
    pending: Vec<Vec<u8>>,
}

/// Run as a local UDP→CONNECT-UDP proxy. The local listen socket is bound once
/// and persists; the QUIC connection to the proxy is (re)established in a loop
/// that never gives up, so a server restart, a dropped NAT mapping, or any other
/// failure recovers automatically. Flows reopen lazily as local datagrams
/// arrive (apps retransmit lost UDP, so they self-heal).
pub async fn run_proxy(opts: ProxyOptions) -> Result<()> {
    let lsock = Rc::new(
        UdpSocket::bind(opts.listen)
            .with_context(|| format!("binding local UDP listen socket {}", opts.listen))?,
    );
    quic::enlarge_udp_buffers(&*lsock);
    log::info!("local UDP proxy listening on {}", opts.listen);

    // The local recv task persists across reconnects, buffering datagrams that
    // arrive while the tunnel is briefly down.
    let (ltx, mut lrx) = mpsc::channel(CHANNEL_CAP);
    io::spawn_udp_recv(lsock.clone(), ltx, None);

    let mut backoff = RECONNECT_MIN;
    loop {
        let established = run_session(&opts.conn, &lsock, &mut lrx).await;
        if established {
            backoff = RECONNECT_MIN;
        }
        log::warn!("tunnel down; reconnecting in {backoff:?}");
        monoio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(RECONNECT_MAX);
    }
}

/// Drive one connection lifetime to the proxy. Returns whether the tunnel became
/// established (so the caller resets its backoff). Never propagates connection
/// errors: on any failure it logs and returns so the caller reconnects.
async fn run_session(
    p: &ConnectParams,
    lsock: &Rc<UdpSocket>,
    lrx: &mut mpsc::Receiver<(Vec<u8>, SocketAddr)>,
) -> bool {
    let Dialed {
        socket: qsock,
        mut conn,
        local_addr,
        path,
        authority,
    } = match dial(p) {
        Ok(d) => d,
        Err(e) => {
            log::warn!("dial failed: {e}");
            return false;
        }
    };

    let h3_config = match quic::build_h3_config() {
        Ok(c) => c,
        Err(e) => {
            log::warn!("h3 config: {e}");
            return false;
        }
    };
    let mut http3: Option<quiche::h3::Connection> = None;
    let mut established = false;
    let mut by_addr: HashMap<SocketAddr, FlowState> = HashMap::new();
    let mut flows: HashMap<u64, SocketAddr> = HashMap::new();

    if let Err(e) = io::flush_connection(&qsock, &mut conn).await {
        log::warn!("initial flush: {e}");
        return established;
    }

    // Dedicated QUIC receive task: drains the socket into a channel so the main
    // loop can absorb an entire inbound burst per wakeup. Reading one packet per
    // `select!` iteration starves download reads under a busy uplink, overflowing
    // the recv buffer and collapsing the download congestion window. Dropping
    // `_recv_cancel` on return stops the task, so reconnect teardown stays clean.
    let (qpkt_tx, mut qpkt_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(CHANNEL_CAP);
    let (_recv_cancel, cancel_rx) = oneshot::channel::<()>();
    io::spawn_udp_recv(qsock.clone(), qpkt_tx, Some(cancel_rx));

    loop {
        let timeout = conn.timeout();
        let mut proxy_pkts: Vec<(Vec<u8>, SocketAddr)> = Vec::new();
        let mut local_pkts: Vec<(Vec<u8>, SocketAddr)> = Vec::new();
        let mut do_keepalive = false;
        let mut do_timeout = false;
        monoio::select! {
            q = qpkt_rx.next() => {
                match q {
                    Some(p) => proxy_pkts.push(p),
                    None => return established, // recv task ended (socket error)
                }
            }
            l = lrx.next() => { if let Some(p) = l { local_pkts.push(p); } }
            _ = sleep_opt(timeout) => { do_timeout = true; }
            _ = monoio::time::sleep(KEEPALIVE) => { do_keepalive = true; }
        }
        // Drain everything already queued in both directions, so one wakeup
        // processes a whole burst: prompt ACKs and no recv-buffer overflow.
        while let Ok(p) = qpkt_rx.try_recv() {
            proxy_pkts.push(p);
        }
        while let Ok(p) = lrx.try_recv() {
            local_pkts.push(p);
        }

        for (mut buf, from) in proxy_pkts {
            let info = quiche::RecvInfo {
                to: local_addr,
                from,
            };
            if let Err(e) = conn.recv(&mut buf, info) {
                log::debug!("conn.recv: {e}");
            }
        }
        if do_timeout {
            conn.on_timeout();
        }
        if do_keepalive {
            let _ = conn.send_ack_eliciting();
        }

        if conn.is_closed() {
            log::info!("tunnel closed: {:?}", conn.stats());
            return established;
        }

        if (conn.is_established() || conn.is_in_early_data()) && http3.is_none() {
            if let Some(der) = conn.peer_cert() {
                log::info!(
                    "proxy certificate sha256: {}",
                    hex(&boring::sha::sha256(der))
                );
            }
            match quiche::h3::Connection::with_transport(&mut conn, &h3_config) {
                Ok(h3) => {
                    http3 = Some(h3);
                    established = true;
                    log::info!("tunnel established");
                }
                Err(e) => {
                    log::warn!("h3 with_transport: {e}");
                    return established;
                }
            }
        }

        // Queue freshly received local datagrams for their flows. Forward
        // immediately once a flow is established; otherwise buffer until 200.
        for (data, src) in local_pkts {
            let st = by_addr.entry(src).or_insert_with(|| FlowState {
                flow_id: None,
                established: false,
                pending: Vec::new(),
            });
            match (st.established, st.flow_id) {
                (true, Some(fid)) => send_datagram(&mut conn, fid, &data),
                _ => {
                    if st.pending.len() < MAX_PENDING {
                        st.pending.push(data);
                    }
                }
            }
        }

        if let Some(h3) = http3.as_mut() {
            open_pending_flows(&mut conn, h3, &authority, &path, &mut by_addr, &mut flows);
            poll_responses(&mut conn, h3, &mut by_addr, &mut flows);
            route_tunnel_datagrams(&mut conn, lsock, &flows).await;
        }

        if let Err(e) = io::flush_connection(&qsock, &mut conn).await {
            log::warn!("flush: {e}");
            return established;
        }
    }
}

/// Send a CONNECT request for any local source that doesn't have a flow yet, and
/// flush that source's buffered datagrams once its flow id is known.
fn open_pending_flows(
    conn: &mut quiche::Connection,
    http3: &mut quiche::h3::Connection,
    authority: &str,
    path: &str,
    by_addr: &mut HashMap<SocketAddr, FlowState>,
    flows: &mut HashMap<u64, SocketAddr>,
) {
    let headers = connect_headers(authority, path);
    let mut dropped = Vec::new();
    for (src, st) in by_addr.iter_mut() {
        if st.flow_id.is_some() {
            continue;
        }
        match http3.send_request(conn, &headers, false) {
            Ok(stream_id) => {
                let fid = stream_id / 4;
                st.flow_id = Some(fid);
                flows.insert(fid, *src);
                log::info!("opened flow {fid} for local {src} (stream {stream_id})");
                // Buffered datagrams are flushed once the proxy answers 200.
            }
            Err(quiche::h3::Error::StreamBlocked) => {} // retry next iteration
            Err(quiche::h3::Error::TransportError(quiche::Error::StreamLimit)) => {
                log::warn!("stream limit reached; dropping local {src}");
                dropped.push(*src);
            }
            Err(e) => {
                log::warn!("send_request for {src} failed: {e}");
                dropped.push(*src);
            }
        }
    }
    for src in dropped {
        by_addr.remove(&src);
    }
}

/// Consume CONNECT responses and stream closes, dropping rejected/closed flows.
fn poll_responses(
    conn: &mut quiche::Connection,
    http3: &mut quiche::h3::Connection,
    by_addr: &mut HashMap<SocketAddr, FlowState>,
    flows: &mut HashMap<u64, SocketAddr>,
) {
    loop {
        match http3.poll(conn) {
            Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                let fid = stream_id / 4;
                match status_of(&list) {
                    Some(s) if (200..300).contains(&s) => {
                        log::debug!("flow {fid} accepted (status {s})");
                        // The server has created the flow; release buffered data.
                        if let Some(src) = flows.get(&fid).copied()
                            && let Some(st) = by_addr.get_mut(&src)
                        {
                            st.established = true;
                            let pending = std::mem::take(&mut st.pending);
                            for data in pending {
                                send_datagram(conn, fid, &data);
                            }
                        }
                    }
                    Some(s) => {
                        log::warn!("flow {fid} rejected (status {s})");
                        if let Some(src) = flows.remove(&fid) {
                            by_addr.remove(&src);
                        }
                    }
                    None => {}
                }
            }
            Ok((stream_id, quiche::h3::Event::Finished))
            | Ok((stream_id, quiche::h3::Event::Reset(_))) => {
                let fid = stream_id / 4;
                if let Some(src) = flows.remove(&fid) {
                    by_addr.remove(&src);
                }
            }
            Ok((_, _)) => {}
            Err(quiche::h3::Error::Done) => break,
            Err(e) => {
                log::debug!("h3 poll: {e}");
                break;
            }
        }
    }
}

/// Forward tunnelled datagrams back to the local source for their flow.
async fn route_tunnel_datagrams(
    conn: &mut quiche::Connection,
    lsock: &UdpSocket,
    flows: &HashMap<u64, SocketAddr>,
) {
    let mut dbuf = vec![0u8; RECV_BUF];
    loop {
        match conn.dgram_recv(&mut dbuf) {
            Ok(len) => {
                let Some(p) = dgram::decode(&dbuf[..len]) else {
                    continue;
                };
                if p.context_id != dgram::CONTEXT_ID_UDP {
                    continue;
                }
                let (flow_id, payload) = (p.flow_id, p.payload.to_vec());
                if let Some(src) = flows.get(&flow_id) {
                    let (res, _) = lsock.send_to(payload, *src).await;
                    if let Err(e) = res {
                        log::debug!("send to local {src} failed: {e}");
                    }
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

fn send_datagram(conn: &mut quiche::Connection, flow_id: u64, data: &[u8]) {
    let datagram = dgram::encode(flow_id, data);
    match conn.dgram_send(&datagram) {
        Ok(()) => log::debug!("-> tunnel flow {flow_id}: {} bytes", data.len()),
        Err(quiche::Error::Done) => log::debug!("dgram_send dropped (queue full) flow {flow_id}"),
        Err(quiche::Error::BufferTooShort) => log::warn!(
            "dropping {}-byte datagram on flow {flow_id}: exceeds writable QUIC \
             datagram ({:?}B). The inner payload is too large for the \
             client<->proxy path MTU; QUIC DATAGRAMs cannot fragment. Lower the \
             tunnelled interface MTU or ensure the proxy path carries larger packets.",
            datagram.len(),
            conn.dgram_max_writable_len(),
        ),
        Err(e) => log::debug!("dgram_send failed: {e}"),
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
