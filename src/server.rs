//! io_uring CONNECT-UDP proxy (RFC 9298) over monoio + quiche.
//!
//! A single task owns the listening UDP socket and every quiche connection.
//! Inbound QUIC packets are pumped in from a dedicated receive task; each
//! accepted CONNECT-UDP request spawns a per-flow task that owns the target UDP
//! socket and shuttles datagrams in both directions via local channels.

use std::cell::RefCell;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use futures::StreamExt;
use futures::channel::mpsc;
use monoio::net::udp::UdpSocket;
use quiche::h3::NameValue;

use crate::dgram;
use crate::quic;
use crate::rules::RuleTable;

const MAX_DATAGRAM_SIZE: usize = 1350;
const RECV_BUF: usize = 65535;
const CHANNEL_CAP: usize = 1024;
/// Fixed length of the connection IDs this server issues. Short-header packets
/// do not carry the DCID length on the wire, so the receiver must know it; we
/// pick one length for every connection and feed it to `Header::from_slice`.
const LOCAL_CONN_ID_LEN: usize = 16;
/// Structured-field value `?1` (Boolean true) for the Capsule-Protocol header.
const CAPSULE_PROTOCOL_TRUE: &[u8] = b"?1";
/// How often to sweep flows for the per-flow idle timeout.
const FLOW_SWEEP_INTERVAL: Duration = Duration::from_secs(1);

type ConnId = Vec<u8>;

/// A UDP payload received from a target, on its way back to a proxy client.
struct ToClient {
    conn_id: ConnId,
    flow_id: u64,
    payload: Vec<u8>,
}

/// One active CONNECT-UDP flow: the channel feeding its target socket task plus
/// idle-timeout bookkeeping.
struct Flow {
    to_target: mpsc::Sender<Vec<u8>>,
    /// Last time a datagram crossed this flow in either direction.
    last_activity: Instant,
    /// Idle timeout; `None` disables it. From the matching rule.
    idle_timeout: Option<Duration>,
}

struct Client {
    conn: quiche::Connection,
    http3: Option<quiche::h3::Connection>,
    flows: HashMap<u64, Flow>,
    peer: SocketAddr,
}

/// Hot-reloadable server configuration. The reload task swaps the inner config
/// (rotated certificates / ECH keys) and the endpoint→target rule table; new
/// connections and requests pick up the new values, while live connections keep
/// the TLS config captured at accept time.
pub struct ServerConfig {
    pub config: RefCell<quiche::Config>,
    pub rules: RefCell<RuleTable>,
}

pub struct Server {
    socket: Rc<UdpSocket>,
    local_addr: SocketAddr,
    server_config: Rc<ServerConfig>,
    h3_config: quiche::h3::Config,
    /// Active connections keyed by the server-chosen SCID.
    clients: HashMap<ConnId, Client>,
    /// Maps a client's original (handshake) DCID to our SCID, so early Initial
    /// retransmits route to the right connection before the client adopts our
    /// SCID as its DCID.
    routes: HashMap<ConnId, ConnId>,
    to_client_tx: mpsc::Sender<ToClient>,
    to_client_rx: mpsc::Receiver<ToClient>,
}

impl Server {
    pub fn new(socket: UdpSocket, server_config: Rc<ServerConfig>) -> Result<Self> {
        let local_addr = socket.local_addr().context("reading local UDP address")?;
        let h3_config = quic::build_h3_config()?;
        let (to_client_tx, to_client_rx) = mpsc::channel(CHANNEL_CAP);
        Ok(Self {
            socket: Rc::new(socket),
            local_addr,
            server_config,
            h3_config,
            clients: HashMap::new(),
            routes: HashMap::new(),
            to_client_tx,
            to_client_rx,
        })
    }

    pub async fn run(mut self) -> Result<()> {
        // Dedicated receive task: owns the recv side of the socket so it is
        // never cancelled by the main select, and forwards each datagram.
        let (mut pkt_tx, mut pkt_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(CHANNEL_CAP);
        let recv_socket = self.socket.clone();
        monoio::spawn(async move {
            loop {
                let buf = vec![0u8; RECV_BUF];
                let (res, buf) = recv_socket.recv_from(buf).await;
                match res {
                    Ok((len, from)) => {
                        let mut pkt = buf;
                        pkt.truncate(len);
                        if pkt_tx.try_send((pkt, from)).is_err() {
                            // Channel full: drop (the peer will retransmit).
                        }
                    }
                    Err(e) => {
                        log::error!("udp recv failed: {e}");
                        break;
                    }
                }
            }
        });

        loop {
            let timeout = self.min_timeout();
            monoio::select! {
                pkt = pkt_rx.next() => {
                    match pkt {
                        Some((mut data, from)) => self.on_packet(&mut data, from).await,
                        None => break,
                    }
                }
                tc = self.to_client_rx.next() => {
                    if let Some(tc) = tc { self.on_target_payload(tc); }
                }
                _ = sleep_opt(timeout) => {
                    for client in self.clients.values_mut() {
                        client.conn.on_timeout();
                    }
                }
                _ = monoio::time::sleep(FLOW_SWEEP_INTERVAL) => {
                    self.sweep_idle_flows();
                }
            }
            self.flush_all().await;
            self.reap_closed();
        }
        Ok(())
    }

    fn min_timeout(&self) -> Option<std::time::Duration> {
        self.clients.values().filter_map(|c| c.conn.timeout()).min()
    }

    async fn on_packet(&mut self, pkt: &mut [u8], from: SocketAddr) {
        let hdr = match quiche::Header::from_slice(pkt, LOCAL_CONN_ID_LEN) {
            Ok(h) => h,
            Err(e) => {
                log::debug!("dropping malformed packet from {from}: {e}");
                return;
            }
        };
        let dcid: ConnId = hdr.dcid.to_vec();

        // Route to an existing connection, by our SCID or the original DCID.
        let conn_key = if self.clients.contains_key(&dcid) {
            dcid.clone()
        } else if let Some(scid) = self.routes.get(&dcid) {
            scid.clone()
        } else {
            if hdr.ty != quiche::Type::Initial {
                log::debug!(
                    "packet for unknown connection (non-Initial, dcid={}) from {from}",
                    hex(&dcid)
                );
                return;
            }
            if !quiche::version_is_supported(hdr.version) {
                self.send_version_negotiation(&hdr, from).await;
                return;
            }
            match self.accept(&dcid, from) {
                Ok(scid) => scid,
                Err(e) => {
                    log::warn!("accept failed for {from}: {e}");
                    return;
                }
            }
        };

        let client = self.clients.get_mut(&conn_key).unwrap();
        client.peer = from;
        let recv_info = quiche::RecvInfo {
            to: self.local_addr,
            from,
        };
        if let Err(e) = client.conn.recv(pkt, recv_info) {
            log::debug!("conn.recv error from {from}: {e}");
            return;
        }

        process_client(
            client,
            &conn_key,
            &self.h3_config,
            &self.server_config,
            &self.to_client_tx,
        );
    }

    /// Accept a new connection. Generates a fixed-length server SCID (so short
    /// headers parse with `LOCAL_CONN_ID_LEN`), records the DCID→SCID route, and
    /// returns the SCID used as the connection's map key.
    fn accept(&mut self, original_dcid: &ConnId, from: SocketAddr) -> Result<ConnId> {
        let mut scid_bytes = [0u8; LOCAL_CONN_ID_LEN];
        rand::Rng::fill(&mut rand::thread_rng(), &mut scid_bytes[..]);
        let scid = quiche::ConnectionId::from_ref(&scid_bytes);

        let mut cfg = self.server_config.config.borrow_mut();
        let conn = quiche::accept(&scid, None, self.local_addr, from, &mut cfg)
            .map_err(|e| anyhow!("quiche::accept: {e}"))?;
        drop(cfg);

        let key = scid_bytes.to_vec();
        log::info!(
            "new QUIC connection from {from} (scid={}, dcid={})",
            hex(&key),
            hex(original_dcid)
        );
        self.clients.insert(
            key.clone(),
            Client {
                conn,
                http3: None,
                flows: HashMap::new(),
                peer: from,
            },
        );
        self.routes.insert(original_dcid.clone(), key.clone());
        Ok(key)
    }

    async fn send_version_negotiation(&self, hdr: &quiche::Header<'_>, from: SocketAddr) {
        let mut out = vec![0u8; MAX_DATAGRAM_SIZE];
        match quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out) {
            Ok(n) => {
                out.truncate(n);
                let (res, _) = self.socket.send_to(out, from).await;
                if let Err(e) = res {
                    log::debug!("version-negotiation send failed: {e}");
                }
            }
            Err(e) => log::debug!("negotiate_version failed: {e}"),
        }
    }

    fn on_target_payload(&mut self, tc: ToClient) {
        if let Some(client) = self.clients.get_mut(&tc.conn_id) {
            let datagram = dgram::encode(tc.flow_id, &tc.payload);
            match client.conn.dgram_send(&datagram) {
                Ok(()) | Err(quiche::Error::Done) => {}
                Err(quiche::Error::BufferTooShort) => log::warn!(
                    "dropping {}-byte reply datagram on flow {}: exceeds writable QUIC \
                     datagram ({:?}B). The target's reply is too large for the \
                     client<->proxy path MTU; QUIC DATAGRAMs cannot fragment. Lower the \
                     tunnelled interface MTU or ensure the proxy path carries larger packets.",
                    datagram.len(),
                    tc.flow_id,
                    client.conn.dgram_max_writable_len(),
                ),
                Err(e) => log::debug!("dgram_send to client failed: {e}"),
            }
            // Target→client traffic keeps the flow alive.
            if let Some(flow) = client.flows.get_mut(&tc.flow_id) {
                flow.last_activity = Instant::now();
            }
        }
    }

    async fn flush_all(&mut self) {
        for client in self.clients.values_mut() {
            loop {
                let mut out = vec![0u8; MAX_DATAGRAM_SIZE];
                match client.conn.send(&mut out) {
                    Ok((n, info)) => {
                        out.truncate(n);
                        let (res, _) = self.socket.send_to(out, info.to).await;
                        if let Err(e) = res {
                            log::debug!("udp send failed: {e}");
                            break;
                        }
                    }
                    Err(quiche::Error::Done) => break,
                    Err(e) => {
                        log::debug!("conn.send error: {e}");
                        break;
                    }
                }
            }
        }
    }

    fn reap_closed(&mut self) {
        let clients = &mut self.clients;
        let routes = &mut self.routes;
        clients.retain(|cid, client| {
            if client.conn.is_closed() {
                log::info!("connection closed (scid={})", hex(cid));
                // Drop any DCID routes pointing at this connection.
                routes.retain(|_, scid| scid != cid);
                false
            } else {
                true
            }
        });
    }

    /// Close flows idle past their per-rule timeout. Removing a flow drops the
    /// channel to its target task (which then exits, closing the target socket),
    /// and resetting the request stream tells the client the flow is gone (so it
    /// frees the QUIC stream and reopens lazily on the next datagram).
    fn sweep_idle_flows(&mut self) {
        let now = Instant::now();
        for client in self.clients.values_mut() {
            let expired: Vec<u64> = client
                .flows
                .iter()
                .filter_map(|(flow_id, flow)| {
                    let d = flow.idle_timeout?;
                    (now.duration_since(flow.last_activity) >= d).then_some(*flow_id)
                })
                .collect();
            for flow_id in expired {
                client.flows.remove(&flow_id);
                let stream_id = flow_id * 4;
                let _ = client
                    .conn
                    .stream_shutdown(stream_id, quiche::Shutdown::Write, 0x100);
                let _ = client
                    .conn
                    .stream_shutdown(stream_id, quiche::Shutdown::Read, 0x100);
                log::info!("flow {flow_id} idle-timed-out; closed");
            }
        }
    }
}

/// Establish HTTP/3 once the QUIC handshake is ready, then drain request events
/// and client→target datagrams for one connection.
fn process_client(
    client: &mut Client,
    conn_id: &ConnId,
    h3_config: &quiche::h3::Config,
    server_config: &ServerConfig,
    to_client_tx: &mpsc::Sender<ToClient>,
) {
    if !(client.conn.is_established() || client.conn.is_in_early_data()) {
        return;
    }
    // The client's external address — used as the preserved source for
    // transparent rules.
    let client_addr = client.peer;
    if client.http3.is_none() {
        match quiche::h3::Connection::with_transport(&mut client.conn, h3_config) {
            Ok(h3) => client.http3 = Some(h3),
            Err(quiche::h3::Error::Done) => return,
            Err(e) => {
                log::warn!("failed to create HTTP/3 connection: {e}");
                return;
            }
        }
    }
    let http3 = client.http3.as_mut().unwrap();

    loop {
        match http3.poll(&mut client.conn) {
            Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                handle_connect_request(
                    &mut client.conn,
                    http3,
                    &mut client.flows,
                    stream_id,
                    &list,
                    server_config,
                    client_addr,
                    conn_id,
                    to_client_tx,
                );
            }
            Ok((stream_id, quiche::h3::Event::Data)) => {
                // Drain and ignore any capsules on the request stream; UDP rides
                // in datagrams.
                let mut buf = [0u8; 4096];
                while let Ok(n) = http3.recv_body(&mut client.conn, stream_id, &mut buf) {
                    if n == 0 {
                        break;
                    }
                }
            }
            Ok((stream_id, quiche::h3::Event::Finished))
            | Ok((stream_id, quiche::h3::Event::Reset(_))) => {
                let flow_id = stream_id / 4;
                client.flows.remove(&flow_id);
            }
            Ok((_, _)) => {}
            Err(quiche::h3::Error::Done) => break,
            Err(e) => {
                log::debug!("h3 poll error: {e}");
                break;
            }
        }
    }

    drain_client_datagrams(&mut client.conn, &mut client.flows);
}

#[allow(clippy::too_many_arguments)]
fn handle_connect_request(
    conn: &mut quiche::Connection,
    http3: &mut quiche::h3::Connection,
    flows: &mut HashMap<u64, Flow>,
    stream_id: u64,
    headers: &[quiche::h3::Header],
    server_config: &ServerConfig,
    client_addr: SocketAddr,
    conn_id: &ConnId,
    to_client_tx: &mpsc::Sender<ToClient>,
) {
    let flow_id = stream_id / 4;
    let req = match ConnectRequest::parse(headers) {
        Ok(req) => req,
        Err(status) => {
            respond_status(conn, http3, stream_id, status);
            return;
        }
    };

    // Look up the forwarding rule for this request's authority + path. The
    // borrow is released immediately (`RuleMatch` is `Copy`). The client never
    // selects a destination.
    let rule = match server_config
        .rules
        .borrow()
        .match_target(&req.authority, &req.path)
    {
        Some(rule) => rule,
        None => {
            log::debug!(
                "no rule for authority {:?} path {:?}",
                req.authority,
                req.path
            );
            respond_status(conn, http3, stream_id, 404);
            return;
        }
    };

    let target_sock = match bind_target(rule.target, client_addr, rule.transparent, rule.fwmark) {
        Ok(s) => s,
        Err(e) => {
            log::warn!("failed to open target socket for {}: {e}", rule.target);
            respond_status(conn, http3, stream_id, 502);
            return;
        }
    };

    let (to_target_tx, to_target_rx) = mpsc::channel::<Vec<u8>>(CHANNEL_CAP);
    monoio::spawn(target_task(
        target_sock,
        to_target_rx,
        to_client_tx.clone(),
        conn_id.clone(),
        flow_id,
    ));
    flows.insert(
        flow_id,
        Flow {
            to_target: to_target_tx,
            last_activity: Instant::now(),
            idle_timeout: rule.idle_timeout,
        },
    );

    let mut extra = String::new();
    if rule.transparent {
        extra.push_str(&format!(" transparent src {}", client_addr.ip()));
    }
    if let Some(mark) = rule.fwmark {
        extra.push_str(&format!(" fwmark {mark}"));
    }
    log::info!("CONNECT-UDP flow {flow_id} -> {}{extra}", rule.target);

    let response = [
        quiche::h3::Header::new(b":status", b"200"),
        quiche::h3::Header::new(b"capsule-protocol", CAPSULE_PROTOCOL_TRUE),
    ];
    // Keep the stream open (fin = false) so datagrams keep flowing.
    if let Err(e) = http3.send_response(conn, stream_id, &response, false) {
        log::warn!("failed to send CONNECT-UDP 200 response: {e}");
        flows.remove(&flow_id);
    }
}

/// Forward any queued client→target datagrams to the matching flow task.
fn drain_client_datagrams(conn: &mut quiche::Connection, flows: &mut HashMap<u64, Flow>) {
    let mut buf = vec![0u8; RECV_BUF];
    loop {
        match conn.dgram_recv(&mut buf) {
            Ok(len) => {
                let Some(parsed) = dgram::decode(&buf[..len]) else {
                    continue;
                };
                if parsed.context_id != dgram::CONTEXT_ID_UDP {
                    continue; // only raw UDP payloads are supported
                }
                if let Some(flow) = flows.get_mut(&parsed.flow_id) {
                    log::debug!(
                        "client datagram flow {} -> target: {} bytes",
                        parsed.flow_id,
                        parsed.payload.len()
                    );
                    // Drop on full: UDP is lossy by contract.
                    let _ = flow.to_target.try_send(parsed.payload.to_vec());
                    // Client→target traffic keeps the flow alive.
                    flow.last_activity = Instant::now();
                } else {
                    log::debug!("no flow for client datagram flow_id {}", parsed.flow_id);
                }
            }
            Err(quiche::Error::Done) => break,
            Err(e) => {
                log::debug!("dgram_recv error: {e}");
                break;
            }
        }
    }
}

/// Owns one target UDP socket, relaying payloads both directions for a flow.
async fn target_task(
    target: UdpSocket,
    mut from_client: mpsc::Receiver<Vec<u8>>,
    mut to_client: mpsc::Sender<ToClient>,
    conn_id: ConnId,
    flow_id: u64,
) {
    loop {
        let buf = vec![0u8; RECV_BUF];
        monoio::select! {
            maybe = from_client.next() => {
                match maybe {
                    Some(payload) => {
                        let (res, _) = target.send(payload).await;
                        if let Err(e) = res {
                            log::debug!("send to target failed: {e}");
                        }
                    }
                    None => break, // flow closed (sender dropped)
                }
            }
            recv = target.recv(buf) => {
                let (res, buf) = recv;
                match res {
                    Ok(n) => {
                        let tc = ToClient {
                            conn_id: conn_id.clone(),
                            flow_id,
                            payload: buf[..n].to_vec(),
                        };
                        if to_client.try_send(tc).is_err() {
                            // Main loop is backed up or gone; drop / detect close.
                            if to_client.is_closed() {
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        log::debug!("recv from target failed: {e}");
                        break;
                    }
                }
            }
        }
    }
}

/// Parsed pseudo-headers of a CONNECT-UDP request.
struct ConnectRequest {
    authority: String,
    path: String,
}

impl ConnectRequest {
    /// Validate the request line; on failure return the HTTP status to reply.
    fn parse(headers: &[quiche::h3::Header]) -> std::result::Result<Self, u16> {
        let mut method = None;
        let mut protocol = None;
        let mut authority = None;
        let mut path = None;
        for h in headers {
            match h.name() {
                b":method" => method = Some(h.value().to_vec()),
                b":protocol" => protocol = Some(h.value().to_vec()),
                b":authority" => authority = Some(h.value().to_vec()),
                b":path" => path = Some(h.value().to_vec()),
                _ => {}
            }
        }
        if method.as_deref() != Some(b"CONNECT") {
            return Err(405);
        }
        if protocol.as_deref() != Some(b"connect-udp") {
            return Err(501);
        }
        let authority = authority.ok_or(400u16)?;
        let authority = String::from_utf8(authority).map_err(|_| 400u16)?;
        let path = path.ok_or(400u16)?;
        let path = String::from_utf8(path).map_err(|_| 400u16)?;
        Ok(Self { authority, path })
    }
}

fn respond_status(
    conn: &mut quiche::Connection,
    http3: &mut quiche::h3::Connection,
    stream_id: u64,
    status: u16,
) {
    let status = status.to_string();
    let headers = [quiche::h3::Header::new(b":status", status.as_bytes())];
    if let Err(e) = http3.send_response(conn, stream_id, &headers, true) {
        log::debug!("failed to send error status {status}: {e}");
    }
}

/// Open the UDP socket used to relay one flow to its target. In transparent mode
/// (Linux only) the socket forwards with the client's external source IP
/// preserved via `IP_TRANSPARENT`; otherwise it uses an ephemeral local source.
/// `fwmark`, when set, applies `SO_MARK` for policy routing (Linux only).
fn bind_target(
    target: SocketAddr,
    client_addr: SocketAddr,
    transparent: bool,
    fwmark: Option<u32>,
) -> Result<UdpSocket> {
    if transparent {
        return bind_target_transparent(target, client_addr, fwmark);
    }
    #[cfg(not(target_os = "linux"))]
    if fwmark.is_some() {
        bail!("fwmark is only supported on Linux");
    }
    let bind: SocketAddr = if target.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    // Connect with std (synchronous, non-blocking for datagram sockets) so the
    // socket has a fixed peer, then adopt it into monoio's io_uring driver.
    let std_sock = std::net::UdpSocket::bind(bind).context("binding target UDP socket")?;
    #[cfg(target_os = "linux")]
    if let Some(mark) = fwmark {
        use std::os::fd::AsRawFd;
        set_so_mark(std_sock.as_raw_fd(), mark)
            .with_context(|| format!("setting fwmark {mark} (needs CAP_NET_ADMIN)"))?;
    }
    std_sock
        .connect(target)
        .context("connecting target socket")?;
    std_sock
        .set_nonblocking(true)
        .context("set target nonblocking")?;
    UdpSocket::from_std(std_sock).context("adopting target socket into monoio")
}

/// Set `SO_MARK` (fwmark) on a socket. Requires `CAP_NET_ADMIN`.
#[cfg(target_os = "linux")]
fn set_so_mark(fd: std::os::fd::RawFd, mark: u32) -> std::io::Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Transparent forwarding: send to `target` with the client's external source IP
/// preserved (`IP_TRANSPARENT`). Tries the client's exact `ip:port`, falling back
/// to an ephemeral port on that IP if it's already in use (a client multiplexes
/// many flows over one QUIC address). Requires `CAP_NET_ADMIN`; the operator must
/// also route the target's replies (to the spoofed source) back to the proxy,
/// which is straightforward for a local target.
#[cfg(target_os = "linux")]
fn bind_target_transparent(
    target: SocketAddr,
    client_addr: SocketAddr,
    fwmark: Option<u32>,
) -> Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::os::fd::AsRawFd;

    // Source and target must share an address family. Canonicalise so an
    // IPv4-mapped IPv6 client address (dual-stack listener) compares as IPv4.
    let src_ip = client_addr.ip().to_canonical();
    let (domain, is_v6) = match (src_ip.is_ipv4(), target.is_ipv4()) {
        (true, true) => (Domain::IPV4, false),
        (false, false) => (Domain::IPV6, true),
        _ => bail!(
            "transparent rule: client {client_addr} and target {target} address families differ"
        ),
    };

    let make = |src: SocketAddr| -> std::io::Result<Socket> {
        let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        // IP_TRANSPARENT must be set before bind; it requires CAP_NET_ADMIN.
        let one: libc::c_int = 1;
        let (level, optname) = if is_v6 {
            (libc::SOL_IPV6, libc::IPV6_TRANSPARENT)
        } else {
            (libc::SOL_IP, libc::IP_TRANSPARENT)
        };
        let rc = unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                level,
                optname,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of_val(&one) as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if let Some(mark) = fwmark {
            set_so_mark(sock.as_raw_fd(), mark)?;
        }
        sock.set_reuse_address(true)?;
        sock.bind(&src.into())?;
        sock.connect(&target.into())?;
        sock.set_nonblocking(true)?;
        Ok(sock)
    };

    let exact = SocketAddr::new(src_ip, client_addr.port());
    let sock = match make(exact) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            log::debug!("transparent source {exact} busy; using ephemeral port");
            make(SocketAddr::new(src_ip, 0)).map_err(|e| {
                anyhow!("transparent bind to {src_ip} failed: {e} (needs CAP_NET_ADMIN)")
            })?
        }
        Err(e) => {
            return Err(anyhow!(
                "transparent bind to {exact} failed: {e} (transparent rules need CAP_NET_ADMIN)"
            ));
        }
    };

    UdpSocket::from_std(sock.into()).context("adopting transparent target socket into monoio")
}

#[cfg(not(target_os = "linux"))]
fn bind_target_transparent(
    _target: SocketAddr,
    _client_addr: SocketAddr,
    _fwmark: Option<u32>,
) -> Result<UdpSocket> {
    bail!("transparent proxy mode (transparent rules) is only supported on Linux")
}

async fn sleep_opt(timeout: Option<std::time::Duration>) {
    match timeout {
        Some(d) => monoio::time::sleep(d).await,
        // No active timers: park "forever" until another select arm fires.
        None => std::future::pending::<()>().await,
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
