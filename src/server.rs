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

use anyhow::{Context, Result, anyhow};
use futures::StreamExt;
use futures::channel::mpsc;
use monoio::net::udp::UdpSocket;
use quiche::h3::NameValue;

use crate::dgram;
use crate::endpoint::Endpoint;
use crate::quic;

const MAX_DATAGRAM_SIZE: usize = 1350;
const RECV_BUF: usize = 65535;
const CHANNEL_CAP: usize = 1024;
/// Fixed length of the connection IDs this server issues. Short-header packets
/// do not carry the DCID length on the wire, so the receiver must know it; we
/// pick one length for every connection and feed it to `Header::from_slice`.
const LOCAL_CONN_ID_LEN: usize = 16;
/// Structured-field value `?1` (Boolean true) for the Capsule-Protocol header.
const CAPSULE_PROTOCOL_TRUE: &[u8] = b"?1";

type ConnId = Vec<u8>;

/// A UDP payload received from a target, on its way back to a proxy client.
struct ToClient {
    conn_id: ConnId,
    flow_id: u64,
    payload: Vec<u8>,
}

/// One active CONNECT-UDP flow: the channel feeding its target socket task.
struct Flow {
    to_target: mpsc::Sender<Vec<u8>>,
}

struct Client {
    conn: quiche::Connection,
    http3: Option<quiche::h3::Connection>,
    flows: HashMap<u64, Flow>,
    peer: SocketAddr,
}

/// Hot-reloadable TLS/QUIC configuration. The reload task swaps the inner
/// config so new connections pick up rotated certificates and ECH keys; live
/// connections keep the config captured at accept time.
pub struct ServerConfig {
    pub config: RefCell<quiche::Config>,
}

pub struct Server {
    socket: Rc<UdpSocket>,
    local_addr: SocketAddr,
    server_config: Rc<ServerConfig>,
    h3_config: quiche::h3::Config,
    endpoint: Rc<Endpoint>,
    /// Every flow forwards here; the target is pinned server-side.
    pinned_target: SocketAddr,
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
    pub fn new(
        socket: UdpSocket,
        server_config: Rc<ServerConfig>,
        endpoint: Rc<Endpoint>,
        pinned_target: SocketAddr,
    ) -> Result<Self> {
        let local_addr = socket.local_addr().context("reading local UDP address")?;
        let h3_config = quic::build_h3_config()?;
        let (to_client_tx, to_client_rx) = mpsc::channel(CHANNEL_CAP);
        Ok(Self {
            socket: Rc::new(socket),
            local_addr,
            server_config,
            h3_config,
            endpoint,
            pinned_target,
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
            &self.endpoint,
            self.pinned_target,
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
                Err(e) => log::debug!("dgram_send to client failed: {e}"),
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
}

/// Establish HTTP/3 once the QUIC handshake is ready, then drain request events
/// and client→target datagrams for one connection.
fn process_client(
    client: &mut Client,
    conn_id: &ConnId,
    h3_config: &quiche::h3::Config,
    endpoint: &Endpoint,
    pinned_target: SocketAddr,
    to_client_tx: &mpsc::Sender<ToClient>,
) {
    if !(client.conn.is_established() || client.conn.is_in_early_data()) {
        return;
    }
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
                    endpoint,
                    pinned_target,
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

    drain_client_datagrams(&mut client.conn, &client.flows);
}

#[allow(clippy::too_many_arguments)]
fn handle_connect_request(
    conn: &mut quiche::Connection,
    http3: &mut quiche::h3::Connection,
    flows: &mut HashMap<u64, Flow>,
    stream_id: u64,
    headers: &[quiche::h3::Header],
    endpoint: &Endpoint,
    target: SocketAddr,
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

    // The path must match the configured endpoint exactly. The forwarding
    // target is pinned, so the client never selects a destination.
    if !endpoint.matches(&req.path) {
        log::debug!(
            "path {:?} did not match endpoint {:?}",
            req.path,
            endpoint.path
        );
        respond_status(conn, http3, stream_id, 404);
        return;
    }

    let target_sock = match bind_target(target) {
        Ok(s) => s,
        Err(e) => {
            log::warn!("failed to open target socket for {target}: {e}");
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
        },
    );

    log::info!("CONNECT-UDP flow {flow_id} -> {target}");

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
fn drain_client_datagrams(conn: &mut quiche::Connection, flows: &HashMap<u64, Flow>) {
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
                if let Some(flow) = flows.get(&parsed.flow_id) {
                    log::debug!(
                        "client datagram flow {} -> target: {} bytes",
                        parsed.flow_id,
                        parsed.payload.len()
                    );
                    // Drop on full: UDP is lossy by contract.
                    let mut sender = flow.to_target.clone();
                    let _ = sender.try_send(parsed.payload.to_vec());
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
    path: String,
}

impl ConnectRequest {
    /// Validate the request line; on failure return the HTTP status to reply.
    fn parse(headers: &[quiche::h3::Header]) -> std::result::Result<Self, u16> {
        let mut method = None;
        let mut protocol = None;
        let mut path = None;
        for h in headers {
            match h.name() {
                b":method" => method = Some(h.value().to_vec()),
                b":protocol" => protocol = Some(h.value().to_vec()),
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
        let path = path.ok_or(400u16)?;
        let path = String::from_utf8(path).map_err(|_| 400u16)?;
        Ok(Self { path })
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

fn bind_target(target: SocketAddr) -> Result<UdpSocket> {
    let bind: SocketAddr = if target.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    // Connect with std (synchronous, non-blocking for datagram sockets) so the
    // socket has a fixed peer, then adopt it into monoio's io_uring driver.
    let std_sock = std::net::UdpSocket::bind(bind).context("binding target UDP socket")?;
    std_sock
        .connect(target)
        .context("connecting target socket")?;
    std_sock
        .set_nonblocking(true)
        .context("set target nonblocking")?;
    UdpSocket::from_std(std_sock).context("adopting target socket into monoio")
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
