//! Shared runtime I/O for driving a quiche connection over a monoio UDP socket.
//! Both the proxy server and the client pump inbound packets through a channel
//! and flush outbound packets the same way; these are the shared primitives.

use std::io::{self, ErrorKind};
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::rc::Rc;

use anyhow::{Context, Result, bail};
use futures::channel::{mpsc, oneshot};
use monoio::net::udp::UdpSocket;
use socket2::SockAddr;

use crate::quic::{self, MAX_DATAGRAM_SIZE};

const SEND_BATCH: usize = 32;
pub(crate) const RECV_BATCH: usize = 32;

/// Bind a UDP socket for monoio's completion APIs.
pub(crate) fn bind_udp(addr: SocketAddr) -> Result<UdpSocket> {
    let socket = std::net::UdpSocket::bind(addr).with_context(|| format!("binding UDP {addr}"))?;
    socket
        .set_nonblocking(true)
        .with_context(|| format!("setting UDP {addr} nonblocking"))?;
    quic::enable_udp_gro(&socket);
    UdpSocket::from_std(socket).with_context(|| format!("adopting UDP {addr} into monoio"))
}

/// Spawn a task that reads datagrams from `socket` and forwards `(data, peer)`
/// into `tx`, dropping when the channel is full (datagrams are lossy by
/// contract). When `cancel` is given, the task also stops once it resolves —
/// used for per-session teardown on the client (drop the paired sender); the
/// server's process-lifetime listener passes `None`.
pub(crate) fn spawn_udp_recv(
    socket: Rc<UdpSocket>,
    mut tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    cancel: Option<oneshot::Receiver<()>>,
    buf_size: usize,
) {
    monoio::spawn(async move {
        let mut cancel = cancel;
        loop {
            let ready = match cancel.as_mut() {
                Some(c) => monoio::select! {
                    r = socket.readable(false) => r,
                    _ = c => break,
                },
                None => socket.readable(false).await,
            };
            if let Err(e) = ready {
                log::debug!("udp recv readiness ended: {e}");
                break;
            }

            for _ in 0..RECV_BATCH {
                match recv_udp_segments(&socket, buf_size) {
                    Ok(segments) => {
                        for (buf, from) in segments {
                            let _ = tx.try_send((buf, from));
                        }
                    }
                    Err(e) if matches!(e.kind(), ErrorKind::WouldBlock) => break,
                    Err(e) if matches!(e.kind(), ErrorKind::Interrupted) => continue,
                    Err(e) => {
                        log::debug!("udp recv ended: {e}");
                        return;
                    }
                }
            }
        }
    });
}

/// Write every packet quiche currently wants to send for `conn` to `socket`.
/// Returns `Err` on a fatal socket/transport error: the server logs it and moves
/// on to the next connection, the client treats it as connection loss.
pub(crate) async fn flush_connection(
    socket: &UdpSocket,
    conn: &mut quiche::Connection,
) -> Result<()> {
    let mut batch = SendBatch::new();

    'flush: loop {
        for _ in 0..SEND_BATCH {
            let mut out = vec![0u8; MAX_DATAGRAM_SIZE];
            match conn.send(&mut out) {
                Ok((n, info)) => {
                    out.truncate(n);
                    if let Some(pending) = batch.try_push(out, info.to) {
                        send_batch(socket, &mut batch).await?;
                        batch.push_first(pending, info.to);
                    }
                    if batch.ends_with_short_segment() {
                        send_batch(socket, &mut batch).await?;
                    }
                }
                Err(quiche::Error::Done) => break 'flush,
                Err(e) => bail!("conn.send: {e}"),
            }
        }

        send_batch(socket, &mut batch).await?;
    }
    send_batch(socket, &mut batch).await?;
    Ok(())
}

pub(crate) async fn send_udp(socket: &UdpSocket, buf: Vec<u8>, to: SocketAddr) -> io::Result<()> {
    let mut batch = SendBatch::new();
    batch.push_first(buf, to);
    send_batch(socket, &mut batch).await
}

pub(crate) async fn send_udp_connected(socket: &UdpSocket, buf: Vec<u8>) -> io::Result<()> {
    loop {
        match sendmsg_udp_connected(socket.as_raw_fd(), &buf) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == ErrorKind::WouldBlock => socket.writable(false).await?,
            Err(e) => return Err(e),
        }
    }
}

pub(crate) fn recv_udp_connected(socket: &UdpSocket, buf_size: usize) -> io::Result<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::with_capacity(buf_size);
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.capacity(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;

    let n = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut msg, libc::MSG_DONTWAIT) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    unsafe { buf.set_len(n as usize) };
    Ok(buf)
}

struct SendBatch {
    to: Option<SocketAddr>,
    segment_size: usize,
    packets: Vec<Vec<u8>>,
}

impl SendBatch {
    fn new() -> Self {
        Self {
            to: None,
            segment_size: 0,
            packets: Vec::with_capacity(SEND_BATCH),
        }
    }

    fn push_first(&mut self, packet: Vec<u8>, to: SocketAddr) {
        debug_assert!(self.packets.is_empty());
        self.segment_size = packet.len();
        self.to = Some(to);
        self.packets.push(packet);
    }

    fn try_push(&mut self, packet: Vec<u8>, to: SocketAddr) -> Option<Vec<u8>> {
        if self.packets.is_empty() {
            self.push_first(packet, to);
            return None;
        }

        let compatible = self.to == Some(to)
            && packet.len() <= self.segment_size
            && (packet.len() == self.segment_size || self.packets.len() + 1 <= SEND_BATCH);

        if compatible {
            self.packets.push(packet);
            None
        } else {
            Some(packet)
        }
    }

    fn ends_with_short_segment(&self) -> bool {
        self.packets
            .last()
            .is_some_and(|p| p.len() < self.segment_size)
    }

    fn take(&mut self) -> Option<(SocketAddr, usize, Vec<Vec<u8>>)> {
        let to = self.to.take()?;
        let segment_size = self.segment_size;
        self.segment_size = 0;
        let packets = std::mem::take(&mut self.packets);
        Some((to, segment_size, packets))
    }
}

async fn send_batch(socket: &UdpSocket, batch: &mut SendBatch) -> io::Result<()> {
    let Some((to, segment_size, packets)) = batch.take() else {
        return Ok(());
    };
    send_packets(socket, to, segment_size, packets).await
}

async fn send_packets(
    socket: &UdpSocket,
    to: SocketAddr,
    segment_size: usize,
    packets: Vec<Vec<u8>>,
) -> io::Result<()> {
    let use_gso = cfg!(target_os = "linux") && packets.len() > 1;
    if !use_gso && packets.len() > 1 {
        for packet in packets {
            send_payload(socket, to, &packet, None).await?;
        }
        return Ok(());
    }

    let mut payload = Vec::with_capacity(packets.iter().map(Vec::len).sum());
    for packet in &packets {
        payload.extend_from_slice(packet);
    }

    match send_payload(socket, to, &payload, use_gso.then_some(segment_size)).await {
        Ok(()) => Ok(()),
        Err(e) if use_gso && is_gso_unsupported(&e) => {
            log::debug!("UDP_SEGMENT send failed ({e}); falling back to plain sendmsg");
            for packet in packets {
                send_payload(socket, to, &packet, None).await?;
            }
            Ok(())
        }
        Err(e) => Err(e),
    }
}

async fn send_payload(
    socket: &UdpSocket,
    to: SocketAddr,
    payload: &[u8],
    gso_segment_size: Option<usize>,
) -> io::Result<()> {
    loop {
        match sendmsg_udp(socket.as_raw_fd(), to, payload, gso_segment_size) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == ErrorKind::WouldBlock => socket.writable(false).await?,
            Err(e) => return Err(e),
        }
    }
}

fn recv_udp_segments(
    socket: &UdpSocket,
    segment_size: usize,
) -> io::Result<Vec<(Vec<u8>, SocketAddr)>> {
    let capacity = segment_size
        .saturating_mul(RECV_BATCH)
        .min(u16::MAX as usize);
    let mut buf: Vec<u8> = Vec::with_capacity(capacity.max(segment_size));
    let mut addr: MaybeUninit<libc::sockaddr_storage> = MaybeUninit::uninit();
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.capacity(),
    };
    let mut control = vec![0u8; cmsg_space(std::mem::size_of::<u16>())];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = addr.as_mut_ptr().cast();
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control.len();

    let n = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut msg, libc::MSG_DONTWAIT) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    let n = n as usize;
    let from = socket_addr_from_storage(unsafe { addr.assume_init() })?;
    let gro_size = recv_gro_segment_size(&msg);
    unsafe { buf.set_len(n) };

    let Some(gro_size) = gro_size.filter(|&s| s > 0 && s < n) else {
        return Ok(vec![(buf, from)]);
    };

    let mut out = Vec::with_capacity(n.div_ceil(gro_size));
    for chunk in buf.chunks(gro_size) {
        out.push((chunk.to_vec(), from));
    }
    Ok(out)
}

fn sendmsg_udp(
    fd: std::os::fd::RawFd,
    to: SocketAddr,
    payload: &[u8],
    gso_segment_size: Option<usize>,
) -> io::Result<()> {
    let to = SockAddr::from(to);
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    let mut control = gso_segment_size
        .map(|_| vec![0u8; cmsg_space(std::mem::size_of::<u16>())])
        .unwrap_or_default();
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = to.as_ptr() as *mut libc::c_void;
    msg.msg_namelen = to.len();
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;

    if let Some(segment_size) = gso_segment_size {
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = control.len();
        set_udp_segment_cmsg(&mut msg, segment_size as u16);
    }

    let n = unsafe { libc::sendmsg(fd, &msg, send_flags()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n as usize != payload.len() {
        return Err(io::Error::new(
            ErrorKind::WriteZero,
            format!("short UDP send: {n}/{}", payload.len()),
        ));
    }
    Ok(())
}

fn sendmsg_udp_connected(fd: std::os::fd::RawFd, payload: &[u8]) -> io::Result<()> {
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;

    let n = unsafe { libc::sendmsg(fd, &msg, send_flags()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n as usize != payload.len() {
        return Err(io::Error::new(
            ErrorKind::WriteZero,
            format!("short UDP send: {n}/{}", payload.len()),
        ));
    }
    Ok(())
}

fn socket_addr_from_storage(storage: libc::sockaddr_storage) -> io::Result<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let addr: libc::sockaddr_in =
                unsafe { std::ptr::read((&storage as *const _) as *const _) };
            Ok(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes()),
                u16::from_be(addr.sin_port),
            )))
        }
        libc::AF_INET6 => {
            let addr: libc::sockaddr_in6 =
                unsafe { std::ptr::read((&storage as *const _) as *const _) };
            Ok(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(addr.sin6_addr.s6_addr),
                u16::from_be(addr.sin6_port),
                addr.sin6_flowinfo,
                addr.sin6_scope_id,
            )))
        }
        family => Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("unexpected UDP peer address family {family}"),
        )),
    }
}

fn cmsg_space(len: usize) -> usize {
    unsafe { libc::CMSG_SPACE(len as libc::c_uint) as usize }
}

fn cmsg_len(len: usize) -> usize {
    unsafe { libc::CMSG_LEN(len as libc::c_uint) as usize }
}

#[cfg(target_os = "linux")]
fn send_flags() -> libc::c_int {
    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL
}

#[cfg(not(target_os = "linux"))]
fn send_flags() -> libc::c_int {
    libc::MSG_DONTWAIT
}

#[cfg(target_os = "linux")]
fn recv_gro_segment_size(msg: &libc::msghdr) -> Option<usize> {
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_UDP && (*cmsg).cmsg_type == libc::UDP_GRO {
                return Some(*(libc::CMSG_DATA(cmsg) as *const u16) as usize);
            }
            cmsg = libc::CMSG_NXTHDR(msg, cmsg);
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn recv_gro_segment_size(_msg: &libc::msghdr) -> Option<usize> {
    None
}

#[cfg(target_os = "linux")]
fn set_udp_segment_cmsg(msg: &mut libc::msghdr, segment_size: u16) {
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(msg);
        (*cmsg).cmsg_level = libc::SOL_UDP;
        (*cmsg).cmsg_type = libc::UDP_SEGMENT;
        (*cmsg).cmsg_len = cmsg_len(std::mem::size_of::<u16>());
        *(libc::CMSG_DATA(cmsg) as *mut u16) = segment_size;
    }
}

#[cfg(not(target_os = "linux"))]
fn set_udp_segment_cmsg(_msg: &mut libc::msghdr, _segment_size: u16) {}

fn is_gso_unsupported(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::EINVAL) | Some(libc::EIO) | Some(libc::ENOTSUP)
    )
}
