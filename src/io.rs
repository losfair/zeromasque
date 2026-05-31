//! Shared runtime I/O for driving a quiche connection over a monoio UDP socket.
//! Both the proxy server and the client pump inbound packets through a channel
//! and flush outbound packets the same way; these are the shared primitives.

use std::net::SocketAddr;
use std::rc::Rc;

use anyhow::{Context, Result, bail};
use futures::channel::{mpsc, oneshot};
use monoio::net::udp::UdpSocket;

use crate::quic::MAX_DATAGRAM_SIZE;
use crate::util::RECV_BUF;

/// Spawn a task that reads datagrams from `socket` and forwards `(data, peer)`
/// into `tx`, dropping when the channel is full (datagrams are lossy by
/// contract). When `cancel` is given, the task also stops once it resolves —
/// used for per-session teardown on the client (drop the paired sender); the
/// server's process-lifetime listener passes `None`.
pub(crate) fn spawn_udp_recv(
    socket: Rc<UdpSocket>,
    mut tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    cancel: Option<oneshot::Receiver<()>>,
) {
    monoio::spawn(async move {
        let mut cancel = cancel;
        loop {
            let buf = vec![0u8; RECV_BUF];
            let (res, buf) = match cancel.as_mut() {
                Some(c) => monoio::select! {
                    r = socket.recv_from(buf) => r,
                    _ = c => break,
                },
                None => socket.recv_from(buf).await,
            };
            match res {
                Ok((n, from)) => {
                    let mut pkt = buf;
                    pkt.truncate(n);
                    let _ = tx.try_send((pkt, from));
                }
                Err(e) => {
                    log::debug!("udp recv ended: {e}");
                    break;
                }
            }
        }
    });
}

/// Write every packet quiche currently wants to send for `conn` to `socket`.
/// Returns `Err` on a fatal socket/transport error: the server logs it and moves
/// on to the next connection, the client treats it as connection loss.
pub(crate) async fn flush_connection(socket: &UdpSocket, conn: &mut quiche::Connection) -> Result<()> {
    loop {
        let mut out = vec![0u8; MAX_DATAGRAM_SIZE];
        match conn.send(&mut out) {
            Ok((n, info)) => {
                out.truncate(n);
                let (res, _) = socket.send_to(out, info.to).await;
                res.context("udp send")?;
            }
            Err(quiche::Error::Done) => break,
            Err(e) => bail!("conn.send: {e}"),
        }
    }
    Ok(())
}
