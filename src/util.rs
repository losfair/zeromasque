//! Small helpers shared by the proxy server and client.

use std::time::Duration;

/// Scratch buffer size for a single UDP datagram read.
pub(crate) const RECV_BUF: usize = 65535;
/// Bound on the local mpsc channels shuttling packets between tasks.
pub(crate) const CHANNEL_CAP: usize = 1024;

/// Lower-case hex encoding, for logging connection IDs and fingerprints.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Sleep until `timeout` elapses, or park forever when it is `None` (no active
/// timer) so it can sit as a `select!` arm without ever firing.
pub(crate) async fn sleep_opt(timeout: Option<Duration>) {
    match timeout {
        Some(d) => monoio::time::sleep(d).await,
        None => std::future::pending::<()>().await,
    }
}
