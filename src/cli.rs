use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(author, version, about = "io_uring MASQUE (CONNECT-UDP) proxy and client", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run the CONNECT-UDP proxy server.
    Serve(ServeArgs),
    /// Run the CONNECT-UDP client probe.
    Client(ClientArgs),
    /// Generate an ECH (Encrypted Client Hello) keypair + ECHConfig.
    GenEchKey(GenEchArgs),
}

#[derive(Parser, Debug)]
pub struct ServeArgs {
    /// UDP address to bind the QUIC listener to.
    #[arg(long, default_value = "0.0.0.0:4433")]
    pub addr: SocketAddr,

    /// Proxy URI template, e.g.
    /// `https://localhost:4433/masque?h={target_host}&p={target_port}`.
    #[arg(long)]
    pub template: String,

    /// TLS certificate chain (PEM).
    #[arg(long)]
    pub cert: PathBuf,

    /// TLS private key (PEM).
    #[arg(long)]
    pub key: PathBuf,

    /// Path to an ECH key file or directory (enables server-side ECH).
    #[arg(long, value_name = "PATH")]
    pub ech_key: Option<PathBuf>,
}

#[derive(Parser, Debug)]
pub struct ClientArgs {
    /// Proxy URI template, same form the server is configured with.
    #[arg(long)]
    pub template: String,

    /// Target to reach through the proxy, as `host:port`.
    #[arg(long)]
    pub target: String,

    /// Skip TLS certificate verification (testing only).
    #[arg(long)]
    pub insecure: bool,

    /// Extra CA certificate (PEM) to trust when verifying the proxy.
    #[arg(long, value_name = "FILE")]
    pub ca: Option<PathBuf>,

    /// Offer Encrypted Client Hello using this base64 ECHConfigList (the DNS
    /// `ech=` value).
    #[arg(long, value_name = "BASE64")]
    pub ech_config: Option<String>,

    /// Read the ECHConfigList (base64) from a file instead of the argument.
    #[arg(long, value_name = "FILE", conflicts_with = "ech_config")]
    pub ech_config_file: Option<PathBuf>,

    /// Message to tunnel to the target.
    #[arg(long, default_value = "ping")]
    pub message: String,

    /// How long to wait for tunnelled responses, in milliseconds.
    #[arg(long, default_value_t = 5000)]
    pub response_window_ms: u64,
}

impl ClientArgs {
    pub fn response_window(&self) -> Duration {
        Duration::from_millis(self.response_window_ms)
    }
}

#[derive(Parser, Debug)]
pub struct GenEchArgs {
    /// Public name embedded in the ECHConfig. The server's TLS cert must cover
    /// this name.
    #[arg(long, value_name = "NAME")]
    pub public_name: String,
}
