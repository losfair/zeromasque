use std::net::SocketAddr;
use std::path::PathBuf;

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

    /// JSON rule table mapping endpoints to pinned targets, e.g.
    /// `[{"endpoint":"https://a.example.com/masque","target":"127.0.0.1:1234"}]`.
    /// Requests are matched on `:authority` + path (query ignored); the matching
    /// rule's target is the pinned destination. Hot-reloadable via SIGHUP.
    #[arg(long, value_name = "FILE")]
    pub rules: PathBuf,

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
    /// Proxy endpoint URI, identical to the server's `--endpoint`.
    #[arg(long)]
    pub endpoint: String,

    /// Local UDP address to bind. Every datagram received here is tunnelled
    /// through the proxy (one CONNECT-UDP flow per local source address), with
    /// replies relayed back. The destination is whatever the server pins.
    #[arg(long, value_name = "IP:PORT")]
    pub listen: SocketAddr,

    /// Override the proxy UDP address to connect to (`ip:port`). The template
    /// host is still used for SNI and `:authority`; this only changes where
    /// packets are sent. Useful when the template host resolves to an address
    /// the proxy isn't listening on (e.g. `localhost` -> `::1`).
    #[arg(long, value_name = "IP:PORT")]
    pub proxy_addr: Option<SocketAddr>,

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
}

#[derive(Parser, Debug)]
pub struct GenEchArgs {
    /// Public name (cleartext cover identity) embedded in the ECHConfig. The
    /// server should be able to present a valid cert for it for the ECH-rejection
    /// fallback; on ECH acceptance only the inner SNI is authenticated.
    #[arg(long, value_name = "NAME")]
    pub public_name: String,
}
