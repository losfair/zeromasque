mod cli;
mod client;
mod dgram;
mod ech;
#[cfg(test)]
mod ech_test;
mod quic;
mod reload;
mod server;
mod template;
mod varint;

use std::rc::Rc;

use anyhow::{Context, Result};
use clap::Parser;
use monoio::{IoUringDriver, RuntimeBuilder};

use crate::cli::{Cli, ClientArgs, Command, GenEchArgs, ServeArgs};
use crate::ech::key::EchKeySet;
use crate::quic::Verify;
use crate::reload::{ReloadPaths, SighupBlocked, spawn_reload};
use crate::server::{Server, ServerConfig};
use crate::template::Template;

fn main() -> Result<()> {
    init_logging();
    let cli = Cli::parse();
    match cli.command {
        Command::Serve(args) => serve(args),
        Command::Client(args) => client(args),
        Command::GenEchKey(args) => gen_ech_key(args),
    }
}

fn serve(args: ServeArgs) -> Result<()> {
    let template = Rc::new(Template::parse(&args.template)?);

    // Build the initial config eagerly so config errors fail fast (before the
    // runtime is up). ECH keys are loaded here too.
    let ech = match &args.ech_key {
        Some(path) => {
            let set = EchKeySet::load(path)
                .with_context(|| format!("loading ECH keys from {}", path.display()))?;
            use base64ct::{Base64, Encoding};
            let list_b64 = Base64::encode_string(&set.config_list_bytes());
            eprintln!(
                "ECH enabled: {} key(s). On ECH acceptance only the inner SNI is \
                 authenticated; the public name needs a valid cert for the rejection fallback.",
                set.pairs.len()
            );
            eprintln!("Publish in the DNS HTTPS record: ech=\"{list_b64}\"");
            Some(set)
        }
        None => None,
    };
    let config = quic::build_server_config(&args.cert, &args.key, ech.as_ref())?;
    let server_config = Rc::new(ServerConfig {
        config: std::cell::RefCell::new(config),
    });

    let reload_paths = ReloadPaths {
        cert: args.cert.clone(),
        key: args.key.clone(),
        ech_key: args.ech_key.clone(),
    };

    // Block SIGHUP before the runtime starts any work.
    let blocked = SighupBlocked::new();

    RuntimeBuilder::<IoUringDriver>::new()
        .enable_timer()
        .build()
        .expect("failed to build io_uring runtime")
        .block_on(async move {
            let socket = monoio::net::udp::UdpSocket::bind(args.addr)
                .with_context(|| format!("binding QUIC listener {}", args.addr))?;
            eprintln!("zeromasque proxy listening on {} (udp)", args.addr);
            eprintln!("proxy template: {}", template.raw);

            spawn_reload(server_config.clone(), reload_paths, blocked)?;

            let server = Server::new(socket, server_config, template)?;
            server.run().await
        })
}

fn client(args: ClientArgs) -> Result<()> {
    let template = Template::parse(&args.template)?;
    let (target_host, target_port) = split_host_port(&args.target)?;

    let verify = if args.insecure {
        Verify::Insecure
    } else {
        Verify::Roots {
            ca_file: args.ca.clone(),
        }
    };

    let ech_config_list = load_ech_config(&args)?;

    let response_window = args.response_window();
    let opts = client::ClientOptions {
        template,
        target_host,
        target_port,
        verify,
        ech_config_list,
        message: args.message.into_bytes(),
        response_window,
    };

    RuntimeBuilder::<IoUringDriver>::new()
        .enable_timer()
        .build()
        .expect("failed to build io_uring runtime")
        .block_on(client::run(opts))
}

fn gen_ech_key(args: GenEchArgs) -> Result<()> {
    ech::keygen::run(&args.public_name)
}

fn load_ech_config(args: &ClientArgs) -> Result<Option<Vec<u8>>> {
    use base64ct::{Base64, Encoding};
    let b64 = if let Some(s) = &args.ech_config {
        Some(s.trim().to_string())
    } else if let Some(path) = &args.ech_config_file {
        Some(
            std::fs::read_to_string(path)
                .with_context(|| format!("reading ECH config file {}", path.display()))?
                .trim()
                .to_string(),
        )
    } else {
        None
    };
    match b64 {
        Some(b64) => {
            let bytes = Base64::decode_vec(&b64)
                .map_err(|e| anyhow::anyhow!("invalid base64 ECHConfigList: {e}"))?;
            Ok(Some(bytes))
        }
        None => Ok(None),
    }
}

fn split_host_port(s: &str) -> Result<(String, u16)> {
    // Support host:port and [ipv6]:port.
    if let Some(rest) = s.strip_prefix('[') {
        let (host, port) = rest
            .split_once("]:")
            .ok_or_else(|| anyhow::anyhow!("invalid [ipv6]:port target: {s}"))?;
        return Ok((
            host.to_string(),
            port.parse().context("parsing target port")?,
        ));
    }
    let (host, port) = s
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("target must be host:port: {s}"))?;
    Ok((
        host.to_string(),
        port.parse().context("parsing target port")?,
    ))
}

fn init_logging() {
    // Minimal stderr logger; honour RUST_LOG=off/error/warn/info/debug.
    let level = std::env::var("RUST_LOG").ok();
    let filter = match level.as_deref() {
        Some("off") => log::LevelFilter::Off,
        Some("error") => log::LevelFilter::Error,
        Some("warn") => log::LevelFilter::Warn,
        Some("debug") => log::LevelFilter::Debug,
        Some("trace") => log::LevelFilter::Trace,
        _ => log::LevelFilter::Info,
    };
    log::set_logger(&LOGGER).ok();
    log::set_max_level(filter);
}

struct StderrLogger;
static LOGGER: StderrLogger = StderrLogger;
impl log::Log for StderrLogger {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }
    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            eprintln!("[{}] {}", record.level(), record.args());
        }
    }
    fn flush(&self) {}
}
