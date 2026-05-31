//! Certificate / ECH hot reload, triggered by `SIGHUP`.
//!
//! On Linux this mirrors zeroserve: SIGHUP is blocked process-wide and drained
//! through a `signalfd` wrapped as a monoio file, so the reload runs on the
//! runtime rather than in an async-signal-unsafe handler. On each signal the
//! server's quiche config is rebuilt from the cert/key/ECH paths and swapped in;
//! new connections pick up the rotated material while live ones keep theirs.
//!
//! `signalfd` is Linux-only, so on other platforms (e.g. macOS with the kqueue
//! backend) hot reload is disabled: SIGHUP is ignored and the server keeps the
//! configuration it started with.

use std::path::PathBuf;

/// Cert/key/ECH paths needed to rebuild the server config on reload.
#[derive(Clone)]
pub struct ReloadPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
    pub ech_key: Option<PathBuf>,
}

#[cfg(target_os = "linux")]
mod imp {
    use std::os::fd::FromRawFd;
    use std::rc::Rc;

    use anyhow::{Context, Result};
    use monoio::fs::File;
    use monoio::io::AsyncReadRentExt;

    use super::ReloadPaths;
    use crate::ech::key::EchKeySet;
    use crate::quic;
    use crate::server::ServerConfig;

    /// Block `SIGHUP` on the calling thread (and, since this is the only thread,
    /// the process). Must run before any task could observe the default action.
    pub struct SighupBlocked {
        pub(super) mask: libc::sigset_t,
    }

    impl SighupBlocked {
        pub fn new() -> Self {
            let mut mask: libc::sigset_t = unsafe { core::mem::zeroed() };
            unsafe {
                libc::sigemptyset(&mut mask);
                libc::sigaddset(&mut mask, libc::SIGHUP);
                libc::sigprocmask(libc::SIG_BLOCK, &mask, core::ptr::null_mut());
            }
            Self { mask }
        }
    }

    /// Spawn the reload task. Returns once the signalfd is installed.
    pub fn spawn_reload(
        server_config: Rc<ServerConfig>,
        paths: ReloadPaths,
        blocked: SighupBlocked,
    ) -> Result<()> {
        let sfd = unsafe { libc::signalfd(-1, &blocked.mask, libc::SFD_CLOEXEC) };
        if sfd < 0 {
            return Err(std::io::Error::last_os_error()).context("creating signalfd");
        }
        let sfile = unsafe {
            File::from_std(std::fs::File::from_raw_fd(sfd)).context("wrapping signalfd as file")?
        };

        monoio::spawn(reload_task(server_config, paths, sfile));
        Ok(())
    }

    async fn reload_task(server_config: Rc<ServerConfig>, paths: ReloadPaths, mut sfile: File) {
        loop {
            // Drain one siginfo struct per delivered SIGHUP.
            let (res, _) = sfile
                .read_exact(Vec::with_capacity(std::mem::size_of::<
                    libc::signalfd_siginfo,
                >()))
                .await;
            if let Err(e) = res {
                if e.raw_os_error() == Some(libc::ECANCELED) {
                    continue;
                }
                log::error!("signalfd read failed: {e}");
                continue;
            }

            match rebuild(&paths) {
                Ok(config) => {
                    *server_config.config.borrow_mut() = config;
                    log::info!("reloaded TLS/ECH configuration");
                }
                Err(e) => log::error!("reload failed, keeping previous config: {e:?}"),
            }
        }
    }

    fn rebuild(paths: &ReloadPaths) -> Result<quiche::Config> {
        let ech = match &paths.ech_key {
            Some(path) => Some(
                EchKeySet::load(path)
                    .with_context(|| format!("loading ECH keys from {}", path.display()))?,
            ),
            None => None,
        };
        quic::build_server_config(&paths.cert, &paths.key, ech.as_ref())
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use std::rc::Rc;

    use anyhow::Result;

    use super::ReloadPaths;
    use crate::server::ServerConfig;

    /// On non-Linux platforms hot reload is unavailable (`signalfd` is
    /// Linux-only). Ignore SIGHUP so it does not terminate the process.
    pub struct SighupBlocked;

    impl SighupBlocked {
        pub fn new() -> Self {
            // SIG_IGN keeps SIGHUP from killing the process via its default
            // action, since we cannot act on it here.
            unsafe { libc::signal(libc::SIGHUP, libc::SIG_IGN) };
            Self
        }
    }

    pub fn spawn_reload(
        _server_config: Rc<ServerConfig>,
        _paths: ReloadPaths,
        _blocked: SighupBlocked,
    ) -> Result<()> {
        log::warn!(
            "certificate hot reload (SIGHUP) is only supported on Linux; \
             running with the configuration loaded at startup"
        );
        Ok(())
    }
}

pub use imp::{SighupBlocked, spawn_reload};
