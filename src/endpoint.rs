//! The proxy endpoint: the fixed `https://authority/path` a CONNECT-UDP client
//! requests. The forwarding target is pinned on the server (`serve --target`),
//! so — unlike a generic RFC 9298 URI template — the path carries no
//! `{target_host}`/`{target_port}` variables; it is a constant the client and
//! server agree on.
//!
//! The server matches on the **path component only**, ignoring the query string.
//! That keeps it compatible with generic MASQUE clients whose URI template puts
//! `target_host`/`target_port` (or other parameters) in the query: the server
//! ignores them and forwards to its pinned target.

use anyhow::{Result, anyhow};

/// The path component (everything before `?`).
fn path_only(p: &str) -> &str {
    p.split_once('?').map(|(path, _)| path).unwrap_or(p)
}

/// A parsed proxy endpoint: the authority to connect to and the exact request
/// `:path` to send / accept.
#[derive(Debug, Clone)]
pub struct Endpoint {
    /// The full original endpoint string.
    pub raw: String,
    /// Authority (host[:port]) the client connects to / the server expects in
    /// the `:authority` pseudo-header.
    pub authority: String,
    /// The exact request `:path` (path + optional query).
    pub path: String,
}

impl Endpoint {
    pub fn parse(raw: &str) -> Result<Self> {
        // Split scheme://authority/pathquery without a URL crate: find "://".
        let after_scheme = raw
            .split_once("://")
            .map(|(_, rest)| rest)
            .ok_or_else(|| anyhow!("endpoint must be an absolute https URI: {raw}"))?;
        let (authority, path) = match after_scheme.find('/') {
            Some(idx) => (&after_scheme[..idx], &after_scheme[idx..]),
            None => (after_scheme, "/"),
        };
        if authority.is_empty() {
            return Err(anyhow!("endpoint has no authority: {raw}"));
        }
        Ok(Self {
            raw: raw.to_string(),
            authority: authority.to_string(),
            path: path.to_string(),
        })
    }

    /// Whether a request `:path` matches this endpoint, comparing the path
    /// component only (the query string is ignored on both sides).
    pub fn matches(&self, path: &str) -> bool {
        path_only(path) == path_only(&self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_authority_and_path() {
        let e = Endpoint::parse("https://localhost:4433/connect").unwrap();
        assert_eq!(e.authority, "localhost:4433");
        assert_eq!(e.path, "/connect");
        assert!(e.matches("/connect"));
        // The query string is ignored when matching.
        assert!(e.matches("/connect?x=1"));
        assert!(!e.matches("/other"));
    }

    #[test]
    fn query_is_ignored_when_matching() {
        // Compatible with variable-template clients: the server endpoint can be
        // a bare path, and a client that sends target_host/target_port in the
        // query still matches.
        let e = Endpoint::parse("https://proxy:4433/masque").unwrap();
        assert!(e.matches("/masque?h=127.0.0.1&p=53"));
        assert!(e.matches("/masque"));
        assert!(!e.matches("/other?h=127.0.0.1&p=53"));

        // A configured query is likewise ignored on the server side.
        let e2 = Endpoint::parse("https://proxy:4433/masque?ignored=1").unwrap();
        assert!(e2.matches("/masque?h=1&p=2"));
        assert!(e2.matches("/masque"));
    }

    #[test]
    fn defaults_path_when_absent() {
        let e = Endpoint::parse("https://proxy:4433").unwrap();
        assert_eq!(e.authority, "proxy:4433");
        assert_eq!(e.path, "/");
    }

    #[test]
    fn rejects_relative_uri() {
        assert!(Endpoint::parse("/connect").is_err());
    }
}
