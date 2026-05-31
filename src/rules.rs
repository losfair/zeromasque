//! The server's endpoint → target rule table, loaded from a JSON file:
//!
//! ```json
//! [
//!   {"endpoint": "https://a.example.com/masque", "target": "127.0.0.1:1234"},
//!   {"endpoint": "https://b.example.com/connect", "target": "10.0.0.2:53"}
//! ]
//! ```
//!
//! A CONNECT-UDP request is matched on its `:authority` and `:path` (path
//! component only — the query string is ignored, so generic MASQUE clients that
//! carry `target_host`/`target_port` in the query still match). The first rule
//! whose endpoint authority and path match wins, and its target is the pinned
//! forwarding destination; clients never choose a target.

use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;

use crate::endpoint::Endpoint;

#[derive(Deserialize)]
struct RuleSpec {
    endpoint: String,
    target: String,
    /// Linux only: forward with the client's external source address preserved
    /// (`IP_TRANSPARENT`). See `RuleMatch`.
    #[serde(default)]
    transparent: bool,
}

struct Rule {
    endpoint: Endpoint,
    target: SocketAddr,
    transparent: bool,
}

/// The forwarding decision for a matched request.
#[derive(Clone, Copy)]
pub struct RuleMatch {
    pub target: SocketAddr,
    /// When set, forward to the target with the client's external source IP
    /// preserved via `IP_TRANSPARENT` (Linux only).
    pub transparent: bool,
}

/// A loaded, validated rule table.
pub struct RuleTable {
    rules: Vec<Rule>,
}

impl RuleTable {
    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read_to_string(path)
            .with_context(|| format!("reading rule table {}", path.display()))?;
        let specs: Vec<RuleSpec> = serde_json::from_str(&data)
            .with_context(|| format!("parsing rule table {}", path.display()))?;
        if specs.is_empty() {
            bail!("rule table {} is empty", path.display());
        }
        let mut rules = Vec::with_capacity(specs.len());
        for spec in specs {
            let endpoint = Endpoint::parse(&spec.endpoint)
                .with_context(|| format!("rule endpoint {:?}", spec.endpoint))?;
            let target =
                resolve(&spec.target).with_context(|| format!("rule target {:?}", spec.target))?;
            rules.push(Rule {
                endpoint,
                target,
                transparent: spec.transparent,
            });
        }
        Ok(Self { rules })
    }

    /// The forwarding decision for a request `:authority` + `:path`, or `None`
    /// if no rule matches.
    pub fn match_target(&self, authority: &str, path: &str) -> Option<RuleMatch> {
        self.rules
            .iter()
            .find(|r| r.endpoint.authority == authority && r.endpoint.matches(path))
            .map(|r| RuleMatch {
                target: r.target,
                transparent: r.transparent,
            })
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Number of rules requesting transparent forwarding.
    pub fn transparent_count(&self) -> usize {
        self.rules.iter().filter(|r| r.transparent).count()
    }
}

fn resolve(s: &str) -> Result<SocketAddr> {
    s.to_socket_addrs()
        .with_context(|| format!("resolving {s}"))?
        .next()
        .ok_or_else(|| anyhow!("no addresses for {s}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp(name: &str, contents: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "zeromasque-rules-{}-{name}.json",
            std::process::id()
        ));
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        p
    }

    fn target(t: &RuleTable, authority: &str, path: &str) -> Option<SocketAddr> {
        t.match_target(authority, path).map(|m| m.target)
    }

    #[test]
    fn matches_authority_and_path_ignoring_query() {
        let p = write_temp(
            "match",
            r#"[
              {"endpoint":"https://a.example.com/masque","target":"127.0.0.1:1234"},
              {"endpoint":"https://b.example.com/connect","target":"127.0.0.1:5678"}
            ]"#,
        );
        let t = RuleTable::load(&p).unwrap();
        assert_eq!(t.len(), 2);
        assert_eq!(
            target(&t, "a.example.com", "/masque"),
            "127.0.0.1:1234".parse().ok()
        );
        // Query is ignored on the path match.
        assert_eq!(
            target(&t, "a.example.com", "/masque?h=1.2.3.4&p=53"),
            "127.0.0.1:1234".parse().ok()
        );
        assert_eq!(
            target(&t, "b.example.com", "/connect"),
            "127.0.0.1:5678".parse().ok()
        );
        // Right path, wrong host -> no match.
        assert_eq!(target(&t, "b.example.com", "/masque"), None);
        // Right host, wrong path -> no match.
        assert_eq!(target(&t, "a.example.com", "/other"), None);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn transparent_defaults_off_and_parses_when_set() {
        let p = write_temp(
            "transparent",
            r#"[
              {"endpoint":"https://a/x","target":"127.0.0.1:1","transparent":true},
              {"endpoint":"https://b/y","target":"127.0.0.1:2"}
            ]"#,
        );
        let t = RuleTable::load(&p).unwrap();
        assert!(t.match_target("a", "/x").unwrap().transparent);
        assert!(!t.match_target("b", "/y").unwrap().transparent);
        assert_eq!(t.transparent_count(), 1);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn rejects_empty_table() {
        let p = write_temp("empty", "[]");
        assert!(RuleTable::load(&p).is_err());
        let _ = std::fs::remove_file(&p);
    }
}
