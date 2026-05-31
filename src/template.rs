//! Minimal RFC 6570-style URI template support for the two CONNECT-UDP
//! variables (`target_host`, `target_port`), interoperable with the
//! `uritemplate` library masque-go uses.
//!
//! Both the well-known path form
//! `…/.well-known/masque/udp/{target_host}/{target_port}/` and the query form
//! `…/masque?h={target_host}&p={target_port}` reduce to: a literal prefix, the
//! host variable, a literal middle, the port variable, and a literal suffix
//! (host always precedes port). We split on that shape rather than pulling in a
//! full template engine.

use anyhow::{Result, anyhow, bail};

pub const VAR_HOST: &str = "{target_host}";
pub const VAR_PORT: &str = "{target_port}";

/// A parsed proxy URI template, retaining the scheme/authority for client use
/// and the path+query skeleton for expansion and matching.
#[derive(Debug, Clone)]
pub struct Template {
    /// The full original template string.
    pub raw: String,
    /// Authority (host[:port]) the client connects to / the server expects in
    /// the `:authority` pseudo-header.
    pub authority: String,
    /// Literal text of the path+query before `{target_host}`.
    prefix: String,
    /// Literal text between `{target_host}` and `{target_port}`.
    middle: String,
    /// Literal text after `{target_port}`.
    suffix: String,
}

impl Template {
    pub fn parse(raw: &str) -> Result<Self> {
        // Split scheme://authority/pathquery without a URL crate: find "://".
        let after_scheme = raw
            .split_once("://")
            .map(|(_, rest)| rest)
            .ok_or_else(|| anyhow!("template must be an absolute https URI: {raw}"))?;
        let (authority, path_query) = match after_scheme.find('/') {
            Some(idx) => (&after_scheme[..idx], &after_scheme[idx..]),
            None => (after_scheme, "/"),
        };

        let host_at = path_query
            .find(VAR_HOST)
            .ok_or_else(|| anyhow!("template missing {VAR_HOST}: {raw}"))?;
        let after_host = host_at + VAR_HOST.len();
        let port_rel = path_query[after_host..]
            .find(VAR_PORT)
            .ok_or_else(|| anyhow!("template missing {VAR_PORT} after {VAR_HOST}: {raw}"))?;
        let port_at = after_host + port_rel;

        Ok(Self {
            raw: raw.to_string(),
            authority: authority.to_string(),
            prefix: path_query[..host_at].to_string(),
            middle: path_query[after_host..port_at].to_string(),
            suffix: path_query[port_at + VAR_PORT.len()..].to_string(),
        })
    }

    /// Expand into a concrete `:path` value (client side). IPv6 literals carry
    /// colons, which RFC 9298 asks to percent-encode in the host slot.
    pub fn expand(&self, host: &str, port: u16) -> String {
        let host = host.replace(':', "%3A");
        format!("{}{host}{}{port}{}", self.prefix, self.middle, self.suffix)
    }

    /// Match a request `:path` against the template, recovering the target host
    /// and port (server side).
    pub fn match_path(&self, path: &str) -> Result<(String, u16)> {
        let rest = path
            .strip_prefix(&self.prefix)
            .ok_or_else(|| anyhow!("path does not match template prefix"))?;
        // Both supported template forms have a non-empty middle separator.
        let host_end = rest
            .find(&self.middle)
            .filter(|_| !self.middle.is_empty())
            .ok_or_else(|| anyhow!("path does not match template separator"))?;
        let host = &rest[..host_end];
        let after = &rest[host_end + self.middle.len()..];
        let port_str = if self.suffix.is_empty() {
            after
        } else {
            after
                .strip_suffix(&self.suffix)
                .ok_or_else(|| anyhow!("path does not match template suffix"))?
        };
        if host.is_empty() || port_str.is_empty() {
            bail!("template match produced empty target_host/target_port");
        }
        let host = host.replace("%3A", ":");
        let port: u16 = port_str
            .parse()
            .map_err(|e| anyhow!("invalid target_port {port_str:?}: {e}"))?;
        Ok((host, port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_form_roundtrip() {
        let t = Template::parse("https://localhost:4433/masque?h={target_host}&p={target_port}")
            .unwrap();
        assert_eq!(t.authority, "localhost:4433");
        let path = t.expand("192.0.2.1", 4242);
        assert_eq!(path, "/masque?h=192.0.2.1&p=4242");
        assert_eq!(
            t.match_path(&path).unwrap(),
            ("192.0.2.1".to_string(), 4242)
        );
    }

    #[test]
    fn well_known_path_form_roundtrip() {
        let t = Template::parse(
            "https://proxy.example/.well-known/masque/udp/{target_host}/{target_port}/",
        )
        .unwrap();
        let path = t.expand("example.com", 443);
        assert_eq!(path, "/.well-known/masque/udp/example.com/443/");
        assert_eq!(
            t.match_path(&path).unwrap(),
            ("example.com".to_string(), 443)
        );
    }

    #[test]
    fn ipv6_host_is_percent_encoded() {
        let t = Template::parse("https://h/p?h={target_host}&p={target_port}").unwrap();
        let path = t.expand("2001:db8::1", 53);
        assert!(path.contains("2001%3Adb8%3A%3A1"));
        assert_eq!(t.match_path(&path).unwrap().0, "2001:db8::1");
    }

    #[test]
    fn rejects_missing_variables() {
        assert!(Template::parse("https://h/p?h={target_host}").is_err());
        assert!(Template::parse("https://h/p").is_err());
    }
}
