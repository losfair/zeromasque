// PEM-bundled ECH key loading. Each pair is one `ECH PRIVATE KEY` block
// followed by one `ECH CONFIG` block. Files may contain multiple pairs.
// `--ech-key` accepts either a single file or a directory of files.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use base64ct::{Base64, Encoding};

use super::config::EchConfig;

pub const PEM_LABEL_KEY: &str = "ECH PRIVATE KEY";
pub const PEM_LABEL_CONFIG: &str = "ECH CONFIG";

#[derive(Clone, Debug)]
pub struct EchKeyPair {
    pub private_key: Vec<u8>,
    pub config: EchConfig,
}

#[derive(Clone, Debug)]
pub struct EchKeySet {
    pub pairs: Vec<EchKeyPair>,
}

impl EchKeySet {
    pub fn load(path: &Path) -> Result<Self> {
        let mut bundles = Vec::new();
        let meta = std::fs::metadata(path)
            .with_context(|| format!("failed to stat ECH key path {}", path.display()))?;
        if meta.is_dir() {
            let mut entries: Vec<PathBuf> = std::fs::read_dir(path)
                .with_context(|| format!("failed to read ECH key dir {}", path.display()))?
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|s| s.to_str())
                        .map(|n| !n.starts_with('.'))
                        .unwrap_or(false)
                })
                .collect();
            entries.sort();
            for entry in entries {
                if entry.is_file() {
                    let bytes = std::fs::read(&entry).with_context(|| {
                        format!("failed to read ECH key file {}", entry.display())
                    })?;
                    bundles.push((entry, bytes));
                }
            }
            if bundles.is_empty() {
                bail!("ECH key directory {} is empty", path.display());
            }
        } else {
            let bytes = std::fs::read(path)
                .with_context(|| format!("failed to read ECH key file {}", path.display()))?;
            bundles.push((path.to_path_buf(), bytes));
        }

        let mut pairs = Vec::new();
        for (origin, bytes) in &bundles {
            let file_pairs = parse_pem_bundle(bytes)
                .with_context(|| format!("parsing ECH PEM file {}", origin.display()))?;
            if file_pairs.is_empty() {
                bail!("no ECH key pairs found in {}", origin.display());
            }
            pairs.extend(file_pairs);
        }

        // Reject config_id collisions across pairs — receiver disambiguates by
        // config_id, so duplicates make the choice ambiguous.
        for i in 0..pairs.len() {
            for j in (i + 1)..pairs.len() {
                if pairs[i].config.config_id == pairs[j].config.config_id {
                    bail!(
                        "duplicate ECH config_id 0x{:02x} across loaded keys",
                        pairs[i].config.config_id
                    );
                }
            }
        }
        Ok(Self { pairs })
    }

    /// Encode all configs as one ECHConfigList ready for the DNS `ech=` value.
    pub fn config_list_bytes(&self) -> Vec<u8> {
        let configs: Vec<EchConfig> = self.pairs.iter().map(|p| p.config.clone()).collect();
        super::config::encode_list(&configs)
    }
}

fn parse_pem_bundle(bytes: &[u8]) -> Result<Vec<EchKeyPair>> {
    let blocks = parse_pem_blocks(bytes)?;
    let mut out = Vec::new();
    let mut iter = blocks.into_iter();
    while let Some(first) = iter.next() {
        let key_block = if first.label == PEM_LABEL_KEY {
            first
        } else if first.label == PEM_LABEL_CONFIG {
            bail!(
                "expected `{}` block before `{}`",
                PEM_LABEL_KEY,
                PEM_LABEL_CONFIG
            );
        } else {
            bail!("unexpected PEM label `{}`", first.label);
        };
        let config_block = iter.next().ok_or_else(|| {
            anyhow!(
                "missing `{}` block after `{}`",
                PEM_LABEL_CONFIG,
                PEM_LABEL_KEY
            )
        })?;
        if config_block.label != PEM_LABEL_CONFIG {
            bail!(
                "expected `{}` after `{}`, found `{}`",
                PEM_LABEL_CONFIG,
                PEM_LABEL_KEY,
                config_block.label
            );
        }
        let config =
            EchConfig::decode(&config_block.body).with_context(|| "decoding `ECH CONFIG`")?;
        out.push(EchKeyPair {
            private_key: key_block.body,
            config,
        });
    }
    Ok(out)
}

struct PemBlock {
    label: String,
    body: Vec<u8>,
}

/// A minimal PEM parser tolerant of arbitrary whitespace between blocks.
/// We don't reuse rustls's PEM parser because it only recognises the
/// pki-types labels (`CERTIFICATE`, `PRIVATE KEY`, ...).
fn parse_pem_blocks(bytes: &[u8]) -> Result<Vec<PemBlock>> {
    let text = std::str::from_utf8(bytes).map_err(|_| anyhow!("PEM file is not valid UTF-8"))?;
    let mut out = Vec::new();
    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let label = if let Some(rest) = trimmed
            .strip_prefix("-----BEGIN ")
            .and_then(|s| s.strip_suffix("-----"))
        {
            rest.to_string()
        } else {
            bail!("expected PEM `-----BEGIN ...-----`, got: {trimmed}");
        };
        let mut b64 = String::new();
        let end_marker = format!("-----END {}-----", label);
        let mut saw_end = false;
        for inner in lines.by_ref() {
            let t = inner.trim();
            if t == end_marker {
                saw_end = true;
                break;
            }
            if t.is_empty() {
                continue;
            }
            b64.push_str(t);
        }
        if !saw_end {
            bail!("missing PEM end marker for label `{}`", label);
        }
        let body = Base64::decode_vec(&b64)
            .map_err(|e| anyhow!("invalid base64 in PEM block `{}`: {}", label, e))?;
        out.push(PemBlock { label, body });
    }
    Ok(out)
}

/// Render a key pair as the two-block PEM bundle expected by `--ech-key`.
pub fn encode_pair_pem(private_key: &[u8], config: &EchConfig) -> String {
    let mut out = String::new();
    write_pem_block(&mut out, PEM_LABEL_KEY, private_key);
    write_pem_block(&mut out, PEM_LABEL_CONFIG, &config.encode());
    out
}

fn write_pem_block(out: &mut String, label: &str, body: &[u8]) {
    let encoded = Base64::encode_string(body);
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ech::config::{
        CipherSuite, HPKE_AEAD_AES_128_GCM, HPKE_KDF_HKDF_SHA256, HPKE_KEM_DHKEM_X25519,
    };

    fn sample_config(id: u8) -> EchConfig {
        EchConfig {
            config_id: id,
            kem_id: HPKE_KEM_DHKEM_X25519,
            public_key: vec![0xab; 32],
            cipher_suites: vec![CipherSuite {
                kdf_id: HPKE_KDF_HKDF_SHA256,
                aead_id: HPKE_AEAD_AES_128_GCM,
            }],
            maximum_name_length: 0,
            public_name: "example.com".into(),
        }
    }

    #[test]
    fn pem_roundtrip_single_pair() {
        let cfg = sample_config(7);
        let pem = encode_pair_pem(&[0x55; 32], &cfg);
        let pairs = parse_pem_bundle(pem.as_bytes()).unwrap();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].private_key, vec![0x55; 32]);
        assert_eq!(pairs[0].config.config_id, 7);
    }

    #[test]
    fn pem_roundtrip_multiple_pairs() {
        let a = sample_config(1);
        let b = sample_config(2);
        let mut pem = String::new();
        pem.push_str(&encode_pair_pem(&[0x01; 32], &a));
        pem.push('\n');
        pem.push_str(&encode_pair_pem(&[0x02; 32], &b));
        let pairs = parse_pem_bundle(pem.as_bytes()).unwrap();
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].config.config_id, 1);
        assert_eq!(pairs[1].config.config_id, 2);
    }
}
