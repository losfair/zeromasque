// Wire format for ECHConfig / ECHConfigList per draft-ietf-tls-esni-22 §4.

use anyhow::{Result, anyhow, bail};

pub const ECH_CONFIG_VERSION_V18: u16 = 0xfe0d;

// HPKE codepoints from RFC 9180 §7. Most are kept as a reference catalogue
// even when not yet referenced from runtime code — the values are stable.
#[allow(dead_code)]
pub const HPKE_KEM_DHKEM_P256: u16 = 0x0010;
#[allow(dead_code)]
pub const HPKE_KEM_DHKEM_P384: u16 = 0x0011;
#[allow(dead_code)]
pub const HPKE_KEM_DHKEM_P521: u16 = 0x0012;
pub const HPKE_KEM_DHKEM_X25519: u16 = 0x0020;

pub const HPKE_KDF_HKDF_SHA256: u16 = 0x0001;
#[allow(dead_code)]
pub const HPKE_KDF_HKDF_SHA384: u16 = 0x0002;
#[allow(dead_code)]
pub const HPKE_KDF_HKDF_SHA512: u16 = 0x0003;

pub const HPKE_AEAD_AES_128_GCM: u16 = 0x0001;
#[allow(dead_code)]
pub const HPKE_AEAD_AES_256_GCM: u16 = 0x0002;
#[allow(dead_code)]
pub const HPKE_AEAD_CHACHA20_POLY1305: u16 = 0x0003;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CipherSuite {
    pub kdf_id: u16,
    pub aead_id: u16,
}

#[derive(Clone, Debug)]
pub struct EchConfig {
    pub config_id: u8,
    pub kem_id: u16,
    pub public_key: Vec<u8>,
    pub cipher_suites: Vec<CipherSuite>,
    pub maximum_name_length: u8,
    pub public_name: String,
}

impl EchConfig {
    /// Serialize the full ECHConfig (version + length + contents) — the form
    /// embedded inside an ECHConfigList and used as part of the HPKE `info`
    /// per draft-ietf-tls-esni-22 §6.1.
    pub fn encode(&self) -> Vec<u8> {
        let mut contents = Vec::with_capacity(64 + self.public_key.len() + self.public_name.len());

        // HpkeKeyConfig
        contents.push(self.config_id);
        contents.extend_from_slice(&self.kem_id.to_be_bytes());
        let pk_len = u16::try_from(self.public_key.len()).expect("public_key too long");
        contents.extend_from_slice(&pk_len.to_be_bytes());
        contents.extend_from_slice(&self.public_key);

        // cipher_suites<4..2^16-4>
        let cs_bytes_len = u16::try_from(self.cipher_suites.len() * 4).expect("too many suites");
        contents.extend_from_slice(&cs_bytes_len.to_be_bytes());
        for cs in &self.cipher_suites {
            contents.extend_from_slice(&cs.kdf_id.to_be_bytes());
            contents.extend_from_slice(&cs.aead_id.to_be_bytes());
        }

        // maximum_name_length, public_name<1..255>, extensions<0..2^16-1>
        contents.push(self.maximum_name_length);
        let pn_bytes = self.public_name.as_bytes();
        let pn_len = u8::try_from(pn_bytes.len()).expect("public_name too long");
        contents.push(pn_len);
        contents.extend_from_slice(pn_bytes);
        contents.extend_from_slice(&[0u8, 0u8]); // empty extensions list

        let mut out = Vec::with_capacity(contents.len() + 4);
        out.extend_from_slice(&ECH_CONFIG_VERSION_V18.to_be_bytes());
        let contents_len = u16::try_from(contents.len()).expect("config contents too long");
        out.extend_from_slice(&contents_len.to_be_bytes());
        out.extend_from_slice(&contents);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let cfg = Self::decode_from(&mut r)?;
        if !r.is_empty() {
            bail!("trailing bytes after ECHConfig");
        }
        Ok(cfg)
    }

    pub fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        let version = r.read_u16()?;
        let contents_len = r.read_u16()? as usize;
        let contents = r.read_slice(contents_len)?;
        if version != ECH_CONFIG_VERSION_V18 {
            bail!("unsupported ECHConfig version 0x{:04x}", version);
        }
        let mut cr = Reader::new(contents);
        let config_id = cr.read_u8()?;
        let kem_id = cr.read_u16()?;
        let pk_len = cr.read_u16()? as usize;
        let public_key = cr.read_slice(pk_len)?.to_vec();
        let cs_bytes_len = cr.read_u16()? as usize;
        if !cs_bytes_len.is_multiple_of(4) || cs_bytes_len == 0 {
            bail!("invalid cipher_suites length");
        }
        let mut cipher_suites = Vec::with_capacity(cs_bytes_len / 4);
        let cs_bytes = cr.read_slice(cs_bytes_len)?;
        let mut csr = Reader::new(cs_bytes);
        while !csr.is_empty() {
            cipher_suites.push(CipherSuite {
                kdf_id: csr.read_u16()?,
                aead_id: csr.read_u16()?,
            });
        }
        let maximum_name_length = cr.read_u8()?;
        let pn_len = cr.read_u8()? as usize;
        let pn_bytes = cr.read_slice(pn_len)?.to_vec();
        let public_name = String::from_utf8(pn_bytes)
            .map_err(|_| anyhow!("ECHConfig public_name is not valid UTF-8"))?;
        // extensions<0..2^16-1>
        let ext_len = cr.read_u16()? as usize;
        let _ext_bytes = cr.read_slice(ext_len)?;
        // Don't enforce trailing-empty on contents — future ESNI revisions may
        // append fields and the spec asks readers to ignore unknown contents.
        Ok(Self {
            config_id,
            kem_id,
            public_key,
            cipher_suites,
            maximum_name_length,
            public_name,
        })
    }
}

/// Serialize an ECHConfigList (u16-length-prefixed concatenation of ECHConfig).
pub fn encode_list(configs: &[EchConfig]) -> Vec<u8> {
    let mut body = Vec::new();
    for c in configs {
        body.extend_from_slice(&c.encode());
    }
    let mut out = Vec::with_capacity(body.len() + 2);
    let body_len = u16::try_from(body.len()).expect("ECHConfigList too long");
    out.extend_from_slice(&body_len.to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// Minimal byte reader used by the ECH parsers. Keeping our own copy avoids
/// pulling in rustls's doc-hidden `internal::msgs::codec::Reader`.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        if self.remaining() < 1 {
            bail!("short read u8");
        }
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    pub fn read_u16(&mut self) -> Result<u16> {
        if self.remaining() < 2 {
            bail!("short read u16");
        }
        let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    #[allow(dead_code)]
    pub fn read_u24(&mut self) -> Result<u32> {
        if self.remaining() < 3 {
            bail!("short read u24");
        }
        let v = u32::from_be_bytes([
            0,
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
        ]);
        self.pos += 3;
        Ok(v)
    }

    pub fn read_slice(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            bail!("short read {} bytes", n);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_minimal() {
        let cfg = EchConfig {
            config_id: 42,
            kem_id: HPKE_KEM_DHKEM_X25519,
            public_key: vec![0x11; 32],
            cipher_suites: vec![CipherSuite {
                kdf_id: HPKE_KDF_HKDF_SHA256,
                aead_id: HPKE_AEAD_AES_128_GCM,
            }],
            maximum_name_length: 0,
            public_name: "example.com".into(),
        };
        let bytes = cfg.encode();
        let parsed = EchConfig::decode(&bytes).unwrap();
        assert_eq!(parsed.config_id, 42);
        assert_eq!(parsed.kem_id, HPKE_KEM_DHKEM_X25519);
        assert_eq!(parsed.public_key, vec![0x11; 32]);
        assert_eq!(parsed.cipher_suites.len(), 1);
        assert_eq!(parsed.public_name, "example.com");
    }

    #[test]
    fn list_roundtrip() {
        let cfg = EchConfig {
            config_id: 1,
            kem_id: HPKE_KEM_DHKEM_X25519,
            public_key: vec![0x22; 32],
            cipher_suites: vec![CipherSuite {
                kdf_id: HPKE_KDF_HKDF_SHA256,
                aead_id: HPKE_AEAD_AES_128_GCM,
            }],
            maximum_name_length: 0,
            public_name: "example.com".into(),
        };
        let list = encode_list(&[cfg.clone(), cfg.clone()]);
        let mut r = Reader::new(&list);
        let list_len = r.read_u16().unwrap() as usize;
        assert_eq!(list_len, list.len() - 2);
        let body = r.read_slice(list_len).unwrap();
        let mut br = Reader::new(body);
        let a = EchConfig::decode_from(&mut br).unwrap();
        let b = EchConfig::decode_from(&mut br).unwrap();
        assert!(br.is_empty());
        assert_eq!(a.config_id, 1);
        assert_eq!(b.config_id, 1);
    }
}
