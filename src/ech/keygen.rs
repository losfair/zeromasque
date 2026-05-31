use std::io::Write;

use anyhow::{Context, Result, bail};
use base64ct::{Base64, Encoding};
use rand::RngCore;

use super::config::{
    CipherSuite, EchConfig, HPKE_AEAD_AES_128_GCM, HPKE_KDF_HKDF_SHA256, HPKE_KEM_DHKEM_X25519,
    encode_list,
};
use super::key::encode_pair_pem;

/// Generate a fresh DHKEM(X25519, HKDF-SHA256) HPKE keypair, returning the raw
/// 32-byte (public, private) representations (RFC 9180). boring 4's `PKey` lacks
/// an X25519 `generate`, so we mint the key through BoringSSL's HPKE FFI — the
/// exact key type `HpkeKey::dhkem_p256_sha256` (an X25519 constructor despite
/// the name) and BoringSSL's ECH stack consume.
pub(crate) fn generate_hpke_x25519_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    unsafe {
        let kem = boring_sys::EVP_hpke_x25519_hkdf_sha256();
        let key = boring_sys::EVP_HPKE_KEY_new();
        if key.is_null() {
            bail!("EVP_HPKE_KEY_new failed");
        }
        let _guard = HpkeKeyGuard(key); // free on every exit path
        if boring_sys::EVP_HPKE_KEY_generate(key, kem) != 1 {
            bail!("EVP_HPKE_KEY_generate failed");
        }
        let (mut public_key, mut pub_len) = ([0u8; 32], 0usize);
        if boring_sys::EVP_HPKE_KEY_public_key(key, public_key.as_mut_ptr(), &mut pub_len, 32) != 1
        {
            bail!("EVP_HPKE_KEY_public_key failed");
        }
        let (mut private_key, mut priv_len) = ([0u8; 32], 0usize);
        if boring_sys::EVP_HPKE_KEY_private_key(key, private_key.as_mut_ptr(), &mut priv_len, 32)
            != 1
        {
            bail!("EVP_HPKE_KEY_private_key failed");
        }
        Ok((
            public_key[..pub_len].to_vec(),
            private_key[..priv_len].to_vec(),
        ))
    }
}

struct HpkeKeyGuard(*mut boring_sys::EVP_HPKE_KEY);
impl Drop for HpkeKeyGuard {
    fn drop(&mut self) {
        unsafe { boring_sys::EVP_HPKE_KEY_free(self.0) };
    }
}

/// Validate the public name follows the strict subset of names servers
/// embed in ECHConfigs (per draft-ietf-tls-esni-22 §4.2: an A-label-form DNS
/// name; we additionally require a dot to avoid bare local names).
fn validate_public_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 253 {
        bail!("ECH public name must be 1..=253 characters");
    }
    if !name.contains('.') {
        bail!("ECH public name must contain at least one dot (use a real DNS name)");
    }
    for c in name.chars() {
        if !(c.is_ascii_alphanumeric() || c == '.' || c == '-') {
            bail!("ECH public name has invalid character `{}`", c);
        }
    }
    Ok(())
}

/// Generate a fresh X25519 HPKE keypair and matching ECHConfig, write the
/// PEM bundle (private key + config) to `stdout`, and the human-readable DNS
/// guidance with the base64 ECHConfigList to `stderr`.
pub fn run(public_name: &str) -> Result<()> {
    validate_public_name(public_name)?;

    // Generate a DHKEM(X25519) keypair with BoringSSL and extract the raw
    // 32-byte scalar / public point (RFC 9180 representation). The same raw
    // private key is later loaded via `HpkeKey::dhkem_p256_sha256` (an X25519
    // constructor despite the name).
    let (public_key, private_key) = generate_hpke_x25519_keypair()?;

    let mut config_id = [0u8; 1];
    rand::thread_rng().fill_bytes(&mut config_id);

    let config = EchConfig {
        config_id: config_id[0],
        kem_id: HPKE_KEM_DHKEM_X25519,
        public_key,
        cipher_suites: vec![CipherSuite {
            kdf_id: HPKE_KDF_HKDF_SHA256,
            aead_id: HPKE_AEAD_AES_128_GCM,
        }],
        maximum_name_length: 0,
        public_name: public_name.to_string(),
    };

    let pem = encode_pair_pem(&private_key, &config);
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(pem.as_bytes())
        .with_context(|| "writing ECH PEM bundle")?;
    stdout.flush().ok();

    let list_bytes = encode_list(std::slice::from_ref(&config));
    let list_b64 = Base64::encode_string(&list_bytes);

    let mut stderr = std::io::stderr().lock();
    writeln!(
        stderr,
        "Generated ECH key for public name `{}`.",
        public_name
    )?;
    writeln!(stderr, "config_id: 0x{:02x}", config.config_id)?;
    writeln!(stderr, "Publish the following base64-encoded ECHConfigList")?;
    writeln!(
        stderr,
        "in an HTTPS DNS resource record's `ech=` parameter:"
    )?;
    writeln!(stderr)?;
    writeln!(stderr, "  ech=\"{}\"", list_b64)?;
    writeln!(stderr)?;
    writeln!(
        stderr,
        "Run `zeromasque serve --ech-key <FILE>` pointing at the PEM saved from stdout."
    )?;
    Ok(())
}
