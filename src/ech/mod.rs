// ECH key material: wire format, PEM key files, and key generation.
// Server-side ECH *termination* (inner-ClientHello decryption, acceptance
// signaling, retry_configs) is handled natively by BoringSSL — see
// `crate::boringtls` and `crate::tls`. These modules only produce and load the
// HPKE keys + ECHConfigs that get fed to BoringSSL.
pub mod config;
pub mod key;
pub mod keygen;
