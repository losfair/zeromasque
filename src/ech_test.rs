//! End-to-end ECH proof at the BoringSSL layer.
//!
//! quiche cannot surface `ech_accepted()` on a Connection, so we verify the ECH
//! machinery — server key installation (`quic::install_ech_keys`) and the
//! client-side config-list injection (`quic::install_client_ech`) — by driving
//! an in-memory TLS 1.3 handshake and asserting both peers report ECH accepted.
//! These are the exact helpers the live server/client configs use.

#![cfg(test)]

use std::io::{self, Read, Write};

use boring::ssl::{
    HandshakeError, MidHandshakeSslStream, Ssl, SslConnector, SslContextBuilder, SslMethod,
    SslStream, SslStreamBuilder, SslVerifyMode, SslVersion,
};

use crate::ech::config::{
    CipherSuite, EchConfig, HPKE_AEAD_AES_128_GCM, HPKE_KDF_HKDF_SHA256, HPKE_KEM_DHKEM_X25519,
    encode_list,
};
use crate::ech::key::{EchKeyPair, EchKeySet};
use crate::ech::keygen::generate_hpke_x25519_keypair;
use crate::quic;

/// In-memory transport BoringSSL drives synchronously.
struct Mem {
    inbound: Vec<u8>,
    pos: usize,
    outbound: Vec<u8>,
}
impl Mem {
    fn new() -> Self {
        Self {
            inbound: Vec::new(),
            pos: 0,
            outbound: Vec::new(),
        }
    }
}
impl Read for Mem {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let avail = &self.inbound[self.pos..];
        if avail.is_empty() {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        let n = avail.len().min(buf.len());
        buf[..n].copy_from_slice(&avail[..n]);
        self.pos += n;
        Ok(n)
    }
}
impl Write for Mem {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.outbound.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

enum Side {
    Mid(MidHandshakeSslStream<Mem>),
    Done(SslStream<Mem>),
}
impl Side {
    fn mem(&mut self) -> &mut Mem {
        match self {
            Side::Mid(m) => m.get_mut(),
            Side::Done(s) => s.get_mut(),
        }
    }
    fn pump(self) -> (Side, Option<bool>) {
        let mid = match self {
            Side::Mid(m) => m,
            other => return (other, None),
        };
        match mid.handshake() {
            Ok(s) => {
                let ech = s.ssl().ech_accepted();
                (Side::Done(s), Some(ech))
            }
            Err(HandshakeError::WouldBlock(m)) => (Side::Mid(m), None),
            Err(e) => panic!("handshake error: {e}"),
        }
    }
}

fn move_bytes(from: &mut Side, to: &mut Side) {
    let out = std::mem::take(&mut from.mem().outbound);
    if !out.is_empty() {
        let m = to.mem();
        if m.pos == m.inbound.len() {
            m.inbound.clear();
            m.pos = 0;
        }
        m.inbound.extend_from_slice(&out);
    }
}

/// Minimal self-signed leaf covering the inner+outer names, for the test only.
fn self_signed() -> (
    boring::x509::X509,
    boring::pkey::PKey<boring::pkey::Private>,
) {
    use boring::asn1::Asn1Time;
    use boring::bn::{BigNum, MsbOption};
    use boring::hash::MessageDigest;
    use boring::pkey::PKey;
    use boring::x509::extension::SubjectAlternativeName;
    use boring::x509::{X509, X509NameBuilder};

    let rsa = boring::rsa::Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();
    let mut nb = X509NameBuilder::new().unwrap();
    nb.append_entry_by_text("CN", "secret.internal").unwrap();
    let name = nb.build();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    let serial = {
        let mut bn = BigNum::new().unwrap();
        bn.rand(159, MsbOption::MAYBE_ZERO, false).unwrap();
        bn.to_asn1_integer().unwrap()
    };
    b.set_serial_number(&serial).unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&pkey).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    let san = SubjectAlternativeName::new()
        .dns("secret.internal")
        .dns("public.example.com")
        .build(&b.x509v3_context(None, None))
        .unwrap();
    b.append_extension(san).unwrap();
    b.sign(&pkey, MessageDigest::sha256()).unwrap();
    (b.build(), pkey)
}

#[test]
fn ech_accepted_end_to_end() {
    // Fresh HPKE keypair + matching ECHConfig (our production keygen + codec).
    let (public_key, private_key) = generate_hpke_x25519_keypair().unwrap();
    let config = EchConfig {
        config_id: 0x2a,
        kem_id: HPKE_KEM_DHKEM_X25519,
        public_key,
        cipher_suites: vec![CipherSuite {
            kdf_id: HPKE_KDF_HKDF_SHA256,
            aead_id: HPKE_AEAD_AES_128_GCM,
        }],
        maximum_name_length: 0,
        public_name: "public.example.com".into(),
    };
    let config_list = encode_list(std::slice::from_ref(&config));
    let key_set = EchKeySet {
        pairs: vec![EchKeyPair {
            private_key,
            config,
        }],
    };

    let (cert, key) = self_signed();

    // Server context with ECH keys installed via the production helper.
    let mut sb = SslContextBuilder::new(SslMethod::tls()).unwrap();
    sb.set_min_proto_version(Some(SslVersion::TLS1_3)).unwrap();
    sb.set_max_proto_version(Some(SslVersion::TLS1_3)).unwrap();
    sb.set_certificate(&cert).unwrap();
    sb.set_private_key(&key).unwrap();
    quic::install_ech_keys(&mut sb, &key_set).unwrap();
    let server_ctx = sb.build();

    // Client context offering ECH via the production injection helper.
    let mut cb = SslConnector::builder(SslMethod::tls()).unwrap();
    cb.set_verify(SslVerifyMode::NONE);
    quic::install_client_ech(&mut cb, config_list);
    let client_conf = cb.build().configure().unwrap();

    let server_ssl = Ssl::new(&server_ctx).unwrap();
    let mut srv = Side::Mid(SslStreamBuilder::new(server_ssl, Mem::new()).setup_accept());
    let client_ssl = client_conf.into_ssl("secret.internal").unwrap();
    let mut cli = Side::Mid(SslStreamBuilder::new(client_ssl, Mem::new()).setup_connect());

    let (mut client_ech, mut server_ech) = (None, None);
    for _ in 0..30 {
        let (c, e) = cli.pump();
        cli = c;
        if let Some(e) = e {
            client_ech = Some(e);
        }
        move_bytes(&mut cli, &mut srv);
        let (s, e) = srv.pump();
        srv = s;
        if let Some(e) = e {
            server_ech = Some(e);
        }
        move_bytes(&mut srv, &mut cli);
        if client_ech.is_some() && server_ech.is_some() {
            break;
        }
    }

    assert_eq!(client_ech, Some(true), "client must report ECH accepted");
    assert_eq!(server_ech, Some(true), "server must report ECH accepted");

    // With ECH accepted, the server is serving the protected inner name.
    if let Side::Done(s) = &srv {
        assert_eq!(
            s.ssl().servername(boring::ssl::NameType::HOST_NAME),
            Some("secret.internal")
        );
    } else {
        panic!("server handshake did not complete");
    }
}
