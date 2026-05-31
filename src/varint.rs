//! QUIC variable-length integer encoding (RFC 9000 §16).
//!
//! HTTP/3 datagrams and the CONNECT-UDP context ID are varint-prefixed, and
//! quiche does not export its internal `octets` codec, so we carry a small
//! self-contained implementation.

/// Decode a QUIC varint from the front of `buf`. Returns the value and the
/// number of bytes consumed, or `None` if `buf` is too short.
pub fn decode(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6); // 2 high bits select 1/2/4/8 bytes
    if buf.len() < len {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for &b in &buf[1..len] {
        value = (value << 8) | u64::from(b);
    }
    Some((value, len))
}

/// Number of bytes `value` encodes to.
pub fn encoded_len(value: u64) -> usize {
    match value {
        0..=63 => 1,
        64..=16383 => 2,
        16384..=1_073_741_823 => 4,
        _ => 8,
    }
}

/// Append the varint encoding of `value` to `out`.
pub fn encode(value: u64, out: &mut Vec<u8>) {
    match encoded_len(value) {
        1 => out.push(value as u8),
        2 => out.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes()),
        4 => out.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes()),
        _ => out.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_boundaries() {
        for v in [
            0u64,
            63,
            64,
            16383,
            16384,
            1_073_741_823,
            1_073_741_824,
            u64::MAX >> 2,
        ] {
            let mut out = Vec::new();
            encode(v, &mut out);
            assert_eq!(out.len(), encoded_len(v));
            let (decoded, n) = decode(&out).unwrap();
            assert_eq!(decoded, v);
            assert_eq!(n, out.len());
        }
    }

    #[test]
    fn decode_short_buffer_is_none() {
        // A 4-byte varint header with only 2 bytes present.
        assert!(decode(&[0x80, 0x00]).is_none());
        assert!(decode(&[]).is_none());
    }

    #[test]
    fn known_vectors() {
        // RFC 9000 §A.1 sample: 0x25 -> 37, two-byte 0x7bbd -> 15293.
        assert_eq!(decode(&[0x25]).unwrap().0, 37);
        assert_eq!(decode(&[0x7b, 0xbd]).unwrap().0, 15293);
    }
}
