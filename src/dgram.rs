//! CONNECT-UDP HTTP/3 datagram framing (RFC 9297 + RFC 9298).
//!
//! The payload handed to / received from quiche's transport-level
//! `dgram_send`/`dgram_recv` is:
//!
//! ```text
//! Quarter-Stream-ID (varint) | Context-ID (varint) | UDP payload
//! ```
//!
//! The quarter-stream-id is `request_stream_id / 4` (RFC 9297 §2.1). Context-ID
//! `0` denotes a raw UDP payload (RFC 9298 §5); other contexts are reserved and
//! dropped.

use crate::varint;

pub const CONTEXT_ID_UDP: u64 = 0;

/// Encode a UDP payload as a CONNECT-UDP HTTP datagram for `flow_id`.
pub fn encode(flow_id: u64, udp_payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(varint::encoded_len(flow_id) + 1 + udp_payload.len());
    varint::encode(flow_id, &mut out);
    varint::encode(CONTEXT_ID_UDP, &mut out);
    out.extend_from_slice(udp_payload);
    out
}

/// Parsed view of a received HTTP datagram.
pub struct Parsed<'a> {
    pub flow_id: u64,
    pub context_id: u64,
    pub payload: &'a [u8],
}

/// Decode the flow id, context id and remaining UDP payload from a datagram.
pub fn decode(buf: &[u8]) -> Option<Parsed<'_>> {
    let (flow_id, n1) = varint::decode(buf)?;
    let (context_id, n2) = varint::decode(&buf[n1..])?;
    Some(Parsed {
        flow_id,
        context_id,
        payload: &buf[n1 + n2..],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let d = encode(0, b"hello");
        let p = decode(&d).unwrap();
        assert_eq!(p.flow_id, 0);
        assert_eq!(p.context_id, CONTEXT_ID_UDP);
        assert_eq!(p.payload, b"hello");
    }

    #[test]
    fn nonzero_flow_and_context() {
        let d = encode(7, b"x");
        let p = decode(&d).unwrap();
        assert_eq!(p.flow_id, 7);
        // context id is always 0 (UDP) in what we encode
        assert_eq!(p.context_id, 0);
        assert_eq!(p.payload, b"x");
    }
}
