# zeromasque

An io_uring-based **MASQUE / CONNECT-UDP** proxy and client written in Rust,
built on [`monoio`](https://github.com/bytedance/monoio),
[`quiche`](https://github.com/cloudflare/quiche) (QUIC + HTTP/3) and
[`boring`](https://github.com/cloudflare/boring) (BoringSSL). It implements the
CONNECT-UDP protocol of [RFC 9298](https://www.rfc-editor.org/rfc/rfc9298) and
supports **TLS certificate hot reload** (Linux) and **Encrypted Client Hello
(ECH)** on both the server (termination) and client (offering).

The runtime uses monoio's `FusionDriver`: io_uring on Linux (with an epoll
fallback when io_uring is unavailable) and the kqueue backend on macOS/BSD.

It interoperates with [masque-go](https://github.com/quic-go/masque-go), the
quic-go reference implementation, in both directions.

## Build

```
cargo build --release
```

The first build compiles BoringSSL from source (via `boring-sys`), so it takes a
few minutes.

## Usage

Run the proxy:

```
zeromasque serve \
  --addr 0.0.0.0:4433 \
  --template 'https://proxy.example:4433/masque?h={target_host}&p={target_port}' \
  --cert cert.pem --key key.pem
```

Probe a target through a proxy (sends one UDP datagram, prints the reply):

```
zeromasque client \
  --template 'https://proxy.example:4433/masque?h={target_host}&p={target_port}' \
  --target 192.0.2.10:53 \
  --message 'hello'
```

The URI template uses the two RFC 9298 variables `{target_host}` and
`{target_port}`. Both the query form above and the well-known path form
(`.../.well-known/masque/udp/{target_host}/{target_port}/`) are supported.

### Certificate hot reload (Linux only)

Send `SIGHUP` to rebuild the TLS/ECH configuration from the cert, key and ECH
files. New connections pick up the rotated material; existing connections keep
the configuration they handshook with. A failed reload (e.g. a half-written
file) is logged and the previous configuration is retained.

```
kill -SIGHUP "$(pidof zeromasque)"
```

Hot reload relies on `signalfd`, which is Linux-only. On other platforms it is
disabled (SIGHUP is ignored) and the server keeps the configuration it started
with; restart to pick up new certificates.

### Encrypted Client Hello (ECH)

Generate a keypair + ECHConfig (prints the PEM bundle to stdout and the DNS
`ech=` value to stderr):

```
zeromasque gen-ech-key --public-name public.example.com > ech.pem
```

Run the server with ECH termination:

```
zeromasque serve ... --cert cert.pem --key key.pem --ech-key ech.pem
```

Offer ECH from the client with the published ECHConfigList:

```
zeromasque client ... --ech-config "AEX+DQBB...AAA="
```

Certificate coverage with ECH is subtle. When ECH is **accepted**, the
handshake completes from the encrypted ClientHelloInner, so only the **inner**
(real) SNI is authenticated — the certificate must cover the real proxy hostname
the client puts in `:authority`, not the public name. The public name is the
cleartext cover identity; it only needs a valid certificate for the ECH
**rejection** fallback, where the client authenticates the outer name and retries
with the server's fresh `retry_configs`. A cert covering both names handles both
paths.

quiche exposes no per-connection `SSL` accessor, so the client installs the ECH
config list via a BoringSSL context info-callback that fires at handshake start -
see `src/quic.rs` (`install_client_ech`).

## Testing

Unit tests (framing, URI templates, ECH wire format, and an in-memory BoringSSL
handshake asserting ECH is accepted on both peers):

```
cargo test
```

End-to-end interop against masque-go (needs `go` and a masque-go checkout at
`../masque-go`, override with `MASQUE_GO=`):

```
./testing/interop.sh
```

The harness exercises: zeromasque client -> masque-go proxy, masque-go client ->
zeromasque server, zeromasque <-> zeromasque, an ECH variant, and a SIGHUP
certificate-reload check that confirms the served certificate changes.

## Layout

- `src/server.rs` - the io_uring CONNECT-UDP proxy event loop.
- `src/client.rs` - the MASQUE client.
- `src/quic.rs` - quiche transport + BoringSSL configuration, ECH install hooks.
- `src/reload.rs` - `signalfd`-driven SIGHUP cert/ECH hot reload (Linux; a no-op
  stub elsewhere).
- `src/template.rs`, `src/dgram.rs`, `src/varint.rs` - URI templates and HTTP/3
  datagram / QUIC varint framing.
- `src/ech/` - ECH key material: wire format, PEM key files, keygen (ported from
  zeroserve, adapted to boring 4 / `boring-sys` HPKE keygen).
- `testing/` - interop harness and Go helpers.

## Notes & limitations

- Only context ID 0 (raw UDP payloads) is proxied; other HTTP-datagram contexts
  and stream capsules are discarded, matching masque-go.
- This minimal server echoes a fresh fixed-length connection ID and does not
  perform QUIC Retry / stateless address validation; it is intended for trusted
  deployments and interop testing, not open-internet hardening.
- Unlike zeroserve, the proxy does not (yet) apply namespace/landlock sandboxing.
- Linux gets the full feature set (io_uring + certificate hot reload). macOS/BSD
  run on the kqueue backend without hot reload; restart to rotate certificates.
