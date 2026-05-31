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

## Model

The forwarding **target is pinned on the server** — clients cannot choose a
destination. The server loads a **rule table** mapping endpoints to targets, and
a CONNECT-UDP request is matched on its `:authority` + path (the query string is
ignored, so generic MASQUE clients that carry `target_host`/`target_port` in the
query still interoperate; the server ignores those and uses the rule's target).

The **client is a local UDP proxy**: it binds a UDP socket and tunnels every
datagram received there through the proxy, opening one CONNECT-UDP flow per local
source address and relaying replies back.

## Usage

Write a rule table (`rules.json`) mapping endpoints to pinned targets:

```json
[
  {"endpoint": "https://dns.example:4433/connect", "target": "192.0.2.10:53"},
  {"endpoint": "https://ntp.example:4433/connect", "target": "192.0.2.20:123", "idle_timeout": 60}
]
```

Each rule may set `"idle_timeout": N` (seconds, default `35`, `0` disables it): the
server closes a tunnelled UDP flow that has had no traffic in either direction for
that long. A later datagram from the same local source simply reopens a fresh
flow, so this bounds per-flow sockets/tasks and frees QUIC streams for reuse.

Run the proxy:

```
zeromasque serve \
  --addr 0.0.0.0:4433 \
  --rules rules.json \
  --cert cert.pem --key key.pem
```

Run the client as a local UDP proxy on `127.0.0.1:5353`, pointed at one endpoint:

```
zeromasque client \
  --endpoint 'https://dns.example:4433/connect' \
  --listen 127.0.0.1:5353
```

Anything sent to `127.0.0.1:5353` is now tunnelled to `192.0.2.10:53`:

```
dig @127.0.0.1 -p 5353 example.com
```

`--proxy-addr <ip:port>` overrides the UDP address to connect to while keeping
the endpoint host as SNI / `:authority` (useful when the host resolves to an
address the proxy isn't bound to, e.g. `localhost` → `::1`).

The client verifies the proxy's certificate against the system trust store by
default; pass `--ca <pem>` to add a CA, or `--insecure` to skip verification
(testing only).

### Transparent forwarding (Linux only)

A rule with `"transparent": true` forwards to its target with the client's
**external source IP preserved** via `IP_TRANSPARENT`, so a local target service
sees traffic as coming from the real client rather than the proxy:

```json
[{"endpoint": "https://proxy:4433/dns", "target": "127.0.0.1:53", "transparent": true}]
```

This requires `CAP_NET_ADMIN`, and the operator must route the target's replies
(addressed to the spoofed client source) back to the proxy — straightforward when
the target is a local service. The source port is the client's QUIC port where
free, else an ephemeral port on the same IP (a client multiplexes many flows over
one address). Non-transparent rules use an ordinary ephemeral source.

A rule may also set `"fwmark": N` to apply `SO_MARK` to the target socket (Linux,
needs `CAP_NET_ADMIN`), e.g. to drive policy routing for the reply path:

```json
[{"endpoint": "https://proxy:4433/dns", "target": "127.0.0.1:53", "transparent": true, "fwmark": 100}]
```

### Hot reload (Linux only)

Send `SIGHUP` to rebuild the TLS/ECH configuration *and* the rule table from
their files. New connections pick up rotated certificates; new requests pick up
the new rule table; existing connections keep
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
zeromasque client --endpoint ... --listen ... --ech-config "AEX+DQBB...AAA="
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

### Access control

By default the proxy performs **no client authentication**: any peer that can
reach it and send a CONNECT-UDP request matching a rule's authority + path is
granted a tunnel. (The client still authenticates the *server* via TLS unless
`--insecure`.)

A secret can be embedded in a rule's endpoint **path** as a lightweight
shared-secret gate. The server matches on the path component (the query string is
ignored), so put the secret in a path segment — not the query:

```json
// rules.json
[{"endpoint": "https://proxy:4433/connect/s3cret-9f2c", "target": "192.0.2.10:53"}]
```

```
# client uses the same secret path:
zeromasque client --endpoint 'https://proxy:4433/connect/s3cret-9f2c' --listen ...
```

A client requesting a different path (or none) is rejected with `404`. The path
is not exposed to passive on-path observers — it travels inside the encrypted
QUIC/HTTP3 stream (and ECH hides the SNI) — so this is enough to keep
opportunistic scanners from using an open proxy.

It is **not** real authentication, though:

- It is a single static bearer secret in a URL path: it can leak via logs, shell
  history, or config files, and a *failed* attempt is logged at debug level.
- There is no per-client identity, no selective revocation, and no rate-limiting
  by identity — rotating means updating the server and every client at once.
- It is replayable indefinitely by anyone who learns it, and the match is not
  constant-time.

For access control of untrusted clients, prefer a real scheme: `Proxy-Authorization`
validated at the request layer (proper `407`, per-client tokens, secret kept out
of the path/logs) or mTLS for cryptographic per-client identity. Neither is
implemented yet.

## Testing

Unit tests (framing, endpoint matching, ECH wire format, and an in-memory
BoringSSL handshake asserting ECH is accepted on both peers):

```
cargo test
```

End-to-end interop against masque-go (needs `go` and a masque-go checkout at
`../masque-go`, override with `MASQUE_GO=`):

```
./testing/interop.sh
```

The harness exercises: zeromasque client -> masque-go proxy, masque-go
(variable-template) client -> zeromasque pinned server, zeromasque <-> zeromasque,
an ECH variant, and a SIGHUP certificate-reload check that confirms the served
certificate changes.

## Layout

- `src/server.rs` - the io_uring CONNECT-UDP proxy event loop (rule-pinned).
- `src/client.rs` - the local UDP→CONNECT-UDP proxy client.
- `src/rules.rs` - the JSON endpoint→target rule table.
- `src/quic.rs` - quiche transport + BoringSSL configuration, ECH install hooks.
- `src/reload.rs` - `signalfd`-driven SIGHUP cert/ECH/rule hot reload (Linux; a
  no-op stub elsewhere).
- `src/endpoint.rs`, `src/dgram.rs`, `src/varint.rs` - endpoint matching and
  HTTP/3 datagram / QUIC varint framing.
- `src/ech/` - ECH key material: wire format, PEM key files, keygen (ported from
  zeroserve, adapted to boring 4 / `boring-sys` HPKE keygen).
- `testing/` - interop harness and Go helpers.

## Resilience

The client never exits: it redials the proxy indefinitely with capped
exponential backoff (100 ms → 5 s), so a server restart, a dropped NAT mapping,
or any transient failure recovers automatically. The local listen socket stays
bound across reconnects, and flows reopen lazily as local datagrams arrive (apps
retransmit lost UDP and self-heal). A 1 s keepalive (ack-eliciting) keeps idle
NAT mappings warm and makes a dead path detectable within the 10 s idle timeout.

The server reaps connections that idle out and closes their target sockets, so
vanished clients don't leak resources.

## Performance & tuning (high-RTT links)

The whole tunnel is a single QUIC connection and every UDP payload rides an
*unreliable* QUIC DATAGRAM (RFC 9297/9298) — there is no tunnel-level
retransmission, by design. The consequence: any packet the kernel drops because
a UDP socket buffer overflowed becomes a loss the *tunnelled* protocol must
recover from. Over a high-RTT path even a few percent loss collapses an inner
TCP flow (Mathis: throughput ≈ MSS / (RTT·√loss)), so a tunnel that drops 40 %
of a burst can crush a 20 Mbit/s TCP transfer down to a few hundred Kbit/s.

zeromasque therefore requests large send/receive buffers (8 MB) on every UDP
socket. **The kernel silently clamps that request to `net.core.rmem_max` /
`net.core.wmem_max`, which default to ~208 KB on stock Linux** — far below the
bandwidth-delay product of a fast, high-latency link (e.g. 20 Mbit/s × 270 ms ≈
675 KB). On both the proxy host and the client host, raise those ceilings:

```sh
sudo sysctl -w net.core.rmem_max=16777216 net.core.wmem_max=16777216
# persist in /etc/sysctl.d/99-zeromasque.conf:
#   net.core.rmem_max = 16777216
#   net.core.wmem_max = 16777216
```

Measured over an emulated 270 ms RTT path, this takes a 2000 pkt/s
(~19 Mbit/s) flow from ~40–60 % loss (erratic) to a stable ~3 %. Also keep the
tunnelled interface's MTU low enough that an inner packet plus encapsulation
fits one QUIC DATAGRAM (these cannot fragment); see the datagram-size note in
`src/quic.rs`.

## Notes & limitations

- Only context ID 0 (raw UDP payloads) is proxied; other HTTP-datagram contexts
  and stream capsules are discarded, matching masque-go.
- This minimal server echoes a fresh fixed-length connection ID and does not
  perform QUIC Retry / stateless address validation; it is intended for trusted
  deployments and interop testing, not open-internet hardening.
- The client opens one CONNECT-UDP flow per local source address (bounded by the
  connection's stream limit) and keeps flows for the connection's lifetime; the
  first datagram of a new flow waits one round-trip for the `200` response.
- No client authentication by default; see [Access control](#access-control) for
  the path-secret gate and its limits.
- Unlike zeroserve, the proxy does not (yet) apply namespace/landlock sandboxing.
- Linux gets the full feature set (io_uring + certificate hot reload). macOS/BSD
  run on the kqueue backend without hot reload; restart to rotate certificates.
