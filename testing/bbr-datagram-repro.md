# Single-host reproducer: BBRv2 ProbeUp with a sub-packet cwnd remainder

## Run

From this checkout, with the normal Rust/C compiler/CMake build prerequisites
(and Python 3.8 or later):

```sh
python3 testing/repro_bbr_datagram.py
```

Tested with Rust 1.95.0. The first run builds quiche and BoringSSL and can take a
few minutes. Cargo may need Internet access to fetch dependencies; the actual
reproducer runs entirely in memory. No second host, root privileges, sockets,
certificates, virtual machine, traffic shaping, or kernel setting changes are
needed. An optional `--target-dir /path/to/cache` retains Cargo build artifacts.

The script copies the source into a temporary directory and runs the **same
three tests against the actual quiche implementation** twice. The first run
restores only the original cwnd guard; the second restores the fix. It leaves
the source checkout unchanged. Compilation errors and unexpected test failures
are reported as errors, not mistaken for successful reproduction.

## Minimal state and expected result

The fixture starts in BBRv2 ProbeBW/Up with:

```text
current maximum packet size (MSS) = 1400 bytes
prior_cwnd                       = 14000 bytes
prior_bytes_in_flight            = 13950 bytes
inflight_hi                      = 13950 bytes
probe_up_bytes                   = 14000 bytes
```

Ten 1,395-byte packets leave 50 bytes of cwnd unused. Another complete packet
cannot fit; a QUIC DATAGRAM cannot be split to use those last 50 bytes. The
fixture feeds twenty ACK events of 1,395 bytes to `probe_inflight_high_upward`,
keeping this window-limited state. With the old guard, **every event returns
before accounting the ACKed bytes**, because `13950 < 14000`.

Expected output (compiler output omitted):

```text
=== Original guard: expect one regression failure ===
mss=1400 cwnd=14000 inflight=13950 inflight_hi: 13950 -> 13950
ProbeUp wedged with packet size 1400
test result: FAILED. 2 passed; 1 failed

=== Fixed guard: expect all three tests to pass ===
mss=1400 cwnd=14000 inflight=13950 inflight_hi: 13950 -> 15250
test result: ok. 3 passed; 0 failed

VERIFIED: original guard stalls; fixed guard grows; both negative controls pass.
```

The growth increment remains quiche's existing `DEFAULT_MSS`; this patch only
changes when growth is allowed, using the connection's current MSS for the
window-utilization check.

The regression also covers 1,200-, 1,450- and 9,000-byte MSS values. The other
two tests verify that a whole packet of unused cwnd still prevents growth,
that a completely utilized window still permits growth, and that the separate
`inflight_hi` guard is retained. To run just the fixed tests:

```sh
cargo test --locked -p quiche datagram_cwnd_tests -- --nocapture
```

This is a deterministic **controller-level** reproduction of the observed
stalled state. It deliberately does not claim to reproduce the entire network
sequence that first brings BBRv2 into that state, or to model an application
queue, packet loss and full connection state transitions.

## Independent network evidence

The state above was observed while a ZeroMasque CONNECT-UDP connection carried
WireGuard/GRE traffic on an approximately 50 Mbps / 60 ms RTT path. After a
traffic-direction reversal, throughput could remain around 1–5 Mbps. Diagnostic
sampling showed ProbeBW/Up, queued datagrams (23 in one sample), the 50-byte
window remainder above, and non-app-limited samples.

In an instrumented experiment, changing only this guard on the **existing
connection**, without a reconnect, changed sender interval throughput from
1.82 Mbps before the toggle to 49.60 Mbps after recovery. The diagnostic toggle
used a fixed 1,400-byte allowance; the production patch uses `self.mss` instead
and includes no diagnostic toggle or logging.

The final patched binaries were separately deployed at both endpoints and
measured with receiver-side iperf3 results:

| Sequence | Duration | Receiver throughput |
| --- | ---: | ---: |
| Upload | 120 s | 50.00 Mbps |
| Download | 30 s | 51.83 Mbps |
| Upload after direction change | 120 s | 49.90 Mbps |
| Download again | 30 s | 51.97 Mbps |
| Four-stream download | 30 s | 52.08 Mbps |

The services were not restarted during that sequence. These are measurements
on one path, not a claim about all BBRv2 workloads or link conditions.
