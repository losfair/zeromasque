# quiche 0.29.1

`quiche-0.29.1/` contains the published crates.io quiche 0.29.1 source, retaining
its upstream licenses and example/test fixtures. It is selected through
`[patch.crates-io]` so both ZeroMasque and the regression tests use the fix.
Existing production dependency versions are retained in the root lockfile.

Only these upstream source files differ:

- `src/recovery/gcongestion/bbr2.rs`: carry the connection's current MSS into the
  congestion event, including updates from path MTU discovery.
- `src/recovery/gcongestion/bbr2/probe_bw.rs`: permit ProbeUp growth when less
  than one full packet fits in the unused window; add regression/control tests.

The focused diff is [`testing/quiche-bbr-datagram-cwnd.patch`](../testing/quiche-bbr-datagram-cwnd.patch).
The added formatter configuration is from cloudflare/quiche tag `0.29.1`.
The root workspace includes this crate for testing but keeps ZeroMasque as the
default package. Stable rustfmt checks are scoped to ZeroMasque because the
vendor source uses upstream's nightly rustfmt configuration.

Vendoring is an interim dependency workaround, not a new congestion-control
implementation. Replace it with a released upstream dependency once this fix
(or an equivalent one) is available there. No upstream quiche acceptance is
implied by this patch.
