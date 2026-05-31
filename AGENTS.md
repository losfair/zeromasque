# Repository Guidelines

## Project Structure & Module Organization

- `src/` contains the proxy server, client, quiche/BoringSSL configuration, the
  SIGHUP reload task, and the HTTP/3 datagram + endpoint matching.
- `src/ech/` holds ECH key material (wire format, PEM key files, keygen).
- `testing/` contains the masque-go interop harness and its Go helpers.

## Build, Test, and Development Commands

- `cargo build` — compile the `zeromasque` binary (subcommands: `serve`,
  `client`, `gen-ech-key`).
- `cargo test` — unit tests, including an in-memory BoringSSL ECH handshake.
- `./testing/interop.sh` — end-to-end interop against masque-go (needs `go` and a
  masque-go checkout at `../masque-go`, override with `MASQUE_GO=`).
- `kill -SIGHUP <pid>` — hot-reload the server's TLS certificate and ECH keys
  (Linux only).

## Platform Support

The runtime uses monoio's `FusionDriver` (io_uring on Linux with an epoll
fallback; kqueue on macOS/BSD), so both the `iouring` and `legacy` monoio
features are enabled. Certificate hot reload uses `signalfd` and is gated to
Linux in `src/reload.rs`; the `#[cfg(not(target_os = "linux"))]` variant ignores
SIGHUP and logs that reload is unavailable. Keep both `reload.rs` cfg branches'
`SighupBlocked` / `spawn_reload` signatures identical so `main.rs` compiles on
every target.

## Coding Style & Naming Conventions

- Follow standard Rust style; `snake_case` for functions/vars, `CamelCase` for
  types. Run `cargo fmt` before submitting Rust changes.
- Keep modules small and focused; keep CLI flags documented in `src/cli.rs`.
- Keep `README.md` in sync with user-facing behavior and CLI changes.

## Dependency Constraints

- `quiche` pins `boring` to `^4.3`, so this crate uses `boring = "4"` (NOT 5 like
  zeroserve). The ECH `SslContextBuilder` handed to
  `quiche::Config::with_boring_ssl_ctx_builder` must come from that same boring
  version so they share one BoringSSL ABI.
- boring 4's `PKey` has no X25519 `generate`; ECH HPKE keypairs are minted via
  `boring-sys` (`EVP_HPKE_KEY_*`).

## Testing Guidelines

- quiche cannot surface `ech_accepted()` on a `Connection`; assert ECH acceptance
  with the raw-BoringSSL handshake test in `src/ech_test.rs`, which exercises the
  same `quic::install_ech_keys` / `quic::install_client_ech` helpers the live
  configs use.
- The interop harness must keep passing in both directions against masque-go.

## Security & Configuration Tips

- TLS expects PEM files; use local test certs (see `testing/gencert.go`).
- With ECH accepted, only the inner (real) SNI is authenticated, so the
  certificate must cover the real proxy hostname clients send in `:authority`.
  The public name only needs a valid certificate for the ECH-rejection fallback.
