#!/usr/bin/env bash
# End-to-end interop test for zeromasque against the masque-go reference
# implementation (https://github.com/quic-go/masque-go).
#
# zeromasque pins the forwarding target on the server and the client is a local
# UDP proxy, so each case sends a UDP datagram into a client's --listen socket
# and checks the echoed reply.
#
# Matrix:
#   1. zeromasque client  -> masque-go proxy   -> UDP echo (target encoded in the
#      endpoint query, which masque-go reads)
#   2. masque-go client   -> zeromasque server -> UDP echo (server pins the
#      target and ignores the client's query)
#   3. zeromasque client  -> zeromasque server -> UDP echo
#   4. zeromasque client (ECH) -> zeromasque server (ECH termination) -> UDP echo
#   5. SIGHUP certificate hot reload swaps the served cert on the zeromasque server
#
# Requirements: cargo, go, and a masque-go checkout (default ../masque-go).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MASQUE_GO="${MASQUE_GO:-$ROOT/../masque-go}"
WORK="$(mktemp -d)"
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$WORK"; }
trap cleanup EXIT

pass=0; fail=0
ok()  { echo "PASS: $1"; pass=$((pass+1)); }
bad() { echo "FAIL: $1"; fail=$((fail+1)); }

echo "== building =="
( cd "$ROOT" && cargo build --quiet )
ZM="$ROOT/target/debug/zeromasque"
# Standalone single-file helpers; build outside module mode so the surrounding
# (non-Go) repo doesn't confuse the toolchain.
GO111MODULE=off go build -o "$WORK/udpecho" "$ROOT/testing/udpecho.go"
GO111MODULE=off go build -o "$WORK/udpsend" "$ROOT/testing/udpsend.go"
GO111MODULE=off go build -o "$WORK/gencert" "$ROOT/testing/gencert.go"
( cd "$MASQUE_GO" && go build -o "$WORK/mg-proxy" ./cmd/proxy )

# masque-go library client (needs a module with a replace directive)
cp -r "$ROOT/testing/mgclient" "$WORK/mgclient"
sed "s#MASQUE_GO_PATH#$MASQUE_GO#" "$ROOT/testing/mgclient/go.mod.template" > "$WORK/mgclient/go.mod"
rm -f "$WORK/mgclient/go.mod.template"
( cd "$WORK/mgclient" && go mod tidy >/dev/null 2>&1 && go build -o "$WORK/mg-client" . )

"$WORK/gencert" "$WORK/cert.pem" "$WORK/key.pem" 1001 cert-A
ECHO=127.0.0.1:5390   # primary echo target (prefix "echo:")
ECHO2=127.0.0.1:5391  # alternate echo target (prefix "echo2:"), for rule reload

# Rule tables (endpoint -> pinned target).
echo "[{\"endpoint\":\"https://localhost:4471/connect\",\"target\":\"$ECHO\"}]" > "$WORK/rules.json"
echo "[{\"endpoint\":\"https://localhost:4472/connect\",\"target\":\"$ECHO\"}]" > "$WORK/rules-ech.json"

echo "== starting servers =="
"$WORK/udpecho" "$ECHO" & PIDS+=($!)
"$WORK/udpecho" "$ECHO2" "echo2:" & PIDS+=($!)
# masque-go proxy: variable template, client selects the target.
"$WORK/mg-proxy" -t 'https://localhost:4470/masque?h={target_host}&p={target_port}' \
  -b 127.0.0.1:4470 -c "$WORK/cert.pem" -k "$WORK/key.pem" & PIDS+=($!)
# zeromasque server: rule table pins the target.
"$ZM" serve --addr 127.0.0.1:4471 --rules "$WORK/rules.json" \
  --cert "$WORK/cert.pem" --key "$WORK/key.pem" \
  >"$WORK/zm-server.log" 2>&1 & PIDS+=($!)

# ECH server (also rule-pinned). Extract the base64 ECHConfigList with sed (portable).
"$ZM" gen-ech-key --public-name public.example.com >"$WORK/ech.pem" 2>"$WORK/ech.err"
ECH_B64=$(sed -n 's/.*ech="\([^"]*\)".*/\1/p' "$WORK/ech.err")
"$ZM" serve --addr 127.0.0.1:4472 --rules "$WORK/rules-ech.json" \
  --cert "$WORK/cert.pem" --key "$WORK/key.pem" --ech-key "$WORK/ech.pem" \
  >"$WORK/zm-ech.log" 2>&1 & PIDS+=($!)
sleep 2

# Start a zeromasque client UDP proxy, send one datagram into it, print the
# reply, then stop the client. Args: listen, endpoint, proxy-addr, message, extra...
zm_send() {
  local listen="$1" endpoint="$2" paddr="$3" msg="$4"; shift 4
  "$ZM" client --listen "$listen" --endpoint "$endpoint" --proxy-addr "$paddr" --insecure "$@" \
    >/dev/null 2>"$WORK/zm-client.log" &
  local cpid=$!
  sleep 2
  "$WORK/udpsend" "$listen" "$msg" 2>/dev/null || true
  kill "$cpid" 2>/dev/null || true
  wait "$cpid" 2>/dev/null || true
}

# 1. zeromasque client -> masque-go proxy (target encoded in the endpoint query).
if zm_send 127.0.0.1:6001 "https://localhost:4470/masque?h=127.0.0.1&p=5390" 127.0.0.1:4470 one \
   | grep -q 'echo:one'; then ok "zeromasque client -> masque-go proxy"; else bad "zeromasque client -> masque-go proxy"; fi

# 2. masque-go variable-template client -> zeromasque pinned server (query ignored).
if "$WORK/mg-client" 'https://localhost:4471/connect?h={target_host}&p={target_port}' "$ECHO" two 2>/dev/null \
   | grep -q 'echo:two'; then ok "masque-go client -> zeromasque server"; else bad "masque-go client -> zeromasque server"; fi

# 3. zeromasque client -> zeromasque server.
if zm_send 127.0.0.1:6003 "https://localhost:4471/connect" 127.0.0.1:4471 three \
   | grep -q 'echo:three'; then ok "zeromasque client -> zeromasque server"; else bad "zeromasque client -> zeromasque server"; fi

# 4. zeromasque client with ECH -> zeromasque ECH server.
if zm_send 127.0.0.1:6004 "https://localhost:4472/connect" 127.0.0.1:4472 four --ech-config "$ECH_B64" \
   | grep -q 'echo:four'; then ok "zeromasque ECH client -> ECH server"; else bad "zeromasque ECH client -> ECH server"; fi

# 5. SIGHUP hot reload (Linux only: reload uses signalfd and /proc). Covers both
#    the TLS certificate and the rule table.
if [ "$(uname -s)" = "Linux" ]; then
  # Identify the 4471 server process (cmdline contains both `serve` and the addr).
  ZM_PID=""
  for p in "${PIDS[@]}"; do
    cmd=$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null || true)
    case "$cmd" in *serve*127.0.0.1:4471*) ZM_PID=$p; break ;; esac
  done

  # 5a. Cert reload: swap to cert-B, confirm the served fingerprint changes.
  fp() {
    "$ZM" client --listen "$1" --endpoint 'https://localhost:4471/connect' \
      --proxy-addr 127.0.0.1:4471 --insecure >/dev/null 2>"$WORK/fp.log" &
    local cpid=$!
    sleep 2
    kill "$cpid" 2>/dev/null || true
    wait "$cpid" 2>/dev/null || true
    sed -n 's/.*sha256: \([0-9a-f]*\).*/\1/p' "$WORK/fp.log" | head -1
  }
  FP1=$(fp 127.0.0.1:6005)
  "$WORK/gencert" "$WORK/cert.pem" "$WORK/key.pem" 2002 cert-B
  kill -HUP "$ZM_PID"; sleep 1
  FP2=$(fp 127.0.0.1:6006)
  if [ -n "$FP1" ] && [ -n "$FP2" ] && [ "$FP1" != "$FP2" ]; then
    ok "SIGHUP cert hot reload (served cert changed $FP1 -> $FP2)"
  else bad "SIGHUP cert hot reload (FP1=$FP1 FP2=$FP2)"; fi

  # 5b. Rule reload: repoint the target from ECHO (echo:) to ECHO2 (echo2:) and
  #     confirm tunnelled traffic now reaches the new target.
  echo "[{\"endpoint\":\"https://localhost:4471/connect\",\"target\":\"$ECHO2\"}]" > "$WORK/rules.json"
  kill -HUP "$ZM_PID"; sleep 1
  if zm_send 127.0.0.1:6007 "https://localhost:4471/connect" 127.0.0.1:4471 reloaded \
     | grep -q 'echo2:reloaded'; then ok "SIGHUP rule hot reload (target repointed)"; else bad "SIGHUP rule hot reload"; fi
else
  echo "SKIP: SIGHUP hot reload (Linux-only feature; $(uname -s) ignores SIGHUP)"
fi

echo
echo "== $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
