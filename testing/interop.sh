#!/usr/bin/env bash
# End-to-end interop test for zeromasque against the masque-go reference
# implementation (https://github.com/quic-go/masque-go).
#
# Matrix:
#   1. zeromasque client  -> masque-go proxy   -> UDP echo
#   2. masque-go client   -> zeromasque server -> UDP echo
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
ok()   { echo "PASS: $1"; pass=$((pass+1)); }
bad()  { echo "FAIL: $1"; fail=$((fail+1)); }

echo "== building =="
( cd "$ROOT" && cargo build --quiet )
ZM="$ROOT/target/debug/zeromasque"
# The two single-file helpers are standalone; build them outside module mode so
# the surrounding (non-Go) repo doesn't confuse the toolchain.
GO111MODULE=off go build -o "$WORK/udpecho" "$ROOT/testing/udpecho.go"
GO111MODULE=off go build -o "$WORK/gencert" "$ROOT/testing/gencert.go"
( cd "$MASQUE_GO" && go build -o "$WORK/mg-proxy" ./cmd/proxy )

# masque-go library client (needs a module with a replace directive)
cp -r "$ROOT/testing/mgclient" "$WORK/mgclient"
sed "s#MASQUE_GO_PATH#$MASQUE_GO#" "$ROOT/testing/mgclient/go.mod.template" > "$WORK/mgclient/go.mod"
rm -f "$WORK/mgclient/go.mod.template"
( cd "$WORK/mgclient" && go mod tidy >/dev/null 2>&1 && go build -o "$WORK/mg-client" . )

"$WORK/gencert" "$WORK/cert.pem" "$WORK/key.pem" 1001 cert-A

TMPL_MG='https://localhost:4470/masque?h={target_host}&p={target_port}'
TMPL_ZM='https://localhost:4471/masque?h={target_host}&p={target_port}'
TMPL_ECH='https://localhost:4472/masque?h={target_host}&p={target_port}'

echo "== starting servers =="
"$WORK/udpecho" 127.0.0.1:5390 & PIDS+=($!)
"$WORK/mg-proxy" -t "$TMPL_MG" -b 127.0.0.1:4470 -c "$WORK/cert.pem" -k "$WORK/key.pem" & PIDS+=($!)
"$ZM" serve --addr 127.0.0.1:4471 --template "$TMPL_ZM" --cert "$WORK/cert.pem" --key "$WORK/key.pem" \
  >"$WORK/zm-server.log" 2>&1 & PIDS+=($!)

# ECH server
"$ZM" gen-ech-key --public-name public.example.com >"$WORK/ech.pem" 2>"$WORK/ech.err"
ECH_B64=$(grep -oP 'ech="\K[^"]+' "$WORK/ech.err")
"$ZM" serve --addr 127.0.0.1:4472 --template "$TMPL_ECH" --cert "$WORK/cert.pem" --key "$WORK/key.pem" \
  --ech-key "$WORK/ech.pem" >"$WORK/zm-ech.log" 2>&1 & PIDS+=($!)
sleep 2

# The template authority is `localhost:<port>` (so masque-go's :authority check
# passes), but we pin the UDP connect address to 127.0.0.1 because `localhost`
# may resolve to ::1 first while the servers bind IPv4.
# 1. zeromasque client -> masque-go proxy
if "$ZM" client --template "$TMPL_MG" --proxy-addr 127.0.0.1:4470 --target 127.0.0.1:5390 --insecure --message one 2>/dev/null \
   | grep -q 'echo:one'; then ok "zeromasque client -> masque-go proxy"; else bad "zeromasque client -> masque-go proxy"; fi

# 2. masque-go client -> zeromasque server
if "$WORK/mg-client" "$TMPL_ZM" 127.0.0.1:5390 two 2>/dev/null | grep -q 'echo:two'; then
  ok "masque-go client -> zeromasque server"; else bad "masque-go client -> zeromasque server"; fi

# 3. zeromasque client -> zeromasque server
if "$ZM" client --template "$TMPL_ZM" --proxy-addr 127.0.0.1:4471 --target 127.0.0.1:5390 --insecure --message three 2>/dev/null \
   | grep -q 'echo:three'; then ok "zeromasque client -> zeromasque server"; else bad "zeromasque client -> zeromasque server"; fi

# 4. zeromasque client with ECH -> zeromasque ECH server
if "$ZM" client --template "$TMPL_ECH" --proxy-addr 127.0.0.1:4472 --target 127.0.0.1:5390 --insecure --ech-config "$ECH_B64" \
   --message four 2>/dev/null | grep -q 'echo:four'; then ok "zeromasque ECH client -> ECH server"; else bad "zeromasque ECH client -> ECH server"; fi

# 5. SIGHUP cert hot reload: swap to cert-B and confirm the served fingerprint changes.
fp() { "$ZM" client --template "$TMPL_ZM" --proxy-addr 127.0.0.1:4471 --target 127.0.0.1:5390 --insecure --message x 2>&1 \
       | grep -oP 'sha256: \K[0-9a-f]+' || true; }
FP1=$(fp)
"$WORK/gencert" "$WORK/cert.pem" "$WORK/key.pem" 2002 cert-B
ZM_PID=""
for p in "${PIDS[@]}"; do
  if tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -q '4471'; then ZM_PID=$p; break; fi
done
kill -HUP "$ZM_PID"; sleep 1
FP2=$(fp)
if [ -n "$FP1" ] && [ -n "$FP2" ] && [ "$FP1" != "$FP2" ]; then
  ok "SIGHUP cert hot reload (served cert changed $FP1 -> $FP2)"
else bad "SIGHUP cert hot reload (FP1=$FP1 FP2=$FP2)"; fi

echo
echo "== $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
