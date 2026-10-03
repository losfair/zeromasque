#!/usr/bin/env python3
"""Reproduce the quiche BBRv2 DATAGRAM window stall, then verify the fix.

Runs entirely in memory on one host. No root, network namespace, server,
certificate, interface, or impairment setup is required. Cargo may download
build dependencies. The source checkout is never patched in place.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

FIXED_GUARD = """if congestion_event
                .prior_cwnd
                .saturating_sub(congestion_event.prior_bytes_in_flight) >=
                congestion_event.max_datagram_size"""
ORIGINAL_GUARD = """if congestion_event.prior_bytes_in_flight <
                congestion_event.prior_cwnd"""
REGRESSION = "queued_datagrams_grow_probe_up_with_sub_packet_cwnd_remainder"
FILTER = "recovery::gcongestion::bbr2::probe_bw::datagram_cwnd_tests::"


def run_tests(checkout, target, label):
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(target)
    env["CARGO_TERM_COLOR"] = "never"
    print("\n=== " + label + " ===", flush=True)
    command = [
        "cargo", "test", "--locked", "--manifest-path", str(checkout / "Cargo.toml"),
        "-p", "quiche", FILTER, "--", "--nocapture", "--test-threads=1",
    ]
    lines = []
    with subprocess.Popen(command, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True, env=env) as process:
        for line in process.stdout:
            print(line, end="", flush=True)
            lines.append(line)
        code = process.wait()
    return code, "".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-dir", type=Path,
                        help="Optional persistent Cargo build cache; defaults to the temporary directory")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory(prefix="zeromasque-bbr-repro-") as temp:
        checkout = Path(temp) / "source"
        checkout.mkdir()
        for name in ("Cargo.toml", "Cargo.lock"):
            shutil.copy2(root / name, checkout / name)
        for name in ("src", "vendor"):
            shutil.copytree(root / name, checkout / name)
        target = args.target_dir.resolve() if args.target_dir else Path(temp) / "target"
        source = checkout / "vendor/quiche-0.29.1/src/recovery/gcongestion/bbr2/probe_bw.rs"
        fixed = source.read_text()
        if fixed.count(FIXED_GUARD) != 1:
            raise SystemExit("The expected fixed guard was not found exactly once; refusing to change another condition")

        # Keep the exact same tests, MSS plumbing and dependencies on both runs.
        # Only restore the old cwnd-utilization condition for the first run.
        source.write_text(fixed.replace(FIXED_GUARD, ORIGINAL_GUARD, 1))
        code, output = run_tests(checkout, target, "Original guard: expect one regression failure")
        if not (code == 101 and "ProbeUp wedged with packet size 1400" in output
                and "2 passed; 1 failed" in output and REGRESSION in output):
            raise SystemExit("The expected regression was NOT reproduced (build/toolchain failures do not count)")

        source.write_text(fixed)
        code, output = run_tests(checkout, target, "Fixed guard: expect all three tests to pass")
        if code != 0 or "3 passed; 0 failed" not in output:
            raise SystemExit("The fix did not pass all three regression/control tests")

    print("\nVERIFIED: original guard stalls; fixed guard grows; both negative controls pass.")


if __name__ == "__main__":
    main()
