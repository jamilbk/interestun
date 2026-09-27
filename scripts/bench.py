#!/usr/bin/env python3
"""Record CSV transport samples and reproducibility metadata; does not change QoS/power."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("--max-workers", type=int, default=1)
parser.add_argument("--samples", type=int, default=5)
parser.add_argument("--packets", type=int, default=200000)
parser.add_argument("--output", type=Path, default=Path("transport.csv"))
args = parser.parse_args()


def capture(*command):
    result = subprocess.run(command, text=True, capture_output=True)
    return result.stdout.strip() if result.returncode == 0 else result.stderr.strip()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


args.output.parent.mkdir(parents=True, exist_ok=True)
metadata = {
    "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "rustc": capture("rustc", "-Vv"),
    "os": capture("uname", "-srm"),
    "cpu": capture("sysctl", "-n", "machdep.cpu.brand_string"),
    "logical_cpus": capture("sysctl", "-n", "hw.ncpu"),
    "power_before": capture("pmset", "-g", "batt"),
    "power_settings": capture("pmset", "-g", "custom"),
    "qos": "inherited default; no affinity or QoS changes",
    "profile": "release/bench, thin LTO, codegen-units=1, debug=1; no target-cpu override",
    "rustflags": os.environ.get("RUSTFLAGS", ""),
    "packets_per_worker": args.packets,
    "samples": args.samples,
    "workers": list(range(1, args.max_workers + 1)),
    "cargo_lock_sha256": sha("Cargo.lock"),
    "harness_sha256": sha("benches/transport.rs"),
    "scope": "seal+open Tunn roundtrip; payload bytes counted once; no socket/utun I/O",
}
env = os.environ.copy()
env.update(MAX_WORKERS=str(args.max_workers), SAMPLES=str(args.samples), PACKETS=str(args.packets))
with args.output.open("w") as output:
    subprocess.run(["cargo", "bench", "--locked", "--bench", "transport"], env=env, stdout=output, check=True)
metadata["power_after"] = capture("pmset", "-g", "batt")
metadata["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
args.output.with_suffix(".json").write_text(json.dumps(metadata, indent=2) + "\n")
