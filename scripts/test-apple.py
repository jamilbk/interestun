#!/usr/bin/env python3
"""Compile and run the packet-flow bridge tests without opening a real interface."""
import argparse
import json
import os
from pathlib import Path
import platform
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--ethernet-offline", action="store_true", help="Test Ethernet settings without sockets or interfaces")
args = parser.parse_args()

root = Path(__file__).resolve().parents[1]
def run(*args, **kwargs):
    subprocess.run([str(a) for a in args], check=True, **kwargs)

run("cargo", "build", "--locked", "--release", "--lib", "--features", "apple-packet-tunnel", cwd=root,
    env={**os.environ, "MACOSX_DEPLOYMENT_TARGET": "15.0"})
meta = json.loads(subprocess.check_output(["cargo", "metadata", "--no-deps", "--format-version=1"], cwd=root))
library = Path(meta["target_directory"]) / "release/libinterestun.a"
output = root / "target/apple-tests"
output.mkdir(parents=True, exist_ok=True)
binary = output / ("ethernet-tests" if args.ethernet_offline else "bridge-tests")
flags = ["-D", "INTERESTUN_ETHERNET"] if args.ethernet_offline else []
run("xcrun", "swiftc", *flags, "-O", "-g", "-swift-version", "5", "-warnings-as-errors",
    "-target", f"{platform.machine()}-apple-macosx15.0", "-module-name", "InterestunBridgeTests",
    "-import-objc-header", root / "apple/Bridge/Interestun.h", "-framework", "Foundation",
    "-framework", "Network", "-framework", "NetworkExtension", library,
    root / "apple/Shared/Configuration.swift", root / "apple/Extension/PacketTunnelProvider.swift",
    root / ("apple/EthernetTests/main.swift" if args.ethernet_offline else "apple/Tests/main.swift"), "-o", binary)
run(binary)
