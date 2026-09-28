#!/usr/bin/env python3
"""Read saved panic/Mach-O files and symbolicate offline. Never opens a tunnel.

Only emits the panic assertion and stacks for the panicked interestun process.
The original report may contain unrelated process information; do not publish it.
"""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import struct
import subprocess
import uuid


def macho(path):
    data = path.read_bytes()
    if data[:4] != b"\xcf\xfa\xed\xfe":
        raise ValueError(f"expected a little-endian 64-bit Mach-O: {path}")
    segments = {}
    image_uuid = None
    offset = 32
    for _ in range(struct.unpack_from("<I", data, 16)[0]):
        command, size = struct.unpack_from("<II", data, offset)
        if size < 8 or offset + size > len(data):
            raise ValueError("invalid Mach-O load command")
        if command == 0x19:  # LC_SEGMENT_64
            name = data[offset + 8:offset + 24].rstrip(b"\0").decode()
            segments[name] = struct.unpack_from("<Q", data, offset + 24)[0]
        elif command == 0x1B:  # LC_UUID
            image_uuid = str(uuid.UUID(bytes=data[offset + 8:offset + 24]))
        offset += size
    if image_uuid is None:
        raise ValueError(f"missing Mach-O UUID: {path}")
    return image_uuid, segments


def symbols(path, addresses):
    if not addresses:
        return []
    result = subprocess.run(
        ["xcrun", "atos", "-o", str(path), *map(hex, addresses)],
        check=True, capture_output=True, text=True,
    )
    lines = result.stdout.splitlines()
    if len(lines) != len(addresses):
        raise ValueError("unexpected atos output count")
    return [
        {"file_address": hex(address), "atos": line}
        for address, line in zip(addresses, lines)
    ]


def analyze(report_path, kernel_path, executable_path):
    raw = report_path.read_text()
    _, end = json.JSONDecoder().raw_decode(raw)
    report = json.loads(raw[end:])
    panic = report["panicString"]
    pid_match = re.search(r"pid (\d+): interestun\b", panic)
    if pid_match is None:
        raise ValueError("report does not identify interestun as the panicked process")
    pid = pid_match[1]
    kernel_uuid, kernel_segments = macho(kernel_path)
    expected = re.search(r"Kernel UUID:\s*([0-9A-Fa-f-]+)", panic)[1].lower()
    if kernel_uuid != expected:
        raise ValueError(f"kernel UUID mismatch: {kernel_uuid} != {expected}")
    # Kernel-collection executable segments can be relocated independently.
    # Map from the report's executable base to this Mach-O's __TEXT_EXEC.
    # Subtracting the generic kernel slide alone produces misleading symbols.
    loaded_exec = int(re.search(r"Kernel text exec base:\s*(0x[0-9a-f]+)", panic)[1], 16)
    addresses = [
        int(value, 16) - loaded_exec + kernel_segments["__TEXT_EXEC"]
        for value in re.findall(r"lr: (0xffff[0-9a-f]+)", panic)
    ]
    calendar = int(re.search(r"  Calendar\s*:\s*(0x[0-9a-f]+)", panic)[1], 16)
    process = report["processByPid"][pid]
    # Omit the build-system path and unrelated process/system details.
    assertion = panic.splitlines()[0]
    assertion = re.sub(r"file: .*?/Sources/xnu/", "file: xnu/", assertion)
    result = {
        "report": report_path.name,
        "panic_time_utc": datetime.fromtimestamp(calendar, timezone.utc).isoformat(),
        "assertion": assertion,
        "pid": int(pid),
        "process_uptime_seconds": process["processUptime"],
        "kernel_uuid": kernel_uuid,
        "kernel_frames": symbols(kernel_path, addresses),
    }
    if executable_path is not None:
        executable_uuid, segments = macho(executable_path)
        addresses = []
        for thread in process["threadById"].values():
            for index, offset in thread.get("userFrames", []):
                image_uuid, _, _ = report["binaryImages"][index]
                if image_uuid.lower() == executable_uuid:
                    addresses.append(segments["__TEXT"] + offset)
        if not addresses:
            raise ValueError("executable UUID does not match the panicked process stack")
        result["executable_uuid"] = executable_uuid
        result["executable_frames"] = symbols(executable_path, addresses)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reports", type=Path, nargs="+")
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--executable", type=Path)
    args = parser.parse_args()
    try:
        results = [analyze(p, args.kernel, args.executable) for p in args.reports]
    except (OSError, ValueError, KeyError, TypeError, IndexError, struct.error,
            subprocess.CalledProcessError) as error:
        parser.exit(1, f"offline symbolication failed: {error}\n")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
