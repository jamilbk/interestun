#!/usr/bin/env python3
"""Summarize an xctrace time-profile XML export; never attach to a process.

Weights represent sampled running CPU time, not elapsed stack residence or
syscall counts. Inclusive entries overlap; the category partition does not.
"""
import argparse
from collections import Counter, defaultdict
import gzip
import json
from pathlib import Path
import xml.etree.ElementTree as ET


def category(thread, names):
    def has(text):
        return any(text in name for name in names)

    if thread.startswith("peer-") and "-tx (" in thread:
        if has("recvmsg_x"):
            return "TX: utun read"
        if has("in_flow_send"):
            return "TX: Network.framework send submission"
        if any(has(text) for text in (
            "ring::aead", "ring_core_0_17_14__aes", "TransportSender::encapsulate",
            "session::seal_in_place",
        )):
            return "TX: encryption and transport framing"
        return "TX: other routing, buffers, clocks and polling"
    if thread.startswith("peer-") and "-rx (" in thread:
        return "RX: receive worker"
    if has("nw_endpoint_handler_service_writes"):
        return "Dispatch: Network.framework asynchronous send service"
    return "Other framework, dispatch and callback work"


def analyze(path, start, end):
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rb") as source:
        root = ET.parse(source).getroot()
    schemas = root.findall(".//schema")
    if len(schemas) != 1 or schemas[0].get("name") != "time-profile":
        raise ValueError("export exactly one time-profile table")
    columns = [col.findtext("mnemonic") for col in schemas[0].findall("col")]
    if columns != ["time", "thread", "process", "core", "thread-state", "weight", "stack"]:
        raise ValueError(f"unexpected time-profile schema: {columns}")
    ids = {element.attrib["id"]: element for element in root.iter() if "id" in element.attrib}

    def resolve(element):
        return ids[element.attrib["ref"]] if "ref" in element.attrib else element

    threads, categories, leaves, inclusive, states = [Counter() for _ in range(5)]
    thread_leaves = defaultdict(Counter)
    copies = Counter()
    focus = Counter()
    samples = 0
    for row in root.iter("row"):
        cells = [resolve(cell) for cell in row]
        timestamp = int(cells[0].text)
        if not start * 1e9 <= timestamp < end * 1e9:
            continue
        if cells[4].text != "Running":
            raise ValueError("CPU attribution requires running-only samples; disable waiting-thread sampling")
        weight = int(cells[5].text)
        thread = cells[1].get("fmt", "unknown")
        frames = [resolve(frame) for frame in cells[6] if frame.tag == "frame"]
        names = [frame.get("name", frame.get("addr", "unknown")) for frame in frames]
        leaf = names[0] if names else "<empty stack>"
        samples += 1
        states[cells[4].text] += weight
        threads[thread] += weight
        categories[category(thread, names)] += weight
        leaves[leaf] += weight
        thread_leaves[thread][leaf] += weight
        for name in set(names):
            inclusive[name] += weight
        for pattern in (
            "__channel_sync", "nw_write_request_list_prune", "nw_write_request_report",
            "nw_flow_copy_write_request", "dispatch_data_create",
            "ring_core_0_17_14__aes_gcm_enc_kernel",
        ):
            if any(pattern in name for name in names):
                focus[pattern] += weight
        if leaf in ("objc_retain", "objc_release"):
            focus["objc_retain + objc_release (self only)"] += weight
        # Self weights avoid double-counting nested copying routines. These
        # include metadata copies; they do not measure only packet payloads.
        if leaf in ("copyin", "copyout", "memcpy", "memmove", "_platform_memmove", "_platform_memcpy"):
            copies[leaf] += weight
    total = sum(threads.values())
    if samples == 0 or total <= 0:
        raise ValueError("no samples in the requested window")
    assert total == sum(categories.values()) == sum(leaves.values())

    def entries(counter, limit=None):
        ordered = sorted(counter.items(), key=lambda item: (-item[1], item[0]))
        return [
            {"name": name, "sampled_cpu_seconds": ns / 1e9,
             "percent_of_sampled_cpu": ns * 100 / total,
             "estimated_cores": ns / 1e9 / (end - start)}
            for name, ns in ordered[:limit]
        ]

    return {
        "input": str(path), "window_start_seconds": start, "window_end_seconds": end,
        "samples": samples, "sampled_cpu_seconds": total / 1e9,
        "estimated_cores": total / 1e9 / (end - start),
        "states": entries(states), "threads": entries(threads),
        "categories_exclusive": entries(categories), "leaf_top_40": entries(leaves, 40),
        "inclusive_top_60_overlapping": entries(inclusive, 60),
        "copy_routine_self": entries(copies),
        "focus_overlapping": entries(focus),
        "thread_leaf_top_15": {name: entries(counts, 15) for name, counts in thread_leaves.items()},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--start", type=float, default=2)
    parser.add_argument("--end", type=float, default=22)
    args = parser.parse_args()
    if not 0 <= args.start < args.end:
        parser.error("require 0 <= start < end")
    value = analyze(args.input, args.start, args.end)
    args.output.write_text(json.dumps(value, indent=2) + "\n")
    print(json.dumps({key: value[key] for key in (
        "samples", "sampled_cpu_seconds", "estimated_cores", "categories_exclusive",
    )}, indent=2))


if __name__ == "__main__":
    main()
