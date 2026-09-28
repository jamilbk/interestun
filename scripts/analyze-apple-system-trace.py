#!/usr/bin/env python3
"""Summarize xctrace syscall/thread-state XML, resolving its interned references.

Export each table separately; some xctrace versions append foreign rows under
the first schema when using a compound XPath. Intervals are clipped to --start/--end, counts
include calls starting inside that window. Syscall CPU/wait fields are retained
as diagnostics, not treated as reliable when they exceed the wall interval.
"""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import xml.etree.ElementTree as ET


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('--start', type=float, default=2)
    parser.add_argument('--end', type=float, default=22)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--skip-foreign-rows', action='store_true',
                        help='Work around xctrace compound export appending rows from a different table under the first schema')
    args = parser.parse_args()
    assert 0 <= args.start < args.end
    lower, upper = int(args.start * 1e9), int(args.end * 1e9)
    cache = [None]
    numeric = {'start-time', 'duration', 'duration-on-core', 'duration-waiting',
               'syscall-arg', 'syscall-return', 'end-time'}
    named = {'thread', 'process', 'syscall', 'thread-state', 'thread-state-kind',
             'core', 'cpu', 'state'}
    interned = numeric | named | {'frame', 'tagged-backtrace'}
    calls = defaultdict(Counter)
    threads = defaultdict(Counter)
    stacks = defaultdict(Counter)
    states = defaultdict(Counter)
    cores = defaultdict(Counter)
    runnable_sources = defaultdict(Counter)
    schemas = []
    rows = 0
    invalid = Counter()

    def value(element):
        if element.tag == 'sentinel':
            return None
        if 'ref' in element.attrib:
            index = int(element.attrib['ref'])
            return cache[index] if index < len(cache) else None
        if element.tag in numeric:
            return int(element.text or '0')
        if element.tag == 'frame':
            return element.attrib.get('name', '?')
        if element.tag == 'tagged-backtrace':
            return tuple(value(frame) for frame in element if frame.tag == 'frame')
        return element.attrib.get('fmt', element.text)

    def intern(element):
        for child in element:
            intern(child)
        if 'id' in element.attrib and element.tag in interned:
            index = int(element.attrib['id'])
            if index >= len(cache):
                cache.extend([None] * (index + 1 - len(cache)))
            cache[index] = value(element)

    columns = []
    node = None
    for event, element in ET.iterparse(args.input, events=('start', 'end')):
        if event == 'start':
            if element.tag == 'node':
                node = element
            continue
        if element.tag == 'schema':
            schema = element.attrib['name']
            columns = [col.findtext('mnemonic') for col in element.findall('col')]
            schemas.append({'name': schema, 'columns': columns})
        elif element.tag == 'row':
            intern(element)
            if schema == 'syscall' and element[2].tag != 'syscall':
                if not args.skip_foreign_rows:
                    raise ValueError('foreign rows under syscall schema; export each table separately')
                invalid['foreign_rows_skipped'] += 1
                element.clear()
                node.remove(element)
                continue
            row = dict(zip(columns, (value(item) for item in element)))
            rows += 1
            if schema == 'syscall':
                start = row['start']
                if lower <= start < upper:
                    thread, call = row['thread'], row['call']
                    duration = row['duration'] or 0
                    cpu, wait = row['cputime'] or 0, row['waittime'] or 0
                    if cpu > duration or wait > duration or cpu + wait > duration + 2:
                        invalid['syscall_cpu_wait_exceeds_wall_rows'] += 1
                    data = {'count': 1, 'wall_ns': duration, 'reported_cpu_ns': cpu,
                            'reported_wait_ns': wait, 'errors': int(bool(row['errno']))}
                    calls[call].update(data)
                    threads[thread].update(data)
                    threads[thread][call] += 1
                    if call in ('recvmsg_x', 'sendmsg_x') and not row['errno']:
                        calls[call]['successful_messages'] += row['return'] or 0
                    stack = row['backtrace'] or ()
                    label = ' → '.join(frame or '?' for frame in stack[:6])
                    stacks[call][label] += 1
            elif schema == 'thread-state':
                # Fail loudly if a new Instruments schema needs a different mapping.
                start = row['start']
                duration = row['duration'] or 0
                overlap = max(0, min(start + duration, upper) - max(start, lower))
                if overlap:
                    states[row['thread']][row['state']] += overlap
                    if row['state'] == 'Running':
                        cores[row['thread']][row['core']] += overlap
                    if row['state'] == 'Runnable':
                        runnable_sources[row['thread']][row['made-runnable-by-thread'] or 'unknown'] += overlap
            element.clear()
            if node is not None:
                node.remove(element)

    report = {
        'window_seconds': [args.start, args.end], 'schemas': schemas, 'rows': rows,
        'diagnostics': dict(invalid),
        'syscalls': dict(sorted(calls.items(), key=lambda p: -p[1]['count'])),
        'threads_syscalls': dict(threads),
        'top_call_stacks': {call: counts.most_common(10) for call, counts in stacks.items()},
        'thread_state_seconds': {thread: {state: ns / 1e9 for state, ns in values.items()}
                                 for thread, values in states.items()},
        'running_core_seconds': {thread: {core: ns / 1e9 for core, ns in values.items()} for thread, values in cores.items()},
        'runnable_source_seconds': {thread: {source: ns / 1e9 for source, ns in values.items()} for thread, values in runnable_sources.items()},
    }
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in ('window_seconds', 'rows', 'diagnostics', 'syscalls', 'thread_state_seconds')}, indent=2))


if __name__ == '__main__':
    main()
