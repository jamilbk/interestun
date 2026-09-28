#!/usr/bin/env python3
"""Measure one TCP stream inside the existing Windows UDP tunnel, with CPU/counters."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import threading
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('mode', choices=['send', 'receive', 'duplex'])
parser.add_argument('--duration', type=int, default=30)
parser.add_argument('--bitrate', help='Optional TCP pacing rate, e.g. 3G for a CPU control')
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
if args.duration <= 0:
    parser.error('--duration must be positive')
OUT = args.output.resolve()
OUT.mkdir(parents=True, exist_ok=False)
CLI = '/Applications/Interestun.app/Contents/MacOS/interestunctl'
PID = subprocess.check_output(['pgrep', '-x', 'InterestunPacketTunnel'], text=True).strip()
assert PID.isdigit(), 'Expected one provider process'

def capture(command):
    return subprocess.check_output(command, text=True, timeout=10)

def cpu():
    fields = capture(['ps', '-p', PID, '-o', 'time=,rss=']).split()
    seconds = 0.0
    for part in fields[0].split(':'):
        seconds = seconds * 60 + float(part)
    return {'monotonic': time.monotonic(), 'cpu_seconds': seconds, 'rss_kib': int(fields[1])}

mode = args.mode
duration = args.duration
executable = Path(capture(['ps', '-p', PID, '-o', 'comm=']).strip())
binary_hash = hashlib.sha256(executable.read_bytes()).hexdigest() if executable.is_file() else None
flags = {'send': [], 'receive': ['-R'], 'duplex': ['--bidir']}[mode]
label = f'tunnel-{mode}-{duration}s'
before = json.loads(capture([CLI, 'show']))
assert len(before['peers']) == 1, 'Expected one peer for this measurement'
assert not before['failed'] and before['peers'][0]['latest_handshake_unix_seconds'] > 0
interface = before['interface']
(OUT / f'{label}-before.json').write_text(json.dumps(before, indent=2) + '\n')
(OUT / f'{label}-interface-before.txt').write_text(capture(['netstat', '-ibnI', interface]))
samples = [cpu()]
errors = []
stop = threading.Event()
def sample():
    while not stop.wait(0.5):
        try:
            samples.append(cpu())
        except Exception as error:
            errors.append(str(error))
            return
thread = threading.Thread(target=sample)
thread.start()
command = ['/opt/homebrew/bin/iperf3', '-c', '10.20.0.1', '-t', str(duration), '-O', '1', '-J', '--connect-timeout', '3000', *flags]
if args.bitrate:
    command += ['-b', args.bitrate]
started = datetime.datetime.now().astimezone().isoformat()
print(f'Starting {label} at {started}; provider PID {PID}', flush=True)
try:
    result = subprocess.run(command, capture_output=True, text=True, timeout=duration + 20)
finally:
    stop.set()
    thread.join()
samples.append(cpu())
(OUT / f'{label}.json').write_text(result.stdout)
(OUT / f'{label}.stderr').write_text(result.stderr)
after = json.loads(capture([CLI, 'show']))
(OUT / f'{label}-after.json').write_text(json.dumps(after, indent=2) + '\n')
(OUT / f'{label}-interface-after.txt').write_text(capture(['netstat', '-ibnI', interface]))
data = json.loads(result.stdout)
end = data.get('end', {})
steady = [s for s in samples if 2 <= s['monotonic'] - samples[0]['monotonic'] <= duration]
cores = None
if len(steady) >= 2:
    cores = (steady[-1]['cpu_seconds'] - steady[0]['cpu_seconds']) / (steady[-1]['monotonic'] - steady[0]['monotonic'])
metrics = ('input_packets', 'input_batches', 'input_drops', 'output_packets', 'output_batches', 'output_failures', 'read_callbacks')
delta = {key: after[key] - before[key] for key in metrics if key in after and key in before}
delta['peer_drops'] = after['peers'][0]['drops'] - before['peers'][0]['drops']
delta['tx_queue_drops'] = after['peers'][0].get('tx_queue_drops', 0) - before['peers'][0].get('tx_queue_drops', 0)
tx_before = before['peers'][0].get('network_tx')
tx_after = after['peers'][0].get('network_tx')
if tx_before is not None and tx_after is not None:
    delta['network_tx'] = {key: [b - a for a, b in zip(tx_before[key], value)]
                           if isinstance(value, list) else value - tx_before[key]
                           for key, value in tx_after.items()}
    tx = delta['network_tx']
    batches = sum(tx['batches'])
    tx['mean_batch'] = tx['accepted'] / batches if batches else 0
    tx['blocked_retry_seconds'] = tx['blocked_ns'] / 1e9
summary = {
    'started_at': started, 'command': command, 'provider_pid': int(PID),
    'provider_executable': str(executable), 'provider_sha256': binary_hash,
    'interface': interface, 'cipher': after['cipher'], 'mode': mode,
    'duration': duration, 'gbps': end.get('sum_received', {}).get('bits_per_second', 0) / 1e9,
    'reverse_gbps': end.get('sum_received_bidir_reverse', {}).get('bits_per_second', 0) / 1e9,
    'provider_cpu_cores': cores, 'rss_peak_mib': max(s['rss_kib'] for s in samples) / 1024,
    'retransmits': end.get('sum_sent', {}).get('retransmits'),
    'counter_delta': delta, 'largest_read_callback': after.get('largest_read_callback'), 'tun_backend': after['tun_backend'],
    'failed': after['failed'], 'exit_code': result.returncode, 'error': data.get('error'),
    'cpu_sample_errors': errors, 'cpu_samples': samples,
}
(OUT / f'{label}-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
print(json.dumps({k: v for k, v in summary.items() if k != 'cpu_samples'}, indent=2), flush=True)
sys.exit(result.returncode)
