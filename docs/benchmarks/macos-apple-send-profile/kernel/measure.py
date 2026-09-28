import datetime
import json
from pathlib import Path
import subprocess
import sys
import threading
import time

OUT = Path(__file__).resolve().parent
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

mode = sys.argv[1]
duration = int(sys.argv[2]) if len(sys.argv) > 2 else 30
flags = {'send': [], 'receive': ['-R'], 'duplex': ['--bidir']}[mode]
label = f'tunnel-{mode}-{duration}s'
before = json.loads(capture([CLI, 'show']))
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
summary = {
    'started_at': started, 'command': command, 'provider_pid': int(PID),
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
