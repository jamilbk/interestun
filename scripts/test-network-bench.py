#!/usr/bin/env python3
"""Finite loopback wire-format/lifetime checks, not a throughput benchmark."""
import argparse
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--iperf3", help="Optional real local iperf3 protocol smoke test")
    args = parser.parse_args()
    count = 257  # Exercises two full 128-packet batches and one short batch.
    for mode in ("raw", "aes", "chacha"):
        for batch, size in ((1, 20), (128, 1420)):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sink:
                sink.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
                sink.bind(("127.0.0.1", 0))
                sink.settimeout(5)
                received = []
                failures = []

                def drain():
                    try:
                        for _ in range(count):
                            received.append(sink.recv(65536))
                    except OSError as error:
                        failures.append(str(error))

                reader = threading.Thread(target=drain)
                reader.start()
                result = subprocess.run(
                    [args.binary, "send", "--target", f"127.0.0.1:{sink.getsockname()[1]}",
                     "--mode", mode, "--packets", str(count),
                     "--batch", str(batch), "--size", str(size)],
                    capture_output=True, text=True, timeout=20,
                )
                reader.join(timeout=6)
                assert result.returncode == 0, result.stderr
                assert not reader.is_alive() and not failures, failures
                assert len(received) == count
                assert all(len(data) == size + 32 for data in received)
                sequences = {int.from_bytes(data[8:16], "little") for data in received}
                assert len(sequences) == count, "duplicate data/nonce on wire"
                if mode == "raw":
                    assert sequences == set(range(count))
                    assert all(data[:4] == b"INB1" and not any(data[16:]) for data in received)
                else:
                    assert all(data[:4] == b"\x04\x00\x00\x00" for data in received)
                    assert max(sequences) - min(sequences) + 1 == count
                print(f"PASS production-network {mode} batch={batch} size={size}: {count} unique datagrams")

    if args.iperf3:
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1', 0))
            port = reserve.getsockname()[1]
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / 'results.json'
            with (Path(directory) / 'server.log').open('w') as log:
                server = subprocess.Popen([args.iperf3, '-s', '-1', '-B', '127.0.0.1', '-p', str(port)],
                                          stdout=log, stderr=log)
                try:
                    time.sleep(.3)  # Server setup only; not a throughput test.
                    result = subprocess.run([args.binary, 'send', '--target', f'127.0.0.1:{port}',
                                             '--iperf', '--seconds', '1', '--bitrate', '10000000',
                                             '--json', str(report)], capture_output=True, text=True, timeout=20)
                    assert result.returncode == 0, result.stderr
                    data = json.loads(report.read_text())
                    assert data['submitted_packets'] == data['received_packets'] > 0
                    assert data['receiver']['streams'][0]['errors'] == 0
                    assert data['tx']['accepted_including_setup'] == data['submitted_packets'] + 1
                    assert server.wait(timeout=5) == 0
                    print('PASS real iperf3 UDP protocol: receiver bytes, sequences, and graceful control teardown')
                finally:
                    if server.poll() is None:
                        server.terminate()
                        server.wait(timeout=5)


if __name__ == "__main__":
    main()
