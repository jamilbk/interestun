#!/usr/bin/env python3
"""Finite loopback wire-format/lifetime checks, not a throughput benchmark."""
import argparse
import socket
import subprocess
import threading


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    args = parser.parse_args()
    count = 257  # Exercises two full 128-packet batches and one short batch.
    for backend in ("bsd", "network"):
        for mode in ("raw", "aes", "chacha"):
            for batch, size, window in ((1, 20, 1), (128, 1420, 8)):
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
                         "--backend", backend, "--mode", mode, "--packets", str(count),
                         "--batch", str(batch), "--size", str(size), "--window", str(window)],
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
                    print(f"PASS {backend} {mode} batch={batch} size={size} window={window}: {count} unique datagrams")


if __name__ == "__main__":
    main()
