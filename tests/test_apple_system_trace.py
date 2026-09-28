"""Small known-answer checks for trace references, windowing, and export quirks."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/analyze-apple-system-trace.py'


def analyze(schema, columns, rows, *flags):
    columns = ''.join(f'<col><mnemonic>{name}</mnemonic></col>' for name in columns)
    data = f'<trace-query-result><node><schema name="{schema}">{columns}</schema>{rows}</node></trace-query-result>'
    with tempfile.TemporaryDirectory() as directory:
        path, output = Path(directory) / 'trace.xml', Path(directory) / 'result.json'
        path.write_text(data)
        result = subprocess.run([sys.executable, str(SCRIPT), str(path), '--start', '1',
                                 '--end', '3', '--output', str(output), *flags], capture_output=True, text=True)
        return result, json.loads(output.read_text()) if output.exists() else None


class TraceTests(unittest.TestCase):
    def test_syscall_references_and_window(self):
        columns = 'start thread call duration process cputime waittime arg1 arg2 arg3 arg4 return errno backtrace note signature'.split()
        common = ('<thread id="2" fmt="peer-0-tx"/><syscall id="3" fmt="recvmsg_x"/>'
                  '<duration id="4">100</duration><process id="5" fmt="provider"/>'
                  '<duration-on-core id="6">101</duration-on-core><sentinel/>'
                  '<syscall-arg id="7">4</syscall-arg><sentinel/><sentinel/><sentinel/>'
                  '<syscall-return id="8">5</syscall-return><syscall-return id="9">0</syscall-return>'
                  '<tagged-backtrace id="10"><frame id="11" name="recvmsg_x"/></tagged-backtrace><sentinel/><sentinel/>')
        refs = ('<thread ref="2"/><syscall ref="3"/><duration ref="4"/><process ref="5"/>'
                '<duration-on-core ref="6"/><sentinel/><syscall-arg ref="7"/><sentinel/><sentinel/><sentinel/>'
                '<syscall-return ref="8"/><syscall-return ref="9"/><tagged-backtrace ref="10"/><sentinel/><sentinel/>')
        rows = f'<row><start-time>0</start-time>{common}</row><row><start-time>2000000000</start-time>{refs}</row><row><start-time>3000000000</start-time>{refs}</row>'
        result, data = analyze('syscall', columns, rows)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(data['syscalls']['recvmsg_x']['count'], 1)
        self.assertEqual(data['syscalls']['recvmsg_x']['successful_messages'], 5)
        self.assertEqual(data['diagnostics']['syscall_cpu_wait_exceeds_wall_rows'], 1)
        self.assertEqual(data['top_call_stacks']['recvmsg_x'], [['recvmsg_x', 1]])

    def test_state_clipping_and_foreign_rows(self):
        columns = ['start', 'thread', 'state', 'duration', 'process', 'core', 'made-runnable-by-thread']
        rows = ('<row><start-time>0</start-time><thread id="1" fmt="peer-0-tx"/>'
                '<thread-state fmt="Blocked"/><duration id="2">2000000000</duration><sentinel/><sentinel/><sentinel/></row>'
                '<row><start-time>2000000000</start-time><thread ref="1"/>'
                '<thread-state fmt="Running"/><duration ref="2"/><sentinel/><core fmt="CPU 4"/><sentinel/></row>')
        result, data = analyze('thread-state', columns, rows)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(data['thread_state_seconds']['peer-0-tx'], {'Blocked': 1, 'Running': 1})
        result, _ = analyze('syscall', columns, rows)
        self.assertNotEqual(result.returncode, 0)
        result, data = analyze('syscall', columns, rows, '--skip-foreign-rows')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(data['diagnostics']['foreign_rows_skipped'], 2)


if __name__ == '__main__':
    unittest.main()
