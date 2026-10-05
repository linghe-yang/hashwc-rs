"""Native libpcap capture spool; Python attributes compact packets after STOP."""
import os
import re
import shutil
import signal
import struct
import subprocess
import tempfile
import time
from pathlib import Path

from benchmark.utils import BenchError


class NativeCapture:
    def __init__(self, ports, directory=None):
        self.temporary = tempfile.TemporaryDirectory(prefix='whcc-capture-') if directory is None else None
        self.directory = Path(self.temporary.name if self.temporary else directory)
        self.file = self.directory/'.traffic.pcap'
        self.log = self.directory/'capture.log'
        self.process = None
        self.handle = None
        self.ports = ports

    def start(self):
        self.directory.mkdir(parents=True, exist_ok=True)
        expression = 'ip and tcp and portrange {}-{} and (tcp[13] & 2 != 0 or ip[2:2] - ((ip[0] & 15) << 2) - ((tcp[12] & 240) >> 2) > 0)'.format(min(self.ports), max(self.ports))
        # libpcap suppresses the outgoing loopback twin on older Linux versions.
        # Capture its incoming twin once; sender attribution still uses TCP/frame
        # source identity, never the receiving party.
        command = [shutil.which('tcpdump'), '-i', 'lo', '-Q', 'in', '-y', 'EN10MB', '-nn',
                   '--immediate-mode', '-s', '256', '-B', '131072', '-w', str(self.file)]
        if os.geteuid() == 0:
            command += ['-Z', 'root']
        self.handle = self.log.open('wb')
        try:
            self.process = subprocess.Popen(command+[expression], stdout=subprocess.DEVNULL, stderr=self.handle,
                                            stdin=subprocess.DEVNULL, env=dict(os.environ, LC_ALL='C'))
            deadline = time.monotonic()+5
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise BenchError('Native capture exited: '+self.log.read_text())
                if 'listening on lo' in self.log.read_text():
                    return
                time.sleep(0.01)
            raise BenchError('Native capture did not become ready')
        except BaseException:
            self.close()
            raise

    def finish(self):
        # All party processes have exited. Give the native mmap reader a short
        # drain interval; this is outside the synchronizer latency measurement.
        time.sleep(0.2)
        self.process.send_signal(signal.SIGINT)
        try:
            code = self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
            raise BenchError('Native capture did not stop')
        self.handle.close()
        self.handle = None
        log = self.log.read_text()
        if code != 0:
            raise BenchError('Native capture failed: '+log)
        counts = {}
        for field, phrase in [('captured','packets captured'), ('received','packets received by filter'), ('dropped','packets dropped by kernel')]:
            matches = re.findall(r'(\d+) '+phrase, log)
            if not matches:
                raise BenchError('Missing native capture statistics: '+log)
            # SIGUSR1 may have emitted intermediate counters; the final counters are authoritative.
            counts[field] = int(matches[-1])
        if counts['dropped']:
            raise BenchError('Native capture dropped {} packets; result is invalid'.format(counts['dropped']))
        return counts

    def packets(self):
        with self.file.open('rb') as stream:
            header = stream.read(24)
            if len(header) != 24 or header[:4] not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
                raise BenchError('Unsupported or truncated capture format')
            endian = '<' if header[:4] == b'\xd4\xc3\xb2\xa1' else '>'
            if struct.unpack(endian+'I', header[20:24])[0] != 1:
                raise BenchError('Capture requires Ethernet link headers')
            while True:
                record = stream.read(16)
                if not record:
                    break
                if len(record) != 16:
                    raise BenchError('Truncated capture record')
                _, _, captured, original = struct.unpack(endian+'IIII', record)
                if captured > 256 or captured > original:
                    raise BenchError('Invalid capture snapshot length')
                packet = stream.read(captured)
                if len(packet) != captured:
                    raise BenchError('Truncated capture packet')
                yield packet, original

    def close(self):
        if self.process is not None and self.process.poll() is None:
            self.process.send_signal(signal.SIGINT)
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        if self.handle is not None:
            self.handle.close()
            self.handle = None
        if self.temporary is not None:
            self.temporary.cleanup()
