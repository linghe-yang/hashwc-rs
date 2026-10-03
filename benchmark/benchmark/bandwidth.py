"""Linux loopback capture: count each outgoing TCP payload once, without a proxy.
Includes application framing/MAC/ACK and retransmitted payload; excludes TCP/IP/Ethernet
headers and pure TCP ACKs. Self-deliveries do not use TCP and are not counted.
"""
import select
import socket
import struct
import threading
import time

from benchmark.utils import BenchError


class BandwidthMeter:
    def __init__(self, ports, parties=None):
        self.ports = ports
        self.totals = {p['service']: 0 for p in ports.values()}
        self.per_party = None if parties is None else {i: dict(self.totals) for i in parties}
        self.connections = {}
        self.unattributed = 0
        self.packets = 0
        self.stop_event = threading.Event()
        self.error = None
        self.socket = None
        self.thread = None

    @staticmethod
    def decode(packet, direction, ports):
        # Linux sends both outgoing and incoming copies on lo; retain only outgoing.
        if direction != 4 or len(packet) < 54 or packet[12:14] != b'\x08\x00':
            return None
        ip = 14
        ihl = (packet[ip] & 15) * 4
        if packet[ip] >> 4 != 4 or ihl < 20 or packet[ip+9] != 6:
            return None
        total = int.from_bytes(packet[ip+2:ip+4], 'big')
        if len(packet) < ip + total or total < ihl + 20:
            raise BenchError('Truncated packet during bandwidth measurement')
        tcp = ip + ihl
        source, target = struct.unpack_from('!HH', packet, tcp)
        if source not in ports and target not in ports:
            return None
        if int.from_bytes(packet[ip+6:ip+8], 'big') & 0x3fff:
            raise BenchError('Fragmented benchmark TCP packet; cannot measure reliably')
        tcp_len = (packet[tcp+12] >> 4) * 4
        if tcp_len < 20 or ihl + tcp_len > total:
            raise BenchError('Invalid benchmark TCP header')
        size = total - ihl - tcp_len
        service = ports[source if source in ports else target]['service']
        return service, size

    def start(self):
        if not hasattr(socket, 'AF_PACKET'):
            raise BenchError('Bandwidth measurement requires Linux/WSL (AF_PACKET)')
        try:
            self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16*1024*1024)
            try:
                # Linux SO_RCVBUFFORCE, per socket only; root/CAP_NET_ADMIN can
                # avoid the small system rmem_max cap without changing sysctls.
                self.socket.setsockopt(socket.SOL_SOCKET, 33, 16*1024*1024)
            except PermissionError:
                pass
            self.receive_buffer_bytes = self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            self.socket.bind(('lo', 0))
            self.socket.setblocking(False)
            # Reset packet/drop counters immediately before the measurement.
            self.socket.getsockopt(263, 6, 8)
        except OSError as e:
            if self.socket is not None:
                self.socket.close()
            raise BenchError('Cannot capture loopback traffic; run in Linux/WSL with root or CAP_NET_RAW', e)
        self.started_us = time.time_ns() // 1000
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        try:
            while not self.stop_event.is_set():
                if not select.select([self.socket], [], [], 0.05)[0]:
                    continue
                self._receive()
            # Drain queued packets after all parties output and the settling period.
            deadline = time.monotonic() + 2
            while select.select([self.socket], [], [], 0)[0]:
                if time.monotonic() > deadline:
                    raise BenchError('Traffic did not drain at measurement cutoff')
                self._receive()
        except Exception as e:
            self.error = e

    def _receive(self):
        try:
            packet, address = self.socket.recvfrom(262144)
        except BlockingIOError:
            return
        decoded = self.decode(packet, address[2], self.ports)
        if decoded is None:
            return
        service, size = decoded
        self.totals[service] += size
        if size:
            self.packets += 1
        if self.per_party is not None:
            self.attribute(packet, service, size)

    def attribute(self, packet, service, size):
        # Server-to-client application ACKs have the sender's listening port.
        tcp = 14 + (packet[14] & 15) * 4
        source, target, seq = struct.unpack_from('!HHI', packet, tcp)
        if source in self.ports:
            if not size:
                return  # Kernel RST/pure ACK from an unstarted party carries no application bytes.
            party = self.ports[source]['party']
            if party not in self.per_party:
                raise BenchError('Unexpected inactive party traffic')
            self.per_party[party][service] += size
            return
        # For outgoing data, identify the physical sender from the first upstream
        # authenticated Frame header. Keep only 52 bytes, not secret payloads.
        key = (source, target)
        syn = bool(packet[tcp+13] & 2)
        if syn:
            origin = (seq+1) & 0xffffffff
            current = self.connections.get(key)
            if current is None or current['origin'] != origin:
                if current is not None and current['pending']:
                    raise BenchError('Unattributed traffic before connection reuse')
                self.connections[key] = dict(origin=origin, header={}, pending=0, party=None)
        if not size:
            return
        if key not in self.connections:
            raise BenchError('Missed TCP SYN; cannot attribute sender bytes')
        conn = self.connections[key]
        if conn['party'] is not None:
            self.per_party[conn['party']][service] += size
            return
        conn['pending'] += size
        self.unattributed += size
        offset = (seq + int(syn) - conn['origin']) & 0xffffffff
        payload = packet[tcp + (packet[tcp+12] >> 4)*4:]
        for j in range(min(size, max(0, 52-offset))):
            position = offset+j
            byte = payload[j]
            if position in conn['header'] and conn['header'][position] != byte:
                raise BenchError('Conflicting retransmitted TCP header')
            conn['header'][position] = byte
        if len(conn['header']) == 52:
            header = bytes(conn['header'][i] for i in range(52))
            # upstream Frame: u32 length, [u8;32] context, u64 sender, u64 recipient.
            sender = int.from_bytes(header[36:44], 'little')
            recipient = int.from_bytes(header[44:52], 'little')
            if (int.from_bytes(header[:4], 'little') < 96 or sender not in self.per_party
                    or recipient != self.ports[target]['party']):
                raise BenchError('Unexpected upstream frame layout or party identity')
            conn['party'] = sender
            self.per_party[sender][service] += conn['pending']
            self.unattributed -= conn['pending']
            conn['pending'] = 0
            conn['header'].clear()

    def stop(self):
        if self.thread is None:
            return None
        self.stop_event.set()
        self.thread.join(timeout=4)
        try:
            if self.thread.is_alive():
                raise BenchError('Bandwidth capture did not stop')
            received, dropped = struct.unpack('II', self.socket.getsockopt(263, 6, 8))
            if self.error:
                raise BenchError('Bandwidth capture failed', self.error)
            if dropped:
                raise BenchError('Bandwidth capture dropped {} packets; result is invalid'.format(dropped))
            if self.unattributed:
                raise BenchError('Incomplete first frame: {} unassigned bytes'.format(self.unattributed))
            return dict(receive_buffer_bytes=self.receive_buffer_bytes, per_party_sent_bytes=self.per_party, backend='linux-af-packet-loopback', metric='tcp_payload_bytes',
                        total_sent_bytes=sum(self.totals.values()), per_service_sent_bytes=self.totals,
                        payload_packets=self.packets, capture_packets=received, dropped_packets=dropped,
                        started_us=self.started_us, completed_us=time.time_ns()//1000,
                        scope='PREPARE through receipt of STOP and party process exit; synchronizer traffic excluded',
                        includes='transport framing, MAC, application ACK, encrypted tokens, TCP retransmitted payload',
                        excludes='self delivery, TCP/IP/Ethernet headers, pure TCP ACKs')
        finally:
            self.socket.close()
            self.thread = None
