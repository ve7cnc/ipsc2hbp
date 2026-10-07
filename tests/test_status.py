#!/usr/bin/env python3
"""
Unit tests for the peer status file (ipsc/status.py).

ipsc2hbp tracks every IPSC peer with keepalive state; with [global] status_file set
it writes that table as JSON, atomically, on a timer and at once on a change. With it
unset, nothing is written and nothing on the wire changes.

Run with:
    python -m unittest tests.test_status -v
"""

import asyncio
import dataclasses
import json
import os
import socket
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import load as load_config
from ipsc.const import (DE_REG_REQ, MASTER_REG_REQ, MASTER_REG_REPLY, PEER_LIST_REPLY,
                        PEER_REG_REPLY, VOICE_HEAD, VOICE_TERM, SLOT2_VOICE)
from ipsc.protocol import IPSCMasterProtocol, IPSCPeerProtocol
from ipsc.status import StatusWriter
from tests.test_rssi_burst import _CFG_PATH, _MockHBP, _ipsc_gv
from translate.translator import CallTranslator

PEER_IP = '198.51.100.7'
REPEATER = 3120000


class _Transport:
    def __init__(self):
        self.sent = []

    def sendto(self, data, addr):
        self.sent.append((bytes(data), addr))


class _Translator:
    def __init__(self):
        self.events = []

    def peer_joined(self):
        self.events.append('joined')

    def peer_lost(self):
        self.events.append('lost')

    def check_call_timeouts(self):
        pass

    def ipsc_voice_received(self, data, ts, burst):
        self.events.append(('voice', bytes(data), ts, burst))


def _cfg(**over):
    return dataclasses.replace(load_config(_CFG_PATH), **over)


def _reg(pid=REPEATER):
    return bytes([MASTER_REG_REQ]) + pid.to_bytes(4, 'big') + b'\x6a' + b'\x00\x00\x00\x0d' + b'\x04\x02\x04\x01'


def _master(cfg=None, translator=None):
    proto = IPSCMasterProtocol(cfg or _cfg(), translator or _Translator())
    proto._transport = _Transport()          # no watchdog task: tests drive it
    return proto


class _TmpDir(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, 'status.json')

    def tearDown(self):
        self.dir.cleanup()

    def read(self):
        with open(self.path) as fh:
            return json.load(fh)


class TestStatusFile(_TmpDir):

    def test_status_file_written_each_tick(self):
        proto = _master(_cfg(status_file=self.path, status_interval=1))
        w = StatusWriter(proto._cfg, proto)
        loop = asyncio.new_event_loop()
        try:
            w.start(loop)
            loop.run_until_complete(asyncio.sleep(0.05))
            first = os.stat(self.path).st_mtime_ns
            loop.run_until_complete(asyncio.sleep(1.1))
            self.assertGreater(os.stat(self.path).st_mtime_ns, first)
        finally:
            w.stop()
            loop.run_until_complete(asyncio.sleep(0))
            loop.close()
        doc = self.read()
        self.assertEqual((doc['mode'], doc['hbp_repeater_id'], doc['peers']), ('MASTER', REPEATER, []))
        # Atomic: only the file itself, no temp left behind.
        self.assertEqual(os.listdir(self.dir.name), ['status.json'])

    def test_status_file_absent_when_unconfigured(self):
        cfg = load_config(_CFG_PATH)
        self.assertEqual(cfg.status_file, '')
        proto = _master(cfg)
        proto.datagram_received(_reg(), (PEER_IP, 50001))
        self.assertIsNone(proto.on_status_change)
        self.assertEqual(os.listdir(self.dir.name), [])

    def test_status_file_contains_no_ip_addresses(self):
        proto = _master(_cfg(status_file=self.path))
        StatusWriter(proto._cfg, proto)
        proto.datagram_received(_reg(), (PEER_IP, 50001))
        with open(self.path) as fh:
            text = fh.read()
        self.assertNotIn('198.51.100', text)
        self.assertNotIn('"ip"', text)
        peer = json.loads(text)['peers'][0]
        self.assertEqual((peer['peer_id'], peer['ip_present'], peer['state']), (REPEATER, True, 'connected'))

    def test_peer_state_derived_from_keepalive_watchdog(self):
        proto = _master(_cfg(status_file=self.path))
        proto.datagram_received(_reg(), (PEER_IP, 50001))
        pid = REPEATER.to_bytes(4, 'big')
        proto._peers[pid]['last_ka'] = time.time() - proto._cfg.keepalive_watchdog - 1
        self.assertEqual(proto.status_peers()[0]['state'], 'not_connected')
        proto._peers[pid]['last_ka'] = time.time()
        self.assertEqual(proto.status_peers()[0]['state'], 'connected')

    def test_master_mode_writes_immediately_on_register(self):
        proto = _master(_cfg(status_file=self.path))
        StatusWriter(proto._cfg, proto)
        proto.datagram_received(_reg(), (PEER_IP, 50001))
        self.assertEqual([p['peer_id'] for p in self.read()['peers']], [REPEATER])
        # ... and on de-register.
        proto.datagram_received(bytes([DE_REG_REQ]) + REPEATER.to_bytes(4, 'big'), (PEER_IP, 50001))
        self.assertEqual(self.read()['peers'], [])

    def test_the_directory_is_made(self):
        path = os.path.join(self.dir.name, 'peers', 'rep.json')
        proto = _master(_cfg(status_file=path))
        StatusWriter(proto._cfg, proto).write()
        self.assertTrue(os.path.exists(path))

    def test_a_write_failure_never_raises(self):
        blocker = os.path.join(self.dir.name, 'a-file')
        open(blocker, 'w').close()                     # a directory that cannot be made
        proto = _master(_cfg(status_file=os.path.join(blocker, 'status.json')))
        StatusWriter(proto._cfg, proto)
        with self.assertLogs('ipsc.status', level='WARNING'):
            proto.datagram_received(_reg(), (PEER_IP, 50001))     # still registers
        self.assertIn(REPEATER.to_bytes(4, 'big'), proto._peers)


class TestPeerMode(_TmpDir):

    MASTER_IP, MASTER_RID, SLAVES = '203.0.113.1', 302700, (302025, 302394)

    def _peer(self):
        cfg = _cfg(ipsc_mode='PEER', ipsc_master_ip=self.MASTER_IP, ipsc_master_port=50000,
                   keepalive_interval=5, keepalive_missed_max=3, status_file=self.path)
        proto = IPSCPeerProtocol(cfg, _Translator())
        proto._transport = _Transport()
        StatusWriter(cfg, proto)
        return proto

    def _register(self, proto):
        m = self.MASTER_RID.to_bytes(4, 'big')
        proto.datagram_received(bytes([MASTER_REG_REPLY]) + m + b'\x6a\x00\x00\x00\x0d' + b'\x00\x03'
                                + b'\x04\x02\x04\x01', (self.MASTER_IP, 50000))
        entries = b''.join(r.to_bytes(4, 'big') + socket.inet_aton(f'198.51.100.{i + 20}')
                           + (50000 + i).to_bytes(2, 'big') + b'\x6a'
                           for i, r in enumerate(self.SLAVES))
        proto.datagram_received(bytes([PEER_LIST_REPLY]) + m + len(entries).to_bytes(2, 'big')
                                + entries, (self.MASTER_IP, 50000))

    def test_the_master_and_every_mesh_peer_with_their_state(self):
        proto = self._peer()
        self._register(proto)
        doc = self.read()
        self.assertEqual(doc['mode'], 'PEER')
        self.assertEqual([(p['peer_id'], p['role'], p['state']) for p in doc['peers']],
                         [(302700, 'master', 'connected'),
                          (302025, 'peer', 'not_connected'), (302394, 'peer', 'not_connected')])
        # The first slave answers our peer registration: connected, written at once.
        proto.datagram_received(bytes([PEER_REG_REPLY]) + (302025).to_bytes(4, 'big') + b'\x04\x02\x04\x01',
                                ('198.51.100.20', 50000))
        states = {p['peer_id']: p['state'] for p in self.read()['peers']}
        self.assertEqual(states[302025], 'connected')
        sq = next(p for p in self.read()['peers'] if p['peer_id'] == 302025)
        self.assertIsNotNone(sq['last_keepalive'])
        self.assertIsNotNone(sq['connected_since'])     # up since, for "up 5h"
        self.assertIsNotNone(self.read()['peers'][0]['connected_since'])   # the master link
        self.assertNotIn('198.51.100', json.dumps(self.read()))

    def test_a_slave_that_stops_answering_drops_with_the_protocols_own_rule(self):
        proto = self._peer()
        self._register(proto)
        proto.datagram_received(bytes([PEER_REG_REPLY]) + (302025).to_bytes(4, 'big') + b'\x04\x02\x04\x01',
                                ('198.51.100.20', 50000))
        for _ in range(proto._cfg.keepalive_missed_max + 1):      # ticks with no PEER_ALIVE_REPLY
            proto._service_mesh_peers()
        states = {p['peer_id']: p['state'] for p in self.read()['peers']}
        self.assertEqual(states[302025], 'not_connected')

    def test_losing_the_master_marks_everyone_not_connected(self):
        proto = self._peer()
        self._register(proto)
        proto._lose_connection()
        self.assertEqual({p['state'] for p in self.read()['peers']}, {'not_connected'})


class TestMeshPeerBehindNat(TestPeerMode):
    """Squamish (302025) is listed by the master at the port its NAT uses toward the
    master; it reaches us from another. That one is the one that works."""

    def test_a_peer_is_reached_where_it_talks_from(self):
        from ipsc.const import PEER_ALIVE_REQ, PEER_REG_REQ
        proto = self._peer()
        self._register(proto)                       # listed at 198.51.100.20:50000
        nat = ('198.51.100.20', 9612)
        proto.datagram_received(bytes([PEER_ALIVE_REQ]) + (302025).to_bytes(4, 'big') + b'\x6a\x00\x00\x00\x0d', nat)
        proto._transport.sent.clear()
        proto._service_mesh_peers()
        reg = [a for d, a in proto._transport.sent if d[0] == PEER_REG_REQ]
        self.assertIn(nat, reg)                     # registration goes where it works
        proto.datagram_received(bytes([PEER_REG_REPLY]) + (302025).to_bytes(4, 'big') + b'\x04\x02\x04\x01', nat)
        self.assertEqual({p['peer_id']: p['state'] for p in self.read()['peers']}[302025], 'connected')
        # The master's next peer list still says :50000: the learned port stays.
        self._register(proto)
        self.assertEqual(proto._mesh[(302025).to_bytes(4, 'big')]['port'], 9612)

    def test_a_peer_that_moves_to_another_ip_follows_the_list(self):
        proto = self._peer()
        self._register(proto)
        pid = (302025).to_bytes(4, 'big')
        proto._mesh[pid].update(ip='203.0.113.9', port=7, learned=True)
        self._register(proto)                       # listed elsewhere: believe the list
        self.assertEqual((proto._mesh[pid]['ip'], proto._mesh[pid]['port']), ('198.51.100.20', 50000))


class TestWireUntouched(_TmpDir):
    """The fork adds one writer and nothing else: what ipsc2hbp sends either way is the same."""

    def _run(self, status: bool):
        cfg = _cfg(status_file=self.path if status else '')
        hbp = _MockHBP()
        tr = CallTranslator(cfg)
        proto = _master(cfg, tr)
        tr.set_protocols(proto, hbp)
        if status:
            StatusWriter(cfg, proto)
        proto.datagram_received(_reg(), (PEER_IP, 50001))
        proto.datagram_received(_with_peer(_ipsc_gv(VOICE_HEAD)), (PEER_IP, 50001))
        for _ in range(6):
            proto.datagram_received(_with_peer(_ipsc_gv(SLOT2_VOICE)), (PEER_IP, 50001))
        proto.datagram_received(_with_peer(_ipsc_gv(VOICE_TERM)), (PEER_IP, 50001))
        return [d for d, _ in proto._transport.sent], hbp.sent

    def test_dmrd_repeater_id_unchanged(self):
        _, dmrd = self._run(status=True)
        self.assertTrue(dmrd)
        for frame in dmrd:
            self.assertEqual(int.from_bytes(frame[11:15], 'big'), REPEATER)

    def test_voice_path_identical_with_status_disabled(self):
        off_ipsc, off_hbp = self._run(status=False)
        on_ipsc, on_hbp = self._run(status=True)
        self.assertEqual(off_ipsc, on_ipsc)
        # Stream IDs are random per call; everything else must match byte for byte.
        strip = lambda frames: [f[:16] + f[20:] for f in frames]
        self.assertEqual(strip(off_hbp), strip(on_hbp))


class TestCallLogNamesThePeer(_TmpDir):
    """Which repeater in the IPSC heard a call, for the monitor: in the log only."""

    def test_call_start_and_end_say_which_peer(self):
        with self.assertLogs('translate.translator', level='INFO') as logs:
            TestWireUntouched._run(self, status=False)
        start = [l for l in logs.output if 'IPSC call start' in l]
        end = [l for l in logs.output if 'IPSC call end:' in l]
        self.assertTrue(start and end)
        self.assertIn(f'peer={REPEATER}', start[0])
        self.assertIn(f'peer={REPEATER}', end[0])


def _with_peer(pkt: bytes) -> bytes:
    """The synthetic GROUP_VOICE, from our registered peer."""
    return pkt[:1] + REPEATER.to_bytes(4, 'big') + pkt[5:]


if __name__ == '__main__':
    unittest.main()
