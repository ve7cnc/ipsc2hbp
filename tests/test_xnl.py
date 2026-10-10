#!/usr/bin/env python3
"""
XNL/XCMP read-only status client, against messages from a c-Bridge ↔ SLR5700
(VE7RAG) capture, 2026-10-10 (IPSC 0x70 + peer ID and auth digest stripped).

The real login needs Motorola's XNL constants, which are not in this repository:
the fake repeater here accepts any answer. test_recorded_login_vector checks a set
of constants against the recorded challenge/response when XNL_AUTH_CONSTANTS is set.

Run with:
    python -m unittest tests.test_xnl -v
"""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ipsc import xnl
from ipsc.xnl import Xnl, XnlSession

H = bytes.fromhex
# Repeater → c-Bridge, in login order.
MASTER_STATUS = H('001300020000000000060000000700000002010101')
AUTH_KEY_REPLY = H('001600050000000000060000000afd5048d4365b38131646')
CONN_REPLY = H('001a00070000fd5000060000000e016101600b010f0eb8a31184fadc')
INIT_STATUS = H('0027000b010000000006012c001bb4000300000b00040000100005020004000501070209000d000e00')
RADIO_ID_REPLY = H('0014000b01020160000661000008800e000e00049e6d')
ALIAS_REPLY = H('0026000b0103016000066101001a800e000f005600450037005200410047002d0055004800460000')
RSSI_REPLY = H('0014000b01040160000661000008800e00027e046c6e')
# c-Bridge → repeater.
CONN_REQUEST = H('0018000600000006fd500000000c00000b01e15f99bcc93f0a6b')
RSSI_REQUEST = H('000f000b01020006016061000003000e02')

CHALLENGE, RESPONSE = H('48d4365b38131646'), H('e15f99bcc93f0a6b')
FAKE_K = (0x9E3779B9, 1, 2, 3, 4)       # not Motorola's: exercises the code path only


class FakeClock:
    def __init__(self):
        self.t = 1000.0
    def __call__(self):
        return self.t


class FakeSlr:
    """Answers like VE7RAG did, building replies from its recorded values."""
    ME, MASTER = 0x0160, 0x0006

    def __init__(self, accept=True):
        self.accept = accept
        self.flag = 0
        self.seen: list = []

    def handle(self, raw: bytes) -> list:
        m = Xnl.decode(raw)
        self.seen.append(m)
        if m.opcode == xnl.DEVICE_MASTER_QUERY:
            return [MASTER_STATUS]
        if m.opcode == xnl.DEVICE_AUTH_KEY_REQUEST:
            return [AUTH_KEY_REPLY]
        if m.opcode == xnl.DEVICE_CONN_REQUEST:
            if self.accept:
                return [CONN_REPLY]
            return [Xnl(xnl.DEVICE_CONN_REPLY, dst=0xfd50, src=self.MASTER,
                        payload=bytes(14)).encode()]
        if m.opcode == xnl.DATA_MSG:
            ack = Xnl(xnl.DATA_MSG_ACK, 1, m.flags, m.src, self.MASTER, m.tid).encode()
            op, arg = struct.unpack('>HB', m.payload[:3])
            if op == xnl.XCMP_RADIO_STATUS and arg == xnl.RS_RSSI:
                value = H('7e046c6e')
            elif op == xnl.XCMP_RADIO_STATUS and arg == xnl.RS_RADIO_ID:
                value = H('00049e6d')
            elif op == xnl.XCMP_RADIO_STATUS and arg == xnl.RS_ALIAS:
                value = H('005600450037005200410047002d0055004800460000')
            else:
                return [ack, Xnl(xnl.DATA_MSG, 1, self._flag(), m.src, self.MASTER, m.tid,
                                 struct.pack('>HB', 0x8000 | op, 0x01)).encode()]
            reply = Xnl(xnl.DATA_MSG, 1, self._flag(), m.src, self.MASTER, m.tid,
                        struct.pack('>HBB', 0x8000 | op, 0, arg) + value).encode()
            return [ack, reply]
        return []

    def _flag(self):
        self.flag = (self.flag + 1) % 8
        return self.flag


def run(session, slr, clock, call_up=False, steps=10):
    """Drive session ↔ fake repeater until quiet; returns everything the session sent."""
    sent = []
    pending = session.tick(call_up)
    for _ in range(steps):
        if not pending:
            pending = session.tick(call_up)
            if not pending:
                break
        nxt = []
        for raw in pending:
            sent.append(raw)
            for reply in slr.handle(raw):
                nxt += session.received(reply)
        pending = nxt
    return sent


class TestFraming(unittest.TestCase):

    def test_recorded_messages_round_trip(self):
        for raw in (MASTER_STATUS, AUTH_KEY_REPLY, CONN_REPLY, INIT_STATUS, RADIO_ID_REPLY,
                    ALIAS_REPLY, RSSI_REPLY, CONN_REQUEST, RSSI_REQUEST):
            self.assertEqual(Xnl.decode(raw).encode(), raw)

    def test_rssi_is_two_slots_8_8(self):
        m = Xnl.decode(RSSI_REPLY)
        s1, s2 = xnl.decode_rssi(m.payload[4:])
        self.assertAlmostEqual(s1, -126.02, places=2)
        self.assertAlmostEqual(s2, -108.43, places=2)

    def test_alias_is_utf16(self):
        self.assertEqual(xnl.decode_text(Xnl.decode(ALIAS_REPLY).payload[4:]), 'VE7RAG-UHF')

    def test_only_read_only_requests_can_be_built(self):
        self.assertEqual(xnl.xcmp_request(xnl.XCMP_RADIO_STATUS, xnl.RS_RSSI), H('000e02'))
        self.assertEqual(Xnl.decode(RSSI_REQUEST).payload, H('000e02'))
        for op, arg in ((0x0401, 0x00), (0x000E, 0x99), (0x0410, 0x01), (0x000C, 0x00)):
            with self.assertRaises(ValueError):
                xnl.xcmp_request(op, arg)

    def test_constants_parse(self):
        self.assertEqual(xnl.parse_constants('9e3779b9 1 2 3 4'), FAKE_K)
        self.assertIsNone(xnl.parse_constants('1 2 3'))
        self.assertIsNone(xnl.parse_constants('xyz 1 2 3 4'))

    @unittest.skipUnless(os.environ.get('XNL_AUTH_CONSTANTS'), 'XNL_AUTH_CONSTANTS not set')
    def test_recorded_login_vector(self):
        k = xnl.parse_constants(os.environ['XNL_AUTH_CONSTANTS'])
        self.assertTrue(xnl.check_constants(k, CHALLENGE, RESPONSE),
                        'constants do not reproduce the c-Bridge answer to VE7RAG')


class TestSession(unittest.TestCase):

    def setUp(self):
        self.clock = FakeClock()
        self.rssi = []
        self.s = XnlSession(FAKE_K, on_rssi=lambda a, b: self.rssi.append((a, b)),
                            clock=self.clock)
        self.slr = FakeSlr()

    def test_off_without_constants(self):
        s = XnlSession(None)
        self.assertEqual(s.tick(True), [])
        self.assertEqual(s.status.state, 'off')

    def test_login_matches_the_c_bridge(self):
        run(self.s, self.slr, self.clock)
        ops = [m.opcode for m in self.slr.seen[:3]]
        self.assertEqual(ops, [xnl.DEVICE_MASTER_QUERY, xnl.DEVICE_AUTH_KEY_REQUEST,
                               xnl.DEVICE_CONN_REQUEST])
        req = self.slr.seen[2]
        ref = Xnl.decode(CONN_REQUEST)
        self.assertEqual((req.dst, req.src, req.payload[:4]), (ref.dst, ref.src, ref.payload[:4]))
        self.assertEqual(req.payload[4:], xnl.encrypt(CHALLENGE, FAKE_K))
        self.assertTrue(self.s.connected)
        self.assertEqual(self.s.status.state, 'connected')

    def test_identity_read_after_login(self):
        run(self.s, self.slr, self.clock)
        self.assertEqual(self.s.status.radio_id, 302701)
        self.assertEqual(self.s.status.alias, 'VE7RAG-UHF')
        # Requests use the assigned address and the repeater's transaction base.
        data = [m for m in self.slr.seen if m.opcode == xnl.DATA_MSG]
        self.assertEqual({(m.src, m.dst) for m in data}, {(0x0160, 0x0006)})
        self.assertEqual(data[0].tid, 0x6100)

    def test_rssi_polled_once_a_second_only_during_a_call(self):
        run(self.s, self.slr, self.clock)
        self.assertEqual(self.rssi, [])
        run(self.s, self.slr, self.clock, call_up=True)
        self.assertEqual(len(self.rssi), 1)
        run(self.s, self.slr, self.clock, call_up=True)        # same second: no new poll
        self.assertEqual(len(self.rssi), 1)
        self.clock.t += 1.0
        run(self.s, self.slr, self.clock, call_up=True)
        self.assertEqual(len(self.rssi), 2)
        self.assertAlmostEqual(self.rssi[0][1], -108.43, places=2)
        self.clock.t += 5.0
        run(self.s, self.slr, self.clock, call_up=False)
        self.assertEqual(len(self.rssi), 2)

    def test_acks_repeater_data(self):
        run(self.s, self.slr, self.clock)
        out = self.s.received(INIT_STATUS)
        ack = Xnl.decode(out[0])
        self.assertEqual((ack.opcode, ack.tid, ack.dst, ack.src),
                         (xnl.DATA_MSG_ACK, 0x012c, 0x0006, 0x0160))

    def test_refused_login_backs_off(self):
        slr = FakeSlr(accept=False)
        run(self.s, slr, self.clock)
        self.assertFalse(self.s.connected)
        self.assertEqual(self.s.status.state, 'failed')
        self.assertEqual(self.s.tick(), [])                   # backing off
        self.clock.t += xnl.RELOGIN_BACKOFF_S
        self.assertEqual(Xnl.decode(self.s.tick()[0]).opcode, xnl.DEVICE_MASTER_QUERY)

    def test_silent_repeater_retries_then_relogs(self):
        first = self.s.tick()
        self.assertEqual(len(first), 1)
        for _ in range(xnl.MAX_RETRIES - 1):
            self.clock.t += xnl.RETRY_S
            self.assertEqual(len(self.s.tick()), 1)
        self.clock.t += xnl.RETRY_S
        self.assertEqual(self.s.tick(), [])
        self.assertEqual(self.s.status.state, 'failed')

    def test_never_sends_anything_off_the_list(self):
        run(self.s, self.slr, self.clock, call_up=True)
        for m in self.slr.seen:
            if m.opcode == xnl.DATA_MSG:
                op, arg = struct.unpack('>HB', m.payload[:3])
                self.assertIn((op, arg), xnl.ALLOWED_REQUESTS)


if __name__ == '__main__':
    unittest.main()


class TestIpscGlue(unittest.TestCase):
    """XnlLink inside the real master-mode protocol: registration, 0x70 framing with our
    IPSC ID and the auth digest, RSSI into the translator during a call."""

    def setUp(self):
        import dataclasses, tempfile
        from config import load as load_config
        from tests.test_status import _Transport, _reg
        from tests.test_rssi_burst import _CFG_PATH
        self.rid = 3120000
        self.cfg = dataclasses.replace(load_config(_CFG_PATH), auth_enabled=True,
                                       auth_key=bytes(20), xnl_enabled=True,
                                       xnl_constants=FAKE_K)
        self.rssi, self.call = [], False
        tr = self

        class _Tr:
            def peer_joined(self): pass
            def peer_lost(self): pass
            def check_call_timeouts(self): pass
            def ipsc_voice_received(self, *a): pass
            def ipsc_call_up(self): return tr.call
            def xnl_rssi(self, a, b): tr.rssi.append((a, b))

        from ipsc.protocol import IPSCMasterProtocol
        self.proto = IPSCMasterProtocol(self.cfg, _Tr())
        self.proto._transport = _Transport()
        self.clock = FakeClock()
        self.proto.xnl.session._clock = self.clock
        self.slr = FakeSlr()
        self.addr = ('192.0.2.7', 50000)
        self.proto.datagram_received(self._signed(_reg(self.rid)), self.addr)

    def _signed(self, pkt):
        return pkt + self.proto._auth_suffix(pkt)

    def _pump(self, rounds=12):
        """Tick, hand our 0x70 packets to the fake SLR, feed its replies back."""
        for _ in range(rounds):
            self.proto.xnl._tick()
            sent = [(d, a) for d, a in self.proto._transport.sent if d[0] == 0x70]
            self.proto._transport.sent.clear()
            for data, addr in sent:
                self.assertEqual(addr, self.addr)
                self.assertTrue(self.proto._check_auth(data))
                body = data[:-10]
                self.assertEqual(body[1:5], self.cfg.ipsc_master_id.to_bytes(4, 'big'))
                for reply in self.slr.handle(body[5:]):
                    pkt = bytes([0x70]) + self.rid.to_bytes(4, 'big') + reply
                    self.proto.datagram_received(self._signed(pkt), self.addr)

    def test_xnl_slave_flag_only_with_constants(self):
        self.assertEqual(self.cfg.ipsc_flags_bytes[3] & 0x20, 0)   # set by load(), not replace()

    def test_login_and_rssi_through_ipsc(self):
        self._pump()
        self.assertTrue(self.proto.xnl.session.connected)
        self.assertEqual(self.proto.xnl.status.alias, 'VE7RAG-UHF')
        self.assertEqual(self.rssi, [])
        self.call = True
        self._pump()
        self.assertEqual(len(self.rssi), 1)
        self.assertAlmostEqual(self.rssi[0][1], -108.43, places=2)

    def test_ignores_xnl_from_anyone_else(self):
        from ipsc.xnl import Xnl
        pkt = bytes([0x70]) + (1234567).to_bytes(4, 'big') + MASTER_STATUS
        self.proto.datagram_received(self._signed(pkt), self.addr)
        self.proto.datagram_received(self._signed(bytes([0x70]) + self.rid.to_bytes(4, 'big')
                                                  + MASTER_STATUS), ('198.51.100.1', 5))
        self.assertEqual(self.proto.xnl.session._phase, 'query')

    def test_session_drops_when_repeater_leaves(self):
        self._pump()
        self.assertTrue(self.proto.xnl.session.connected)
        self.proto._remove_peer(self.rid.to_bytes(4, 'big'))
        self.proto.xnl._tick()
        self.assertFalse(self.proto.xnl.session.connected)
        self.assertEqual(self.proto.xnl.status.detail, 'repeater not registered')


class TestConfig(unittest.TestCase):

    def _load(self, extra):
        import tempfile
        from config import load as load_config
        from tests.test_rssi_burst import _CFG_PATH
        with open(_CFG_PATH) as f:
            text = f.read()
        with tempfile.NamedTemporaryFile('w', suffix='.toml', delete=False) as f:
            f.write(text + extra)
        try:
            return load_config(f.name)
        finally:
            os.unlink(f.name)

    def test_off_by_default(self):
        c = self._load('')
        self.assertFalse(c.xnl_enabled)
        self.assertIsNone(c.xnl_constants)
        self.assertEqual(c.ipsc_flags_bytes[3] & 0x20, 0)

    def test_enabled_with_constants_claims_xnl_slave(self):
        c = self._load('\n[xnl]\nenabled = true\nauth_constants = "9e3779b9 1 2 3 4"\n')
        self.assertEqual(c.xnl_constants, FAKE_K)
        self.assertEqual(c.ipsc_flags_bytes[3] & 0x20, 0x20)

    def test_placeholder_constants_leave_it_off(self):
        c = self._load('\n[xnl]\nenabled = true\nauth_constants = "CHANGEME"\n')
        self.assertIsNone(c.xnl_constants)
        self.assertEqual(c.ipsc_flags_bytes[3] & 0x20, 0)
