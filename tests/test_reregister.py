#!/usr/bin/env python3
"""
Peer mode: losing the master and getting it back.

VE7NWR, 2026-10-12 03:16: three keepalives went unanswered, so we dropped the link
and sent MASTER_REG_REQ. Nine seconds later, before any MASTER_REG_REPLY, the
repeater sent one of its unprompted PEER_LIST_REPLYs. We took that for a
registration: state ACTIVE, no more retries, keepalives answered every 5 s. But we
never connected, so voice was dropped both ways for 17 hours.

Run with:
    python -m unittest tests.test_reregister -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ipsc.const import MASTER_ALIVE_REPLY, MASTER_ALIVE_REQ, MASTER_REG_REQ, PEER_LIST_REPLY
from tests import test_status


class TestReRegistration(test_status._TmpDir):

    MASTER_IP, MASTER_RID, SLAVES = '203.0.113.1', 302700, (302025, 302394)
    _peer = test_status.TestPeerMode._peer
    _register = test_status.TestPeerMode._register

    def _sent(self, proto):
        ops = [d[0] for d, addr in proto._transport.sent if addr[0] == self.MASTER_IP]
        proto._transport.sent.clear()
        return ops

    def _from_master(self, proto, opcode, body=b''):
        proto.datagram_received(bytes([opcode]) + self.MASTER_RID.to_bytes(4, 'big') + body,
                                (self.MASTER_IP, 50000))

    def _unprompted_peer_list(self, proto):
        self._from_master(proto, PEER_LIST_REPLY, b'\x00\x00')

    def _lose(self, proto):
        """Registered, then keepalives go unanswered until we re-register."""
        self._register(proto)
        self._sent(proto)
        for _ in range(proto._cfg.keepalive_missed_max + 1):
            proto._tick()
        self.assertEqual(self._sent(proto)[-1], MASTER_REG_REQ)
        self.assertFalse(proto._registered())

    def test_an_unprompted_peer_list_is_no_registration(self):
        proto = self._peer()
        self._lose(proto)
        self._unprompted_peer_list(proto)
        self.assertEqual(proto._state, proto._REGISTERING)
        for _ in range(proto._cfg.keepalive_missed_max):
            proto._tick()
        ops = self._sent(proto)
        self.assertIn(MASTER_REG_REQ, ops)          # still retrying
        self.assertNotIn(MASTER_ALIVE_REQ, ops)     # not keepaliving an unregistered link
        self.assertEqual(self.read()['peers'][0]['state'], 'not_connected')
        # The master's reply brings it all back: connected, HBP side re-joined.
        self._register(proto)
        self.assertTrue(proto._registered())
        self.assertEqual(proto._translator.events, ['joined', 'lost', 'joined'])
        self.assertEqual(self.read()['peers'][0]['state'], 'connected')

    def test_a_late_keepalive_reply_does_not_hold_off_the_retry(self):
        proto = self._peer()
        self._lose(proto)
        for _ in range(proto._cfg.keepalive_missed_max):
            self._from_master(proto, MASTER_ALIVE_REPLY)
            proto._tick()
        self.assertIn(MASTER_REG_REQ, self._sent(proto))

    def test_a_keepalive_session_without_a_registration_re_registers(self):
        proto = self._peer()
        self._lose(proto)
        proto._state = proto._ACTIVE                # however it got there
        proto._tick()
        self.assertEqual(self._sent(proto), [MASTER_REG_REQ])
        self.assertEqual(proto._state, proto._REGISTERING)

    def test_a_peer_list_after_registration_still_activates(self):
        proto = self._peer()
        self._register(proto)
        self.assertEqual(proto._state, proto._ACTIVE)
        self.assertEqual(len(proto._mesh), len(self.SLAVES))


if __name__ == '__main__':
    unittest.main()
