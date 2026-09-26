#!/usr/bin/env python3
"""
Unit tests for per-call packet loss (repeater -> us), measured from the
repeater's IPSC RTP sequence numbers and carried in the DMRD BER byte as
1 + 10 x percent (0 = not measured).

Run with:
    python -m unittest tests.test_loss -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ipsc.const import VOICE_HEAD, VOICE_TERM, SLOT2_VOICE
from tests.test_rssi_burst import _ipsc_gv, _MockIPSC, _MockHBP, _CFG_PATH
from config import load as load_config
from translate.translator import CallTranslator


def _with_seq(pkt: bytes, seq: int) -> bytes:
    return pkt[:20] + (seq & 0xFFFF).to_bytes(2, 'big') + pkt[22:]


class TestLoss(unittest.TestCase):

    def setUp(self):
        self.tr  = CallTranslator(load_config(_CFG_PATH))
        self.hbp = _MockHBP()
        self.tr.set_protocols(_MockIPSC(), self.hbp)

    def _send(self, bt, seq):
        self.tr.ipsc_voice_received(_with_seq(_ipsc_gv(bt), seq), 2, bt)

    def _code(self):
        return self.hbp.sent[-1][53]

    def test_no_loss(self):
        self._send(VOICE_HEAD, 100)
        for s in range(101, 111):
            self._send(SLOT2_VOICE, s)
        self._send(VOICE_TERM, 111)
        self.assertEqual(self._code(), 1)          # measured, 0.0 %

    def test_one_lost(self):
        self._send(VOICE_HEAD, 100)
        for s in range(101, 111):
            if s != 105:
                self._send(SLOT2_VOICE, s)
        # 10 of 11 packets (100..110): 9.1 % -> 1 + 91
        self.assertEqual(self._code(), 92)

    def test_wraparound(self):
        self._send(VOICE_HEAD, 65533)
        for s in (65534, 65535, 0, 1, 2):
            self._send(SLOT2_VOICE, s)
        self.assertEqual(self._code(), 1)

    def test_duplicate_ignored(self):
        self._send(VOICE_HEAD, 10)
        self._send(SLOT2_VOICE, 11)
        self._send(SLOT2_VOICE, 11)
        self._send(SLOT2_VOICE, 12)
        self.assertEqual(self._code(), 1)

    def test_new_call_resets(self):
        self._send(VOICE_HEAD, 100)
        self._send(SLOT2_VOICE, 110)               # 9 lost
        self._send(VOICE_TERM, 111)
        self._send(VOICE_HEAD, 5000)               # new call
        self._send(SLOT2_VOICE, 5001)
        self.assertEqual(self._code(), 1)


if __name__ == '__main__':
    unittest.main()
