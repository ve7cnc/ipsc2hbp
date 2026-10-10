#!/usr/bin/env python3
"""
Repeater call monitoring packets (0x61 / 0x62), from a c-Bridge ↔ SLR5700
(VE7RAG) capture on 2026-10-10, auth digest stripped.

Run with:
    python -m unittest tests.test_callmon -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ipsc import callmon

_START = bytes.fromhex('6100049e6d00049e6d000000300100012e308b0192734f020010')
_END   = bytes.fromhex('6100049e6d00049e6d000000300100022e308b0192734f020010')
_ACTIVE = bytes.fromhex('6200049e6d0201')
_IDLE   = bytes.fromhex('6200049e6d0202')


class TestCallMon(unittest.TestCase):

    def test_call_start_and_end(self):
        c = callmon.parse_status(_START)
        self.assertEqual((c['status'], c['src'], c['dst'], c['ts'], c['repeater']),
                         ('start', 3027083, 103027, 2, 302701))
        self.assertEqual(callmon.parse_status(_END)['status'], 'end')

    def test_slot_reports(self):
        self.assertEqual(callmon.parse_report(_ACTIVE), {'peer': 302701, 'ts': 2, 'state': 'active'})
        self.assertEqual(callmon.parse_report(_IDLE)['state'], 'idle')

    def test_describe(self):
        self.assertIn('call start  src=3027083  tg=103027  ts=2', callmon.describe(_START))
        self.assertIn('ts=2 idle', callmon.describe(_IDLE))
        # Short or unexpected packets are logged raw, never raise.
        self.assertIn('raw=6100', callmon.describe(_START[:10]))
        self.assertIn('raw=62', callmon.describe(_IDLE[:5]))


if __name__ == '__main__':
    unittest.main()
