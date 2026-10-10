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
_ACTIVE = bytes.fromhex('6200049e6d0201')      # TS1 idle, TS2 active
_IDLE   = bytes.fromhex('6200049e6d0202')
# VE7NWR reporting a network call (from our ipsc2hbp, IPSC ID 13027151) on TS1.
_NWR_TS1 = bytes.fromhex('6100049e6c00c6c74f000000050000012e2ef3000bd34f020000')
_NWR_TS1_UP = bytes.fromhex('6200049e6c0102')


class TestCallMon(unittest.TestCase):

    def test_call_start_and_end(self):
        c = callmon.parse_status(_START)
        self.assertEqual((c['status'], c['src'], c['dst'], c['ts'], c['peer'], c['origin']),
                         ('start', 3027083, 103027, 2, 302701, 302701))   # RF call on TS2
        self.assertEqual(callmon.parse_status(_END)['status'], 'end')
        n = callmon.parse_status(_NWR_TS1)
        self.assertEqual((n['ts'], n['src'], n['dst'], n['peer'], n['origin']),
                         (1, 3026675, 3027, 302700, 13027151))           # from the network

    def test_slot_reports(self):
        self.assertEqual(callmon.parse_report(_ACTIVE), {'peer': 302701, 'ts1': 'idle', 'ts2': 'active'})
        self.assertEqual(callmon.parse_report(_NWR_TS1_UP)['ts1'], 'active')
        self.assertEqual(callmon.parse_report(_IDLE), {'peer': 302701, 'ts1': 'idle', 'ts2': 'idle'})

    def test_describe(self):
        self.assertIn('call start  src=3027083  tg=103027  ts=2', callmon.describe(_START))
        self.assertIn('TS1 idle, TS2 idle', callmon.describe(_IDLE))
        # Short or unexpected packets are logged raw, never raise.
        self.assertIn('raw=6100', callmon.describe(_START[:10]))
        self.assertIn('raw=62', callmon.describe(_IDLE[:5]))


if __name__ == '__main__':
    unittest.main()
