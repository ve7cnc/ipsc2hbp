#!/usr/bin/env python3
"""
Unit tests for the IPSC in-call RSSI report (burst type 0x24, VOICE_RSSI).

XPR8400 repeaters send one every third superframe in place of voice burst F:
it takes that burst's RTP timestamp slot and no burst-F voice packet is sent.
Dropping it left a 60 ms hole every 1.08 s (~5.6% loss downstream).

Run with:
    python -m unittest tests.test_rssi_burst -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import load as load_config
from ipsc.const import GROUP_VOICE, VOICE_HEAD, VOICE_TERM, SLOT2_VOICE, VOICE_RSSI, TS_CALL_MSK
from hbp.const import HBPF_FRAMETYPE_VOICE, HBPF_FRAMETYPE_VOICESYNC, HBPF_FRAMETYPE_MASK, HBPF_DTYPE_MASK
from translate.translator import CallTranslator

_CFG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test.toml')

# A real VOICE_RSSI packet from an XPR8400 (TS2, auth digest stripped).
# Bytes 38–39 = 0x267c = 9852 → -98.52 dBm.
_RSSI_PKT = bytes.fromhex(
    '8000049e7f172e308b019273020000223720805d0cf746be34420000000024c00003c0000000267c')
# The synthetic bursts below carry RTP timestamp 0; zero the captured one to match,
# or the translator (correctly) reads the jump as a new call.
_RSSI_PKT = _RSSI_PKT[:22] + b'\x00' * 4 + _RSSI_PKT[26:]

_SRC_SUB   = _RSSI_PKT[6:9]
_DST_GROUP = _RSSI_PKT[9:12]


class _MockIPSC:
    def has_peers(self):
        return True
    def send_voice(self, pkt):
        pass


class _MockHBP:
    def __init__(self):
        self.sent = []
    def is_connected(self):
        return True
    def send_dmrd(self, dmrd):
        self.sent.append(bytes(dmrd))
    def activate(self):
        pass
    def deactivate(self):
        pass


def _ipsc_gv(burst_type: int, ambe_fill: int = 0) -> bytes:
    """TS2 GROUP_VOICE packet; AMBE bytes 33–51 filled with `ambe_fill`."""
    call_info = TS_CALL_MSK if burst_type in (VOICE_HEAD, VOICE_TERM) else 0x00
    hdr = (
        bytes([GROUP_VOICE]) + b'\x00\x30\x12\x00' + b'\x01'
        + _SRC_SUB + _DST_GROUP + b'\x02' + b'\x00\x00\x43\xe2'
        + bytes([call_info]) + b'\x00' * 12 + bytes([burst_type]) + b'\x00\x00'
    )
    return hdr + bytes([ambe_fill]) * 19


def _voice_bits(dmrd: bytes) -> bytes:
    """The AMBE-bearing bits of a DMRD voice payload (EMBED/SYNC field removed)."""
    payload = int.from_bytes(dmrd[20:53], 'big')
    bits = format(payload, '0264b')
    return (bits[:108] + bits[156:]).encode()


class TestVoiceRssi(unittest.TestCase):

    def setUp(self):
        self.tr  = CallTranslator(load_config(_CFG_PATH))
        self.hbp = _MockHBP()
        self.tr.set_protocols(_MockIPSC(), self.hbp)

    def _start_call_through_e(self):
        """VOICE_HEAD then bursts A–E, each with distinct AMBE."""
        self.tr.ipsc_voice_received(_ipsc_gv(VOICE_HEAD), 2, VOICE_HEAD)
        for i in range(5):
            self.tr.ipsc_voice_received(_ipsc_gv(SLOT2_VOICE, 0x11 * (i + 1)), 2, SLOT2_VOICE)

    def test_rssi_fills_burst_f(self):
        self._start_call_through_e()
        self.assertEqual(len(self.hbp.sent), 6)
        self.tr.ipsc_voice_received(_RSSI_PKT, 2, VOICE_RSSI)

        self.assertEqual(len(self.hbp.sent), 7, 'VOICE_RSSI slot must produce a DMRD burst')
        f = self.hbp.sent[-1]
        self.assertEqual(f[15] & HBPF_FRAMETYPE_MASK, HBPF_FRAMETYPE_VOICE)
        self.assertEqual(f[15] & HBPF_DTYPE_MASK, 5, 'filler must sit at superframe position F')
        self.assertEqual(_voice_bits(f), _voice_bits(self.hbp.sent[-2]),
                         'filler repeats the previous burst\'s AMBE')

        # The next real burst starts a new superframe at A.
        self.tr.ipsc_voice_received(_ipsc_gv(SLOT2_VOICE, 0x77), 2, SLOT2_VOICE)
        self.assertEqual(self.hbp.sent[-1][15] & HBPF_FRAMETYPE_MASK, HBPF_FRAMETYPE_VOICESYNC)

    def test_rssi_byte_in_dmrd(self):
        self._start_call_through_e()
        self.assertEqual(self.hbp.sent[-1][54], 0, 'no RSSI before the first report')
        self.tr.ipsc_voice_received(_RSSI_PKT, 2, VOICE_RSSI)
        self.assertEqual(self.hbp.sent[-1][54], 99)   # -98.52 dBm
        self.tr.ipsc_voice_received(_ipsc_gv(SLOT2_VOICE), 2, SLOT2_VOICE)
        self.assertEqual(self.hbp.sent[-1][54], 99, 'latest reading carries forward')

    def test_rssi_without_call_is_ignored(self):
        self.tr.ipsc_voice_received(_RSSI_PKT, 2, VOICE_RSSI)
        self.assertEqual(self.hbp.sent, [])

    def test_call_end_logs_rssi_and_resets(self):
        self._start_call_through_e()
        self.tr.ipsc_voice_received(_RSSI_PKT, 2, VOICE_RSSI)
        with self.assertLogs('translate.translator', level='INFO') as cm:
            self.tr.ipsc_voice_received(_ipsc_gv(VOICE_TERM), 2, VOICE_TERM)
        self.assertTrue(any('rssi=-98.5 dBm' in m for m in cm.output), cm.output)

        # A new call starts with no RSSI carried over.
        self.tr.ipsc_voice_received(_ipsc_gv(VOICE_HEAD), 2, VOICE_HEAD)
        self.tr.ipsc_voice_received(_ipsc_gv(SLOT2_VOICE), 2, SLOT2_VOICE)
        self.assertEqual(self.hbp.sent[-1][54], 0)


if __name__ == '__main__':
    unittest.main()
