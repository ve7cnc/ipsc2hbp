"""
Repeater call monitoring (IPSC 0x61 CALL_MON_STATUS, 0x62 CALL_MON_RPT).

A repeater sends these to a master or peer that advertises the "repeater call
monitoring" service ([ipsc.capabilities] rpt_mon); in a mesh every repeater
reports. Layout from a c-Bridge ↔ VE7RAG capture (an RF call on TS2) and VE7NWR,
Squamish and Whistler reporting a network call on TS1 (2026-10-10), matching
DMRlink's rcm.py (auth digest stripped):

  0x61, 26 bytes — a call event:
    1–4   reporting repeater       5–8   who started the call over IPSC (the
                                         repeater itself for an RF call)
    9–12  call sequence            13    timeslot (0 = TS1, 1 = TS2)
    15    status (0x01 start, 0x02 end)
    16–18 source subscriber        19–21 destination group
    22    call type (0x4f group voice)   23 priority   24 security

  0x62, 7 bytes — slot states after a change:
    1–4   reporting repeater       5     TS1 state   6  TS2 state
    (0x01 active, 0x02 idle; 0x03 disabled, 0x04 re-enabled per DMRlink)
"""

_RPT_STATES = {1: 'active', 2: 'idle', 3: 'disabled', 4: 'reenabled'}
_CALL_STATUS = {1: 'start', 2: 'end'}


def parse_status(data: bytes):
    """0x61 → dict, or None when too short."""
    if len(data) < 26:
        return None
    return {
        'peer': int.from_bytes(data[1:5], 'big'),
        'origin': int.from_bytes(data[5:9], 'big'),
        'seq': int.from_bytes(data[9:13], 'big'),
        'ts': data[13] + 1,
        'status': _CALL_STATUS.get(data[15], f'0x{data[15]:02x}'),
        'src': int.from_bytes(data[16:19], 'big'),
        'dst': int.from_bytes(data[19:22], 'big'),
        'type': data[22],
        'prio': data[23],
        'sec': data[24],
    }


def parse_report(data: bytes):
    """0x62 → dict, or None when too short."""
    if len(data) < 7:
        return None
    st = lambda b: _RPT_STATES.get(b, f'0x{b:02x}')
    return {'peer': int.from_bytes(data[1:5], 'big'), 'ts1': st(data[5]), 'ts2': st(data[6])}


def describe(data: bytes) -> str:
    """One log line for a 0x61 / 0x62 packet; the raw bytes when it does not parse."""
    if data[0] == 0x61:
        c = parse_status(data)
        if c:
            return ('call monitor: call %s  src=%d  tg=%d  ts=%d  peer=%d  origin=%d  seq=%d  '
                    'type=0x%02x' % (c['status'], c['src'], c['dst'], c['ts'], c['peer'],
                                     c['origin'], c['seq'], c['type']))
    elif data[0] == 0x62:
        r = parse_report(data)
        if r:
            return 'call monitor: TS1 %s, TS2 %s  peer=%d' % (r['ts1'], r['ts2'], r['peer'])
    return 'call monitor: 0x%02x len=%d raw=%s' % (data[0], len(data), data.hex())
