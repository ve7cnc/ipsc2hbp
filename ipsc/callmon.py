"""
Repeater call monitoring (IPSC 0x61 CALL_MON_STATUS, 0x62 CALL_MON_RPT).

A repeater sends these only to a master that advertises the "repeater call
monitoring" service ([ipsc.capabilities] rpt_mon). Layout from a c-Bridge ↔
SLR5700 capture (2026-10-10, auth digest stripped):

  0x61, 26 bytes — a call event:
    1–4   sending peer ID          5–8   repeater ID
    12    call sequence number     15    status (0x01 start, 0x02 end)
    16–18 source subscriber        19–21 destination group
    22    call type (0x4f seen on group voice)
    23    timeslot (1 or 2)        24–25 flags (0x0010 / 0x0000 seen)

  0x62, 7 bytes — a timeslot changed state:
    1–4   sending peer ID          5     timeslot
    6     state (0x01 active, 0x02 idle; 0x03 disabled, 0x04 re-enabled per DMRlink)

Only seen on group voice calls on TS2 so far; the timeslot offsets are the
fields that matched the 0x62 report sent alongside.
"""

_RPT_STATES = {1: 'active', 2: 'idle', 3: 'disabled', 4: 'reenabled'}
_CALL_STATUS = {1: 'start', 2: 'end'}


def parse_status(data: bytes):
    """0x61 → dict, or None when too short."""
    if len(data) < 26:
        return None
    return {
        'peer': int.from_bytes(data[1:5], 'big'),
        'repeater': int.from_bytes(data[5:9], 'big'),
        'seq': data[12],
        'status': _CALL_STATUS.get(data[15], f'0x{data[15]:02x}'),
        'src': int.from_bytes(data[16:19], 'big'),
        'dst': int.from_bytes(data[19:22], 'big'),
        'type': data[22],
        'ts': data[23],
        'flags': int.from_bytes(data[24:26], 'big'),
    }


def parse_report(data: bytes):
    """0x62 → dict, or None when too short."""
    if len(data) < 7:
        return None
    return {
        'peer': int.from_bytes(data[1:5], 'big'),
        'ts': data[5],
        'state': _RPT_STATES.get(data[6], f'0x{data[6]:02x}'),
    }


def describe(data: bytes) -> str:
    """One log line for a 0x61 / 0x62 packet; the raw bytes when it does not parse."""
    if data[0] == 0x61:
        c = parse_status(data)
        if c:
            return ('call monitor: call %s  src=%d  tg=%d  ts=%d  seq=0x%02x  type=0x%02x  '
                    'flags=0x%04x  repeater=%d' % (c['status'], c['src'], c['dst'], c['ts'],
                                                   c['seq'], c['type'], c['flags'], c['repeater']))
    elif data[0] == 0x62:
        r = parse_report(data)
        if r:
            return 'call monitor: ts=%d %s  peer=%d' % (r['ts'], r['state'], r['peer'])
    return 'call monitor: 0x%02x len=%d raw=%s' % (data[0], len(data), data.hex())
