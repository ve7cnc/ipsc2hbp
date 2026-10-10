"""
XNL / XCMP over IPSC (opcode 0x70): a read-only status client for one repeater.

This is how a c-Bridge reads an SLR5700's RSSI, radio ID and alias: it logs in to
the repeater's XNL network as a slave device and polls XCMP RadioStatus, once a
second while a call is up (c-Bridge ↔ VE7RAG capture, 2026-10-10). Message
layouts follow that capture and pboyd04/MotoGo (Apache-2.0); names follow
george-hopkins/xcmp-xnl-dissector.

READ-ONLY BY CONSTRUCTION. XCMP can also reprogram, reset or key a radio. This
module only ever builds the requests in ALLOWED_REQUESTS; `xcmp_request` refuses
anything else, and the session never forwards or replays repeater data.

The login answers the repeater's 8-byte challenge with a TEA-style cipher keyed by
Motorola's XNL constants (a delta and four key words). Those are NOT in this
repository: they come from config ([xnl] auth_constants), and without them the
session stays off. `check_constants` verifies a set against a challenge/response
pair recorded from a real login before it is used on a repeater.

Wire format (inside IPSC 0x70 after the 4-byte peer ID; the IPSC auth digest is
handled by the caller):
    0–1  length of the rest            2–3   XNL opcode
    4    protocol (0 XNL, 1 XCMP)      5     flags (data messages: 0–7 rolling)
    6–7  destination XNL address       8–9   source XNL address
    10–11 transaction ID               12–13 payload length     14– payload
"""

import logging
import struct
import time
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger(__name__)

# XNL opcodes
MASTER_STATUS_BRDCST = 0x0002
DEVICE_MASTER_QUERY = 0x0003
DEVICE_AUTH_KEY_REQUEST = 0x0004
DEVICE_AUTH_KEY_REPLY = 0x0005
DEVICE_CONN_REQUEST = 0x0006
DEVICE_CONN_REPLY = 0x0007
DEVICE_SYSMAP_BRDCST = 0x0009
DATA_MSG = 0x000B
DATA_MSG_ACK = 0x000C

PROTO_XNL = 0
PROTO_XCMP = 1

# XCMP opcodes (request; reply = 0x8000 |, broadcast = 0xB000 |)
XCMP_RADIO_STATUS = 0x000E
XCMP_VERSION_INFO = 0x000F
XCMP_DEVICE_INIT_STATUS = 0x0400

# RadioStatus conditions
RS_RSSI = 0x02
RS_MODEL = 0x07
RS_SERIAL = 0x0B
RS_RADIO_ID = 0x0E
RS_ALIAS = 0x0F

# The only XCMP requests this module will build: (opcode, first payload byte).
ALLOWED_REQUESTS = frozenset({
    (XCMP_RADIO_STATUS, RS_RSSI), (XCMP_RADIO_STATUS, RS_MODEL),
    (XCMP_RADIO_STATUS, RS_SERIAL), (XCMP_RADIO_STATUS, RS_RADIO_ID),
    (XCMP_RADIO_STATUS, RS_ALIAS), (XCMP_VERSION_INFO, 0x00),
})

# Connection type the c-Bridge requests (MotoGo uses 0x0a); index 1.
CONN_TYPE = 0x0B
CONN_INDEX = 0x01

RETRY_S = 3.0          # resend an unanswered login step / data message after this
MAX_RETRIES = 3        # then start the login again
RELOGIN_BACKOFF_S = 30.0
RSSI_INTERVAL_S = 1.0  # while a call is up, as the c-Bridge does


# ---------------------------------------------------------------------- framing

@dataclass
class Xnl:
    opcode: int
    proto: int = PROTO_XNL
    flags: int = 0
    dst: int = 0
    src: int = 0
    tid: int = 0
    payload: bytes = b''

    def encode(self) -> bytes:
        body = struct.pack('>HBBHHHH', self.opcode, self.proto, self.flags, self.dst,
                           self.src, self.tid, len(self.payload)) + self.payload
        return struct.pack('>H', len(body)) + body

    @classmethod
    def decode(cls, data: bytes) -> Optional['Xnl']:
        if len(data) < 14:
            return None
        n, op, proto, flags, dst, src, tid, plen = struct.unpack('>HHBBHHHH', data[:14])
        payload = data[14:14 + plen]
        if n != len(data) - 2 or len(payload) != plen:
            return None
        return cls(op, proto, flags, dst, src, tid, payload)


def xcmp_request(opcode: int, arg: int) -> bytes:
    """An XCMP request payload, refused unless it is a known read-only query."""
    if (opcode, arg) not in ALLOWED_REQUESTS:
        raise ValueError(f'XCMP request 0x{opcode:04x}/0x{arg:02x} is not on the read-only list')
    return struct.pack('>HB', opcode, arg)


def q88_dbm(raw: int) -> float:
    """XCMP RSSI: dB below 0 dBm × 256 (0x6c6e → -108.43)."""
    return -raw / 256


def decode_rssi(value: bytes):
    """RadioStatus RSSI value → (slot1 dBm, slot2 dBm), or None."""
    if len(value) < 4:
        return None
    s1, s2 = struct.unpack('>HH', value[:4])
    return q88_dbm(s1), q88_dbm(s2)


def decode_text(value: bytes) -> str:
    """UTF-16BE, NUL-terminated (the alias: 'VE7RAG-UHF')."""
    if len(value) % 2:
        value = value[:-1]
    return value.decode('utf-16-be', errors='replace').split('\x00', 1)[0]


# ---------------------------------------------------------------------- cipher

def parse_constants(text: str):
    """'delta k0 k1 k2 k3' as five 32-bit hex words → tuple, or None if malformed."""
    words = text.replace(',', ' ').split()
    if len(words) != 5:
        return None
    try:
        vals = tuple(int(w, 16) for w in words)
    except ValueError:
        return None
    return vals if all(0 <= v <= 0xFFFFFFFF for v in vals) else None


def encrypt(challenge: bytes, constants) -> bytes:
    """Answer an 8-byte XNL challenge (TEA-style, 32 rounds; see MotoGo encrypter.go)."""
    delta, k0, k1, k2, k3 = constants
    v0, v1 = struct.unpack('>II', challenge[:8])
    total = 0
    m = 0xFFFFFFFF
    for _ in range(32):
        total = (total + delta) & m
        v0 = (v0 + ((((v1 << 4) & m) + k0) ^ (v1 + total) ^ ((v1 >> 5) + k1))) & m
        v1 = (v1 + ((((v0 << 4) & m) + k2) ^ (v0 + total) ^ ((v0 >> 5) + k3))) & m
    return struct.pack('>II', v0, v1)


def check_constants(constants, challenge: bytes, response: bytes) -> bool:
    return encrypt(challenge, constants) == response


# ---------------------------------------------------------------------- session

@dataclass
class Status:
    """What the session has learned; written to the status file."""
    state: str = 'off'               # off, connecting, connected, failed
    detail: str = ''
    radio_id: Optional[int] = None
    alias: Optional[str] = None
    model: Optional[str] = None
    serial: Optional[str] = None
    version: Optional[str] = None
    rssi: Optional[tuple] = None     # (slot1, slot2) dBm, latest
    rssi_at: Optional[float] = None
    connected_since: Optional[float] = None
    logins: int = 0

    def as_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v is not None}


@dataclass
class _Pending:
    msg: Xnl
    sent: float
    tries: int = 1


class XnlSession:
    """Sans-IO XNL slave session. Feed it the repeater's XNL bytes with `received`,
    call `tick` regularly; both return XNL messages (bytes) to send to the repeater.
    `on_rssi(slot1_dbm, slot2_dbm)` is called for each RSSI reply."""

    def __init__(self, constants, on_rssi=None, clock=time.monotonic):
        self._k = constants
        self._on_rssi = on_rssi
        self._clock = clock
        self.status = Status(state='off' if constants is None else 'connecting',
                             detail='no auth_constants' if constants is None else '')
        self._reset()

    # -- state

    def _reset(self):
        self._phase = 'query'          # query → auth → connect → up
        self._master = 0               # repeater's XNL address
        self._me = 0                   # address the repeater assigned us
        self._tid_base = 0
        self._tid = 0
        self._flag = 0
        self._step: Optional[_Pending] = None      # outstanding login message
        self._data: dict[int, _Pending] = {}       # outstanding data messages by tid
        self._last_rssi_ask = 0.0
        self._asked_identity = False
        self._next_login = 0.0

    def _fail(self, why: str):
        log.warning('XNL: %s — logging in again in %.0f s', why, RELOGIN_BACKOFF_S)
        self.status.state, self.status.detail = 'failed', why
        self.status.connected_since = None
        self._reset()
        self._next_login = self._clock() + RELOGIN_BACKOFF_S

    @property
    def connected(self) -> bool:
        return self._phase == 'up'

    # -- outgoing

    def _send_step(self, msg: Xnl) -> list:
        self._step = _Pending(msg, self._clock())
        return [msg.encode()]

    def _send_data(self, payload: bytes) -> list:
        tid = (self._tid_base << 8) | (self._tid & 0xFF)
        self._tid = (self._tid + 1) & 0xFF
        msg = Xnl(DATA_MSG, PROTO_XCMP, self._flag, self._master, self._me, tid, payload)
        self._flag = (self._flag + 1) % 8
        self._data[tid] = _Pending(msg, self._clock())
        return [msg.encode()]

    def ask(self, opcode: int, arg: int) -> list:
        if not self.connected:
            return []
        return self._send_data(xcmp_request(opcode, arg))

    def tick(self, call_up: bool = False) -> list:
        """Retries, the login, and RSSI polls while `call_up`."""
        if self._k is None:
            return []
        now = self._clock()
        out: list = []
        if self._phase == 'query' and self._step is None:
            if now < self._next_login:
                return []
            self.status.state = 'connecting'
            return self._send_step(Xnl(DEVICE_MASTER_QUERY))
        if self._step is not None and now - self._step.sent >= RETRY_S:
            if self._step.tries >= MAX_RETRIES:
                self._fail(f'no answer in phase {self._phase}')
                return []
            self._step.tries += 1
            self._step.sent = now
            out.append(self._step.msg.encode())
        for tid, p in list(self._data.items()):
            if now - p.sent >= RETRY_S:
                if p.tries >= MAX_RETRIES:
                    self._fail('XCMP request not acknowledged')
                    return []
                p.tries += 1
                p.sent = now
                out.append(p.msg.encode())
        if self.connected:
            if not self._asked_identity:
                self._asked_identity = True
                for arg in (RS_RADIO_ID, RS_ALIAS, RS_MODEL, RS_SERIAL):
                    out += self.ask(XCMP_RADIO_STATUS, arg)
                out += self.ask(XCMP_VERSION_INFO, 0x00)
            if call_up and now - self._last_rssi_ask >= RSSI_INTERVAL_S \
                    and not any(p.msg.payload[:3] == xcmp_request(XCMP_RADIO_STATUS, RS_RSSI)
                                for p in self._data.values()):
                self._last_rssi_ask = now
                out += self.ask(XCMP_RADIO_STATUS, RS_RSSI)
        return out

    # -- incoming

    def received(self, data: bytes) -> list:
        if self._k is None:
            return []
        m = Xnl.decode(data)
        if m is None:
            log.debug('XNL: malformed %s', data.hex())
            return []
        op = m.opcode
        if op == MASTER_STATUS_BRDCST and self._phase == 'query':
            self._master = m.src
            self._phase = 'auth'
            return self._send_step(Xnl(DEVICE_AUTH_KEY_REQUEST, dst=self._master))
        if op == DEVICE_AUTH_KEY_REPLY and self._phase == 'auth' and len(m.payload) >= 10:
            temp = struct.unpack('>H', m.payload[:2])[0]
            answer = encrypt(m.payload[2:10], self._k)
            self._phase = 'connect'
            return self._send_step(Xnl(DEVICE_CONN_REQUEST, dst=self._master, src=temp,
                                       payload=struct.pack('>HBB', 0, CONN_TYPE, CONN_INDEX)
                                       + answer))
        if op == DEVICE_CONN_REPLY and self._phase == 'connect':
            self._step = None
            if len(m.payload) < 4 or m.payload[0] != 0x01:
                self._fail('login refused (wrong auth_constants?)')
                return []
            self._tid_base = m.payload[1]
            self._me = struct.unpack('>H', m.payload[2:4])[0]
            self._phase = 'up'
            self.status.state, self.status.detail = 'connected', ''
            self.status.connected_since = time.time()
            self.status.logins += 1
            log.info('XNL: logged in to repeater (XNL 0x%04x), we are 0x%04x',
                     self._master, self._me)
            return []
        if op == DATA_MSG_ACK:
            self._data.pop(m.tid, None)
            return []
        if op == DATA_MSG:
            ack = Xnl(DATA_MSG_ACK, m.proto, m.flags, m.src, self._me, m.tid).encode()
            if m.dst not in (0, self._me):
                return []
            if m.proto == PROTO_XCMP:
                self._xcmp(m)
            return [ack]
        # DEVICE_SYSMAP_BRDCST and anything else: nothing to do.
        return []

    def _xcmp(self, m: Xnl):
        p = m.payload
        if len(p) < 2:
            return
        op = struct.unpack('>H', p[:2])[0]
        self._data.pop(m.tid, None)          # a reply also settles its request
        if op == 0x8000 | XCMP_RADIO_STATUS and len(p) >= 4:
            result, cond, value = p[2], p[3], p[4:]
            if result != 0:
                log.debug('XNL: RadioStatus 0x%02x refused (0x%02x)', cond, result)
                return
            if cond == RS_RSSI:
                r = decode_rssi(value)
                if r:
                    self.status.rssi, self.status.rssi_at = r, time.time()
                    if self._on_rssi:
                        self._on_rssi(*r)
            elif cond == RS_RADIO_ID and len(value) >= 4:
                self.status.radio_id = int.from_bytes(value[:4], 'big')
            elif cond == RS_ALIAS:
                self.status.alias = decode_text(value)
            elif cond == RS_MODEL:
                self.status.model = value.decode('ascii', errors='replace').strip('\x00 ')
            elif cond == RS_SERIAL:
                self.status.serial = value.decode('ascii', errors='replace').strip('\x00 ')
        elif op == 0x8000 | XCMP_VERSION_INFO and len(p) >= 3:
            if p[2] == 0:
                self.status.version = p[3:].decode('ascii', errors='replace').strip('\x00 ')
        elif op == 0xB000 | XCMP_DEVICE_INIT_STATUS:
            pass                                  # the repeater announcing itself


# ---------------------------------------------------------------------- IPSC glue

class XnlLink:
    """One repeater's XNL session over the IPSC socket. `send(packet, host, port)` is
    the protocol's authenticated send; `target()` gives the repeater's (host, port)
    while it is registered, else None; `translator` takes the RSSI and says whether
    a call from the repeater is up."""

    TICK_S = 0.25

    def __init__(self, cfg, translator, send, target):
        self._cfg = cfg
        self._translator = translator
        self._send = send
        self._target = target
        self._our_id = cfg.ipsc_master_id.to_bytes(4, 'big')
        self._repeater = cfg.hbp_repeater_id.to_bytes(4, 'big')
        self.session = XnlSession(cfg.xnl_constants, on_rssi=translator.xnl_rssi)
        self._task = None

    @property
    def status(self) -> Status:
        return self.session.status

    def received(self, data: bytes, host: str) -> None:
        """An IPSC 0x70 packet (auth digest already stripped)."""
        t = self._target()
        if t is None or host != t[0] or data[1:5] != self._repeater:
            log.debug('XNL from %s (id %d) — not our repeater, ignored',
                      host, int.from_bytes(data[1:5], 'big'))
            return
        self._out(self.session.received(data[5:]), t)

    def _out(self, msgs, t) -> None:
        for m in msgs:
            self._send(bytes([0x70]) + self._our_id + m, t[0], t[1])

    def _tick(self) -> None:
        t = self._target()
        if t is None:
            if self.session.status.state == 'connected' or self.session._step is not None:
                log.info('XNL: repeater not registered — session dropped')
                self.session._reset()
                self.session.status.state, self.session.status.detail = 'connecting', 'repeater not registered'
                self.session.status.connected_since = None
            return
        self._out(self.session.tick(self._translator.ipsc_call_up()), t)

    async def _loop(self):
        import asyncio
        while True:
            try:
                self._tick()
            except Exception:                       # never take the voice path down
                log.exception('XNL tick failed')
            await asyncio.sleep(self.TICK_S)

    def start(self, loop) -> None:
        if self._task is None and self._cfg.xnl_constants is not None:
            self._task = loop.create_task(self._loop())

    def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
