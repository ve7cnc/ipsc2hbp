"""
Peer status file — who is in this IPSC, and whether each is answering.

ipsc2hbp already tracks every IPSC peer with keepalive state (the master's `_peers`,
the peer stack's master link and `_mesh`), but only the log ever saw it. With
`status_file` set ([global]), StatusWriter writes that table as JSON:

- every `status_interval` seconds, and at once when the protocol reports a change
  (a peer registered, re-registered, de-registered, timed out, connected, went quiet);
- atomically: a temp file in the same directory, then rename, so a reader never sees
  half a file, and a crashed writer leaves the last good snapshot.

What it holds is deliberately small:

- **no IP addresses** — `ip_present` only. The monitor strips repeater addresses at the
  site before anything leaves it; this file must not be the hole in that rule;
- **`state` decided here**, from the same keepalive rules the protocol acts on
  (master mode: `keepalive_watchdog`; peer mode: `keepalive_missed_max`), so nothing
  downstream re-derives "connected" and disagrees during an incident;
- **no per-call attribution**: the voice path's source lock latches onto whichever
  duplicate copy arrives first, so "who was this call heard on" would be usually right,
  not reliably right.

`status_file` empty (the default): no writer exists, nothing is written, and the
protocols' change hook is never set — behaviour is upstream's, byte for byte.
"""

import asyncio
import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from time import time

log = logging.getLogger(__name__)


def iso(ts):
    """Epoch seconds -> RFC 3339 UTC, or None."""
    if not ts:
        return None
    return datetime.fromtimestamp(ts, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


class StatusWriter:

    def __init__(self, cfg, proto):
        self._cfg = cfg
        self._proto = proto
        self._path = cfg.status_file
        self._interval = max(1, int(cfg.status_interval))
        self._task = None
        self._failing = False
        proto.on_status_change = self.write

    def snapshot(self) -> dict:
        return {
            'emitted_at': iso(time()),
            'mode': self._cfg.ipsc_mode,
            'ipsc_id': self._cfg.ipsc_master_id,          # our own IPSC ID, either mode
            'hbp_repeater_id': self._cfg.hbp_repeater_id,
            'interval': self._interval,
            'peers': self._proto.status_peers(),
        }

    def write(self) -> None:
        """Write the snapshot now. Never raises: a status file is not worth a translator."""
        try:
            data = json.dumps(self.snapshot(), indent=1, sort_keys=True) + '\n'
            directory = os.path.dirname(os.path.abspath(self._path))
            os.makedirs(directory, exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix='.status-', dir=directory)
            try:
                with os.fdopen(fd, 'w') as fh:
                    fh.write(data)
                os.chmod(tmp, 0o644)
                os.replace(tmp, self._path)
            except BaseException:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
            if self._failing:
                log.info('status file %s written again', self._path)
                self._failing = False
        except Exception as exc:
            if not self._failing:                         # once, not every tick
                log.warning('status file %s: %s', self._path, exc)
                self._failing = True

    async def _loop(self):
        while True:
            self.write()
            await asyncio.sleep(self._interval)

    def start(self, loop) -> None:
        log.info('status file %s, every %ds', self._path, self._interval)
        self._task = loop.create_task(self._loop())

    def stop(self) -> None:
        if self._task:
            self._task.cancel()
