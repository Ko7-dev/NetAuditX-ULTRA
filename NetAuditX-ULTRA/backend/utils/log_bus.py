"""In-process pub/sub for streaming log records to SSE subscribers.

A `logging.Handler` (installed in :mod:`backend.utils.logger`) pushes each
formatted log line into the bus. Any number of asyncio consumers can subscribe
via :func:`subscribe`; they receive new lines on their queue. A bounded ring
buffer of recent lines is also kept so new subscribers immediately get
historical context.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from collections import deque
from typing import AsyncIterator


_MAX_RING = 500


class LogBus:
    def __init__(self, max_ring: int = _MAX_RING) -> None:
        self._ring: deque[dict] = deque(maxlen=max_ring)
        self._subscribers: set[asyncio.Queue[dict]] = set()
        self._lock = threading.Lock()
        # The asyncio loop where subscribers live (set on first subscribe).
        self._loop: asyncio.AbstractEventLoop | None = None

    # -- producer side (called from sync logging.Handler) ------------------

    def publish(self, record: dict) -> None:
        with self._lock:
            self._ring.append(record)
            subs = list(self._subscribers)
            loop = self._loop
        if not subs or loop is None or loop.is_closed():
            return
        for q in subs:
            try:
                loop.call_soon_threadsafe(q.put_nowait, record)
            except RuntimeError:
                # Loop is shutting down — silently drop.
                pass

    # -- consumer side ------------------------------------------------------

    def recent(self, limit: int = 100) -> list[dict]:
        with self._lock:
            items = list(self._ring)
        return items[-limit:]

    def subscribe(self) -> asyncio.Queue[dict]:
        q: asyncio.Queue[dict] = asyncio.Queue(maxsize=1000)
        with self._lock:
            self._subscribers.add(q)
            if self._loop is None:
                try:
                    self._loop = asyncio.get_running_loop()
                except RuntimeError:
                    self._loop = None
        return q

    def unsubscribe(self, q: asyncio.Queue[dict]) -> None:
        with self._lock:
            self._subscribers.discard(q)

    async def stream(self, replay: int = 50) -> AsyncIterator[dict]:
        """Yield historical records (replay) and then live ones forever."""
        for record in self.recent(replay):
            yield record
        q = self.subscribe()
        try:
            while True:
                try:
                    record = await asyncio.wait_for(q.get(), timeout=15)
                    yield record
                except asyncio.TimeoutError:
                    yield {"keepalive": True, "ts": time.time()}
        finally:
            self.unsubscribe(q)


bus = LogBus()


class BusHandler(logging.Handler):
    """Logging handler that pushes formatted records into the bus."""

    def emit(self, record: logging.LogRecord) -> None:  # noqa: D401 (logging API)
        try:
            msg = self.format(record)
            bus.publish(
                {
                    "ts": record.created,
                    "level": record.levelname,
                    "name": record.name,
                    "message": msg,
                }
            )
        except Exception:
            self.handleError(record)
