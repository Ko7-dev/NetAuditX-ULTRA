"""Live log streaming routes (SSE) and recent-log fetch."""

from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse

from backend.utils.log_bus import bus

router = APIRouter(tags=["logs"])


@router.get("/logs/recent")
def recent_logs(limit: int = Query(default=200, ge=1, le=1000)) -> dict:
    return {"items": bus.recent(limit)}


def _sse_event(data: dict) -> bytes:
    return f"data: {json.dumps(data, default=str)}\n\n".encode("utf-8")


@router.get("/logs/stream")
async def stream_logs(replay: int = Query(default=80, ge=0, le=500)):
    async def event_source():
        # Replay buffered records.
        for record in bus.recent(replay):
            yield _sse_event(record)
        q = bus.subscribe()
        try:
            yield b": connected\n\n"
            while True:
                try:
                    record = await asyncio.wait_for(q.get(), timeout=15.0)
                    yield _sse_event(record)
                except asyncio.TimeoutError:
                    yield b": keepalive\n\n"
        except asyncio.CancelledError:
            raise
        finally:
            bus.unsubscribe(q)

    headers = {
        "Cache-Control": "no-cache, no-transform",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",
    }
    return StreamingResponse(
        event_source(), media_type="text/event-stream", headers=headers
    )
