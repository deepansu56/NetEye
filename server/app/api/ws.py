"""WebSocket：实时推送新包与统计。"""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ..capture.manager import manager

router = APIRouter()


@router.websocket("/ws")
async def ws_endpoint(ws: WebSocket) -> None:
    await ws.accept()
    q = manager.subscribe()
    try:
        while True:
            try:
                payload = await asyncio.wait_for(q.get(), timeout=2.0)
            except asyncio.TimeoutError:
                await ws.send_json({"type": "stats", "data": manager.live_stats()})
                continue
            await ws.send_json(payload)
    except WebSocketDisconnect:
        pass
    except Exception:                                               # noqa: BLE001
        pass
    finally:
        manager.unsubscribe(q)
