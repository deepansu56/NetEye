"""捕获控制与数据查询 API。"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, HTTPException
from fastapi.responses import FileResponse, JSONResponse

from ..capture.manager import manager
from ..core.config import CAPTURE_DIR
from ..core.models import CaptureStartRequest, ExportRequest, PacketsQuery
from ..storage import db, pcapio

router = APIRouter(prefix="/api")


@router.get("/engines")
async def engines() -> Dict[str, Any]:
    return manager.engine_status()


@router.get("/interfaces")
async def interfaces() -> Dict[str, Any]:
    return {"items": manager.interfaces(), "engines": manager.engine_status()}


@router.post("/capture/start")
async def capture_start(req: CaptureStartRequest) -> Dict[str, Any]:
    res = manager.start(req.model_dump())
    if not res.get("ok"):
        return JSONResponse(status_code=400, content=res)
    return res


@router.post("/capture/stop")
async def capture_stop() -> Dict[str, Any]:
    return manager.stop()


@router.post("/capture/pause")
async def capture_pause() -> Dict[str, Any]:
    return manager.pause()


@router.post("/capture/resume")
async def capture_resume() -> Dict[str, Any]:
    return manager.resume()


@router.post("/capture/clear")
async def capture_clear() -> Dict[str, Any]:
    manager.clear()
    return {"ok": True}


@router.get("/capture/status")
async def capture_status() -> Dict[str, Any]:
    return {"state": manager.state, "engine": manager.engine_name, "packets": len(manager.records),
            "session_id": manager.session_id, "pcap_path": manager.pcap_path or "",
            "error": manager.error, **manager.agg.summary()}


@router.post("/packets/query")
async def packets_query(q: PacketsQuery) -> Dict[str, Any]:
    return manager.query_packets(q.filter, q.offset, q.limit)


@router.get("/packets/{pid}")
async def packet_detail(pid: int) -> Dict[str, Any]:
    d = manager.get_detail(pid)
    if not d:
        raise HTTPException(404, "packet not found")
    return d


@router.get("/packets/{pid}/stream")
async def packet_stream(pid: int) -> Dict[str, Any]:
    return manager.follow_stream(pid)


@router.post("/export")
async def export(req: ExportRequest) -> Dict[str, Any]:
    path = manager.export(scope=req.scope, filter_str=req.filter, ids=req.ids, fmt=req.format,
                          filename=req.filename)
    return {"ok": True, "path": path, "size": os.path.getsize(path) if os.path.exists(path) else 0}


@router.get("/download")
async def download(path: str) -> Any:
    if not os.path.exists(path):
        raise HTTPException(404, "file not found")
    return FileResponse(path, filename=os.path.basename(path))


# ------------------------------------------------------------------ 会话
@router.post("/sessions/save")
async def session_save(payload: Dict[str, Any] = Body(default={})) -> Dict[str, Any]:
    return manager.save_session(payload.get("name", ""), payload.get("note", ""))


@router.get("/sessions")
async def sessions() -> Dict[str, Any]:
    return {"items": db.list_sessions()}


@router.post("/sessions/load/{sid}")
async def session_load(sid: str) -> Dict[str, Any]:
    s = db.get_session(sid)
    if not s:
        raise HTTPException(404, "session not found")
    if s["pcap_path"] and os.path.exists(s["pcap_path"]):
        return manager.load_pcap(s["pcap_path"])
    rows = db.load_packets(sid)
    return {"ok": True, "packets": len(rows), "note": "无 pcap 文件，仅加载索引", "rows": rows[:500]}


@router.delete("/sessions/{sid}")
async def session_delete(sid: str) -> Dict[str, Any]:
    db.delete_session(sid)
    return {"ok": True}


@router.post("/sessions/import-pcap")
async def import_pcap(payload: Dict[str, str] = Body(default={})) -> Dict[str, Any]:
    path = payload.get("path", "")
    if not path or not os.path.exists(path):
        raise HTTPException(400, f"文件不存在：{path}")
    return manager.load_pcap(path)


@router.get("/captures")
async def list_captures() -> Dict[str, Any]:
    items = []
    for f in sorted(CAPTURE_DIR.glob("*.pcap"), key=lambda p: -p.stat().st_mtime)[:50]:
        try:
            items.append({"name": f.name, "path": str(f), "size": f.stat().st_size,
                          **pcapio.pcap_info(str(f))})
        except Exception:                                           # noqa: BLE001
            continue
    return {"items": items}
