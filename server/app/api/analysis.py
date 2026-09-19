"""统计与端口状态 API。"""
from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Query

from ..capture.manager import manager
from ..filters.display_filter import validate_filter
from ..stats import portstate

router = APIRouter(prefix="/api/stats")


@router.get("/summary")
async def summary() -> Dict[str, Any]:
    return {"summary": manager.agg.summary(), "rate": manager.agg.recent_rate(5),
            "state": manager.state, "engine": manager.engine_name}


@router.get("/protocols")
async def protocols() -> Dict[str, Any]:
    return {"items": manager.agg.protocol_stats()}


@router.get("/conversations")
async def conversations(limit: int = Query(200), sort_by: str = "bytes") -> Dict[str, Any]:
    return {"items": manager.agg.conversations(limit=limit, sort_by=sort_by)}


@router.get("/endpoints")
async def endpoints(limit: int = Query(200)) -> Dict[str, Any]:
    return {"items": manager.agg.endpoints(limit=limit)}


@router.get("/ports")
async def ports(limit: int = Query(300)) -> Dict[str, Any]:
    return {"items": manager.agg.port_stats(limit=limit)}


@router.get("/portstate")
async def port_state(only_listen: bool = False) -> Dict[str, Any]:
    return {"items": portstate.list_port_states(only_listen=only_listen),
            "summary": portstate.port_summary()}


@router.get("/expert")
async def expert(severity: str = "all", limit: int = 300) -> Dict[str, Any]:
    return {"items": manager.agg.expert_info(severity, limit)}


@router.get("/anomalies")
async def anomalies() -> Dict[str, Any]:
    return {"items": manager.agg.anomalies()}


@router.get("/io")
async def io_series(filter: str = "", bucket_ms: int = 1000) -> Dict[str, Any]:
    return manager.io_series(filter, bucket_ms)


@router.get("/filter/validate")
async def filter_validate(expr: str = "") -> Dict[str, Any]:
    err = validate_filter(expr)
    return {"ok": err is None, "error": err}


@router.get("/live")
async def live() -> Dict[str, Any]:
    return manager.live_stats()
