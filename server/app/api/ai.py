"""AI 对话 API：配置、连通性测试、SSE 流式对话（带工具调用）。"""
from __future__ import annotations

import json
from typing import Any, Dict, List

from fastapi import APIRouter, Body
from fastapi.responses import StreamingResponse

from ..ai.client import AIClient
from ..ai.tools import TOOLS, execute_tool
from ..capture.manager import manager
from ..core.config import settings
from ..core.models import AIConfigIn, ChatRequest
from ..storage import db

router = APIRouter(prefix="/api/ai")


def _mask(key: str) -> str:
    if not key:
        return ""
    return key[:6] + "*" * max(len(key) - 10, 3) + key[-4:]


@router.get("/config")
async def get_config() -> Dict[str, Any]:
    cfg = dict(settings.ai)
    cfg["api_key"] = _mask(cfg.get("api_key", ""))
    cfg["has_key"] = bool(settings.ai.get("api_key"))
    cfg["presets"] = settings.get("presets", {})
    cfg["tools"] = [t["function"]["name"] for t in TOOLS]
    return cfg


@router.post("/config")
async def set_config(cfg: AIConfigIn) -> Dict[str, Any]:
    patch = {k: v for k, v in cfg.model_dump().items() if v is not None}
    if "api_key" in patch and patch["api_key"] == "" :
        patch.pop("api_key")
    settings.update({"ai": patch})
    return {"ok": True, "config": await get_config()}


@router.post("/test")
async def test_connection() -> Dict[str, Any]:
    cfg = settings.ai
    if not cfg.get("api_key") and "localhost" not in cfg.get("base_url", ""):
        return {"ok": False, "error": "未配置 API Key，请先在设置中填写"}
    cli = AIClient(cfg.get("base_url", ""), cfg.get("api_key", ""), cfg.get("model", ""),
                   cfg.get("temperature", 0.2), cfg.get("max_tokens", 2048))
    return await cli.test()


def _build_context() -> str:
    s = manager.agg.summary()
    top = manager.agg.protocol_stats()[:5]
    convs = manager.agg.conversations(limit=3)
    anom = manager.agg.anomalies()[:4]
    lines = [
        f"当前捕获状态：{manager.state}，引擎 {manager.engine_name or '未启动'}，共 {s['packets']} 个报文 / {s['bytes']} 字节，"
        f"持续 {s['duration']} 秒，平均 {s['avg_pps']} pps / {s['avg_bps']} bps。",
        "协议分布（前 5）：" + ("，".join(f"{p['protocol']} {p['percent']}%" for p in top) or "无"),
        "主要会话：" + ("；".join(f"{c['src']}:{c['src_port']}→{c['dst']}:{c['dst_port']} {c['bytes']}B" for c in convs) or "无"),
        "异常检测：" + ("；".join(f"[{a['level']}]{a['type']}" for a in anom) or "无"),
        f"重传 {s['retransmissions']} 次，专家信息 {s['expert_count']} 条。",
    ]
    return "\n".join(lines)


@router.post("/chat")
async def chat(req: ChatRequest) -> StreamingResponse:
    cfg = settings.ai
    sid = manager.session_id or "default"
    user_text = ""
    for m in reversed(req.messages):
        if m.role == "user":
            user_text = m.content
            break
    db.save_chat(sid, "user", user_text)

    sys_prompt = cfg.get("system_prompt", "")
    ctx = ""
    if req.context_packet_ids:
        ctx = "\n\n用户选中的报文：\n" + json.dumps(
            [manager.get_detail(i)["summary"] for i in req.context_packet_ids[:5]
             if manager.get_detail(i)], ensure_ascii=False)
    messages: List[Dict[str, Any]] = [
        {"role": "system", "content": f"{sys_prompt}\n\n===== 当前抓包上下文（真实数据） =====\n{_build_context()}{ctx}"}
    ]
    messages += [{"role": m.role, "content": m.content} for m in req.messages]

    cli = AIClient(cfg.get("base_url", ""), cfg.get("api_key", ""), cfg.get("model", ""),
                   cfg.get("temperature", 0.2), cfg.get("max_tokens", 2048))

    async def gen():
        full: List[str] = []
        try:
            if not cfg.get("api_key") or not cfg.get("enabled", True):
                from ..ai.local_brain import local_answer                   # noqa: PLC0415
                async for ev in local_answer(manager, user_text):
                    if ev["type"] == "done":
                        db.save_chat(sid, "assistant", ev.get("text", ""))
                    yield f"data: {json.dumps(ev, ensure_ascii=False)}\n\n"
                yield "data: [DONE]\n\n"
                return
            async for ev in cli.chat_stream(messages, TOOLS, lambda n, a: execute_tool(manager, n, a)):
                full.append(ev.get("text", "") if ev["type"] == "token" else "")
                yield f"data: {json.dumps(ev, ensure_ascii=False)}\n\n"
                if ev["type"] == "done":
                    db.save_chat(sid, "assistant", ev.get("text", ""))
        except Exception as exc:                                    # noqa: BLE001
            yield f"data: {json.dumps({'type': 'error', 'text': str(exc)}, ensure_ascii=False)}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.get("/history")
async def history() -> Dict[str, Any]:
    return {"items": db.load_chat(manager.session_id or "default")}


@router.delete("/history")
async def clear_history() -> Dict[str, Any]:
    db.clear_chat(manager.session_id or "default")
    return {"ok": True}


@router.post("/analyze-selection")
async def analyze_selection(payload: Dict[str, Any] = Body(default={})) -> Dict[str, Any]:
    """快捷分析：不经过 LLM，直接给出选中包的规则化结论。"""
    ids = payload.get("ids", []) or []
    out = []
    for i in ids[:20]:
        d = manager.get_detail(int(i))
        if d:
            out.append(d["summary"])
    return {"items": out, "anomalies": manager.agg.anomalies()}
