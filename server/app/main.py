"""NetEye 后端入口。"""
from __future__ import annotations

import asyncio
import os
from pathlib import Path

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .api import ai, analysis, capture, ws
from .capture.manager import manager
from .core.config import BASE_DIR, DATA_DIR, settings
from .storage import db


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """启动初始化 / 退出清理（替代已废弃的 @app.on_event）。"""
    db.init_db()
    manager.set_loop(asyncio.get_event_loop())
    try:
        yield
    finally:
        try:
            if getattr(manager, "state", "") == "running":
                manager.stop()
        except Exception:
            pass


app = FastAPI(title="NetEye", version="1.0.0", lifespan=lifespan,
              description="网络端口监控与协议分析平台（Wireshark 级能力 + AI 对话分析）")

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])

app.include_router(capture.router)
app.include_router(analysis.router)
app.include_router(ai.router)
app.include_router(ws.router)


@app.get("/api/health")
async def health() -> dict:
    return {"ok": True, "version": "0.1.0", "data_dir": str(DATA_DIR),
            "engines": manager.engine_status(), "state": manager.state}


# ------------------------------------------------------------------ 前端静态托管
DIST = BASE_DIR / "web" / "dist"

# index.html 必须禁用缓存：每次前端构建后 assets 文件名会变，
# 若浏览器沿用缓存的旧 index.html 会指向已删除的 JS 导致白屏。
NO_CACHE = {"Cache-Control": "no-cache, no-store, must-revalidate", "Pragma": "no-cache"}

if DIST.exists():
    app.mount("/assets", StaticFiles(directory=str(DIST / "assets")), name="assets")

    @app.get("/")
    async def index() -> FileResponse:
        return FileResponse(str(DIST / "index.html"), headers=NO_CACHE)

    @app.get("/{full_path:path}")
    async def spa(full_path: str):
        target = DIST / full_path
        if target.exists() and target.is_file():
            return FileResponse(str(target))
        return FileResponse(str(DIST / "index.html"), headers=NO_CACHE)
else:
    @app.get("/")
    async def index() -> JSONResponse:
        return JSONResponse({"ok": True, "msg": "NetEye 后端已启动，前端尚未构建（web/dist 不存在）",
                             "docs": "/docs"})
