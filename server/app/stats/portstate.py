"""本机端口/连接状态（netstat 级），与抓包统计互补。

注意：psutil.net_connections() 在 Windows 上需要逐个进程取名称，单次可能耗时数百毫秒到数秒，
因此这里做了两级缓存（进程名 + 整体结果），避免前端轮询把服务打爆。
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

import psutil

_PROC_CACHE: Dict[int, tuple] = {}
_RESULT_CACHE: Dict[str, Any] = {"ts": 0.0, "kind": "", "data": None}
_RESULT_TTL = 2.0          # 整体结果缓存秒数
_PROC_TTL = 30.0           # 进程名缓存秒数

STATUS_CN = {
    "ESTABLISHED": "已建立", "LISTEN": "监听", "TIME_WAIT": "等待关闭", "CLOSE_WAIT": "等待关闭(对端)",
    "SYN_SENT": "SYN已发送", "SYN_RECV": "SYN已收到", "FIN_WAIT1": "FIN等待1", "FIN_WAIT2": "FIN等待2",
    "CLOSING": "关闭中", "LAST_ACK": "最后确认", "NONE": "无", "BOUND": "已绑定",
}


def _safe(s: str) -> str:
    """清理 Windows 进程名中可能出现的非法代理字符，避免 JSON 序列化失败。"""
    try:
        return s.encode("utf-8", "ignore").decode("utf-8", "ignore")
    except Exception:                                               # noqa: BLE001
        return "".join(ch for ch in s if ch.isprintable())


def _addr(addr, default: str = "") -> str:
    if not addr:
        return default
    if isinstance(addr, tuple):
        ip = addr[0] if len(addr) > 0 else ""
        port = addr[1] if len(addr) > 1 else ""
        return f"{ip}:{port}" if ip else str(port)
    return str(addr)


def _proc_name(pid: int) -> str:
    now = time.time()
    hit = _PROC_CACHE.get(pid)
    if hit and now - hit[1] < _PROC_TTL:
        return hit[0]
    try:
        name = _safe(psutil.Process(pid).name())
    except Exception:                                               # noqa: BLE001
        name = ""
    if len(_PROC_CACHE) > 3000:
        _PROC_CACHE.clear()
    _PROC_CACHE[pid] = (name, now)
    return name


def list_port_states(kind: str = "all", only_listen: bool = False) -> List[Dict[str, Any]]:
    now = time.time()
    cached = _RESULT_CACHE["data"]
    if cached is not None and _RESULT_CACHE["kind"] == kind and now - _RESULT_CACHE["ts"] < _RESULT_TTL:
        return [c for c in cached if not only_listen or c["status_raw"] == "LISTEN"]

    out: List[Dict[str, Any]] = []
    try:
        conns = psutil.net_connections(kind=kind)
    except Exception:                                               # noqa: BLE001
        return []
    for c in conns:
        try:
            if only_listen and c.status != psutil.CONN_LISTEN:
                continue
            pid = c.pid
            pname = _proc_name(pid) if pid else ""
            la = c.laddr
            out.append({
                "proto": "TCP" if c.type == 1 else "UDP" if c.type == 2 else str(c.type),
                "local": _safe(_addr(la)), "local_port": la[1] if isinstance(la, tuple) and len(la) > 1 else 0,
                "remote": _safe(_addr(c.raddr, "*")),
                "remote_port": c.raddr[1] if c.raddr and len(c.raddr) > 1 else 0,
                "status": STATUS_CN.get(c.status, c.status or ""),
                "status_raw": c.status or "",
                "pid": pid or 0, "process": pname,
            })
        except Exception:                                           # noqa: BLE001
            continue
    out.sort(key=lambda x: (x["local_port"] or 0))
    _RESULT_CACHE.update(ts=now, kind=kind, data=out)
    return [c for c in out if not only_listen or c["status_raw"] == "LISTEN"]


def port_summary() -> Dict[str, Any]:
    conns = list_port_states()
    listen = [c for c in conns if c["status_raw"] == "LISTEN"]
    est = [c for c in conns if c["status_raw"] == "ESTABLISHED"]
    tcp_ports = {c["local_port"] for c in conns if c["proto"] == "TCP" and c["local_port"]}
    udp_ports = {c["local_port"] for c in conns if c["proto"] == "UDP" and c["local_port"]}
    return {
        "total": len(conns), "listening": len(listen), "established": len(est),
        "tcp_ports": len(tcp_ports), "udp_ports": len(udp_ports),
        "top_processes": _top_processes(conns),
    }


def _top_processes(conns: List[Dict[str, Any]], limit: int = 8) -> List[Dict[str, Any]]:
    agg: Dict[str, int] = {}
    for c in conns:
        key = c["process"] or f"pid:{c['pid']}" or "未知"
        agg[key] = agg.get(key, 0) + 1
    return [{"process": k, "connections": v} for k, v in sorted(agg.items(), key=lambda kv: -kv[1])[:limit]]
