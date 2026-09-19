"""AI 可用工具（Function Calling）。

设计原则：AI 只能通过这些工具读取真实数据，禁止凭空生成统计值。
"""
from __future__ import annotations

import json
from typing import Any, Dict, List

from ..capture.manager import CaptureManager
from ..stats import portstate


def _clip(obj: Any, limit: int = 4000) -> str:
    s = json.dumps(obj, ensure_ascii=False) if not isinstance(obj, str) else obj
    return s if len(s) <= limit else s[:limit] + f"…（已截断，共 {len(s)} 字符）"


TOOLS: List[Dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "get_capture_summary",
            "description": "获取当前捕获会话的整体概览：包数、字节、时长、速率、峰值、TCP 流数、重传数、异常数。任何数据分析前建议先调用。",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_packets",
            "description": "按显示过滤器查询报文列表。过滤器语法：tcp.port==80、ip.addr==192.168.1.1、http、dns、tcp.flags.reset==1、frame.len>1000，支持 && || ! 与括号。",
            "parameters": {
                "type": "object",
                "properties": {
                    "filter": {"type": "string", "description": "显示过滤器表达式，空字符串表示全部"},
                    "limit": {"type": "integer", "description": "返回条数上限，默认 50，最大 200"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_packet_detail",
            "description": "按包序号获取单个报文的完整协议分层字段（含 TCP 标志位、序列号、应用层信息）。",
            "parameters": {"type": "object", "properties": {"packet_id": {"type": "integer", "description": "包序号"}}, "required": ["packet_id"]},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_statistics",
            "description": "获取统计表：protocol（协议分级）、conversation（会话）、endpoint（端点）、port（端口流量）、port_state（本机端口监听状态与进程）。",
            "parameters": {
                "type": "object",
                "properties": {
                    "type": {"type": "string", "enum": ["protocol", "conversation", "endpoint", "port", "port_state"], "description": "统计类型"},
                    "limit": {"type": "integer", "description": "返回条数，默认 20"},
                },
                "required": ["type"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_expert_info",
            "description": "获取专家信息（异常事件）：重传、乱序、零窗口、RST、扫描告警等。",
            "parameters": {
                "type": "object",
                "properties": {
                    "severity": {"type": "string", "enum": ["all", "error", "warn", "note"], "description": "级别过滤"},
                    "limit": {"type": "integer", "description": "条数，默认 30"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_io_series",
            "description": "获取时间序列数据（按时间桶聚合的包数/字节/比特率），用于判断趋势、突发、周期性流量。",
            "parameters": {
                "type": "object",
                "properties": {
                    "filter": {"type": "string", "description": "显示过滤器，可空"},
                    "bucket_ms": {"type": "integer", "description": "时间桶大小（毫秒），默认 1000"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_port",
            "description": "对单个端口做深度画像：流量、对端数量、服务类型、相关异常、最近活跃时间、本机是否监听该端口。",
            "parameters": {"type": "object", "properties": {"port": {"type": "integer", "description": "端口号"}}, "required": ["port"]},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "follow_stream",
            "description": "重组并查看某个 TCP/UDP 流的完整内容（双向），输入该流中任意一个包序号。",
            "parameters": {"type": "object", "properties": {"packet_id": {"type": "integer", "description": "流中任意包序号"}}, "required": ["packet_id"]},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "detect_anomaly",
            "description": "运行异常检测规则，返回结构化异常清单（重传率、扫描、DNS 失败、HTTP 错误、广播风暴、流量集中度等）。",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "export_result",
            "description": "导出数据到文件（pcap/csv/json），返回文件路径。",
            "parameters": {
                "type": "object",
                "properties": {
                    "format": {"type": "string", "enum": ["pcap", "csv", "json"]},
                    "scope": {"type": "string", "enum": ["all", "filtered"], "description": "全部或按过滤器"},
                    "filter": {"type": "string", "description": "scope=filtered 时生效"},
                },
                "required": ["format"],
            },
        },
    },
]


def execute_tool(mgr: CaptureManager, name: str, args: Dict[str, Any]) -> str:
    """执行工具，返回结果字符串（JSON 文本）。"""
    try:
        if name == "get_capture_summary":
            return _clip({"summary": mgr.agg.summary(), "live_rate": mgr.agg.recent_rate(5),
                          "state": mgr.state, "engine": mgr.engine_name})
        if name == "query_packets":
            limit = min(int(args.get("limit", 50)), 200)
            res = mgr.query_packets(args.get("filter", ""), 0, limit)
            return _clip({"total": res["total"], "shown": len(res["items"]), "packets": res["items"]})
        if name == "get_packet_detail":
            d = mgr.get_detail(int(args["packet_id"]))
            if not d:
                return _clip({"error": f"找不到包 #{args['packet_id']}"})
            return _clip({"summary": d["summary"], "layers": [
                {"name": l["name"], "title": l["title"],
                 "fields": {f["name"]: f["value"] for f in l["fields"]}} for l in d["layers"]]})
        if name == "get_statistics":
            stype = args.get("type", "protocol")
            limit = min(int(args.get("limit", 20)), 200)
            if stype == "protocol":
                return _clip(mgr.agg.protocol_stats()[:limit])
            if stype == "conversation":
                return _clip(mgr.agg.conversations(limit=limit))
            if stype == "endpoint":
                return _clip(mgr.agg.endpoints(limit=limit))
            if stype == "port":
                return _clip(mgr.agg.port_stats(limit=limit))
            if stype == "port_state":
                return _clip({"listening": portstate.list_port_states(only_listen=True)[:limit],
                              "summary": portstate.port_summary()})
            return _clip({"error": f"未知统计类型 {stype}"})
        if name == "get_expert_info":
            return _clip(mgr.agg.expert_info(args.get("severity", "all"), int(args.get("limit", 30))))
        if name == "get_io_series":
            ser = mgr.io_series(args.get("filter", ""), int(args.get("bucket_ms", 1000)))
            pts = ser["points"]
            if len(pts) > 120:                        # 抽样，避免爆炸
                step = max(len(pts) // 120, 1)
                pts = pts[::step]
            return _clip({"fields": ser["fields"], "points": pts, "count": ser.get("count", 0)})
        if name == "analyze_port":
            return _clip(_analyze_port(mgr, int(args["port"])))
        if name == "follow_stream":
            s = mgr.follow_stream(int(args["packet_id"]))
            if not s.get("available"):
                return _clip(s)
            return _clip({"stream": s["stream"], "a_len": s["a_len"], "b_len": s["b_len"],
                          "a_text": s["a_text"][:1500], "b_text": s["b_text"][:1500],
                          "packets": s["packets"][:60]})
        if name == "detect_anomaly":
            return _clip(mgr.agg.anomalies())
        if name == "export_result":
            path = mgr.export(scope=args.get("scope", "all"), filter_str=args.get("filter", ""),
                              fmt=args.get("format", "csv"))
            return _clip({"path": path, "format": args.get("format", "csv")})
        return _clip({"error": f"未知工具 {name}"})
    except Exception as exc:                                        # noqa: BLE001
        return _clip({"error": f"工具执行失败：{exc}"})


def _analyze_port(mgr: CaptureManager, port: int) -> Dict[str, Any]:
    p = mgr.agg.ports.get(port)
    info: Dict[str, Any] = {"port": port, "seen_in_capture": bool(p)}
    if p:
        info.update({"packets": p["packets"], "bytes": p["bytes"], "tcp": p.get("tcp", 0),
                     "udp": p.get("udp", 0), "streams": len(p["streams"]),
                     "peers": sorted(p["peers"])[:20], "services": sorted(p["services"]),
                     "last_seen": p["last_ts"]})
    states = portstate.list_port_states()
    listening = [s for s in states if s["local_port"] == port and s["status_raw"] == "LISTEN"]
    conns = [s for s in states if s["local_port"] == port]
    info["local_listening"] = listening[:5]
    info["local_connections"] = len(conns)
    info["related_experts"] = [e for e in list(mgr.agg.experts)[-300:]
                               if f":{port}" in e["text"]][:10]
    info["top_talkers"] = [c for c in mgr.agg.conversations(limit=200)
                           if c["src_port"] == port or c["dst_port"] == port][:5]
    return info
