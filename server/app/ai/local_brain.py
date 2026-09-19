"""本地规则大脑：未配置大模型 API Key 时的兜底分析。

仍然只通过工具读取真实数据，用模板组织成中文结论，保证"有问必答、答案可溯源"。
"""
from __future__ import annotations

import asyncio
import json
import re
from typing import Any, AsyncIterator, Dict, List

from ..capture.manager import CaptureManager
from .tools import execute_tool

RULES: List[tuple] = [
    (r"(异常|问题|风险|故障|哪.*不对|健康)", "anomaly"),
    (r"(重传|retrans|丢包|乱序)", "retrans"),
    (r"(dns|域名|解析)", "dns"),
    (r"(http|接口|请求|响应|4\d\d|5\d\d)", "http"),
    (r"(tls|https|ssl|握手|证书|sni)", "tls"),
    (r"(会话|连接|谁.*通信|流量最大|top)", "conversation"),
    (r"(端点|主机|地址|ip)", "endpoint"),
    (r"(端口)", "port"),
    (r"(协议|构成|占比|分布)", "protocol"),
    (r"(趋势|曲线|突发|峰值|随时间)", "trend"),
    (r"(摘要|总结|概括|结论|报告|情况)", "summary"),
]


def route(question: str) -> str:
    q = question.lower()
    for pattern, kind in RULES:
        if re.search(pattern, q):
            return kind
    return "summary"


def _j(mgr: CaptureManager, tool: str, args: Dict[str, Any]) -> Any:
    try:
        return json.loads(execute_tool(mgr, tool, args))
    except Exception:                                               # noqa: BLE001
        return {}


async def local_answer(mgr: CaptureManager, question: str) -> AsyncIterator[Dict[str, Any]]:
    kind = route(question)
    yield {"type": "status", "text": "本地规则引擎分析中（未接入大模型）…"}

    summary = _j(mgr, "get_capture_summary", {})
    s = summary.get("summary", {})
    lines: List[str] = []
    tools_used: List[Dict[str, Any]] = []

    def use(tool: str, args: Dict[str, Any]) -> Any:
        res = _j(mgr, tool, args)
        tools_used.append({"name": tool, "args": args})
        return res

    if s.get("packets", 0) == 0:
        yield {"type": "token", "text": "当前没有任何报文数据。请先点「开始」抓包，或用「导入 pcap」加载离线文件，再问我一次。"}
        yield {"type": "done", "text": "当前没有任何报文数据。请先点「开始」抓包，或用「导入 pcap」加载离线文件，再问我一次。", "tools": []}
        return

    lines.append(f"**数据范围**：{s['packets']} 个报文 / {s['bytes']} 字节，持续 {s['duration']} 秒，"
                 f"平均 {s['avg_pps']} pps、{s['avg_bps']} bps，峰值 {s['peak_bps']} bps。")

    if kind == "anomaly":
        anom = use("detect_anomaly", {})
        exp = use("get_expert_info", {"limit": 20})
        lines.append("\n**异常检测结论**：")
        for a in (anom if isinstance(anom, list) else []):
            lines.append(f"- [{a.get('level')}] {a.get('type')}：{a.get('detail')}")
        if isinstance(exp, list) and exp:
            lines.append("\n**最近事件**（最多 8 条）：")
            for e in exp[-8:]:
                lines.append(f"- #{e.get('packet_id')} [{e.get('group')}] {e.get('text')}")
        lines.append("\n**建议**：优先处理 high 级别项；若是重传集中在单一会话，重点查该路径的链路质量或对端处理能力。")

    elif kind == "retrans":
        exp = use("get_expert_info", {"limit": 50})
        rr = [e for e in (exp if isinstance(exp, list) else []) if e.get("group") in ("重传", "丢包")]
        lines.append(f"\n**重传/丢包**：共检测到 {len(rr)} 条相关事件（全部报文 {s['packets']} 个）。")
        for e in rr[-10:]:
            lines.append(f"- #{e.get('packet_id')} {e.get('text')}")
        lines.append("\n**判断**：偶发重传属正常；若重传集中在同一会话或占比超过 1%，通常指向链路拥塞、缓冲区不足或对端响应慢。")

    elif kind == "dns":
        pk = use("query_packets", {"filter": "dns", "limit": 40})
        lines.append(f"\n**DNS 报文**：命中 {pk.get('total', 0)} 个。")
        for p in (pk.get("packets") or [])[:12]:
            lines.append(f"- #{p['id']} {p['src']} → {p['dst']} {p['info']}")
        lines.append(f"\nDNS 失败响应 {s.get('dns_failures', 0)} 次。")

    elif kind == "http":
        pk = use("query_packets", {"filter": "http", "limit": 40})
        lines.append(f"\n**HTTP 报文**：命中 {pk.get('total', 0)} 个，错误响应 {s.get('http_errors', 0)} 次。")
        for p in (pk.get("packets") or [])[:12]:
            lines.append(f"- #{p['id']} {p['src']}:{p['src_port']} → {p['dst']}:{p['dst_port']} {p['info']}")

    elif kind == "tls":
        pk = use("query_packets", {"filter": "tls", "limit": 30})
        lines.append(f"\n**TLS 报文**：命中 {pk.get('total', 0)} 个。")
        for p in (pk.get("packets") or [])[:12]:
            lines.append(f"- #{p['id']} {p['src']} → {p['dst']} {p['info']}")

    elif kind == "conversation":
        convs = use("get_statistics", {"type": "conversation", "limit": 10})
        lines.append("\n**流量 Top 会话**：")
        for i, c in enumerate((convs or [])[:10], 1):
            lines.append(f"{i}. {c['src']}:{c['src_port']} → {c['dst']}:{c['dst_port']}｜"
                         f"{c['packets']} 包 / {c['bytes']} 字节 / {c['bps']} bps" +
                         (f"｜重传 {c['retrans']}" if c.get('retrans') else ""))

    elif kind == "endpoint":
        eps = use("get_statistics", {"type": "endpoint", "limit": 10})
        lines.append("\n**活跃端点**（按字节）：")
        for i, e in enumerate((eps or [])[:10], 1):
            lines.append(f"{i}. {e['address']}｜发 {e['tx_bytes']}B / 收 {e['rx_bytes']}B｜{e['packets']} 包")

    elif kind == "port":
        m = re.search(r"(\d{2,5})", question)
        if m:
            port = int(m.group(1))
            info = use("analyze_port", {"port": port})
            lines.append(f"\n**端口 {port} 画像**：")
            lines.append(f"- 抓包中：{'是' if info.get('seen_in_capture') else '否'}，"
                         f"{info.get('packets', 0)} 包 / {info.get('bytes', 0)} 字节，"
                         f"{info.get('streams', 0)} 条流，{len(info.get('peers', []))} 个对端")
            if info.get("services"):
                lines.append(f"- 识别服务：{', '.join(info['services'])}")
            if info.get("local_listening"):
                lines.append(f"- 本机监听：{', '.join(str(x['local']) for x in info['local_listening'])}"
                             f"（{info['local_listening'][0].get('process', '')}）")
            else:
                lines.append("- 本机未监听该端口")
            for t in (info.get("top_talkers") or [])[:5]:
                lines.append(f"- 主要会话：{t['src']}:{t['src_port']} ↔ {t['dst']}:{t['dst_port']} {t['bytes']}B")
            if info.get("related_experts"):
                lines.append("- 相关异常：" + "；".join(e["text"][:50] for e in info["related_experts"][:4]))
        else:
            ports = use("get_statistics", {"type": "port", "limit": 15})
            lines.append("\n**端口流量 Top**：")
            for i, p in enumerate((ports or [])[:15], 1):
                lines.append(f"{i}. 端口 {p['port']}｜{p['packets']} 包 / {p['bytes']} 字节｜"
                             f"{p['streams']} 流｜{p['peers']} 对端" +
                             (f"｜{'/'.join(p['services'])}" if p.get('services') else ""))
            lines.append("\n**本机端口监听状态**：")
            st = use("get_statistics", {"type": "port_state", "limit": 10})
            if isinstance(st, dict):
                lines.append(f"- 监听 {st.get('summary', {}).get('listening', 0)} 个，"
                             f"已建立连接 {st.get('summary', {}).get('established', 0)} 条")

    elif kind == "protocol":
        prots = use("get_statistics", {"type": "protocol", "limit": 15})
        lines.append("\n**协议构成**：")
        for p in (prots or [])[:15]:
            lines.append(f"- {p['protocol']}：{p['packets']} 包（{p['percent']}%）/ {p['bytes']} 字节")

    elif kind == "trend":
        ser = use("get_io_series", {"bucket_ms": 1000})
        pts = ser.get("points", []) if isinstance(ser, dict) else []
        if pts:
            peaks = sorted(pts, key=lambda x: -x[2])[:3]
            lines.append("\n**流量趋势**：")
            lines.append(f"- 共 {len(pts)} 个时间桶，峰值包数 {max(p[1] for p in pts)}，峰值字节 {peaks[0][2] if peaks else 0}")
            lines.append("- 最活跃的 3 个时间点：" + "，".join(
                f"{_t(p[0])}（{p[1]} 包）" for p in peaks))
        lines.append(f"- 平均速率 {s['avg_bps']} bps，峰值 {s['peak_bps']} bps。")

    else:  # summary
        prots = use("get_statistics", {"type": "protocol", "limit": 6})
        convs = use("get_statistics", {"type": "conversation", "limit": 5})
        anom = use("detect_anomaly", {})
        lines.append("\n**协议构成**：" + "，".join(f"{p['protocol']} {p['percent']}%" for p in (prots or [])[:6]))
        lines.append("\n**主要会话**：")
        for c in (convs or [])[:5]:
            lines.append(f"- {c['src']}:{c['src_port']} → {c['dst']}:{c['dst_port']}｜{c['bytes']} 字节")
        lines.append("\n**异常**：" + "；".join(f"[{a.get('level')}]{a.get('type')}" for a in (anom or [])))
        lines.append(f"\n**结论**：本次共 {s['packets']} 个报文，"
                     + ("存在需要关注的问题，建议按上面的 high/medium 项逐条排查。" if any(
                         a.get('level') in ('high', 'medium') for a in (anom or []))
                        else "未发现明显异常，流量构成与速率处于正常范围。"))

    text = "\n".join(lines)
    # 模拟流式输出
    for i in range(0, len(text), 12):
        yield {"type": "token", "text": text[i:i + 12]}
        await asyncio.sleep(0.012)
    yield {"type": "done", "text": text, "tools": tools_used}


def _t(ts: float) -> str:
    import time
    return time.strftime("%H:%M:%S", time.localtime(ts))
