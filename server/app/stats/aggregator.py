"""统计聚合 + TCP 流跟踪 + 专家信息 + 异常规则。"""
from __future__ import annotations

import time
from collections import OrderedDict, defaultdict, deque
from typing import Any, Callable, Deque, Dict, List, Optional

from ..parser.dissect import (TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN)

SEV_ORDER = {"error": 0, "warn": 1, "note": 2, "chat": 3}

# 中文分组 → Wireshark 的 TCP Analysis Flag 名（详情页协议树里显示）
_WS_FLAG = {
    "丢包": "TCP Previous segment not captured",
    "保活": "TCP Keep-Alive",
    "重传": "TCP Retransmission",
    "乱序": "TCP Out-Of-Order",
    "连接": "TCP RST",
    "性能": "TCP ZeroWindow",
    "扫描": "TCP SYN Scan",
}


class _Conv:
    __slots__ = ("packets", "bytes", "start", "end", "src_packets", "dst_packets",
                 "src_bytes", "dst_bytes", "syn", "fin", "rst", "retrans",
                 "out_of_order", "gaps")

    def __init__(self) -> None:
        self.packets = self.bytes = 0
        self.src_packets = self.dst_packets = 0
        self.src_bytes = self.dst_bytes = 0
        self.start = self.end = 0.0
        self.syn = self.fin = self.rst = self.retrans = 0
        self.out_of_order = self.gaps = 0


class _Ep:
    __slots__ = ("packets", "bytes", "tx_packets", "rx_packets", "tx_bytes", "rx_bytes", "start", "end")

    def __init__(self) -> None:
        self.packets = self.bytes = 0
        self.tx_packets = self.rx_packets = 0
        self.tx_bytes = self.rx_bytes = 0
        self.start = self.end = 0.0


class Aggregator:
    """实时统计聚合器（随抓包增量更新）。"""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.start_ts: Optional[float] = None
        self.last_ts: Optional[float] = None
        self.total_packets = 0
        self.total_bytes = 0
        self.proto_counter: Dict[str, int] = defaultdict(int)
        self.proto_bytes: Dict[str, int] = defaultdict(int)
        self.convs: Dict[tuple, _Conv] = {}
        self.eps: Dict[str, _Ep] = defaultdict(_Ep)
        self.ports: Dict[int, Dict[str, Any]] = defaultdict(
            lambda: {"port": 0, "tcp": 0, "udp": 0, "packets": 0, "bytes": 0, "streams": set(),
                     "errors": 0, "peers": set(), "services": set(), "last_ts": 0.0})
        self.experts: Deque[Dict[str, Any]] = deque(maxlen=5000)
        # 逐包 TCP 分析标记（Wireshark 的 [TCP Analysis Flags]）：
        # packet_id -> [{flag, severity, text, group}]，详情页按包展示。
        self.pkt_notes: Dict[int, List[Dict[str, Any]]] = {}
        self.pkt_notes_capped = False
        self.tcp_state: Dict[tuple, Dict[str, Any]] = {}
        self.stream_ids: Dict[tuple, int] = {}
        self.dns_fail = 0
        self.http_errors = 0
        self.icmp_count = 0
        self.arp_count = 0
        self.broadcast_pkts = 0
        self.syn_scan_src: Dict[str, set] = defaultdict(set)
        self.peak_pps = 0.0
        self.peak_bps = 0.0
        self._sec_packets: Dict[int, int] = defaultdict(int)
        self._sec_bytes: Dict[int, int] = defaultdict(int)
        self.retrans_total = 0
        self.out_of_order_total = 0
        self.gap_total = 0
        self.dup_deliveries = 0          # 驱动把同一帧递交多次的次数
        # 重传按间隔分级：< RTT 级抢修 / RTO 退避 / 长期空闲后的应用层重试。
        # 只有前两类反映链路质量，第三类多为半开连接，不能用来评价网络。
        self.fast_retrans = 0
        self.rto_retrans = 0
        self.stale_retrans = 0
        self.keepalive_total = 0         # TCP Keep-Alive 探测（易被误判为重传）

    # ------------------------------------------------------------ 主入口
    def add(self, rec, raw_len: int) -> None:
        ts = rec.ts
        if self.start_ts is None:
            self.start_ts = ts
        self.last_ts = ts
        self.total_packets += 1
        self.total_bytes += raw_len
        sec = int(ts)
        self._sec_packets[sec] += 1
        self._sec_bytes[sec] += raw_len
        pps = self._sec_packets[sec]
        bps = self._sec_bytes[sec] * 8
        self.peak_pps = max(self.peak_pps, float(pps))
        self.peak_bps = max(self.peak_bps, float(bps))

        proto = rec.proto or "Unknown"
        self.proto_counter[proto] += 1
        self.proto_bytes[proto] += raw_len

        # 端点
        if rec.src:
            e = self.eps[rec.src]
            e.packets += 1; e.bytes += raw_len
            e.tx_packets += 1; e.tx_bytes += raw_len
            e.start = e.start or ts; e.end = ts
        if rec.dst:
            e = self.eps[rec.dst]
            e.packets += 1; e.bytes += raw_len
            e.rx_packets += 1; e.rx_bytes += raw_len
            e.start = e.start or ts; e.end = ts

        # 会话（双向归一）
        conv = None
        if rec.src and rec.dst:
            a = (rec.src, rec.src_port or 0, rec.dst, rec.dst_port or 0)
            b = (rec.dst, rec.dst_port or 0, rec.src, rec.src_port or 0)
            key = a if a <= b else b
            c = self.convs.get(key)
            if c is None:
                c = self.convs[key] = _Conv()
                c.start = ts
            conv = c
            c.packets += 1; c.bytes += raw_len; c.end = ts
            if (rec.src, rec.src_port) == (key[0], key[1]):
                c.src_packets += 1; c.src_bytes += raw_len
            else:
                c.dst_packets += 1; c.dst_bytes += raw_len
            sid = self.stream_ids.get(key)
            if sid is None:
                sid = self.stream_ids[key] = len(self.stream_ids) + 1
            rec.stream = sid

            # 端口
            for port, is_src in ((rec.src_port, True), (rec.dst_port, False)):
                if not port:
                    continue
                p = self.ports[port]
                p["port"] = port
                p["packets"] += 1
                p["bytes"] += raw_len
                p["tcp" if rec.proto == "TCP" else "udp" if rec.proto == "UDP" else "packets"] = \
                    p.get("tcp" if rec.proto == "TCP" else "udp" if rec.proto == "UDP" else "packets", 0) + 1
                p["streams"].add(sid)
                p["peers"].add(rec.dst if is_src else rec.src)
                if rec.app:
                    p["services"].add(rec.app)
                p["last_ts"] = ts

        if rec.proto == "ICMP":
            self.icmp_count += 1
        elif rec.proto == "ARP":
            self.arp_count += 1
        if rec.dst in ("255.255.255.255", "ff:ff:ff:ff:ff:ff") or (rec.dst or "").endswith(".255"):
            self.broadcast_pkts += 1
        if rec.app == "DNS" and rec.dns_rcode and rec.dns_rcode not in (0,):
            self.dns_fail += 1
        if rec.http_code and rec.http_code >= 400:
            self.http_errors += 1

        if rec.proto == "TCP":
            self._tcp_track(rec, ts, conv)

    # ------------------------------------------------------------ TCP 跟踪
    # 判据与 Wireshark TCP Analysis 对齐：只有「同一 (seq, seg_len) 段此前完整
    # 出现过」才算重传；落在已收范围内但此前未见过的段属于乱序(Out-Of-Order)，
    # 不计入重传率。缺少这层记忆会把无线网络上常见的乱序全部误判成重传
    # （实测 WLAN 上会虚报到 8%+，而真实重传率不足 1%）。
    _SEEN_PER_FLOW = 192          # 每方向保留的段历史条数（FIFO 淘汰）
    _MAX_FLOWS = 30000            # tcp_state 上限，超出按最久未活跃淘汰
    _MIN_RETRANS_GAP = 0.0005     # < 0.5ms 的重复帧视为驱动重复递交

    @staticmethod
    def _seq_rel(a: int, b: int) -> int:
        """a 相对 b 的序列号偏移（正确处理 32 位回绕）。"""
        d = (a - b) & 0xFFFFFFFF
        return d if d < 0x80000000 else d - 0x100000000

    @staticmethod
    def _seq_end(seq: int, length: int) -> int:
        return (seq + length) & 0xFFFFFFFF

    def _new_tcp_state(self, ts: float) -> Dict[str, Any]:
        return {"next_seq": None, "highest_end": None, "last_ack": None, "dup_acks": 0,
                "established": False, "zero_win": False, "last_ts": ts,
                "seen": OrderedDict()}

    def _evict_flows(self) -> None:
        """限制 tcp_state 规模，避免长时间抓包导致内存无界增长。"""
        excess = len(self.tcp_state) - self._MAX_FLOWS
        if excess <= 0:
            return
        oldest = sorted(self.tcp_state.items(), key=lambda kv: kv[1].get("last_ts", 0.0))
        for k, _v in oldest[:excess + 1024]:
            self.tcp_state.pop(k, None)

    @staticmethod
    def _trim_seen(seen: "OrderedDict") -> None:
        while len(seen) > 192:
            seen.popitem(last=False)

    @staticmethod
    def _bump_conv(conv, field: str) -> None:
        if conv is not None:
            setattr(conv, field, getattr(conv, field, 0) + 1)

    def _tcp_track(self, rec, ts: float, conv=None) -> None:
        fl = rec.tcp_flags or 0
        key = (rec.src, rec.src_port, rec.dst, rec.dst_port)
        payload_len = rec.payload_len or 0
        seq = rec.seq or 0
        st = self.tcp_state.get(key)
        if st is None:
            st = self.tcp_state[key] = self._new_tcp_state(ts)
            self._evict_flows()
        st["last_ts"] = ts
        # SYN / FIN 各自占用一个序列号
        seg_len = payload_len + (1 if fl & (TCP_SYN | TCP_FIN) else 0)

        if fl & TCP_SYN:
            st["established"] = bool(fl & TCP_ACK)
            st["highest_end"] = st["next_seq"] = self._seq_end(seq, 1)
            if not (fl & TCP_ACK) and rec.dst_port is not None:
                self.syn_scan_src[rec.src].add(rec.dst_port)
                if len(self.syn_scan_src[rec.src]) == 12:
                    self._expert("warn", "扫描",
                                 f"{rec.src} 向 12 个以上不同端口发起 SYN，疑似端口扫描",
                                 rec.id, ts)
            return

        if fl & TCP_RST:
            self._expert("warn", "连接", f"TCP 连接被重置（RST）：{rec.src}:{rec.src_port} → {rec.dst}:{rec.dst_port}",
                         rec.id, ts)
            self.tcp_state.pop(key, None)
            return

        if seg_len > 0:
            self._track_seq(rec, st, conv, seq, seg_len, payload_len, ts)
        self._track_ack(rec, st, fl, payload_len, ts)
        if fl & TCP_FIN:
            self.tcp_state.pop(key, None)

    def _track_seq(self, rec, st, conv, seq: int, seg_len: int, payload_len: int, ts: float) -> None:
        highest = st["highest_end"]
        seen = st["seen"]
        sig = (seq, seg_len)
        end = self._seq_end(seq, seg_len)

        if highest is None:
            st["highest_end"] = st["next_seq"] = end
            seen[sig] = ts
            return

        if self._seq_rel(seq, highest) >= 0:
            # 位于窗口之后：正常推进；有缺口说明中间有段未被捕获
            st["highest_end"] = end
            expected = st["next_seq"]
            gap = self._seq_rel(seq, expected) if expected is not None and payload_len else 0
            if gap > 0:
                self.gap_total += 1
                self._bump_conv(conv, "gaps")
                self._expert("note", "丢包",
                             f"TCP 序列号跳跃：期望 {expected}，实际 {seq}，"
                             f"中间约 {gap} 字节未被捕获", rec.id, ts)
            # 无论是否发生缺口都推进到新末端，否则同一缺口会被后续每个包
            # 重复上报；缺口里的段真正晚到时会走 rel<0 分支判为「乱序」
            st["next_seq"] = end
            seen[sig] = ts
            self._trim_seen(seen)
            return

        # seq 落在已收范围之内
        end = self._seq_end(seq, seg_len)
        # TCP Keep-Alive 探测：1 字节（或更少）垃圾数据，seq 正好停在接收末端的
        # 前一字节。它真实存在但不是丢包导致的重传 —— 一条僵死连接每秒探测一次，
        # 就能凭一己之力把该流虚报到 40%+ 的重传率。必须与重传区分。
        if seg_len <= 1 and end == highest:
            self.keepalive_total += 1
            self._expert("note", "保活",
                         f"TCP Keep-Alive 探测：{rec.src}:{rec.src_port} → {rec.dst}:{rec.dst_port} "
                         f"Seq={seq}", rec.id, ts)
            seen[sig] = ts
            self._trim_seen(seen)
            return
        prev_ts = seen.get(sig)
        if prev_ts is not None:
            gap = ts - prev_ts
            if gap >= self._MIN_RETRANS_GAP:
                self.retrans_total += 1
                if gap < 0.2:
                    self.fast_retrans += 1
                    kind = "快速重传"
                elif gap < 5.0:
                    self.rto_retrans += 1
                    kind = "超时重传"
                else:
                    self.stale_retrans += 1
                    kind = "陈旧重试"
                self._bump_conv(conv, "retrans")
                self._expert("warn" if gap < 5.0 else "note", "重传",
                             f"TCP {kind}：{rec.src}:{rec.src_port} → {rec.dst}:{rec.dst_port} "
                             f"Seq={seq} Len={payload_len}（距上次 {gap * 1000:.1f}ms）",
                             rec.id, ts)
            else:
                # 同一帧被驱动重复递交，不是真实网络行为，静默忽略
                self.dup_deliveries += 1
        else:
            self.out_of_order_total += 1
            self._bump_conv(conv, "out_of_order")
            kind = "乱序" if self._seq_rel(end, highest) <= 0 else "部分重叠"
            self._expert("note", "乱序",
                         f"TCP {kind}：{rec.src}:{rec.src_port} → {rec.dst}:{rec.dst_port} "
                         f"Seq={seq} Len={payload_len}（该方向已收到至 {highest}）",
                         rec.id, ts)
        seen[sig] = ts
        self._trim_seen(seen)

    def _track_ack(self, rec, st, fl: int, payload_len: int, ts: float) -> None:
        if not (fl & TCP_ACK):
            return
        if payload_len == 0:
            if rec.ack is not None and st["last_ack"] == rec.ack:
                st["dup_acks"] += 1
                if st["dup_acks"] == 3:
                    self._expert("note", "重传", f"收到 3 个重复 ACK（Ack={rec.ack}），对端触发快速重传",
                                 rec.id, ts)
            else:
                st["dup_acks"] = 0
            st["last_ack"] = rec.ack
        if rec.window == 0 and not (fl & TCP_SYN):
            if not st["zero_win"]:
                self._expert("warn", "性能", f"TCP 零窗口通告：{rec.src}:{rec.src_port} 接收窗口为 0，可能存在性能瓶颈",
                             rec.id, ts)
            st["zero_win"] = True
        else:
            st["zero_win"] = False

    def _expert(self, severity: str, group: str, text: str, packet_id: int, ts: float) -> None:
        self.experts.append({"id": len(self.experts) + 1, "severity": severity, "group": group,
                             "text": text, "packet_id": packet_id,
                             "time": time.strftime("%H:%M:%S", time.localtime(ts))})
        # 同步记到逐包标记，供报文详情页展示（对齐 Wireshark 的 TCP Analysis Flags）
        if not self.pkt_notes_capped and packet_id:
            notes = self.pkt_notes.get(packet_id)
            if notes is None:
                if len(self.pkt_notes) >= 30000:
                    self.pkt_notes_capped = True
                    return
                notes = self.pkt_notes[packet_id] = []
            flag = _WS_FLAG.get(group, group)
            if all(n["flag"] != flag for n in notes):
                notes.append({"flag": flag, "severity": severity, "text": text, "group": group})

    def notes_for(self, packet_id: int) -> List[Dict[str, Any]]:
        """取某包的 TCP 分析标记（无则空列表）。"""
        return self.pkt_notes.get(packet_id) or []

    # ------------------------------------------------------------ 输出
    def summary(self) -> Dict[str, Any]:
        dur = 0.0
        if self.start_ts and self.last_ts:
            dur = max(self.last_ts - self.start_ts, 0.001)
        return {
            "packets": self.total_packets,
            "bytes": self.total_bytes,
            "duration": round(dur, 3),
            "avg_pps": round(self.total_packets / dur, 1) if dur else 0,
            "avg_bps": round(self.total_bytes * 8 / dur, 1) if dur else 0,
            "peak_pps": round(self.peak_pps, 1),
            "peak_bps": round(self.peak_bps, 1),
            "tcp_streams": len(self.stream_ids),
            "retransmissions": self.retrans_total,
            "fast_retrans": self.fast_retrans,
            "rto_retrans": self.rto_retrans,
            "stale_retrans": self.stale_retrans,
            "keepalives": self.keepalive_total,
            "out_of_order": self.out_of_order_total,
            "gaps": self.gap_total,
            "dup_deliveries": self.dup_deliveries,
            "dns_failures": self.dns_fail,
            "http_errors": self.http_errors,
            "expert_count": len(self.experts),
            "start_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.start_ts)) if self.start_ts else "",
        }

    def protocol_stats(self) -> List[Dict[str, Any]]:
        total = self.total_packets or 1
        dur = max((self.last_ts or 0) - (self.start_ts or 0), 0.001)
        out = []
        for proto, cnt in sorted(self.proto_counter.items(), key=lambda kv: -kv[1]):
            out.append({"protocol": proto, "packets": cnt, "bytes": self.proto_bytes[proto],
                        "percent": round(cnt * 100.0 / total, 2),
                        "pps": round(cnt / dur, 1),
                        "bps": round(self.proto_bytes[proto] * 8 / dur, 1)})
        return out

    def conversations(self, limit: int = 500, sort_by: str = "bytes") -> List[Dict[str, Any]]:
        out = []
        for (a, ap, b, bp), c in self.convs.items():
            dur = max(c.end - c.start, 0.0001)
            out.append({"src": a, "src_port": ap, "dst": b, "dst_port": bp,
                        "packets": c.packets, "bytes": c.bytes,
                        "src_packets": c.src_packets, "dst_packets": c.dst_packets,
                        "src_bytes": c.src_bytes, "dst_bytes": c.dst_bytes,
                        "duration": round(dur, 3), "bps": round(c.bytes * 8 / dur, 1),
                        "retrans": c.retrans,
                        "stream": self.stream_ids.get((a, ap, b, bp), 0)})
        out.sort(key=lambda x: -(x.get(sort_by) or 0))
        return out[:limit]

    def endpoints(self, limit: int = 500) -> List[Dict[str, Any]]:
        out = []
        for addr, e in self.eps.items():
            out.append({"address": addr, "packets": e.packets, "bytes": e.bytes,
                        "tx_packets": e.tx_packets, "rx_packets": e.rx_packets,
                        "tx_bytes": e.tx_bytes, "rx_bytes": e.rx_bytes})
        out.sort(key=lambda x: -x["bytes"])
        return out[:limit]

    def port_stats(self, limit: int = 500) -> List[Dict[str, Any]]:
        out = []
        for port, p in self.ports.items():
            out.append({"port": port, "tcp": p.get("tcp", 0), "udp": p.get("udp", 0),
                        "packets": p["packets"], "bytes": p["bytes"],
                        "streams": len(p["streams"]), "peers": len(p["peers"]),
                        "services": sorted(p["services"])[:4],
                        "last_seen": time.strftime("%H:%M:%S", time.localtime(p["last_ts"])) if p["last_ts"] else ""})
        out.sort(key=lambda x: -x["bytes"])
        return out[:limit]

    def expert_info(self, severity: str = "all", limit: int = 500) -> List[Dict[str, Any]]:
        items = list(self.experts)
        if severity != "all":
            items = [i for i in items if i["severity"] == severity]
        return items[-limit:]

    def anomalies(self) -> List[Dict[str, Any]]:
        """规则驱动的异常摘要（供 AI 与仪表盘用）。"""
        res: List[Dict[str, Any]] = []
        dur = max((self.last_ts or 0) - (self.start_ts or 0), 0.001)
        # 只有快速/超时重传反映当前链路质量；间隔 > 5s 的陈旧重试另算，
        # 否则半开连接会把重传率虚高到失真（实测可达 6%，而 ping 零丢包）。
        link_retrans = self.fast_retrans + self.rto_retrans
        retrans_rate = link_retrans * 100.0 / max(self.total_packets, 1)
        if retrans_rate > 1:
            res.append({"level": "high" if retrans_rate > 5 else "medium",
                        "type": "链路质量：重传率偏高",
                        "detail": f"TCP 快速/超时重传 {link_retrans} 次，占全部报文 {retrans_rate:.2f}%"
                                  f"（快速 {self.fast_retrans} / 超时 {self.rto_retrans}），"
                                  f"通常意味着链路丢包、拥塞或对端处理慢"})
        if self.stale_retrans:
            res.append({"level": "low", "type": f"陈旧连接重试 {self.stale_retrans} 次",
                        "detail": "重传间隔超过 5 秒，多为半开连接或应用层重试，"
                                  "不代表当前链路质量；若集中在同一会话说明该连接已僵死"})
        if self.keepalive_total:
            res.append({"level": "low", "type": f"TCP Keep-Alive 探测 {self.keepalive_total} 次",
                        "detail": "空闲连接的保活探针被计入单独类别，不参与重传率统计；"
                                  "若某条会话占比极高，说明该连接长时间无数据交互"})
        errs = [e for e in self.experts if e["severity"] == "error"]
        warns = [e for e in self.experts if e["severity"] == "warn"]
        if errs:
            res.append({"level": "high", "type": f"严重事件 {len(errs)} 条",
                        "detail": "；".join(e["text"][:60] for e in errs[-3:])})
        if warns:
            res.append({"level": "medium", "type": f"警告事件 {len(warns)} 条",
                        "detail": "；".join(e["text"][:60] for e in warns[-3:])})
        if self.dns_fail:
            res.append({"level": "medium", "type": f"DNS 失败 {self.dns_fail} 次",
                        "detail": "存在解析失败的响应（rcode != 0），检查 DNS 服务器或域名配置"})
        if self.http_errors:
            res.append({"level": "medium", "type": f"HTTP 错误响应 {self.http_errors} 次",
                        "detail": "出现 4xx/5xx 响应，结合 URI 定位具体接口"})
        if self.total_packets > 100 and self.broadcast_pkts / self.total_packets > 0.2:
            res.append({"level": "medium", "type": "广播/组播占比过高",
                        "detail": f"广播报文占比 {self.broadcast_pkts * 100 / self.total_packets:.1f}%，可能存在广播风暴"})
        for src, ports in self.syn_scan_src.items():
            if len(ports) >= 12:
                res.append({"level": "high", "type": f"疑似端口扫描：{src}",
                            "detail": f"向 {len(ports)} 个不同端口发送 SYN"})
        top = self.conversations(limit=1)
        if top and self.total_bytes:
            share = top[0]["bytes"] * 100.0 / self.total_bytes
            if share > 40:
                res.append({"level": "low", "type": "流量高度集中",
                            "detail": f"{top[0]['src']}:{top[0]['src_port']} ↔ {top[0]['dst']}:{top[0]['dst_port']} "
                                      f"占总流量 {share:.1f}%"})
        if not res:
            res.append({"level": "low", "type": "未发现明显异常", "detail": f"已分析 {self.total_packets} 个报文，持续 {dur:.1f}s"})
        return res

    def recent_rate(self, window: int = 5) -> Dict[str, float]:
        now = int(time.time())
        pk = by = 0
        for s in range(now - window + 1, now + 1):
            pk += self._sec_packets.get(s, 0)
            by += self._sec_bytes.get(s, 0)
        return {"pps": round(pk / window, 1), "bps": round(by * 8 / window, 1)}
