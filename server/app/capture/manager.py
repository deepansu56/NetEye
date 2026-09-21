"""捕获管理器：串起引擎、解析器、统计聚合、持久化与 WebSocket 推送。"""
from __future__ import annotations

import asyncio
import csv
import io
import json
import threading
import time
import uuid
from collections import deque
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

from ..core.config import CAPTURE_DIR, settings
from ..core.models import InterfaceInfo

from ..filters.display_filter import compile_filter
from ..parser import tree
from ..parser.dissect import PacketRecord, detail, parse
from ..stats.aggregator import Aggregator
from ..storage import db, pcapio
from .base import LINK_ETHERNET, LINK_RAW
from .raw_engine import RawSocketEngine
from .scapy_engine import ScapyEngine


_KNOWN_EXTS = (".pcap", ".pcapng", ".cap", ".json", ".csv")


def _ensure_ext(filename: str, fmt: str) -> str:
    """用户指定的导出文件名若没写扩展名，自动补齐。

    否则会产出不带后缀的文件，Wireshark / Excel 都无法直接打开。
    """
    name = (filename or "").strip()
    if not name:
        return ""
    if name.lower().endswith(_KNOWN_EXTS):
        return name
    return f"{name}.{fmt}"


class CaptureManager:
    def __init__(self) -> None:
        self.state: str = "idle"                 # idle | running | paused | offline
        self.engine_name: str = ""
        self.linktype: int = LINK_ETHERNET
        self.agg = Aggregator()
        self.records: Deque[PacketRecord] = deque()
        self.raws: Dict[int, bytes] = {}
        self._seq = 0
        self.session_id: str = ""
        self.current: Dict[str, Any] = {}
        self.pcap_path: Optional[str] = None
        self.filter_str: str = ""
        self._pending: List[dict] = []
        self._pending_lock = threading.Lock()
        self._subs: List[asyncio.Queue] = []
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._flush_task: Optional[asyncio.Task] = None
        self._filter_cache: Dict[Tuple[str, int], Any] = {}
        self.error: str = ""
        self.engine: Any = None

    # ------------------------------------------------------------ 引擎/接口
    def engine_status(self) -> Dict[str, Any]:
        npcap_ok = ScapyEngine.check()
        raw_ok = RawSocketEngine.check()
        return {
            "npcap": {"available": npcap_ok, "reason": ScapyEngine.reason or "Npcap 就绪"},
            "raw": {"available": raw_ok, "reason": RawSocketEngine.reason or "Raw socket 可用"},
            "active": self.engine_name,
            "state": self.state,
            "error": self.error,
        }

    # 伪适配器 / 抓不到实际流量的接口名特征
    _PSEUDO_HINTS = ("wan miniport", "pseudo-interface", "loopback", "bluetooth",
                     "wi-fi direct", "virtual adapter", "km-test", "tap-", "npcap")

    @classmethod
    def _iface_score(cls, item: Dict[str, Any]) -> int:
        """给网卡打分，越大越适合作为默认抓包口。

        Npcap 枚举出来的第一条往往是 "本地连接* N"(WAN Miniport) 这类伪适配器，
        选它抓包会得到 0 个包。这里把真实在用的网卡排到最前面。
        """
        name = (item.get("name") or "").lower()
        desc = (item.get("description") or "").lower()
        ip = item.get("ip") or ""
        score = 0
        if ip:
            score += 100
            if not (ip.startswith("169.254") or ip.startswith("127.")):
                score += 60                      # 链路本地地址通常是没网的口
            if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
                score += 20
        if any(h in name or h in desc for h in cls._PSEUDO_HINTS):
            score -= 150
        if item.get("is_up", True):
            score += 10
        if item.get("engine") == "npcap":
            score += 5
        return score

    def interfaces(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        seen = set()
        if ScapyEngine.check():
            try:
                for iface in ScapyEngine().list_interfaces():
                    out.append({**iface.model_dump(), "engine": "npcap"})
                    seen.add(iface.ip)
            except Exception as exc:                                # noqa: BLE001
                self.error = str(exc)
        try:
            for iface in RawSocketEngine().list_interfaces():
                if iface.ip in seen:
                    continue
                out.append({**iface.model_dump(), "engine": "raw"})
        except Exception:                                           # noqa: BLE001
            pass

        out.sort(key=self._iface_score, reverse=True)
        for i, item in enumerate(out):
            item["index"] = i
            item["recommended"] = (i == 0)
        return out

    # ------------------------------------------------------------ 控制
    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def start(self, req: Dict[str, Any]) -> Dict[str, Any]:
        """开始一次全新捕获：清空历史数据后启动引擎。"""
        if self.state == "running":
            return {"ok": False, "error": "已在捕获中"}

        self.agg.reset()
        ring = int(req.get("ring_buffer") or settings.capture.get("ring_buffer", 100000))
        self.records = deque(maxlen=max(ring, 1000))
        self.raws = {}
        self._seq = 0
        self._pending = []
        self._filter_cache = {}
        self.session_id = uuid.uuid4().hex[:12]
        self.current = dict(req)
        self.error = ""
        self.pcap_path = None
        return self._launch()

    def _launch(self) -> Dict[str, Any]:
        """按 self.current 启动引擎。不清空已抓到的数据（供 resume 复用）。"""
        req = self.current or {}
        engine_pref = req.get("engine", "auto")
        use_npcap = ScapyEngine.check()
        if engine_pref == "npcap" and not use_npcap:
            return {"ok": False, "error": f"Npcap 不可用：{ScapyEngine.reason}"}
        if engine_pref == "raw":
            use_npcap = False

        if use_npcap:
            self.engine = ScapyEngine()
            self.engine_name = "npcap"
            self.linktype = LINK_ETHERNET
        else:
            self.engine = RawSocketEngine()
            self.engine_name = "raw"
            self.linktype = LINK_RAW
        self.engine.check()

        if not self.pcap_path and (req.get("save_pcap")
                                   or settings.capture.get("auto_save_pcap")):
            self.pcap_path = str(CAPTURE_DIR / f"neteye_{self.session_id}.pcap")

        iface = req.get("interface")
        if not iface:
            # 未指定时挑评分最高的网卡，避免落到 WAN Miniport 这类伪适配器上（0 包）
            best = self.interfaces()
            iface = best[0].get("name") if best else None
            self.current["interface"] = iface

        try:
            self.engine.start(iface, req.get("bpf_filter", ""),
                              req.get("promisc", True), int(req.get("snaplen", 65535)),
                              self._on_packet)
        except Exception as exc:                                    # noqa: BLE001
            self.error = f"启动失败：{exc}"
            return {"ok": False, "error": self.error}

        self.state = "running"
        if self._loop and self._flush_task is None:
            self._flush_task = self._loop.create_task(self._flush_loop())
        return {"ok": True, "session_id": self.session_id, "engine": self.engine_name,
                "linktype": self.linktype, "pcap_path": self.pcap_path or ""}

    def stop(self) -> Dict[str, Any]:
        if getattr(self, "engine", None) is not None:
            try:
                self.engine.stop()
            except Exception:                                       # noqa: BLE001
                pass
        if self.state == "running":
            self.state = "stopped"
        if self._flush_task:
            self._flush_task.cancel()
            self._flush_task = None
        return {"ok": True, "state": self.state, "packets": len(self.records)}

    def clear(self) -> None:
        self.stop()
        self.records = deque(maxlen=self.records.maxlen or 100000)
        self.raws = {}
        self.agg.reset()
        self._seq = 0
        self.state = "idle"
        self._pending = []
        self._filter_cache = {}

    def pause(self) -> Dict[str, Any]:
        if self.state != "running":
            return {"ok": False, "error": "未在捕获"}
        self.stop()
        self.state = "paused"
        return {"ok": True, "state": "paused"}

    def resume(self) -> Dict[str, Any]:
        """继续捕获：沿用暂停前的会话与数据，不重新计数。"""
        if self.state != "paused":
            return {"ok": False, "error": "只能在暂停后继续"}
        if not self.current:
            return {"ok": False, "error": "没有可继续的捕获配置"}
        return self._launch()

    # ------------------------------------------------------------ 包入口
    def _on_packet(self, raw: bytes, ts: float) -> None:
        if self.state != "running":
            return
        self._seq += 1
        try:
            rec = parse(raw, ts, self.linktype, self._seq)
        except Exception:                                           # noqa: BLE001
            return
        self.records.append(rec)
        ring = self.records.maxlen or 100000
        self.raws[rec.id] = raw
        if len(self.raws) > ring:
            try:
                oldest = next(iter(self.raws))
                self.raws.pop(oldest)
            except StopIteration:
                pass
        try:
            self.agg.add(rec, len(raw))
        except Exception:                                           # noqa: BLE001
            pass
        if self.pcap_path:
            try:
                pcapio.append_pcap(self.pcap_path, ts, raw, self.linktype)
            except Exception:                                       # noqa: BLE001
                pass
        with self._pending_lock:
            if len(self._pending) < 5000:
                self._pending.append(rec.to_summary())

    # ------------------------------------------------------------ WebSocket
    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=50)
        self._subs.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        if q in self._subs:
            self._subs.remove(q)

    async def _flush_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(0.25)
                with self._pending_lock:
                    if not self._pending:
                        if not self._subs:
                            continue
                        payload = {"type": "stats", "data": self.live_stats()}
                    else:
                        items = self._pending[:400]
                        self._pending = self._pending[len(items):]
                        payload = {"type": "packets", "data": items,
                                   "stats": self.live_stats()}
                for q in list(self._subs):
                    try:
                        q.put_nowait(payload)
                    except asyncio.QueueFull:
                        try:
                            q.get_nowait()
                            q.put_nowait(payload)
                        except Exception:                           # noqa: BLE001
                            pass
            except asyncio.CancelledError:
                raise
            except Exception:                                       # noqa: BLE001
                await asyncio.sleep(0.5)

    def live_stats(self) -> Dict[str, Any]:
        s = self.agg.summary()
        s["rate"] = self.agg.recent_rate(3)
        s["state"] = self.state
        s["engine"] = self.engine_name
        s["top_protocols"] = self.agg.protocol_stats()[:6]
        return s

    # ------------------------------------------------------------ 查询
    def _filtered(self, filter_str: str) -> List[PacketRecord]:
        key = (filter_str, len(self.records), self._seq)
        hit = self._filter_cache.get(key)
        if hit is not None:
            return hit
        fn = compile_filter(filter_str)
        recs = list(self.records)
        if fn is None:
            out = recs
        else:
            out = [r for r in recs if _safe(fn, r)]
        if len(self._filter_cache) > 8:
            self._filter_cache.clear()
        self._filter_cache[key] = out
        return out

    def query_packets(self, filter_str: str = "", offset: int = 0, limit: int = 200) -> Dict[str, Any]:
        recs = self._filtered(filter_str)
        total = len(recs)
        page = recs[offset:offset + limit]
        return {"total": total, "offset": offset, "limit": limit,
                "items": [r.to_summary() for r in page]}

    def get_detail(self, pid: int) -> Optional[Dict[str, Any]]:
        rec = next((r for r in self.records if r.id == pid), None)
        raw = self.raws.get(pid)
        if rec is None and raw is None:
            return None
        if rec is None:
            rec = parse(raw, time.time(), self.linktype, pid)
        notes = self.agg.notes_for(pid)
        if raw is None:
            return {"id": pid, "summary": rec.to_summary(), "layers": [], "hex": "",
                    "notes": notes}
        # 使用 Wireshark 风格协议树（tree.py），并注入该包的 TCP 分析标记
        layers = tree.build(raw, self.linktype, rec, notes=notes)
        return {"id": pid, "summary": rec.to_summary(), "layers": layers,
                "hex": tree.hexdump(raw), "notes": notes}

    def io_series(self, filter_str: str = "", bucket_ms: int = 1000, max_buckets: int = 600) -> Dict[str, Any]:
        recs = self._filtered(filter_str)
        if not recs:
            return {"points": [], "bucket_ms": bucket_ms}
        start = recs[0].ts
        end = recs[-1].ts
        span = max(end - start, 0.001)
        bsize = max(bucket_ms, 100) / 1000.0
        n = min(int(span / bsize) + 1, max_buckets)
        if n <= 1:
            bsize = span / 60.0 or 0.001
            n = 60
        buckets = [{"ts": start + i * bsize, "packets": 0, "bytes": 0} for i in range(n + 1)]
        for r in recs:
            idx = int((r.ts - start) / bsize)
            if 0 <= idx <= n:
                buckets[idx]["packets"] += 1
                buckets[idx]["bytes"] += r.length or 0
        pts = [(b["ts"], b["packets"], b["bytes"], b["bytes"] * 8 / bsize) for b in buckets]
        return {"points": pts, "bucket_ms": bucket_ms,
                "fields": ["ts", "packets", "bytes", "bps"], "count": len(recs)}

    def follow_stream(self, pid: int) -> Dict[str, Any]:
        rec = next((r for r in self.records if r.id == pid), None)
        if not rec or not rec.stream:
            return {"available": False, "reason": "该包不属于可跟踪的 TCP/UDP 流"}
        sid = rec.stream
        items = []
        payload_a, payload_b = bytearray(), bytearray()
        for r in self.records:
            if r.stream != sid:
                continue
            raw = self.raws.get(r.id)
            if raw and r.off_payload and r.payload_len:
                chunk = raw[r.off_payload:r.off_payload + r.payload_len]
            else:
                chunk = b""
            if r.src_port == rec.src_port and r.src == rec.src:
                payload_a += chunk
                direction = "A"
            else:
                payload_b += chunk
                direction = "B"
            items.append({"id": r.id, "time": r.time, "src": r.src, "dst": r.dst,
                          "sport": r.src_port, "dport": r.dst_port, "len": r.payload_len or 0,
                          "flags": r.flags, "direction": direction,
                          "text": chunk[:2000].decode("latin-1", "ignore")})
        return {"available": True, "stream": sid, "packets": items,
                "a_text": payload_a.decode("latin-1", "ignore"),
                "b_text": payload_b.decode("latin-1", "ignore"),
                "a_len": len(payload_a), "b_len": len(payload_b)}

    # ------------------------------------------------------------ 持久化 / 导入导出
    def save_session(self, name: str = "", note: str = "") -> Dict[str, Any]:
        sid = self.session_id or uuid.uuid4().hex[:12]
        ts = time.time()
        pcap = self.pcap_path
        if not pcap:
            pcap = str(CAPTURE_DIR / f"neteye_{sid}.pcap")
            try:
                pcapio.write_pcap(pcap, [(r.ts, self.raws[r.id]) for r in self.records if r.id in self.raws],
                                  self.linktype)
            except Exception as exc:                                # noqa: BLE001
                pcap = ""
        rows = [(r.id, r.ts, r.time, r.src, r.dst, r.proto, r.length, r.info,
                 ",".join(r.layers), r.src_port, r.dst_port, r.stream, r.flags)
                for r in self.records]
        db.save_session({"id": sid, "name": name or f"捕获 {time.strftime('%m-%d %H:%M')}",
                         "created_at": ts, "packet_count": len(rows), "pcap_path": pcap,
                         "note": note, "bpf_filter": self.current.get("bpf_filter", ""),
                         "interface": str(self.current.get("interface", "")),
                         "summary": json.dumps(self.agg.summary(), ensure_ascii=False)})
        db.insert_packets(sid, rows)
        return {"ok": True, "id": sid, "packets": len(rows), "pcap_path": pcap}

    def load_pcap(self, path: str, limit: int = 200000) -> Dict[str, Any]:
        self.stop()
        self.agg.reset()
        self.records = deque(maxlen=max(limit, 1000))
        self.raws = {}
        self._seq = 0
        self._filter_cache = {}
        self.session_id = uuid.uuid4().hex[:12]
        count = 0
        for ts, raw, lt in pcapio.read_pcap(path):
            self.linktype = lt
            self._seq += 1
            rec = parse(raw, ts, lt, self._seq)
            self.records.append(rec)
            self.raws[rec.id] = raw
            try:
                self.agg.add(rec, len(raw))
            except Exception:                                       # noqa: BLE001
                pass
            count += 1
            if count >= limit:
                break
        self.state = "offline"
        self.pcap_path = path
        return {"ok": True, "packets": count, "linktype": self.linktype, "path": path}

    def export(self, scope: str = "all", filter_str: str = "", ids: Optional[List[int]] = None,
               fmt: str = "pcap", filename: str = "") -> str:
        if scope == "selected" and ids:
            recs = [r for r in self.records if r.id in set(ids)]
        else:
            recs = self._filtered(filter_str if scope == "filtered" else "")
        stamp = time.strftime("%Y%m%d_%H%M%S")
        name = _ensure_ext(filename, fmt)      # 用户没写后缀时自动补齐
        if fmt == "pcap":
            out = str(CAPTURE_DIR / (name or f"export_{stamp}.pcap"))
            pcapio.write_pcap(out, [(r.ts, self.raws[r.id]) for r in recs if r.id in self.raws], self.linktype)
            return out
        if fmt == "json":
            out = str(CAPTURE_DIR / (name or f"export_{stamp}.json"))
            with open(out, "w", encoding="utf-8") as f:
                json.dump([r.to_summary() for r in recs], f, ensure_ascii=False, indent=1)
            return out
        out = str(CAPTURE_DIR / (name or f"export_{stamp}.csv"))
        with open(out, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.writer(f)
            w.writerow(["No", "Time", "Source", "Destination", "Protocol", "Length", "Info",
                        "SrcPort", "DstPort", "Stream", "Flags"])
            for r in recs:
                w.writerow([r.id, r.time, r.src, r.dst, r.proto, r.length, r.info,
                            r.src_port, r.dst_port, r.stream, r.flags])
        return out


def _safe(fn: Callable[[Any], bool], rec) -> bool:
    try:
        return bool(fn(rec))
    except Exception:                                               # noqa: BLE001
        return False


manager = CaptureManager()
