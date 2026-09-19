"""NetEye 协议解析引擎。

- 快速路径：手写 L2/L3/L4 解析（零依赖、高吞吐），供实时包列表与统计使用。
- 深度路径：详情视图用 scapy 做完整协议树（含偏移、HTTP/DNS/TLS/DoIP/SOME-IP）。
"""
from __future__ import annotations

import datetime as _dt
import re
import socket
import struct
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------- 常量
ETH_IP4, ETH_ARP, ETH_IP6, ETH_VLAN = 0x0800, 0x0806, 0x86DD, 0x8100
IP_PROTO = {1: "ICMP", 6: "TCP", 17: "UDP", 2: "IGMP", 47: "GRE", 58: "ICMPv6", 132: "SCTP"}
TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK, TCP_URG, TCP_ECE, TCP_CWR, TCP_NS = (
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x100)
FLAG_ORDER = [("NS", TCP_NS), ("CWR", TCP_CWR), ("ECE", TCP_ECE), ("URG", TCP_URG),
              ("ACK", TCP_ACK), ("PSH", TCP_PSH), ("RST", TCP_RST), ("SYN", TCP_SYN), ("FIN", TCP_FIN)]
ICMP_TYPES = {0: "Echo Reply", 3: "Destination Unreachable", 8: "Echo Request", 11: "Time Exceeded"}
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS"}
HTTP_PORTS = {80, 8080, 8000, 8008, 8888, 3128}
TLS_PORTS = {443, 8443, 993, 995, 465, 636}
DOIP_PORTS = {13400}
SOMEIP_PORTS = {30490, 30491}


class PacketRecord:
    """紧凑包记录（__slots__，百万级也扛得住内存）。"""

    __slots__ = ("id", "ts", "time", "src", "dst", "proto", "length", "caplen", "info",
                 "layers", "src_port", "dst_port", "stream", "flags", "tcp_flags",
                 "ip_proto", "ttl", "eth_type", "off_eth", "off_ip", "off_l4", "off_payload",
                 "payload_len", "seq", "ack", "window", "icmp_type", "icmp_code",
                 "dns_name", "dns_type", "dns_rcode", "http_method", "http_uri",
                 "http_host", "http_code", "tls_type", "tls_sni", "app", "vlan", "color")

    def __init__(self, **kw: Any) -> None:
        for slot in self.__slots__:
            setattr(self, slot, kw.get(slot, None))
        self.layers: Tuple[str, ...] = tuple(kw.get("layers") or ())
        self.color = ""

    def to_summary(self) -> Dict[str, Any]:
        return {
            "id": self.id, "ts": self.ts, "time": self.time, "src": self.src, "dst": self.dst,
            "proto": self.proto, "length": self.length, "caplen": self.caplen, "info": self.info,
            "layers": list(self.layers), "src_port": self.src_port, "dst_port": self.dst_port,
            "stream": self.stream, "flags": self.flags, "color": self.color,
        }


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def _ipv4(b: bytes) -> str:
    return socket.inet_ntoa(b)


def _ipv6(b: bytes) -> str:
    try:
        return socket.inet_ntop(socket.AF_INET6, b)
    except Exception:
        return b.hex()


def _flags_str(f: int) -> str:
    return "".join(n for n, bit in FLAG_ORDER if f & bit)


def _flags_ws(f: int) -> str:
    return "".join(n if f & bit else "·" for n, bit in FLAG_ORDER)


# ---------------------------------------------------------------- 应用层轻量解析
def _parse_dns(payload: bytes) -> Tuple[str, int, int]:
    """返回 (查询名, qtype, rcode)。"""
    try:
        if len(payload) < 12:
            return "", 0, 0
        tid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", payload[:12])
        rcode = flags & 0x000F
        pos, name = 12, []
        while pos < len(payload):
            ln = payload[pos]
            if ln == 0:
                pos += 1
                break
            if ln & 0xC0:
                pos += 2
                break
            name.append(payload[pos + 1:pos + 1 + ln].decode("utf-8", "ignore"))
            pos += 1 + ln
        qtype = 0
        if pos + 4 <= len(payload):
            qtype = struct.unpack("!H", payload[pos:pos + 2])[0]
        return ".".join(name), qtype, rcode
    except Exception:
        return "", 0, 0


def _parse_http(payload: bytes) -> Tuple[str, str, str, int]:
    """返回 (method, uri, host, code)。"""
    try:
        text = payload[:2048].decode("latin-1", "ignore")
        head = text.split("\r\n\r\n", 1)[0]
        lines = head.split("\r\n")
        if not lines:
            return "", "", "", 0
        start = lines[0]
        host = ""
        for ln in lines[1:]:
            if ln.lower().startswith("host:"):
                host = ln.split(":", 1)[1].strip()
                break
        parts = start.split(" ")
        if start.startswith("HTTP/"):
            # 响应
            code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
            return "", "", host, code
        if len(parts) >= 2 and parts[0] in ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT"):
            return parts[0], parts[1], host, 0
        return "", "", host, 0
    except Exception:
        return "", "", "", 0


def _parse_tls(payload: bytes) -> Tuple[str, str]:
    """返回 (handshake_type 名称, SNI)。"""
    try:
        if len(payload) < 5 or payload[0] not in (0x14, 0x15, 0x16, 0x17):
            return "", ""
        ctype = payload[0]
        name = {0x14: "ChangeCipherSpec", 0x15: "Alert", 0x16: "Handshake", 0x17: "ApplicationData"}.get(ctype, "")
        if ctype != 0x16 or len(payload) < 6:
            return name, ""
        htype = payload[5]
        hname = {1: "ClientHello", 2: "ServerHello", 11: "Certificate", 14: "ServerHelloDone"}.get(htype, f"HS{htype}")
        sni = ""
        if htype == 1:
            m = re.search(rb"[a-zA-Z0-9][a-zA-Z0-9\-]{0,62}(\.[a-zA-Z0-9\-]{1,63})+\x00?", payload)
            if m:
                cand = m.group(0).rstrip(b"\x00")
                if b"." in cand:
                    sni = cand.decode("latin-1", "ignore")
            if not sni:
                for cand in re.findall(rb"(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}", payload[:512]):
                    sni = cand.decode("latin-1", "ignore")
                    break
        return f"{name}:{hname}" if hname else name, sni
    except Exception:
        return "", ""


def _parse_doip(payload: bytes) -> Tuple[int, str]:
    try:
        if len(payload) < 8 or payload[0] != 0x02:
            return 0, ""
        ptype = struct.unpack("!H", payload[2:4])[0]
        names = {0x0005: "RoutingActivation", 0x0006: "RoutingActivationResponse",
                 0x8001: "DiagnosticMessage", 0x8002: "DiagnosticMessageAck",
                 0x8003: "DiagnosticMessageNack", 0x0001: "VehicleIdentificationRequest",
                 0x0004: "VehicleIdentificationResponse", 0x0007: "AliveCheckRequest",
                 0x0008: "AliveCheckResponse"}
        return ptype, names.get(ptype, f"DoIP-0x{ptype:04X}")
    except Exception:
        return 0, ""


def _parse_someip(payload: bytes) -> Tuple[int, str]:
    try:
        if len(payload) < 16:
            return 0, ""
        mid, length, reqid, pver, iver, mtype, rc = struct.unpack("!IIIBBBB", payload[:16])
        return mid, f"MessageID=0x{mid:08X} Method=0x{mid & 0xFFFF:04X} Type=0x{mtype:02X}"
    except Exception:
        return 0, ""


# ---------------------------------------------------------------- 主解析（快速路径）
def parse(raw: bytes, ts: float, linktype: int, idx: int) -> PacketRecord:
    rec = PacketRecord()
    rec.id = idx
    rec.ts = ts
    rec.length = len(raw)
    rec.caplen = len(raw)
    dt = _dt.datetime.fromtimestamp(ts)
    rec.time = dt.strftime("%H:%M:%S.") + f"{dt.microsecond // 1000:03d}"
    layers: List[str] = ["frame"]
    off = 0
    eth_type = None

    if linktype == 1:                      # Ethernet
        if len(raw) < 14:
            rec.proto = "Malformed"
            rec.info = "短帧"
            rec.layers = tuple(layers)
            return rec
    try:
        if linktype == 1:
            dst_m, src_m, eth_type = struct.unpack("!6s6sH", raw[0:14])
            layers.append("eth")
            rec.off_eth = 0
            if eth_type == ETH_VLAN and len(raw) >= 18:
                rec.vlan = struct.unpack("!H", raw[14:16])[0] & 0x0FFF
                eth_type = struct.unpack("!H", raw[16:18])[0]
                off = 18
                layers.append("vlan")
            else:
                off = 14
        elif linktype == 101:              # RAW IPv4
            eth_type, off = ETH_IP4, 0
        elif linktype == 113:              # Linux cooked
            eth_type = struct.unpack("!H", raw[14:16])[0]
            off = 16
        elif linktype == 0:                # NULL / loopback
            eth_type, off = ETH_IP4, 4
        else:
            eth_type, off = ETH_IP4, 0
    except Exception:
        rec.proto, rec.info, rec.layers = "Malformed", "解析失败", tuple(layers)
        return rec

    rec.eth_type = eth_type

    # ---------------- ARP
    if eth_type == ETH_ARP:
        try:
            op = struct.unpack("!H", raw[off + 6:off + 8])[0]
            rec.src = _ipv4(raw[off + 14:off + 18])
            rec.dst = _ipv4(raw[off + 24:off + 28])
            rec.proto = "ARP"
            rec.info = f"{'Who has ' + rec.dst + '? Tell ' + rec.src if op == 1 else rec.src + ' is at ' + _mac(raw[off + 8:off + 14])}"
            layers.append("arp")
            rec.layers = tuple(layers)
            return rec
        except Exception:
            pass

    # ---------------- IPv4
    if eth_type == ETH_IP4:
        ip_off = off
        if len(raw) < ip_off + 20:
            rec.proto, rec.info, rec.layers = "Malformed", "IP 头截断", tuple(layers)
            return rec
        ihl = (raw[ip_off] & 0x0F) * 4
        total = struct.unpack("!H", raw[ip_off + 2:ip_off + 4])[0]
        proto_num = raw[ip_off + 9]
        ttl = raw[ip_off + 8]
        src = _ipv4(raw[ip_off + 12:ip_off + 16])
        dst = _ipv4(raw[ip_off + 16:ip_off + 20])
        ip_id = struct.unpack("!H", raw[ip_off + 4:ip_off + 6])[0]
        l4 = ip_off + ihl
        rec.off_ip, rec.off_l4 = ip_off, l4
        rec.src, rec.dst, rec.ttl, rec.ip_proto = src, dst, ttl, proto_num
        rec.length = max(total, len(raw))
        layers.append("ip")
        name = IP_PROTO.get(proto_num, str(proto_num))

        if proto_num == 6 and len(raw) >= l4 + 20:      # TCP
            sp, dp, seq, ack = struct.unpack("!HHII", raw[l4:l4 + 12])
            doff = (raw[l4 + 12] >> 4) * 4
            flags = raw[l4 + 13] | ((raw[l4 + 12] & 0x01) << 8)
            win = struct.unpack("!H", raw[l4 + 14:l4 + 16])[0]
            payload = raw[l4 + doff:]
            rec.src_port, rec.dst_port = sp, dp
            rec.seq, rec.ack, rec.window = seq, ack, win
            rec.tcp_flags, rec.flags = flags, _flags_str(flags)
            rec.off_payload, rec.payload_len = l4 + doff, len(payload)
            rec.proto = "TCP"
            layers.append("tcp")
            info = [f"{sp} → {dp}", f"[{_flags_str(flags)}]", f"Seq={seq}"]
            if flags & TCP_ACK:
                info.append(f"Ack={ack}")
            info.append(f"Win={win}")
            info.append(f"Len={len(payload)}")
            # 应用层轻量识别
            hint = _app_hint(rec, payload, layers)
            if hint:
                info.append(hint)
            rec.info = " ".join(info)
            rec.layers = tuple(layers)
            return rec

        if proto_num == 17 and len(raw) >= l4 + 8:      # UDP
            sp, dp, ulen = struct.unpack("!HHH", raw[l4:l4 + 6])
            payload = raw[l4 + 8:]
            rec.src_port, rec.dst_port = sp, dp
            rec.off_payload, rec.payload_len = l4 + 8, len(payload)
            rec.proto = "UDP"
            layers.append("udp")
            info = [f"{sp} → {dp}", f"Len={len(payload)}"]
            hint = _app_hint(rec, payload, layers)
            if hint:
                info.append(hint)
            rec.info = " ".join(info)
            rec.layers = tuple(layers)
            return rec

        if proto_num == 1:                              # ICMP
            itype, icode = raw[l4], raw[l4 + 1]
            rec.icmp_type, rec.icmp_code = itype, icode
            rec.proto = "ICMP"
            layers.append("icmp")
            extra = ""
            if itype in (0, 8) and len(raw) >= l4 + 8:
                ident, seqn = struct.unpack("!HH", raw[l4 + 4:l4 + 8])
                extra = f" id=0x{ident:04x} seq={seqn}"
            rec.info = f"{ICMP_TYPES.get(itype, 'Type ' + str(itype))} code={icode}{extra}"
            rec.layers = tuple(layers)
            return rec

        rec.proto = name
        rec.info = f"{src} → {dst} {name}"
        rec.layers = tuple(layers)
        return rec

    # ---------------- IPv6
    if eth_type == ETH_IP6:
        ip_off = off
        nh = raw[ip_off + 6]
        src = _ipv6(raw[ip_off + 8:ip_off + 24])
        dst = _ipv6(raw[ip_off + 24:ip_off + 40])
        l4 = ip_off + 40
        rec.off_ip, rec.off_l4 = ip_off, l4
        rec.src, rec.dst, rec.ip_proto = src, dst, nh
        rec.ttl = raw[ip_off + 7]
        layers.append("ipv6")
        rec.proto = IP_PROTO.get(nh, str(nh))
        if nh == 6 and len(raw) >= l4 + 20:
            sp, dp, seq, ack = struct.unpack("!HHII", raw[l4:l4 + 12])
            doff = (raw[l4 + 12] >> 4) * 4
            flags = raw[l4 + 13] | ((raw[l4 + 12] & 0x01) << 8)
            rec.src_port, rec.dst_port, rec.seq, rec.ack = sp, dp, seq, ack
            rec.tcp_flags, rec.flags = flags, _flags_str(flags)
            rec.window = struct.unpack("!H", raw[l4 + 14:l4 + 16])[0]
            rec.proto = "TCP"
            layers.append("tcp")
            rec.info = f"{sp} → {dp} [{_flags_str(flags)}] Seq={seq} Win={rec.window} Len={len(raw) - l4 - doff}"
        elif nh == 17 and len(raw) >= l4 + 8:
            sp, dp = struct.unpack("!HH", raw[l4:l4 + 4])
            rec.src_port, rec.dst_port = sp, dp
            rec.proto = "UDP"
            layers.append("udp")
            rec.info = f"{sp} → {dp} Len={len(raw) - l4 - 8}"
        elif nh == 58:
            rec.icmp_type, rec.icmp_code = raw[l4], raw[l4 + 1]
            rec.proto = "ICMPv6"
            layers.append("icmpv6")
            rec.info = f"ICMPv6 type={rec.icmp_type} code={rec.icmp_code}"
        else:
            rec.info = f"{src} → {dst} {rec.proto}"
        rec.layers = tuple(layers)
        return rec

    rec.proto = f"EthType-0x{eth_type:04X}"
    rec.info = f"未识别的以太网类型 0x{eth_type:04X}"
    rec.layers = tuple(layers)
    return rec


def _app_hint(rec: PacketRecord, payload: bytes, layers: List[str]) -> str:
    """按端口/内容识别应用层协议，写入 rec 并返回摘要片段。"""
    if not payload:
        return ""
    ports = {rec.src_port, rec.dst_port}
    if ports & DOIP_PORTS:
        ptype, name = _parse_doip(payload)
        if name:
            rec.app, rec.proto = "DoIP", "DoIP"
            rec.tls_type = ptype
            layers.append("doip")
            return f"[{name}]"
    if ports & SOMEIP_PORTS:
        mid, name = _parse_someip(payload)
        if name:
            rec.app = "SOME/IP"
            layers.append("someip")
            return f"[{name}]"
    if ports & {53, 5353}:
        name, qtype, rcode = _parse_dns(payload)
        if name:
            rec.dns_name, rec.dns_type, rec.dns_rcode = name, qtype, rcode
            rec.app = "DNS"
            layers.append("dns")
            qr = "响应" if (rcode or qtype and payload[2] & 0x80) else "查询"
            return f"[{qr} {name} {DNS_TYPES.get(qtype, str(qtype))}]"
    if ports & TLS_PORTS:
        htype, sni = _parse_tls(payload)
        if htype:
            rec.tls_type = htype
            rec.tls_sni = sni
            rec.app = "TLS"
            layers.append("tls")
            return f"[{htype}{(' ' + sni) if sni else ''}]"
    if ports & HTTP_PORTS or payload[:3] in (b"GET", b"PUT", b"POS", b"HEA", b"DEL", b"OPT", b"PAT", b"CON") \
            or payload[:5] == b"HTTP/":
        method, uri, host, code = _parse_http(payload)
        if method:
            rec.http_method, rec.http_uri, rec.http_host = method, uri, host
            rec.app = "HTTP"
            layers.append("http")
            return f"[{method} {uri[:60]}{(' Host:' + host) if host else ''}]"
        if code:
            rec.http_code = code
            rec.app = "HTTP"
            layers.append("http")
            return f"[响应 {code}]"
    return ""


# ---------------------------------------------------------------- 深度解析（详情视图）
def detail(raw: bytes, linktype: int, rec: Optional[PacketRecord] = None) -> Tuple[List[Dict[str, Any]], str]:
    """生成带字节偏移的完整协议树 + 十六进制视图。"""
    if rec is None:
        rec = parse(raw, 0, linktype, 0)
    layers: List[Dict[str, Any]] = []
    f = lambda n, v, o=-1, s=-1: {"name": n, "value": str(v), "offset": o, "size": s}
    layers.append({"name": "frame", "title": f"Frame {rec.id}: {rec.length} bytes on wire", "fields": [
        f("frame.number", rec.id), f("frame.time", rec.time), f("frame.len", rec.length),
        f("frame.cap_len", rec.caplen)]})

    o = rec.off_eth if rec.off_eth is not None else 0
    if linktype == 1 and len(raw) >= 14:
        dst, src, et = struct.unpack("!6s6sH", raw[o:o + 14])
        fields = [f("eth.dst", _mac(dst), o, 6), f("eth.src", _mac(src), o + 6, 6),
                  f("eth.type", f"0x{et:04x}", o + 12, 2)]
        layers.append({"name": "eth", "title": f"Ethernet II, Src: {_mac(src)}, Dst: {_mac(dst)}", "fields": fields})
    if rec.off_ip is not None and rec.eth_type in (ETH_IP4, 0x0800):
        io = rec.off_ip
        ver, tos, tot, ident, frag, ttl, proto_num = (
            raw[io] >> 4, raw[io + 1], *struct.unpack("!HH", raw[io + 2:io + 6]),
            struct.unpack("!H", raw[io + 6:io + 8])[0], raw[io + 8], raw[io + 9])
        df = "DF" if frag & 0x4000 else ""
        mf = "MF" if frag & 0x2000 else ""
        layers.append({"name": "ip", "title": f"Internet Protocol v4, Src: {rec.src}, Dst: {rec.dst}", "fields": [
            f("ip.version", 4, io, 1), f("ip.ihl", (raw[io] & 0x0F), io, 1), f("ip.tos", tos, io + 1, 1),
            f("ip.len", tot, io + 2, 2), f("ip.id", f"0x{ident:04x}", io + 4, 2),
            f("ip.flags", f"{df}{mf}", io + 6, 2), f("ip.ttl", ttl, io + 8, 1),
            f("ip.proto", IP_PROTO.get(proto_num, proto_num), io + 9, 1),
            f("ip.src", rec.src, io + 12, 4), f("ip.dst", rec.dst, io + 16, 4)]})
    if rec.proto == "TCP" and rec.off_l4 is not None:
        lo = rec.off_l4
        sp, dp, seq, ack = struct.unpack("!HHII", raw[lo:lo + 12])
        doff = (raw[lo + 12] >> 4) * 4
        fl = raw[lo + 13] | ((raw[lo + 12] & 0x01) << 8)
        win, chk, urg = struct.unpack("!HHH", raw[lo + 14:lo + 20])
        fields = [f("tcp.srcport", sp, lo, 2), f("tcp.dstport", dp, lo + 2, 2),
                  f("tcp.seq", seq, lo + 4, 4), f("tcp.ack", ack, lo + 8, 4),
                  f("tcp.data_offset", doff // 4, lo + 12, 1),
                  f("tcp.flags", f"0x{fl:03x} ({_flags_ws(fl)})", lo + 13, 1)]
        for n, bit in FLAG_ORDER:
            fields.append(f(f"tcp.flags.{n.lower()}", 1 if fl & bit else 0, -1, -1))
        fields += [f("tcp.window", win, lo + 14, 2), f("tcp.checksum", f"0x{chk:04x}", lo + 16, 2),
                   f("tcp.urgent", urg, lo + 18, 2)]
        if doff > 20:
            opts = raw[lo + 20:lo + doff]
            fields.append(f("tcp.options", opts.hex(), lo + 20, len(opts)))
        layers.append({"name": "tcp", "title": f"Transmission Control Protocol, Src Port: {sp}, Dst Port: {dp}, "
                                               f"Seq: {seq}, Ack: {ack}, Len: {rec.payload_len}", "fields": fields})
    elif rec.proto == "UDP" and rec.off_l4 is not None:
        lo = rec.off_l4
        sp, dp, ulen, chk = struct.unpack("!HHHH", raw[lo:lo + 8])
        layers.append({"name": "udp", "title": f"User Datagram Protocol, Src Port: {sp}, Dst Port: {dp}",
                       "fields": [f("udp.srcport", sp, lo, 2), f("udp.dstport", dp, lo + 2, 2),
                                  f("udp.length", ulen, lo + 4, 2), f("udp.checksum", f"0x{chk:04x}", lo + 6, 2)]})
    elif rec.proto in ("ICMP", "ICMPv6") and rec.off_l4 is not None:
        lo = rec.off_l4
        layers.append({"name": rec.proto.lower(), "title": f"{rec.proto} (type={rec.icmp_type}, code={rec.icmp_code})",
                       "fields": [f("icmp.type", rec.icmp_type, lo, 1), f("icmp.code", rec.icmp_code, lo + 1, 1)]})
    elif rec.proto == "ARP":
        layers.append({"name": "arp", "title": f"ARP {rec.info}", "fields": [
            f("arp.src", rec.src, -1, -1), f("arp.dst", rec.dst, -1, -1)]})

    # 应用层（用 scapy 增强，失败则退回已有摘要）
    payload = raw[rec.off_payload:] if rec.off_payload else b""
    if payload:
        app_layer = _deep_app(rec, payload, f)
        if app_layer:
            layers.append(app_layer)
        else:
            layers.append({"name": "data", "title": f"Data ({len(payload)} bytes)",
                           "fields": [f("data.text", payload[:200].hex(), rec.off_payload or 0, len(payload))]})

    # 十六进制视图
    lines = []
    for i in range(0, len(raw), 16):
        chunk = raw[i:i + 16]
        hx = " ".join(f"{b:02x}" for b in chunk)
        hx = hx.ljust(47)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:08x}  {hx}  {asc}")
    return layers, "\n".join(lines)


def _deep_app(rec: PacketRecord, payload: bytes, f) -> Optional[Dict[str, Any]]:
    """应用层深度解析：优先 scapy，失败用内置轻量解析。"""
    try:
        if rec.app == "DNS" or (rec.dns_name and "dns" in rec.layers):
            name, qtype, rcode = _parse_dns(payload)
            return {"name": "dns", "title": f"Domain Name System ({'response' if rcode or (payload[2] & 0x80) else 'query'})",
                    "fields": [f("dns.qry.name", name), f("dns.qry.type", DNS_TYPES.get(qtype, qtype)),
                               f("dns.flags.rcode", rcode), f("dns.id", struct.unpack('!H', payload[:2])[0] if len(payload) > 2 else 0)]}
        if rec.app == "HTTP":
            method, uri, host, code = _parse_http(payload)
            if code:
                return {"name": "http", "title": f"HTTP Response {code}",
                        "fields": [f("http.response.code", code), f("http.host", host),
                                   f("http.content", payload[:200].decode('latin-1', 'ignore'))]}
            return {"name": "http", "title": f"HTTP Request: {method} {uri}",
                    "fields": [f("http.request.method", method), f("http.request.uri", uri),
                               f("http.host", host), f("http.raw", payload[:200].decode('latin-1', 'ignore'))]}
        if rec.app == "TLS":
            htype, sni = _parse_tls(payload)
            return {"name": "tls", "title": f"TLS {htype}",
                    "fields": [f("tls.record.content_type", payload[0]), f("tls.handshake.type", htype),
                               f("tls.sni", sni)]}
        if rec.app == "DoIP":
            ptype, name = _parse_doip(payload)
            return {"name": "doip", "title": f"DoIP {name}",
                    "fields": [f("doip.version", payload[0] if payload else 0),
                               f("doip.payload_type", f"0x{ptype:04X}"),
                               f("doip.payload_length", struct.unpack('!I', payload[4:8])[0] if len(payload) >= 8 else 0)]}
        if rec.app == "SOME/IP":
            mid, name = _parse_someip(payload)
            return {"name": "someip", "title": f"SOME/IP {name}",
                    "fields": [f("someip.message_id", f"0x{mid:08X}" if mid else ""), f("someip.info", name)]}
    except Exception:
        return None
    return None
