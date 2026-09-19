"""Wireshark 风格协议树解析器（详情视图专用）。

与 `dissect.parse()` 的"快速路径"互补：这里追求的是**信息完整度**而不是吞吐，
输出可折叠的嵌套协议树，每个字段带：

    name    Wireshark 显示过滤器字段名（如 tcp.flags.syn、dns.qry.name）
    label   人类可读的字段名（如 "Source Port"）
    value   字段值（已格式化）
    offset  相对整个报文（frame）的字节偏移，-1 表示无法定位
    size    字节长度，0 表示生成字段/位字段
    desc    字段含义解释（对应 Wireshark 状态栏的字段说明）
    bits    位字段的位掩码描述（可选）

覆盖：Frame / Ethernet / 802.1Q / ARP / IPv4 / IPv6 / ICMP / ICMPv6 / TCP（含选项
逐个展开）/ UDP / DNS（问题 + 资源记录）/ HTTP（逐头部）/ TLS（记录层 + 握手 +
扩展）/ DoIP / SOME/IP / 原始数据。整体结构对齐 Wireshark 的 Packet Details 面板。
"""
from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional, Tuple

from .dissect import (
    DNS_TYPES, ETH_ARP, ETH_IP4, ETH_IP6, ETH_VLAN, FLAG_ORDER,
    ICMP_TYPES, IP_PROTO, PacketRecord, _mac,
)

Field = Dict[str, Any]

# ------------------------------------------------------------------ 字段构造
def _f(name: str, label: str, value: Any, off: int = -1, size: int = 0,
       desc: str = "", bits: str = "") -> Field:
    f: Field = {"name": name, "label": label, "value": str(value),
                "offset": off, "size": size}
    if desc:
        f["desc"] = desc
    if bits:
        f["bits"] = bits
    return f


def _layer(name: str, title: str, fields: List[Field],
           children: Optional[List[Dict[str, Any]]] = None, desc: str = "") -> Dict[str, Any]:
    node: Dict[str, Any] = {"name": name, "title": title, "fields": fields,
                            "children": children or []}
    if desc:
        node["desc"] = desc
    return node


# ------------------------------------------------------------------ 小工具
def _hexdump(data: bytes, base: int) -> str:
    lines: List[str] = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hx = " ".join(f"{b:02x}" for b in chunk).ljust(47)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base + i:08x}  {hx}  {asc}")
    return "\n".join(lines)


def hexdump(raw: bytes) -> str:
    """报文十六进制视图（0 基偏移，每秒 16 字节一行，右侧 ASCII）。"""
    return _hexdump(raw, 0)


def _ipv4_checksum_ok(header: bytes) -> bool:
    if len(header) % 2:
        header += b"\x00"
    total = 0
    for i in range(0, len(header), 2):
        total += (header[i] << 8) | header[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total == 0xFFFF


def _oui_name(mac: str) -> str:
    """极简 OUI 表：只覆盖最常见的几家，避免引入外部依赖。"""
    prefix = mac[:8].lower()
    return {
        "b0:47:e9": "IntelCorporate", "00:1a:2b": "Cisco", "00:0c:29": "Vmware",
        "a4:5e:60": "Apple", "3c:22:fb": "Apple",
    }.get(prefix, "")


DNS_CLASS = {1: "IN", 3: "CH", 4: "HS", 255: "ANY"}
DNS_OPCODE = {0: "Query", 1: "IQuery", 2: "Status", 4: "Notify", 5: "Update"}
DNS_RCODE = {0: "No error", 1: "Format error", 2: "Server failure",
             3: "No such name", 4: "Not implemented", 5: "Refused"}

TLS_CONTENT = {20: "Change Cipher Spec", 21: "Alert", 22: "Handshake", 23: "Application Data",
               24: "Heartbeat"}
TLS_HS = {0: "Hello Request", 1: "Client Hello", 2: "Server Hello", 4: "New Session Ticket",
          8: "Encrypted Extensions", 11: "Certificate", 12: "Server Key Exchange",
          13: "Certificate Request", 14: "Server Hello Done", 15: "Certificate Verify",
          16: "Client Key Exchange", 20: "Finished"}
TLS_VER = {0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3",
           0x0300: "SSL 3.0"}
TLS_EXTS = {0: "server_name", 10: "supported_groups", 11: "ec_point_formats",
            13: "signature_algorithms", 16: "application_layer_protocol_negotiation",
            21: "padding", 23: "extended_master_secret", 35: "session_ticket",
            43: "supported_versions", 45: "psk_key_exchange_modes", 51: "key_share",
            65281: "renegotiation_info"}
TLS_CIPHERS = {
    0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256", 0x1304: "TLS_AES_128_CCM_SHA256",
    0xC02B: "ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02F: "ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC02C: "ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0x009C: "RSA_WITH_AES_128_GCM_SHA256", 0x009D: "RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
}
TLS_GROUPS = {0x001D: "x25519", 0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1",
              0x0100: "ffdhe2048", 0x0101: "ffdhe3072", 0x001E: "x448"}

DOIP_TYPES = {0x0000: "GenericNegativeAcknowledge", 0x0001: "VehicleIdentificationRequest",
              0x0002: "VehicleIdentificationRequestWithEID",
              0x0003: "VehicleIdentificationRequestWithVIN",
              0x0004: "VehicleAnnouncement/IdentificationResponse",
              0x0005: "RoutingActivationRequest", 0x0006: "RoutingActivationResponse",
              0x0007: "AliveCheckRequest", 0x0008: "AliveCheckResponse",
              0x4001: "DoIPEntityStatusRequest", 0x4002: "DoIPEntityStatusResponse",
              0x4003: "DiagnosticPowerModeInformationRequest",
              0x4004: "DiagnosticPowerModeInformationResponse",
              0x8001: "DiagnosticMessage", 0x8002: "DiagnosticMessagePositiveAck",
              0x8003: "DiagnosticMessageNegativeAck"}

SOMEIP_MTYPE = {0x00: "REQUEST", 0x01: "REQUEST_NO_RETURN", 0x02: "NOTIFICATION",
                0x80: "RESPONSE", 0x81: "ERROR"}
SOMEIP_RC = {0x00: "E_OK", 0x01: "E_NOT_OK", 0x02: "E_UNKNOWN_SERVICE",
             0x03: "E_UNKNOWN_METHOD", 0x04: "E_NOT_READY", 0x05: "E_NOT_REACHABLE",
             0x06: "E_TIMEOUT", 0x07: "E_WRONG_PROTOCOL_VERSION",
             0x08: "E_WRONG_INTERFACE_VERSION", 0x09: "E_MALFORMED_MESSAGE"}

HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE")
HDR_FIELDS = {
    "host": ("http.host", "Host"),
    "user-agent": ("http.user_agent", "User-Agent"),
    "accept": ("http.accept", "Accept"),
    "accept-encoding": ("http.accept_encoding", "Accept-Encoding"),
    "accept-language": ("http.accept_language", "Accept-Language"),
    "connection": ("http.connection", "Connection"),
    "content-type": ("http.content_type", "Content-Type"),
    "content-length": ("http.content_length_header", "Content-Length"),
    "cookie": ("http.cookie", "Cookie"),
    "referer": ("http.referer", "Referer"),
    "origin": ("http.origin", "Origin"),
    "server": ("http.server", "Server"),
    "date": ("http.date", "Date"),
    "cache-control": ("http.cache_control", "Cache-Control"),
    "location": ("http.location", "Location"),
    "set-cookie": ("http.set_cookie", "Set-Cookie"),
    "transfer-encoding": ("http.transfer_encoding", "Transfer-Encoding"),
}


# ------------------------------------------------------------------ IPv4
def _ipv4_layer(raw: bytes, rec: PacketRecord) -> Optional[Dict[str, Any]]:
    io = rec.off_ip
    if io is None or io + 20 > len(raw):
        return None
    ver_ihl, tos, tot, ident, frag, ttl, proto_num, chk = struct.unpack(
        "!BBHHHBBH", raw[io:io + 12])
    ver, ihl = ver_ihl >> 4, ver_ihl & 0x0F
    hlen = ihl * 4
    df, mf = bool(frag & 0x4000), bool(frag & 0x2000)
    flag_str = "".join(x for x, on in (("DF", df), ("MF", mf)) if on) or "None"
    fields = [
        _f("ip.version", "Version", ver, io, 1, "IP 协议版本，IPv4 固定为 4",
           bits=".... 0100"),
        _f("ip.hdr_len", "Header Length", hlen, io, 1,
           f"首部长度 {ihl} × 4 = {hlen} 字节（含选项）", bits=".... 0101"),
        _f("ip.dsfield", "Differentiated Services Field", f"0x{tos:02x}", io + 1, 1,
           "服务类型：包含 DSCP（高 6 位）与 ECN（低 2 位）"),
        _f("ip.dsfield.dscp", "Differentiated Services Codepoint", tos >> 2, -1, 0, ""),
        _f("ip.dsfield.ecn", "Explicit Congestion Notification", tos & 0x03, -1, 0,
           "0=不支持 ECN，1/2=支持 ECN，3=拥塞已标记（CE）"),
        _f("ip.len", "Total Length", tot, io + 2, 2, "首部 + 数据的字节总数"),
        _f("ip.id", "Identification", f"0x{ident:04x} ({ident})", io + 4, 2,
           "分片重组时用于判定同属一个原始报文"),
        _f("ip.flags", "Flags", f"0x{frag >> 13:01x}", io + 6, 1,
           f"分片标志：{flag_str}"),
    ]
    flags_children = [_layer("ip.flags_tree", "[IPv4 Flags]", [
        _f("ip.flags.rb", "Reserved bit", 1 if frag & 0x8000 else 0, io + 6, 1, "保留位，应为 0"),
        _f("ip.flags.df", "Don't fragment", 1 if df else 0, io + 6, 1,
           "置位表示该报文不允许分片"),
        _f("ip.flags.mf", "More fragments", 1 if mf else 0, io + 6, 1,
           "置位表示后面还有分片"),
    ])]
    fields += [
        _f("ip.frag_offset", "Fragment Offset", frag & 0x1FFF, io + 6, 2,
           "相对原始报文数据起点的偏移（8 字节为单位）"),
        _f("ip.ttl", "Time to Live", ttl, io + 8, 1, "每经过一个路由器减 1，为 0 时丢弃"),
        _f("ip.proto", "Protocol", IP_PROTO.get(proto_num, proto_num), io + 9, 1,
           "承载的上层协议编号"),
        _f("ip.checksum", "Header Checksum", f"0x{chk:04x}", io + 10, 2,
           "仅覆盖首部的校验和"),
    ]
    if hlen >= 20 and io + hlen <= len(raw):
        ok = _ipv4_checksum_ok(raw[io:io + hlen])
        fields.append(_f("ip.checksum.status", "Header checksum status",
                         "Good" if ok else "Bad", -1, 0,
                         "本机重算首部校验和的结果；Bad 通常意味着报文在传输中被破坏"))
    fields += [
        _f("ip.src", "Source Address", rec.src or "", io + 12, 4, "源 IP 地址"),
        _f("ip.dst", "Destination Address", rec.dst or "", io + 16, 4, "目的 IP 地址"),
    ]
    return _layer("ip", f"Internet Protocol Version 4, Src: {rec.src}, Dst: {rec.dst}",
                  fields, flags_children,
                  desc="IPv4 网络层首部，负责寻址与分片")


# ------------------------------------------------------------------ IPv6
def _ipv6_layer(raw: bytes, rec: PacketRecord) -> Optional[Dict[str, Any]]:
    io = rec.off_ip
    if io is None or io + 40 > len(raw):
        return None
    head = raw[io:io + 40]
    vtc = struct.unpack("!I", head[:4])[0]
    ver = vtc >> 28
    tclass = (vtc >> 20) & 0xFF
    flow = vtc & 0xFFFFF
    plen, nxt, hlim = struct.unpack("!HBB", head[4:8])
    return _layer("ipv6", f"Internet Protocol Version 6, Src: {rec.src}, Dst: {rec.dst}", [
        _f("ipv6.version", "Version", ver, io, 1, "IPv6 固定为 6"),
        _f("ipv6.tclass", "Traffic Class", f"0x{tclass:02x}", io, 0, "流量类别（类似 IPv4 TOS）"),
        _f("ipv6.flow", "Flow Label", f"0x{flow:05x}", io + 1, 3, "流标签，用于标识同一条流"),
        _f("ipv6.plen", "Payload Length", plen, io + 4, 2, "除首部外的负载长度"),
        _f("ipv6.nxt", "Next Header", IP_PROTO.get(nxt, nxt), io + 6, 1, "下一个首部类型"),
        _f("ipv6.hlim", "Hop Limit", hlim, io + 7, 1, "跳数限制，等价于 IPv4 TTL"),
        _f("ipv6.src", "Source Address", rec.src or "", io + 8, 16, ""),
        _f("ipv6.dst", "Destination Address", rec.dst or "", io + 24, 16, ""),
    ], desc="IPv6 网络层首部")


# ------------------------------------------------------------------ TCP
def _tcp_options(raw: bytes, lo: int, doff: int, rec: PacketRecord) -> List[Dict[str, Any]]:
    """逐条展开 TCP 选项（Wireshark 的 Options 子树）。"""
    opts = raw[lo + 20:lo + doff]
    kids: List[Dict[str, Any]] = []
    idx = 0
    while idx < len(opts):
        kind = opts[idx]
        if kind == 0:
            kids.append(_layer("tcp.options.eol", "TCP Option - End of Option List (EOL)", [
                _f("tcp.options.eol.kind", "Kind", 0, lo + 20 + idx, 1, "选项类型 0，标志选项区结束")]))
            idx += 1
            break
        if kind == 1:
            kids.append(_layer("tcp.options.nop", "TCP Option - No-Operation (NOP)", [
                _f("tcp.options.nop.kind", "Kind", 1, lo + 20 + idx, 1, "填充字节，用于对齐")]))
            idx += 1
            continue
        if idx + 2 > len(opts):
            break
        olen = opts[idx + 1]
        body = opts[idx + 2:idx + olen]
        base = lo + 20 + idx
        head = [_f("tcp.options.kind", "Kind", kind, base, 1, "选项类型"),
                _f("tcp.options.length", "Length", olen, base + 1, 1, "选项总长度（含 Kind/Length）")]
        if kind == 2 and len(body) >= 2:
            mss = struct.unpack("!H", body[:2])[0]
            meta = ("tcp.options.mss", f"TCP Option - Maximum segment size: {mss} bytes",
                    [head, _f("tcp.options.mss_val", "MSS Value", mss, base + 2, 2,
                              "本端可接收的最大 TCP 载荷长度，通常为 MTU - 40")])
        elif kind == 3 and len(body) >= 1:
            shift = body[0]
            meta = ("tcp.options.wscale", f"TCP Option - Window scale: {shift} (multiply by {2 ** shift})",
                    [head, _f("tcp.options.wscale.shift", "Shift count", shift, base + 2, 1,
                              f"接收窗口将左移 {shift} 位，即实际窗口放大 {2 ** shift} 倍"),
                     _f("tcp.options.wscale.multiplier", "Multiply by", 2 ** shift, -1, 0, "")])
        elif kind == 4:
            meta = ("tcp.options.sack_perm", "TCP Option - SACK permitted",
                    [head, _f("tcp.options.sack_perm.sack_perm", "SACK Permitted", 1, -1, 0,
                              "声明本端支持选择性确认（RFC 2018）")])
        elif kind == 5:
            blocks = []
            for i in range(0, len(body) - 7, 8):
                left, right = struct.unpack("!II", body[i:i + 8])
                blocks.append(_f(f"tcp.options.sack_le[{i // 8}]", "left edge", left,
                                 base + 2 + i, 4, "已收到的区间起点（序列号）"))
                blocks.append(_f(f"tcp.options.sack_re[{i // 8}]", "right edge", right,
                                 base + 6 + i, 4, "区间终点（不含）"))
            meta = ("tcp.options.sack", "TCP Option - SACK", [head] + blocks)
        elif kind == 8 and len(body) >= 8:
            tsval, tsecr = struct.unpack("!II", body[:8])
            meta = ("tcp.options.timestamp", "TCP Option - Timestamps", [
                head,
                _f("tcp.options.timestamp.tsval", "Timestamp value", tsval, base + 2, 4,
                   "发送方当前时间戳，用于 RTT 测量"),
                _f("tcp.options.timestamp.tsecr", "Timestamp echo reply", tsecr, base + 6, 4,
                   "回显对端最近一次的时间戳，为 0 表示对端未启用")])
        else:
            meta = (f"tcp.options.type{kind}", f"TCP Option - kind {kind}",
                    [head, _f("tcp.options.data", "Option Data", body.hex(), base + 2, len(body), "")])
        kids.append(_layer(meta[0], meta[1], meta[2]))
        idx += max(olen, 2)
    return kids


def _tcp_layer(raw: bytes, rec: PacketRecord) -> Optional[Dict[str, Any]]:
    lo = rec.off_l4
    if lo is None or lo + 20 > len(raw):
        return None
    sp, dp, seq, ack = struct.unpack("!HHII", raw[lo:lo + 12])
    doff = (raw[lo + 12] >> 4) * 4
    fl = raw[lo + 13] | ((raw[lo + 12] & 0x01) << 8)
    win, chk, urg = struct.unpack("!HHH", raw[lo + 14:lo + 20])
    seglen = max(rec.payload_len or 0, 0)
    fields = [
        _f("tcp.srcport", "Source Port", sp, lo, 2, f"源端口 {sp}"),
        _f("tcp.dstport", "Destination Port", dp, lo + 2, 2, f"目的端口 {dp}"),
        _f("tcp.stream", "Stream index", rec.stream if rec.stream else 0, -1, 0,
           "NetEye 为该 TCP 流分配的序号，同一会话的双向报文共享"),
        _f("tcp.len", "TCP Segment Len", seglen, -1, 0, "本段携带的 TCP 载荷字节数"),
        _f("tcp.seq", "Sequence Number", seq, lo + 4, 4,
           f"绝对序列号；相对序号 {seq}"),
        _f("tcp.seq_raw", "Sequence Number (raw)", seq, lo + 4, 4, "原始序列号，不经相对换算"),
        _f("tcp.ack", "Acknowledgment Number", ack, lo + 8, 4,
           "期望收到的下一个序列号"),
        _f("tcp.hdr_len", "Header Length", doff, lo + 12, 1,
           f"数据偏移 {doff // 4} × 4 = {doff} 字节"),
        _f("tcp.flags", "Flags", f"0x{fl:03x}", lo + 12, 2,
           "TCP 标志位：" + ", ".join(n for n, bit in FLAG_ORDER if fl & bit)),
    ]
    flag_children = [_layer("tcp.flags_tree", "[TCP Flags]", [
        _f(f"tcp.flags.{n.lower()}", n, 1 if fl & bit else 0, lo + 13, 1,
           {
               "FIN": "发送方已无数据，请求关闭连接",
               "SYN": "建立连接时同步序列号",
               "RST": "异常重置连接",
               "PSH": "要求接收方尽快把数据交给应用层",
               "ACK": "确认号字段有效",
               "URG": "紧急指针字段有效",
               "ECE": "ECN 回显（对端曾标记拥塞）",
               "CWR": "拥塞窗口已减小",
               "NS": "ECN-nonce 隐藏保护",
           }.get(n, ""))
        for n, bit in FLAG_ORDER])]
    fields += [
        _f("tcp.window_size_value", "Window", win, lo + 14, 2,
           f"本端通告的接收窗口 {win} 字节，为 0 表示暂停发送"),
        _f("tcp.checksum", "Checksum", f"0x{chk:04x}", lo + 16, 2,
           "含伪首部的校验和；网卡校验和卸载会使抓到的值无效"),
        _f("tcp.checksum.status", "Checksum Status", "Unverified", -1, 0,
           "本机不校验 TCP 校验和：现代网卡做校验和卸载，抓包时该字段常为占位值"),
        _f("tcp.urgent_pointer", "Urgent Pointer", urg, lo + 18, 2,
           "紧急数据的偏移量，仅当 URG 置位时有意义"),
    ]
    children: List[Dict[str, Any]] = list(flag_children)
    if doff > 20:
        opts_children = _tcp_options(raw, lo, doff, rec)
        if opts_children:
            children.append(_layer("tcp.options", f"[TCP Options] ({len(opts_children)} 项)",
                                   [ _f("tcp.options.count", "Option Count", len(opts_children), -1, 0,
                                        "本段携带的 TCP 选项数量")], opts_children))
    title = (f"Transmission Control Protocol, Src Port: {sp}, Dst Port: {dp}, "
             f"Seq: {seq}, Ack: {ack}, Len: {seglen}")
    return _layer("tcp", title, fields, children,
                  desc="TCP 传输层首部，提供面向连接的可靠传输")


# ------------------------------------------------------------------ UDP / ICMP
def _udp_layer(raw: bytes, rec: PacketRecord) -> Optional[Dict[str, Any]]:
    lo = rec.off_l4
    if lo is None or lo + 8 > len(raw):
        return None
    sp, dp, ulen, chk = struct.unpack("!HHHH", raw[lo:lo + 8])
    return _layer("udp", f"User Datagram Protocol, Src Port: {sp}, Dst Port: {dp}", [
        _f("udp.srcport", "Source Port", sp, lo, 2, f"源端口 {sp}"),
        _f("udp.dstport", "Destination Port", dp, lo + 2, 2, f"目的端口 {dp}"),
        _f("udp.length", "Length", ulen, lo + 4, 2, "首部 + 数据的字节总数"),
        _f("udp.checksum", "Checksum", f"0x{chk:04x}", lo + 6, 2,
           "含伪首部的校验和；网卡校验和卸载时该值不可信"),
    ], desc="UDP 传输层首部，无连接、不保证可靠")


def _icmp_layer(raw: bytes, rec: PacketRecord) -> Optional[Dict[str, Any]]:
    lo = rec.off_l4
    if lo is None or lo + 4 > len(raw):
        return None
    t, c, chk = struct.unpack("!BBH", raw[lo:lo + 4])
    desc = ICMP_TYPES.get(t, "未知 ICMP 类型")
    fields = [
        _f("icmp.type", "Type", f"{t} ({desc})", lo, 1, "ICMP 报文类型"),
        _f("icmp.code", "Code", c, lo + 1, 1, "同类型下的细分原因码"),
        _f("icmp.checksum", "Checksum", f"0x{chk:04x}", lo + 2, 2, "ICMP 校验和"),
    ]
    if t in (0, 8) and lo + 8 <= len(raw):
        ident, seq = struct.unpack("!HH", raw[lo + 4:lo + 8])
        fields += [_f("icmp.ident", "Identifier", f"0x{ident:04x}", lo + 4, 2,
                      "用于匹配请求与应答的标识（ping 里常是进程号）"),
                   _f("icmp.seq", "Sequence Number", seq, lo + 6, 2, "序列号，逐个递增")]
    return _layer("icmp", f"Internet Control Message Protocol, Type: {t} ({desc}), Code: {c}",
                  fields, desc="ICMP 控制报文，ping / traceroute 等依赖它")


def _icmpv6_layer(raw: bytes, rec: PacketRecord) -> Optional[Dict[str, Any]]:
    lo = rec.off_l4
    if lo is None or lo + 4 > len(raw):
        return None
    t, c, chk = struct.unpack("!BBH", raw[lo:lo + 4])
    names = {1: "Destination Unreachable", 2: "Packet Too Big", 3: "Time Exceeded",
             128: "Echo Request", 129: "Echo Reply", 133: "Router Solicitation",
             134: "Router Advertisement", 135: "Neighbor Solicitation",
             136: "Neighbor Advertisement"}
    return _layer("icmpv6", f"Internet Control Message Protocol v6, Type: {t} "
                            f"({names.get(t, '未知')}), Code: {c}", [
        _f("icmpv6.type", "Type", t, lo, 1, ""),
        _f("icmpv6.code", "Code", c, lo + 1, 1, ""),
        _f("icmpv6.checksum", "Checksum", f"0x{chk:04x}", lo + 2, 2, ""),
    ], desc="ICMPv6 控制报文")


def _arp_layer(raw: bytes, rec: PacketRecord) -> Optional[Dict[str, Any]]:
    o = rec.off_eth if rec.off_eth is not None else 0
    base = o + 14
    if base + 28 > len(raw):
        return None
    hw, pt, hlen, plen, op = struct.unpack("!HHBBH", raw[base:base + 8])
    sha = _mac(raw[base + 8:base + 14])
    spa = ".".join(str(b) for b in raw[base + 14:base + 18])
    tha = _mac(raw[base + 18:base + 24])
    tpa = ".".join(str(b) for b in raw[base + 24:base + 28])
    ops = {1: "request", 2: "reply", 3: "reverse request", 4: "reverse reply"}
    return _layer("arp", f"Address Resolution Protocol ({ops.get(op, op)})", [
        _f("arp.hw.type", "Hardware type", f"Ethernet (1)", base, 2, "硬件地址类型"),
        _f("arp.proto.type", "Protocol type", f"IPv4 (0x0800)", base + 2, 2, "上层协议类型"),
        _f("arp.hw.size", "Hardware size", hlen, base + 4, 1, "硬件地址长度，以太网为 6"),
        _f("arp.proto.size", "Protocol size", plen, base + 5, 1, "协议地址长度，IPv4 为 4"),
        _f("arp.opcode", "Opcode", f"{op} ({ops.get(op, op)})", base + 6, 2, "ARP 操作码"),
        _f("arp.src.hw_mac", "Sender MAC address", sha, base + 8, 6, "发送方硬件地址"),
        _f("arp.src.proto_ipv4", "Sender IP address", spa, base + 14, 4, "发送方协议地址"),
        _f("arp.dst.hw_mac", "Target MAC address", tha, base + 18, 6,
           "目标硬件地址，请求报文里为全 0"),
        _f("arp.dst.proto_ipv4", "Target IP address", tpa, base + 24, 4, "目标协议地址"),
    ], desc="ARP 地址解析：把 IP 地址映射到 MAC 地址")


# ------------------------------------------------------------------ DNS
def _dns_name(buf: bytes, pos: int, base: int, depth: int = 0) -> Tuple[str, int, int]:
    """解析（可能带压缩指针的）域名，返回 (名字, 下一个位置, 名字起点)。"""
    start = pos
    if depth > 12 or pos >= len(buf):
        return "", pos, pos
    labels: List[str] = []
    cur, end, jumped = pos, pos, False
    while cur < len(buf):
        ln = buf[cur]
        if ln == 0:
            cur += 1
            if not jumped:
                end = cur
            break
        if ln & 0xC0 == 0xC0:
            if cur + 1 >= len(buf):
                break
            ptr = ((ln & 0x3F) << 8) | buf[cur + 1]
            if not jumped:
                end = cur + 2
            sub, _, _ = _dns_name(buf, ptr, base, depth + 1)
            if sub:
                labels.append(sub)
            jumped = True
            break
        labels.append(buf[cur + 1:cur + 1 + ln].decode("latin-1", "ignore"))
        cur += 1 + ln
        if not jumped:
            end = cur
    return ".".join(labels), end, start


def _dns_rr(buf: bytes, pos: int, base: int) -> Tuple[Optional[Dict[str, Any]], int]:
    name, pos, name_off = _dns_name(buf, pos, base)
    if pos + 10 > len(buf):
        return None, pos
    rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", buf[pos:pos + 10])
    rd_off = pos + 10
    kids = [
        _f("dns.resp.name", "Name", name, base + name_off, pos - name_off, ""),
        _f("dns.resp.type", "Type", f"{DNS_TYPES.get(rtype, rtype)} ({rtype})", base + pos, 2, ""),
        _f("dns.resp.class", "Class", f"{DNS_CLASS.get(rclass, rclass)} (0x{rclass:04x})",
           base + pos + 2, 2, ""),
        _f("dns.resp.ttl", "Time to live", ttl, base + pos + 4, 4, "该记录可缓存秒数"),
        _f("dns.resp.len", "Data length", rdlen, base + pos + 8, 2, ""),
    ]
    rd = buf[rd_off:rd_off + rdlen]
    if rtype == 1 and rdlen == 4:                       # A
        kids.append(_f("dns.a", "Address", ".".join(str(b) for b in rd), base + rd_off, 4,
                       "IPv4 地址"))
    elif rtype == 28 and rdlen == 16:                   # AAAA
        import socket as _s
        try:
            addr = _s.inet_ntop(_s.AF_INET6, rd)
        except Exception:
            addr = rd.hex()
        kids.append(_f("dns.aaaa", "Address", addr, base + rd_off, 16, "IPv6 地址"))
    elif rtype in (5, 2, 12):                           # CNAME / NS / PTR
        nm, _, _ = _dns_name(buf, rd_off, base)
        kids.append(_f({5: "dns.cname", 2: "dns.ns", 12: "dns.ptr"}[rtype],
                       {5: "CNAME", 2: "Name Server", 12: "PTR"}[rtype], nm,
                       base + rd_off, rdlen, ""))
    elif rtype == 15 and rdlen >= 3:                    # MX
        pref = struct.unpack("!H", rd[:2])[0]
        nm, _, _ = _dns_name(buf, rd_off + 2, base)
        kids += [_f("dns.mx.preference", "Preference", pref, base + rd_off, 2, ""),
                 _f("dns.mx.mail_exchange", "Mail Exchange", nm, base + rd_off + 2, 0, "")]
    elif rtype == 16:                                   # TXT
        txt = rd[1:1 + rd[0]].decode("latin-1", "ignore") if rd else ""
        kids.append(_f("dns.txt", "TXT", txt, base + rd_off, rdlen, ""))
    elif rtype == 33 and rdlen >= 7:                    # SRV
        pri, weight, port = struct.unpack("!HHH", rd[:6])
        nm, _, _ = _dns_name(buf, rd_off + 6, base)
        kids += [_f("dns.srv.priority", "Priority", pri, base + rd_off, 2, ""),
                 _f("dns.srv.weight", "Weight", weight, base + rd_off + 2, 2, ""),
                 _f("dns.srv.port", "Port", port, base + rd_off + 4, 2, ""),
                 _f("dns.srv.target", "Target", nm, base + rd_off + 6, 0, "")]
    else:
        kids.append(_f("dns.rdata", "RData", rd.hex(), base + rd_off, rdlen, ""))
    return _layer(f"dns.resp_{rtype}_{rd_off}", f"{DNS_TYPES.get(rtype, rtype)} Record",
                  kids), rd_off + rdlen


def _dns_layer(buf: bytes, base: int, tcp: bool = False) -> Optional[Dict[str, Any]]:
    off = 2 if tcp else 0          # TCP 承载时前 2 字节是长度前缀
    if len(buf) < off + 12:
        return None
    tid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", buf[off:off + 12])
    is_resp = bool(flags & 0x8000)
    opcode = (flags >> 11) & 0x0F
    rcode = flags & 0x000F
    fields = [
        _f("dns.id", "Transaction ID", f"0x{tid:04x}", base + off, 2,
           "客户端生成的事务 ID，应答需原样返回"),
        _f("dns.flags", "Flags", f"0x{flags:04x}", base + off + 2, 2, "包含下列各个标志位"),
        _f("dns.count.queries", "Questions", qd, base + off + 4, 2, "问题区条目数"),
        _f("dns.count.answers", "Answer RRs", an, base + off + 6, 2, "答案区资源记录数"),
        _f("dns.count.auth_rr", "Authority RRs", ns, base + off + 8, 2, "权威区资源记录数"),
        _f("dns.count.add_rr", "Additional RRs", ar, base + off + 10, 2, "附加区资源记录数"),
    ]
    flag_children = [_layer("dns.flags_tree", "[DNS Flags]", [
        _f("dns.flags.response", "Response", 1 if is_resp else 0, base + off + 2, 1,
           "0=查询，1=应答"),
        _f("dns.flags.opcode", "Opcode", f"{opcode} ({DNS_OPCODE.get(opcode, '?')})",
           base + off + 2, 1, "查询类型（Query / Update 等）"),
        _f("dns.flags.authoritative", "Authoritative", 1 if flags & 0x0400 else 0, base + off + 2, 1,
           "应答由该域的权威服务器给出"),
        _f("dns.flags.truncated", "Truncated", 1 if flags & 0x0200 else 0, base + off + 2, 1,
           "置位表示报文被截断，需改用 TCP 重发"),
        _f("dns.flags.recdesired", "Recursion desired", 1 if flags & 0x0100 else 0, base + off + 2, 1,
           "客户端要求递归解析"),
        _f("dns.flags.recavail", "Recursion available", 1 if flags & 0x0080 else 0, base + off + 2, 1,
           "服务器支持递归查询"),
        _f("dns.flags.rcode", "Reply code", f"{rcode} ({DNS_RCODE.get(rcode, '?')})",
           base + off + 3, 1, "应答码，非 0 表示解析失败"),
    ])]
    children = list(flag_children)
    pos = off + 12
    q_children: List[Dict[str, Any]] = []
    for _i in range(qd):
        name, pos2, noff = _dns_name(buf, pos, base)
        if pos2 + 4 > len(buf):
            break
        qtype, qclass = struct.unpack("!HH", buf[pos2:pos2 + 4])
        q_children.append(_layer(f"dns.qry_{noff}", f"Queries · {name or '<root>'}", [
            _f("dns.qry.name", "Name", name or "<root>", base + noff, pos2 - noff,
               "被查询的域名"),
            _f("dns.qry.type", "Type", f"{DNS_TYPES.get(qtype, qtype)} ({qtype})",
               base + pos2, 2, "查询的记录类型"),
            _f("dns.qry.class", "Class", f"{DNS_CLASS.get(qclass, qclass)} (0x{qclass:04x})",
               base + pos2 + 2, 2, "查询类别，IN 表示 Internet"),
        ]))
        pos = pos2 + 4
    if q_children:
        children.append(_layer("dns.queries", f"Queries ({qd})", [], q_children))
    ans_children: List[Dict[str, Any]] = []
    for _i in range(an):
        rr, pos = _dns_rr(buf, pos, base)
        if rr is None:
            break
        ans_children.append(rr)
    if ans_children:
        children.append(_layer("dns.answers", f"Answers ({an})", [], ans_children))
    for i in range(ns):
        rr, pos = _dns_rr(buf, pos, base)
        if rr is None:
            break
        children.append(_layer(f"dns.auth_{i}", "Authority Record", [], [rr]))
    return {"name": "dns", "title": f"Domain Name System ({'response' if is_resp else 'query'})",
            "fields": fields, "children": children,
            "desc": "DNS 域名解析报文（RFC 1035）"}


# ------------------------------------------------------------------ HTTP
def _http_layer(payload: bytes, base: int) -> Optional[Dict[str, Any]]:
    text = payload[:4096].decode("latin-1", "ignore")
    head = text.split("\r\n\r\n", 1)[0]
    lines = head.split("\r\n")
    if not lines or not lines[0]:
        return None
    first = lines[0]
    fields: List[Field] = []
    line_off = 0
    title = ""
    if first.startswith("HTTP/"):
        parts = first.split(" ", 2)
        code = parts[1] if len(parts) > 1 else ""
        phrase = parts[2] if len(parts) > 2 else ""
        fields += [
            _f("http.response.version", "Response Version", parts[0], base, len(parts[0]),
               "HTTP 协议版本"),
            _f("http.response.code", "Status Code", code, base + len(parts[0]) + 1, len(code),
               "3 位状态码，2xx 成功 / 3xx 重定向 / 4xx 客户端错误 / 5xx 服务端错误"),
            _f("http.response.phrase", "Reason Phrase", phrase, -1, 0, "状态码的文本描述"),
        ]
        title = f"HTTP/1.1 {code} {phrase}"
    else:
        parts = first.split(" ")
        if len(parts) < 2 or parts[0] not in HTTP_METHODS:
            return None
        fields += [
            _f("http.request.method", "Request Method", parts[0], base, len(parts[0]),
               "HTTP 请求方法"),
            _f("http.request.uri", "Request URI", parts[1], base + len(parts[0]) + 1, len(parts[1]),
               "请求路径（含查询串）"),
        ]
        if len(parts) > 2:
            fields.append(_f("http.request.version", "Request Version", parts[2], -1, 0,
                             "HTTP 协议版本"))
        title = f"{parts[0]} {parts[1]}"
    pos = len(first) + 2
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            key = k.strip()
            fname, label = HDR_FIELDS.get(key.lower(), (f"http.header.{key.lower()}", key))
            fields.append(_f(fname, label, v.strip(), base + pos, len(ln),
                             f"HTTP 头部字段 {key}"))
            # 常见头部补一个 Wireshark 风格的语义解释
            if key.lower() == "content-length":
                fields.append(_f("http.content_length", "Content Length", v.strip(),
                                 base + pos, len(ln), "报文体字节数"))
        pos += len(ln) + 2
    tag = "Response" if first.startswith("HTTP/") else "Request"
    return {"name": "http", "title": f"Hypertext Transfer Protocol · {title}",
            "fields": fields, "children": [],
            "desc": f"HTTP {tag}，明文超文本传输协议（RFC 7230）"}


# ------------------------------------------------------------------ TLS
def _tls_layer(payload: bytes, base: int) -> Optional[Dict[str, Any]]:
    if len(payload) < 5:
        return None
    ctype, rver, rlen = payload[0], struct.unpack("!H", payload[1:3])[0], \
        struct.unpack("!H", payload[3:5])[0]
    if ctype not in TLS_CONTENT or rver >> 8 != 3:
        return None
    children: List[Dict[str, Any]] = []
    fields = [
        _f("tls.record.content_type", "Content Type",
           f"{ctype} ({TLS_CONTENT.get(ctype, '未知')})", base, 1, "记录层承载的内容类型"),
        _f("tls.record.version", "Version", f"0x{rver:04x} ({TLS_VER.get(rver, '?')})",
           base + 1, 2, "记录层协议版本"),
        _f("tls.record.length", "Length", rlen, base + 3, 2, "后续记录内容长度"),
    ]
    if ctype == 22 and len(payload) >= 9:
        hs_off = base + 5
        htype = payload[5]
        hlen = int.from_bytes(payload[6:9], "big")
        hname = TLS_HS.get(htype, f"Handshake {htype}")
        hs_fields = [
            _f("tls.handshake.type", "Handshake Type", f"{htype} ({hname})", hs_off, 1, ""),
            _f("tls.handshake.length", "Length", hlen, hs_off + 1, 3, ""),
        ]
        body = payload[9:9 + hlen]
        b_off = base + 9
        if htype in (1, 2) and len(body) >= 34:
            v = struct.unpack("!H", body[:2])[0]
            hs_fields += [
                _f("tls.handshake.version", "Version", f"0x{v:04x} ({TLS_VER.get(v, '?')})",
                   b_off, 2, "客户端支持的最高协议版本（TLS 1.3 时代仅作兼容值）"),
                _f("tls.handshake.random", "Random", body[2:34].hex(), b_off + 2, 32,
                   "32 字节随机数，参与密钥派生"),
            ]
            p = 34
            sid_len = body[p] if p < len(body) else 0
            hs_fields.append(_f("tls.handshake.session_id", "Session ID",
                                body[p + 1:p + 1 + sid_len].hex() or "(空)", b_off + p + 1, sid_len,
                                "会话 ID，用于恢复会话"))
            p += 1 + sid_len
            if htype == 1 and p + 2 <= len(body):       # ClientHello
                cs_len = struct.unpack("!H", body[p:p + 2])[0]
                p += 2
                suites = struct.unpack(f"!{cs_len // 2}H", body[p:p + cs_len]) if cs_len else ()
                names = [TLS_CIPHERS.get(s, f"0x{s:04x}") for s in suites]
                hs_fields.append(_f("tls.handshake.ciphersuites", "Cipher Suites",
                                    f"{cs_len // 2} 套", b_off + p - 2, cs_len + 2,
                                    "客户端支持的加密套件列表"))
                suite_kids = [_f(f"tls.handshake.ciphersuite[{i}]", f"Cipher Suite", nm,
                                 b_off + p + i * 2, 2, "") for i, nm in enumerate(names[:48])]
                children.append(_layer("tls.handshake.ciphersuites_tree",
                                       f"[Cipher Suites] ({len(names)})", suite_kids))
                p += cs_len
                cm_len = body[p] if p < len(body) else 0
                p += 1 + cm_len
                if p + 2 <= len(body):
                    ext_len = struct.unpack("!H", body[p:p + 2])[0]
                    p += 2
                    ext_end = min(p + ext_len, len(body))
                    ext_kids: List[Dict[str, Any]] = []
                    while p + 4 <= ext_end:
                        etype, elen = struct.unpack("!HH", body[p:p + 4])
                        ename = TLS_EXTS.get(etype, f"extension 0x{etype:04x}")
                        ebody = body[p + 4:p + 4 + elen]
                        if etype == 0 and len(ebody) >= 5:      # SNI
                            nlen = struct.unpack("!H", ebody[3:5])[0]
                            sni = ebody[5:5 + nlen].decode("latin-1", "ignore")
                            ext_kids.append(_layer("tls.ext.sni", f"Extension: {ename} (len={elen})", [
                                _f("tls.handshake.extensions_server_name", "Server Name Indication",
                                   sni, b_off + p + 9, nlen,
                                   "客户端希望访问的域名（TLS 握手明文可见，是识别访问目标的关键）")] ))
                        elif etype == 43 and len(ebody) >= 1:
                            n = ebody[0]
                            vers = [struct.unpack("!H", ebody[1 + i * 2:3 + i * 2])[0]
                                    for i in range(n // 2)]
                            ext_kids.append(_layer("tls.ext.supver", f"Extension: {ename} (len={elen})", [
                                _f("tls.handshake.extensions_supported_version",
                                   "Supported Versions",
                                   ", ".join(TLS_VER.get(v, f"0x{v:04x}") for v in vers),
                                   b_off + p + 4, elen, "客户端支持的所有 TLS 版本")]))
                        elif etype == 10:
                            n = struct.unpack("!H", ebody[:2])[0] if len(ebody) >= 2 else 0
                            gs = [struct.unpack("!H", ebody[2 + i * 2:4 + i * 2])[0]
                                  for i in range(n // 2)]
                            ext_kids.append(_layer("tls.ext.groups", f"Extension: {ename} (len={elen})", [
                                _f("tls.handshake.extensions_supported_group",
                                   "Supported Groups",
                                   ", ".join(TLS_GROUPS.get(g, f"0x{g:04x}") for g in gs),
                                   b_off + p + 4, elen, "客户端支持的椭圆曲线/有限域群")]))
                        elif etype == 16:
                            n = struct.unpack("!H", ebody[:2])[0] if len(ebody) >= 2 else 0
                            protos = []
                            q = 2
                            for _k in range(n):
                                if q >= len(ebody):
                                    break
                                pl = ebody[q]
                                protos.append(ebody[q + 1:q + 1 + pl].decode("latin-1", "ignore"))
                                q += 1 + pl
                            ext_kids.append(_layer("tls.ext.alpn", f"Extension: {ename} (len={elen})", [
                                _f("tls.handshake.extensions_alpn_str", "ALPN Protocol",
                                   ", ".join(protos) or "-", b_off + p + 4, elen,
                                   "应用层协议协商（h2 表示 HTTP/2）")]))
                        else:
                            shown = min(elen, 32)
                            ext_kids.append(_layer(f"tls.ext.{etype}", f"Extension: {ename} (len={elen})", [
                                _f(f"tls.handshake.extension.data", "Data (截断显示)",
                                   ebody[:shown].hex(), b_off + p + 4, shown,
                                   f"扩展数据共 {elen} 字节，此处展示前 {shown} 字节；"
                                   f"完整二进制可用「导出 pcap」后分析")]))
                        p += 4 + elen
                    if ext_kids:
                        children.append(_layer("tls.extensions", f"[Extensions] ({len(ext_kids)})",
                                               [], ext_kids))
            elif htype == 2 and p + 3 <= len(body):        # ServerHello
                suite = struct.unpack("!H", body[p:p + 2])[0]
                hs_fields.append(_f("tls.handshake.cipher_suite", "Cipher Suite",
                                    f"{TLS_CIPHERS.get(suite, hex(suite))} (0x{suite:04x})",
                                    b_off + p, 2, "服务端选定的加密套件"))
        children.insert(0, _layer("tls.handshake", f"Handshake Protocol: {hname}", hs_fields))
    elif ctype == 21 and len(payload) >= 7:
        level, desc_ = payload[5], payload[6]
        children.append(_layer("tls.alert", "Alert", [
            _f("tls.alert_message.level", "Level",
               f"{level} ({'warning' if level == 1 else 'fatal'})", base + 5, 1, ""),
            _f("tls.alert_message.desc", "Description", desc_, base + 6, 1, "")]))
    return {"name": "tls", "title": f"Transport Layer Security · Record Layer: "
                                   f"{TLS_CONTENT.get(ctype, ctype)}",
            "fields": fields, "children": children,
            "desc": "TLS 加密传输，握手阶段的 SNI / 证书信息在明文可见"}


# ------------------------------------------------------------------ 汽车协议
def _doip_layer(payload: bytes, base: int) -> Optional[Dict[str, Any]]:
    if len(payload) < 8 or payload[0] != 0x02:
        return None
    inv, ptype, plen = payload[1], struct.unpack("!H", payload[2:4])[0], \
        struct.unpack("!I", payload[4:8])[0]
    name = DOIP_TYPES.get(ptype, f"Unknown (0x{ptype:04X})")
    fields = [
        _f("doip.version", "Protocol Version", payload[0], base, 1, "DoIP 协议版本，当前为 2"),
        _f("doip.inverse_version", "Inverse Protocol Version", f"0x{inv:02X}", base + 1, 1,
           "版本取反，用于校验"),
        _f("doip.payload_type", "Payload Type", f"0x{ptype:04X} ({name})", base + 2, 2,
           "DoIP 报文类型（诊断报文 / 路由激活 / 车辆识别等）"),
        _f("doip.payload_length", "Payload Length", plen, base + 4, 4, "负载字节数"),
    ]
    kids: List[Dict[str, Any]] = []
    body = payload[8:8 + plen]
    b = base + 8
    if ptype in (0x8001, 0x8002, 0x8003) and len(body) >= 4:
        sa, ta = struct.unpack("!HH", body[:4])
        kids.append(_layer("doip.diag", "Diagnostic Message", [
            _f("doip.source_address", "Source Address", f"0x{sa:04X}", b, 2,
               "诊断请求发起方逻辑地址（Tester）"),
            _f("doip.target_address", "Target Address", f"0x{ta:04X}", b + 2, 2,
               "诊断目标 ECU 逻辑地址"),
            _f("doip.data", "Diagnostic Data", body[4:].hex(), b + 4, len(body) - 4,
               "UDS 诊断服务数据（ISO 14229）"),
        ]))
    elif ptype in (0x0005, 0x0006) and len(body) >= 7:
        sa, act = struct.unpack("!HB", body[:3])
        kids.append(_layer("doip.routing", "Routing Activation", [
            _f("doip.source_address", "Source Address", f"0x{sa:04X}", b, 2, "客户端逻辑地址"),
            _f("doip.activation_type", "Activation Type", act, b + 2, 1, "激活类型"),
        ]))
    return {"name": "doip", "title": f"Diagnostics over IP · {name}", "fields": fields,
            "children": kids,
            "desc": "DoIP 车载诊断传输协议（ISO 13400），典型端口 13400"}


def _someip_layer(payload: bytes, base: int) -> Optional[Dict[str, Any]]:
    if len(payload) < 16:
        return None
    mid, length, reqid, pver, iver, mtype, rc = struct.unpack("!IIIBBBB", payload[:16])
    service = mid >> 16
    method = mid & 0xFFFF
    sess = reqid >> 16
    fields = [
        _f("someip.messageid", "Message ID", f"0x{mid:08X}", base, 4,
           f"服务 {service} / 方法 {method}"),
        _f("someip.serviceid", "Service ID", f"0x{service:04X}", base, 2, "服务标识"),
        _f("someip.methodid", "Method/Event ID", f"0x{method:04X}", base + 2, 2, "方法或事件标识"),
        _f("someip.length", "Length", length, base + 4, 4, "Length 之后的字节数"),
        _f("someip.requestid", "Request ID", f"0x{reqid:08X}", base + 8, 4,
           f"客户端 {reqid >> 16} / 会话 {sess}"),
        _f("someip.clientid", "Client ID", f"0x{reqid >> 16:04X}", base + 8, 2, "客户端标识"),
        _f("someip.sessionid", "Session ID", f"0x{sess:04X}", base + 10, 2, "会话标识"),
        _f("someip.protocol_version", "Protocol Version", pver, base + 12, 1, "协议版本"),
        _f("someip.interface_version", "Interface Version", f"0x{iver:02X}", base + 13, 1,
           "服务接口版本，不匹配时返回 E_WRONG_INTERFACE_VERSION"),
        _f("someip.messagetype", "Message Type",
           f"0x{mtype:02X} ({SOMEIP_MTYPE.get(mtype, '?')})", base + 14, 1, "报文类型"),
        _f("someip.returncode", "Return Code",
           f"0x{rc:02X} ({SOMEIP_RC.get(rc, '?')})", base + 15, 1, "返回码"),
    ]
    return {"name": "someip", "title": f"SOME/IP · Service 0x{service:04X} "
                                       f"Method 0x{method:04X} "
                                       f"({SOMEIP_MTYPE.get(mtype, '?')})",
            "fields": fields, "children": [],
            "desc": "SOME/IP 面向服务的车载通信协议（典型端口 30490）"}


# ------------------------------------------------------------------ 结构自愈
def _normalize(node: Dict[str, Any]) -> Dict[str, Any]:
    """兜底：确保 children 里全是"层"、fields 里全是"字段"。

    手工组装树时很容易把字段列表误塞进 children（或被反向塞入），
    这里统一纠正，避免前端渲染时取不到 title 而崩溃。
    """
    fds: List[Field] = []
    kids: List[Dict[str, Any]] = []
    for item in list(node.get("fields") or []):
        if isinstance(item, dict) and "title" in item:
            kids.append(item)
        elif isinstance(item, dict):
            fds.append(item)
    for item in list(node.get("children") or []):
        if isinstance(item, dict) and "title" in item:
            kids.append(item)
        elif isinstance(item, dict):
            fds.append(item)
    node["fields"] = fds
    node["children"] = kids
    for c in kids:
        _normalize(c)
    return node


# ------------------------------------------------------------------ 主入口：协议树
def build(raw: bytes, linktype: int, rec: PacketRecord,
          notes: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """构建 Wireshark 风格协议树；notes 为该包的 TCP 分析标记。"""
    layers: List[Dict[str, Any]] = []
    protos: List[str] = []

    # ---- Frame
    frame_children: List[Dict[str, Any]] = []
    if notes:
        frame_children.append(_layer("tcp.analysis", "[TCP Analysis Flags]", [
            _f("tcp.analysis.flags", n.get("flag", ""), n.get("text", ""), -1, 0, "") for n in notes]))
    layers.append(_layer("frame", f"Frame {rec.id}: {rec.length} bytes on wire "
                                  f"({rec.caplen} bytes captured)", [
        _f("frame.number", "Frame Number", rec.id, -1, 0, "该报文在本次抓包中的序号"),
        _f("frame.time", "Arrival Time", rec.time, -1, 0, "捕获时间（本地时钟）"),
        _f("frame.time_epoch", "Epoch Time", f"{rec.ts:.6f}", -1, 0, "自 1970-01-01 起的秒数"),
        _f("frame.len", "Frame Length", rec.length, -1, 0, "线上帧长度"),
        _f("frame.cap_len", "Capture Length", rec.caplen, -1, 0, "实际保存的字节数"),
        _f("frame.protocols", "Protocols in frame", "", -1, 0, "本帧包含的协议栈"),
    ], frame_children, desc="物理层抓包元信息（非报文内容，由抓包引擎生成）"))

    # ---- 链路层
    o = rec.off_eth if rec.off_eth is not None else 0
    eth_type = rec.eth_type
    if linktype == 1 and len(raw) >= o + 14:
        dst, src, et = struct.unpack("!6s6sH", raw[o:o + 14])
        d_oui, s_oui = _oui_name(_mac(dst)), _oui_name(_mac(src))
        protos += ["eth"]
        fields = [
            _f("eth.dst", "Destination", _mac(dst) + (f" ({d_oui})" if d_oui else ""), o, 6,
               "目的 MAC 地址"),
            _f("eth.dst.oui", "Destination OUI", _mac(dst)[:8], o, 3, "IEEE 分配的厂商标识"),
            _f("eth.src", "Source", _mac(src) + (f" ({s_oui})" if s_oui else ""), o + 6, 6,
               "源 MAC 地址"),
            _f("eth.src.oui", "Source OUI", _mac(src)[:8], o + 6, 3, "IEEE 分配的厂商标识"),
            _f("eth.type", "Type", f"0x{et:04x}", o + 12, 2,
               {ETH_IP4: "IPv4 (0x0800)", ETH_IP6: "IPv6 (0x86dd)", ETH_ARP: "ARP (0x0806)",
                ETH_VLAN: "802.1Q Virtual LAN (0x8100)"}.get(et, f"0x{et:04x}")),
        ]
        type_children = []
        if et == ETH_VLAN and len(raw) >= o + 18:
            pri = raw[o + 14] >> 5
            dei = (raw[o + 14] >> 4) & 1
            vid = ((raw[o + 14] & 0x0F) << 8) | raw[o + 15]
            inner = struct.unpack("!H", raw[o + 16:o + 18])[0]
            eth_type = inner
            protos.append("vlan")
            type_children.append(_layer("vlan", f"802.1Q Virtual LAN, PRI: {pri}, DEI: {dei}, "
                                                f"ID: {vid}", [
                _f("vlan.priority", "Priority", pri, o + 14, 1, "802.1p 优先级（0-7）"),
                _f("vlan.dei", "DEI", dei, o + 14, 1, "丢弃合格指示"),
                _f("vlan.id", "VLAN ID", vid, o + 14, 2, "VLAN 编号"),
                _f("vlan.etype", "Type", f"0x{inner:04x}", o + 16, 2, "内层以太类型"),
            ]))
        layers.append(_layer("eth", f"Ethernet II, Src: {_mac(src)}, Dst: {_mac(dst)}",
                             fields, type_children,
                             desc="以太网链路层首部"))

    # ---- 网络层
    if eth_type in (ETH_IP4, 0x0800) and rec.off_ip is not None:
        lay = _ipv4_layer(raw, rec)
        if lay:
            protos.append("ip")
            if rec.proto in ("TCP", "UDP", "ICMP"):
                protos.append(rec.proto.lower())
            layers.append(lay)
    elif eth_type in (ETH_IP6, 0x86DD) and rec.off_ip is not None:
        lay = _ipv6_layer(raw, rec)
        if lay:
            protos.append("ipv6")
            if rec.proto:
                protos.append(rec.proto.lower())
            layers.append(lay)
    elif rec.proto == "ARP":
        lay = _arp_layer(raw, rec)
        if lay:
            protos.append("arp")
            layers.append(lay)

    # ---- 传输层
    if rec.proto == "TCP":
        lay = _tcp_layer(raw, rec)
        if lay:
            if notes:
                lay["children"].append(_layer("tcp.analysis_flags", "[TCP Analysis Flags]", [
                    _f("tcp.analysis.flags", n.get("flag", ""), n.get("text", ""), -1, 0,
                       "NetEye TCP 分析引擎依据序列号/时序判定") for n in notes]))
            layers.append(lay)
    elif rec.proto == "UDP":
        lay = _udp_layer(raw, rec)
        if lay:
            layers.append(lay)
    elif rec.proto == "ICMP":
        lay = _icmp_layer(raw, rec)
        if lay:
            layers.append(lay)
    elif rec.proto == "ICMPv6":
        lay = _icmpv6_layer(raw, rec)
        if lay:
            layers.append(lay)

    # ---- 应用层
    pay_off = rec.off_payload or 0
    payload = raw[pay_off:] if pay_off and pay_off <= len(raw) else b""
    app = rec.app or ""
    if payload:
        app_layer = None
        if app == "DNS" or "dns" in rec.layers:
            app_layer = _dns_layer(payload, pay_off, tcp=(rec.proto == "TCP"))
            protos.append("dns")
        elif app == "HTTP" or "http" in rec.layers:
            app_layer = _http_layer(payload, pay_off)
            protos.append("http")
        elif app == "TLS" or "tls" in rec.layers:
            app_layer = _tls_layer(payload, pay_off)
            protos.append("tls")
        elif app == "DoIP" or "doip" in rec.layers:
            app_layer = _doip_layer(payload, pay_off)
            protos.append("doip")
        elif app == "SOME/IP" or "someip" in rec.layers:
            app_layer = _someip_layer(payload, pay_off)
            protos.append("someip")
        if app_layer:
            layers.append(app_layer)
        else:
            protos.append("data")
            shown = min(len(payload), 32)
            layers.append(_layer("data", f"Data ({len(payload)} bytes)", [
                _f("data.len", "Length", len(payload), -1, 0, "应用层载荷长度"),
                _f("data.data", "Data (截断显示)", payload[:shown].hex(" "),
                   pay_off, shown, f"载荷共 {len(payload)} 字节，此处展示前 {shown} 字节"),
            ], desc="未能进一步解析的载荷（可能是加密或私有协议）"))

    # 回填 frame.protocols
    for lay in layers:
        if lay["name"] == "frame":
            for fd in lay["fields"]:
                if fd["name"] == "frame.protocols":
                    fd["value"] = ":".join(protos)
    for lay in layers:
        _normalize(lay)
    return layers
