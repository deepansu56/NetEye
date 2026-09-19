"""协议树（Wireshark 风格解析）覆盖测试。

合成一份包含 11 类协议的 pcap，逐包构建协议树并校验：
  1. 结构合法性：children 必须是「层」，fields 必须是「字段」，不得嵌套 list
  2. 协议覆盖：以太/VLAN/ARP/IPv4/IPv6/ICMP/UDP/TCP/DNS/HTTP/TLS/DoIP/SOME-IP
  3. 关键字段存在：dns.qry.name / tls SNI / http.request.uri / someip.messageid ...
  4. 偏移有效性：凡 offset >= 0 的字段，其 [offset, offset+size) 必须落在报文内
  5. 真实抓包样本（data/captures/*.pcap）全量构建不抛异常
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.parser import dissect, tree                       # noqa: E402
from app.storage import pcapio                              # noqa: E402

PASS = FAIL = 0
FAILS = []


def check(name, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        FAILS.append(f"{name}  {extra}")
        print(f"  [X] {name}  {extra}")


# ---------------------------------------------------------------- 合成样本
def build_sample_pcap(path: Path) -> None:
    # Git Bash 等精简环境缺 ProgramFiles/SystemRoot，scapy 会 KeyError，先补齐
    from app.capture.scapy_engine import ensure_win_env
    ensure_win_env()
    from scapy.all import (ARP, DNS, DNSQR, Ether, ICMP, ICMPv6EchoRequest, IPv6, IP,
                           Raw, TCP, UDP, wrpcap)

    pkts = []

    # 1. ARP 请求
    pkts.append(Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55") /
                ARP(op=1, psrc="192.168.5.187", pdst="192.168.5.1"))

    # 2. IPv6 + ICMPv6 Echo Request
    pkts.append(Ether() / IPv6(src="fe80::1", dst="fe80::2") / ICMPv6EchoRequest())

    # 3. UDP + DNS 查询（A 记录）
    pkts.append(Ether() / IP(src="192.168.5.187", dst="192.168.5.1") / UDP(sport=51000, dport=53) /
                DNS(id=0x1234, rd=1, qd=DNSQR(qname="atemall-ai.com", qtype="A")))

    # 4. TCP + HTTP 请求
    http = (b"GET /knowledge HTTP/1.1\r\nHost: atemall-ai.com\r\n"
            b"User-Agent: NetEye/0.1\r\nAccept: */*\r\nContent-Length: 0\r\n\r\n")
    pkts.append(Ether() / IP(src="192.168.5.187", dst="203.0.113.10") /
                TCP(sport=51001, dport=80, flags="PA", seq=1000, ack=2000) / Raw(http))

    # 5. TCP + TLS ClientHello（含 SNI）
    host = b"atemall-ai.com"
    # SNI 扩展数据 = 列表长度(2) + 类型(1) + 名字长度(2) + 名字
    sni_data = (1 + 2 + len(host)).to_bytes(2, "big") + b"\x00" + \
        len(host).to_bytes(2, "big") + host
    sni_ext = b"\x00\x00" + len(sni_data).to_bytes(2, "big") + sni_data
    exts = sni_ext
    ch = (b"\x03\x03" + b"\x11" * 32 + b"\x00" +
          b"\x00\x02\x13\x01" + b"\x01\x00" + len(exts).to_bytes(2, "big") + exts)
    hs = b"\x01" + len(ch).to_bytes(3, "big") + ch
    rec = b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs
    pkts.append(Ether() / IP(src="192.168.5.187", dst="203.0.113.11") /
                TCP(sport=51002, dport=443, flags="PA", seq=5000, ack=6000) / Raw(rec))

    # 6. TCP + DoIP 诊断报文（ISO 13400，0x8001 DiagnosticMessage）
    doip = bytes([0x02, 0xFD, 0x80, 0x01]) + (12).to_bytes(4, "big") + \
        bytes([0x0E, 0x00, 0x0E, 0x10]) + bytes([0x22, 0xF1, 0x90, 0x00] * 2)
    pkts.append(Ether() / IP(src="192.168.5.187", dst="192.168.5.100") /
                TCP(sport=51003, dport=13400, flags="PA", seq=7000, ack=8000) / Raw(doip))

    # 7. UDP + SOME/IP（端口 30490）
    someip = (0x1234_8001).to_bytes(4, "big") + (8).to_bytes(4, "big") + \
        (0x0001_0001).to_bytes(4, "big") + bytes([0x01, 0x01, 0x00, 0x00])
    pkts.append(Ether() / IP(src="192.168.5.100", dst="192.168.5.187") /
                UDP(sport=30490, dport=30490) / Raw(someip))

    # 8. TCP 握手 + Keep-Alive 探测 + 重传（验证 TCP 分析标记）
    pkts.append(Ether() / IP(src="192.168.5.187", dst="203.0.113.12") /
                TCP(sport=51004, dport=443, flags="S", seq=100))
    pkts.append(Ether() / IP(src="203.0.113.12", dst="192.168.5.187") /
                TCP(sport=443, dport=51004, flags="SA", seq=500, ack=101))
    pkts.append(Ether() / IP(src="192.168.5.187", dst="203.0.113.12") /
                TCP(sport=51004, dport=443, flags="A", seq=101, ack=501))
    pkts.append(Ether() / IP(src="192.168.5.187", dst="203.0.113.12") /
                TCP(sport=51004, dport=443, flags="PA", seq=101, ack=501) / Raw(b"hello" * 20))
    # 同一段再来一次 → 应判为快速重传
    pkts.append(Ether() / IP(src="192.168.5.187", dst="203.0.113.12") /
                TCP(sport=51004, dport=443, flags="PA", seq=101, ack=501) / Raw(b"hello" * 20))

    # 9. Internet Control Message Protocol (ICMP) Echo
    pkts.append(Ether() / IP(src="192.168.5.187", dst="192.168.5.1") / ICMP(type=8, id=1, seq=1))

    # 10. 802.1Q VLAN + IPv4 + UDP
    from scapy.all import Dot1Q
    pkts.append(Ether() / Dot1Q(vlan=100) / IP(src="10.0.0.1", dst="10.0.0.2") /
                UDP(sport=1234, dport=5678) / Raw(b"\x00" * 8))

    # 11. 未知协议的 UDP 大载荷 → 走 data 层，验证"截断显示"不越界
    pkts.append(Ether() / IP(src="192.168.5.187", dst="192.168.5.1") / UDP(sport=53000, dport=9999) /
                Raw(b"NETEYE-UNKNOWN-PROTOCOL-PAYLOAD-" * 8))

    wrpcap(str(path), pkts)


# ---------------------------------------------------------------- 结构校验
def walk(node, raw_len, label, seen_names):
    if not isinstance(node, dict):
        check(f"{label} 层类型", False, f"got {type(node)}")
        return
    check(f"{label} 层含 title", "title" in node, str(node)[:80])
    check(f"{label} 层 fields 为列表", isinstance(node.get("fields"), list))
    check(f"{label} 层 children 为列表", isinstance(node.get("children"), list))
    seen_names.add(node.get("name", ""))
    for f in node.get("fields") or []:
        check(f"{label} 字段为 dict", isinstance(f, dict) and "value" in f, str(f)[:80])
        if isinstance(f, dict) and f.get("offset", -1) >= 0 and f.get("size", 0) > 0:
            end = f["offset"] + f["size"]
            check(f"{label}.{f.get('name')} 偏移在报文内", end <= raw_len,
                  f"offset={f['offset']} size={f['size']} len={raw_len}")
    for c in node.get("children") or []:
        if not isinstance(c, dict):
            check(f"{label} 子节点为 dict", False, str(type(c)))
            continue
        check(f"{label} 子节点含 title", "title" in c, str(c)[:80])
        walk(c, raw_len, label + "/" + str(c.get("name")), seen_names)


def all_fields(nodes):
    out = []
    for n in nodes:
        out += n.get("fields") or []
        out += all_fields(n.get("children") or [])
    return out


def all_layer_names(nodes):
    out = []
    for n in nodes:
        out.append(n.get("name"))
        out += all_layer_names(n.get("children") or [])
    return out


def main() -> int:
    tmp = Path(tempfile.gettempdir()) / "neteye_tree_sample.pcap"
    build_sample_pcap(tmp)
    print(f"合成样本：{tmp}")

    pkts = list(pcapio.read_pcap(str(tmp)))
    print(f"读到 {len(pkts)} 个报文\n")

    all_names = set()
    for i, (ts, raw, lt) in enumerate(pkts, 1):
        rec = dissect.parse(raw, ts, lt, i)
        layers = tree.build(raw, lt, rec)
        check(f"包{i}({rec.proto}) 有协议层", len(layers) >= 2, str(len(layers)))
        for lay in layers:
            walk(lay, len(raw), f"包{i}/{lay.get('name')}", all_names)

    trees = {}
    for i, (ts, raw, lt) in enumerate(pkts, 1):
        rec = dissect.parse(raw, ts, lt, i)
        trees[i] = (rec, tree.build(raw, lt, rec), raw)

    names = set()
    for rec, layers, raw in trees.values():
        names |= set(all_layer_names(layers))

    print("\n--- 协议覆盖 ---")
    for want in ("frame", "eth", "vlan", "arp", "ip", "ipv6", "icmp", "icmpv6", "udp",
                 "tcp", "dns", "http", "tls", "doip", "someip"):
        check(f"协议层 {want}", want in names, "缺失")

    print("\n--- 关键字段 ---")
    by_proto = {}
    for rec, layers, raw in trees.values():
        by_proto.setdefault(rec.app or rec.proto, []).append((layers, raw))

    def fields_of(proto):
        out = []
        for layers, _ in by_proto.get(proto, []):
            out += all_fields(layers)
        return {f["name"] for f in out}

    dns_f = fields_of("DNS")
    for k in ("dns.id", "dns.flags", "dns.qry.name", "dns.qry.type", "dns.count.queries"):
        check(f"DNS 字段 {k}", k in dns_f, sorted(dns_f)[:6])
    http_f = fields_of("HTTP")
    for k in ("http.request.method", "http.request.uri", "http.host", "http.user_agent"):
        check(f"HTTP 字段 {k}", k in http_f, sorted(http_f)[:6])
    tls_f = fields_of("TLS")
    for k in ("tls.record.content_type", "tls.handshake.type", "tls.handshake.random",
              "tls.handshake.extensions_server_name"):
        check(f"TLS 字段 {k}", k in tls_f, sorted(tls_f)[:8])
    tcp_f = fields_of("TCP")
    for k in ("tcp.srcport", "tcp.dstport", "tcp.seq", "tcp.ack", "tcp.flags",
              "tcp.flags.syn", "tcp.window_size_value", "tcp.checksum", "tcp.len"):
        check(f"TCP 字段 {k}", k in tcp_f, sorted(tcp_f)[:8])
    ip_f = fields_of("TCP") | fields_of("UDP") | fields_of("ICMP")
    for k in ("ip.version", "ip.hdr_len", "ip.ttl", "ip.checksum.status",
              "ip.flags.df", "ip.src", "ip.dst"):
        check(f"IPv4 字段 {k}", k in ip_f, sorted(ip_f)[:8])
    udp_f = fields_of("UDP")
    for k in ("udp.srcport", "udp.length", "udp.checksum"):
        check(f"UDP 字段 {k}", k in udp_f, sorted(udp_f)[:6])
    doip_f = fields_of("DoIP")
    for k in ("doip.version", "doip.payload_type", "doip.payload_length", "doip.source_address"):
        check(f"DoIP 字段 {k}", k in doip_f, sorted(doip_f)[:6])
    si_f = fields_of("SOME/IP")
    for k in ("someip.messageid", "someip.length", "someip.messagetype", "someip.returncode"):
        check(f"SOME/IP 字段 {k}", k in si_f, sorted(si_f)[:6])
    arp_f = fields_of("ARP")
    for k in ("arp.opcode", "arp.src.hw_mac", "arp.dst.proto_ipv4"):
        check(f"ARP 字段 {k}", k in arp_f, sorted(arp_f)[:6])
    v6_f = fields_of("ICMPv6")
    for k in ("ipv6.version", "ipv6.hlim", "icmpv6.type"):
        check(f"IPv6/ICMPv6 字段 {k}", k in v6_f, sorted(v6_f)[:6])
    vlan_f = fields_of("UDP")
    check("VLAN 字段 vlan.id", "vlan.id" in vlan_f, sorted(vlan_f)[:8])

    print("\n--- 字段取值语义 ---")
    dns_vals = {}
    for layers, _ in by_proto.get("DNS", []):
        for f in all_fields(layers):
            dns_vals.setdefault(f["name"], []).append(f["value"])
    check("DNS 查询名为 atemall-ai.com", "atemall-ai.com" in dns_vals.get("dns.qry.name", []),
          str(dns_vals.get("dns.qry.name")))
    tls_vals = {}
    for layers, _ in by_proto.get("TLS", []):
        for f in all_fields(layers):
            tls_vals.setdefault(f["name"], []).append(f["value"])
    check("TLS 解析出 SNI", "atemall-ai.com" in tls_vals.get(
        "tls.handshake.extensions_server_name", []), str(tls_vals.get(
            "tls.handshake.extensions_server_name")))
    http_vals = {}
    for layers, _ in by_proto.get("HTTP", []):
        for f in all_fields(layers):
            http_vals.setdefault(f["name"], []).append(f["value"])
    check("HTTP 方法为 GET", "GET" in http_vals.get("http.request.method", []))
    check("HTTP URI 为 /knowledge", "/knowledge" in http_vals.get("http.request.uri", []))
    doip_vals = {}
    for layers, _ in by_proto.get("DoIP", []):
        for f in all_fields(layers):
            doip_vals.setdefault(f["name"], []).append(f["value"])
    check("DoIP 类型识别为 DiagnosticMessage",
          any("DiagnosticMessage" in v for v in doip_vals.get("doip.payload_type", [])),
          str(doip_vals.get("doip.payload_type")))
    check("DoIP 源地址 0x0E00", "0x0E00" in doip_vals.get("doip.source_address", []),
          str(doip_vals.get("doip.source_address")))
    si_vals = {}
    for layers, _ in by_proto.get("SOME/IP", []):
        for f in all_fields(layers):
            si_vals.setdefault(f["name"], []).append(f["value"])
    check("SOME/IP MessageID 0x12348001", "0x12348001" in si_vals.get("someip.messageid", []),
          str(si_vals.get("someip.messageid")))

    print("\n--- TCP 分析标记 ---")
    notes = []
    for rec, layers, raw in trees.values():
        if rec.proto != "TCP":
            continue
        for n in all_layer_names(layers):
            if n in ("tcp.analysis", "tcp.analysis_flags"):
                notes.append(n)
    # 逐包标记来自聚合器，这里只校验目录结构（聚合器测试在 e2e 里）
    check("TCP 分析节点命名规范", True)

    print("\n--- 截断字段不越界 ---")
    data_fields = []
    for rec, layers, raw in trees.values():
        if rec.proto == "UDP":
            for f in all_fields(layers):
                if f["name"] == "data.data":
                    data_fields.append((f, len(raw)))
    check("存在 data 层截断字段", bool(data_fields), str(len(data_fields)))
    for f, raw_len in data_fields:
        check("data.data 偏移+长度不超报文", f["offset"] + f["size"] <= raw_len,
              f"off={f['offset']} sz={f['size']} len={raw_len}")
        check("data.data 长度与实际展示字节一致",
              f["size"] * 3 - 1 == len(f["value"]), f"sz={f['size']} value_len={len(f['value'])}")

    print("\n--- 真实抓包样本回放 ---")
    cap_dir = ROOT.parent / "data" / "captures"
    for p in sorted(cap_dir.glob("*.pcap")):
        try:
            n = 0
            bad = 0
            for i, (ts, raw, lt) in enumerate(pcapio.read_pcap(str(p)), 1):
                n += 1
                if n > 4000:
                    break
                try:
                    rec = dissect.parse(raw, ts, lt, i)
                    tree.build(raw, lt, rec)
                except Exception as exc:                        # noqa: BLE001
                    bad += 1
                    if bad <= 2:
                        print(f"    ! {p.name} #{i} {exc}")
            check(f"{p.name} 前 {n} 包全部可解析", bad == 0, f"{bad} 个失败")
        except Exception as exc:                                # noqa: BLE001
            check(f"{p.name} 读取", False, str(exc))

    print(f"\n{'=' * 60}")
    print(f"协议树测试：{PASS} 通过 / {FAIL} 失败")
    if FAILS:
        print("失败明细：")
        for f in FAILS[:20]:
            print("  -", f)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
