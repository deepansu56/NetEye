"""NetEye 核心冒烟测试：合成报文 → 解析 → 过滤 → 统计 → pcap 往返。"""
from __future__ import annotations

import os
import struct
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.filters.display_filter import compile_filter, validate_filter          # noqa: E402
from app.parser.dissect import detail, parse                                    # noqa: E402
from app.stats.aggregator import Aggregator                                     # noqa: E402
from app.storage.pcapio import pcap_info, read_pcap, write_pcap                 # noqa: E402

ETH_H = bytes.fromhex("aabbccddeeff") + bytes.fromhex("112233445566") + b"\x08\x00"


def ip4(src: str, dst: str, proto: int, payload: bytes, ttl: int = 64) -> bytes:
    def a(s: str) -> bytes:
        return bytes(int(x) for x in s.split("."))
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH", 0x45, 0, total, 0x1234, 0x4000, ttl, proto, 0) + a(src) + a(dst)
    return ETH_H + hdr + payload


def tcp(sport: int, dport: int, seq: int, ack: int, flags: int, win: int = 8192, payload: bytes = b"") -> bytes:
    off = (5 << 4)
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, off, flags, win, 0, 0)
    return hdr + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def dns_query(name: str = "www.baidu.com") -> bytes:
    tid = b"\x12\x34"
    flags = b"\x01\x00"
    counts = struct.pack("!HHHH", 1, 0, 0, 0)
    q = b""
    for part in name.split("."):
        q += bytes([len(part)]) + part.encode()
    q += b"\x00" + struct.pack("!HH", 1, 1)
    return tid + flags + counts + q


ok = fail = 0


def check(name: str, cond: bool, extra: str = "") -> None:
    global ok, fail
    if cond:
        ok += 1
        print(f"  PASS  {name}")
    else:
        fail += 1
        print(f"  FAIL  {name} {extra}")


print("== 1. 解析 ==")
p_syn = ip4("10.0.0.1", "10.0.0.2", 6, tcp(12345, 80, 100, 0, 0x02))
r1 = parse(p_syn, time.time(), 1, 1)
check("TCP SYN 协议识别", r1.proto == "TCP", r1.proto)
check("TCP 端口", (r1.src_port, r1.dst_port) == (12345, 80), f"{r1.src_port}->{r1.dst_port}")
check("SYN 标志", "SYN" in (r1.flags or ""), r1.flags)
check("IP 地址", (r1.src, r1.dst) == ("10.0.0.1", "10.0.0.2"), f"{r1.src}/{r1.dst}")
check("载荷长度", r1.payload_len == 0, str(r1.payload_len))

p_http = ip4("10.0.0.1", "10.0.0.2", 6,
             tcp(54321, 80, 1, 1, 0x18, payload=b"GET /api/login HTTP/1.1\r\nHost: a.cn\r\n\r\n"))
r2 = parse(p_http, time.time(), 1, 2)
check("HTTP 方法", r2.http_method == "GET", str(r2.http_method))
check("HTTP URI", r2.http_uri == "/api/login", str(r2.http_uri))
check("HTTP Host", r2.http_host == "a.cn", str(r2.http_host))
check("HTTP 层标记", "http" in r2.layers, str(r2.layers))

p_dns = ip4("10.0.0.5", "8.8.8.8", 17, udp(5555, 53, dns_query("www.baidu.com")))
r3 = parse(p_dns, time.time(), 1, 3)
check("DNS 查询名", r3.dns_name == "www.baidu.com", str(r3.dns_name))
check("DNS 层标记", "dns" in r3.layers, str(r3.layers))

p_udp = ip4("10.0.0.1", "10.0.0.2", 17, udp(5000, 6000, b"hello"))
r4 = parse(p_udp, time.time(), 1, 4)
check("UDP 端口", (r4.src_port, r4.dst_port) == (5000, 6000))

p_icmp = ip4("10.0.0.1", "10.0.0.2", 1, b"\x08\x00\xf7\xff\x00\x01\x00\x02abcd")
r5 = parse(p_icmp, time.time(), 1, 5)
check("ICMP 类型", r5.icmp_type == 8, str(r5.icmp_type))

print("== 2. 深度解析 / 十六进制 ==")
layers, hexs = detail(p_syn, 1, r1)
check("协议树层数 >= 3", len(layers) >= 3, str([l["name"] for l in layers]))
check("hex 视图非空", "aa bb cc" in hexs, hexs[:60])
tcp_layer = next((l for l in layers if l["name"] == "tcp"), None)
check("TCP 层含 SYN 标志字段", tcp_layer is not None and any(
    f["name"] == "tcp.flags.syn" and f["value"] == "1" for f in tcp_layer["fields"]), str(tcp_layer))

print("== 3. 显示过滤器 ==")
recs = [r1, r2, r3, r4, r5]
f1 = compile_filter("tcp.port == 80")
check("tcp.port==80 命中 2 个", f1 and sum(1 for r in recs if f1(r)) == 2,
      str([r.id for r in recs if f1 and f1(r)]))
f2 = compile_filter("http")
check("http 命中 1 个", f2 and sum(1 for r in recs if f2(r)) == 1)
f3 = compile_filter("dns && udp.port == 53")
check("dns && udp.port==53", f3 and sum(1 for r in recs if f3(r)) == 1)
f4 = compile_filter("ip.addr == 10.0.0.0/24")
check("CIDR 匹配 5 个（源或目的任一在 10.0.0.0/24）", f4 and sum(1 for r in recs if f4(r)) == 5,
      str(sum(1 for r in recs if f4(r))))
f5 = compile_filter("!(tcp.port == 80) && ip.ttl == 64")
check("取反 + 与", f5 and sum(1 for r in recs if f5(r)) == 3, str(sum(1 for r in recs if f5(r))))
f6 = compile_filter("frame.len > 50")
check("数值比较", f6 and sum(1 for r in recs if f6(r)) >= 1)
f7 = compile_filter("tcp.flags.syn == 1")
check("TCP 标志位", f7 and sum(1 for r in recs if f7(r)) == 1)
f8 = compile_filter("http.request.uri contains login")
check("contains", f8 and sum(1 for r in recs if f8(r)) == 1)
check("非法表达式可被发现", validate_filter("tcp.port ==") is not None)
check("空表达式合法", validate_filter("") is None)

print("== 4. 统计聚合 ==")
agg = Aggregator()
now = time.time()
for i, (payload, sz) in enumerate([(p_syn, len(p_syn)), (p_http, len(p_http)), (p_dns, len(p_dns)),
                                   (p_udp, len(p_udp)), (p_icmp, len(p_icmp))], start=1):
    rec = parse(payload, now + i * 0.01, 1, i)
    agg.add(rec, sz)
check("总包数 5", agg.total_packets == 5, str(agg.total_packets))
check("协议分级含 TCP", any(p["protocol"] == "TCP" for p in agg.protocol_stats()))
check("会话统计非空", len(agg.conversations()) >= 3, str(len(agg.conversations())))
check("端口统计含 80", any(p["port"] == 80 for p in agg.port_stats()))
check("端点统计含 10.0.0.1", any(e["address"] == "10.0.0.1" for e in agg.endpoints()))
# 重传检测：同流重复 seq
seq_dup = ip4("10.0.0.1", "10.0.0.2", 6, tcp(12345, 80, 100, 1, 0x10, payload=b"abc"))
for i in range(3):
    rec = parse(seq_dup, now + 1 + i * 0.01, 1, 100 + i)
    agg.add(rec, len(seq_dup))
check("检测到重传", agg.retrans_total >= 1, str(agg.retrans_total))
check("专家信息非空", len(agg.experts) >= 1)
check("异常检测有输出", len(agg.anomalies()) >= 1)
check("摘要字段完整", set(["packets", "bytes", "duration", "avg_pps"]) <= set(agg.summary()))

print("== 5. pcap 读写往返 ==")
tmp = os.path.join(os.path.dirname(__file__), "tmp_test.pcap")
packets = [(now + i * 0.001, p_syn) for i in range(5)] + [(now, p_http), (now, p_dns)]
write_pcap(tmp, packets, 1)
info = pcap_info(tmp)
check("pcap 包数一致", info["packets"] == 7, str(info))
back = list(read_pcap(tmp))
check("往返内容一致", len(back) == 7 and back[0][1] == p_syn)
pr = parse(back[5][1], back[5][0], info["linktype"], 1)      # 第 6 个包是 HTTP
check("往返后可解析", pr.http_method == "GET", str(pr.http_method))
os.remove(tmp)

print(f"\n结果：{ok} 通过 / {fail} 失败")
sys.exit(1 if fail else 0)
