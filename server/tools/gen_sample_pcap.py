"""生成 NetEye 演示用 pcap：覆盖 TCP/HTTP/DNS/TLS/DoIP/SOME-IP/重传/端口扫描/ICMP。"""
from __future__ import annotations

import os
import random
import struct
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.storage.pcapio import write_pcap                            # noqa: E402

ETH = bytes.fromhex("001122334455") + bytes.fromhex("66778899aabb") + b"\x08\x00"
SYN, ACK, PSH, RST, FIN = 0x02, 0x10, 0x08, 0x04, 0x01
random.seed(7)


def ip4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    def a(s: str) -> bytes:
        return bytes(int(x) for x in s.split("."))
    total = 20 + len(payload)
    return (ETH + struct.pack("!BBHHHBBH", 0x45, 0, total, random.randint(1, 65535), 0x4000, 64, proto, 0)
            + a(src) + a(dst) + payload)


def tcp(sp: int, dp: int, seq: int, ack: int, flags: int, payload: bytes = b"", win: int = 8192) -> bytes:
    return struct.pack("!HHIIBBHHH", sp, dp, seq, ack, 5 << 4, flags, win, 0, 0) + payload


def udp(sp: int, dp: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sp, dp, 8 + len(payload), 0) + payload


def dns(name: str, qtype: int = 1, qr: bool = False, rcode: int = 0) -> bytes:
    flags = (0x8180 if qr else 0x0100) | (rcode & 0xF)
    q = b""
    for part in name.split("."):
        q += bytes([len(part)]) + part.encode()
    q += b"\x00" + struct.pack("!HH", qtype, 1)
    body = struct.pack("!HHHH", random.randint(1, 9999), flags, 1, 1 if qr else 0) + q
    if qr:
        body += b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 60, 4) + bytes([93, 107, 216, 34])
    return body


def tls_client_hello(sni: str) -> bytes:
    ext = b"\x00\x00" + struct.pack("!HH", len(sni) + 5, len(sni) + 3) + b"\x00" + \
        struct.pack("!H", len(sni)) + sni.encode()
    body = b"\x01" + struct.pack("!I", 200)[1:] + b"\x00\x00\x00\x20" + b"\x00\x02\x13\x01" + \
        b"\x01\x00" + struct.pack("!H", len(ext)) + ext
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def someip(msg_id: int, mtype: int = 0x02) -> bytes:
    return struct.pack("!IIIBBBB", msg_id, 16, 0x12340001, 0x01, 0x01, mtype, 0x00)


def doip(ptype: int, payload: bytes = b"\x22\xf1\x90") -> bytes:
    return b"\x02\xfd" + struct.pack("!HHI", ptype, len(payload) + 8, len(payload)) + payload


pkts = []
t = time.time() - 60


def add(raw: bytes, dt: float = 0.0) -> None:
    global t
    t += dt or random.uniform(0.02, 0.12)
    pkts.append((t, raw))


# 1) 正常 HTTP 会话（含 3 次请求、1 次 404）
for i in range(3):
    sp = 51000 + i
    add(ip4("192.168.5.187", "93.107.216.34", 6, tcp(sp, 80, 1, 0, SYN)))
    add(ip4("93.107.216.34", "192.168.5.187", 6, tcp(80, sp, 1, 2, SYN | ACK)))
    add(ip4("192.168.5.187", "93.107.216.34", 6, tcp(sp, 80, 2, 2, ACK)))
    uri = "/api/v1/devices" if i < 2 else "/api/v1/notfound"
    add(ip4("192.168.5.187", "93.107.216.34", 6,
            tcp(sp, 80, 2, 2, PSH | ACK, f"GET {uri} HTTP/1.1\r\nHost: atemall-ai.com\r\nUser-Agent: NetEye\r\n\r\n".encode())))
    code = b"200 OK" if i < 2 else b"404 Not Found"
    add(ip4("93.107.216.34", "192.168.5.187", 6,
            tcp(80, sp, 2, 2 + 60, PSH | ACK, b"HTTP/1.1 " + code + b"\r\nContent-Length: 12\r\n\r\n{\"ok\":true}")))
    add(ip4("192.168.5.187", "93.107.216.34", 6, tcp(sp, 80, 62, 2 + 12, ACK)))
    add(ip4("192.168.5.187", "93.168.5.187".replace("93.168", "93.107"), 6, tcp(sp, 80, 62, 14, FIN | ACK)))

# 2) TLS 握手（含 SNI）
for sni in ("www.baidu.com", "api.deepseek.com", "github.com"):
    sp = 52000 + random.randint(1, 999)
    add(ip4("192.168.5.187", "8.8.8.8", 6, tcp(sp, 443, 10, 0, SYN)))
    add(ip4("8.8.8.8", "192.168.5.187", 6, tcp(443, sp, 10, 11, SYN | ACK)))
    add(ip4("192.168.5.187", "8.8.8.8", 6, tcp(sp, 443, 11, 11, PSH | ACK, tls_client_hello(sni))))
    add(ip4("8.8.8.8", "192.168.5.187", 6, tcp(443, sp, 11, 11 + 200, PSH | ACK, b"\x16\x03\x03\x00\x05\x02\x00\x00\x46\x03\x03")))

# 3) DNS（含 1 次 NXDOMAIN）
for name, rc in (("www.baidu.com", 0), ("atemall-ai.com", 0), ("not-exist-xyz.cn", 3), ("github.com", 0)):
    add(ip4("192.168.5.187", "192.168.5.1", 17, udp(53000 + random.randint(1, 999), 53, dns(name))))
    add(ip4("192.168.5.1", "192.168.5.187", 17, udp(53, 53000, dns(name, qr=True, rcode=rc))))

# 4) 汽车电子：DoIP 诊断 + SOME/IP
add(ip4("192.168.5.187", "192.168.5.60", 6, tcp(53000, 13400, 1, 0, SYN)))
add(ip4("192.168.5.187", "192.168.5.60", 6, tcp(53000, 13400, 2, 1, PSH | ACK, doip(0x8001))))
add(ip4("192.168.5.60", "192.168.5.187", 6, tcp(13400, 53000, 1, 12, PSH | ACK, doip(0x8002))))
for i in range(6):
    add(ip4("192.168.5.60", "239.255.0.1", 17, udp(30490, 30490, someip(0x12340000 + i))))

# 5) TCP 重传（同 seq 重复发）
for i in range(4):
    add(ip4("192.168.5.187", "10.10.10.10", 6, tcp(54000, 8080, 100, 1, PSH | ACK, b"payload-data-block")), 0.02)
add(ip4("10.10.10.10", "192.168.5.187", 6, tcp(8080, 54000, 1, 118, ACK)))

# 6) 疑似端口扫描：连续 SYN 到不同端口
for p in range(20):
    add(ip4("10.0.0.66", "192.168.5.187", 6, tcp(40000, 1000 + p, 0, 0, SYN)), 0.005)
add(ip4("192.168.5.187", "10.0.0.66", 6, tcp(445, 40000, 0, 1, RST)))

# 7) 广播 + ICMP
add(ip4("192.168.5.187", "255.255.255.255", 17, udp(137, 137, b"\x00" * 20)))
for i in range(3):
    add(ip4("192.168.5.187", "192.168.5.1", 1, b"\x08\x00" + struct.pack("!HH", 0, i) + b"pingdata"))

# 8) 零窗口（性能告警）与 UDP 大流量
add(ip4("10.10.10.10", "192.168.5.187", 6, tcp(8080, 54000, 118, 118, ACK, b"", win=0)))
for i in range(30):
    add(ip4("192.168.5.187", "192.168.5.200", 17, udp(60000, 7000 + i % 5, b"x" * 200)), 0.005)

out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(__file__), "..", "..", "data", "captures", "sample_demo.pcap")
out = os.path.abspath(out)
os.makedirs(os.path.dirname(out), exist_ok=True)
n = write_pcap(out, pkts, 1)
print(f"已生成 {out}  共 {n} 个报文")
