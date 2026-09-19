"""pcap 文件读写（libpcap 格式，自研实现，零依赖）。

支持：保存、追加、读取、按序号随机访问（离线分析用）。
"""
from __future__ import annotations

import struct
from typing import Iterator, List, Optional, Tuple

GLOBAL_HDR = struct.Struct("<IHHiIII")
PKT_HDR = struct.Struct("<IIII")
MAGIC_LE = 0xA1B2C3D4
MAGIC_BE = 0xD4C3B2A1
NANO_MAGIC = 0xA1B23C4D


def write_pcap(path: str, packets: List[Tuple[float, bytes]], linktype: int = 1) -> int:
    """写入 pcap，返回写入包数。"""
    with open(path, "wb") as f:
        f.write(GLOBAL_HDR.pack(MAGIC_LE, 2, 4, 0, 0, 65535, linktype))
        for ts, raw in packets:
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000)) % 1_000_000
            f.write(PKT_HDR.pack(sec, usec, len(raw), len(raw)))
            f.write(raw)
    return len(packets)


def append_pcap(path: str, ts: float, raw: bytes, linktype: int = 1) -> None:
    """追加单包（文件不存在则创建）。"""
    import os
    new = not os.path.exists(path)
    with open(path, "ab") as f:
        if new:
            f.write(GLOBAL_HDR.pack(MAGIC_LE, 2, 4, 0, 0, 65535, linktype))
        sec = int(ts)
        usec = int(round((ts - sec) * 1_000_000)) % 1_000_000
        f.write(PKT_HDR.pack(sec, usec, len(raw), len(raw)))
        f.write(raw)


def read_pcap(path: str) -> Iterator[Tuple[float, bytes, int]]:
    """迭代 (timestamp, raw_bytes, linktype)。"""
    with open(path, "rb") as f:
        head = f.read(24)
        if len(head) < 24:
            return
        magic, vmaj, vmin, tz, sig, snaplen, network = struct.unpack("<IHHiIII", head)
        if magic == MAGIC_BE:
            endian = ">"
        elif magic == NANO_MAGIC or magic == MAGIC_LE:
            endian = "<"
        else:
            endian = "<"
        nanos = (magic == NANO_MAGIC)
        phdr = struct.Struct(endian + "IIII")
        while True:
            h = f.read(16)
            if len(h) < 16:
                break
            sec, frac, incl, orig = phdr.unpack(h)
            ts = sec + (frac / 1_000_000_000 if nanos else frac / 1_000_000)
            data = f.read(incl)
            if len(data) < incl:
                break
            yield ts, data, network


def pcap_info(path: str) -> dict:
    count = 0
    linktype = 1
    first = last = 0.0
    for ts, raw, lt in read_pcap(path):
        if count == 0:
            first, linktype = ts, lt
        last = ts
        count += 1
    return {"packets": count, "linktype": linktype, "first": first, "last": last,
            "duration": round(max(last - first, 0), 3)}
