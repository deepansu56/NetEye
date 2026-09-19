"""判定“重传”真伪：比对重复段的 IP ID、TTL、payload 是否完全一致。

判据（同一 TCP 方向内 seq 与 payload 长度都相同的两个段）：
  - IP ID 相同 + TTL 相同 + payload 相同  → 同一帧被递交两次（捕获层重复）
  - IP ID 不同（重新封装）                → 真实 TCP 重传
"""
from __future__ import annotations

import hashlib
import sys
from collections import Counter, defaultdict

sys.path.insert(0, ".")

from app.parser.dissect import parse        # noqa: E402
from app.storage.pcapio import read_pcap    # noqa: E402


def ip_fields(raw: bytes, l3: int) -> tuple[int, int]:
    """返回 (ip_id, ttl)，失败返回 (-1, -1)。"""
    try:
        if len(raw) < l3 + 12:
            return -1, -1
        if (raw[l3] >> 4) == 4:
            ip_id = int.from_bytes(raw[l3 + 4:l3 + 6], "big")
            ttl = raw[l3 + 8]
            return ip_id, ttl
    except Exception:                                                # noqa: BLE001
        pass
    return -1, -1


def main() -> int:
    path = sys.argv[1]
    segs: dict[tuple, list] = defaultdict(list)
    total = 0
    for ts, raw, lt in read_pcap(path):
        total += 1
        try:
            rec = parse(raw, ts, lt, total)
        except Exception:                                            # noqa: BLE001
            continue
        if rec.proto != "TCP" or not (rec.payload_len or 0):
            continue
        l3 = 14
        if len(raw) > 13 and int.from_bytes(raw[12:14], "big") == 0x8100:   # VLAN
            l3 = 18
        ipid, ttl = ip_fields(raw, l3)
        h = hashlib.md5(bytes(raw)).hexdigest()[:10]
        key = (rec.src, rec.src_port, rec.dst, rec.dst_port, rec.seq, rec.payload_len)
        segs[key].append((total, ts, ipid, ttl, h, raw))

    print(f"总报文 {total}，受跟踪数据段 {sum(len(v) for v in segs.values())}")
    same_id = diff_id = 0
    id_deltas: Counter = Counter()
    gaps: list[float] = []
    samples: list[tuple] = []
    for key, arr in segs.items():
        if len(arr) < 2:
            continue
        base = arr[0]
        for ev in arr[1:]:
            gap = ev[1] - base[1]
            gaps.append(gap)
            if ev[2] == base[2] and ev[3] == base[3] and ev[4] == base[4]:
                same_id += 1
                if len(samples) < 5:
                    samples.append((key, gap, base[0], ev[0], base[2], ev[2], base[4]))
            else:
                diff_id += 1
                id_deltas[(ev[2] - base[2]) & 0xFFFF] += 1

    print(f"\n重复的段出现次数：{same_id + diff_id}")
    print(f"  完全一致（IP ID/TTL/整帧哈希都相同）: {same_id}   ← 捕获层重复递交")
    print(f"  不完全一致（重新封装）            : {diff_id}   ← 疑似真实重传")
    if gaps:
        gaps.sort()
        print(f"\n重复间隔：最小 {gaps[0]*1000:.2f}ms  中位 {gaps[len(gaps)//2]*1000:.2f}ms  "
              f"最大 {gaps[-1]*1000:.1f}ms")
    if id_deltas:
        print(f"IP ID 差值分布（top5）: {id_deltas.most_common(5)}")
    print("\n完全一致样例（帧号/间隔/IP_ID/哈希）:")
    for k, gap, a, b, i1, i2, h in samples:
        print(f"  {k[0]}:{k[1]} → {k[2]}:{k[3]}  seq={k[4]} len={k[5]}  "
              f"帧#{a}→#{b}  间隔 {gap*1000:.1f}ms  ipid={i1}/{i2}  hash={h}")

    verdict = "捕获层重复递交占多数 —— 需要在引擎层去重" if same_id > diff_id else \
              "真实 TCP 重传占多数 —— 统计可信"
    print(f"\n结论：{verdict}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
