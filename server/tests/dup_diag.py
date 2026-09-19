"""诊断：实时抓取并检查是否存在“相邻完全重复的原始帧”。

若同一 raw bytes 在极短间隔内多次出现，说明是 Npcap/驱动重复递交，
而非真实网络重传 —— 这会污染所有统计（重传率、pps、字节数）。
"""
from __future__ import annotations

import sys
import threading
import time
from collections import OrderedDict

sys.path.insert(0, ".")

from app.capture.scapy_engine import ScapyEngine          # noqa: E402

LOCK = threading.Lock()
frames: list[tuple[float, bytes]] = []
DUPS: list[tuple[int, float, str]] = []       # (index, delta_us, note)
_seen: "OrderedDict[bytes, int]" = OrderedDict()
WINDOW = 256            # 滑动窗口：最近 256 帧内查重


def cb(raw: bytes, ts: float) -> None:
    with LOCK:
        idx = len(frames)
        frames.append((ts, raw))
        hit = _seen.get(raw)
        if hit is not None:
            # 相对被撞的前一帧算间隔
            prev_ts = frames[hit][0]
            DUPS.append((idx, (ts - prev_ts) * 1e6, f"与 #{hit} 完全相同({len(raw)}B)"))
        _seen[raw] = idx
        if len(_seen) > WINDOW:
            _seen.popitem(last=False)


def main() -> int:
    e = ScapyEngine()
    seconds = float(sys.argv[1]) if len(sys.argv) > 1 else 6.0
    print(f"抓取 {seconds}s ...")
    e.start(sys.argv[2] if len(sys.argv) > 2 else None, "", True, 65535, cb)
    time.sleep(seconds + 0.5)
    e.stop()

    with LOCK:
        total = len(frames)
        print(f"\n抓到帧数: {total}")
        print(f"重复帧数: {len(DUPS)}  ({len(DUPS) / max(total, 1) * 100:.1f}%)")
        if DUPS:
            print("\n前 10 条重复记录（间隔单位 微秒）:")
            for idx, dt, note in DUPS[:10]:
                print(f"  #{idx:<6d} 间隔 {dt:>10.0f}us  {note}")
            dts = sorted(d for _, d, _ in DUPS)
            print(f"\n间隔分布: 最小={dts[0]:.0f}us 中位={dts[len(dts)//2]:.0f}us "
                  f"最大={dts[-1]:.0f}us")
            n = sum(1 for d in dts if d < 100)
            print(f"间隔 <100us（几乎可断定重复递交）: {n}/{len(dts)} = {n/len(dts)*100:.0f}%")
        # 检查是否集中在某些 4 元组
        print("\n结论:", "存在重复递交，需在捕获层去重" if len(DUPS) > total * 0.001
              else "未见明显重复递交")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
