"""真机抓包验证：直接用 ScapyEngine 抓若干秒，检查能否拿到真实链路层数据。"""
from __future__ import annotations

import sys
import time

sys.path.insert(0, __file__.rsplit("\\", 2)[0] if "\\" in __file__ else ".")
sys.path.insert(0, ".")

from app.capture.scapy_engine import ScapyEngine          # noqa: E402
from app.parser.dissect import parse                      # noqa: E402


def main() -> int:
    e = ScapyEngine()
    if not e.check():
        print("FAIL check:", e.reason)
        return 1
    ifs = e.list_interfaces()
    # 挑一张有真实 IPv4 的网卡（排除 APIPA 169.254）
    target = None
    for i in ifs:
        ip = i.ip or ""
        if ip and not ip.startswith("169.254") and not ip.startswith("127."):
            target = i
            break
    if target is None:
        target = next((i for i in ifs if i.is_up), None)
    if target is None:
        print("FAIL 无可用网卡")
        return 1
    print(f"抓包网卡: {target.name!r}  ip={target.ip}")
    print(f"  desc={target.description!r}")

    got = []

    def cb(raw: bytes, ts: float) -> None:
        got.append((raw, ts))

    seconds = float(sys.argv[1]) if len(sys.argv) > 1 else 5.0
    e.start(target.name, "", True, 65535, cb)
    print(f"开始抓取 {seconds}s（请留意是否弹出 UAC / 是否有流量）...")
    t0 = time.time()
    while time.time() - t0 < seconds * 1.4:
        time.sleep(0.25)
        if not e._running:
            break
    e.stop()
    print(f"引擎 reason={e.reason!r}")

    print(f"\n=== 抓到 {len(got)} 个包 ===")
    if not got:
        print("无包。可能原因：1) 无管理员权限 2) 该网卡无流量 3) 驱动限制")
        return 2
    ok = 0
    protos = {}
    for idx, (raw, ts) in enumerate(got[:8], 1):
        try:
            rec = parse(raw, ts, 1, idx)
        except Exception as exc:                                    # noqa: BLE001
            print(f"#{idx} 解析失败: {exc}")
            continue
        ok += 1
        protos[rec.proto] = protos.get(rec.proto, 0) + 1
        print(f"#{idx:3d} len={len(raw):5d} {rec.src:>15} -> {rec.dst:<15} "
              f"{rec.proto:6} {rec.app or '':8} {rec.info[:52]}")
    # 全量统计
    for raw, ts in got:
        try:
            rec = parse(raw, ts, 1, 0)
            protos[rec.proto] = protos.get(rec.proto, 0) + 1
            if rec.app:
                protos[rec.app] = protos.get(rec.app, 0) + 1
        except Exception:                                            # noqa: BLE001
            protos["<解析失败>"] = protos.get("<解析失败>", 0) + 1
    print("\n协议分布:", dict(sorted(protos.items(), key=lambda kv: -kv[1])))
    print(f"链路层类型检查（前{len(got[:8])}个以太头）:")
    for raw, _ in got[:3]:
        print("   dst_mac=", ":".join(f"{b:02X}" for b in raw[0:6]),
              "src_mac=", ":".join(f"{b:02X}" for b in raw[6:12]),
              "ethertype=0x" + raw[12:14].hex())
    print(f"\nRESULT packets={len(got)} parsed_ok_sample={ok}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
