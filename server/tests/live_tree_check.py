"""真机深度解析验证：抓真实流量，逐包拉详情接口，校验协议树质量。

与 tree_test.py 的分工：
  tree_test.py   → 合成样本，覆盖 15 类协议与字段语义（可离线跑）
  live_tree_check.py → 真实网卡流量，验证端到端（抓包→解析→API）与真实协议识别率

用法：python tests/live_tree_check.py [抓包秒数] [最多校验包数]
"""
from __future__ import annotations

import json
import sys
import time
import urllib.request
from collections import Counter
from pathlib import Path

BASE = "http://127.0.0.1:8765"
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_op = urllib.request.build_opener(urllib.request.ProxyHandler({}))

PASS = FAIL = 0
FAILS: list[str] = []


def check(name, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [v] {name}  {extra}")
    else:
        FAIL += 1
        FAILS.append(f"{name} {extra}")
        print(f"  [X] {name}  {extra}")


def get(path, timeout=20):
    with _op.open(BASE + path, timeout=timeout) as r:
        return json.load(r)


def post(path, data, timeout=40):
    req = urllib.request.Request(BASE + path, data=json.dumps(data).encode(),
                                 headers={"Content-Type": "application/json"})
    with _op.open(req, timeout=timeout) as r:
        return json.load(r)


def flat_fields(layers):
    out = []
    for l in layers:
        out += l.get("fields") or []
        out += flat_fields(l.get("children") or [])
    return out


def walk_ok(node, raw_len, label, problems):
    if not isinstance(node, dict) or "title" not in node:
        problems.append(f"{label}: 层结构非法")
        return
    if not isinstance(node.get("fields"), list) or not isinstance(node.get("children"), list):
        problems.append(f"{label}: fields/children 非列表")
        return
    for f in node["fields"]:
        if not isinstance(f, dict) or "value" not in f or "offset" not in f:
            problems.append(f"{label}: 字段结构非法 {str(f)[:60]}")
            continue
        if f["offset"] >= 0 and f["size"] > 0 and f["offset"] + f["size"] > raw_len:
            problems.append(f"{label}.{f['name']}: 越界 off={f['offset']} sz={f['size']}")
    for c in node["children"]:
        walk_ok(c, raw_len, label + "/" + str(c.get("name")), problems)


def main() -> int:
    secs = int(sys.argv[1]) if len(sys.argv) > 1 else 15
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 1200

    h = get("/api/health")
    check("服务健康", h.get("ok") is True, str(h.get("engines", {}).get("active")))

    ifs = get("/api/interfaces")["items"]
    rec = next((i for i in ifs if i.get("recommended")), ifs[0] if ifs else None)
    check("推荐网卡可用", bool(rec) and bool(rec.get("ip")), str(rec and rec.get("name")))

    r = post("/api/capture/start", {"interface": rec["name"], "bpf_filter": "", "promisc": True})
    check("启动抓包", r.get("ok") is True, f"engine={r.get('engine')}")

    # 主动制造 TLS / DNS 流量，确保 ClientHello（SNI）、DNS 查询会被抓到
    def generate():
        time.sleep(1.0)
        for url in ("https://www.baidu.com", "https://www.qq.com", "https://www.aliyun.com"):
            try:
                with _op.open(url, timeout=6):
                    pass
            except Exception:                                     # noqa: BLE001
                pass

    import threading
    th = threading.Thread(target=generate, daemon=True)
    th.start()

    time.sleep(secs)
    st = get("/api/capture/status")
    check("已抓到报文", st.get("packets", 0) > 0, f"packets={st.get('packets')}")

    # 采样校验详情
    items = post("/api/packets/query", {"filter": "", "offset": 0, "limit": limit})["items"]
    step = max(len(items) // 400, 1)
    sample = items[::step][:400]
    proto_counter: Counter = Counter()
    app_counter: Counter = Counter()
    snis: list[str] = []
    notes_hits: list[str] = []
    problems: list[str] = []
    layer_counts: list[int] = []

    for it in sample:
        try:
            d = get("/api/packets/%d" % it["id"])
        except Exception as exc:                                  # noqa: BLE001
            problems.append(f"#{it['id']} 详情接口失败 {exc}")
            continue
        layers = d.get("layers") or []
        if not layers:
            problems.append(f"#{it['id']} 无协议树")
            continue
        layer_counts.append(len(layers))
        raw_len = d["summary"]["length"]
        for lay in layers:
            walk_ok(lay, raw_len, f"#{it['id']}", problems)
        names = [l["name"] for l in layers]
        for n in names:
            app_counter[n] += 1
        proto_counter[it["proto"]] += 1
        fields = flat_fields(layers)
        for f in fields:
            if f["name"] == "tls.handshake.extensions_server_name" and f["value"]:
                snis.append(f["value"])
        if d.get("notes"):
            notes_hits.append(f"#{it['id']} " + " | ".join(n["flag"] for n in d["notes"]))

    check("详情接口全部可解析", not problems, f"{len(problems)} 个问题")
    if problems:
        for p in problems[:6]:
            print("      -", p)
    check("协议树平均层数 ≥ 3", (sum(layer_counts) / max(len(layer_counts), 1)) >= 3,
          "%.2f 层" % (sum(layer_counts) / max(len(layer_counts), 1)))

    print("\n  协议命中（采样 %d 包）：%s" % (len(sample), dict(app_counter.most_common(12))))
    print("  协议分布：%s" % dict(proto_counter.most_common(8)))

    if app_counter.get("tls"):
        # 采样可能错过 ClientHello（新连接才发），专门扫一遍 tls 包
        ch_scanned = 0
        for it in post("/api/packets/query", {"filter": "tls", "offset": 0, "limit": 400})["items"]:
            if "Cli" not in (it.get("info") or ""):
                continue
            ch_scanned += 1
            d = get("/api/packets/%d" % it["id"])
            for f in flat_fields(d.get("layers") or []):
                if f["name"] == "tls.handshake.extensions_server_name" and f["value"]:
                    snis.append(f["value"])
            if ch_scanned >= 40:
                break
        check("TLS ClientHello 解析出 SNI", bool(snis) or ch_scanned == 0,
              ("扫描 %d 个 ClientHello；" % ch_scanned) +
              ("、".join(dict.fromkeys(snis[:6])) if snis else "本次无 ClientHello"))
    if app_counter.get("dns"):
        check("DNS 包被识别", True, "dns 层 %d 个" % app_counter["dns"])
    if notes_hits:
        print("\n  TCP 分析标记示例：")
        for n in notes_hits[:6]:
            print("    ", n)
        check("TCP 分析标记可用", True, f"{len(notes_hits)} 个包带标记")

    r = post("/api/capture/stop", {})
    check("停止抓包", r.get("ok") is not False, str(r.get("packets")))

    print(f"\n{'=' * 60}")
    print(f"真机解析验证：{PASS} 通过 / {FAIL} 失败")
    for f in FAILS:
        print("  -", f)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
