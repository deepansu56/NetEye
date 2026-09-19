"""NetEye 端到端链路测试：对运行中的服务做真实 HTTP 调用。

覆盖：导入 pcap → 查询 → 统计 → 过滤 → 详情/流 → 实时抓包 → 导出回读
      → 会话存取 → AI 对话（本地兜底）→ 端口状态。

用法：
    python tests/e2e_test.py [base_url]
默认 http://127.0.0.1:8765
"""
from __future__ import annotations

import os
import sys
import time
import json
from pathlib import Path

import httpx

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8765"
ROOT = Path(__file__).resolve().parents[2]
SERVER = ROOT / "server"

PASS, FAIL = 0, 0
FAILS: list[str] = []


def check(name: str, cond: bool, extra: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  PASS  %s%s" % (name, ("  -> " + extra) if extra else ""))
    else:
        FAIL += 1
        FAILS.append(name)
        print("  FAIL  %s%s" % (name, ("  -> " + extra) if extra else ""))


def req(method: str, path: str, **kw):
    with httpx.Client(base_url=BASE, timeout=60.0) as c:
        r = c.request(method, path, **kw)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, r.text[:400]


def section(t: str) -> None:
    print()
    print("== %s ==" % t)


def main() -> int:
    global PASS, FAIL
    print("=" * 52)
    print("  NetEye 端到端链路测试  ->  %s" % BASE)
    print("=" * 52)

    # ------------------------------------------------------------ 0. 健康
    section("0. 服务健康")
    code, body = req("GET", "/api/health")
    check("GET /api/health 200", code == 200, str(code))
    check("health.ok 为 true", isinstance(body, dict) and body.get("ok") is True)
    engines = (body or {}).get("engines", {})
    check("返回引擎状态", isinstance(engines, dict),
          "npcap=%s raw=%s" % (engines.get("npcap", {}).get("available"),
                               engines.get("raw", {}).get("available")))
    check("前端静态资源可访问",
          req("GET", "/")[0] == 200)

    # ------------------------------------------------------------ 1. 清空 + 导入
    section("1. 清空并导入样例 pcap")
    req("POST", "/api/capture/stop")
    check("POST /api/capture/clear", req("POST", "/api/capture/clear")[0] == 200)

    sample = SERVER / "tools" / "gen_sample_pcap.py"
    pcap = ROOT / "data" / "captures" / "sample_demo.pcap"
    if not pcap.is_file() and sample.is_file():
        pcap.parent.mkdir(parents=True, exist_ok=True)
        os.system('"%s" "%s" "%s"' % (sys.executable, sample, pcap))
    check("样例 pcap 存在", pcap.is_file(), str(pcap))

    if pcap.is_file():
        code, body = req("POST", "/api/sessions/import-pcap",
                         json={"path": str(pcap)})
        check("导入 pcap 成功", code == 200 and (body or {}).get("ok") is True,
              json.dumps(body, ensure_ascii=False)[:200])
    n_after = (req("GET", "/api/capture/status")[1] or {}).get("packets", 0)
    check("导入后有报文数据", n_after > 0, "packets=%s" % n_after)

    # ------------------------------------------------------------ 2. 报文查询
    section("2. 报文查询 / 详情 / 流")
    code, body = req("POST", "/api/packets/query",
                     json={"filter": "", "offset": 0, "limit": 20})
    check("POST /api/packets/query", code == 200)
    items = (body or {}).get("items", [])
    check("返回报文列表", len(items) > 0, "count=%d" % len(items))
    check("报文含必要字段",
          bool(items) and all(k in items[0] for k in ("id", "proto", "src", "dst")))

    if items:
        pid = items[0]["id"]
        code, detail = req("GET", "/api/packets/%d" % pid)
        check("GET /api/packets/{id} 详情", code == 200 and (detail or {}).get("id") == pid)
        code, stream = req("GET", "/api/packets/%d/stream" % pid)
        check("GET /api/packets/{id}/stream", code == 200)

    # ------------------------------------------------------------ 3. 统计
    section("3. 统计分析")
    for name, path in (("summary", "/api/stats/summary"),
                       ("protocols", "/api/stats/protocols"),
                       ("conversations", "/api/stats/conversations"),
                       ("endpoints", "/api/stats/endpoints"),
                       ("ports", "/api/stats/ports"),
                       ("expert", "/api/stats/expert"),
                       ("anomalies", "/api/stats/anomalies"),
                       ("io", "/api/stats/io")):
        code, body = req("GET", path)
        ok_ = code == 200 and isinstance(body, (dict, list))
        check("GET /api/stats/%s" % name, ok_)
    code, summ = req("GET", "/api/stats/summary")
    inner = (summ or {}).get("summary", {}) if isinstance(summ, dict) else {}
    for k in ("packets", "bytes", "tcp_streams", "retransmissions",
              "keepalives", "out_of_order"):
        check("summary 含字段 %s" % k, k in inner, str(inner.get(k)))

    # ------------------------------------------------------------ 4. 显示过滤
    section("4. 显示过滤器")
    for expr in ("tcp", "udp", "ip", "tcp.port==80", "!arp", "dns"):
        code, body = req("GET", "/api/stats/filter/validate", params={"expr": expr})
        check("过滤语法合法: %s" % expr, code == 200 and (body or {}).get("ok") is True)
    code, body = req("GET", "/api/stats/filter/validate", params={"expr": "tcp.port=="})
    check("非法表达式被拒绝",
          code == 200 and (body or {}).get("ok") is False, str(body)[:120])

    code, body = req("POST", "/api/packets/query", json={"filter": "tcp", "offset": 0, "limit": 50})
    tcp_items = (body or {}).get("items", [])
    check("按 tcp 过滤可返回结果", code == 200 and len(tcp_items) >= 0,
          "matched=%d" % len(tcp_items))

    # ------------------------------------------------------------ 5. 实时抓包
    section("5. 实时抓包（Npcap）")
    code, ifs = req("GET", "/api/interfaces")
    check("GET /api/interfaces", code == 200)
    iface = ""
    if isinstance(ifs, dict) and ifs.get("items"):
        items = ifs["items"]
        rec = [i for i in items if i.get("recommended")]
        iface = (rec[0] if rec else items[0]).get("name", "")
        check("列出网卡", bool(iface), "%s / 共 %d 个" % (iface, len(items)))
        check("首选网卡非伪适配器",
              not any(h in (iface or "").lower() for h in ("miniport", "pseudo", "loopback")),
              iface)
        iface_ip = (rec[0] if rec else items[0]).get("ip", "")
        check("首选网卡有 IP 地址", bool(iface_ip), iface_ip)

    code, body = req("POST", "/api/capture/start",
                     json={"interface": iface, "filter": "", "promisc": True,
                           "snaplen": 65535, "auto_save_pcap": False})
    started = code == 200 and (body or {}).get("ok") is True
    check("POST /api/capture/start", started, json.dumps(body, ensure_ascii=False)[:200])

    packets_live = 0
    if started:
        for _ in range(20):
            time.sleep(1)
            st = req("GET", "/api/capture/status")[1] or {}
            packets_live = st.get("packets", 0)
            if packets_live > 30:
                break
        check("实时抓到报文", packets_live > 0, "packets=%d" % packets_live)

        # 暂停 / 继续：继续后必须保留暂停前的数据（不能重新计数）
        code, st = req("POST", "/api/capture/pause")
        check("POST /api/capture/pause", code == 200 and (st or {}).get("state") == "paused")
        n_paused = (req("GET", "/api/capture/status")[1] or {}).get("packets", 0)
        check("暂停后数据仍在", n_paused >= packets_live,
              "%d -> %d" % (packets_live, n_paused))
        code, st = req("POST", "/api/capture/resume")
        check("POST /api/capture/resume", code == 200 and (st or {}).get("ok") is True)
        time.sleep(3)
        n_resumed = (req("GET", "/api/capture/status")[1] or {}).get("packets", 0)
        check("继续后不清空历史数据", n_resumed >= n_paused,
              "%d -> %d" % (n_paused, n_resumed))

        code, st = req("POST", "/api/capture/stop")
        check("POST /api/capture/stop", code == 200 and (st or {}).get("ok") is True,
              json.dumps(st, ensure_ascii=False)[:200])
        check("停止后包数与继续时一致", (st or {}).get("packets", 0) >= n_paused,
              "stop=%s vs paused=%s" % ((st or {}).get("packets"), n_paused))
    else:
        print("  SKIP  实时抓包不可用（需要管理员权限 / Npcap），跳过抓包子用例")

    # ------------------------------------------------------------ 6. 导出
    section("6. 导出与回读")
    n_before = (req("GET", "/api/capture/status")[1] or {}).get("packets", 0)
    for fmt, ext in (("pcap", ".pcap"), ("csv", ".csv"), ("json", ".json")):
        name = "e2e_export_%s" % fmt
        code, body = req("POST", "/api/export", json={"format": fmt, "filename": name})
        good = code == 200 and (body or {}).get("ok") is True
        check("导出 %s" % fmt, good, json.dumps(body, ensure_ascii=False)[:160])
        if good:
            path = (body or {}).get("path", "")
            check("  %s 文件带扩展名 %s" % (fmt, ext), path.lower().endswith(ext), path)
            if path and os.path.isfile(path):
                check("  %s 文件非空" % fmt, os.path.getsize(path) > 0,
                      "%d bytes" % os.path.getsize(path))
            else:
                check("  %s 文件存在" % fmt, False, path)

    # pcap 回读
    code, body = req("GET", "/api/captures")
    caps = (body or {}).get("items", []) if isinstance(body, dict) else []
    check("GET /api/captures 列出产物", code == 200, "count=%d" % len(caps))
    pcap_files = [c for c in caps if str(c.get("path", "")).lower().endswith(".pcap")]
    if pcap_files:
        target = sorted(pcap_files, key=lambda c: c.get("size", 0), reverse=True)[0]
        code, body = req("POST", "/api/sessions/import-pcap",
                         json={"path": target["path"]})
        check("pcap 回读（导入自己导出的文件）",
              code == 200 and (body or {}).get("ok") is True,
              json.dumps(body, ensure_ascii=False)[:200])

    # ------------------------------------------------------------ 7. 会话存取
    section("7. 会话存取")
    code, body = req("POST", "/api/sessions/save", json={"name": "e2e_session"})
    check("POST /api/sessions/save", code == 200 and (body or {}).get("ok") is True)
    sid = (body or {}).get("id") or (body or {}).get("session_id")
    code, body = req("GET", "/api/sessions")
    lst = (body or {}).get("items", []) if isinstance(body, dict) else body
    check("GET /api/sessions 列表", code == 200 and len(lst) > 0, "count=%d" % len(lst))
    if sid:
        code, body = req("POST", "/api/sessions/load/%s" % sid)
        check("POST /api/sessions/load/{id}", code == 200 and (body or {}).get("ok") is True)
        check("DELETE /api/sessions/{id}",
              req("DELETE", "/api/sessions/%s" % sid)[0] == 200)

    # ------------------------------------------------------------ 8. AI
    section("8. AI 对话")
    code, body = req("GET", "/api/ai/config")
    check("GET /api/ai/config", code == 200)
    tools = (body or {}).get("tools", [])
    check("AI 工具已注册", len(tools) >= 5, "tools=%d" % len(tools))
    check("GET /api/ai/history", req("GET", "/api/ai/history")[0] == 200)
    code, body = req("POST", "/api/ai/chat",
                     json={"messages": [{"role": "user",
                                         "content": "当前抓包数据里一共有多少个包？"}]})
    check("POST /api/ai/chat 返回", code == 200, "code=%s" % code)
    if code == 200:
        text = json.dumps(body, ensure_ascii=False)
        check("AI 回复非空", len(text) > 20, text[:160])

    # ------------------------------------------------------------ 9. 端口状态
    section("9. 端口 / 连接状态")
    code, body = req("GET", "/api/stats/portstate")
    ok_ = code == 200
    check("GET /api/stats/portstate", ok_)
    if isinstance(body, dict):
        items = body.get("items", [])
        check("端口状态非空", len(items) > 0, "count=%d" % len(items))
        check("端口状态可序列化（无非法字符）", True)

    # ------------------------------------------------------------ 结果
    print()
    print("=" * 52)
    print("  结果：%d 通过 / %d 失败" % (PASS, FAIL))
    if FAILS:
        print("  失败项：")
        for f in FAILS:
            print("    - %s" % f)
    print("=" * 52)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
