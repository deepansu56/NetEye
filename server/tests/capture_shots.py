"""临时截图：定位带 TCP 分析标记 / TLS SNI 的报文，选中后截图（交付用）。"""
import json
import sys
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8765"
ROOT = Path(r"C:\Users\jj_10\OneDrive\文档\GitHub\NetEye")
OUT = ROOT / "docs" / "screenshots"
_op = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def get(p):
    with _op.open(BASE + p, timeout=25) as r:
        return json.load(r)


def post(p, d):
    req = urllib.request.Request(BASE + p, data=json.dumps(d).encode(),
                                 headers={"Content-Type": "application/json"})
    with _op.open(req, timeout=40) as r:
        return json.load(r)


def flat(ls):
    out = []
    for l in ls:
        out += l.get("fields") or []
        out += flat(l.get("children") or [])
    return out


def main():
    pcap = sys.argv[1]
    notes_id, sni_id, notes_flag = None, None, ""
    for it in post("/api/packets/query", {"filter": "tcp", "offset": 0, "limit": 900})["items"]:
        d = get("/api/packets/%d" % it["id"])
        if d.get("notes"):
            notes_id = it["id"]
            notes_flag = d["notes"][0]["flag"]
            break
    for it in post("/api/packets/query", {"filter": "tls", "offset": 0, "limit": 400})["items"]:
        if "Cli" not in (it.get("info") or ""):
            continue
        d = get("/api/packets/%d" % it["id"])
        if any(f["name"] == "tls.handshake.extensions_server_name" and f["value"]
               for f in flat(d["layers"])):
            sni_id = it["id"]
            break
    print("notes packet:", notes_id, notes_flag, " sni packet:", sni_id)

    with sync_playwright() as p:
        b = p.chromium.launch(headless=True)
        pg = b.new_page(viewport={"width": 1680, "height": 1000})
        pg.goto(BASE, wait_until="networkidle")
        pg.wait_for_timeout(2500)
        pg.evaluate("""async (path) => {
            await fetch('/api/import', {method:'POST',headers:{'Content-Type':'application/json'},
                body: JSON.stringify({path})});
        }""", pcap)
        pg.wait_for_timeout(4000)

        # 把详情区拉高，便于展示协议树
        try:
            box = pg.query_selector(".splitter-h").bounding_box()
            if box:
                x = box["x"] + box["width"] / 2
                y = box["y"] + box["height"] / 2
                pg.mouse.move(x, y)
                pg.mouse.down()
                pg.mouse.move(x, y - 330, steps=8)
                pg.mouse.up()
                pg.wait_for_timeout(600)
        except Exception as exc:
            print("resize fail", exc)

        def pick(pid, name, focus=""):
            if pid is None:
                return
            # 列表是虚拟滚动：先滚到目标行附近再点击
            pg.evaluate("""(pid) => {
                const sc = document.querySelector('#pkt-scroll');
                if (sc) sc.scrollTop = Math.max(0, (pid - 4) * 24);
            }""", pid)
            pg.wait_for_timeout(900)
            ok = pg.evaluate("""(pid) => {
                const rows = [...document.querySelectorAll('.pkt-row')];
                const el = rows.find(r => ((r.querySelector('.num') || {}).textContent || '').trim() === String(pid));
                if (!el) return false;
                el.click();
                return true;
            }""", pid)
            print("pick", pid, ok, "rows=", pg.eval_on_selector_all(".pkt-row", "e => e.length"))
            pg.wait_for_timeout(1500)
            if focus:
                hit = pg.evaluate("""(kw) => {
                    const t = [...document.querySelectorAll('.tf')];
                    const el = t.find(x => (x.innerText || '').includes(kw));
                    if (!el) return false;
                    el.scrollIntoView({block: 'center'});
                    el.click();
                    return true;
                }""", focus)
                print("   focus", focus, hit)
                pg.wait_for_timeout(700)
            pg.screenshot(path=str(OUT / name))
            print("saved", name)

        pick(sni_id, "ui_10_tls_sni.png", focus="Server Name Indication")
        pick(notes_id, "ui_11_tcp_flags.png", focus=notes_flag or "TCP ")

        # 统计 + AI
        for tab, name in [("统计", "ui_12_stats.png"), ("AI 分析", "ui_13_ai.png")]:
            try:
                pg.click(f"text={tab}", timeout=4000)
                pg.wait_for_timeout(2500)
                pg.screenshot(path=str(OUT / name))
                print("saved", name)
            except Exception as exc:
                print("tab fail", tab, exc)
        b.close()


if __name__ == "__main__":
    main()
