"""NetEye 前端 UI 冒烟：真实浏览器打开页面，捕获 JS 报错，点「开始」验证抓包链路。

用法： python tests/ui_check.py [url] [shot_dir]
需要 playwright（本仓库其它测试不依赖它，缺了会直接跳过）。
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8765"
SHOT = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(__file__).resolve().parents[1] / ".." / "docs" / "screenshots"
SHOT = SHOT.resolve()

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


def main() -> int:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("SKIP: 未安装 playwright，跳过 UI 检查")
        return 0

    SHOT.mkdir(parents=True, exist_ok=True)
    console_errors: list[str] = []
    page_errors: list[str] = []

    with sync_playwright() as p:
        browser = None
        for kwargs in ({}, {"channel": "msedge"}, {"channel": "chrome"}):
            try:
                browser = p.chromium.launch(**kwargs)
                break
            except Exception:
                continue
        if browser is None:
            print("SKIP: 没有可用的 Chromium/Edge/Chrome，跳过 UI 检查")
            return 0

        pg = browser.new_page(viewport={"width": 1600, "height": 950})
        pg.on("console", lambda m: console_errors.append("%s: %s" % (m.type, m.text))
              if m.type == "error" else None)
        pg.on("pageerror", lambda e: page_errors.append(str(e)))

        print("== 打开首页 ==")
        pg.goto(URL, wait_until="networkidle", timeout=60000)
        pg.wait_for_timeout(3000)

        check("页面标题正确", "NetEye" in (pg.title() or ""), pg.title())
        root_html = pg.inner_html("#root") if pg.query_selector("#root") else ""
        check("React 已挂载（#root 非空）", len(root_html) > 500, "%d chars" % len(root_html))

        body = pg.inner_text("body")
        for kw in ("NetEye", "开始", "停止", "清空", "保存", "导入",
                   "协议分布", "曲线", "统计", "端口", "专家"):
            check("页面包含「%s」" % kw, kw in body)

        # 网卡下拉应默认选中真实在用的网卡（有 IP、非伪适配器）
        sel_txt = ""
        el = pg.query_selector("select")
        if el:
            sel_txt = (el.inner_text() or "").replace("\n", " ")
        check("网卡下拉默认选中真实网卡",
              bool(sel_txt) and ("." in sel_txt), sel_txt[:80])

        pg.screenshot(path=str(SHOT / "ui_01_home.png"), full_page=False)

        # ---------- 点击开始抓包 ----------
        print()
        print("== 点击「开始」抓包 ==")
        clicked = False
        for sel in ("button:has-text('开始')", ".btn.primary"):
            try:
                if pg.query_selector(sel):
                    pg.click(sel, timeout=5000)
                    clicked = True
                    break
            except Exception:
                continue
        check("点到「开始」按钮", clicked)

        if clicked:
            pg.wait_for_timeout(7000)
            txt = pg.inner_text("body")
            pg.screenshot(path=str(SHOT / "ui_02_capturing.png"), full_page=False)

            # 抓包中应出现「停止」按钮
            check("出现「停止」按钮（说明状态已切到抓包中）", "停止" in txt)
            # 概览里应出现非零数字
            digits = [w for w in txt.replace(",", "").split() if w.isdigit() and int(w) > 0]
            check("页面上出现非零统计数字", len(digits) > 0, "e.g. %s" % digits[:8])

            # 停止
            try:
                pg.click("button:has-text('停止')", timeout=5000)
                pg.wait_for_timeout(1500)
            except Exception:
                pass
            pg.screenshot(path=str(SHOT / "ui_03_stopped.png"), full_page=False)

        # ---------- 协议树（Wireshark 风格详情） ----------
        print()
        print("== 协议树 / 十六进制联动 ==")
        sample = Path(__file__).resolve().parents[2] / "data" / "captures" / "sample_demo.pcap"
        if not sample.exists():
            try:
                import subprocess
                subprocess.run([sys.executable, str(Path(__file__).parent.parent / "tools" / "gen_sample_pcap.py")],
                               cwd=str(Path(__file__).parent.parent), timeout=120)
            except Exception:
                pass
        imported = False
        if sample.exists():
            try:
                pg.evaluate("""async (path) => {
                    const r = await fetch('/api/import', {method:'POST',
                        headers:{'Content-Type':'application/json'},
                        body: JSON.stringify({path})});
                    return await r.text();
                }""", str(sample))
                pg.wait_for_timeout(3500)
                imported = True
            except Exception as exc:
                print("      导入样本失败：", exc)
        check("导入样本 pcap", imported, sample.name)

        rows = pg.query_selector_all(".pkt-row")
        check("报文列表已渲染", len(rows) > 0, "%d 行" % len(rows))
        if rows:
            rows[min(3, len(rows) - 1)].click()
            pg.wait_for_timeout(2200)

        n_layer = pg.eval_on_selector_all(".tnode", "e => e.length")
        n_field = pg.eval_on_selector_all(".tf", "e => e.length")
        check("协议树有 3 层以上协议", n_layer >= 3, "%d 层" % n_layer)
        check("协议树字段数 ≥ 15", n_field >= 15, "%d 个字段" % n_field)
        titles = pg.eval_on_selector_all(".tt .ttext", "e => e.map(x => x.textContent)")
        check("出现 Frame / Ethernet 层", any("Frame" in t for t in titles)
              and any("Ethernet" in t for t in titles), " | ".join(t[:26] for t in titles[:4]))

        # 折叠 / 展开
        try:
            first = pg.query_selector(".tt")
            before = pg.eval_on_selector_all(".tf", "e => e.length")
            first.click()
            pg.wait_for_timeout(400)
            after = pg.eval_on_selector_all(".tf", "e => e.length")
            check("协议层可折叠", after != before, "%d -> %d" % (before, after))
            first.click()
            pg.wait_for_timeout(300)
        except Exception as exc:
            check("协议层可折叠", False, str(exc))

        # 点击字段 → 十六进制高亮 + 说明栏
        picked = ""
        for e in pg.query_selector_all(".tf"):
            t = (e.inner_text() or "")
            if "Source Port" in t or "Destination" in t or "Source Address" in t:
                e.click()
                picked = t.replace("\n", " ")
                pg.wait_for_timeout(500)
                break
        n_hl = pg.eval_on_selector_all(".hl", "e => e.length")
        check("点击字段高亮对应字节", n_hl > 0, "%d 个高亮段落" % n_hl)
        fbar = pg.query_selector(".field-bar")
        fbar_txt = (fbar.inner_text() if fbar else "").replace("\n", " | ")
        check("字段说明栏显示显示过滤器名与含义",
              ("." in fbar_txt) and ("字节" in fbar_txt or "说明" in fbar_txt or len(fbar_txt) > 12),
              fbar_txt[:110])

        # 点击十六进制字节 → 反查字段
        try:
            spans = pg.query_selector_all(".hex-line span")
            rev = ""
            if len(spans) > 14:
                spans[14].click()
                pg.wait_for_timeout(500)
                rev = (pg.query_selector(".field-bar").inner_text() or "").replace("\n", " | ")
            check("点击字节可反查字段", "." in rev and "字节" in rev, rev[:110])
        except Exception as exc:
            check("点击字节可反查字段", False, str(exc))

        pg.screenshot(path=str(SHOT / "ui_05_detail_tree.png"), full_page=False)

        # ---------- 统计面板 ----------
        print()
        print("== 统计与分析面板 ==")
        try:
            pg.click("text=统计", timeout=4000)
            pg.wait_for_timeout(2500)
        except Exception:
            pass
        kpis = pg.eval_on_selector_all(".kpi", "e => e.map(x => x.innerText.replace(/\\n/g,'='))")
        check("统计面板有 KPI 概览卡片", len(kpis) >= 6, " / ".join(kpis[:3]))
        subtabs = pg.eval_on_selector_all(".subtabs .st", "e => e.map(x => x.textContent)")
        for want in ("协议分级", "会话", "端点", "端口流量", "IO 分桶", "专家信息", "异常检测"):
            check("统计子表「%s」存在" % want, want in subtabs, "")
        try:
            pg.click("text=异常检测", timeout=4000)
            pg.wait_for_timeout(2500)
            anom = pg.eval_on_selector_all(".anom", "e => e.length")
            check("异常检测页有内容或空提示",
                  anom > 0 or "暂无异常" in pg.inner_text("body"), "%d 条" % anom)
            pg.click("text=会话", timeout=4000)
            pg.wait_for_timeout(2500)
            cells = pg.eval_on_selector_all(".tbl tbody tr", "e => e.length")
            check("会话表有数据行", cells > 0, "%d 行" % cells)
        except Exception as exc:
            check("统计子表切换", False, str(exc))
        pg.screenshot(path=str(SHOT / "ui_06_stats.png"), full_page=False)

        # ---------- AI 面板 ----------
        print()
        print("== AI 对话面板 ==")
        for tab in ("AI 分析", "AI"):
            try:
                if pg.query_selector("text=%s" % tab):
                    pg.click("text=%s" % tab, timeout=4000)
                    pg.wait_for_timeout(1500)
                    break
            except Exception:
                continue
        status = pg.query_selector(".ai-status")
        check("AI 面板有引擎状态条", status is not None,
              (status.inner_text().replace("\n", " ") if status else "")[:90])
        quick = pg.eval_on_selector_all(".quick button", "e => e.map(x => x.textContent)")
        check("有待选快捷问题", len(quick) >= 4, " / ".join(quick[:3]))
        snap = pg.query_selector(".snap")
        check("AI 面板显示数据快照", snap is not None,
              (snap.inner_text().replace("\n", " · ") if snap else "")[:100])
        one_key = pg.query_selector("button:has-text('一键分析')")
        check("有「一键分析当前抓包」按钮", one_key is not None)

        ai_sel = None
        for sel in ("textarea", "input[placeholder*='问']"):
            if pg.query_selector(sel):
                ai_sel = sel
                break
        check("找到 AI 对话输入框", ai_sel is not None, ai_sel or "")
        if one_key:
            try:
                one_key.click()
                pg.wait_for_timeout(9000)
                replies = pg.eval_on_selector_all(".msg.ai", "e => e.map(x => x.innerText)")
                joined = "\n".join(replies)
                check("一键分析返回了结论", len(joined.strip()) > 30, joined[:120].replace("\n", " "))
                check("结论基于真实数据（提到报文/流量等）",
                      any(k in joined for k in ("报文", "包", "流量", "TCP", "UDP", "异常")),
                      "")
            except Exception as exc:
                check("一键分析返回了结论", False, str(exc))
        elif ai_sel:
            try:
                pg.fill(ai_sel, "一共有多少个包？")
                pg.keyboard.press("Enter")
                pg.wait_for_timeout(8000)
                replies = pg.eval_on_selector_all(".msg.ai", "e => e.map(x => x.innerText)")
                check("AI 对话有回复", any(len(r.strip()) > 10 for r in replies),
                      (replies[-1][:90] if replies else ""))
            except Exception as exc:
                check("AI 对话有回复", False, str(exc))
        pg.wait_for_timeout(2000)
        pg.screenshot(path=str(SHOT / "ui_04_ai.png"), full_page=False)

        # ---------- 报错检查 ----------
        print()
        print("== 控制台 / JS 报错 ==")
        real_page = [e for e in page_errors if "favicon" not in e.lower()]
        real_console = [e for e in console_errors
                        if "favicon" not in e.lower() and "Failed to load resource" not in e]
        check("无 JS 运行时异常", not real_page, "; ".join(real_page[:3]))
        check("无控制台 error", not real_console, "; ".join(real_console[:3]))

        browser.close()

    print()
    print("=" * 52)
    print("  UI 结果：%d 通过 / %d 失败" % (PASS, FAIL))
    for f in FAILS:
        print("    - %s" % f)
    print("=" * 52)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
