#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""NetEye 一体化安装 / 启动 / 体检工具。

用法（均由 install.bat / 启动NetEye.bat 调用，也可手动执行）：

    python tools/neteye.py install [--skip-frontend] [--mirror URL] [--python PATH]
    python tools/neteye.py start   [--port 8765] [--no-browser] [--no-elevate]
    python tools/neteye.py doctor

设计原则：
  * 不依赖 PATH 里有没有 python / npm —— 主动扫描常见安装位置与注册表；
  * 每一步都有明确的成功/失败提示，失败时告诉用户怎么手动补救；
  * 安装与启动使用同一套探测逻辑，保证"装到哪、就从哪启动"。
"""
from __future__ import annotations

import argparse
import ctypes
import glob
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path

MIN_PY = (3, 10)

ROOT = Path(__file__).resolve().parent.parent          # NetEye/
SERVER_DIR = ROOT / "server"
WEB_DIR = ROOT / "web"
VENV_DIR = ROOT / ".venv"
REQUIREMENTS = SERVER_DIR / "requirements.txt"
DIST_INDEX = WEB_DIR / "dist" / "index.html"

# 安装包内置的 Npcap 安装器（实时抓包必需；离线分析 pcap 不需要）
NPCAP_VERSION = "1.89"
NPCAP_INSTALLER = ROOT / "installer" / "npcap" / ("npcap-%s.exe" % NPCAP_VERSION)

IS_WIN = os.name == "nt"

# ------------------------------------------------------------------ 终端输出
if IS_WIN:
    try:
        import ctypes as _ct

        _ct.windll.kernel32.SetConsoleMode(
            _ct.windll.kernel32.GetStdHandle(-11), 7)   # 开启 ANSI 转义
    except Exception:
        pass


def _c(text: str, code: str) -> str:
    if not sys.stdout.isatty():
        return text
    return "\033[%sm%s\033[0m" % (code, text)


def info(msg: str) -> None:
    print(_c("[*] ", "36") + msg, flush=True)


def ok(msg: str) -> None:
    print(_c("[OK] ", "32") + msg, flush=True)


def warn(msg: str) -> None:
    print(_c("[!] ", "33") + msg, flush=True)


def err(msg: str) -> None:
    print(_c("[X] ", "31") + msg, flush=True)


def step(msg: str) -> None:
    print()
    print(_c(">>> ", "36") + _c(msg, "1;36"), flush=True)


# ------------------------------------------------------------------ Python 探测
def _run(cmd, timeout: int = 60):
    """运行命令，返回 (returncode, stdout)。任何异常都被吞掉。"""
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           creationflags=(subprocess.CREATE_NO_WINDOW if IS_WIN else 0))
        out = (p.stdout or b"").decode("utf-8", "replace").strip()
        return p.returncode, out
    except Exception:
        return 1, ""


def python_version_of(path: str):
    """返回 (major, minor, micro) 或 None。"""
    if not path or not os.path.isfile(path):
        return None
    low = path.lower()
    # Microsoft Store 的 python.exe 是个 0 字节 stub，会弹商店，必须排除
    if "windowsapps" in low:
        return None
    rc, out = _run([path, "-c", "import sys;print('%d.%d.%d'%sys.version_info[:3])"],
                   timeout=30)
    if rc != 0 or not out:
        return None
    try:
        parts = out.splitlines()[0].strip().split(".")
        return tuple(int(x) for x in parts[:3])
    except Exception:
        return None


def _valid(path: str):
    v = python_version_of(path)
    if not v:
        return None
    if v[:2] < MIN_PY:
        return None
    return (path, "%d.%d.%d" % v)


def _expand(patterns):
    out = []
    for pat in patterns:
        try:
            out.extend(sorted(glob.glob(pat), reverse=True))
        except Exception:
            pass
    return out


def find_python():
    """按优先级返回第一个可用的 (path, version)。"""
    home = os.path.expanduser("~")
    localappdata = os.environ.get("LOCALAPPDATA", os.path.join(home, "AppData", "Local"))
    cands = []

    # 1) 显式指定
    env_py = os.environ.get("NETEYE_PYTHON", "").strip('"')
    if env_py:
        cands.append(env_py)

    # 2) 项目自带 venv（保证 install / start 用的是同一个环境）
    cands.append(str(VENV_DIR / "Scripts" / "python.exe"))
    cands.append(str(VENV_DIR / "bin" / "python"))

    # 3) py 启动器
    if shutil.which("py"):
        rc, out = _run(["py", "-3", "-c", "import sys;print(sys.executable)"], timeout=30)
        if rc == 0 and out:
            cands.append(out.splitlines()[0].strip())

    # 4) PATH
    for name in ("python", "python3"):
        w = shutil.which(name)
        if w:
            cands.append(w)

    # 5) WorkBuddy 托管版本（本机开发环境的默认位置）
    wb_versions = os.path.join(home, ".workbuddy", "binaries", "python", "versions")
    for d in _expand([os.path.join(wb_versions, "*")]):
        cands.append(os.path.join(d, "python.exe"))
    wb_envs = os.path.join(home, ".workbuddy", "binaries", "python", "envs")
    for d in _expand([os.path.join(wb_envs, "*")]):
        cands.append(os.path.join(d, "Scripts", "python.exe"))
        cands.append(os.path.join(d, "bin", "python"))

    # 6) 常规安装位置
    for base in (os.path.join(localappdata, "Programs", "Python"),
                 os.path.join(home, "AppData", "Local", "Programs", "Python"),
                 "C:\\", "D:\\"):
        for d in _expand([os.path.join(base, "Python3*"), os.path.join(base, "Python3*")]):
            cands.append(os.path.join(d, "python.exe"))

    # 7) Conda
    for rel in ("anaconda3", "miniconda3", "miniforge3",
                os.path.join(localappdata, "miniforge3")):
        p = rel if os.path.isabs(rel) else os.path.join(home, rel)
        cands.append(os.path.join(p, "python.exe"))

    # 8) Windows 注册表
    if IS_WIN:
        try:
            import winreg

            for hive, flag in ((winreg.HKEY_CURRENT_USER, 0),
                               (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY)):
                try:
                    key = winreg.OpenKey(hive, r"SOFTWARE\Python\PythonCore", 0,
                                         winreg.KEY_READ | flag)
                except Exception:
                    continue
                i = 0
                while True:
                    try:
                        sub = winreg.EnumKey(key, i)
                    except OSError:
                        break
                    i += 1
                    try:
                        k2 = winreg.OpenKey(key, sub + r"\InstallPath")
                        val, _ = winreg.QueryValueEx(k2, "ExecutablePath")
                        if val:
                            cands.append(val)
                    except Exception:
                        try:
                            k2 = winreg.OpenKey(key, sub + r"\InstallPath")
                            val, _ = winreg.QueryValueEx(k2, "")
                            if val:
                                cands.append(os.path.join(val, "python.exe"))
                        except Exception:
                            pass
        except Exception:
            pass

    seen = set()
    for c in cands:
        if not c:
            continue
        c = os.path.normpath(c)
        if c in seen:
            continue
        seen.add(c)
        r = _valid(c)
        if r:
            return r
    return None


def find_npm():
    """返回 (npm_path, version) 或 None。"""
    home = os.path.expanduser("~")
    cands = []
    for name in ("npm.cmd", "npm"):
        w = shutil.which(name)
        if w:
            cands.append(w)

    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    for base in (os.path.join(pf, "nodejs"), os.path.join(pf86, "nodejs"),
                 os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "nodejs")):
        if base:
            cands.append(os.path.join(base, "npm.cmd"))

    # nvm-windows
    nvm = os.path.join(os.environ.get("APPDATA", os.path.join(home, "AppData", "Roaming")), "nvm")
    for d in _expand([os.path.join(nvm, "*")]):
        cands.append(os.path.join(d, "npm.cmd"))

    # WorkBuddy 托管 node
    wb_node = os.path.join(home, ".workbuddy", "binaries", "node", "versions")
    for d in _expand([os.path.join(wb_node, "*")]):
        cands.append(os.path.join(d, "npm.cmd"))
        cands.append(os.path.join(d, "npm"))

    seen = set()
    for c in cands:
        if not c:
            continue
        c = os.path.normpath(c)
        if c in seen or not os.path.isfile(c):
            continue
        seen.add(c)
        rc, out = _run([c, "--version"], timeout=30)
        if rc == 0 and out:
            return (c, out.splitlines()[0].strip())
    return None


def has_npcap() -> bool:
    if not IS_WIN:
        return False
    sysroot = os.environ.get("SystemRoot") or os.environ.get("systemroot") or r"C:\Windows"
    cands = [os.path.join(sysroot, "System32", "Npcap"),
             r"C:\Windows\System32\Npcap",
             r"C:\Windows\SysWOW64\Npcap"]
    for d in cands:
        if os.path.isfile(os.path.join(d, "wpcap.dll")):
            return True
    return False


def run_elevated_wait(exe: str, params: list, cwd: str = "") -> int:
    """以管理员身份同步运行 exe 并等待结束，返回退出码（失败返回 -1）。

    用 ShellExecuteEx + SEE_MASK_NOCLOSEPROCESS 拿到进程句柄后 WaitForSingleObject，
    这样既能触发 UAC 提权，又能拿到真实退出码。
    """
    if not IS_WIN:
        try:
            return subprocess.call([exe] + params, cwd=cwd or None)
        except Exception:
            return -1
    try:
        import ctypes.wintypes as wt

        class SHELLEXECUTEINFO(ctypes.Structure):
            _fields_ = [
                ("cbSize", wt.DWORD),
                ("fMask", wt.ULONG),
                ("hwnd", wt.HWND),
                ("lpVerb", wt.LPCWSTR),
                ("lpFile", wt.LPCWSTR),
                ("lpParameters", wt.LPCWSTR),
                ("lpDirectory", wt.LPCWSTR),
                ("nShow", ctypes.c_int),
                ("hInstApp", wt.HINSTANCE),
                ("lpIDList", ctypes.c_void_p),
                ("lpClass", wt.LPCWSTR),
                ("hKeyClass", ctypes.c_void_p),
                ("dwHotKey", wt.DWORD),
                ("hIconOrMonitor", ctypes.c_void_p),
                ("hProcess", wt.HANDLE),
            ]

        sei = SHELLEXECUTEINFO()
        sei.cbSize = ctypes.sizeof(sei)
        sei.fMask = 0x00000040  # SEE_MASK_NOCLOSEPROCESS
        sei.lpVerb = "runas"
        sei.lpFile = exe
        sei.lpParameters = " ".join('"%s"' % a for a in params)
        sei.lpDirectory = cwd or ""
        sei.nShow = 1
        if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei)):
            return -1
        handle = sei.hProcess
        ctypes.windll.kernel32.WaitForSingleObject(handle, 0xFFFFFFFF)
        ec = wt.DWORD()
        ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(ec))
        ctypes.windll.kernel32.CloseHandle(handle)
        return int(ec.value)
    except Exception:
        return -1


def _download_npcap():
    """从官网下载 Npcap 安装器到临时目录，返回本地路径或 None。"""
    try:
        import urllib.request
        import tempfile

        url = "https://npcap.com/dist/npcap-%s.exe" % NPCAP_VERSION
        dest = os.path.join(tempfile.gettempdir(), "npcap-%s.exe" % NPCAP_VERSION)
        info("下载 Npcap 安装器：%s" % url)
        urllib.request.urlretrieve(url, dest)
        if os.path.isfile(dest) and os.path.getsize(dest) > 100000:
            ok("Npcap 安装器已下载 -> %s" % dest)
            return dest
    except Exception as e:  # noqa: BLE001
        warn("下载 Npcap 失败：%s" % e)
    return None


def install_npcap() -> bool:
    """安装内置 Npcap。已安装视为成功；缺失时回退下载；最终以 has_npcap() 判定。"""
    if has_npcap():
        ok("已检测到 Npcap，跳过安装")
        return True

    exe = str(NPCAP_INSTALLER)
    if not os.path.isfile(exe):
        warn("未找到内置 Npcap 安装器：%s" % exe)
        exe = _download_npcap() or ""
    if not exe or not os.path.isfile(exe):
        err("Npcap 安装器不可用。请手动安装（实时抓包必需）：")
        err("     https://npcap.com/#download")
        err("     安装时必须勾选 \"Install Npcap in WinPcap API-compatible Mode\"")
        return False

    info("正在静默安装 Npcap（会弹出 UAC 提权窗口，请点击【允许】）...")
    rc = run_elevated_wait(exe, ["/S", "/winpcap_mode=yes", "/loopback_support=yes"])
    if has_npcap():
        ok("Npcap 安装完成（WinPcap 兼容模式 + 回环支持）")
        return True
    if rc == 0:
        ok("Npcap 安装程序已退出（退出码 0），请确认驱动目录是否存在")
        return True
    warn("Npcap 安装退出码=%s，可能未成功（若本机已装过可忽略）。" % rc)
    warn("手动安装：https://npcap.com/#download ，务必勾选 WinPcap API-compatible Mode")
    return False


def port_listening(port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.8)
    try:
        return s.connect_ex(("127.0.0.1", port)) == 0
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def probe_neteye(port: int) -> bool:
    """端口上跑的是不是 NetEye。"""
    import urllib.request

    try:
        with urllib.request.urlopen("http://127.0.0.1:%d/api/health" % port,
                                    timeout=3) as r:
            body = json.loads(r.read().decode("utf-8", "replace"))
            return bool(body.get("ok"))
    except Exception:
        return False


def is_admin() -> bool:
    if not IS_WIN:
        return os.geteuid() == 0
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def elevate(argv) -> bool:
    """请求 UAC 提权后重新执行本脚本。返回是否成功发起。"""
    if not IS_WIN or is_admin():
        return False
    try:
        exe = sys.executable
        params = " ".join('"%s"' % a for a in argv)
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
        return int(rc) > 32
    except Exception:
        return False


def pause(msg: str = "按回车键关闭...") -> None:
    try:
        input("\n" + msg)
    except Exception:
        pass


# ------------------------------------------------------------------ install
def cmd_install(args) -> int:
    print()
    print("=" * 46)
    print("  NetEye 安装向导")
    print("=" * 46)
    print("  项目目录: %s" % ROOT)

    if "onedrive" in str(ROOT).lower():
        print()
        warn("项目位于 OneDrive 目录内。OneDrive 的文件同步会加锁甚至回滚改动，")
        warn("是安装/运行出现随机失败的常见原因。建议把项目移到普通磁盘")
        warn("（例如 D:\\Projects\\NetEye）后重新安装。本次仍会继续。")

    # ---------------- 1. Python
    step("[1/5] 定位 Python（需要 >= %d.%d）" % MIN_PY)
    py = None
    if args.python:
        r = _valid(args.python)
        if r:
            py = r
            ok("使用 --python 指定的解释器 %s（%s）" % (r[0], r[1]))
        else:
            warn("--python %s 不可用，改为自动探测" % args.python)
    if not py:
        py = find_python()
    if not py:
        err("未找到可用的 Python %d.%d+。" % MIN_PY)
        print()
        print("  解决办法（任选其一）：")
        print("   1) 到 https://www.python.org/downloads/ 安装，勾选 Add python.exe to PATH")
        print("   2) 已装但不在 PATH：先设置变量再运行 install.bat")
        print('        set NETEYE_PYTHON=C:\\完整路径\\python.exe')
        print("   3) 直接指定：python tools\\neteye.py install --python C:\\路径\\python.exe")
        return 1
    py_exe, py_ver = py
    ok("Python %s  ->  %s" % (py_ver, py_exe))

    # ---------------- 2. venv
    step("[2/5] 准备虚拟环境 .venv")
    venv_py = VENV_DIR / ("Scripts/python.exe" if IS_WIN else "bin/python")
    reuse = False
    if venv_py.is_file():
        r = _valid(str(venv_py))
        if r:
            ok("已存在可用的 .venv（Python %s），直接复用" % r[1])
            reuse = True
            py_exe = str(venv_py)
        else:
            warn(".venv 已存在但不可用，将删除重建")
            shutil.rmtree(str(VENV_DIR), ignore_errors=True)
    if not reuse:
        print("     正在创建（通常 10-60 秒，OneDrive 目录会更慢）...", flush=True)
        rc, out = _run([py_exe, "-m", "venv", str(VENV_DIR)], timeout=600)
        if rc != 0 or not venv_py.is_file():
            err("venv 创建失败（exit=%s）。请确认 Python 安装完整（含 ensurepip）。" % rc)
            if out:
                print(out)
            return 1
        ok(".venv 创建完成")
        py_exe = str(venv_py)

    # ---------------- 3. 依赖
    step("[3/5] 安装后端依赖")
    if not REQUIREMENTS.is_file():
        err("找不到依赖清单 %s" % REQUIREMENTS)
        return 1

    def pip(*a):
        cmd = [py_exe, "-m", "pip"] + list(a)
        if args.mirror:
            cmd += ["-i", args.mirror]
        return _run(cmd, timeout=1800)

    for attempt in (1, 2, 3):
        print("     升级 pip（第 %d 次尝试）..." % attempt, flush=True)
        rc, _ = pip("install", "--upgrade", "pip", "--disable-pip-version-check", "-q")
        if rc == 0:
            break
        time.sleep(2)
    else:
        warn("pip 升级未成功，继续安装依赖（一般不影响）")

    dep_ok = False
    for attempt in (1, 2, 3):
        print("     安装依赖（第 %d 次尝试，约 1-3 分钟）..." % attempt, flush=True)
        rc, out = pip("install", "-r", str(REQUIREMENTS), "--disable-pip-version-check")
        if rc == 0:
            dep_ok = True
            break
        warn("失败（exit=%s），3 秒后重试..." % rc)
        time.sleep(3)
    if not dep_ok and not args.mirror:
        warn("改用清华镜像重试一次...")
        os.environ.setdefault("PIP_MIRROR", "1")
        rc, out = pip("install", "-r", str(REQUIREMENTS), "--disable-pip-version-check",
                      "-i", "https://pypi.tuna.tsinghua.edu.cn/simple")
        dep_ok = (rc == 0)
    if not dep_ok:
        err("后端依赖安装失败。请检查网络/代理，或手动执行：")
        print('     %s -m pip install -r "%s"' % (py_exe, REQUIREMENTS))
        if out:
            print(out[-2000:])
        return 1
    ok("后端依赖安装完成")

    print("     自检：导入后端模块 ...", flush=True)
    try:
        p = subprocess.run([py_exe, "-c", "import app.main;print('IMPORT_OK')"],
                           cwd=str(SERVER_DIR), capture_output=True, timeout=180,
                           creationflags=(subprocess.CREATE_NO_WINDOW if IS_WIN else 0))
        out = (p.stdout or b"").decode("utf-8", "replace") + \
              (p.stderr or b"").decode("utf-8", "replace")
        rc = p.returncode
    except Exception as e:                                   # noqa: BLE001
        rc, out = 1, str(e)
    if rc == 0 and "IMPORT_OK" in out:
        ok("后端模块自检通过")
    else:
        err("后端自检失败，输出如下：")
        print(out[-3000:])
        return 1

    # ---------------- 4. 前端
    if args.skip_frontend:
        step("[4/5] 已跳过前端构建")
    else:
        step("[4/5] 安装并构建前端")
        npm = find_npm()
        if not npm:
            warn("未找到 npm（Node.js）。前端界面不可用，后端与 API 仍可正常使用。")
            warn("安装 Node.js 18+ 后重跑 install.bat 即可补齐。")
            print("     https://nodejs.org/zh-cn/download")
        else:
            npm_exe, npm_ver = npm
            ok("npm %s  ->  %s" % (npm_ver, npm_exe))
            env_path = os.path.dirname(npm_exe)
            need_install = not (WEB_DIR / "node_modules").exists()
            if need_install:
                print("     npm install（约 1-3 分钟）...", flush=True)
                rc = subprocess.call([npm_exe, "install", "--no-audit", "--no-fund"],
                                     cwd=str(WEB_DIR))
                if rc != 0:
                    err("npm install 失败（exit=%s）" % rc)
                else:
                    ok("npm install 完成")
            else:
                print("     node_modules 已存在，跳过 npm install", flush=True)
            if (WEB_DIR / "node_modules").exists():
                print("     npm run build ...", flush=True)
                rc = subprocess.call([npm_exe, "run", "build"], cwd=str(WEB_DIR))
                if rc != 0:
                    err("npm run build 失败（exit=%s）。可稍后手动执行：" % rc)
                    print("     cd web && npm install && npm run build")
                else:
                    ok("前端构建完成 -> web/dist")

    # ---------------- 5. Npcap
    step("[5/5] 检查抓包驱动 Npcap")
    if has_npcap():
        ok("已安装 Npcap")
    else:
        warn("未检测到 Npcap —— 实时抓包需要它（离线分析 pcap 不受影响）")
        print("     下载：https://npcap.com/#download")
        print("     安装时必须勾选 \"Install Npcap in WinPcap API-compatible Mode\"")

    print()
    print("=" * 46)
    ok("安装完成")
    print("=" * 46)
    print("  下一步：双击「启动NetEye.bat」，浏览器会打开 http://127.0.0.1:8765")
    print()
    return 0


# ------------------------------------------------------------------ start
def cmd_start(args) -> int:
    port = args.port

    print()
    print("=" * 46)
    print("  NetEye 网络端口监控与分析平台")
    print("=" * 46)
    print("  项目目录: %s" % ROOT)
    print()

    # ---------------- 1. 提权
    if IS_WIN and not is_admin():
        if args.elevated:
            warn("提权未成功（UAC 被取消或账户受限），以普通权限继续。")
            warn("普通权限下实时抓包可能不可用（离线分析 pcap 不受影响）。")
        elif not args.no_elevate:
            warn("当前不是管理员权限，正在请求提权（实时抓包需要驱动权限）...")
            argv = [str(Path(__file__).resolve()), "start", "--elevated"]
            if args.no_browser:
                argv.append("--no-browser")
            argv += ["--port", str(port)]
            if elevate(argv):
                return 0
            warn("提权未成功，以普通权限继续。")
        else:
            warn("--no-elevate：跳过提权，以普通权限运行。")
    elif is_admin():
        ok("已获取管理员权限")

    # ---------------- 2. Python
    step("定位 Python 运行环境")
    py = None
    venv_py = VENV_DIR / ("Scripts/python.exe" if IS_WIN else "bin/python")
    if venv_py.is_file():
        py = _valid(str(venv_py))
        if py:
            ok("使用项目虚拟环境 .venv（Python %s）" % py[1])
    if not py:
        warn("未找到可用的 .venv，回退到系统 Python（若失败请先运行 install.bat）")
        py = find_python()
    if not py:
        err("找不到任何可用的 Python %d.%d+，请先运行 install.bat。" % MIN_PY)
        pause()
        return 1
    py_exe = py[0]

    miss = []
    try:
        p = subprocess.run(
            [py_exe, "-c",
             "import importlib.util as u;"
             "print(','.join(m for m in ['fastapi','uvicorn','websockets','scapy',"
             "'psutil','httpx','pydantic_settings'] if u.find_spec(m) is None))"],
            capture_output=True, timeout=120)
        miss = [m for m in (p.stdout or b"").decode().strip().split(",") if m]
    except Exception:
        pass
    if miss:
        err("缺少后端依赖：%s" % ", ".join(miss))
        print("     请先双击 install.bat，或手动执行：")
        print('     %s -m pip install -r "%s"' % (py_exe, REQUIREMENTS))
        pause()
        return 1
    ok("后端依赖检查通过")

    # ---------------- 3. 端口
    if port_listening(port):
        if probe_neteye(port):
            ok("端口 %d 上已有 NetEye 实例在运行，直接打开浏览器" % port)
            if not args.no_browser:
                webbrowser.open("http://127.0.0.1:%d" % port)
            pause("按回车键关闭本窗口...")
            return 0
        err("端口 %d 被其它进程占用，且不是 NetEye 服务。" % port)
        print("     释放端口，或换端口启动：python tools\\neteye.py start --port 8766")
        rc, out = _run(["netstat", "-ano"], timeout=20)
        for line in out.splitlines():
            if ":%d" % port in line and "LISTENING" in line.upper():
                print("     " + line.strip())
        pause()
        return 1

    # ---------------- 4. 前端产物
    if not DIST_INDEX.is_file():
        warn("未找到 web\\dist\\index.html —— 前端界面不可用（仅 API 可用）。")
        warn("请先运行 install.bat，或：cd web && npm install && npm run build")

    # ---------------- 5. 启动
    step("启动后端服务 http://127.0.0.1:%d" % port)
    print("     （关闭本窗口或按 Ctrl+C 停止服务）")
    print(flush=True)

    cmd = [py_exe, "-m", "uvicorn", "app.main:app",
           "--host", "127.0.0.1", "--port", str(port),
           "--app-dir", str(SERVER_DIR)]

    if not args.no_browser:
        def _open():
            for _ in range(20):                    # 最多等 10 秒
                if port_listening(port):
                    time.sleep(0.3)
                    webbrowser.open("http://127.0.0.1:%d" % port)
                    return
                time.sleep(0.5)
        threading.Thread(target=_open, daemon=True).start()

    try:
        return subprocess.call(cmd, cwd=str(SERVER_DIR))
    except KeyboardInterrupt:
        print()
        warn("已停止服务。")
        return 0
    except FileNotFoundError:
        err("启动失败：找不到 %s" % py_exe)
        pause()
        return 1


# ------------------------------------------------------------------ doctor
def cmd_doctor(args) -> int:
    print()
    print("=" * 46)
    print("  NetEye 环境体检")
    print("=" * 46)
    print("  项目目录 : %s" % ROOT)
    print("  当前用户 : %s" % os.environ.get("USERNAME", "-"))
    print("  管理员   : %s" % ("是" if is_admin() else "否"))
    print()

    py = find_python()
    print("  Python   : %s" % (("%s（%s）" % py) if py else _c("未找到", "31")))
    venv_py = VENV_DIR / ("Scripts/python.exe" if IS_WIN else "bin/python")
    if venv_py.is_file():
        r = _valid(str(venv_py))
        print("  .venv    : %s" % (r[1] if r else _c("存在但不可用", "31")))
    else:
        print("  .venv    : %s" % _c("不存在（未安装）", "33"))
    npm = find_npm()
    print("  npm      : %s" % (("%s（%s）" % npm) if npm else _c("未找到", "33")))
    print("  Npcap    : %s" % ("已安装" if has_npcap() else _c("未安装", "33")))
    print("  web/dist : %s" % ("已构建" if DIST_INDEX.is_file() else _c("未构建", "33")))
    for p in (8765, 5273):
        alive = port_listening(p)
        tag = "NetEye 服务" if (alive and probe_neteye(p)) else "其它进程"
        print("  端口 %d  : %s" % (p, (tag if alive else "空闲")))
    print()
    return 0 if py else 1


# ------------------------------------------------------------------ main
def main() -> int:
    parser = argparse.ArgumentParser(
        description="NetEye 安装 / 启动 / 体检工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="常用：\n"
               "  python tools\\neteye.py install\n"
               "  python tools\\neteye.py start\n"
               "  python tools\\neteye.py doctor\n")
    sub = parser.add_subparsers(dest="cmd")

    p_i = sub.add_parser("install", help="安装后端依赖并构建前端")
    p_i.add_argument("--skip-frontend", action="store_true", help="跳过前端构建")
    p_i.add_argument("--mirror", default="", help="pip 镜像地址")
    p_i.add_argument("--python", default="", help="强制指定 Python 解释器路径")
    p_i.add_argument("--no-npcap", action="store_true",
                     help="跳过 Npcap 安装（离线分析 pcap 不需要实时抓包驱动）")
    p_i.set_defaults(func=cmd_install)

    p_s = sub.add_parser("start", help="启动 NetEye 服务")
    p_s.add_argument("--port", type=int, default=8765)
    p_s.add_argument("--no-browser", action="store_true")
    p_s.add_argument("--no-elevate", action="store_true", help="不请求管理员权限")
    p_s.add_argument("--elevated", action="store_true", help=argparse.SUPPRESS)
    p_s.set_defaults(func=cmd_start)

    p_d = sub.add_parser("doctor", help="环境体检")
    p_d.set_defaults(func=cmd_doctor)

    args = parser.parse_args()
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
