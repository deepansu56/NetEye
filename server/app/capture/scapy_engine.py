"""主引擎：scapy + Npcap（Windows 官方抓包通道，支持混杂模式与 BPF）。"""
from __future__ import annotations

import ctypes
import os
import threading
import time
from typing import Callable, List, Optional, Tuple

from ..core.models import InterfaceInfo
from .base import CaptureEngine, LINK_ETHERNET


def ensure_win_env() -> None:
    """补齐 scapy 硬依赖的 Windows 环境变量。

    scapy 在导入期会用 ``os.environ["ProgramFiles"]`` / ``["SystemRoot"]``
    下标方式读取变量（见 scapy/arch/windows/__init__.py 的 WinProgPath）。
    Git Bash、WSL 互调、某些 CI/计划任务 shell 下这些变量并不存在，会直接
    KeyError 导致整个捕获层不可用。这里用 setdefault 兜底，不覆盖真实值。
    """
    if os.name != "nt":
        return
    drive = os.environ.get("SystemDrive") or "C:"
    defaults = {
        "SystemDrive": drive,
        "SystemRoot": os.path.join(drive, "Windows"),
        "windir": os.path.join(drive, "Windows"),
        "ProgramFiles": os.path.join(drive, "Program Files"),
        "ProgramFiles(x86)": os.path.join(drive, "Program Files (x86)"),
        "ProgramData": os.path.join(drive, "ProgramData"),
        "ALLUSERSPROFILE": os.path.join(drive, "ProgramData"),
    }
    profile = os.environ.get("USERPROFILE") or os.path.join(drive, "Users", "Public")
    defaults["APPDATA"] = os.path.join(profile, "AppData", "Roaming")
    defaults["LOCALAPPDATA"] = os.path.join(profile, "AppData", "Local")
    # 注意：必须判空，不能用 setdefault —— 某些 shell（Git Bash / 计划任务）
    # 会把这些变量导出成**空字符串**，此时 setdefault 不会补值，
    # 下游 os.path.join("", "ProgramData", ...) 就变成相对路径，
    # 在 cwd 下凭空生成 ProgramData\Microsoft\Windows\Caches 目录。
    for key, value in defaults.items():
        if not os.environ.get(key):
            os.environ[key] = value

    # Npcap 的 wpcap.dll 位于 %SystemRoot%\System32\Npcap，虽然在 DLL 搜索路径
    # 内，但个别沙箱/降权环境下搜不到，显式加入 PATH 可稳定 DLL 解析。
    npcap_dir = os.path.join(os.environ.get("SystemRoot", drive + "\\Windows"),
                             "System32", "Npcap")
    if os.path.isdir(npcap_dir):
        path = os.environ.get("PATH", "")
        if npcap_dir.lower() not in path.lower():
            os.environ["PATH"] = npcap_dir + os.pathsep + path


class ScapyEngine(CaptureEngine):
    name = "npcap"
    linktype = LINK_ETHERNET
    _checked_at = 0.0
    _check_cache: bool = False
    _check_reason = ""

    def __init__(self) -> None:
        super().__init__()
        self._thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------ 可用性
    @classmethod
    def check(cls, iface: Optional[str] = None) -> bool:
        now = time.time()
        if cls._checked_at and now - cls._checked_at < 30 and not iface:
            cls.available, cls.reason = cls._check_cache, cls._check_reason
            return cls.available
        try:
            for dll in ("wpcap.dll", "npcap.dll"):
                try:
                    ctypes.WinDLL(dll) if hasattr(ctypes, "WinDLL") else ctypes.CDLL(dll)
                except OSError:
                    continue
                break
            else:
                cls.available, cls.reason = False, "未检测到 Npcap/WinPcap（wpcap.dll 缺失），请安装 Npcap 后重启"
                cls._checked_at, cls._check_cache, cls._check_reason = now, cls.available, cls.reason
                return False
            cls.available, cls.reason = True, "Npcap 可用"
            cls._checked_at, cls._check_cache, cls._check_reason = now, cls.available, cls.reason
            return True
        except Exception as exc:                                   # noqa: BLE001
            cls.available, cls.reason = False, f"检测失败：{exc}"
            return False

    @staticmethod
    def _scapy():
        ensure_win_env()                    # 必须在 import scapy 之前补齐环境变量
        from scapy.all import IFACES, conf, sniff          # noqa: PLC0415  延迟导入（scapy 加载约 1-2s）
        return IFACES, conf, sniff

    # ------------------------------------------------------------ 接口
    def list_interfaces(self) -> List[InterfaceInfo]:
        IFACES, _conf, _sniff = self._scapy()
        out: List[InterfaceInfo] = []
        try:
            for iface in IFACES.values():
                out.append(InterfaceInfo(
                    name=str(iface.name),
                    description=str(getattr(iface, "description", "") or iface.name),
                    ip=str(getattr(iface, "ip", "") or ""),
                    mac=str(getattr(iface, "mac", "") or ""),
                    is_up=not bool(getattr(iface, "is_invalid", False)),
                    guid=str(getattr(iface, "guid", "") or ""),
                ))
        except Exception:                                           # noqa: BLE001
            pass
        return out

    # ------------------------------------------------------------ 捕获
    def start(self, iface: Optional[str], bpf: str, promisc: bool, snaplen: int,
              cb: Callable[[bytes, float], None]) -> None:
        IFACES, conf, sniff = self._scapy()
        conf.sniff_promisc = bool(promisc)
        try:
            conf.snaplen = int(snaplen)
        except Exception:                                           # noqa: BLE001
            pass
        self._running = True

        def _prn(pkt) -> None:
            if not self._running:
                return
            raw = getattr(pkt, "original", None) or bytes(pkt)
            try:
                ts = float(pkt.time)
            except Exception:                                       # noqa: BLE001
                ts = time.time()
            try:
                cb(raw, ts)
            except Exception:                                       # noqa: BLE001
                pass

        def loop() -> None:
            try:
                sniff(iface=iface or None, prn=_prn, store=False,
                      filter=bpf or None,
                      stop_filter=lambda _p: not self._running)
            except Exception as exc:                                # noqa: BLE001
                self.reason = f"捕获异常：{exc}"
                self._running = False

        self._thread = threading.Thread(target=loop, daemon=True, name="neteye-npcap")
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        self._thread = None
