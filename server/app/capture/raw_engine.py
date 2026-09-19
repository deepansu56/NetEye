"""降级引擎：Windows raw socket + SIO_RCVALL。

无需 Npcap，只需管理员权限。抓到的是 IPv4 包（无以太网头，linktype=101），
不支持 ARP / 非 IP 协议，不支持真正的混杂模式，用于在未装 Npcap 时保持可用。
"""
from __future__ import annotations

import ctypes
import socket
import struct
import threading
import time
from typing import Callable, List, Optional

import psutil

from ..core.models import InterfaceInfo
from .base import CaptureEngine, LINK_RAW

SIO_RCVALL = 0x98000001
RCVALL_ON = 1
RCVALL_OFF = 0


class RawSocketEngine(CaptureEngine):
    name = "raw"
    linktype = LINK_RAW

    def __init__(self) -> None:
        super().__init__()
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None

    @classmethod
    def check(cls) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.close()
            cls.available, cls.reason = True, "可用（需管理员权限）"
            return True
        except Exception as exc:                                   # noqa: BLE001
            cls.available, cls.reason = False, f"无法创建 raw socket：{exc}"
            return False

    def list_interfaces(self) -> List[InterfaceInfo]:
        out: List[InterfaceInfo] = []
        stats = psutil.net_if_stats()
        for name, addrs in psutil.net_if_addrs().items():
            ip = next((a.address for a in addrs if a.family == socket.AF_INET), "")
            mac = next((a.address for a in addrs if getattr(a, "family", None) == psutil.AF_LINK), "")
            st = stats.get(name)
            out.append(InterfaceInfo(
                name=name, description=name, ip=ip, mac=mac,
                is_up=bool(st.isup) if st else False,
            ))
        return out

    def start(self, iface: Optional[str], bpf: str, promisc: bool, snaplen: int,
              cb: Callable[[bytes, float], None]) -> None:
        addrs = psutil.net_if_addrs().get(iface or "", [])
        ip = next((a.address for a in addrs if a.family == socket.AF_INET), None)
        if not ip:
            # 没指定或没 IP，用默认出口 IP
            ip = socket.gethostbyname(socket.gethostname())
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((ip, 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.ioctl(SIO_RCVALL, struct.pack("I", RCVALL_ON))
        self._sock = s
        self._running = True
        self._cb = cb

        def loop() -> None:
            while self._running and self._sock:
                try:
                    data, _ = self._sock.recvfrom(65535)
                except OSError:
                    break
                if not data:
                    continue
                try:
                    cb(data, time.time())
                except Exception:                                   # noqa: BLE001
                    pass

        self._thread = threading.Thread(target=loop, daemon=True, name="neteye-raw")
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._sock:
            try:
                self._sock.ioctl(SIO_RCVALL, struct.pack("I", RCVALL_OFF))
            except Exception:                                       # noqa: BLE001
                pass
            try:
                self._sock.close()
            except Exception:                                       # noqa: BLE001
                pass
            self._sock = None
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.5)
        self._thread = None
