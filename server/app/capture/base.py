"""捕获引擎抽象层。"""
from __future__ import annotations

from typing import Callable, List, Optional

from ..core.models import InterfaceInfo

# linktype: 1=Ethernet, 101=RAW IPv4, 113=Linux cooked, 0=NULL
LINK_ETHERNET, LINK_RAW, LINK_SLL, LINK_NULL = 1, 101, 113, 0


class CaptureEngine:
    """引擎基类：子类实现 start/stop，把 (raw_bytes, timestamp) 交给回调。"""

    name = "base"
    linktype = LINK_ETHERNET
    available: bool = False
    reason: str = ""

    def __init__(self) -> None:
        self._running = False
        self._cb: Optional[Callable[[bytes, float], None]] = None

    @classmethod
    def check(cls) -> bool:
        """检测引擎是否可用（不抛异常）。"""
        raise NotImplementedError

    def list_interfaces(self) -> List[InterfaceInfo]:
        raise NotImplementedError

    def start(self, iface: Optional[str], bpf: str, promisc: bool, snaplen: int,
              cb: Callable[[bytes, float], None]) -> None:
        raise NotImplementedError

    def stop(self) -> None:
        self._running = False

    @property
    def running(self) -> bool:
        return self._running
