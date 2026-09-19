"""NetEye 配置中心：路径、捕获默认值、AI 配置（持久化到 data/settings.json）。"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict

BASE_DIR = Path(__file__).resolve().parents[3]          # NetEye/
DATA_DIR = Path(os.environ.get("NETEYE_DATA_DIR", BASE_DIR / "data"))
CAPTURE_DIR = DATA_DIR / "captures"
DB_PATH = DATA_DIR / "neteye.db"
SETTINGS_PATH = DATA_DIR / "settings.json"

for _p in (DATA_DIR, CAPTURE_DIR):
    _p.mkdir(parents=True, exist_ok=True)

DEFAULT_SETTINGS: Dict[str, Any] = {
    "ai": {
        "provider": "deepseek",              # deepseek | openai | custom | ollama
        "base_url": "https://api.deepseek.com",
        "api_key": "",
        "model": "deepseek-chat",
        "temperature": 0.2,
        "max_tokens": 2048,
        "enabled": True,
        "system_prompt": (
            "你是 NetEye 网络分析助手，基于真实抓包数据回答问题。"
            "必须优先调用工具查询数据，禁止凭空编造包、地址、端口或统计值。"
            "回答用中文，简洁结构化，引用具体包序号/端口/协议，并在结尾给出可执行的下一步建议。"
        ),
    },
    "presets": {
        "openai": {"base_url": "https://api.openai.com/v1", "model": "gpt-4o-mini"},
        "deepseek": {"base_url": "https://api.deepseek.com", "model": "deepseek-chat"},
        "ollama": {"base_url": "http://localhost:11434/v1", "model": "qwen2.5:7b"},
    },
    "capture": {
        "snaplen": 65535,
        "promisc": True,
        "ring_buffer": 100000,
        "auto_save_pcap": False,
    },
}


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


class Settings:
    """单例式设置对象，读写 data/settings.json。"""

    def __init__(self) -> None:
        self._data: Dict[str, Any] = {}
        self.load()

    def load(self) -> None:
        data = json.loads(json.dumps(DEFAULT_SETTINGS))
        if SETTINGS_PATH.exists():
            try:
                disk = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
                data = _deep_merge(data, disk)
            except Exception:
                pass
        self._data = data

    def save(self) -> None:
        SETTINGS_PATH.write_text(
            json.dumps(self._data, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    def get(self, key: str, default: Any = None) -> Any:
        node: Any = self._data
        for part in key.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def set(self, key: str, value: Any) -> None:
        parts = key.split(".")
        node = self._data
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value
        self.save()

    def update(self, patch: Dict[str, Any]) -> Dict[str, Any]:
        self._data = _deep_merge(self._data, patch)
        self.save()
        return self._data

    @property
    def ai(self) -> Dict[str, Any]:
        return self._data.get("ai", {})

    @property
    def capture(self) -> Dict[str, Any]:
        return self._data.get("capture", {})

    def all(self) -> Dict[str, Any]:
        return self._data


settings = Settings()
