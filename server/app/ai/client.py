"""OpenAI Chat Completions 兼容客户端（DeepSeek / OpenAI / 通义 / Ollama 通用）。

带 Function Calling 工具循环 + 流式输出。
"""
from __future__ import annotations

import json
from typing import Any, AsyncIterator, Callable, Dict, List, Optional

import httpx


class AIClientError(Exception):
    pass


class AIClient:
    def __init__(self, base_url: str, api_key: str, model: str,
                 temperature: float = 0.2, max_tokens: int = 2048, timeout: float = 90.0) -> None:
        self.base_url = (base_url or "").rstrip("/")
        self.api_key = api_key or ""
        self.model = model or "deepseek-chat"
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout

    @property
    def endpoint(self) -> str:
        return f"{self.base_url}/chat/completions"

    def _headers(self) -> Dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    def _body(self, messages: List[Dict[str, Any]], tools: Optional[List[Dict[str, Any]]], stream: bool) -> Dict[str, Any]:
        body: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "stream": stream,
        }
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"
        return body

    # ---------------------------------------------------------------- 连接测试
    async def test(self) -> Dict[str, Any]:
        if not self.base_url:
            return {"ok": False, "error": "未配置 Base URL"}
        if not self.api_key and "localhost" not in self.base_url and "127.0.0.1" not in self.base_url:
            return {"ok": False, "error": "未配置 API Key"}
        try:
            async with httpx.AsyncClient(timeout=25) as cli:
                r = await cli.post(self.endpoint, headers=self._headers(),
                                   json=self._body([{"role": "user", "content": "ping"}], None, False))
                if r.status_code >= 400:
                    return {"ok": False, "error": f"HTTP {r.status_code}: {r.text[:200]}"}
                data = r.json()
                return {"ok": True, "model": data.get("model", self.model),
                        "reply": (data.get("choices", [{}])[0].get("message", {}).get("content") or "")[:80]}
        except Exception as exc:                                    # noqa: BLE001
            return {"ok": False, "error": str(exc)}

    # ---------------------------------------------------------------- 对话（含工具循环）
    async def chat_stream(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        executor: Optional[Callable[[str, Dict[str, Any]], str]] = None,
        max_rounds: int = 4,
    ) -> AsyncIterator[Dict[str, Any]]:
        """产出事件：status / tool / token / done / error。"""
        msgs: List[Dict[str, Any]] = list(messages)
        used_tools: List[Dict[str, Any]] = []
        final_text = ""

        async with httpx.AsyncClient(timeout=self.timeout) as cli:
            for _round in range(max_rounds):
                payload = self._body(msgs, tools, True)
                tool_calls: Dict[int, Dict[str, Any]] = {}
                content_parts: List[str] = []
                finish = None
                try:
                    async with cli.stream("POST", self.endpoint, headers=self._headers(), json=payload) as resp:
                        if resp.status_code >= 400:
                            body = await resp.aread()
                            yield {"type": "error", "text": f"HTTP {resp.status_code}: {body[:300].decode('utf-8', 'ignore')}"}
                            return
                        async for line in resp.aiter_lines():
                            if not line or not line.startswith("data:"):
                                continue
                            data = line[5:].strip()
                            if data == "[DONE]":
                                break
                            try:
                                chunk = json.loads(data)
                            except Exception:                       # noqa: BLE001
                                continue
                            choices = chunk.get("choices") or []
                            if not choices:
                                continue
                            ch = choices[0]
                            delta = ch.get("delta") or {}
                            if ch.get("finish_reason"):
                                finish = ch["finish_reason"]
                            if delta.get("content"):
                                content_parts.append(delta["content"])
                                yield {"type": "token", "text": delta["content"]}
                            for tc in delta.get("tool_calls") or []:
                                idx = tc.get("index", 0)
                                slot = tool_calls.setdefault(idx, {"id": tc.get("id", ""), "name": "", "arguments": ""})
                                if tc.get("id"):
                                    slot["id"] = tc["id"]
                                fn = tc.get("function") or {}
                                if fn.get("name"):
                                    slot["name"] = fn["name"]
                                if fn.get("arguments"):
                                    slot["arguments"] += fn["arguments"]
                except Exception as exc:                            # noqa: BLE001
                    yield {"type": "error", "text": f"请求失败：{exc}"}
                    return

                if tool_calls and executor:
                    # 组装 assistant 消息（含工具调用）
                    msgs.append({
                        "role": "assistant",
                        "content": "".join(content_parts) or "",
                        "tool_calls": [
                            {"id": tc["id"] or f"call_{i}", "type": "function",
                             "function": {"name": tc["name"], "arguments": tc["arguments"] or "{}"}}
                            for i, tc in tool_calls.items() if tc["name"]
                        ],
                    })
                    for i, tc in tool_calls.items():
                        if not tc["name"]:
                            continue
                        try:
                            args = json.loads(tc["arguments"] or "{}")
                        except Exception:                           # noqa: BLE001
                            args = {}
                        yield {"type": "status", "text": f"调用工具 {tc['name']}…"}
                        result = executor(tc["name"], args)
                        used_tools.append({"name": tc["name"], "args": args, "result": result[:400]})
                        yield {"type": "tool", "name": tc["name"], "args": args, "result": result[:1200]}
                        msgs.append({"role": "tool", "tool_call_id": tc["id"] or f"call_{i}",
                                     "name": tc["name"], "content": result})
                    continue

                final_text = "".join(content_parts)
                yield {"type": "done", "text": final_text, "tools": used_tools}
                return

            yield {"type": "done", "text": final_text or "（多轮工具调用后未生成最终结论）", "tools": used_tools}
