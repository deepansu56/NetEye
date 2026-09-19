"""API 数据模型。"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class InterfaceInfo(BaseModel):
    name: str
    description: str = ""
    ip: str = ""
    mac: str = ""
    is_up: bool = True
    guid: str = ""


class CaptureStartRequest(BaseModel):
    interface: Optional[str] = None
    bpf_filter: str = ""
    promisc: bool = True
    snaplen: int = 65535
    ring_buffer: int = 100000
    engine: str = "auto"          # auto | npcap | raw
    save_pcap: bool = False


class PacketSummary(BaseModel):
    id: int
    ts: float
    time: str
    src: str
    dst: str
    proto: str
    length: int
    info: str
    layers: List[str] = Field(default_factory=list)
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    stream: Optional[int] = None
    flags: str = ""
    color: str = ""


class FieldNode(BaseModel):
    name: str
    value: str
    offset: int = -1
    size: int = -1


class LayerNode(BaseModel):
    name: str
    title: str
    fields: List[FieldNode] = Field(default_factory=list)


class PacketDetail(BaseModel):
    id: int
    summary: PacketSummary
    layers: List[LayerNode] = Field(default_factory=list)
    hex: str = ""


class PacketsQuery(BaseModel):
    filter: str = ""
    offset: int = 0
    limit: int = 200
    order: str = "id"


class AIConfigIn(BaseModel):
    provider: Optional[str] = None
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    model: Optional[str] = None
    temperature: Optional[float] = None
    enabled: Optional[bool] = None
    system_prompt: Optional[str] = None


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    messages: List[ChatMessage]
    context_packet_ids: List[int] = Field(default_factory=list)


class ExportRequest(BaseModel):
    scope: str = "all"            # all | filtered | selected
    filter: str = ""
    ids: List[int] = Field(default_factory=list)
    format: str = "pcap"          # pcap | csv | json
    filename: str = ""


class SessionMeta(BaseModel):
    id: str
    name: str
    created_at: float
    packet_count: int
    pcap_path: str = ""
    note: str = ""
    bpf_filter: str = ""
    interface: str = ""
