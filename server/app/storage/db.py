"""SQLite 持久层：会话、包索引、AI 聊天历史。"""
from __future__ import annotations

import json
import sqlite3
import time
from typing import Any, Dict, List, Optional

from ..core.config import DB_PATH

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    name TEXT, created_at REAL, packet_count INTEGER,
    pcap_path TEXT, note TEXT, bpf_filter TEXT, interface TEXT,
    summary TEXT
);
CREATE TABLE IF NOT EXISTS packets (
    session_id TEXT, pid INTEGER, ts REAL, time TEXT, src TEXT, dst TEXT,
    proto TEXT, length INTEGER, info TEXT, layers TEXT,
    src_port INTEGER, dst_port INTEGER, stream INTEGER, flags TEXT,
    PRIMARY KEY(session_id, pid)
);
CREATE INDEX IF NOT EXISTS idx_pk_session ON packets(session_id);
CREATE TABLE IF NOT EXISTS chat (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT, role TEXT, content TEXT, ts REAL
);
CREATE INDEX IF NOT EXISTS idx_chat_session ON chat(session_id);
"""


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db() -> None:
    conn = get_conn()
    conn.executescript(_SCHEMA)
    conn.commit()
    conn.close()


def save_session(meta: Dict[str, Any]) -> None:
    conn = get_conn()
    conn.execute(
        "INSERT OR REPLACE INTO sessions (id,name,created_at,packet_count,pcap_path,note,bpf_filter,interface,summary)"
        " VALUES (:id,:name,:created_at,:packet_count,:pcap_path,:note,:bpf_filter,:interface,:summary)", meta)
    conn.commit()
    conn.close()


def list_sessions() -> List[Dict[str, Any]]:
    conn = get_conn()
    rows = conn.execute("SELECT * FROM sessions ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_session(sid: str) -> Optional[Dict[str, Any]]:
    conn = get_conn()
    row = conn.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
    conn.close()
    return dict(row) if row else None


def delete_session(sid: str) -> None:
    conn = get_conn()
    conn.execute("DELETE FROM sessions WHERE id=?", (sid,))
    conn.execute("DELETE FROM packets WHERE session_id=?", (sid,))
    conn.execute("DELETE FROM chat WHERE session_id=?", (sid,))
    conn.commit()
    conn.close()


def insert_packets(sid: str, rows: List[tuple]) -> None:
    if not rows:
        return
    conn = get_conn()
    conn.executemany(
        "INSERT OR REPLACE INTO packets (session_id,pid,ts,time,src,dst,proto,length,info,layers,"
        "src_port,dst_port,stream,flags) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        [(sid,) + r for r in rows])
    conn.commit()
    conn.close()


def load_packets(sid: str, limit: int = 100000) -> List[Dict[str, Any]]:
    conn = get_conn()
    rows = conn.execute("SELECT * FROM packets WHERE session_id=? ORDER BY pid LIMIT ?", (sid, limit)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def save_chat(sid: str, role: str, content: str) -> None:
    conn = get_conn()
    conn.execute("INSERT INTO chat (session_id,role,content,ts) VALUES (?,?,?,?)", (sid, role, content, time.time()))
    conn.commit()
    conn.close()


def load_chat(sid: str) -> List[Dict[str, str]]:
    conn = get_conn()
    rows = conn.execute("SELECT role,content FROM chat WHERE session_id=? ORDER BY id", (sid,)).fetchall()
    conn.close()
    return [{"role": r["role"], "content": r["content"]} for r in rows]


def clear_chat(sid: str) -> None:
    conn = get_conn()
    conn.execute("DELETE FROM chat WHERE session_id=?", (sid,))
    conn.commit()
    conn.close()


def stats_json(sid: str, payload: dict) -> None:
    conn = get_conn()
    conn.execute("UPDATE sessions SET summary=? WHERE id=?", (json.dumps(payload, ensure_ascii=False), sid))
    conn.commit()
    conn.close()
