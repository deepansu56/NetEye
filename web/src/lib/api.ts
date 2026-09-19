const BASE = (import.meta as any).env?.VITE_API_BASE ?? ''

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(BASE + path, {
    headers: { 'Content-Type': 'application/json' },
    ...init,
  })
  if (!res.ok) {
    let msg = `HTTP ${res.status}`
    try {
      const j = await res.json()
      msg = j.detail || j.error || msg
    } catch { /* ignore */ }
    throw new Error(msg)
  }
  return res.json()
}

export const api = {
  get: <T,>(p: string) => req<T>(p),
  post: <T,>(p: string, body?: any) =>
    req<T>(p, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) }),
  del: <T,>(p: string) => req<T>(p, { method: 'DELETE' }),
}

export interface PacketSummary {
  id: number; ts: number; time: string; src: string; dst: string; proto: string
  length: number; info: string; layers: string[]; src_port?: number; dst_port?: number
  stream?: number; flags?: string; color?: string
}

export interface FieldNode {
  name: string; label?: string; value: string
  offset: number; size: number; desc?: string; bits?: string
}
export interface LayerNode {
  name: string; title: string; fields: FieldNode[]
  children?: LayerNode[]; desc?: string
}
export interface AnalysisNote { flag: string; severity: string; text: string; group: string }
export interface PacketDetail {
  id: number; summary: PacketSummary; layers: LayerNode[]; hex: string
  notes?: AnalysisNote[]
}
export interface InterfaceInfo { name: string; description: string; ip: string; mac: string; is_up: boolean; engine: string; index: number; recommended?: boolean }
