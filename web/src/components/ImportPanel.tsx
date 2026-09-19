import React, { useEffect, useState } from 'react'
import { api } from '../lib/api'
import { useStore } from '../store'

export default function ImportPanel({ onClose }: { onClose: () => void }) {
  const [caps, setCaps] = useState<any[]>([])
  const [sess, setSess] = useState<any[]>([])
  const [path, setPath] = useState('')
  const [msg, setMsg] = useState('')

  const load = async () => {
    try {
      const [c, s] = await Promise.all([api.get<{ items: any[] }>('/api/captures'),
      api.get<{ items: any[] }>('/api/sessions')])
      setCaps(c.items || []); setSess(s.items || [])
    } catch { /* ignore */ }
  }
  useEffect(() => { load() }, [])

  const doImport = async (p: string) => {
    try {
      const r = await api.post<any>('/api/sessions/import-pcap', { path: p })
      setMsg(`已导入 ${r.packets} 个报文`)
      const st = useStore.getState()
      await st.loadPackets(true)
      useStore.setState({ state: 'offline' })
      setTimeout(onClose, 600)
    } catch (e: any) { setMsg('导入失败：' + e.message) }
  }

  const loadSession = async (id: string) => {
    try {
      const r = await api.post<any>(`/api/sessions/load/${id}`, {})
      setMsg(`已加载 ${r.packets} 个报文`)
      await useStore.getState().loadPackets(true)
      useStore.setState({ state: 'offline' })
      setTimeout(onClose, 600)
    } catch (e: any) { setMsg('加载失败：' + e.message) }
  }

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.45)', zIndex: 50 }}
      onClick={onClose}>
      <div onClick={e => e.stopPropagation()} style={{
        position: 'absolute', top: 60, right: 40, width: 520, maxHeight: '75vh', overflow: 'auto',
        background: 'var(--panel)', border: '1px solid var(--line)', borderRadius: 8, padding: 14,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', marginBottom: 10 }}>
          <b>导入离线数据</b><span className="spacer" style={{ flex: 1 }} />
          <button className="btn" onClick={onClose}>关闭</button>
        </div>

        <div className="card">
          <h4>按路径导入 pcap</h4>
          <div style={{ display: 'flex', gap: 6 }}>
            <input style={{ flex: 1, background: '#0f141b', border: '1px solid var(--line)', borderRadius: 5, padding: '5px 8px' }}
              placeholder="例如 C:\\captures\\test.pcap" value={path} onChange={e => setPath(e.target.value)} />
            <button className="btn primary" onClick={() => doImport(path)}>导入</button>
          </div>
          <div className="hint" style={{ marginTop: 6 }}>支持 libpcap 格式（Wireshark 保存的 .pcap 可直接导入）</div>
        </div>

        <div className="card">
          <h4>已保存的抓包文件</h4>
          {caps.map(c => (
            <div key={c.path} style={{ display: 'flex', alignItems: 'center', padding: '5px 0', borderBottom: '1px solid var(--line)' }}>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 12 }}>{c.name}</div>
                <div className="hint">{c.packets} 包 · {(c.size / 1024).toFixed(1)} KB · {c.path}</div>
              </div>
              <button className="btn" onClick={() => doImport(c.path)}>导入</button>
            </div>
          ))}
          {caps.length === 0 && <div className="hint">暂无文件</div>}
        </div>

        <div className="card">
          <h4>历史会话</h4>
          {sess.map(s => (
            <div key={s.id} style={{ display: 'flex', alignItems: 'center', padding: '5px 0', borderBottom: '1px solid var(--line)' }}>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 12 }}>{s.name}</div>
                <div className="hint">{s.packet_count} 包 · {s.interface || '—'} · {s.bpf_filter || '无过滤'}</div>
              </div>
              <button className="btn" onClick={() => loadSession(s.id)}>加载</button>
              <button className="btn danger" style={{ marginLeft: 4 }}
                onClick={async () => { await api.del(`/api/sessions/${s.id}`); load() }}>删除</button>
            </div>
          ))}
          {sess.length === 0 && <div className="hint">暂无会话</div>}
        </div>

        {msg && <div className="card" style={{ color: 'var(--ok)' }}>{msg}</div>}
      </div>
    </div>
  )
}
