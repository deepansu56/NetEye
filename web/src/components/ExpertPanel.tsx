import React, { useEffect, useState } from 'react'
import { api } from '../lib/api'
import { useStore } from '../store'

export default function ExpertPanel() {
  const [anom, setAnom] = useState<any[]>([])
  const [items, setItems] = useState<any[]>([])
  const [sev, setSev] = useState('all')
  const select = useStore(s => s.select)
  const live = useStore(s => s.live)

  useEffect(() => {
    let alive = true
    const load = async () => {
      try {
        const [a, e] = await Promise.all([
          api.get<{ items: any[] }>('/api/stats/anomalies'),
          api.get<{ items: any[] }>(`/api/stats/expert?severity=${sev}&limit=300`),
        ])
        if (alive) { setAnom(a.items || []); setItems((e.items || []).slice().reverse()) }
      } catch { /* ignore */ }
    }
    load()
    const t = setInterval(load, 4000)
    return () => { alive = false; clearInterval(t) }
  }, [sev, live?.packets])

  return (
    <div className="pane">
      <div className="card">
        <h4>异常检测结论</h4>
        {anom.map((a, i) => (
          <div key={i} style={{ marginBottom: 8, paddingBottom: 8, borderBottom: '1px solid var(--line)' }}>
            <div className={'lvl-' + a.level} style={{ fontWeight: 600 }}>● {a.type}</div>
            <div style={{ color: 'var(--dim)', fontSize: 12 }}>{a.detail}</div>
          </div>
        ))}
        {anom.length === 0 && <div className="hint">暂无结论</div>}
      </div>

      <div style={{ display: 'flex', gap: 6, marginBottom: 8 }}>
        {['all', 'error', 'warn', 'note'].map(s => (
          <button key={s} className="btn" style={{ padding: '2px 8px', fontSize: 11 }}
            onClick={() => setSev(s)}>{s === 'all' ? '全部' : s === 'error' ? '错误' : s === 'warn' ? '警告' : '提示'}</button>
        ))}
        <span className="spacer" style={{ flex: 1 }} />
        <span className="hint">{items.length} 条</span>
      </div>

      <div className="scroll-x">
        <table className="tbl">
          <thead><tr><th>级别</th><th>分组</th><th>说明</th><th>包号</th><th>时间</th></tr></thead>
          <tbody>
            {items.map((e, i) => (
              <tr key={i} style={{ cursor: 'pointer' }} onClick={() => select(e.packet_id)}>
                <td className={'sev-' + e.severity}>{e.severity === 'error' ? '错误' : e.severity === 'warn' ? '警告' : '提示'}</td>
                <td>{e.group}</td>
                <td>{e.text}</td>
                <td className="num">#{e.packet_id}</td>
                <td>{e.time}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {items.length === 0 && <div className="empty">无异常事件</div>}
    </div>
  )
}
