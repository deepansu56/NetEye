import React, { useEffect, useState } from 'react'

/** 带超时的 GET：避免慢请求把浏览器连接池堵死 */
async function getT<T>(url: string, ms = 8000): Promise<T> {
  const ctl = new AbortController()
  const timer = setTimeout(() => ctl.abort(), ms)
  try {
    const res = await fetch(url, { signal: ctl.signal })
    if (!res.ok) throw new Error('HTTP ' + res.status)
    return (await res.json()) as T
  } finally {
    clearTimeout(timer)
  }
}

export default function PortPanel() {
  const [items, setItems] = useState<any[]>([])
  const [sum, setSum] = useState<any>({})
  const [onlyListen, setOnlyListen] = useState(false)
  const [kw, setKw] = useState('')
  const [flow, setFlow] = useState<any[]>([])
  const [err, setErr] = useState('')

  useEffect(() => {
    let alive = true
    let timer: any = null

    // 两个请求互相独立：任一失败不影响另一个；用递归 setTimeout 避免请求堆积
    const load = async () => {
      try {
        const r = await getT<any>(`/api/stats/portstate?only_listen=${onlyListen}`, 10000)
        if (alive) { setItems(r.items || []); setSum(r.summary || {}); setErr('') }
      } catch (e: any) {
        if (alive) setErr('本机连接状态读取失败或超时：' + (e?.message || e))
      }
      try {
        const f = await getT<{ items: any[] }>('/api/stats/ports?limit=100')
        if (alive) setFlow(f.items || [])
      } catch { /* 抓包侧统计失败不影响本机连接表 */ }
      if (alive) timer = setTimeout(load, 5000)
    }

    load()
    return () => { alive = false; if (timer) clearTimeout(timer) }
  }, [onlyListen])

  const list = items.filter(i =>
    !kw || String(i.local_port).includes(kw) || (i.process || '').toLowerCase().includes(kw.toLowerCase()) ||
    (i.local || '').includes(kw))

  return (
    <div className="pane">
      <div className="card">
        <h4>本机连接概览</h4>
        <div className="kv">
          <div><span>总连接</span> <b>{sum.total ?? 0}</b></div>
          <div><span>监听端口</span> <b>{sum.listening ?? 0}</b></div>
          <div><span>已建立</span> <b>{sum.established ?? 0}</b></div>
          <div><span>TCP/UDP 端口</span> <b>{sum.tcp_ports ?? 0} / {sum.udp_ports ?? 0}</b></div>
        </div>
        <div style={{ marginTop: 8 }}>
          {(sum.top_processes || []).map((p: any) => (
            <div key={p.process} style={{ fontSize: 12, display: 'flex' }}>
              <span style={{ width: 130, overflow: 'hidden', whiteSpace: 'nowrap', textOverflow: 'ellipsis' }}>{p.process}</span>
              <span className="bar" style={{ width: Math.min(p.connections * 5, 180), marginTop: 7 }} />
              <span style={{ color: 'var(--dim)', marginLeft: 6 }}>{p.connections}</span>
            </div>
          ))}
        </div>
      </div>

      {err && <div className="hint" style={{ color: 'var(--warn)', marginBottom: 6 }}>{err}</div>}

      <div style={{ display: 'flex', gap: 6, marginBottom: 8, alignItems: 'center' }}>
        <input placeholder="按端口 / 进程筛选" value={kw} onChange={e => setKw(e.target.value)}
          style={{ flex: 1, background: '#0f141b', border: '1px solid var(--line)', borderRadius: 5, padding: '5px 8px' }} />
        <label className="hint" style={{ display: 'flex', alignItems: 'center', gap: 4, whiteSpace: 'nowrap' }}>
          <input type="checkbox" checked={onlyListen} onChange={e => setOnlyListen(e.target.checked)} />仅监听
        </label>
      </div>

      <div className="scroll-x" style={{ maxHeight: 300 }}>
        <table className="tbl" style={{ whiteSpace: 'nowrap', tableLayout: 'fixed', width: '100%' }}>
          <thead><tr>
            <th style={{ width: 42 }}>协议</th>
            <th style={{ width: 160 }}>本地地址</th>
            <th style={{ width: 46 }}>状态</th>
            <th>进程 / 远端</th>
          </tr></thead>
          <tbody>
            {list.slice(0, 300).map((c, i) => (
              <tr key={i}>
                <td>{c.proto}</td>
                <td style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{c.local}</td>
                <td className={c.status_raw === 'LISTEN' ? 'lvl-low' : ''}>{c.status}</td>
                <td style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {c.process || `pid:${c.pid}`}
                  {c.remote && c.remote !== '*' ? <span style={{ color: 'var(--dim)' }}> → {c.remote}</span> : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {list.length === 0 && !err && (
        <div className="hint" style={{ marginTop: 6 }}>
          未读取到连接信息（部分系统需管理员权限才能看到进程名与全部连接）
        </div>
      )}

      <div className="card" style={{ marginTop: 10 }}>
        <h4>端口流量 Top（来自抓包）</h4>
        <div className="scroll-x">
          <table className="tbl" style={{ whiteSpace: 'nowrap', tableLayout: 'fixed', width: '100%' }}>
            <thead><tr>
              <th style={{ width: 54 }}>端口</th>
              <th style={{ width: 60 }}>包数</th>
              <th style={{ width: 74 }}>字节</th>
              <th style={{ width: 44 }}>流数</th>
              <th>服务 / 对端</th>
            </tr></thead>
            <tbody>
              {flow.slice(0, 40).map((p, i) => (
                <tr key={i}>
                  <td><b>{p.port}</b></td><td>{p.packets}</td><td>{p.bytes}</td>
                  <td>{p.streams}</td>
                  <td style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {(p.services || []).join(',') || '—'}
                    <span style={{ color: 'var(--dim)' }}> · {p.peers} 对端</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {flow.length === 0 && <div className="hint">暂无抓包数据</div>}
      </div>
    </div>
  )
}
