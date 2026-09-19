import React, { useEffect, useState } from 'react'
import { useStore } from '../store'
import ImportPanel from './ImportPanel'

export default function Toolbar() {
  const s = useStore()
  const [bpf, setBpf] = useState('')
  const [filter, setFilter] = useState('')
  const [imp, setImp] = useState(false)
  const running = s.state === 'running'
  const srv = useStore(st => st.live)

  useEffect(() => { setBpf(s.bpf) }, [s.bpf])

  const noEngine = s.engines && !s.engines.npcap?.available && !s.engines.raw?.available

  return (
    <div className="topbar">
      <div className="logo">Net<b>Eye</b></div>

      <select value={s.iface} onChange={e => useStore.setState({ iface: e.target.value })}
        style={{ maxWidth: 220 }} title="选择网卡">
        {s.interfaces.length === 0 && <option value="">（无网卡）</option>}
        {s.interfaces.map(i => (
          <option key={i.index} value={i.name}>
            {i.name} {i.ip ? `· ${i.ip}` : ''} {i.is_up ? '' : '(未连接)'}
          </option>
        ))}
      </select>

      <input placeholder="捕获过滤器 BPF，如 tcp port 80" value={bpf} style={{ width: 220 }}
        onChange={e => setBpf(e.target.value)} onBlur={() => useStore.setState({ bpf })} />

      {!running ? (
        <button className="btn primary" onClick={s.start} disabled={noEngine}>▶ 开始</button>
      ) : (
        <button className="btn" onClick={s.pause}>⏸ 暂停</button>
      )}
      {s.state === 'paused' && <button className="btn primary" onClick={s.resume}>▶ 继续</button>}
      <button className="btn" onClick={s.stop} disabled={!running && s.state !== 'paused'}>⏹ 停止</button>
      <button className="btn" onClick={async () => { await s.clear() }}>🗑 清空</button>
      <button className="btn" onClick={s.saveSession} title="保存为会话与 pcap">💾 保存</button>
      <button className="btn" onClick={() => setImp(true)} title="导入 pcap / 历史会话">📂 导入</button>
      {imp && <ImportPanel onClose={() => setImp(false)} />}

      <input placeholder="显示过滤器，如 tcp.port==80 && http" value={filter}
        onChange={e => setFilter(e.target.value)}
        onKeyDown={e => { if (e.key === 'Enter') s.setFilter(filter) }}
        style={{ width: 260, borderColor: s.filterError ? 'var(--err)' : undefined }} title={s.filterError} />
      <button className="btn" onClick={() => s.setFilter(filter)}>应用</button>

      <div className="spacer" />

      {s.error && <span className="chip" style={{ color: 'var(--err)' }} title={s.error}>{s.error.slice(0, 40)}</span>}
      <span className="chip">
        <i className={'dot ' + (running ? 'run' : s.state === 'paused' ? 'pause' : 'idle')} />
        {running ? '捕获中' : s.state === 'paused' ? '已暂停' : s.state === 'offline' ? '离线' : '待机'}
      </span>
      {srv && (
        <span className="chip">{srv.packets} 包 · {fmtRate(srv.rate?.bps || 0)}</span>
      )}
      <span className={'chip ' + (s.wsOn ? 'on' : 'off')}>{s.wsOn ? '实时连接' : '离线'}</span>
      {s.engines?.npcap?.available && <span className="chip on">Npcap</span>}
      {!s.engines?.npcap?.available && <span className="chip" title={s.engines?.npcap?.reason}>无 Npcap</span>}
      {!s.engines?.raw?.available && <span className="chip" title={s.engines?.raw?.reason}>需管理员</span>}
    </div>
  )
}

function fmtRate(bps: number) {
  if (bps > 1e9) return (bps / 1e9).toFixed(2) + ' Gbps'
  if (bps > 1e6) return (bps / 1e6).toFixed(2) + ' Mbps'
  if (bps > 1e3) return (bps / 1e3).toFixed(1) + ' Kbps'
  return Math.round(bps) + ' bps'
}
