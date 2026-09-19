import React, { useEffect, useMemo, useState } from 'react'
import { api } from '../lib/api'
import { useStore } from '../store'

type K = 'protocol' | 'conversation' | 'endpoint' | 'port' | 'io' | 'expert' | 'anomaly'
const TABS: { k: K; t: string }[] = [
  { k: 'protocol', t: '协议分级' },
  { k: 'conversation', t: '会话' },
  { k: 'endpoint', t: '端点' },
  { k: 'port', t: '端口流量' },
  { k: 'io', t: 'IO 分桶' },
  { k: 'expert', t: '专家信息' },
  { k: 'anomaly', t: '异常检测' },
]

/** 统计与分析面板：KPI 概览 + 7 张分析表（对齐 Wireshark 的 Statistics 菜单） */
export default function StatsPanel() {
  const [k, setK] = useState<K>('protocol')
  const [rows, setRows] = useState<any[]>([])
  const [sum, setSum] = useState<any>(null)
  const [rate, setRate] = useState<any>(null)
  const [q, setQ] = useState('')
  const live = useStore(s => s.live)

  useEffect(() => {
    let alive = true
    const load = async () => {
      try {
        const path = k === 'protocol' ? '/api/stats/protocols'
          : k === 'conversation' ? '/api/stats/conversations?limit=300'
            : k === 'endpoint' ? '/api/stats/endpoints?limit=300'
              : k === 'port' ? '/api/stats/ports?limit=300'
                : k === 'io' ? '/api/stats/io?bucket_ms=1000'
                  : k === 'expert' ? '/api/stats/expert?limit=300'
                    : '/api/stats/anomalies'
        const [r, s] = await Promise.all([
          api.get<any>(path),
          k === 'protocol' ? api.get<any>('/api/stats/summary') : Promise.resolve(null),
        ])
        if (!alive) return
        setRows((k === 'io' ? (r.points || []) : (r.items || [])))
        if (s) { setSum(s.summary); setRate(s.rate) }
      } catch { /* ignore */ }
    }
    load()
    const t = setInterval(load, 3000)
    return () => { alive = false; clearInterval(t) }
  }, [k, live?.packets])

  const filtered = useMemo(() => {
    if (!q.trim()) return rows
    const s = q.trim().toLowerCase()
    return rows.filter(r => JSON.stringify(r).toLowerCase().includes(s))
  }, [rows, q])

  const s = sum || {}
  const segTcp = (k === 'protocol' ? (rows.find(r => r.protocol === 'TCP')?.packets || 0) : 0)
  const retransRate = segTcp ? ((s.fast_retrans || 0) + (s.rto_retrans || 0)) / segTcp * 100 : 0

  return (
    <div className="pane">
      {/* 抓包概览：核心指标卡片（无数据时也显示 0，便于确认面板生效） */}
      <div className="kpis">
        <Kpi label="报文" value={fmt(s.packets)} note={`${fmt(s.bytes)} B`} />
        <Kpi label="时长" value={`${s.duration ?? 0}s`} note={`平均 ${fmt(s.avg_pps)} pps`} />
        <Kpi label="吞吐" value={rateLabel(rate)} note={`峰值 ${fmt(s.peak_pps)} pps`} />
        <Kpi label="TCP 流" value={fmt(s.tcp_streams)} note={`${fmt(s.keepalives)} 次保活`} />
        <Kpi label="链路重传率" value={`${retransRate.toFixed(2)}%`}
          note={`快速 ${s.fast_retrans || 0} / 超时 ${s.rto_retrans || 0}`}
          tone={retransRate > 1 ? 'warn' : 'ok'} />
        <Kpi label="乱序·缺口" value={`${fmt(s.out_of_order)}·${fmt(s.gaps)}`}
          note={`专家 ${fmt(s.expert_count)} 条`} />
      </div>

      <div className="subtabs">
        {TABS.map(t => (
          <div key={t.k} className={'st' + (k === t.k ? ' on' : '')} onClick={() => setK(t.k)}>{t.t}</div>
        ))}
      </div>

      <div className="row" style={{ marginBottom: 6 }}>
        <input className="input" placeholder="在结果中搜索…" value={q}
          onChange={e => setQ(e.target.value)} style={{ flex: 1 }} />
        <span className="dim" style={{ fontSize: 11 }}>{filtered.length} 行</span>
        <button className="btn" title="把当前表导出为 CSV" onClick={async () => {
          const r = await api.post<any>('/api/export', { scope: 'filtered', filter: '', format: 'csv' })
          window.open('/api/download?path=' + encodeURIComponent(r.path))
        }}>导出 CSV</button>
      </div>

      {k === 'anomaly' ? (
        <div style={{ overflow: 'auto' }}>
          {filtered.length === 0 && <div className="empty">暂无异常</div>}
          {filtered.map((a, i) => (
            <div key={i} className={'anom sev-' + (a.level || 'low')}>
              <div className="ah">{a.type}</div>
              <div className="ab">{a.detail}</div>
              {a.packet_id ? (
                <div className="ap" onClick={() => useStore.getState().select(a.packet_id)}>
                  跳转报文 #{a.packet_id}
                </div>
              ) : null}
            </div>
          ))}
        </div>
      ) : (
        <div className="scroll-x" style={{ flex: 1, overflow: 'auto' }}>
          <table className="tbl">
            <thead><tr>{head(k).map(h => <th key={h}>{h}</th>)}</tr></thead>
            <tbody>
              {filtered.slice(0, 300).map((r, i) => <tr key={i}>{cells(k, r)}</tr>)}
            </tbody>
          </table>
          {filtered.length === 0 && <div className="empty">暂无数据：先点顶部「开始」抓包，或用「导入」载入 pcap</div>}
        </div>
      )}
    </div>
  )
}

function Kpi({ label, value, note, tone }: { label: string; value: any; note?: string; tone?: string }) {
  return (
    <div className={'kpi' + (tone ? ' ' + tone : '')}>
      <div className="kl">{label}</div>
      <div className="kv">{value}</div>
      {note && <div className="kn">{note}</div>}
    </div>
  )
}

function fmt(n: any) {
  const v = Number(n || 0)
  if (v >= 1e9) return (v / 1e9).toFixed(2) + 'G'
  if (v >= 1e6) return (v / 1e6).toFixed(2) + 'M'
  if (v >= 1e3) return (v / 1e3).toFixed(1) + 'k'
  return String(Math.round(v * 100) / 100)
}

function rateLabel(rate: any) {
  if (!rate) return '—'
  const bps = Number(rate.bps || 0)
  if (bps >= 1e6) return (bps / 1e6).toFixed(2) + ' Mbps'
  if (bps >= 1e3) return (bps / 1e3).toFixed(1) + ' Kbps'
  return bps.toFixed(0) + ' bps'
}

function head(k: K) {
  if (k === 'protocol') return ['协议', '包数', '字节', '占比', '包/秒', 'bps']
  if (k === 'conversation') return ['源地址:端口', '目的地址:端口', '包数', '字节', '重传', '时长(s)']
  if (k === 'endpoint') return ['地址', '包数', '字节', '发送', '接收']
  if (k === 'port') return ['端口', 'TCP', 'UDP', '包数', '字节', '流数', '对端', '服务']
  if (k === 'io') return ['时间(相对)', '包数', '字节', 'bps']
  if (k === 'expert') return ['级别', '类型', '说明', '报文', '时间']
  return []
}

function cells(k: K, r: any) {
  if (k === 'protocol') return [<td className={'p-' + r.protocol}>{r.protocol}</td>, <td>{r.packets}</td>,
  <td>{r.bytes}</td>, <td>{r.percent}%</td>, <td>{r.pps}</td>, <td>{fmt(r.bps)}</td>]
  if (k === 'conversation') return [
    <td>{r.src}:{r.src_port}</td>, <td>{r.dst}:{r.dst_port}</td>, <td>{r.packets}</td>,
    <td>{r.bytes}</td>, <td className={r.retrans ? 'sev-warn' : ''}>{r.retrans}</td>, <td>{r.duration}</td>]
  if (k === 'endpoint') return [<td>{r.address}</td>, <td>{r.packets}</td>, <td>{r.bytes}</td>,
  <td>{r.tx_bytes}</td>, <td>{r.rx_bytes}</td>]
  if (k === 'port') return [<td>{r.port}</td>, <td>{r.tcp}</td>, <td>{r.udp}</td>, <td>{r.packets}</td>,
  <td>{r.bytes}</td>, <td>{r.streams}</td>, <td>{r.peers}</td>, <td>{(r.services || []).join(',')}</td>]
  if (k === 'io') {
    const pts = r as unknown as number[]
    return [<td>+{Number(pts[0] || 0).toFixed(3)}s</td>, <td>{pts[1]}</td>, <td>{pts[2]}</td>, <td>{fmt(pts[3])}</td>]
  }
  if (k === 'expert') return [
    <td className={'sev-' + r.severity}>{sevLabel(r.severity)}</td>, <td>{r.group}</td>,
    <td style={{ whiteSpace: 'normal' }}>{r.text}</td>,
    <td className="link" onClick={() => r.packet_id && useStore.getState().select(r.packet_id)}>
      {r.packet_id ? '#' + r.packet_id : ''}</td>, <td>{r.time}</td>]
  return []
}

function sevLabel(s: string) {
  return { error: '错误', warn: '警告', note: '提示', chat: '会话' }[s] || s
}
