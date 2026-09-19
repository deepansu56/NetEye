import React, { useEffect, useRef, useState } from 'react'
import * as echarts from 'echarts'
import { useStore } from '../store'
import { api } from '../lib/api'

export default function IOChart() {
  const live = useStore(s => s.live)
  const filter = useStore(s => s.filter)
  const [bucket, setBucket] = useState(1000)
  const ref = useRef<HTMLDivElement>(null)
  const chart = useRef<echarts.ECharts>()

  useEffect(() => {
    if (!ref.current) return
    chart.current = echarts.init(ref.current, 'dark')
    const ro = new ResizeObserver(() => chart.current?.resize())
    ro.observe(ref.current)
    return () => { ro.disconnect(); chart.current?.dispose() }
  }, [])

  useEffect(() => {
    let alive = true
    const load = async () => {
      try {
        const r = await api.get<any>(`/api/stats/io?bucket_ms=${bucket}`)
        const f = filter ? await api.get<any>(`/api/stats/io?bucket_ms=${bucket}&filter=${encodeURIComponent(filter)}`) : null
        if (!alive || !chart.current) return
        const pts = r.points || []
        const fp = f?.points || []
        const toSeries = (p: any[], vi: number) => p.map((x: any) => [new Date(x[0] * 1000), x[vi]])
        chart.current.setOption({
          backgroundColor: 'transparent',
          tooltip: { trigger: 'axis' },
          legend: { data: filter ? ['包数', '过滤后包数', '比特率'] : ['包数', '比特率'], textStyle: { fontSize: 11 } },
          grid: { left: 52, right: 56, top: 34, bottom: 46 },
          xAxis: { type: 'time' },
          yAxis: [
            { type: 'value', name: '包/秒', nameTextStyle: { fontSize: 10 } },
            { type: 'value', name: 'bps', nameTextStyle: { fontSize: 10 },
              axisLabel: { formatter: (v: number) => v > 1e6 ? (v / 1e6).toFixed(1) + 'M' : v > 1e3 ? (v / 1e3).toFixed(0) + 'K' : v } },
          ],
          dataZoom: [{ type: 'inside' }, { type: 'slider', height: 16, bottom: 8 }],
          series: [
            { name: '包数', type: 'line', showSymbol: false, smooth: true, data: toSeries(pts, 1),
              lineStyle: { width: 1.5 }, areaStyle: { opacity: .18 }, itemStyle: { color: '#58a6ff' } },
            ...(f ? [{ name: '过滤后包数', type: 'line', showSymbol: false, smooth: true, data: toSeries(fp, 1),
              lineStyle: { width: 1.5 }, itemStyle: { color: '#e63946' } }] : []),
            { name: '比特率', type: 'line', yAxisIndex: 1, showSymbol: false, smooth: true, data: toSeries(pts, 3),
              lineStyle: { width: 1, type: 'dashed' }, itemStyle: { color: '#7ee787' } },
          ],
        }, true)
      } catch { /* ignore */ }
    }
    load()
    const t = setInterval(load, 2000)
    return () => { alive = false; clearInterval(t) }
  }, [bucket, filter])

  const s = live || {}
  return (
    <div className="pane" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      <div className="card">
        <h4>实时概览</h4>
        <div className="kv">
          <div><span>报文数</span> <b>{s.packets ?? 0}</b></div>
          <div><span>字节数</span> <b>{fmtBytes(s.bytes ?? 0)}</b></div>
          <div><span>{s.state === 'running' ? '速率' : '平均速率'}</span> <b>{fmtBps(s.state === 'running' ? (s.rate?.bps || s.avg_bps || 0) : (s.avg_bps || 0))}</b></div>
          <div><span>{s.state === 'running' ? '包速率' : '平均包速率'}</span> <b>{Math.round(s.state === 'running' ? (s.rate?.pps || s.avg_pps || 0) : (s.avg_pps || 0))} pps</b></div>
          <div><span>峰值</span> <b>{fmtBps(s.peak_bps ?? 0)}</b></div>
          <div><span>TCP 流</span> <b>{s.tcp_streams ?? 0}</b></div>
          <div><span>异常</span> <b className={(s.expert_count ?? 0) > 0 ? 'sev-warn' : ''}>{s.expert_count ?? 0}</b></div>
          {/* 链路质量用「快速+超时重传」衡量：Keep-Alive 探测单独列出，否则
              空闲连接每秒一次的探针会把重传率虚高数倍 */}
          <div><span>链路重传</span>
            <b className={((s.fast_retrans ?? 0) + (s.rto_retrans ?? 0)) > 0 ? 'sev-warn' : ''}
               title="快速重传 + 超时重传，反映真实链路丢包">
              {(s.fast_retrans ?? 0) + (s.rto_retrans ?? 0)}
            </b>
          </div>
          <div><span>保活探测</span>
            <b title="TCP Keep-Alive 探针次数，不计入重传">{s.keepalives ?? 0}</b>
          </div>
          <div><span>乱序/缺口</span>
            <b title="乱序报文数 / 序列号缺口数">{(s.out_of_order ?? 0)} / {s.gaps ?? 0}</b>
          </div>
        </div>
      </div>

      <div className="card" style={{ flex: 1, minHeight: 240, display: 'flex', flexDirection: 'column' }}>
        <h4 style={{ display: 'flex', alignItems: 'center' }}>
          流量曲线
          <span className="spacer" style={{ flex: 1 }} />
          <select value={bucket} onChange={e => setBucket(+e.target.value)}
            style={{ background: '#0f141b', border: '1px solid var(--line)', borderRadius: 4, padding: '2px 4px', fontSize: 11 }}>
            <option value={100}>100ms</option>
            <option value={500}>500ms</option>
            <option value={1000}>1s</option>
            <option value={5000}>5s</option>
            <option value={10000}>10s</option>
          </select>
        </h4>
        <div ref={ref} style={{ flex: 1, minHeight: 200 }} />
      </div>

      <div className="card">
        <h4>协议分布</h4>
        {(live?.top_protocols || []).map((p: any) => (
          <div key={p.protocol} style={{ marginBottom: 6 }}>
            <div style={{ display: 'flex', fontSize: 12 }}>
              <span style={{ width: 90 }}>{p.protocol}</span>
              <span style={{ color: 'var(--dim)' }}>{p.packets} 包 · {p.percent}%</span>
            </div>
            <div className="bar" style={{ width: Math.max(p.percent, 1) + '%' }} />
          </div>
        ))}
        {(!live?.top_protocols || live.top_protocols.length === 0) && <div className="hint">暂无数据</div>}
      </div>
    </div>
  )
}

function fmtBytes(b: number) {
  if (b > 1 << 30) return (b / (1 << 30)).toFixed(2) + ' GB'
  if (b > 1 << 20) return (b / (1 << 20)).toFixed(2) + ' MB'
  if (b > 1024) return (b / 1024).toFixed(1) + ' KB'
  return b + ' B'
}
function fmtBps(bps: number) {
  if (bps > 1e9) return (bps / 1e9).toFixed(2) + ' Gbps'
  if (bps > 1e6) return (bps / 1e6).toFixed(2) + ' Mbps'
  if (bps > 1e3) return (bps / 1e3).toFixed(1) + ' Kbps'
  return Math.round(bps) + ' bps'
}
