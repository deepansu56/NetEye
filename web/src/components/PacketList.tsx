import React, { useEffect, useRef, useState } from 'react'
import { useStore } from '../store'
import { PacketSummary } from '../lib/api'

const ROW = 24
const COLS = [
  { k: 'id', t: 'No.', w: 68 },
  { k: 'time', t: 'Time', w: 96 },
  { k: 'src', t: 'Source', w: 160 },
  { k: 'dst', t: 'Destination', w: 160 },
  { k: 'proto', t: 'Protocol', w: 90 },
  { k: 'length', t: 'Length', w: 74 },
  { k: 'info', t: 'Info', w: 9999 },
]

export default function PacketList() {
  const packets = useStore(s => s.packets)
  const selected = useStore(s => s.selected)
  const select = useStore(s => s.select)
  const loadMore = useStore(s => s.loadMore)
  const autoScroll = useStore(s => s.autoScroll)
  const total = useStore(s => s.total)
  const [top, setTop] = useState(0)
  const [vh, setVh] = useState(600)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const el = ref.current
    if (!el) return
    const ro = new ResizeObserver(() => setVh(el.clientHeight))
    ro.observe(el)
    setVh(el.clientHeight)
    return () => ro.disconnect()
  }, [])

  const start = Math.max(0, Math.floor(top / ROW) - 6)
  const end = Math.min(packets.length, Math.ceil((top + vh) / ROW) + 6)
  const slice = packets.slice(start, end)

  return (
    <div className="pktlist">
      <div className="pkt-head">
        {COLS.map(c => <span key={c.k} style={{ width: c.w, flex: c.w === 9999 ? 1 : undefined }}>{c.t}</span>)}
        <span style={{ width: 74, border: 'none' }}>
          <label style={{ cursor: 'pointer', color: autoScroll ? 'var(--ok)' : 'var(--dim)' }}>
            <input type="checkbox" checked={autoScroll} style={{ verticalAlign: -2, marginRight: 3 }}
              onChange={e => useStore.setState({ autoScroll: e.target.checked })} />自动滚动
          </label>
        </span>
      </div>
      <div className="pkt-scroll" id="pkt-scroll" ref={ref}
        onScroll={e => {
          const el = e.currentTarget
          setTop(el.scrollTop)
          if (el.scrollHeight - el.scrollTop - el.clientHeight < 200) loadMore()
        }}>
        {packets.length === 0 && <div className="empty">暂无数据 · 点「开始」抓包，或导入 pcap 离线分析</div>}
        <div style={{ height: packets.length * ROW, position: 'relative' }}>
          {slice.map((p: PacketSummary) => (
            <div key={p.id}
              className={'pkt-row' + (selected === p.id ? ' sel' : '')}
              style={{ position: 'absolute', top: (packets.indexOf(p)) * ROW, left: 0, right: 0 }}
              onClick={() => select(p.id)}>
              <span className="num" style={{ width: 68 }}>{p.id}</span>
              <span style={{ width: 96 }}>{p.time}</span>
              <span style={{ width: 160 }}>{p.src}</span>
              <span style={{ width: 160 }}>{p.dst}</span>
              <span style={{ width: 90 }} className={'p-' + p.proto}>{p.proto}</span>
              <span style={{ width: 74 }}>{p.length}</span>
              <span style={{ flex: 1 }}>{p.info}</span>
            </div>
          ))}
        </div>
      </div>
      <div style={{ padding: '3px 8px', fontSize: 11, color: 'var(--dim)', borderTop: '1px solid var(--line)' }}>
        显示 {packets.length} / {total} 个报文{packets.length < total ? '（滚动加载更多）' : ''}
      </div>
    </div>
  )
}
