import React, { useEffect, useRef, useState } from 'react'
import { useStore, TabKey } from './store'
import Toolbar from './components/Toolbar'
import PacketList from './components/PacketList'
import PacketDetail from './components/PacketDetail'
import IOChart from './components/IOChart'
import StatsPanel from './components/StatsPanel'
import PortPanel from './components/PortPanel'
import ExpertPanel from './components/ExpertPanel'
import AIChat from './components/AIChat'

const TABS: { key: TabKey; label: string }[] = [
  { key: 'io', label: '曲线' },
  { key: 'stats', label: '统计' },
  { key: 'ports', label: '端口' },
  { key: 'expert', label: '专家' },
  { key: 'ai', label: 'AI 分析' },
]

export default function App() {
  const init = useStore(s => s.init)
  const connectWS = useStore(s => s.connectWS)
  const live = useStore(s => s.live)
  const [tab, setTab] = useState<TabKey>('io')
  const [rightW, setRightW] = useState(480)
  const [detailH, setDetailH] = useState(330)
  const drag = useRef<'v' | 'h' | null>(null)

  useEffect(() => { init(); connectWS() }, [])

  // 标签角标：让"统计 / 专家 / AI"这些面板一眼可见且知道有没有内容
  const badge = (k: TabKey) => {
    if (!live) return ''
    const pk = Number(live.packets || 0)
    const ex = Number(live.expert_count || 0)
    if (k === 'stats' && pk) return pk > 9999 ? '9999+' : String(pk)
    if (k === 'expert' && ex) return String(ex)
    if (k === 'ai') return ex ? String(ex) : (pk ? '就绪' : '')
    return ''
  }

  useEffect(() => {
    const move = (e: MouseEvent) => {
      if (drag.current === 'v') setRightW(Math.min(900, Math.max(320, window.innerWidth - e.clientX)))
      if (drag.current === 'h') setDetailH(Math.min(600, Math.max(120, window.innerHeight - e.clientY - 40)))
    }
    const up = () => { drag.current = null }
    window.addEventListener('mousemove', move)
    window.addEventListener('mouseup', up)
    return () => { window.removeEventListener('mousemove', move); window.removeEventListener('mouseup', up) }
  }, [])

  return (
    <div className="app">
      <Toolbar />
      <div className="main">
        <div className="left">
          <PacketList />
          <div className="splitter-h" onMouseDown={() => (drag.current = 'h')} />
          <div style={{ height: detailH, minHeight: 120, display: 'flex', flexDirection: 'column' }}>
            <PacketDetail />
          </div>
        </div>
        <div className="resizer" onMouseDown={() => (drag.current = 'v')} />
        <div className="right" style={{ width: rightW }}>
          <div className="tabs">
            {TABS.map(t => (
              <div key={t.key} className={'t' + (tab === t.key ? ' on' : '')} onClick={() => setTab(t.key)}>
                {t.label}
                {badge(t.key) && <span className="tbadge">{badge(t.key)}</span>}
              </div>
            ))}
          </div>
          {tab === 'io' && <IOChart />}
          {tab === 'stats' && <StatsPanel />}
          {tab === 'ports' && <PortPanel />}
          {tab === 'expert' && <ExpertPanel />}
          {tab === 'ai' && <AIChat />}
        </div>
      </div>
    </div>
  )
}
