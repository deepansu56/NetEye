import React, { useEffect, useRef, useState } from 'react'
import { api } from '../lib/api'
import { useStore } from '../store'

type Msg = { role: 'user' | 'ai' | 'tool' | 'err'; text: string }

const QUICK = [
  '当前流量有什么异常？',
  '流量最大的 5 个会话是哪些？',
  '哪个端口流量最高，可能有风险吗？',
  '有多少 TCP 重传，说明了什么？',
  '最近的 DNS 查询情况如何？',
  '给我一份这次抓包的结论摘要',
]

export default function AIChat() {
  const [msgs, setMsgs] = useState<Msg[]>([])
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const [showCfg, setShowCfg] = useState(false)
  const [cfg, setCfg] = useState<any>({})
  const [testMsg, setTestMsg] = useState('')
  const selected = useStore(s => s.selected)
  const livePackets = useStore(s => s.live?.packets)
  const [snap, setSnap] = useState<any>(null)
  const [anoms, setAnoms] = useState<any[]>([])
  const [protoTop, setProtoTop] = useState('')
  const box = useRef<HTMLDivElement>(null)

  useEffect(() => { api.get<any>('/api/ai/config').then(setCfg).catch(() => {}) }, [])

  // 数据快照：即使不配模型、不问问题，面板也能显示"当前数据长什么样"
  useEffect(() => {
    let alive = true
    const load = async () => {
      try {
        const [s, a, p] = await Promise.all([
          api.get<any>('/api/stats/summary'),
          api.get<any>('/api/stats/anomalies'),
          api.get<any>('/api/stats/protocols'),
        ])
        if (!alive) return
        setSnap(s.summary || null)
        setAnoms(a.items || [])
        setProtoTop(((p.items || []) as any[]).slice(0, 5)
          .map(x => `${x.protocol} ${x.percent}%`).join(' / '))
      } catch { /* ignore */ }
    }
    load()
    const t = setInterval(load, 5000)
    return () => { alive = false; clearInterval(t) }
  }, [livePackets])

  useEffect(() => { box.current?.scrollTo({ top: box.current.scrollHeight }) }, [msgs])

  const send = async (text: string) => {
    if (!text.trim() || busy) return
    setInput('')
    const history = msgs.filter(m => m.role === 'user' || m.role === 'ai')
      .map(m => ({ role: m.role === 'user' ? 'user' : 'assistant', content: m.text }))
    setMsgs(m => [...m, { role: 'user', text }])
    setBusy(true)
    let aiText = ''
    setMsgs(m => [...m, { role: 'ai', text: '' }])
    try {
      const res = await fetch('/api/ai/chat', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          messages: [...history, { role: 'user', content: text }],
          context_packet_ids: selected ? [selected] : [],
        }),
      })
      const reader = res.body?.getReader()
      const dec = new TextDecoder()
      let buf = ''
      while (reader) {
        const { done, value } = await reader.read()
        if (done) break
        buf += dec.decode(value, { stream: true })
        const lines = buf.split('\n')
        buf = lines.pop() || ''
        for (const line of lines) {
          if (!line.startsWith('data:')) continue
          const data = line.slice(5).trim()
          if (data === '[DONE]') continue
          try {
            const ev = JSON.parse(data)
            if (ev.type === 'token') {
              aiText += ev.text
              setMsgs(m => [...m.slice(0, -1), { role: 'ai', text: aiText }])
            } else if (ev.type === 'tool') {
              setMsgs(m => [...m, { role: 'tool', text: `🔧 ${ev.name}(${JSON.stringify(ev.args)}) → ${ev.result.slice(0, 160)}` }])
            } else if (ev.type === 'status') {
              setMsgs(m => [...m, { role: 'tool', text: '⏳ ' + ev.text }])
            } else if (ev.type === 'error') {
              setMsgs(m => [...m, { role: 'err', text: ev.text }])
            }
          } catch { /* ignore */ }
        }
      }
    } catch (e: any) {
      setMsgs(m => [...m, { role: 'err', text: String(e.message || e) }])
    }
    setBusy(false)
  }

  const saveCfg = async () => {
    await api.post('/api/ai/config', {
      provider: cfg.provider, base_url: cfg.base_url, api_key: cfg.api_key === '••••' ? undefined : cfg.api_key,
      model: cfg.model, temperature: cfg.temperature,
    })
    const c = await api.get<any>('/api/ai/config')
    setCfg(c); setShowCfg(false)
  }

  return (
    <div className="ai-wrap">
      {/* 状态条：让「AI 是否可用、走哪条链路、能查什么」一眼可见 */}
      <div className="ai-status">
        <span className={'dot ' + (cfg.has_key ? 'on' : 'off')} />
        <span className="st-txt">
          {cfg.has_key ? `AI 模型：${cfg.model || '已配置'}（${cfg.provider || 'custom'}）`
            : 'AI 模型未配置 → 当前使用内置规则引擎（离线可用，结论同样基于真实数据）'}
        </span>
        <span className="st-tools" title={String((cfg.tools || []).join('、'))}>
          可调用 {String((cfg.tools || []).length)} 个数据查询工具
        </span>
        <button className="btn" onClick={() => setShowCfg(!showCfg)} title="配置 AI 模型">⚙ 设置</button>
      </div>

      <div className="ai-msgs" ref={box}>
        {msgs.length === 0 && (
          <div className="card">
            <h4>NetEye AI 分析助手</h4>
            <div style={{ fontSize: 12, color: 'var(--dim)', lineHeight: 1.75 }}>
              基于<b>真实抓包数据</b>回答：流量构成、异常定位、端口画像、会话还原、趋势判断。
              所有结论都经工具查询取数，不凭空编造；支持语音输入。
            </div>
            <div className="snap">
              {snap ? (
                <>
                  <div className="snap-row">
                    <span><b>{snap.packets}</b> 个报文</span>
                    <span><b>{humanBytes(snap.bytes)}</b></span>
                    <span>时长 <b>{snap.duration}s</b></span>
                    <span>TCP 流 <b>{snap.tcp_streams}</b></span>
                    <span>重传 <b>{snap.retransmissions}</b></span>
                    <span>专家信息 <b>{snap.expert_count}</b></span>
                  </div>
                  <div className="snap-row">
                    协议分布：{protoTop || '—'}
                  </div>
                  {anoms.length > 0 && (
                    <div className="snap-anom">
                      {anoms.slice(0, 3).map((a: any, i: number) => (
                        <div key={i}>· [{a.level}] {a.type}</div>
                      ))}
                    </div>
                  )}
                </>
              ) : (
                <div className="snap-row">尚无抓包数据：先点顶部「开始」抓包，或用「导入」载入 pcap 文件。</div>
              )}
            </div>
            <button className="btn primary" style={{ marginTop: 8, width: '100%' }}
              onClick={() => send('给我一份这次抓包的结论摘要，指出异常与风险')} disabled={busy}>
              ⚡ 一键分析当前抓包
            </button>
          </div>
        )}
        {msgs.map((m, i) => (
          <div key={i} className={'msg ' + m.role}>{m.text || (busy && i === msgs.length - 1 ? '思考中…' : '')}</div>
        ))}
      </div>

      <div className="quick">
        {QUICK.map(q => <button key={q} onClick={() => send(q)} disabled={busy}>{q}</button>)}
      </div>

      <div className="ai-input">
        <textarea value={input} placeholder="问点什么，例如：443 端口的流量主要来自哪里？"
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(input) } }} />
        <VoiceButton onText={t => setInput(v => (v ? v + t : t))} />
        <button className="btn primary" style={{ height: 38 }} onClick={() => send(input)} disabled={busy}>
          {busy ? '…' : '发送'}
        </button>
        <button className="btn" style={{ height: 38 }} onClick={() => setShowCfg(!showCfg)} title="AI 设置">⚙</button>
      </div>

      {showCfg && (
        <div className="cfg">
          <div style={{ display: 'flex', gap: 6 }}>
            <select value={cfg.provider || 'deepseek'} onChange={e => {
              const p = e.target.value
              const preset = (cfg.presets || {})[p] || {}
              setCfg({ ...cfg, provider: p, base_url: preset.base_url || cfg.base_url, model: preset.model || cfg.model })
            }} style={{ background: '#0f141b', border: '1px solid var(--line)', borderRadius: 5, padding: '5px 8px' }}>
              <option value="deepseek">DeepSeek</option>
              <option value="openai">OpenAI</option>
              <option value="custom">自定义（OpenAI 兼容）</option>
              <option value="ollama">本地 Ollama</option>
            </select>
            <input style={{ flex: 1 }} value={cfg.base_url || ''} placeholder="Base URL"
              onChange={e => setCfg({ ...cfg, base_url: e.target.value })} />
          </div>
          <input value={cfg.model || ''} placeholder="模型名，如 deepseek-chat"
            onChange={e => setCfg({ ...cfg, model: e.target.value })} />
          <input type="password" value={cfg.api_key || ''} placeholder="API Key（留空表示不修改）"
            onChange={e => setCfg({ ...cfg, api_key: e.target.value })} />
          <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
            <button className="btn" onClick={saveCfg}>保存配置</button>
            <button className="btn" onClick={async () => {
              const r = await api.post<any>('/api/ai/test', {})
              setTestMsg(r.ok ? `✅ 连通：${r.model || ''} ${r.reply || ''}` : '❌ ' + (r.error || '失败'))
            }}>测试连接</button>
            <button className="btn" onClick={async () => { await api.del('/api/ai/history'); setMsgs([]) }}>清空对话</button>
            {testMsg && <span className="hint">{testMsg}</span>}
          </div>
          <div className="hint">可用工具：{String((cfg.tools || []).join('、'))}</div>
        </div>
      )}
    </div>
  )
}

function humanBytes(n: any) {
  const v = Number(n || 0)
  if (v >= 1 << 30) return (v / (1 << 30)).toFixed(2) + ' GB'
  if (v >= 1 << 20) return (v / (1 << 20)).toFixed(2) + ' MB'
  if (v >= 1 << 10) return (v / (1 << 10)).toFixed(1) + ' KB'
  return v + ' B'
}

function VoiceButton({ onText }: { onText: (t: string) => void }) {
  const [rec, setRec] = useState(false)
  const ref = useRef<any>(null)

  const toggle = () => {
    const SR = (window as any).webkitSpeechRecognition || (window as any).SpeechRecognition
    if (!SR) { alert('当前浏览器不支持语音识别，请使用 Edge 或 Chrome'); return }
    if (rec) { ref.current?.stop(); setRec(false); return }
    const r = new SR()
    r.lang = 'zh-CN'
    r.interimResults = true
    r.continuous = false
    let final = ''
    r.onresult = (e: any) => {
      let interim = ''
      for (let i = e.resultIndex; i < e.results.length; i++) {
        const t = e.results[i][0].transcript
        if (e.results[i].isFinal) final += t; else interim = t
      }
      onText(final + interim)
    }
    r.onend = () => setRec(false)
    r.onerror = () => setRec(false)
    ref.current = r
    r.start()
    setRec(true)
  }

  return (
    <button className={'mic' + (rec ? ' rec' : '')} onClick={toggle} title="语音输入（Edge/Chrome）">
      {rec ? '●' : '🎤'}
    </button>
  )
}
