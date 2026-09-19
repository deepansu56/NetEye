import React, { useEffect, useMemo, useRef, useState } from 'react'
import { useStore } from '../store'

/**
 * 报文详情面板（对齐 Wireshark 的 Packet Details + Packet Bytes）。
 *
 * - 左侧：可折叠的嵌套协议树，每层显示协议摘要，字段显示「名称: 值」
 * - 右侧：十六进制 + ASCII，选中字段时高亮对应字节，点击字节可反查字段
 * - 底部：当前字段的完整显示过滤器名与含义说明
 */
export default function PacketDetail() {
  const detail = useStore(s => s.detail)
  const selected = useStore(s => s.selected)
  const [view, setView] = useState<'tree' | 'hex' | 'both'>('both')
  const [field, setField] = useState<any | null>(null)
  const [bytePos, setBytePos] = useState<number | null>(null)
  const treeRef = useRef<HTMLDivElement>(null)

  useEffect(() => { setField(null); setBytePos(null) }, [selected])

  // 高亮区间：优先字段偏移，其次手动点击的字节
  const hl = useMemo(() => {
    if (field && field.offset >= 0 && field.size > 0) {
      return { offset: field.offset, size: field.size }
    }
    if (bytePos != null) return { offset: bytePos, size: 1 }
    return null
  }, [field, bytePos])

  const lines = useMemo(() => (detail?.hex || '').split('\n').filter(Boolean), [detail])

  // 点击 hex 字节 → 反查所属字段（后出现的层优先，取最内层协议）
  const pickByte = (pos: number) => {
    setBytePos(pos)
    const found = findField(detail?.layers || [], pos)
    if (found) setField(found)
  }

  const layerName = (n: string) => n.replace(/_tree$/, '')

  return (
    <div className="detail">
      <div className="detail-tabs">
        <div className={'tab' + (view === 'tree' ? ' on' : '')} onClick={() => setView('tree')}>协议树</div>
        <div className={'tab' + (view === 'hex' ? ' on' : '')} onClick={() => setView('hex')}>原始数据</div>
        <div className={'tab' + (view === 'both' ? ' on' : '')} onClick={() => setView('both')}>双栏</div>
        {detail && (
          <span className="dinfo">
            #{detail.summary.id} · {detail.summary.src} → {detail.summary.dst} · {detail.summary.proto} · {detail.summary.length} 字节
            {(detail.notes || []).length > 0 && (
              <span className="dnotes" title={(detail.notes || []).map((n: any) => n.text).join('\n')}>
                ⚠ {(detail.notes || []).map((n: any) => n.flag).join(' / ')}
              </span>
            )}
          </span>
        )}
        {detail && (detail.summary.stream ?? 0) > 0 && (
          <button className="btn" style={{ marginLeft: 'auto', padding: '2px 10px', fontSize: 11 }}
            onClick={async () => {
              const r = await fetch(`/api/packets/${detail.id}/stream`).then(r => r.json())
              const w = window.open('', '_blank', 'width=900,height=650')
              if (w) w.document.write(`<pre style="font:12px Consolas;background:#0d1117;color:#d8dee9;padding:14px">` +
                `<h3>流 #${r.stream}（A: ${r.a_len}B / B: ${r.b_len}B）</h3>` +
                `<div style="color:#7ee787">=== 方向 A → B ===</div>${esc(r.a_text)}` +
                `<div style="color:#79c0ff;margin-top:12px">=== 方向 B → A ===</div>${esc(r.b_text)}</pre>`)
            }}>跟踪流</button>
        )}
      </div>

      {!selected && <div className="empty">选中一个报文查看分层详情</div>}
      {selected && !detail && <div className="empty">加载中…</div>}
      {detail && (
        <div className="detail-body">
          {view !== 'hex' && (
            <div className="tree" ref={treeRef} style={{ flex: view === 'both' ? '1 1 55%' : 1 }}>
              {detail.layers.length === 0 && <div className="empty">无解析结果（仅保存了报文头）</div>}
              {detail.layers.map((l, i) => (
                <Node key={i} layer={l} depth={0} field={field} onPick={setField} />
              ))}
            </div>
          )}
          {view !== 'tree' && (
            <div className="hex" style={{ flex: view === 'both' ? '1 1 45%' : 1 }}>
              {lines.map((line, i) => (
                <div key={i} className="hex-line">{renderHexLine(line, i * 16, hl, pickByte)}</div>
              ))}
            </div>
          )}
        </div>
      )}

      {detail && (
        <div className="field-bar">
          {field ? (
            <>
              <span className="fname">{field.name}{field.bits ? `  [${field.bits}]` : ''}</span>
              <span className="fval">{field.value}</span>
              {field.offset >= 0 && <span className="foff">字节 {field.offset}…{field.offset + Math.max(field.size, 0) - 1}</span>}
              {field.desc && <span className="fdesc">{field.desc}</span>}
            </>
          ) : (
            <span className="fdesc">点击任意字段可高亮对应字节；点击右侧字节可反查字段</span>
          )}
        </div>
      )}
    </div>
  )
}

/** 递归节点：一层协议（可展开）+ 其字段 + 子节点 */
function Node({ layer, depth, field, onPick }: {
  layer: any; depth: number; field: any; onPick: (f: any) => void
}) {
  const [open, setOpen] = useState(true)
  const kids: any[] = layer.children || []
  const isFlag = /^\[/.test(layer.title || '')
  return (
    <div className="tnode" style={{ marginLeft: depth ? 14 : 0 }}>
      <div className={'tt' + (isFlag ? ' flag' : '')} onClick={() => setOpen(!open)}>
        <span className="caret">{kids.length || layer.fields.length ? (open ? '▾' : '▸') : '·'}</span>
        <span className="ttext">{layer.title}</span>
        <span className="tproto">{layer.name}</span>
      </div>
      {open && (
        <>
          {layer.fields.map((f: any, i: number) => {
            const on = field && field.offset === f.offset && field.name === f.name && f.name !== undefined
            return (
              <div key={i} className={'tf' + (on ? ' on' : '')} title={f.desc || ''}
                onClick={() => onPick(f)}>
                <span className="fn">{f.label || f.name}</span>
                <span className="fv">{f.value}</span>
                {f.bits && <span className="fb">{f.bits}</span>}
              </div>
            )
          })}
          {kids.map((c, i) => <Node key={i} layer={c} depth={depth + 1} field={field} onPick={onPick} />)}
        </>
      )}
    </div>
  )
}

/** 在协议树里查找覆盖指定字节偏移的字段；取最深（最具体）的一个 */
function findField(layers: any[], pos: number): any | null {
  let best: any = null
  const walk = (nodes: any[]) => {
    for (const l of nodes || []) {
      for (const f of l.fields || []) {
        if (f.offset >= 0 && f.size > 0 && pos >= f.offset && pos < f.offset + f.size) {
          // 越靠后的协议层越具体，同层取更小的字段
          if (!best || f.size <= best.size) best = f
        }
      }
      walk(l.children || [])
    }
  }
  walk(layers)
  return best
}

/** 渲染一行 hex：偏移 + 16 个字节 + ASCII，命中高亮则着色，字节可点击 */
function renderHexLine(line: string, base: number, hl: any, pick: (pos: number) => void) {
  const off = line.slice(0, 8)
  const hexPart = line.slice(10, 57)
  const ascii = line.slice(59)
  const nodes: React.ReactNode[] = [<span key="o" className="off">{off}</span>, <span key="s1">  </span>]
  for (let i = 0; i < 16; i++) {
    const seg = hexPart.slice(i * 3, i * 3 + 3)
    if (!seg.trim()) { nodes.push(<span key={'e' + i}>{'   '}</span>); continue }
    const pos = base + i
    const on = hl && pos >= hl.offset && pos < hl.offset + hl.size
    nodes.push(
      <span key={'h' + i} className={on ? 'hl' : undefined} onClick={() => pick(pos)}>{seg}</span>
    )
  }
  nodes.push(<span key="s2">  </span>)
  for (let i = 0; i < 16 && i < ascii.length; i++) {
    const pos = base + i
    const on = hl && pos >= hl.offset && pos < hl.offset + hl.size
    nodes.push(
      <span key={'a' + i} className={on ? 'hl' : undefined} onClick={() => pick(pos)}>{ascii[i]}</span>
    )
  }
  return nodes
}

function esc(s: string) {
  return (s || '').replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]!))
}
