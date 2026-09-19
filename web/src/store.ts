import { create } from 'zustand'
import { api, InterfaceInfo, PacketDetail, PacketSummary } from './lib/api'

export type TabKey = 'io' | 'stats' | 'ports' | 'expert' | 'ai'

interface State {
  // 捕获
  interfaces: InterfaceInfo[]
  engines: any
  iface: string
  bpf: string
  promisc: boolean
  engine: string
  state: string
  error: string
  live: any
  // 数据
  packets: PacketSummary[]
  total: number
  filter: string
  filterError: string
  loading: boolean
  autoScroll: boolean
  selected: number | null
  detail: PacketDetail | null
  wsOn: boolean
  // 动作
  init(): Promise<void>
  setFilter(f: string): Promise<void>
  loadPackets(reset?: boolean): Promise<void>
  loadMore(): Promise<void>
  select(id: number | null): Promise<void>
  start(): Promise<void>
  stop(): Promise<void>
  pause(): Promise<void>
  resume(): Promise<void>
  clear(): Promise<void>
  saveSession(): Promise<void>
  connectWS(): void
  set<K extends keyof State>(k: K, v: State[K]): void
}

const PAGE = 300

export const useStore = create<State>((set, get) => ({
  interfaces: [], engines: null, iface: '', bpf: '', promisc: true, engine: 'auto',
  state: 'idle', error: '', live: null,
  packets: [], total: 0, filter: '', filterError: '', loading: false,
  autoScroll: true, selected: null, detail: null, wsOn: false,

  set: (k, v) => set({ [k]: v } as any),

  async init() {
    try {
      const [ifs, st] = await Promise.all([
        api.get<{ items: InterfaceInfo[]; engines: any }>('/api/interfaces'),
        api.get<any>('/api/capture/status'),
      ])
      // 后端已按可用性排序并标出 recommended，优先用它；
      // 否则退化为"有非链路本地地址的在用网卡"，避免选到 Loopback / WAN Miniport。
      const up = ifs.items.find(i => i.recommended)
        || ifs.items.find(i => i.is_up && i.ip && !i.ip.startsWith('169.254') && !i.ip.startsWith('127.'))
        || ifs.items[0]
      set({ interfaces: ifs.items, engines: ifs.engines, iface: up?.name || '', state: st.state, live: st })
      await get().loadPackets(true)
    } catch (e: any) {
      set({ error: String(e.message || e) })
    }
  },

  async setFilter(f) {
    set({ filter: f })
    const r = await api.get<{ ok: boolean; error: string }>('/api/stats/filter/validate?expr=' + encodeURIComponent(f))
    set({ filterError: r.ok ? '' : (r.error || '语法错误') })
    if (r.ok) await get().loadPackets(true)
  },

  async loadPackets(reset = true) {
    const { filter, packets } = get()
    set({ loading: true })
    try {
      const r = await api.post<{ total: number; items: PacketSummary[] }>('/api/packets/query', {
        filter, offset: 0, limit: reset ? PAGE : packets.length + PAGE,
      })
      set({ packets: r.items, total: r.total, loading: false })
    } catch (e: any) { set({ loading: false, error: e.message }) }
  },

  async loadMore() {
    const { filter, packets, total, loading } = get()
    if (loading || packets.length >= total) return
    set({ loading: true })
    const r = await api.post<{ total: number; items: PacketSummary[] }>('/api/packets/query', {
      filter, offset: packets.length, limit: PAGE,
    })
    set({ packets: [...packets, ...r.items], total: r.total, loading: false })
  },

  async select(id) {
    set({ selected: id, detail: null })
    if (id == null) return
    try {
      const d = await api.get<PacketDetail>(`/api/packets/${id}`)
      set({ detail: d })
    } catch { /* ignore */ }
  },

  async start() {
    const { iface, bpf, promisc, engine } = get()
    const r = await api.post<any>('/api/capture/start', {
      interface: iface, bpf_filter: bpf, promisc, engine, snaplen: 65535, ring_buffer: 100000, save_pcap: false,
    })
    if (!r.ok) { set({ error: r.error || '启动失败' }); return }
    set({ state: 'running', error: '', packets: [], total: 0 })
    const st = await api.get<any>('/api/capture/status')
    set({ live: st })
  },
  async stop() { await api.post('/api/capture/stop'); set({ state: 'stopped' }); await get().loadPackets(true) },
  async pause() { await api.post('/api/capture/pause'); set({ state: 'paused' }) },
  async resume() { await api.post('/api/capture/resume'); set({ state: 'running' }) },
  async clear() { await api.post('/api/capture/clear'); set({ packets: [], total: 0, state: 'idle', detail: null, selected: null }) },
  async saveSession() {
    const r = await api.post<any>('/api/sessions/save', {})
    alert(r.ok ? `已保存会话 ${r.id}（${r.packets} 个包）` : '保存失败')
  },

  connectWS() {
    if (get().wsOn) return
    const proto = location.protocol === 'https:' ? 'wss' : 'ws'
    const ws = new WebSocket(`${proto}://${location.host}/ws`)
    ws.onopen = () => set({ wsOn: true })
    ws.onclose = () => { set({ wsOn: false }); setTimeout(() => get().connectWS(), 2000) }
    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data)
        if (msg.type === 'packets' && msg.data?.length) {
          const { packets, total, autoScroll } = get()
          const merged = [...packets, ...msg.data].slice(-20000)
          set({ packets: merged, total: (total || 0) + msg.data.length, live: msg.stats })
          if (autoScroll) {
            requestAnimationFrame(() => {
              const el = document.getElementById('pkt-scroll')
              if (el) el.scrollTop = el.scrollHeight
            })
          }
        } else if (msg.type === 'stats') {
          set({ live: msg.data })
        }
      } catch { /* ignore */ }
    }
  },
}))
