# NetEye · 网络端口监控与协议分析平台

参考 Wireshark 打造的网络抓包与分析工具，覆盖其核心能力 80% 以上，并内置 **AI 对话分析**（支持语音输入）。
后端 FastAPI + 自研协议解析引擎，前端 React + ECharts，数据落地 SQLite + pcap。

---

## 一、快速开始

```bat
:: 1. 首次安装（装依赖 + 构建前端 + 安装内置 Npcap，默认勾选）
install.bat

:: 2. 启动（自动请求管理员权限，抓包必需）
启动NetEye.bat
```

浏览器会自动打开 <http://127.0.0.1:8765>。

> 安装/启动脚本本身不依赖 PATH 里有没有 `python` / `npm`：它会自动扫描
> `.venv`、`~/.workbuddy`、官方安装目录、`py` 启动器和注册表。找不到时给出明确指引。

### 安装 / 启动出问题怎么办

先跑一次环境体检，它会列清楚每一项的状态：

```bat
tools\neteye.py doctor
```

| 现象 | 原因与处理 |
|---|---|
| 提示"没有找到 Python 3.10 及以上" | 已装但不在 PATH。先 `set NETEYE_PYTHON=C://完整路径//python.exe` 再双击 `install.bat`；或直接 `python tools\neteye.py install --python C://路径//python.exe` |
| 依赖下载失败 | 脚本会自动重试 3 次并切清华镜像；仍失败可手动 `python tools\neteye.py install --mirror https://pypi.tuna.tsinghua.edu.cn/simple` |
| 找不到 npm | 前端界面不可用，后端与 API 仍可跑。装 Node.js 18+ 后重跑 `install.bat` |
| 提示项目在 OneDrive 里 | OneDrive 同步会锁文件/回滚改动，是随机失败的常见原因，建议迁到 `D://Projects//NetEye` 后重装 |
| 端口 8765 被占用 | 已在运行则会直接打开浏览器；被其它程序占用时换端口：`python tools\neteye.py start --port 8766` |


### 抓包权限说明

| 引擎 | 依赖 | 能力 |
|---|---|---|
| **Npcap 主引擎**（推荐） | 安装 [Npcap](https://npcap.com/#download)，勾选 *WinPcap API-compatible Mode* | 全功能：以太网帧、ARP、混杂模式、BPF 过滤器 |
| **Raw socket 降级引擎** | 仅需管理员权限 | 可抓本机 IPv4 收发，无以太网头、无混杂模式、抓不到 ARP |

软件启动时会自动探测，两个引擎都不可用时界面会提示原因（当前终端若未以管理员运行，会显示"需管理员"）。

> ✅ **Npcap 1.89 已在本机验证通过**（2026-09-17）：实时抓包 223 秒 / 67618 包 / 22.2 MB，
> 丢帧率为 0。详见 `docs/02_交付说明与验证记录.md` 的 v0.1.1 附录。

### 没有 Npcap 也能用

「导入」按钮可加载 `data/captures/*.pcap`，或直接输入任意 pcap 路径做离线分析；
`server/tools/gen_sample_pcap.py` 可生成一份演示数据：

```bash
python server/tools/gen_sample_pcap.py
```

---

## 二、功能清单（对照 Wireshark）

图例：✅ 已实现　🟡 部分实现（子集）　⬜ 规划中

### 捕获
| 功能 | 状态 |
|---|---|
| 网卡枚举与选择（含 IP/MAC/状态） | ✅ |
| 开始 / 暂停 / 继续 / 停止 / 清空 | ✅ |
| 混杂模式开关 | ✅ |
| BPF 捕获过滤器（`tcp port 80`、`host x`） | ✅ |
| 快照长度（snaplen） | ✅ |
| 环形缓冲上限（防内存膨胀） | ✅ |
| 多网卡同时捕获 | ⬜ |
| 按时间/大小自动分片保存 | ⬜ |

### 解析
| 功能 | 状态 |
|---|---|
| 包列表（序号/时间/源/目的/协议/长度/Info） | ✅ |
| **Wireshark 式嵌套协议树**（每层可折叠、字段名用官方显示过滤器名） | ✅ |
| **字段 → 字节联动**（点字段高亮对应字节，点字节反查字段） | ✅ 字节级 |
| **字段含义说明栏**（对齐 Wireshark 状态栏，中文解释） | ✅ |
| Eth / VLAN / ARP / IPv4 / IPv6 / ICMP / ICMPv6 / TCP / UDP | ✅ 全字段含偏移 |
| IPv4 首部校验和实算（Good/Bad） | ✅ |
| TCP 选项逐条展开（MSS / Window Scale / SACK / Timestamps / NOP） | ✅ |
| TCP 标志位逐位展开（NS…FIN）+ **[TCP Analysis Flags]** | ✅ 重传/乱序/缺口/保活/零窗口/RST |
| DNS 完整解析（Flags 逐位 + Questions + Answer/Authority RR，支持压缩指针） | ✅ A/AAAA/CNAME/NS/PTR/MX/TXT/SRV |
| HTTP 请求/响应行 + 逐头部字段（含偏移） | ✅ |
| TLS 记录层 + 握手 + 扩展（SNI / ALPN / supported_versions / 加密套件 / key_share） | ✅ |
| **DoIP（ISO 13400）/ SOME/IP（汽车电子）** | ✅ 含 SA/TA、服务与方法、返回码 |
| 显示过滤器（`==` `!=` `>` `<` `&&` `\|\|` `!` `contains` `~` CIDR） | ✅ |
| 跟踪 TCP/UDP 流（Follow Stream） | ✅ |
| 着色规则自定义 | 🟡 内置配色，暂不可自定义 |
| 协议解码插件机制 | ⬜ |

### 曲线与可视化
| 功能 | 状态 |
|---|---|
| 实时吞吐曲线（包数 / 比特率，双 Y 轴，时间桶 100ms–10s） | ✅ |
| IO Graph 多序列（叠加"过滤后"曲线） | 🟡 2 条 |
| 协议分布条形图 | ✅ |
| Top 会话 / 端点柱状图 | ✅ 表格形式 |
| RTT 分布、端口热力图 | ⬜ |

### 端口状态
| 功能 | 状态 |
|---|---|
| 本机监听端口表（协议 / 地址 / 状态 / PID / 进程名） | ✅ |
| 本机连接总览（监听数、已建立、进程 Top） | ✅ |
| 抓包层端口流量画像（包数/字节/流数/对端/识别服务） | ✅ |
| 端口异常标记（SYN 无响应、RST、扫描、零窗口） | ✅ |
| 单端口连接生命周期时间线 | ⬜ |

### 存储
| 功能 | 状态 |
|---|---|
| 保存为 pcap（全部 / 过滤后 / 选中，自研无依赖 writer） | ✅ |
| 离线打开 pcap | ✅ |
| 会话存档（SQLite 索引 + 备注 + 历史列表） | ✅ |
| 导出 CSV / JSON / pcap | ✅ |
| 配置持久化（AI 配置、捕获默认值） | ✅ |
| Streaming 边抓边写 pcap | ✅ |

### 分析统计
| 功能 | 状态 |
|---|---|
| **概览 KPI 卡片**（报文/字节/时长/吞吐/TCP 流/链路重传率/乱序·缺口） | ✅ |
| 协议分级统计（包数/字节/占比/包秒/bps） | ✅ |
| 会话统计（按字节排序，含重传数） | ✅ |
| 端点统计（收发分别计数） | ✅ |
| 端口流量画像（TCP/UDP/流数/对端/识别服务） | ✅ |
| **IO 分桶表**（逐秒包数/字节/bps） | ✅ |
| **专家信息表**（级别/类型/说明/可点击跳转报文/时间） | ✅ |
| **异常检测卡片**（重传率、扫描、DNS 失败、HTTP 错误、广播风暴、流量集中度） | ✅ |
| 表内搜索 + 导出 CSV | ✅ |
| 定时快照对比 | ⬜ |

### AI 分析
| 功能 | 状态 |
|---|---|
| 对话窗（流式输出、Markdown 结构） | ✅ |
| **数据快照首屏**（未配置模型也能看到当前抓包概览与异常） | ✅ |
| **一键分析当前抓包**（免配置出结论摘要） | ✅ |
| **引擎状态条**（显示走大模型还是本地规则引擎 + 可用工具数） | ✅ |
| Function Calling 工具集（10 个工具，AI 只能查真实数据） | ✅ |
| 语音输入（浏览器 Web Speech API，中文） | ✅ |
| 自动上下文注入（当前捕获摘要 + 选中包） | ✅ |
| 快捷问题（异常/会话/端口/重传/DNS/摘要） | ✅ |
| 未配置 Key 时的本地规则兜底 | ✅ |
| 结论一键跳转对应包 | ✅ 专家信息 / 异常卡片可点 |
| 会话历史持久化 | ✅ |

**AI 可用工具**：`get_capture_summary` `query_packets` `get_packet_detail` `get_statistics`
`get_expert_info` `get_io_series` `analyze_port` `follow_stream` `detect_anomaly` `export_result`

---

## 三、AI 配置

侧栏「AI 分析」→ 齿轮图标：

| 项 | 说明 |
|---|---|
| 供应商 | DeepSeek（默认）/ OpenAI / 自定义 OpenAI 兼容 / 本地 Ollama |
| Base URL | DeepSeek：`https://api.deepseek.com`；OpenAI：`https://api.openai.com/v1` |
| 模型 | `deepseek-chat` / `gpt-4o-mini` / `qwen2.5:7b` 等 |
| API Key | 只存本地 `data/settings.json`，接口返回时打码 |

填好后点「测试连接」验证。**未填 Key 时自动切换到本地规则引擎**，仍能基于真实数据回答问题。

---

## 四、目录结构

```
NetEye/
  tools/                 neteye.py(安装/启动/体检) + find_python.bat(引导层)
├─ 启动NetEye.bat / install.bat     一键启动与安装
├─ server/                          Python 后端
│  ├─ app/
│  │  ├─ main.py                    FastAPI 入口 + 前端静态托管
│  │  ├─ capture/                   base / scapy_engine(Npcap) / raw_engine(降级) / manager
│  │  ├─ parser/dissect.py          手写 L2–L4 快速解析 + scapy 深度解析
│  │  ├─ filters/display_filter.py  显示过滤器（词法+递归下降+求值）
│  │  ├─ stats/                     aggregator(统计/专家/异常) / portstate(本机端口)
│  │  ├─ storage/                   db(SQLite) / pcapio(自研 pcap 读写)
│  │  ├─ ai/                        client(OpenAI 兼容+工具循环) / tools / local_brain
│  │  └─ api/                       capture / analysis / ai / ws
│  ├─ tests/smoke_test.py           38 项核心自测
│  └─ tools/gen_sample_pcap.py      演示数据生成
├─ web/                             React + Vite + TS 前端
│  └─ src/components/               Toolbar PacketList PacketDetail IOChart
│                                   StatsPanel PortPanel ExpertPanel AIChat ImportPanel
└─ data/                            neteye.db / settings.json / captures/*.pcap
```

## 五、性能设计

- 抓包线程**零 scapy 开销**：L2–L4 手写解析，应用层按需识别；协议树与十六进制只在点开报文时生成。
- 客户端虚拟滚动：只渲染视口内约 30 行，20 万报文依然流畅。
- WebSocket 以 250ms 批量推送新包 + 统计，避免逐包渲染抖动。
- SQLite 使用 WAL 模式，保存会话时批量写入。

## 六、已知限制

1. Windows 下抓包**必须管理员权限**；无语义化"非管理员也能抓包"的方案。
2. 未安装 Npcap 时降级引擎抓不到 ARP 与非 IP 帧，且不支持真正的混杂模式。
3. TLS 仅解析握手元数据（版本、SNI、证书类型），不解析加密载荷（与 Wireshark 一致）。
4. HTTP 仅解析 HTTP/1.x 明文，不支持 HTTP/2 帧与 gzip 解压。
5. pcapng 格式（Wireshark 默认新格式）暂不支持导入，请另存为 pcap。

## 七、自测

```bash
# 核心自测：解析 / 过滤 / 统计 / pcap 往返（38 项，离线）
python server/tests/smoke_test.py

# 协议树深度解析：合成 11 类协议样本，校验结构 / 字段语义 / 偏移边界（1572 项，离线）
python server/tests/tree_test.py

# 端到端链路：需服务已在跑，覆盖导入→查询→统计→过滤→实时抓包→导出回读→会话→AI（70 项）
python server/tests/e2e_test.py

# 真机深度解析：抓真实流量校验协议树质量与 SNI/TCP 分析标记（需管理员 + Npcap）
python server/tests/live_tree_check.py 15 1200

# 前端 UI：真实浏览器渲染、协议树交互、字段联动、统计与 AI 面板（45 项，需 playwright）
python server/tests/ui_check.py

# 交付截图（可选）：导入指定 pcap，截协议树/统计/AI 面板
python server/tests/capture_shots.py "<pcap 路径>"
```

最近一次全量结果：`smoke 38/38`、`tree 1572/1572`、`e2e 70/70`、`live_tree 9/9`、`ui 45/45`（2026-09-19，Python 3.14 + Npcap 1.89）。

## 八、界面截图

| 文件 | 内容 |
|---|---|
| `docs/screenshots/ui_10_tls_sni.png` | TLS ClientHello 协议树：密钥套件列表 + SNI（`vas.wps.cn`）字段高亮联动 hex |
| `docs/screenshots/ui_11_tcp_flags.png` | `[TCP Analysis Flags]`：TCP Retransmission 判定与间隔说明 |
| `docs/screenshots/ui_12_stats.png` | 统计面板：KPI 概览卡片 + 7 张分析表 + 搜索/导出 |
| `docs/screenshots/ui_13_ai.png` | AI 面板：引擎状态条 + 数据快照 + 一键分析 + 语音输入 |
| `docs/screenshots/ui_02_capturing.png` | 实时抓包中的主界面 |

