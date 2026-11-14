# 设计：Telegram 告警、内置主机监控、公开状态页

本文是给实现者的完整设计。需求按阶段实现，每个阶段独立可验收：

1. 阶段一：Telegram 告警（只改面板）
2. 阶段二：把 Komari 的监控后台并入 MUI 面板（面板 + Agent）
3. 阶段二补充：计费续期、流量限额与服务器整理（只改面板）
4. 阶段三：公开状态页（已实施）
5. 阶段四：订阅链接防泄露（**暂不实施**，仅留作记录）

通用约束（三个阶段都适用）：

- 不提交、不推送；每个阶段结束时汇报改动文件、迁移编号、偏离设计之处及原因。
- 每个阶段结束时 `go build ./...`、`go vet ./...`、`go test ./...`、`web` 下 `npx tsc --noEmit` 与 `npm run build` 全部通过。
- 数据库同时支持 SQLite 与 PostgreSQL（生产用 PostgreSQL）。新表、新索引走 `internal/server/store_migrate.go` 追加迁移，不改已有迁移。
- 新的管理接口挂在 `a.require(...)` 之后；500 错误继续走 `errorJSON`（内部细节不回给客户端）。
- 所有密钥（Bot Token 等）用 `Store.Encrypt` 加密存储，接口只返回"是否已设置"，永不回显；不得写入日志、审计、错误信息。
- 新增的任何"来自 Agent 的数据"都要限长、限量、校验数值范围，Agent 被攻破时只能影响它自己那台服务器的展示数据。
- 现有文件已按功能拆分，新增代码放新文件，不要把已有文件再写回到上千行。

---

## 现状（实现前请先读）

- 面板到 Agent 的通道：`internal/server/agent_api.go`。`agentAuth` 校验 Bearer Token + HMAC 签名（`verifyAgentSignature`，含时间戳与一次性 nonce）。Agent 每 5 秒 `GET /agent/job`，每 30 秒 `POST /agent/report`。
- 现有 Komari 对接是"Agent 向**外部** Komari 面板上报"：
  - 面板：`internal/server/komari.go`（全局 endpoint 设置、每台服务器一个加密 token、`GET /agent/komari` 把配置发给 Agent）。
  - Agent：`internal/agent/komari.go`，用 `github.com/komari-monitor/komari-agent` 的 `monitoring` 与 `monitoring/unit` 包采集主机指标，每 3 秒上报一次，另外长轮询拉取 TCP ping 任务。远程终端、命令执行、文件、自更新在 Agent 侧已全部拒绝（`handleEvent` 是白名单）。
  - 前端：`web/src/pages/Settings.tsx`（Komari 地址）、`web/src/forms/ServerDialog.tsx`（Komari token）。
- 已有的"告警"只有证书到期，且只写日志和审计：`internal/server/certificates.go` 的 `CheckExpiringCertificates`。
- 设置存储：`mui_settings(key, value)`。
- 前端是 hash 路由的单页应用（`web/src/app/App.tsx`、`url.ts`、`helpers.ts` 的 `Tab`），构建产物由 nginx 提供，`deploy/nginx/routes.conf` 把 `/api`、`/agent`、`/download`、`/s` 转给后端。

---

## 阶段一：Telegram 告警

### 1.1 设置

存 `mui_settings`，键 `telegram`，值为 JSON；其中 `botTokenEnc` 是 `Store.Encrypt` 的结果。

| 字段 | 说明 |
| --- | --- |
| `enabled` | 总开关 |
| `botToken` | 只写。`PUT` 时：字段缺省 = 保留原值，空字符串 = 清除。`GET` 只返回 `botTokenSet: bool` |
| `chatId` | 必填，形如 `-1001234567890` 或 `123456`；只允许可选的 `-` 加数字，或以 `@` 开头的频道名（`@[A-Za-z0-9_]{5,32}`） |
| `threadId` | 可选，话题群的 message_thread_id，正整数 |
| `apiBase` | 可选，默认 `https://api.telegram.org`。必须是 https、无 userinfo、无 query、无 fragment（复用 `validateKomariEndpoint` 的校验思路，但不允许 http） |
| `events` | 各类事件的开关与阈值，见 1.2 |

接口：

- `GET /api/settings/telegram`
- `PUT /api/settings/telegram`
- `POST /api/settings/telegram/test`：用**已保存**的配置发一条测试消息，返回成功或失败原因（失败原因只给 Telegram 返回的 `description` 或"连接失败"，不得包含 URL）。

修改设置写审计（`settings.telegram`），审计内容不含 token。

### 1.2 事件

| 事件键 | 触发条件 | 恢复通知 | 默认 |
| --- | --- | --- | --- |
| `serverOffline` | 在线管理的服务器超过 `offlineMinutes`（默认 3，范围 2–60）没有上报 | 恢复上报后发一条"已恢复，离线了 N 分钟" | 开 |
| `applyFailed` | 任一 `*.apply`、`agent.upgrade`、`core.upgrade`、`ufw.*` 操作以 `failed` 结束 | 无 | 开 |
| `certExpiring` | 证书 `shared.CertExpiryStatus` 判定为即将到期；每张证书每个到期日只提醒 3 次（进入阈值时、剩 3 天、剩 1 天） | 无 | 开 |
| `subscriptionExpiring` | 启用中的订阅距 `ExpiresAt` 不足 3 天提醒一次，到期时再提醒一次 | 无 | 关 |
| `serverExpiring` | 服务器的"到期日"（阶段二新增字段）不足 7 天、3 天、1 天时各提醒一次 | 无 | 开（阶段二生效） |
| `resource` | CPU、内存、磁盘使用率连续 `minutes`（默认 5）分钟高于阈值（默认 90%）；三项各自独立 | 回落到阈值以下并持续同样时长后发恢复 | 关（阶段二生效） |
| `security` | 管理员登录成功、密码修改、TOTP 关闭、TOTP 被锁定、`MUI_ADMIN_RESET` 生效 | 无 | 开 |

`serverExpiring`、`resource` 的数据来自阶段二；阶段一先把开关、阈值、状态机和消息模板写好，评估函数在没有数据时直接跳过，并在代码里留下清晰的接入点。

不告警的情况：

- 离线管理（`OfflineManaged`）、外部节点（`ExternalManaged`）、已吊销、从未接入过（`LastSeen == nil`）的服务器不参与 `serverOffline`。
- 面板自身启动后的前 `offlineMinutes + 1` 分钟不发 `serverOffline`（面板重启期间 Agent 无法上报，不能把自己的停机算成对方离线）。
- 面板发起的 `agent.upgrade` 处于 `running` / `activating` 期间，该服务器不发 `serverOffline`。

### 1.3 实现

新文件 `internal/server/alerts.go`（评估与状态机）、`internal/server/telegram.go`（发送）。

状态表（新迁移）：

```
mui_alert_state(
  key TEXT PRIMARY KEY,        -- 例如 "serverOffline:<serverID>"、"certExpiring:<certID>:<到期日>:3"
  status TEXT NOT NULL,        -- "firing" | "resolved" | "sent"
  since_ms BIGINT NOT NULL,
  updated_ms BIGINT NOT NULL
)
```

- 评估循环：`cmd/server/main.go` 起一个每 30 秒一次的协程，调用 `app.EvaluateAlerts()`。它只读数据库和内存状态，**不得持有 `a.mu` 或任何 `lockServer`**。
- 事件型告警（`applyFailed`、`security`）在事件发生处调用 `app.notify(event, key, text)`，该函数只做非阻塞入队；不得在持锁的请求处理路径里直接发 HTTP。
- 状态型告警（离线、资源）用 `mui_alert_state` 去重：只有状态翻转时发送；面板重启后从表里恢复状态，不重复告警。
- 状态表跟随服务器/证书/订阅删除一并清理；另在 6 小时清理循环里删除 `updated_ms` 早于保留期的 `resolved` / `sent` 行。

发送器：

- 一个带缓冲的队列（容量 200，满了丢最旧的并计数）加一个发送协程。
- 调用 `POST {apiBase}/bot{token}/sendMessage`，JSON 体：`chat_id`、`text`、可选 `message_thread_id`、`disable_web_page_preview: true`。**不设置 `parse_mode`**：服务器名、错误信息等都是不可信文本，纯文本发送就不存在标记注入。
- `http.Client` 超时 10 秒，响应体最多读 64 KiB。
- 失败重试 3 次（2s、10s、30s）；HTTP 429 按返回的 `retry_after` 等待（上限 60 秒）。
- 限速：每分钟最多 20 条；超出时把队列里同一事件类型的消息合并成一条"另有 N 条同类告警"。
- `net/http` 的错误会带完整 URL（含 token），所有日志和返回值都必须先替换成固定文案（参考 `internal/agent/komari.go` 里 `post` 的处理方式）。
- 单条消息超过 3500 个字符时截断（按 rune，不切断多字节字符）。

消息格式（纯文本，中文）：

```
[MUI] 服务器离线
服务器：tokyo-1（JP · 东京）
最后上报：2026-11-14 10:21:05
已离线：3 分钟
```

消息里不出现：IP 地址以外的任何凭据、订阅链接、节点密码、token。`applyFailed` 带上操作类型和 `op.Error`（截断到 500 字符）。

### 1.4 前端

`web/src/pages/Settings.tsx` 增加"Telegram 告警"卡片：开关、Bot Token（密码框，占位符显示"已设置"）、Chat ID、话题 ID、API 地址、各事件开关与阈值、"发送测试消息"按钮（未保存的修改要先提示保存）。

### 1.5 测试

用 `httptest.Server` 充当 Telegram（通过 `apiBase` 指过去，测试里放开 https 限制要用包级变量，不要给生产代码加后门参数）。至少覆盖：

- 离线 → 告警一次 → 持续离线不重复 → 恢复 → 恢复通知一次。
- 面板启动宽限期内不告警；升级中的服务器不告警。
- `GET` 不返回 token；`PUT` 省略 token 时保留原值；日志与错误信息不含 token。
- 429 与失败重试；限速合并。
- 证书同一到期日最多三次提醒。

---

## 阶段二：内置主机监控（并入 Komari 后台）

目标：主机指标直接上报给 MUI 面板并存在 MUI 的数据库里，不再需要单独部署 Komari。

### 2.1 保留与删除

保留（Komari 后台里有用的部分）：

- 主机基础信息：CPU 型号与核数、架构、系统与内核、虚拟化类型、内存/交换/磁盘总量。
- 实时指标：CPU 使用率、内存、交换、磁盘、1/5/15 分钟负载、上下行速率、累计流量、TCP/UDP 连接数、进程数、开机时长。
- 历史记录与图表。
- TCP 延迟监测任务（ping 任务）。
- 服务器的到期日与备注（用于展示和到期告警）。

删除（不实现，Agent 侧也不保留任何入口）：

- 远程终端、远程命令/脚本任务、文件管理、剪贴板。
- 由监控后台下发的 Agent 自更新（MUI 有自己签名校验的升级流程）。
- ICMP 与 HTTP ping（只保留 TCP；ICMP 需要额外权限，HTTP 是 SSRF 面）。
- OAuth/多用户登录、主题商店、自定义 CSS/JS 注入、自定义页头页脚 HTML。
- GPU 明细监控。
- **向外部 Komari 面板上报**（现有功能）：整套移除，见 2.6。

### 2.2 Agent

新文件 `internal/agent/monitor.go`，替代 `komari.go` 的采集部分。继续使用已在依赖里的 `github.com/komari-monitor/komari-agent/monitoring/unit` 采集，不引入新依赖；不要调用 `monitoring.GenerateReport()`（它产出的是 Komari 的线格式），直接用 `unit.*` 填 MUI 自己的结构。

- 每 5 秒采样一次并 `POST /agent/monitor`（签名方式与其它 Agent 请求相同，复用 `sendJSON`）。
- 每 10 分钟（以及启动后第一次）在同一个请求里附带基础信息 `host`。
- 请求失败不重发、不积压：监控样本丢了就丢了。连续失败时退避到 30 秒一次。
- 该循环与任务轮询、`/agent/report` 完全独立，监控出问题不能影响配置下发。
- 响应里带回本机要执行的 ping 任务列表（见 2.4），Agent 按各任务间隔执行，结果随下一次 `/agent/monitor` 提交。TCP ping 的目标校验沿用 `resolveKomariTCPTarget` / `allowedKomariPingIP` 的逻辑（只允许公网地址；一次解析、逐个检查、只拨检查过的字面 IP），把这两个函数挪到新文件并改名，测试一并迁移。
- 能力标记：`shared.AgentReport` 增加 `HostMonitor bool`（`hostStatus()` 里置 true），面板存到 `Server.HostMonitor`，前端据此显示"需升级 Agent 才有监控数据"。

线格式（`internal/shared/types.go`）：

```go
type MonitorSample struct {
    At          time.Time `json:"at"`
    CPU         float64   `json:"cpu"`        // 0–100
    Load1, Load5, Load15 float64
    RAMUsed, RAMTotal, SwapUsed, SwapTotal, DiskUsed, DiskTotal int64
    NetUp, NetDown   int64 // 字节/秒
    NetTotalUp, NetTotalDown int64
    TCP, UDP, Process int
    Uptime      int64     // 秒
}
type MonitorHost struct {
    CPUName string; CPUCores, CPUPhysicalCores int
    Arch, OS, Kernel, Virtualization string
    MemTotal, SwapTotal, DiskTotal int64
}
type PingTask struct { ID string; Target string; IntervalSeconds int }
type PingResult struct { TaskID string; At time.Time; Ms int } // Ms = -1 表示失败
type MonitorRequest struct { Sample MonitorSample; Host *MonitorHost; Pings []PingResult }
type MonitorResponse struct { Pings []PingTask }
```

（字段的 json 名用小驼峰，与现有类型一致。）

### 2.3 面板：接收与存储

新文件 `internal/server/monitor.go`、`internal/server/store_monitor.go`。

`POST /agent/monitor`（挂 `a.agentAuth`）：

- **不取 `lockServer`，不读写 `mui_servers` 的整份文档**，否则每 5 秒一次会和 `/agent/report`、管理端编辑抢锁。只有带 `host` 的那次请求（10 分钟一次）才更新主机信息，且写到单独的表里。
- 校验并钳制：百分比 0–100；字节数、计数非负且不超过合理上限（例如 2^53）；`NaN`/`Inf` 丢弃整条；字符串字段各限 128 字节；`pings` 最多 64 条，且 `taskId` 必须是分配给这台服务器的任务。
- 最新样本放内存：`App` 上一个 `map[serverID]latestSample` 加读写锁，条目随服务器删除而清理；进程重启后为空，等下一次上报填充。
- 分钟聚合：内存里按 `(serverID, 分钟)` 累加，分钟切换时写一行（CPU、负载、内存、连接数取平均；速率取平均并记录峰值；累计流量取最后值）。

表（新迁移）：

```
mui_monitor_hosts(server_id TEXT PRIMARY KEY, data TEXT NOT NULL, updated_ms BIGINT NOT NULL)
mui_monitor_minutes(server_id TEXT, at_ms BIGINT, cpu REAL, load1 REAL, ram_used BIGINT, ram_total BIGINT,
  swap_used BIGINT, disk_used BIGINT, disk_total BIGINT, net_up BIGINT, net_down BIGINT,
  net_up_peak BIGINT, net_down_peak BIGINT, total_up BIGINT, total_down BIGINT,
  tcp INTEGER, udp INTEGER, process INTEGER, PRIMARY KEY(server_id, at_ms))
mui_monitor_hours(同上列, PRIMARY KEY(server_id, at_ms))
mui_ping_tasks(id TEXT PRIMARY KEY, data TEXT NOT NULL)
mui_ping_minutes(task_id TEXT, server_id TEXT, at_ms BIGINT, ms_avg INTEGER, ms_max INTEGER,
  sent INTEGER, lost INTEGER, PRIMARY KEY(task_id, server_id, at_ms))
```

另外各建一个 `(at_ms)` 索引供清理使用。

保留策略（并入 `main.go` 现有的 6 小时清理循环，再加一个每小时一次的汇总任务）：

- 分钟表保留 3 天。
- 每小时把上一个完整小时的分钟行汇总进小时表（幂等，`ON CONFLICT DO UPDATE`）；小时表保留期与 `MUI_TRAFFIC_RETENTION_DAYS` 一致。
- ping 分钟表保留 7 天。
- 删除服务器（`purgeServer`）时一并删除它在这些表里的数据；删除 ping 任务时删除它的记录。

管理接口：

- `GET /api/monitor`：全部服务器的 `{serverId, online, sample?, host?}`，直接读内存与 `mui_monitor_hosts`。
- `GET /api/monitor/{serverId}/records?range=1h|6h|24h|7d|30d`：≤24h 读分钟表，更长读小时表；返回点数上限 1500。
- `GET/POST /api/ping-tasks`、`PATCH/DELETE /api/ping-tasks/{id}`：任务字段 `name`、`target`（`host:port`，创建时用与 Agent 相同的规则校验，字面私网地址直接拒绝）、`intervalSeconds`（30–3600，默认 60）、`serverIds`（空 = 全部支持监控的服务器）。最多 32 个任务。
- `GET /api/ping-tasks/{id}/records?serverId=&range=`。

### 2.4 服务器档案新增字段

`shared.Server` 增加（管理端可编辑，`serverByID` 的白名单拷贝里要加上）：

- `ExpiresAt *time.Time`：服务器到期日，用于展示和 `serverExpiring` 告警。
- `PublicNote string`：公开备注（阶段三展示），限 200 字符。
- `PublicVisible bool`、`PublicName string`：阶段三用，阶段二先加字段和表单。

### 2.5 告警接入

把阶段一留的接入点接上：`resource`（用内存里的最新样本逐分钟判断）、`serverExpiring`。

### 2.6 移除外部 Komari 上报

- Agent：删除 `runKomariManager`、`komariClient` 及相关测试；`komari-agent` 依赖里只保留 `monitoring/unit`（`protocol/v2` 和 `monitoring` 顶层包不再引用，`go mod tidy` 后确认）。
- 面板：删除 Komari endpoint 设置接口、每服务器 token 的读写、`serverInput.KomariToken`、`KomariTokenSet`。`mui_komari_tokens` 表和 `komari_endpoint` 设置在新迁移里删除。
- **兼容旧 Agent**：`GET /agent/komari` 路由保留，固定返回空配置 `{"endpoint":"","token":"","ipv4":"","ipv6":""}`。已安装的 0.6.30 及更早版本每 5 分钟会请求它，拿到空配置就不启动 Komari 上报；删掉路由会让它们每 30 秒报一次错。
- 前端：删除设置页的 Komari 地址和服务器表单里的 Komari token。
- README 与 `deploy/.env.example` 里的相关说明同步更新。

### 2.7 管理端页面

新增 Tab "监控"（`web/src/pages/Monitor.tsx`，在 `helpers.ts` 的 `Tab`、`url.ts`、`App.tsx` 三处登记）：

- 服务器卡片网格：名称、地区、在线状态、CPU/内存/磁盘进度条、上下行速率、累计流量、负载、开机时长、到期日。每 5 秒刷新（只在该 Tab 可见且页面处于前台时轮询；不要并进全局 `refresh`）。
- 点开一台：1h/6h/24h/7d/30d 的 CPU、内存、网络速率、连接数曲线，以及它参与的各 ping 任务的延迟曲线与丢包率。图表复用现有 `TrafficChart` 的画法，不引入图表库。
- ping 任务的增删改。
- Agent 不支持监控的服务器显示"需升级 Agent"。

### 2.8 版本

Agent 版本号升到 0.6.31（`README.md`、`deploy/.env.example`、`deploy/Agent.Dockerfile`、`deploy/build-agent.sh`、`internal/agent/version.go` 五处），并写 `docs/releases/v0.6.31.md`。只改版本号和说明，不要构建或发布。

### 2.9 测试

- `/agent/monitor`：未签名/错误签名被拒；非法数值被丢弃或钳制；不属于本机的 ping 结果被忽略；该接口不会创建 `serverLocks` 条目。
- 分钟聚合与小时汇总的数值正确、幂等；清理按保留期生效。
- 删除服务器后相关表为空。
- 旧 Agent 兼容：`/agent/komari` 返回空配置。
- Agent：采样结构填充、失败退避、ping 目标校验（私网、混合解析结果、DNS 变更）。

---

## 阶段二补充：计费续期、流量限额与服务器整理

目标：补上 Komari 后台里好用、而阶段二没做的部分。只改面板和前端，**不改 Agent、不改 Agent 版本号**（流量数据来自已有的 `/agent/report` 网卡流量，旧 Agent 也有效）。

### 2B.1 服务器档案新增字段

全部存进 `shared.Server`，创建与修改接口按白名单保存，离线管理与外部节点同样可填。

| 字段 | 说明 |
| --- | --- |
| `price` | 每个计费周期的价格，`0`–`1000000`，最多两位小数；`0` 表示未填 |
| `currency` | 货币符号或代码，最多 8 个字符，默认 `$` |
| `billingCycle` | `""`（未设置）、`month`、`quarter`、`halfyear`、`year`、`2year`、`3year`、`days` |
| `billingCycleDays` | 仅 `billingCycle = days` 时有效，`1`–`3650` |
| `autoRenew` | 到期后自动把到期日顺延一个周期 |
| `trafficLimit` | 每个流量周期的限额，字节，`0` 表示不限；上限 `1 << 53` |
| `trafficLimitType` | `sum`（上行 + 下行）、`up`、`down`、`max`（取大者）、`min`（取小者）；默认 `sum` |
| `trafficResetDay` | 每月几号重置流量，`1`–`31`；`0` 表示跟随 `expiresAt` 的日期，`expiresAt` 也没有时按 1 号。当月没有这一天时用当月最后一天 |
| `group` | 分组名，最多 40 个字符 |
| `sortWeight` | 排序权重，`-9999`–`9999`，大的在前，相同时按名称 |
| `alertMuted` | 为真时该服务器不发 `serverOffline` 与 `resource` 告警（到期、流量照发） |

阶段二已有的 `expiresAt` 继续使用。`publicVisible` / `publicName` / `publicNote` 保留字段与接口，但在阶段三实施前**从服务器表单里隐藏**，避免出现没有效果的开关。

### 2B.2 自动续期

新文件 `internal/server/billing.go`。在告警评估循环里（或同频率的独立协程）执行，不持有 `a.mu`、不持有 `lockServer` 以外的锁；写服务器文档时必须走与管理接口相同的加锁与 `PutServer` 路径，避免覆盖并发的 Agent 上报。

规则：

- 条件：`autoRenew` 为真、`expiresAt` 非空、`billingCycle` 非空、`expiresAt <= now`。
- 在线管理的服务器还要求最近 24 小时内有上报（`LastSeen`）；长期离线的机器多半已经退订，不自动续，照常走"已到期"提醒。离线管理与外部节点没有上报信号，直接续。
- 新到期日 = 旧到期日按周期顺延（`month`/`quarter`/`halfyear`/`year`/`2year`/`3year` 用日历月份加法，保持"几号"不变，目标月没有这一天时取月末；`days` 加天数），循环顺延直到晚于 `now`，最多循环 120 次，超过则放弃并记审计。
- 已吊销的服务器不续。
- 每次续期写审计 `server.renew`（服务器 ID、旧到期日、新到期日），并发 Telegram 事件 `serverRenewed`（新事件键，默认开）：

```
[MUI] 服务器已自动续期
服务器：tokyo-1（JP · 东京）
新到期日：2026-12-18
周期费用：$5.00
```

- `autoRenew` 为真的服务器不再发 `serverExpiring` 的 7 / 3 / 1 天提醒，改为在到期前 3 天发一次"即将自动续期"（同样用 `mui_alert_state` 去重，键里带到期日）。
- 续期后清理该服务器旧到期日对应的 `serverExpiring:*` 状态行。

手动续期：服务器列表与监控卡片上，设置了 `billingCycle` 的服务器提供"续期一个周期"按钮，接口 `POST /api/servers/{id}/renew`，逻辑同上但不要求到期，写同样的审计，不发 Telegram。

### 2B.3 流量限额

用量来源：已有的网卡流量（`SaveServerTraffic`，`mui_server_traffic`）。不要每次查询都对原始采样表求和。

新表（新迁移）：

```
mui_server_cycle_traffic(
  server_id TEXT NOT NULL,
  cycle_start_ms BIGINT NOT NULL,   -- 流量周期起点（UTC 毫秒）
  rx BIGINT NOT NULL,
  tx BIGINT NOT NULL,
  PRIMARY KEY(server_id, cycle_start_ms)
)
```

- `SaveServerTraffic` 在同一事务里、与 `mui_server_totals` 相同的"确有新行插入"条件下，把增量累加到采样时间所属周期的那一行。周期起点由服务器的 `trafficResetDay`（及 `expiresAt`）和采样时间算出，按面板本地时区的 0 点。
- 迁移时不回填历史；首次启动后由一次性任务按 `mui_server_traffic` 回填**当前周期**（幂等：先算好再整行覆盖，回填期间新到的增量不能丢，做法自定但要有测试）。
- 修改 `trafficResetDay` 或 `expiresAt` 导致周期起点变化时，按新起点从 `mui_server_traffic` 重算当前周期那一行。
- 保留最近 13 个周期，随 6 小时清理循环删除更早的；删除服务器时一并清理。
- 用量按 `trafficLimitType` 计算：上行 = `tx`，下行 = `rx`。

接口：`GET /api/servers` 与 `GET /api/monitor` 的每台服务器增加 `cycleTraffic: {startAt, resetAt, rx, tx, used, limit, type}`（未设限额时 `limit` 为 0，其余照常返回）。

告警：新事件键 `trafficLimit`（默认开），阈值百分比可设（默认 80，范围 50–100）。用量达到阈值、90%、100% 时各提醒一次，用 `mui_alert_state` 去重，键 `trafficLimit:<serverID>:<周期起点>:<档位>`；阈值高于 90 时跳过低于阈值的档位。新周期开始后自然重新计。`alertMuted` 不影响本事件。

```
[MUI] 流量用量告警
服务器：tokyo-1（JP · 东京）
已用：812.4 GB / 1000 GB（81%，按上行+下行）
周期：2026-11-01 至 2026-11-30
```

**本阶段只展示和告警，不做超限自动停机或停节点。**

### 2B.4 流量报告

Telegram 设置新增 `trafficReport: {daily, weekly, monthly}` 三个开关（默认全关）。在面板本地时间每天 09:00、每周一 09:00、每月 1 号 09:00 各发一条汇总（上一个自然日 / 周 / 月），数据取 `mui_server_traffic` 按时间范围求和（走已有的 `at_ms` 索引）。按用量从大到小列出，最多 30 台，超出部分写"其余 N 台合计"。用 `mui_alert_state` 记录已发的周期，面板重启不重发；面板在 09:00 时没在运行的，启动后 12 小时内补发一次，超过就跳过。

### 2B.5 前端

- 服务器表单：新增"计费与流量"分组（价格、货币、计费周期、自动续期、流量限额及单位 GB/TB、限额类型、重置日）和"整理"分组（分组名、排序权重、静音离线与资源告警）。
- 监控页卡片与服务器列表：
  - 有限额时显示本周期流量进度条（超过阈值变色，超过 100% 标红）；没有限额时只显示本周期用量。
  - 显示到期日与剩余天数（7 天内变色，已过期标红）；自动续期的显示"自动续期"标记。
  - 按 `group` 分组显示（无分组的归到"未分组"），组内按 `sortWeight` 排序；提供分组筛选。
- 监控页顶部加一行费用汇总：把各服务器价格按周期折算成每月，按货币分别合计（例如"每月约 $42.50 · ¥120.00"）；未填价格的不计入。
- Telegram 设置卡片：新增 `serverRenewed`、`trafficLimit`（含阈值）、三个流量报告开关。

### 2B.6 不做

- Komari 的 ICMP / HTTP 延迟任务：ICMP 需要额外权限，HTTP 意义有限，继续只做 TCP。
- GPU、温度采集。
- 远程命令、终端、文件管理。
- Telegram 以外的通知渠道（Webhook、邮件、Bark）。
- 超限自动停机。

### 2B.7 测试

- 续期：月末日期（1 月 31 日 → 2 月 28/29 日 → 3 月 31 日不漂移到 28 日）、过期很久后一次续到未来、`days` 周期、长期离线不续、离线管理直接续、已吊销不续、并发 Agent 上报不被覆盖。
- 自动续期的服务器不发 7 / 3 / 1 天提醒，只发"即将自动续期"和"已自动续期"，各一次。
- 周期流量：跨周期的采样落到各自周期；重复上报的采样不重复累计；修改重置日后重算；五种限额类型的用量计算；回填幂等。
- 流量告警：阈值、90%、100% 各一次；新周期重新计；阈值设为 95 时不发 90 档。
- 流量报告：到点发一次、重启不重发、补发窗口。
- 新字段的范围校验；`alertMuted` 的服务器不发离线与资源告警。

---

## 阶段三：公开状态页

已实施。

### 3.1 原则

- 默认关闭。开启后也只展示管理员逐台勾选了"公开展示"的服务器。
- 公开接口**永不返回**：IP、域名、内部 ID、Agent 版本、节点/订阅/链路/防火墙的任何信息、备注（`Notes`）、标签，以及 `price`、`currency`、`billingCycle`、`billingCycleDays`、`autoRenew`、`alertMuted`、`sortWeight`。
- 公开接口不读写会话，不需要登录，不带 `X-Requested-With` 要求（都是 GET）。

### 3.2 设置

`mui_settings` 键 `status_page`：`enabled`、`title`（≤60 字符）、`description`（≤300 字符，纯文本）、`showTraffic`（是否展示累计流量）、`showPing`（是否展示延迟任务）。接口 `GET/PUT /api/settings/status-page`。

### 3.3 公开接口

新文件 `internal/server/public_status.go`，路由前缀 `/api/public/`：

- `GET /api/public/status`：页面配置加服务器列表。每台：
  - `id`：公开 ID = `Store.Fingerprint("status-page", serverID)`（与内部 ID 不可互推）。
  - `name`：`PublicName`，为空时用服务器名。
  - `group`、`country`、`region`、`city`（已有档案字段）、`online`、`os`、`arch`、`virtualization`、`cpuName`、`cpuCores`、各总量。
  - 最新样本（同 2.2 的 `MonitorSample`，按 `showTraffic` 决定是否带累计流量）。
  - `cycleTraffic`（`startAt`/`resetAt`/`used`/`limit`/`type`，受 `showTraffic` 控制）。
  - `expiresAt`、`publicNote`。
- `GET /api/public/servers/{publicId}/records?range=1h|6h|24h|7d`：历史曲线，点数上限 720。
- `GET /api/public/servers/{publicId}/pings?range=`：`showPing` 开启时可用；任务只返回 `name`，**不返回 target**。

防护：

- 关闭时三个接口一律 404（与路由不存在不可区分）。
- 按来源 IP 限速：`a.rateCount(r, "status", 1) > 120` 返回 429。
- `/api/public/status` 的响应在内存里缓存 2 秒，历史接口缓存 30 秒（按 `publicId+range`，条目数有上限），避免公开流量直接打到数据库。
- 响应头 `Cache-Control: public, max-age=2`（历史接口 30）。

### 3.4 与面板分离部署

状态页是给外人看的，必须和管理面板在入口上彻底分开：访问状态页的人不应该知道面板地址，状态页的入口也不应该能到达任何管理、Agent、订阅接口。

后端（同一个进程，第二个监听）：

- 新环境变量 `MUI_STATUS_LISTEN`（例如 `127.0.0.1:8088`）。设置后，进程另起一个 `http.Server`，它的路由表**只注册** `/api/public/*` 三个接口和 `/healthz`，其余路径一律 404。超时参数与主监听一致。
- 设置了 `MUI_STATUS_LISTEN` 时，主监听上的 `/api/public/*` 返回 404：公开接口只在独立入口上可达。没设置该变量时，状态页功能整体不可用（设置页提示"未配置独立入口"），不要退回到主监听。
- 新环境变量 `MUI_STATUS_URL`（状态页的对外地址，https）。管理端设置页用它显示状态页链接；它不参与 `MUI_PUBLIC_URL` 的任何逻辑，面板生成的命令和订阅链接里永远不出现它，反之状态页的任何响应里也不出现 `MUI_PUBLIC_URL`。
- 独立入口上的来源 IP 判定沿用 `clientIP` 与 `MUI_TRUSTED_PROXIES`。
- 独立入口的响应头：与主入口相同的安全头；另加 `X-Robots-Tag: noindex`（是否允许收录不做成开关，默认不收录）。

前端（独立工程、独立构建产物、独立容器）：

- 独立工程 `status-web/`（自己的 `package.json`，只依赖 `react` 与 `react-dom`），构建输出 `status-web/dist`，构建末尾运行 `scripts/check-dist.mjs`；卡片与图表代码是 `web/src/monitor/` 的一份副本，位于 `status-web/src/monitor/`，样式改动需两处同步；管理端的构建产物里也不包含状态页代码。
- 新镜像与容器 `mui-status`（`deploy/Status.Dockerfile` + `deploy/nginx/status.conf.template`），`Status.Dockerfile` 只复制 `status-web/`，监听独立端口（默认 8089）：只提供 `status-web/dist` 的静态文件，只把 `/api/public/` 反代到 `MUI_STATUS_LISTEN`；其它路径回退到状态页的 `index.html`。安全头、`real_ip` 处理参照现有 `routes.conf`。
- `deploy/compose.yaml` 增加 `mui-status` 服务（可用 profile 控制是否启用）；`deploy/publish.sh` 能构建并发布它；`deploy/.env.example` 与 README 说明：状态页用单独的域名指向这个端口，不要和面板共用域名。
- 现有 `mui-web` 容器与 `routes.conf` **不增加** `/status` 路径，也不反代 `/api/public/`。

页面内容：

- 顶部：标题、说明、在线/总数、浅色/深色切换。
- 卡片网格：旗帜（国家代码转 emoji 即可）、名称、在线状态、系统、CPU/内存/磁盘进度条、上下行速率、累计流量、开机时长、到期日、公开备注。支持按地区分组与按名称搜索。
- 点开一台：1h/6h/24h/7d 的 CPU、内存、网络曲线和延迟曲线。
- 每 5 秒轮询 `/api/public/status`；页面不可见时暂停；请求失败时保留上一份数据并提示"连接中断"。
- 手机宽度（375px）下单列排布，无横向滚动。
- 不用 WebSocket；不引入图表库或 UI 库；CSP 与面板相同（`script-src 'self'`、无内联脚本）。
- 状态页关闭时，页面显示"状态页未开启"，不暴露任何其它信息。
- 页面里不出现指向面板的链接、不出现"MUI"以外能定位面板的信息。

管理端"设置"页增加"公开状态页"卡片（开关、标题、说明、两个展示开关、状态页链接）；服务器表单增加"公开展示""公开名称""公开备注""到期日"。

### 3.5 测试

- 关闭时全部 404；开启但未勾选的服务器不出现。
- 响应里逐字段断言不含 IP、域名、内部 ID、`Notes`、ping 目标。
- 公开 ID 不能用于任何管理或 Agent 接口。
- 限速与缓存生效。
- 入口隔离：独立监听上请求 `/api/login`、`/api/servers`、`/agent/job`、`/s/x`、`/download/install.sh` 全部 404；设置了 `MUI_STATUS_LISTEN` 后主监听上的 `/api/public/status` 为 404。
- 状态页任何响应（含静态文件）里搜不到 `MUI_PUBLIC_URL` 的主机名。
- 浏览器实测（1280 与 375 宽，浅色与深色）：列表、详情曲线、离线服务器的展示、状态页关闭时的提示。

---

## 阶段四：订阅链接防泄露（暂不实施）

**本阶段已决定暂不实施。实现者不要做本节的任何内容，也不要为它预留代码；做完阶段三即结束。**

现状：订阅链接是 `{MUI_PUBLIC_URL}/s/{token}`，token 为 256 位随机数，谁拿到链接谁就能下载。已有的保护只有：轮换链接、到期时间、访问记录（IP 与 UA）、每 IP 每分钟 120 次限速。存在三个问题：

- 链接里就是面板地址，每个拿到订阅的人都知道管理面板在哪。
- 链接泄露后没有任何提示。
- **轮换链接不会让已下载的配置失效**：节点登录凭据由"节点 ID + 订阅 ID"派生（`Store.SubscriptionUser`），轮换只换 token，拿到过旧配置的人可以一直用到订阅被删除。

### 4.1 订阅入口与面板分离

- 新环境变量 `MUI_SUBSCRIPTION_LISTEN` 与 `MUI_SUBSCRIPTION_URL`，做法与 3.4 的状态页相同：独立监听只注册 `GET /s/{token}` 与 `/healthz`；设置后主监听上的 `/s/` 返回 404；面板生成的订阅链接、Surge 配置里的托管地址（`#!MANAGED-CONFIG`）一律用 `MUI_SUBSCRIPTION_URL`。
- 没设置时保持现在的行为（向后兼容）。
- 独立的 nginx 入口（可与状态页共用一个容器的另一个 server 块，或单独容器），只反代 `/s/`，访问日志关闭（token 在路径里）。
- 切换域名后旧链接失效，README 要写明需要给客户重新发链接。

### 4.2 泄露检测与自动处置

- 每个订阅新增可选项 `maxIPs`（24 小时内允许的不同来源 IP 数，0 = 不限制，默认 0）与 `onExceed`（`alert` 只告警 / `pause` 告警并停用订阅，默认 `alert`）。IPv6 按 /64 计一个。
- 下载时用 `mui_subscription_access` 统计近 24 小时的不同来源；需要给该表补 `(subscription_id, at_ms)` 索引。超过上限时：按 `onExceed` 处理，并通过阶段一的通知通道发 Telegram 告警（新事件 `subscriptionLeak`，默认开），同一订阅 24 小时内只告警一次。
- 被自动停用的订阅在列表里标出原因，管理员手动恢复。

### 4.3 来源限制（可选项，逐订阅）

- `allowedSources`：IP / CIDR 列表，非空时只有这些来源能下载，其余返回与"订阅无效"相同的 404。格式校验复用 `shared.NormalizeFirewallAccess`。
- 适合固定出口的客户；移动网络的客户不适用，界面上要有这句提示。

### 4.4 重置凭据

- 订阅新增字段 `credentialEpoch int`；`Store.SubscriptionUser` 的派生输入在 epoch > 0 时追加它（epoch 为 0 时派生结果必须与现在完全一致，否则升级后所有现存订阅的登录都会失效）。
- 新接口 `POST /api/subscriptions/{id}/reset`：epoch 加一、同时轮换 token、对涉及的服务器下发 `subscriptions.apply`。效果是旧链接和**已下载的旧配置**都失效。
- 界面上"轮换链接"旁增加"重置凭据"，二次确认里写明"所有设备需要重新导入订阅"。
- 共享密码的节点（`shared.SharedSubscriptionPassword` 为真的单用户节点、旧式 AEAD SS）不受 epoch 影响，重置时要在返回里列出这些节点并提示需要改节点密码。

### 4.5 不做

- 不做"一次性链接"：客户端需要定期刷新订阅，链接必须长期有效。
- 不做 UA 白名单作为安全措施：UA 可以随意伪造，只在访问记录里展示。
- 不做订阅内容加密：主流客户端不支持。

### 4.6 测试

- 独立入口隔离（同 3.5 的做法）。
- `maxIPs` 的计数、/64 归并、告警去重、自动停用与恢复。
- `allowedSources` 之外的来源得到与无效 token 相同的响应。
- epoch 为 0 时派生凭据与改动前逐字节一致；重置后旧凭据不在下发的状态里，新凭据生效。

---

## 汇报格式

每个阶段结束时给出：

1. 改动与新增的文件。
2. 新增迁移的编号与内容。
3. 新增的接口列表。
4. 偏离本设计的地方与原因。
5. 没有做或没有验证的部分。
6. 各项构建与测试命令的结果。
