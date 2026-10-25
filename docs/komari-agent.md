# 在 mui-agent 中接入 Komari

mui-agent 可以同时向 MUI 和 Komari 面板上报，不需要在服务器上运行独立的 komari-agent 进程。此集成使用 Komari v2 JSON-RPC 的 HTTP 上报与事件拉取接口，支持服务器基本信息（包括 GPU 型号）、CPU、内存、交换分区、磁盘、网络、连接数、进程数、运行时间、在线状态和 TCP Ping。它不会执行 Komari 下发的命令，不提供远程终端、文件管理、Agent 配置读取或由 Komari 发起的版本切换。ICMP 和 HTTP Ping 返回失败值；请在 Komari 面板中只创建 TCP Ping 任务。

## 配置

1. 在 MUI 左侧 **设置 → Komari 监控** 填写 Komari 面板地址，例如 `https://komari.example.com`。
2. 在 Komari 面板为每台服务器取得 Agent token。在 MUI 的 **服务器配置 → Komari Agent token** 分别填写。可以沿用现有 Komari 节点的 token，以保留该节点历史数据。
3. 安装或升级 MUI Agent，然后停用服务器上原来的独立 `komari-agent` 服务。

Agent 启动后立即从 MUI 面板领取配置，之后每 30 秒检查一次变更。token 在 MUI 数据库中加密保存，不会出现在服务器列表或安装命令中。没有 token，或全局面板地址为空时，mui-agent 不启动 Komari 上报；清除 token 会自动停用该服务器的 Komari 上报。无需在目标服务器创建配置文件。旧版 `/etc/mui-agent/komari.json` 文件不再读取，可以删除。

面板地址只接受 HTTPS；仅当 Komari 面板与 Agent 在同机时允许 `http://127.0.0.1`。不支持跳过 TLS 证书校验。Komari 连接失败不会阻止 mui-agent 向 MUI 面板上报或执行 MUI 管理任务。可通过 `journalctl -u mui-agent -f` 或 `/var/log/mui-agent.log` 查看连接错误。

## 协议与安全边界

上报间隔为 3 秒，基本信息每 5 分钟更新一次；HTTP 拉取请求同时保持 Komari 的在线状态和 TCP Ping 任务。本机无法直接识别公网地址时，基本信息会通过 ipify 的 HTTPS 接口查询公网 IPv4 / IPv6，每次查询最多等待 5 秒；查询失败时该地址留空。Komari 面板目前不会按 `agent.pull` 声明的 `capabilities` 过滤待处理事件，因此 mui-agent 只处理 `agent.ping` 中的 `tcp` 类型，并忽略其他事件。Ping 结果上报失败时会重试。Komari 面板中可能仍显示远程操作入口，但此 Agent 不执行这些操作。MUI Agent 的升级仍由 MUI 的签名发布流程管理。

本集成使用固定版本的 [komari-agent](https://github.com/komari-monitor/komari-agent) 监控采集和协议 Go 包，其 MIT 许可证见 [第三方声明](../THIRD_PARTY_NOTICES.md)。
