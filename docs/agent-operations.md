# Agent 系统支持与内存

## Alpine 3.19 及以上（OpenRC）

Agent 0.6.8 起支持 amd64 / arm64。先以 root 安装依赖，再执行面板生成的接入命令：

```sh
apk add --no-cache openrc openssh iproute2 curl ca-certificates
```

服务器应已通过 OpenRC 正常启动；普通未运行 init 的应用容器不能代替受管服务器。使用“手动管理”防火墙不需要 UFW。选择 UFW 托管时另装 `ufw`，并确保宿主机允许容器管理网络过滤规则；Agent 不会通过切换防火墙工具来绕过权限限制。

服务按实际需要创建，支持开机启动、崩溃后重启、在线配置下发和升级回滚：

```sh
rc-service mui-agent status
rc-service mui-agent-helper status
rc-service mui-forward status
rc-service mui-sing-box status
tail -n 80 /var/log/mui-agent.log
tail -n 80 /var/log/mui-agent-helper.log
```

仅做转发时没有 sing-box；无启用转发时不启动转发服务。服务日志写入 `/var/log/mui-*.log`，请通过主机日志轮转策略定期轮转。日志文件须保留服务账户的写权限。

离线安装命令仍为 `mui-agent offline install/apply/upgrade`，程序自动选择 OpenRC 或 systemd。面板导出的签名配置通过 `mui-agent offline apply ./mui-offline.json` 应用；不要直接覆盖运行时文件。纯本地 JSON 数组管理可使用 `rc-service mui-forward reload`。

Ubuntu / Debian 继续使用 systemd，管理命令仍为 `systemctl`，日志仍为 `journalctl`。

## 512 MiB 主机

三个 `mui-agent` 进程各有用途：非特权 worker 连接面板，root helper 只执行受限管理操作，非特权 forward 处理转发连接。sing-box 是另一个独立进程。程序会自动使用主机内存与 cgroup 限额中较小的值，给各角色设置 Go 运行时内存回收目标，无需手动设置环境变量。

512 MiB 环境中的默认目标约为：

| 进程 | Go 内存回收目标 |
|---|---:|
| Agent worker | 32 MiB |
| 权限 helper | 16 MiB |
| 转发 | 85 MiB |
| sing-box | 128 MiB |

这些是软目标，**不是预分配内存、RSS 硬上限或峰值保证**。活跃连接、UDP 缓冲区和内核套接字仍需内存；超过软目标时 Go 会加快回收，但不会为满足目标而强制断开连接。大内存机器的预算会适当提高；服务已有明确 `GOMEMLIMIT` / `GOGC` 设置时，Agent 尊重管理员设置。

worker/helper/forward 继续隔离权限。TCP 尽可能使用 Linux splice，UDP 会话从小缓冲区起步，无规则时停止转发进程。sing-box 的预算随服务文件更新后重启生效；无需升级核心二进制。

多个进程共享同一二进制的只读内存页，不能把各进程 RSS 直接相加当作实际总占用。可以检查 `/proc/<PID>/smaps_rollup` 中的 `Pss`，再结合主机 `MemAvailable` 和 cgroup 的 `memory.current` 判断。高并发负载仍需按实测调整机器内存或连接规模。

服务适配遵循 [OpenRC 服务脚本指南](https://github.com/OpenRC/openrc/blob/master/service-script-guide.md)，Go 软内存限制的含义见 [Go GC 指南](https://go.dev/doc/gc-guide#Memory_limit)。
