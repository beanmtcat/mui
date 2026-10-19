# 完全离线转发（Agent 0.6.7 起）

适用于能连接下一跳、但不能连接面板或互联网的入口/中转服务器。无需接入令牌、环境变量、sing-box 或 UFW，只安装非 root 的 `mui-forward.service`，由 systemd / OpenRC 开机启动。目标机必须能访问配置里的下一跳；没有 DNS 时使用下一跳 IP。

## 面板编排链路和订阅（推荐）

1. **服务器 → 新建服务器**：管理方式选“离线管理”，填写名称、国家、公网 IP 或订阅域名；选入口、线路或中转类型。防火墙固定为手动管理。落地节点继续使用在线 Agent。
2. **链路 → 新建链路**：首跳选择该离线入口，中间跳可混用在线或离线中转，最后选择在线落地节点。仍支持内网地址、多目标主备/轮询、统一端口。也可在“端口转发”页单独新增规则。
3. **服务器 → 离线配置 → 导出并下载配置**：得到 `mui-offline.json`，它是该服务器全部转发规则的完整快照（含链路自动规则和手动规则），不是增量；停用、删除也需导出和应用。
4. 在联网电脑按架构下载弹窗列出的 `mui-agent`、`SHA256SUMS`、`SHA256SUMS.sig`，连同 `mui-offline.json` 上传到目标机 `~/mui-install/`。以目标机 `uname -m` 为准：x86_64 选 amd64，aarch64 选 arm64。不要上传发布私钥。
5. **首次安装或升级**：在目标机执行弹窗给出的完整安装命令（自动判断 root / sudo、校验摘要，命令含发布公钥）。目标机不会下载任何文件，不需要访问面板。
6. 安装命令成功后，自行检查目标机监听端口和整条链路是否连通，无需向面板回传文件。
7. **订阅 → 新建或编辑**：选择这条链路。离线各跳已导出当前配置、在线各跳和落地配置均已生效后，订阅输出首跳地址 + 链路端口，协议与凭据使用落地节点；传统 SS 沿用节点密码，其他支持多用户的协议使用独立凭据。导出不代表目标机已应用，需先完成目标机操作再使用订阅。

后续修改链路或转发：保存后重新导出 `mui-offline.json`，上传，再以 root 执行：

```bash
mui-agent offline check ~/mui-install/mui-offline.json
mui-agent offline apply ~/mui-install/mui-offline.json
```

`apply` 等待转发进程确认配置摘要，失败恢复原配置；执行成功后无需其他确认步骤。签名校验、服务器身份绑定和版本检查会拒绝被修改、传错机器、版本倒退或同版本内容不一致的文件。首次导入的文件用于固定面板公钥与服务器身份，必须从自己的面板下载。**不要手工修改带签名的配置，也不要直接覆盖 `/etc/mui-forward/forwards.json`。**

### 状态、统计与防火墙

- 面板显示“离线管理 / 已导出版本”，只说明配置已经导出，不代表目标机已应用、在线或整条链路连通。
- 离线入口的实时流量、在线状态无法回传；支持独立凭据的节点由在线落地按订阅统计，传统 SS（如 aes-256-gcm）共享密码，只能统计落地节点总流量。客户端使用的订阅仍从面板下载，不需要从入口下载。
- 离线各跳不操作防火墙。入口监听端口需要在宿主机 / 安全组放行；中转和落地需要允许上一跳的实际出口 IP。面板仍为采用 UFW 托管的在线接收服务器计算来源规则。
- 专线入口访问下一跳公网地址、下一跳看到的却是入口内网 IP 时，在链路对应中间跳将“防火墙来源”设为“发送方内网 IP”，目标地址仍可保持公网。落地同样有独立的来源选择。只修改在线接收方的 UFW 来源、未改变离线机转发规则时，无需重新导出离线配置。
- 修改离线服务器的规则后，需要重新导出完整配置并在目标机应用；受影响的链路等待新配置导出。多台离线服务器分别导出并应用，无需导入文件。删除规则在下一次导出后从面板清除，但目标机上的旧规则只有应用新配置后才会停止。
- 首次在线接入或离线导出后管理方式固定，避免在线 Agent 与离线文件同时控制。已有 `/etc/mui-agent/config.json` 的目标机拒绝离线接管；已有离线安装的目标机也拒绝在线接入。
- 升级离线 Agent 时，上传新版三个发布文件后再次执行弹窗安装命令：命令发现本机已安装离线服务，会改由**已安装的旧版程序**用本机固定的发布公钥校验新程序，校验通过后才运行新程序完成安装，新程序不会在校验前被执行。也可手动执行 `/usr/local/bin/mui-agent offline upgrade --binary ./mui-agent`（以 root 执行，不带 `--config` 时沿用当前配置）。未固定发布公钥时拒绝升级；先通过可信渠道核实发布公钥，再将其保存为 `/etc/mui-forward/release.pub`（root 所有，0644）。升级暂存目录位于 `/usr/local/bin`，支持 `/run` 为 `noexec` 的机器。
- 导出文件声明所需的最低 Agent 版本（当前 0.6.7）。面板写入的新字段需要新 Agent 理解时会提高该版本；本机 Agent 过旧时拒绝应用并提示先升级，不会忽略看不懂的设置。文件按内容签名，用编辑器重新排版不影响校验，但修改任何内容都会使签名失效。

## 独立手工配置（无需面板编排）

以下 JSON 数组方式用于独立本地管理。已绑定面板签名配置的机器会拒绝用无签名数组覆盖。需要面板订阅时使用上面的导出流程。

## 1. 准备文件

面板的“首次接入 / 手动修复”弹窗选择 **完全离线转发**，按目标服务器的 `uname -m` 选择 amd64（x86_64）或 arm64（aarch64）。在本机下载文件后用 SFTP/SCP 上传到目标机 `~/mui-install/`：

- `mui-agent`：0.6.7 或更新版本。
- `SHA256SUMS`：与二进制相同的架构和发布版本。
- `SHA256SUMS.sig`：面板启用发布签名时需要。

弹窗提供下载命令、TCP/UDP 配置示例和安装命令，安装命令已含发布公钥，不含接入令牌，也没有十分钟有效期限制。

不通过面板操作时，可以从构建机额外复制 `deploy/.secrets/release.pub` 到目标机，与二进制放在一起，用 `--release-key-file` 指定。只传公钥，私钥留在构建机。

以下命令在目标机以 **root** 执行。若使用普通账户，安装和应用命令前加 `sudo`。目标机需要 systemd（`systemctl`、`useradd`）或 Alpine OpenRC（`rc-service`、`rc-update`、`supervise-daemon`、`adduser`）和标准系统工具；安装期间不下载安装包、不连接面板、不操作防火墙。

## 2. 新建并修改配置

先校验上传的程序再执行：

```bash
cd ~/mui-install
test "$(grep -Ec ' \*?mui-agent$' SHA256SUMS)" -eq 1 &&
  grep -E ' \*?mui-agent$' SHA256SUMS | sha256sum --check
```

确认校验输出为 `mui-agent: OK` 后执行：

```bash
chmod 755 ./mui-agent
./mui-agent offline init ./forwards.json
```

`init` 不会覆盖已有文件。编辑 `forwards.json`，把示例的 `10.0.0.2` 改成入口机能访问的下一跳地址，监听端口和下一跳目标端口可以不同。

### TCP + UDP 示例

面板“端口转发”的协议下拉框选择 **TCP + UDP**。一条规则统一编辑、启停和删除；手写本地 JSON 时使用 `"network": "tcp+udp"`。

入口机监听 `50001`，转发到下一跳 `10.0.0.2:59917`：

```json
[
  {
    "id": "entry",
    "name": "入口 TCP + UDP",
    "network": "tcp+udp",
    "listen": "0.0.0.0",
    "port": 50001,
    "targets": [{"host": "10.0.0.2", "port": 59917}],
    "balance": "failover",
    "firewallPolicy": "manual",
    "enabled": true
  }
]
```

| 字段 | 填写方式 |
|---|---|
| `id` | 每条规则唯一、尽量保持不变；支持 1–100 位字母、数字、点、横线或下划线 |
| `name` | 可读名称；省略时使用 ID |
| `network` | `tcp`、`udp` 或 `tcp+udp`；双协议一条规则管理，相同端口与目标，合并流量统计 |
| `listen` | 本机监听 IP；默认 `0.0.0.0`，IPv6 可填 `::` |
| `port` | 本机监听端口，1024–65535，不能占用已有服务或保留统计端口 |
| `targets` | 1–16 个目标，每个包含 `host` 与 `port` |
| `balance` | `failover` 主备（默认）或 `round-robin` 轮询 |
| `healthCheck` | TCP 默认主动 TCP 探测，UDP 默认被动检查；可选 `tcp` / `none` |
| `firewallPolicy` | 离线模式仅支持 `manual`，省略时自动使用；不会自动放行或限制来源 |
| `enabled` | 默认 `true`；改为 `false` 停用该规则 |

没有 DNS 时使用 IP 地址。内网及专线地址可作为目标；不允许回环、链路本地、组播、未指定地址或云元数据地址。

### 多目标主备或轮询

将某条规则的 `targets` 改为：

```json
"targets": [
  {"host": "10.0.0.2", "port": 59917},
  {"host": "10.0.0.3", "port": 59917}
],
"balance": "failover"
```

主备模式优先第一个健康目标；轮询模式改为 `"balance": "round-robin"`，新连接轮流分配。主动检查每 5 秒进行一次，连续两次失败停用、连续两次成功恢复；只检查下一跳，不代表整条多跳链路都可用。UDP-only 目标使用默认被动检查；只有确定目标也接受 TCP 连接时才设 `"healthCheck": "tcp"`。

## 3. 校验与安装

```bash
./mui-agent offline check ./forwards.json
```

校验配置格式、重复 ID、监听冲突和目标格式，不访问网络、不探测目标，也不占用监听端口。通过后，在面板中复制“离线安装命令”执行；不通过面板时使用：

```bash
./mui-agent offline install --config ./forwards.json --release-key-file ./release.pub
```

未启用发布签名的自有构建可省略 `--release-key-file`，安装器仍要求并校验 `SHA256SUMS`。一旦固定发布公钥，后续离线升级必须携带有效签名，不会静默降级到只校验摘要。

安装结果：

- 程序：`/usr/local/bin/mui-agent`。
- 配置：`/etc/mui-forward/forwards.json`，root 所有、`mui-forward` 组可读。
- 服务：`mui-forward.service`，使用非 root 的 `mui-forward` 用户运行，开机启动。
- 本机流量快照：`/run/mui-forward/stats.json`，仅记录当前进程累计上/下行，进程重启后重计，不上传面板。

查看服务与日志：

```bash
systemctl status mui-forward --no-pager -l
journalctl -u mui-forward -n 80 --no-pager
```

入口监听端口须在宿主机防火墙/安全组放行；下一跳也须允许来自入口机实际出口 IP 的连接。离线安装不会启用、关闭或修改 UFW。

## 4. 修改、停用和删除规则

继续编辑工作文件 `~/mui-install/forwards.json`，不要直接覆盖正在使用的 `/etc/mui-forward/forwards.json`。随后执行：

```bash
mui-agent offline check ~/mui-install/forwards.json
mui-agent offline apply ~/mui-install/forwards.json
```

`apply` 先校验，再原子替换并通过 SIGHUP 加载，等待进程确认配置摘要。未变化规则的连接保留；修改、删除规则会中断该规则已有连接。端口占用等加载失败时恢复原配置并报告错误；单纯 `systemctl reload` 没有这种结果确认。

- 停用：将该规则 `enabled` 改为 `false` 后应用。
- 删除：从数组移除该条规则后应用。
- 停止全部转发：工作文件写为 `[]` 后应用，或执行 `systemctl disable --now mui-forward`。
- 主机重启：服务从磁盘配置恢复运行，不需要面板或接入令牌。

## 5. 离线升级

将新版本 `mui-agent`、`SHA256SUMS`、`SHA256SUMS.sig` 上传至 `~/mui-install/`，然后用**已安装的**程序执行升级：

```bash
cd ~/mui-install
sudo /usr/local/bin/mui-agent offline upgrade --binary ./mui-agent
```

已安装的程序先把三个文件复制到只有 root 可写的临时目录，用本机固定的发布公钥校验签名和摘要，并拒绝降级；全部通过后才运行新程序完成安装，更新程序并重启转发服务，现有连接会短暂中断；启动失败会恢复之前的程序和配置。不要用新上传的程序直接执行 `offline install` 来升级：那样新程序会在被校验之前以 root 运行。正常修改转发规则只使用 `offline apply`，无需重新安装。
