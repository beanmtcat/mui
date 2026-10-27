# MUI 节点管理面板

React + Go 的多服务器节点面板，前端由 Nginx 独立部署，Go 后端提供接口。在线管理服务器运行 Go Agent 和 sing-box；卖家提供的外部节点也可只录入连接信息，不安装 Agent。面板负责期望配置、任务、流量与订阅；Agent 只主动连向面板，不开放远程控制端口。首版支持 Shadowsocks、Snell v5/v6、AnyTLS 和 UFW。

## 功能

Surge 的节点订阅通过代理组 `policy-path` 引用。面板“查看链接”提供可复制的代理组配置；[导入步骤](docs/surge-import.md)。

左侧“帮助”页可搜索、新增、编辑和删除常见问题。答案支持普通文字、行内反引号代码及以三个反引号包围的多行代码块；代码块可一键复制。条目保存在面板数据库中，并记录编辑操作到审计日志。

卖家只提供节点时，在“新建服务器”选择 **外部节点（卖家提供，无需安装）**，填写卖家的 IP 或域名，再到节点页录入原始协议、端口和密码。外部节点固定为单用户，支持直连订阅及作为链路落地；面板不生成接入令牌、不部署节点或防火墙、不采集卖家服务器的流量，也不能确认实时连通性。卖家变更凭据时需在面板同步修改；链路最后一跳的来源放行仍须由卖家处理。

- 服务器档案：名称、国家、地区、城市、服务商、标签、备注、IPv4/IPv6、订阅域名，以及类型（入口、线路、中转、落地，可多选）和内网地址；一次性接入令牌、在线状态、系统、架构、核心/Agent 版本、UFW 和统计状态。动态家宽可开启“自动同步公网 IP”：优先回填 Agent 上报的有效公网 IPv4/IPv6；本机 IPv4 在 NAT 后且 Agent 直接连接面板时，使用面板看到的公网连接来源作为 IPv4。通过面板配置的 SOCKS5 代理连接时不使用该回退，避免把代理出口当成服务器地址。地址改变后重新同步链路和来源规则；暂时检测不到某一地址族时保留其原值。此选项默认关闭；回填的地址仍需能接受入站连接，CGNAT 无法仅靠回填开放端口。开启且填写了订阅域名时，链路上一跳改为通过该域名连接本机，转发进程按 DNS 跟随地址变化；未开启的服务器仍按填写的 IP 连接，域名须解析到本机真实地址，不能是 CDN 代理域名。
- 节点：增删改、启停、端口冲突检查、SS 2022 密钥校验、AnyTLS 证书上传与验证；证书统一管理并可跨服务器复用，私钥仅随引用它的节点配置下发；新建节点及模板的端口默认在 50000–60000 范围，可点击骰子按钮重新随机生成，新建节点会避开已知的同服务器节点和 SSH 端口；Agent 校验 sing-box 配置、管理端口规则、重启并探测监听，失败回滚。
- 节点模板：保存 SS、Snell 或 AnyTLS 的常用协议、端口、连接参数及可选密码 / PSK；Snell 模板还可保存 ShadowTLS v3 的 SNI / 握手域名与独立密码。模板密钥加密存储，选用时填入新节点表单；模板未保存密码时，表单会为新节点生成并显示独立密码。SS 2022 生成按钮按加密方式产生 16 或 32 字节的 Base64 密钥；AnyTLS 按 TLS 域名从统一证书库匹配证书，节点也可手动选择证书。UFW 放行策略只在具体节点上设置，不随模板保存或带入。支持从现有节点保存模板，以及编辑、删除模板；修改模板不会改动已创建的节点。
- 流量：按节点入站 tag 和订阅用户分别从 sing-box V2Ray API 采样上/下行；Agent 本地缓存、实例重启识别、幂等上报。节点和订阅各有累计流量与近 24 小时折线图。Agent 还读取默认网卡的收发字节，面板显示服务器网络累计流量。
- 订阅：sing-box JSON 出站、Surge `[Proxy]` 片段和 v2rayN Base64 分享链接订阅；内容是链路和开启“允许直连”的节点，启停、到期、令牌轮换和删除。订阅配置使用节点或链路的原始名称，不附加 ID 后缀。默认每条订阅在 SS 2022、AnyTLS、Snell v5/v6 节点上使用独立用户凭据，同节点可供多条订阅使用；节点也可开启“单用户”共用原有凭据。SS 2022 多用户客户端密码为“服务器密钥:用户密钥”；经 ShadowTLS v3 接入的 Snell 多用户节点由每条订阅独立的 ShadowTLS 密码鉴权，Snell 本身保持单用户，因此 Surge 等原生客户端也能使用，流量仍按订阅统计（需要 Agent 0.6.0；更早的 Agent 仍要求 sing-box 专有的 `userkey`，这类节点不会出现在 Surge 订阅里）。订阅只下发其配置已在服务器上生效的节点：某台服务器离线或有变更尚未应用时，只有受影响的节点暂不下发，其余节点照常提供；全部节点都在等待生效时返回 503 让客户端稍后重试。订阅链接加密保存，可随时在列表中再次查看。Surge 订阅支持传统 AEAD SS、AES-GCM 的 SS 2022、SOCKS5、启用 ShadowTLS 的 Snell 节点，以及 AnyTLS（Surge Mac 6.4.3+ / iOS 5.17.0+）；AnyTLS 订阅保留落地节点的 SNI 和对应密码，直连和链路均支持，默认校验证书；v2rayN 订阅支持 SS 和 AnyTLS，支持节点直连与链路入口地址；不支持 Snell / ShadowTLS，界面会提示不兼容链路的具体原因，API 也会拒绝不兼容成员。AnyTLS 在 v2rayN 中需选择 sing-box 内核；订阅链接可直接添加到订阅分组，更新后导入节点。传统 SS（例如 `aes-256-gcm`）也可加入订阅及离线链路，沿用节点原有密码，不生成多用户配置。这类节点仅统计节点总流量，无法按订阅或客户拆分；禁用、删除、到期或轮换链接只影响订阅下载，撤销已导入客户端的访问需更换节点密码。

  **新建、编辑、启停、删除订阅以及订阅到期，若涉及独立用户节点，会让这些节点所在服务器的 sing-box 重启一次以更新登录凭据，该服务器上所有连接会中断数秒。** 仅包含单用户或传统 SS 共享凭据节点的订阅无需为用户变更重启。sing-box 没有不重启增删用户的办法。到期日按所选日期当天 23:59:59 生效，相关自动重启因此发生在午夜前后。
- 客户端管理：客户可关联多条订阅，客户页汇总这些订阅的流量。成功下载订阅时记录来源 IP、订阅和客户；Agent 从 sing-box 本机 Clash API 每 10 秒采样活跃节点连接的来源 IP，页面分别展示两类记录。连接快照可能漏掉短连接；订阅用户流量由登录凭据识别，不依赖来源 IP。
- 防火墙管理：每台服务器可选择 **UFW 托管** 或 **手动管理**，现有服务器默认 UFW 托管。已有服务器需要先升级 Agent 至 0.6.4。手动管理无需安装或启用 UFW，仍可部署节点、转发及链路；面板不增删防火墙规则、不自动修补 SSH 放行，也不启用或关闭现有 UFW。防火墙页仅供查看；端口放行、来源白名单和落地仅允许链路访问由宿主机、防火墙或安全组配置。节点“允许直连”此时仅控制能否加入直连订阅。切回 UFW 托管后重新同步面板规则，需确保 UFW 可用。
- UFW 托管：初始化时先放行检测到的 SSH 端口；每个节点可选择自动放行所有来源、仅放行指定 IP/CIDR（最多 32 个），或不生成自动规则并用自定义规则管理。SS 自动规则覆盖 TCP/UDP，Snell 与 AnyTLS 覆盖 TCP；只清理带 `mui-` 标记的规则。指定来源模式要求 UFW 默认入站策略为 deny/reject；已有的其他 UFW 允许规则及云安全组仍会影响实际访问。指定来源和节点级手动规则可以先保存；旧 Agent 不会领取相关配置任务，升级至支持该功能的版本并上报能力后才会应用。升级前原有 UFW 放行规则仍会生效。
- 链路：入口或线路 → 若干跳中转（每跳可多台负载均衡）→ 落地节点，面板在每一跳自动生成转发，详见下文“链路”。
- 端口转发：协议可选 TCP、UDP、TCP + UDP（Agent 0.6.7 起）；双协议以一条规则共用端口与目标、统一启停删除、合并统计流量。在面板为服务器添加 TCP/UDP 监听端口和一个或多个目标地址与端口（多个目标时主备或轮询，支持 TCP 主动探测或 UDP 被动检查）；支持启停、编辑、删除、累计上/下行统计。**新建转发默认仅放行指定来源（restricted）**，需管理员显式确认才会公开放行所有来源；UFW 托管服务器未启用 UFW 或检测到其他防火墙工具时，转发页会展示 error 横幅。UDP 会话以客户端地址为键、无认证，源地址可被伪造并可能被用于反射，属于 UDP 协议固有风险——不要把转发端口当作认证边界。Agent 使用同一个 `mui-agent` 二进制启动独立的 `mui-forward.service`，进程运行在 `mui-forward` 账户下。TCP 在转发机终止客户端连接并向目标新建连接，因此转发机发送数据的 TCP 段可使用该机的拥塞控制算法（如 BBR）；UDP 使用按客户端地址维护的会话。转发规则会检查节点、SSH 和其他转发的监听端口冲突。尚未升级的 Agent 可以先保存规则，能力上报后自动应用；升级任务不会被待应用规则阻塞。
- 管理：密码登录与修改、TOTP 启用与关闭、记录操作来源 IP 的审计日志、操作记录、失败重试、Agent 凭据吊销、节点密钥加密存储。旧审计记录没有来源 IP，系统定时事件显示为系统操作。支持面板分别一键升级 Agent 和 sing-box；中转可按需安装 sing-box 并保留中转类型来建节点；入口、线路安装核心后会添加落地类型。Agent 升级不重启 sing-box，sing-box 升级会短暂中断该服务器上的节点连接。

## 本地开发

需要 Go 1.25、Node 22、Docker Compose 和 C 编译器（当前构建仍包含 SQLite 驱动）。先从仓库根目录启动本地 PostgreSQL：

```bash
docker compose --env-file .env -f deploy/compose.dev.yaml up -d --wait
```

启动 Go 后端：

```bash
go run ./cmd/server
```

在另一个终端启动 React 开发服务器：

```bash
cd web
npm ci
npm run dev
```

浏览器访问 `http://127.0.0.1:5173`。Vite 将 `/api/`、`/agent/`、`/s/`、`/download/` 和 `/healthz` 请求转发到 `127.0.0.1:8080`；Go 后端地址只提供接口，访问其根路径返回 404。后端启动不依赖前端是否构建。

仓库根目录的 `.env` 已包含本地 PostgreSQL 的主机、端口、库名、用户名，以及一份 `MUI_DB_PASSWORD`；后端启动时自动读取并生成连接地址，不需要执行 `export`。`.env` 还包含随机生成的面板密钥与管理员初始密码。登录密码查看或修改 `MUI_ADMIN_PASSWORD`；它只在首次初始化数据库时生效，之后请在“设置”页修改。新环境可复制 `.env.example` 为 `.env`，只需填写一次数据库密码。系统环境变量优先于 `.env`。不要提交 `.env`，也不要更换已有数据库对应的 `MUI_SECRET`。

开发 Compose 首次启动时创建 `mui` 数据库和用户；后端连接数据库后自动执行版本化迁移，创建或更新全部 `mui_` 前缀的业务表，不需要手工建表。数据库数据保存在 Docker 卷 `dev-db-data`。本地模式只用于开发；远程 Agent 要求 HTTPS 面板地址。

旧版数据库若仍使用 `panel` 数据库名和用户，升级时可继续把 `MUI_DB_NAME`、`MUI_DB_USER`、主机与端口指向原数据库，并保持原 `MUI_DB_PASSWORD` 和 `MUI_SECRET` 值。首次启动会在事务中把旧表及迁移记录改名为 `mui_` 前缀并保留数据；如果新旧同名业务表同时存在，会拒绝启动，避免覆盖数据。数据库名和用户本身不会自动改名。

使用默认 SQLite 路径的旧版安装会把 `data/panel.db` 移到 `data/mui.db`，再执行相同的表名迁移。如果两个文件都存在，启动会报错并要求先确定使用哪个数据库。

多用户订阅流量需要 Agent 0.5.0 与支持相应协议的 sing-box 1.14 构建。先按下方部署步骤构建 `bin/amd64`、`bin/arm64` 的 Agent 与校验清单，再安装 Agent 和 sing-box。Agent 上报多用户能力并成功应用配置前，订阅下载会返回“等待 Agent 更新”。Agent 后续可从面板一键升级：它自行下载匹配架构的二进制并核对 SHA-256，升级时保留上一版本供失败回滚。

升级 sing-box 时，Agent 先验证新二进制包含统计与连接采样所需的构建能力，检查现有配置是否兼容，再保留旧二进制为 `/usr/local/bin/sing-box.previous`，替换并重启核心，检查服务和节点监听端口。失败时恢复旧二进制并重启旧核心；成功后 Agent 上报核心构建哈希。升级时该服务器上的节点连接会短暂断开。没有节点、核心服务未运行时，只替换文件并保持服务停止；有启用节点而核心服务异常停止时，会拒绝升级并提示先修复服务。面板必须使用目标服务器可访问的 HTTPS 地址，且构建文件必须与 `SHA256SUMS` 一致。安装器会停用旧的 `panel-*` 服务，并复制尚未上报的流量缓存；旧 UFW 规则仍由新 Agent 管理，删除节点或规则时会同步清理。旧 SSH 放行规则会保留，避免切换期间失去远程访问。

## 手动创建 PostgreSQL 数据库

使用有创建用户和数据库权限的管理员连接 PostgreSQL（例如 `psql -U postgres -d postgres`），分别执行下面两条语句。将示例密码换成与 `MUI_DB_PASSWORD` 相同的值；`CREATE DATABASE` 不能放在事务块中。

```sql
CREATE USER mui WITH PASSWORD '替换为随机数据库密码';
CREATE DATABASE mui WITH OWNER mui ENCODING 'UTF8';
```

使用现有 PostgreSQL 实例时，在 `.env` 中设置 `MUI_DB_HOST`、`MUI_DB_PORT`、`MUI_DB_NAME`、`MUI_DB_USER` 和一次 `MUI_DB_PASSWORD` 即可；后端会安全编码密码并生成连接地址。只有需要传入完整 PostgreSQL URL 时才设置 `MUI_DB_URL`，它会覆盖这些分项配置。后端连接成功后会自动创建 `mui_` 前缀的表。开发 Compose 会自动建库建用户；生产 Compose 使用已有 PostgreSQL，需提前创建数据库和用户，再由后端自动建表。

## 生产部署

前后端分别构建、分别运行：`mui-web` 使用 Nginx 托管 React 静态文件，`mui-service` 运行 Go 接口服务，容器名分别固定为 `mui-web` 和 `mui-service`。PostgreSQL 使用已有实例，生产 Compose 不创建数据库或备份容器。请求链路为 **已有外层 Nginx（HTTPS）→ `127.0.0.1:8086` 的内层 Nginx（HTTP）→ Go 后端**。浏览器、订阅客户端及 Agent 统一访问外层 Nginx 的公开域名；两层代理保留完整路径。MUI 不占用宿主机 80/443，后端默认映射到 `127.0.0.1:8087`，前后端容器内分别监听 8086、8087。前端无需填写数据库或管理员密钥，也不需要配置 CORS。

**目标服务器上的 Agent 使用宿主机二进制 + systemd 部署，无需安装 Docker。** 下文的生产 Compose 用于面板侧的前端和后端。`deploy/Agent.Dockerfile` 是构建工具：只在构建机编译并导出 `mui-agent`、`sing-box` 到 `bin/<架构>/`，安装脚本随后在目标机下载二进制并安装 systemd 服务。

1. 复制 `deploy/.env.example` 为 `deploy/.env`，填写 `MUI_PUBLIC_URL`（对外的 `https://` 地址），以及已有数据库的 `MUI_DB_HOST`、`MUI_DB_PORT`、`MUI_DB_NAME`、`MUI_DB_USER`、`MUI_DB_PASSWORD` 和 `MUI_DB_SSLMODE`。在数据库中提前创建库和用户（见上文 SQL）；独立生成 `MUI_SECRET` 和管理员密码。`MUI_SECRET` 必须稳定保存，丢失后数据库中的节点密钥与证书私钥无法解密。
   数据库地址必须从容器内可访问：宿主机 PostgreSQL 可填 `host.docker.internal`（Compose 已配置 Linux 宿主机映射），其他服务器填其内网 IP 或域名。`127.0.0.1` 在容器内指后端容器自身。PostgreSQL 需监听对应网卡并允许该客户端连接；不使用数据库 TLS 的可信内网实例可将 `MUI_DB_SSLMODE` 设为 `disable`。
2. 保持 `MUI_BIND=127.0.0.1:8086`。在已有外层 Nginx 的面板域名 HTTPS `server` 块中加入 `deploy/nginx/mui-edge.location.conf` 的转发配置（已有 `location /` 时替换该块），检查 `nginx -t` 后重载外层 Nginx。证书及 HTTPS 跳转继续由外层管理；内层不配置证书。远程 Agent 访问外部 HTTPS 地址。外层默认与前端容器在同一台主机；若在另一台主机或容器，调整上游地址和 `MUI_BIND`，并将内层入口限制为仅外层可访问。
3. 在有 Docker Buildx 的构建机运行 `deploy/build-agent.sh amd64` 和/或 `deploy/build-agent.sh arm64`。脚本默认构建 Agent 0.6.21 和 sing-box v1.14.2；第二个参数指定 sing-box 的 `vX.Y.Z` 版本，第三个参数指定 Agent 的 `X.Y.Z` 正式版本（如 `deploy/build-agent.sh amd64 v1.14.2 0.6.21`）。构建脚本要求 Git 工作区干净、提交中的 Agent 版本与指定版本一致。脚本构建带 `with_v2ray_api`、`with_clash_api` 的核心，同时构建 Agent，并生成 `SHA256SUMS`。默认本地发布模式把所需架构的整个 `bin/<架构>/` 目录放到**面板服务器**的仓库 `bin/` 下；GitHub 直下模式见下节。
4. 在 `deploy` 目录运行 `docker compose --env-file .env -f compose.yaml up -d --build`。内层 Nginx 提供页面及接口代理，Go 容器只读挂载 `../bin`，通过 Nginx 的 `/download/` 路径提供安装脚本和构建产物。当前 Compose 使用已有的外部网络 `docker_default`，启动前需确认网络存在。用 `docker network inspect docker_default --format '{{json .IPAM.Config}}'` 查看真实网段和网关；`MUI_PROXY_SUBNET` 仅作为 Go 的默认可信代理范围，填写实际网段或单独设置 `MUI_TRUSTED_PROXIES`，修改它不会创建或更改外部网络。`MUI_EDGE_PROXY_CIDR` 则填写外层 Nginx 的实际来源地址。
5. 目标机支持 Ubuntu 22.04/24.04/26.04、Debian 11/12/13（systemd），以及 Alpine 3.19+（OpenRC），需要 OpenSSH、`curl`、`sha256sum` 和 `ss`；GitHub 直下模式还需要 `tar`。Debian 11 从 Agent 0.6.20 起支持；0.6.19 的发行版检查仍会拒绝它。Debian 11 已结束官方 LTS 安全更新，建议升级至 Debian 12/13；若仍使用 Debian 11，应自行安排 Extended LTS。Alpine 依赖安装、服务管理及小内存机器优化见 [Agent 运维说明](docs/agent-operations.md)。UFW 托管时需安装 UFW（`apt-get install ufw`）；手动管理无需 UFW，安装 iproute2 提供 `ss`。Agent 0.6.3 起同时核对实际 SSH TCP 监听、SSH socket 和 `sshd -T` 配置，无法确认实际监听时拒绝初始化 UFW。LXC 内按容器真实监听端口放行，不能将宿主机映射端口当作容器端口。面板新建服务器时选择类型：带落地类型的下载并安装 Agent 与 sing-box；只做入口、线路、中转的只下载 Agent，不创建 sing-box 账户或服务。在目标机执行显示的一次性接入命令；命令先从面板获取小型安装脚本，再通过标准输入传递一次性接入 token；token 不会放进子进程参数，不需要手动设置环境变量。构建文件按已配置的发布模式从面板或 GitHub 下载，按 `SHA256SUMS` 和已配置的发布签名校验后安装。令牌 10 分钟有效；超时可重新生成。面板的 `MUI_PUBLIC_URL` 在面板服务器的 `.env` 中配置，必须是目标机可访问的 HTTPS 地址。
6. Agent 上线后，UFW 托管服务器在面板执行“初始化 UFW”；手动管理服务器跳过此步，自行配置宿主机或安全组放行。启用 UFW 会按默认策略拒绝 SSH 以外的入站连接；机器上若有别的对外服务，初始化后立即在防火墙页为它们添加允许规则。若机器上 firewalld、nftables、netfilter-persistent 或 shorewall 正在运行，Agent 会拒绝写入 UFW 并在面板提示冲突。AnyTLS 先上传对应域名的 PEM 证书链和私钥。端口从云安全组放行后才能从公网访问。

### 从 GitHub Release 直接下载 Agent

设置 `MUI_AGENT_RELEASE_VERSION=0.6.21` 后，在线接入命令仍从**当前面板**获取 `/download/install.sh`，脚本按第七个参数指定的版本让**目标服务器直接**从 GitHub Release 下载对应架构的压缩包并验证签名、哈希。Agent 0.6.19 起的一键升级也从 GitHub 下载。面板只读取归档以校验和显示可用构建，不向目标服务器提供二进制；`/download/<架构>/...` 在此模式下返回 404。接入和任务通信仍走面板。

目标服务器必须能访问 GitHub Release；访问不了时，为该服务器配置 Agent SOCKS5 代理，或使用“手工安装”把同一 Release 的归档上传到服务器。面板访问 GitHub 失败时，页面会快速显示错误，并在五分钟内复用该失败结果。旧的 `v0.6.18`、`v0.6.19`、`v0.6.20` 标签指向未包含 GitHub 分发代码的提交，不应再用于在线接入。

发布顺序：

1. 在包含安装脚本和 Agent 0.6.21 代码的**干净提交**上构建并签名 amd64、arm64：`./deploy/build-agent.sh amd64 v1.14.2 0.6.21` 和 `./deploy/build-agent.sh arm64 v1.14.2 0.6.21`。已固定发布公钥的 Agent 必须继续使用同一私钥。
2. 运行 `./deploy/release-agent.sh 0.6.21`；脚本检查工作区干净、提交内的 Agent 版本号和标签相同，再创建标签与 GitHub Release。确认两个归档均可下载，且标签指向构建所用的提交。
3. 然后把面板服务器 `deploy/.env` 中的 `MUI_AGENT_RELEASE_VERSION` 改为 `0.6.21`，确认 `MUI_RELEASE_PUBLIC_KEY` 与签名私钥匹配，再发布面板。版本号必须与 Release 标签一致；无需 `--with-agent`。未升级到支持 GitHub 下载的旧 Agent 需用新接入命令重装一次。

版本号固定到一个 Release，不会自动跟随 `latest`。发布后不要重新打包或替换归档，否则已缓存的摘要和服务器下载的文件可能不一致。

`MUI_EDGE_PROXY_CIDR` 填外层 Nginx 连接内层容器时的实际来源；Linux 宿主机 Nginx 通常对应 Docker 网桥网关，不能直接沿用示例地址。外层 Nginx 在其他容器、其他主机或 Docker Desktop 时同样需按实际来源调整。内层只信任该来源的客户端 IP 和 HTTP/HTTPS 转发头，再将确认后的信息传给 Go。`MUI_PUBLIC_URL` 始终填写外部 HTTPS 地址，以生成正确的订阅链接、安装命令和登录 Cookie。仅本机 HTTP 预览时才改为 `http://127.0.0.1:8086`。

前端更新可以单独执行 `docker compose --env-file .env -f compose.yaml up -d --build --no-deps mui-web`；后端更新将最后的服务名改为 `mui-service`。更新其中一个镜像不需要重新构建另一个。

### 多域名访问

后端 `.env` 的 `MUI_PUBLIC_URL` 支持用逗号分隔多个完整地址：

```dotenv
MUI_PUBLIC_URL=https://mui.example.com,https://mui-alt.example.com
```

- 第一个为默认地址。从列表中的域名访问面板时，新建/重新查看/轮换订阅链接、在线接入命令、手工安装命令和文件下载地址均使用当前域名；后端内部调用或无法识别公开域名时使用第一个地址。
- 各域名都可登录，Cookie 只属于当前域名，因此切换域名后需分别登录。生产域名使用 HTTPS；本地开发可配置 `http://127.0.0.1:5173`。
- 所有域名需配置 DNS、有效证书及外层 Nginx 的 `server_name`，并转发到同一个 MUI 服务。代理保留 `Host`（仓库中的 Nginx 配置已包含）；已有 Agent 继续使用接入时保存的单个地址。
- 修改 `.env` 后需重建后端容器，以更新容器环境；例如 `docker compose --env-file deploy/.env -f deploy/compose.yaml up -d --no-deps --force-recreate mui-service`（在项目根目录执行）。仅 `docker restart` 不会加载新的环境变量。

### 手工安装 Agent（目标机下载慢时）

在服务器列表点击 **首次接入 / 手动修复 → 手工安装**，也可在新建服务器后的接入弹窗中选择。文件在本机下载、再上传到目标机；目标机安装时只发送接入请求，不下载二进制。安装后仍需能访问面板，以便上报、接收任务和在线升级。

1. 在目标机运行 `uname -m`：`x86_64` 选择 **amd64**，`aarch64` 选择 **arm64**。选择的是目标服务器架构，不是下载用的电脑架构。
2. 在弹窗中下载全部文件，或复制“本机下载命令”在 macOS / Linux 电脑执行。两种架构均统一下载到本机 `~/mui-install/`，所选架构决定下载内容。所需文件：

   | 文件 | 用途 |
   |---|---|
   | `mui-agent` | Agent 主程序 |
   | `sing-box` | 仅落地类型需要，使用面板构建的核心 |
   | `SHA256SUMS` | 同一发布版本的文件摘要，必需 |
   | `SHA256SUMS.sig` | 面板启用发布签名时必需 |

   同一套文件必须来自同一架构、同一发布版本，不能混用其他渠道的 sing-box。默认本地发布模式的下载链接来自面板的 `/download/amd64/` 或 `/download/arm64/`；启用 GitHub 直下模式时，弹窗提供对应架构的 GitHub 归档，上传到目标机 `~/mui-install/` 后，手工安装命令会先解包再校验。下载链接不包含接入令牌。
3. 在目标机创建目录：

   ```bash
   mkdir -p ~/mui-install
   ```

   使用 SFTP 或 SCP，把第 2 步的**文件**全部上传到此目录，保留原文件名，不要再嵌套一层目录。例如在本机执行（替换 SSH 端口、用户名和目标地址）：

   ```bash
   scp -P 22 ~/mui-install/* root@目标服务器:~/mui-install/
   ```

4. 复制弹窗中的“手工安装命令”，在目标机用上传文件的同一用户执行。命令已包含服务器 ID、发布公钥和本次接入令牌，不需要设置环境变量；先检查文件和摘要，再调用本地 `mui-agent install` 验证签名、接入并安装 systemd 服务。root 不需要 sudo，普通用户自动使用 sudo。
5. 接入令牌有效期为 10 分钟，且只能使用一次。每次重新打开“首次接入 / 手动修复”都会生成新令牌，并让之前复制的命令立即失效。若上传耗时导致过期，关闭弹窗后重新生成命令即可；文件发布版本未改变时无需重复下载。修复安装会重启 Agent，运行中的 sing-box 也可能重启。

程序安装到 `/usr/local/bin/mui-agent`，配置保存在 `/etc/mui-agent/config.json`，服务为 `mui-agent` 和 `mui-agent-helper`；落地额外安装 `/usr/local/bin/sing-box` 与 `mui-sing-box` 服务。不要把临时目录中的接入命令或配置文件发给其他人。目标系统及依赖要求与在线安装一致：systemd、OpenSSH、iproute2（提供 `ss`），UFW 只在选择托管时需要。

### 完全离线转发（无需连接面板）

**Agent 下载入口**：“服务器”或“端口转发”页面右上角的“下载 Agent”，按目标服务器架构选择 amd64 / arm64。默认本地发布模式下载 `mui-agent`、`SHA256SUMS` 和签名文件；GitHub 直下模式下载对应架构的归档，解包后得到这些文件。离线配置弹窗也提供同一入口，无需先导出配置。

Agent 0.6.7 支持离线入口 / 中转参与面板链路和订阅。新建服务器时选“离线管理”，在面板保存链路或转发，再到服务器列表“离线配置”导出 `mui-offline.json`。把配置和对应架构的 Agent、摘要、签名上传到目标机，运行弹窗安装命令即可，无需回传文件。离线各跳导出当前配置、在线各跳和落地配置生效后，相关链路可进入订阅。面板只记录导出状态，目标机是否已应用或连通需自行确认；后续修改通过 `mui-agent offline apply` 加载新导出的配置。

离线目标机无需连接面板，只安装非 root 的 `mui-forward`，不需要 sing-box，不操作 UFW；端口和来源限制由宿主机 / 安全组等手动配置。面板显示已导出版本，无法获取实际应用结果、实时在线状态或入口流量；订阅用量仍由在线落地节点统计。也保留 `offline init/check/install/apply` 的独立 JSON 手工管理方式。
完整安装步骤、TCP/UDP、多目标主备/轮询和离线升级方法见 [完全离线转发指南](docs/offline-forwarding.md)。

### 从本机远程发布

使用 `deploy/publish.sh` 通过 SSH 上传源码，在目标 Linux 主机构建镜像并更新容器。本机需要 Bash、SSH 和 tar；目标机需要 Bash、Docker、支持 `up --wait-timeout` 的 Compose v2、tar 和 flock，SSH 用户需有目录写权限及 Docker 权限。使用 SSH 密钥或 ssh-agent；首次连接先用 SSH 确认目标机指纹。

```bash
cp deploy/publish.env.example deploy/publish.env
# 编辑 publish.env：SSH_HOST、SSH_PORT、可选 SSH_KEY、REMOTE_DIR（远程绝对路径，如 /root/docker/mui，不使用 ~ 或 $HOME）
# 编辑 deploy/.env，填写生产数据库、MUI_SECRET、管理员密码和公网 HTTPS 地址
./deploy/publish.sh --init-env deploy/.env  # 首次：远程已有 .env 时拒绝覆盖
./deploy/publish.sh                       # 后续：保留远程配置
./deploy/publish.sh --service frontend    # 只构建和更新前端
./deploy/publish.sh --service backend     # 只构建和更新后端
./deploy/publish.sh --with-agent          # 额外发布本地已构建的 Agent/sing-box 下载文件
```

默认读取 `deploy/publish.env`，也可用 `--config /path/to/publish.env` 指定不同目标的配置。该文件按 Bash 配置读取，不需要手动 `export`。业务配置始终保存在远程 `<REMOTE_DIR>/deploy/.env`，每次发布的源码保存在 `releases/`；成功后 `current` 指向本次版本，并自动删除更早的脚本发布目录，保留当前版和上一版供回退。发布失败时保留诊断目录，不清理旧版本；手工创建的目录不受影响。源码包不包含本地 `.env`、Git、证书目录或构建缓存。Agent 下载文件保存在远程 `bin/`，只有 `--with-agent` 才更新；它不会自动升级已接入服务器上的 Agent。启用发布签名时，先用相应私钥构建带签名的下载文件。

发布先校验 Compose、构建全部选定镜像，再更新容器并等待健康检查。含前端时还检查通过内层 Nginx 访问后端 `/healthz`。失败返回非零状态，保留诊断目录；已发生的容器更新及数据库迁移不会自动回退。脚本不创建 PostgreSQL、不修改外层 Nginx，也不创建外部 Docker 网络。当前 `compose.yaml` 使用已有的 `docker_default` 网络，请确保它存在，并将 `.env` 的可信代理地址配置为实际网络来源。

如果发布到已有 Compose 项目，`COMPOSE_PROJECT` 需填写原项目名；固定容器名属于其他项目时 Docker 会拒绝创建同名容器。前后端分机部署时，分别准备发布配置：前端设 `COMPOSE_FILES="compose.web.yaml"` 并传 `--service frontend`；后端需要发布内网端口时，设 `COMPOSE_FILES="compose.yaml compose.backend.yaml"` 并传 `--service backend`。

脚本离线测试：`python3 deploy/test-publish.py`（模拟 SSH/Docker，不连接真实服务器）。

### 前后端部署到不同服务器

后端服务器：使用 `deploy/.env.example` 配置数据库和密钥，设置 `MUI_BACKEND_BIND=10.0.0.10:8087`（替换成后端内网 IP）、`MUI_TRUSTED_PROXIES=10.0.0.20/32`（替换成 Nginx 实际来源 IP），`MUI_PUBLIC_URL` 仍填写前端 HTTPS 域名。启动：

```bash
cd deploy
docker compose --env-file .env -f compose.yaml -f compose.backend.yaml up -d --build mui-service
```

前端服务器：复制 `deploy/web.env.example` 为 `deploy/.env`，填写 `MUI_BACKEND_URL=http://10.0.0.10:8087`，让已有外层 Nginx 转发到该主机的 `127.0.0.1:8086`，然后启动：

```bash
cd deploy
docker compose --env-file .env -f compose.web.yaml up -d --build
```

前端 `.env` 只需要上游地址、监听地址及代理网络配置。跨服务器的明文 HTTP 上游用于受信任内网；使用 HTTPS 上游时，Nginx 会校验证书。`MUI_BACKEND_URL` 只填写协议和主机端口，不加路径或末尾斜线。

### 使用宿主机 Nginx

Go 后端可直接通过 `go run ./cmd/server` 或编译后的二进制运行，生产 `.env` 设置 `MUI_LISTEN=127.0.0.1:8087`。前端在 `web/` 执行 `npm ci && npm run build` 后，将 `web/dist/` 内容复制到 `/var/www/mui/`。将 `deploy/nginx/routes.conf` 放到 `/etc/nginx/mui/routes.conf`，将 `deploy/nginx/mui-host.conf` 放到 `/etc/nginx/conf.d/mui.conf`，内层默认只监听 `127.0.0.1:8086`，修改 Go 后端地址，外层转发到该端口。内层只信任同机外层 Nginx，外层在别处时需调整监听地址和可信代理 IP。后端 `.env` 的 `MUI_PUBLIC_URL` 填公开 HTTPS 地址，`MUI_TRUSTED_PROXIES` 填 Nginx 的来源 IP（同机为 `127.0.0.1/32`）。执行 `nginx -t` 后重载 Nginx。

Agent 独立安装并运行 `mui-agent-helper.service`（root，仅接受本机 Agent 的白名单操作）和 `mui-agent.service`（账户 `mui-agent`），无需 sing-box 或转发进程。添加第一条启用的转发规则后，Agent 才创建并启动 `mui-forward.service`（账户 `mui-forward`）；最后一条规则停用或删除后，服务会停止并禁用。落地服务器另安装 `mui-sing-box.service`（账户 `mui-core`）；中转服务器建节点时可按需安装该核心。排查时可用 `journalctl -u mui-agent -u mui-agent-helper -f`，有转发时再加 `-u mui-forward`，落地服务器再加 `-u mui-sing-box`。Agent 配置在 `/etc/mui-agent`，核心配置与证书在 `/etc/mui-core`，转发配置在 `/etc/mui-forward`，统计缓存在 `/var/lib/mui-agent`。已有 PostgreSQL 的备份与恢复见下文“备份与恢复”。

同一 `mui-agent` 进程还可向 Komari 面板上报监控数据并执行 TCP Ping，无需另起 `komari-agent`。在左侧“设置”填写全局 Komari 地址，在各服务器配置中填写对应 token；Agent 安装后自动领取，没有 token 就不启动 Komari 上报。安全范围见 [Komari 接入说明](docs/komari-agent.md)。

在线中转服务器也可创建节点：先在服务器列表或新建节点弹窗点击“安装 sing-box”，成功后保留中转类型，节点支持订阅并可作为链路终点。纯转发中转接入时仍只安装 Agent。入口、线路服务器点击“安装 sing-box 并设为落地”后会添加落地类型。有节点时必须保留中转或落地类型，已安装的 sing-box 不会自动卸载。

服务器类型可在安装核心前保存，例如同时勾选中转和落地。已接入但未安装 sing-box 时，编辑服务器和新建节点弹窗会提供安装入口；安装完成后才能创建节点。保存失败的接口错误在编辑弹窗内直接显示，表单内容保留。

应用配置变更时，只有节点配置或证书发生变化才会重启 sing-box；转发规则变化由转发进程就地重新加载，只有新增、修改或删除的那条规则受影响，其余转发的连接不中断；单独升级 sing-box 也会重启核心，同机节点连接会短暂中断。仅防火墙规则变化不会重启这两个服务。UFW 规则按差异增删；节点或链路访问策略变化时，Agent 可能重新排列优先规则，不重启服务。

Agent **0.6.15** 起（修复 0.6.14 的所有来源规则冲突），UFW 托管的节点和链路端口使用优先策略：已有同端口、端口范围或全端口的 UFW 允许/拒绝规则不再阻止链路下发。指定来源先放行，再拒绝其他来源，因此旧的宽泛允许规则不能绕过来源限制。主机原规则保留；移除链路转发后恢复原规则，落地节点仍按节点访问策略处理。实际 SSH 端口不允许被链路接管，端口被其他进程占用仍需解决进程冲突。手动管理防火墙不受影响。升级后的首次上报会自动重新下发已有节点/转发配置。

服务器离线后可在面板强制删除，连同它的节点、转发、规则和流量记录；统一证书库中的证书会保留。Agent 凭据可在服务器列表中吊销；重新生成接入命令并在目标机再次执行安装即可轮换。

## 配置

| 变量 | 用途 |
|---|---|
| `MUI_SECRET` | 数据加密密钥来源；必须长期稳定且至少 32 个随机字节 |
| `MUI_ADMIN_PASSWORD` | 首次启动时设置管理员密码，至少 12 字符；之后在“设置”页修改 |
| `MUI_ADMIN_RESET` | 一次性重置开关，**不要**写进 `.env` 或 compose 文件。用法见下文“忘记密码”。设为 `1` 启动一次：把密码重置为 `MUI_ADMIN_PASSWORD`、清除 TOTP 并注销所有会话；重置完成后必须去掉该变量再重启一次，否则每次重启都会再次重置 |
| `MUI_DB_PASSWORD` | PostgreSQL 用户密码；已有数据库的登录密码，只配置这一份值 |
| `MUI_DB_HOST` / `MUI_DB_PORT` | PostgreSQL 地址，默认 `127.0.0.1:5432`；本地开发使用 `127.0.0.1:55432` |
| `MUI_DB_NAME` / `MUI_DB_USER` | 数据库名和用户，默认均为 `mui` |
| `MUI_DB_SSLMODE` | PostgreSQL SSL 模式；默认 `require`，本地及生产 Compose 使用 `disable` |
| `MUI_DB_URL` | 可选完整连接 URL，优先于上述分项配置；未配置任何 PostgreSQL 参数时使用 SQLite `data/mui.db` |
| `MUI_PUBLIC_URL` | 对外 HTTPS 地址，支持逗号分隔多个；第一个为默认，链接随当前已配置域名生成，见“多域名访问” |
| `MUI_AGENT_BIN_DIR` | 安装文件目录，默认 `bin`；按 `amd64`、`arm64` 子目录存放三个构建产物 |
| `MUI_AGENT_RELEASE_VERSION` | 设置如 `0.6.21` 后启用 GitHub Release 直下；要求 `MUI_RELEASE_PUBLIC_KEY`，目标服务器直接下载对应版本的归档，面板不再提供二进制下载 |
| `MUI_LISTEN` | Go 后端监听地址，生产容器为 `:8087`；本地开发使用 `127.0.0.1:8080` |
| `MUI_BIND` | Nginx 前端 HTTP 的宿主机端口映射，默认 `127.0.0.1:8086` → Nginx 容器 `:8086`，供已有外层 Nginx 转发 |
| `MUI_BACKEND_URL` | Nginx 的 Go 上游地址，默认 `http://mui-service:8087`；可指向另一台服务器，不加末尾斜线 |
| `MUI_BACKEND_BIND` | Go 后端宿主机端口映射，默认 `127.0.0.1:8087` |
| `MUI_PROXY_SUBNET` | Compose 前后端网络，默认 `172.30.17.0/24`；已有 PostgreSQL 不由生产 Compose 管理 |
| `MUI_DNS_RESOLVER` | Nginx 用于重新解析后端域名的 DNS，Docker 默认 `127.0.0.11` |
| `MUI_EDGE_PROXY_CIDR` | 内层 Nginx 只采信该来源的客户端 IP 和协议头；Compose 默认 `172.30.17.1/32`（Linux 宿主机外层 Nginx） |
| `MUI_TLS_CERT` / `MUI_TLS_KEY` | Go 二进制直接运行时可选的后端 HTTPS 证书；标准部署的公网 TLS 由已有外层 Nginx 提供 |
| `MUI_TRUSTED_PROXIES` | 逗号分隔的反向代理 IP 或 CIDR；仅来自这些地址的 `X-Forwarded-For` 会被采信 |
| `MUI_RELEASE_PUBLIC_KEY` | 发布签名公钥（见下文“发布签名”）。设置后接入命令会让 Agent 固定该公钥，面板也只提供带有效签名的构建 |
| `MUI_TRAFFIC_RETENTION_DAYS` | 原始流量采样、订阅访问与节点连接 IP 保留天数，默认 90（最少 32），`0` 为永久保留；累计流量不受影响 |

Agent 与面板通过 HTTPS 加随机 256 位 Agent 令牌鉴权；接入令牌仅使用一次。面板数据路径 `/api`、订阅 `/s/{token}`、Agent `/agent`，安装文件 `/download` 为公开只读路径且不包含接入令牌。不要将面板直接暴露为明文 HTTP。

登录限速只统计失败的尝试，按客户端地址计数（每分钟 10 次）；密码正确但动态验证码连续错 5 次会锁定第二因素 5 分钟（不分来源地址），同一验证码只接受一次。订阅下载每个地址每分钟 120 次；Agent 与 sing-box 二进制的下载每个地址每分钟 20 次、全站同时最多 4 个（慢连接会一直占用槽位直至完成或断开）。节点密码、ShadowTLS 密码、模板密码、证书私钥、排队任务中的配置快照和 TOTP 密钥均加密保存，任务完成后快照即被清除。多个节点使用同一模板密码时会共享该凭据；需要每节点独立凭据时将模板密码留空。

早期 Agent 构建在未启用签名时，自更新仍会错误请求 `SHA256SUMS.sig` 并报 404。遇到此错误，先发布修复后的 Agent 文件，再在面板重新生成接入命令并在目标服务器执行一次；旧进程无法通过自身有缺陷的升级流程完成这次修复。之后未固定公钥的 Agent 仅校验文件与清单中的 SHA-256，已固定公钥的 Agent 仍强制校验签名。

## 发布签名

Agent 自升级时，root 权限的 helper 会下载并运行面板提供的二进制。不启用签名时，能改动面板 `bin/` 目录的人就能在所有受管服务器上以 root 执行代码。启用签名后，Agent 只接受由离线私钥签过清单的构建。

**威胁模型（请勿夸大）**：签名防的是“构建产物被篡改 / 镜像投毒”——即攻击者只能写 `bin/`、改不了面板代码、配置和安装命令的场景。面板整体被攻破（代码、配置、安装命令被改）时，签名不提供保护，攻击者仍可下发自己的二进制。安装命令会从面板 HTTPS 下载安装脚本，再自动判断执行身份：root 使用 `sh`，普通用户使用 `sudo sh`，无 sudo 时提示切换到 root；安装脚本未签名，其信任根就是面板 HTTPS + 面板本身；只在受信任的面板和目标机上执行，不要转发给他人。

1. 在构建机生成密钥：`mkdir -p deploy/.secrets && chmod 700 deploy/.secrets`，然后运行 `go run ./cmd/release-sign keygen deploy/.secrets/release.key`。命令会打印 `MUI_RELEASE_PUBLIC_KEY=...`，私钥仅留在构建机并备份。`deploy/.secrets/` 已排除 Git、Docker 构建和远程发布上传。
2. `deploy/build-agent.sh amd64` 自动使用 `deploy/.secrets/release.key` 签名，生成 `bin/<架构>/SHA256SUMS.sig`。`deploy/publish.sh --with-agent` 也会在上传前用同一把本地私钥重新签名，不需要手动设置环境变量。使用其他私钥位置时，可在 `deploy/publish.env` 中填写 `MUI_RELEASE_KEY` 的绝对路径；指定的私钥不存在或签名失败会停止发布。如需钉死上游 sing-box 源码：`SING_BOX_COMMIT=<该 tag 对应的 commit> deploy/build-agent.sh amd64`，commit 用 `git ls-remote https://github.com/SagerNet/sing-box.git "refs/tags/v1.14.2^{}"` 查询；不填时只校验 tag，tag 被移动则构建物会变。
3. 把公钥写进面板的 `MUI_RELEASE_PUBLIC_KEY` 并重启。此后生成的接入命令会把公钥交给 Agent，Agent 安装时校验签名并把公钥固定在 `/etc/mui-agent/release.pub`。
4. 已接入的服务器需要用新的接入命令重新安装一次才会固定公钥；服务器列表里会显示“升级需发布签名”或“升级未启用签名校验”。固定后重新安装不能更换公钥，确需更换时先在该服务器上删除 `/etc/mui-agent/release.pub`。

私钥丢失后无法再给已固定公钥的 Agent 升级，只能逐台删除公钥文件后重新接入。

接入命令不需要手动设置环境变量；一次性令牌通过标准输入传入，10 分钟内使用一次后即失效。令牌不放进子进程参数，但可能留在终端历史；请只在受信任的目标机上执行，不要转发给他人。

## 忘记密码

忘记管理员密码或丢失验证器时，用一次性重置流程（不要把 `MUI_ADMIN_RESET` 写进 `.env` 或 compose 文件）：

```bash
cd deploy
MUI_ADMIN_RESET=1 docker compose --env-file .env up -d mui-service
# 用 MUI_ADMIN_PASSWORD 登录一次，确认 TOTP 已清除；然后去掉变量再重启一次，清除重置状态：
docker compose --env-file .env up -d mui-service
```

重置会把密码设为 `MUI_ADMIN_PASSWORD`、清除 TOTP 并注销所有会话。登录后请立即在“设置”页改一个新密码。

## 备份与恢复

生产 Compose 不提供数据库及定时备份服务，使用已有 PostgreSQL 的备份策略。可在能访问该实例且装有 PostgreSQL 客户端的机器上执行（示例中的 `db.example.com:5432`、用户及库名需替换为实际配置；`-W` 交互输入密码）：

```bash
pg_dump -h db.example.com -p 5432 -U mui -W -d mui -Fc -f mui.dump
```

恢复时先停止 `mui-service`，使用数据库管理工具将备份恢复到准备好的数据库，确认连接配置后再启动后端：

```bash
pg_restore -h db.example.com -p 5432 -U mui -W -d mui --no-owner mui.dump
```

`MUI_SECRET` 不在数据库备份的保护范围内：它丢失后，备份里的节点密钥、证书私钥等加密数据无法解密。请把 `MUI_SECRET` 与数据库备份分开、离线保存。

## 链路

服务器有四种类型，可多选：**入口**只能做链路首跳；**线路**可做首跳也可做中间跳；**中转**可做中间跳，也可按需安装 sing-box 搭建节点；**落地**接入时安装 sing-box 并搭建节点。入口和线路是订阅的接入点。

一条链路由首跳服务器、零到八跳中间跳和一个落地节点组成，例如“入口 → 中转 → 中转 → 落地”“线路 → 中转 → 落地”“入口 → 中转 → 线路 → 落地”。保存链路后面板在每一跳自动生成端口转发（SS 节点生成 TCP 和 UDP 两条），这些转发在“端口转发”页只读，修改请编辑链路。

- **监听**：链路转发使用双栈通配监听；系统支持 IPv6 时可接收 IPv4 和 IPv6，只有 IPv4 的系统继续监听 IPv4。
- **端口**：整条链路所有跳使用同一个端口。留空时优先使用落地节点的端口，它在某一跳被占用时自动换一个每一跳都空闲的随机端口；手填的端口被占用会直接报错。
- **负载均衡**：一跳选多台服务器即为一组，上一跳把新连接发给其中健康的服务器。主备模式优先用排在前面的，轮询模式轮流分配。转发进程每 5 秒用 TCP 连接探测各台，连续 2 次失败即停用，连续 2 次成功即恢复；客户端连接某台失败时立即停用该台并改连下一台。UDP 会话在所用服务器停用时迁移到可用的服务器，主备模式下首选服务器恢复后迁回。
- **内网地址**：服务器填写内网地址后，每段链路的“连接地址”可选择接收方的公网或内网地址。每段的“防火墙来源”独立选择发送方的公网或内网 IP，默认按连接地址类型选择；还可选择放行 IPv4、IPv6 或两者，新建链路默认 IPv4，旧链路保留原来的按接收地址族选择行为。界面展示双方机器名和具体地址。专线访问下一跳公网地址、实际来源却是入口内网 IP 时，保留公网目标并选择“发送方内网 IP”。来源选项只控制放行规则，不绑定出站地址；需要来源限制时，发送方必须填写实际 IP，仅有域名无法生成规则。
- **防火墙**：以下自动规则仅用于 UFW 托管服务器；手动管理服务器由管理员配置访问限制。首跳端口对所有来源开放；中间跳只放行所选类型的上一跳服务器地址；节点未开启“允许直连”时，端口放行链路最后一跳，以及使用此 SOCKS5 的 Agent 来源；两者都没有时不对外开放。Agent 使用 SOCKS5 不要求开启客户端直连。公网来源使用填写的公网 IPv4/IPv6 和 Agent 检测到的同地址族地址，内网来源使用发送方的内网 IP。服务器的出口 IP 与填写的公网 IP 不一致时（例如 NAT 机），请把出口 IP 填进公网 IPv4，否则下一跳会拒绝它的连接。
- **订阅**：订阅可以包含链路和开启“允许直连”的节点。链路条目的地址是首跳服务器的订阅域名或公网地址、端口是链路端口，协议、登录凭据和 TLS 名称来自落地节点，所以流量仍按订阅统计。首跳和每组至少一台服务器的转发生效、落地节点已应用该订阅的登录且防火墙已放行最后一跳后，链路才会出现在订阅里。
- 节点、服务器和链路互相引用时，被链路使用的节点和服务器不能删除，被订阅使用的链路不能删除，正在被链路使用的服务器不能去掉对应类型。

## 端口转发的行为与限制

- **TCP**：Linux 上数据在内核里直接从一条连接转到另一条（splice），不经过转发进程，空闲连接不占用缓冲区。流量计数和活动时间每 10 秒更新一次。连续 1 小时双向都没有数据的连接会被关闭。
- **UDP**：每个来源地址和端口对应一个会话，2 分钟没有数据即回收。会话的接收缓冲区从 2 KB 起步，遇到更大的报文时那一个报文会被丢弃，随后该会话改用 64 KB 缓冲区。
- **目标填域名时**：转发进程先监听端口，再在后台解析目标域名，之后每 30 秒重新解析一次。首次解析完成前的连接或报文可能失败；新建的 TCP 连接和 UDP 会话随后使用最新地址，解析失败时沿用上一次的结果。域名指向新地址后，已有的 UDP 会话会被关闭并在客户端下一个报文到来时连到新地址；已建立的 TCP 连接不会被主动切断，旧地址失效后由 TCP 保活机制自行结束。一个地址在连续两次解析结果里都不出现才算“已更换”，在多条记录间轮换的域名不会被误判。
- **上限**：每条规则最多 4096 条 TCP 连接、2048 个 UDP 会话，其中单个来源 IP 最多占一半；整个进程最多 8192 条 TCP 连接、4096 个 UDP 会话。超出的新连接被拒绝，不影响已有连接和其他规则。systemd 单元另设 `MemoryMax=384M` 作为兜底。
- **多个目标**：见上文“链路”中的负载均衡说明；手动 TCP 转发默认进行 TCP 主动探测。纯 UDP 转发默认不发送 TCP 探测，通过套接字错误（例如 ICMP 端口不可达）停用故障目标，10 秒后允许重试，主备模式的现有会话也会重试首选目标；单纯没有回复不能证明目标故障。目标提供同端口 TCP 服务时，可在 UDP 表单中启用 TCP 探测，使用上述连续两次判定的机制。轮询模式在所有目标暂时不可用时仍会轮流尝试，避免固定在第一台。
- 以上上限目前写死在程序里，没有做成面板可调。经由另一台中转机接入、所有连接来自同一个 IP 的场景，单规则并发超过 2048 条时会触到来源上限。

## 协议与客户端说明

- 新建 Snell 节点必须填写 ShadowTLS v3 SNI / 握手域名，指向服务器可访问的真实 TLS 站点（服务器握手目标端口为 443）。面板为 Snell PSK 和 ShadowTLS 密码分别生成并加密保存；公网只监听 ShadowTLS 端口，认证后的连接转给内部 Snell 入站。sing-box 订阅使用 Snell 出站 `detour` 到 ShadowTLS 出站，并为每条订阅生成独立的 ShadowTLS 密码；Surge 订阅输出 `shadow-tls-password`、`shadow-tls-sni` 和 `shadow-tls-version=3`。Surge 这一行的写法已用 sing-box 客户端按同样的凭据验证可连通，但没有在真实 Surge 上测试过。
- Snell 新建节点和模板默认 v6，可选择 v5；服务端按节点版本生成配置，Surge 输出对应的 version=5/6。sing-box v6 出站输出 version=6；仅 v5 TCP 节点使用 v4 出站兼容协议。Snell v6 PSK 为 12–255 字节，需要 Agent 0.6.11；版本变更成功应用前不下发新的客户端配置。Snell v5 的 QUIC Proxy Mode 不支持。
- AnyTLS 需要有效证书，客户端订阅使用域名进行 TLS 校验。证书目前由管理员上传和更新。在证书页直接选择 Nginx 的 `ssl_certificate` 对应 `.pem` / `.crt` 文件及 `ssl_certificate_key` 对应 `.key` 文件，也可粘贴 PEM。一个证书文件可以包含完整证书链，无需拆分；支持 RSA PKCS#1、PKCS#8 和 EC 私钥。名称和域名可留空，从证书 SAN 自动读取；保存时检查配对、有效期和服务器用途，私钥加密保存。通配符和多域名证书按真实 SAN 范围匹配 AnyTLS 的 TLS 域名。
- sing-box 下载内容是节点出站 JSON，供支持导入出站片段的客户端使用；Surge 下载内容是 `[Proxy]` 片段。
- 订阅流量按独立登录用户采样，能分别统计同节点的不同订阅；客户流量为其当前关联订阅的合计。节点可开启“单用户”以沿用原有节点凭据，所有订阅共用该凭据，不生成订阅用户，旧版 Agent 也能下发；未开启的现有节点继续使用独立用户。单用户节点与传统 SS 的共享密码节点仅统计节点总流量，不能按订阅或客户归属；撤销已导入客户端的访问需更换节点密码。订阅链接轮换只换下载令牌，不轮换节点登录凭据。独立用户节点停用、删除或到期会排队移除该订阅的用户；Agent 离线时连接凭据要等 Agent 恢复并应用配置后才失效。节点级流量还包括管理员直接分享节点产生的流量，因此节点合计可高于订阅合计。界面显示共享凭据的统计限制，不将无法归属的流量当成 0 B。
- 节点流量是 sing-box 入站处理字节，不等于云服务商计费流量。断电前最后一次采样可能丢失。没有目标 Linux 服务器时，无法替代真实客户端连通性及 UFW 联调。
- 转发流量为转发进程成功写入两侧连接的字节累计值，不含 TCP/IP 头部和握手。进程异常退出前尚未上报的最后一段流量可能丢失。目标地址可达性在建立连接时决定；“已生效”表示监听成功，不表示目标服务一直健康。自有程序也不能保证不会被安全软件误判。

## 验证

```bash
go test ./...
cd web && npm run build
```

接口级测试覆盖接入令牌、任务领取与回报、节点与转发状态、流量入库与去重、订阅、节点删除确认、强制删除、限速、密码与 TOTP 管理；Agent 的 UFW 规则排序与差异计算、Snell 订阅兼容字段及统计 API 编码另有单元测试。转发器另有 TCP/UDP 回环测试。接口测试只在 SQLite 上运行，PostgreSQL 路径需在部署环境中验证。目标机安装后仍应分别用 SS、Snell、AnyTLS 客户端检查 TCP/UDP 连通、流量增长、UFW 规则和订阅导入，并测试转发目标的实际可达性。

### 截图与手动刷新

右上角盾牌按钮开启截图脱敏，名称替换为编号，地址、链接和凭据隐藏，表单暂时只读；关闭后恢复原显示，不修改数据或复制内容。刷新按钮显示加载状态，完成或部分失败后给出提示。

Snell 节点与模板支持指定内层端口，仅监听 `127.0.0.1`，不再由系统选择随机端口。修改后提交配置，并升级目标 Agent 至 0.6.2。

Agent 安装器显式设置目录权限，并以 `mui-agent` 账户检查配置读取，支持从 `umask 077` 的安装命令接入。

### SOCKS5 节点与 Agent 代理

支持带用户名密码的 SOCKS5 TCP 节点，必须在已启用 UFW 的托管服务器部署。所有在线服务器（入口、线路、中转、落地）均可选择其他服务器上的 SOCKS5 节点，以公网或内网地址连接，经代理安装、接入、上报、取任务及下载升级文件。节点手填端口支持 1–65535，随机生成保留 50000–60000。需要 Agent 0.6.10 或更高版本；取消服务器类型限制仅需更新面板前后端，操作步骤见 [SOCKS5 与 Agent 代理说明](docs/agent-socks5.md)。

### Snell v6 配置修复（Agent 0.6.11）

Snell v5 使用 `obfs_mode`；v6 使用默认流量整形 `mode: default`，不能包含 `obfs_mode`。Agent 0.6.11 修复了服务端生成字段，订阅也同步按版本生成，v6 表单不再提供 HTTP 混淆选项。发布 `./deploy/publish.sh --with-agent` 后升级受影响服务器 Agent，再在操作记录重试失败的配置应用任务。核心仍使用已验证的 sing-box v1.14.2，无需升级核心。

### 节点出口网卡（Agent 0.6.12+）

- 新建或编辑服务器 → **网络与防火墙 → 节点默认出口网卡**：例如 `ppp0`。留空使用系统路由。
- 新建或编辑节点 → **节点出口**：继承服务器、使用系统路由、指定出口网卡。节点覆盖优先于服务器默认；模版不保存机器专属网卡。
- 面板生成 sing-box `direct` 出站的 `bind_interface`，并为节点覆盖生成按入站匹配的路由规则。Agent 0.6.17 的 Snell + ShadowTLS 伪装握手独立使用系统路由，代理业务流量仍绑定所选出口，内层仍监听 `127.0.0.1`。升级后的首次上报会为已指定出口的 Snell + ShadowTLS 节点自动重新下发配置。
- 仅影响 sing-box 节点的对外连接，不修改系统路由，不改变 Agent 与面板的通信或 Go 端口转发。域名解析仍沿用服务器的 DNS 设置。
- Agent 应用前检查网卡存在且已启用；失败时保留原配置。运行中指定网卡断开，绑定的连接不会自动改走其他网卡。请先确保该网卡自身的路由与对端可用。
- 保存服务器默认会重新应用配置，影响实际出口变化的节点；修改核心配置会重启 sing-box 并中断现有连接。旧 Agent 的应用任务保留排队，升级至 0.6.12 后自动继续。

### 链路客户端 IP（Agent 0.6.13+）

- “节点连接 IP”中的入口连接来源由在线首跳的 TCP/UDP 转发采集，独立于节点协议，支持经链路连接的 Snell + ShadowTLS。这些来源可能包含扫描、认证失败和正常访问，界面标记为未验证；不会依据订阅包含这条链路就推断来源使用了该订阅。首跳需升级 Agent 至 0.6.13；首次上报后面板自动下发采集配置，数据一般在 30 秒内上报。
- “采集服务器”是看到原始连接的入口；节点与链路列指明转发去向。落地采样中的中转、Agent 对端地址单独显示，不作为客户端 IP，也不会用订阅下载 IP 猜测替代。
- 离线入口、外部未受面板管理的转发、旧版本入口无法提供客户端 IP；历史对端记录无法还原。入口只能看到连接它的来源地址，例如客户端路由器的 NAT 公网 IP；无法穿透外部 NAT 或额外的转发恢复设备私网地址。
- 入口来源是传输层观察，未验证代理登录，可能包含探测连接；不显示基于链路成员关系推测的订阅归属。直连节点仍使用 sing-box 实时采样，短连接可能漏采；同时用于链路的节点，仅凭落地对端无法确定客户端路径。
- 转发进程每 5 秒发布采集结果，最多保留最近 500 个来源、2 分钟；不在每个数据包上扫描会话，不增加进程。记录沿用数据保留策略，后端启动自动创建带 `mui_` 前缀的新表。
