# MUI 节点管理面板

React + Go 的多服务器节点面板，前端由 Nginx 独立部署，Go 后端提供接口。每台 Linux 服务器运行 Go Agent 和一个 sing-box 实例，面板负责期望配置、任务、流量与订阅；Agent 只主动连向面板，不开放远程控制端口。首版支持 Shadowsocks、Snell v5、AnyTLS 和 UFW。

## 功能

- 服务器档案：名称、国家、地区、城市、服务商、标签、备注、IPv4/IPv6、订阅域名，以及类型（入口、线路、中转、落地，可多选）和内网地址；一次性接入令牌、在线状态、系统、架构、核心/Agent 版本、UFW 和统计状态。
- 节点：增删改、启停、端口冲突检查、SS 2022 密钥校验、AnyTLS 证书上传与验证；新建节点及模板的端口默认在 50000–60000 范围，可点击骰子按钮重新随机生成，新建节点会避开已知的同服务器节点和 SSH 端口；Agent 校验 sing-box 配置、管理端口规则、重启并探测监听，失败回滚。
- 节点模板：保存 SS、Snell 或 AnyTLS 的常用协议、端口、连接参数及可选密码 / PSK；Snell 模板还可保存 ShadowTLS v3 的 SNI / 握手域名与独立密码。模板密钥加密存储，选用时填入新节点表单；模板未保存密码时，表单会为新节点生成并显示独立密码。SS 2022 生成按钮按加密方式产生 16 或 32 字节的 Base64 密钥；AnyTLS 证书按服务器与域名匹配。UFW 放行策略只在具体节点上设置，不随模板保存或带入。支持从现有节点保存模板，以及编辑、删除模板；修改模板不会改动已创建的节点。
- 流量：按节点入站 tag 和订阅用户分别从 sing-box V2Ray API 采样上/下行；Agent 本地缓存、实例重启识别、幂等上报。节点和订阅各有累计流量与近 24 小时折线图。Agent 还读取默认网卡的收发字节，面板显示服务器网络累计流量。
- 订阅：sing-box JSON 出站和 Surge `[Proxy]` 片段；内容是链路和开启“允许直连”的节点，启停、到期、令牌轮换和删除。订阅配置里节点显示名为“节点名称-ID 前 8 位”（不是纯节点名称）。每条订阅在 SS 2022、AnyTLS、Snell v5 节点上使用独立用户凭据，同节点可供多条订阅使用。SS 2022 客户端密码为“服务器密钥:用户密钥”；经 ShadowTLS v3 接入的 Snell 节点由每条订阅独立的 ShadowTLS 密码鉴权，Snell 本身保持单用户，因此 Surge 等原生客户端也能使用，流量仍按订阅统计（需要 Agent 0.6.0；更早的 Agent 仍要求 sing-box 专有的 `userkey`，这类节点不会出现在 Surge 订阅里）。订阅只下发其配置已在服务器上生效的节点：某台服务器离线或有变更尚未应用时，只有受影响的节点暂不下发，其余节点照常提供；全部节点都在等待生效时返回 503 让客户端稍后重试。订阅链接加密保存，可随时在列表中再次查看。Surge 订阅支持 AES-GCM 的 SS 2022 节点和启用 ShadowTLS 的 Snell 节点；AnyTLS 使用 sing-box 订阅。非 2022 的 SS 节点不能加入订阅。

  **新建、编辑、启停、删除订阅以及订阅到期，都会让所选节点所在服务器的 sing-box 重启一次以更新登录凭据，该服务器上所有连接会中断数秒。** sing-box 没有不重启增删用户的办法。到期日按所选日期当天 23:59:59 生效，自动重启因此发生在午夜前后。
- 客户端管理：客户可关联多条订阅，客户页汇总这些订阅的流量。成功下载订阅时记录来源 IP、订阅和客户；Agent 从 sing-box 本机 Clash API 每 10 秒采样活跃节点连接的来源 IP，页面分别展示两类记录。连接快照可能漏掉短连接；订阅用户流量由登录凭据识别，不依赖来源 IP。
- UFW：初始化时先放行检测到的 SSH 端口；每个节点可选择自动放行所有来源、仅放行指定 IP/CIDR（最多 32 个），或不生成自动规则并用自定义规则管理。SS 自动规则覆盖 TCP/UDP，Snell 与 AnyTLS 覆盖 TCP；只清理带 `mui-` 标记的规则。指定来源模式要求 UFW 默认入站策略为 deny/reject；已有的其他 UFW 允许规则及云安全组仍会影响实际访问。指定来源和手动管理模式可以先保存；旧 Agent 不会领取相关配置任务，升级至支持该功能的版本并上报能力后才会应用。升级前原有 UFW 放行规则仍会生效。
- 链路：入口或线路 → 若干跳中转（每跳可多台负载均衡）→ 落地节点，面板在每一跳自动生成转发，详见下文“链路”。
- 端口转发：在面板为服务器添加 TCP/UDP 监听端口和一个或多个目标地址与端口（多个目标时主备或轮询，支持 TCP 主动探测或 UDP 被动检查）；支持启停、编辑、删除、累计上/下行统计。**新建转发默认仅放行指定来源（restricted）**，需管理员显式确认才会公开放行所有来源；UFW 未启用或检测到其他防火墙工具时，转发页会展示 error 横幅。UDP 会话以客户端地址为键、无认证，源地址可被伪造并可能被用于反射，属于 UDP 协议固有风险——不要把转发端口当作认证边界。Agent 使用同一个 `mui-agent` 二进制启动独立的 `mui-forward.service`，进程运行在 `mui-forward` 账户下。TCP 在转发机终止客户端连接并向目标新建连接，因此转发机发送数据的 TCP 段可使用该机的拥塞控制算法（如 BBR）；UDP 使用按客户端地址维护的会话。转发规则会检查节点、SSH 和其他转发的监听端口冲突。尚未升级的 Agent 可以先保存规则，能力上报后自动应用；升级任务不会被待应用规则阻塞。
- 管理：密码登录与修改、TOTP 启用与关闭、审计、操作记录、失败重试、Agent 凭据吊销、节点密钥加密存储。支持面板分别一键升级 Agent 和 sing-box；非落地服务器可在面板上一键安装 sing-box 并成为落地。Agent 升级不重启 sing-box，sing-box 升级会短暂中断该服务器上的节点连接。

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
3. 在有 Docker Buildx 的构建机运行 `deploy/build-agent.sh amd64` 和/或 `deploy/build-agent.sh arm64`。脚本默认构建 sing-box v1.14.2；指定经测试的新版本时，把 `vX.Y.Z` 版本标签作为第二个参数。脚本构建带 `with_v2ray_api`、`with_clash_api` 的核心，同时构建 Agent，并生成 `SHA256SUMS`。把所需架构的整个 `bin/<架构>/` 目录放到**面板服务器**的仓库 `bin/` 下，无需复制到每台目标服务器。
4. 在 `deploy` 目录运行 `docker compose --env-file .env -f compose.yaml up -d --build`。内层 Nginx 提供页面及接口代理，Go 容器只读挂载 `../bin`，通过 Nginx 的 `/download/` 路径提供安装脚本和构建产物。当前 Compose 使用已有的外部网络 `docker_default`，启动前需确认网络存在。用 `docker network inspect docker_default --format '{{json .IPAM.Config}}'` 查看真实网段和网关；`MUI_PROXY_SUBNET` 仅作为 Go 的默认可信代理范围，填写实际网段或单独设置 `MUI_TRUSTED_PROXIES`，修改它不会创建或更改外部网络。`MUI_EDGE_PROXY_CIDR` 则填写外层 Nginx 的实际来源地址。
5. 目标机需要 Ubuntu 22.04/24.04 或 Debian 12/13、systemd、UFW、OpenSSH，以及 `curl`、`sha256sum`。首次使用前安装 UFW（`apt-get install ufw`），确认 `sshd -T` 能显示管理端口。面板新建服务器时选择类型：带落地类型的下载并安装 Agent 与 sing-box；只做入口、线路、中转的只下载 Agent，不创建 sing-box 账户或服务。在目标机执行显示的一次性接入命令；命令通过位置参数传递接入信息，不需要手动设置环境变量。它从面板下载适配架构的文件，按 `SHA256SUMS` 校验后安装。令牌 10 分钟有效；超时可重新生成。面板的 `MUI_PUBLIC_URL` 在面板服务器的 `.env` 中配置，必须是目标机可访问的 HTTPS 地址。
6. Agent 上线后，在面板执行“初始化 UFW”。启用 UFW 会按默认策略拒绝 SSH 以外的入站连接；机器上若有别的对外服务，初始化后立即在防火墙页为它们添加允许规则。若机器上 firewalld、nftables、netfilter-persistent 或 shorewall 正在运行，Agent 会拒绝写入 UFW 并在面板提示冲突。AnyTLS 先上传对应域名的 PEM 证书链和私钥。端口从云安全组放行后才能从公网访问。

`MUI_EDGE_PROXY_CIDR` 填外层 Nginx 连接内层容器时的实际来源；Linux 宿主机 Nginx 通常对应 Docker 网桥网关，不能直接沿用示例地址。外层 Nginx 在其他容器、其他主机或 Docker Desktop 时同样需按实际来源调整。内层只信任该来源的客户端 IP 和 HTTP/HTTPS 转发头，再将确认后的信息传给 Go。`MUI_PUBLIC_URL` 始终填写外部 HTTPS 地址，以生成正确的订阅链接、安装命令和登录 Cookie。仅本机 HTTP 预览时才改为 `http://127.0.0.1:8086`。

前端更新可以单独执行 `docker compose --env-file .env -f compose.yaml up -d --build --no-deps mui-web`；后端更新将最后的服务名改为 `mui-service`。更新其中一个镜像不需要重新构建另一个。

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

默认读取 `deploy/publish.env`，也可用 `--config /path/to/publish.env` 指定不同目标的配置。该文件按 Bash 配置读取，不需要手动 `export`。业务配置始终保存在远程 `<REMOTE_DIR>/deploy/.env`，每次发布的源码保存在 `releases/`；成功后 `current` 指向本次版本。源码包不包含本地 `.env`、Git、证书目录或构建缓存。Agent 下载文件保存在远程 `bin/`，只有 `--with-agent` 才更新；它不会自动升级已接入服务器上的 Agent。启用发布签名时，先用相应私钥构建带签名的下载文件。

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

Agent 独立安装并运行 `mui-agent-helper.service`（root，仅接受本机 Agent 的白名单操作）和 `mui-agent.service`（账户 `mui-agent`），无需 sing-box 或转发进程。添加第一条启用的转发规则后，Agent 才创建并启动 `mui-forward.service`（账户 `mui-forward`）；最后一条规则停用或删除后，服务会停止并禁用。落地服务器另安装 `mui-sing-box.service`（账户 `mui-core`）；其他类型无需该服务和二进制。排查时可用 `journalctl -u mui-agent -u mui-agent-helper -f`，有转发时再加 `-u mui-forward`，落地服务器再加 `-u mui-sing-box`。Agent 配置在 `/etc/mui-agent`，核心配置与证书在 `/etc/mui-core`，转发配置在 `/etc/mui-forward`，统计缓存在 `/var/lib/mui-agent`。已有 PostgreSQL 的备份与恢复见下文“备份与恢复”。

非落地服务器以后需要建节点时，在服务器列表点击“安装 sing-box 并设为落地”。Agent 会从面板下载对应架构的核心、验证 SHA-256 与所需构建功能、安装独立账户和 systemd 服务；成功后自动加上落地类型，面板才允许建节点。去掉落地类型前需先删除其节点，已安装的 sing-box 不会自动卸载。

应用配置变更时，只有节点配置或证书发生变化才会重启 sing-box；转发规则变化由转发进程就地重新加载，只有新增、修改或删除的那条规则受影响，其余转发的连接不中断；单独升级 sing-box 也会重启核心，同机节点连接会短暂中断。仅防火墙规则变化不会重启这两个服务。UFW 规则按差异增删，未变化的端口不会被关闭再打开。

服务器离线后可在面板强制删除，连同它的节点、转发、规则、证书和流量记录。Agent 凭据可在服务器列表中吊销；重新生成接入命令并在目标机再次执行安装即可轮换。

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
| `MUI_PUBLIC_URL` | 对外 HTTPS 地址，用于 Agent 接入命令、安装文件下载与订阅链接 |
| `MUI_AGENT_BIN_DIR` | 安装文件目录，默认 `bin`；按 `amd64`、`arm64` 子目录存放三个构建产物 |
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

## 发布签名

Agent 自升级时，root 权限的 helper 会下载并运行面板提供的二进制。不启用签名时，能改动面板 `bin/` 目录的人就能在所有受管服务器上以 root 执行代码。启用签名后，Agent 只接受由离线私钥签过清单的构建。

**威胁模型（请勿夸大）**：签名防的是“构建产物被篡改 / 镜像投毒”——即攻击者只能写 `bin/`、改不了面板代码、配置和安装命令的场景。面板整体被攻破（代码、配置、安装命令被改）时，签名不提供保护，攻击者仍可下发自己的二进制。安装命令本身是 `curl … | sudo sh`，安装脚本未签名，其信任根就是面板 HTTPS + 面板本身；只在受信任的面板和目标机上执行，不要转发给他人。

1. 在构建机（不要在面板主机上）生成密钥：`go run ./cmd/release-sign keygen release.key`。命令会打印 `MUI_RELEASE_PUBLIC_KEY=...`，私钥文件留在构建机并备份。
2. 构建时带上私钥：`MUI_RELEASE_KEY=release.key deploy/build-agent.sh amd64`，脚本会在 `bin/<架构>/` 下生成 `SHA256SUMS.sig`；若提供了密钥但签名未产出，脚本会失败退出，不会静默产出未签名构建。如需钉死上游 sing-box 源码：`SING_BOX_COMMIT=<该 tag 对应的 commit> deploy/build-agent.sh amd64`，commit 用 `git ls-remote https://github.com/SagerNet/sing-box.git "refs/tags/v1.14.2^{}"` 查询；不填时只校验 tag，tag 被移动则构建物会变。
3. 把公钥写进面板的 `MUI_RELEASE_PUBLIC_KEY` 并重启。此后生成的接入命令会把公钥交给 Agent，Agent 安装时校验签名并把公钥固定在 `/etc/mui-agent/release.pub`。
4. 已接入的服务器需要用新的接入命令重新安装一次才会固定公钥；服务器列表里会显示“升级需发布签名”或“升级未启用签名校验”。固定后重新安装不能更换公钥，确需更换时先在该服务器上删除 `/etc/mui-agent/release.pub`。

私钥丢失后无法再给已固定公钥的 Agent 升级，只能逐台删除公钥文件后重新接入。

接入命令不需要手动设置环境变量；一次性令牌作为安装脚本参数传入，10 分钟内使用一次后即失效。命令及令牌可能留在终端历史或短暂出现在进程列表，请只在受信任的目标机上执行，不要转发给他人。

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

服务器有四种类型，可多选：**入口**只能做链路首跳；**线路**可做首跳也可做中间跳；**中转**只能做中间跳；**落地**安装 sing-box 并搭建节点。入口和线路是订阅的接入点。

一条链路由首跳服务器、零到八跳中间跳和一个落地节点组成，例如“入口 → 中转 → 中转 → 落地”“线路 → 中转 → 落地”“入口 → 中转 → 线路 → 落地”。保存链路后面板在每一跳自动生成端口转发（SS 节点生成 TCP 和 UDP 两条），这些转发在“端口转发”页只读，修改请编辑链路。

- **监听**：链路转发使用双栈通配监听；系统支持 IPv6 时可接收 IPv4 和 IPv6，只有 IPv4 的系统继续监听 IPv4。
- **端口**：整条链路所有跳使用同一个端口。留空时优先使用落地节点的端口，它在某一跳被占用时自动换一个每一跳都空闲的随机端口；手填的端口被占用会直接报错。
- **负载均衡**：一跳选多台服务器即为一组，上一跳把新连接发给其中健康的服务器。主备模式优先用排在前面的，轮询模式轮流分配。转发进程每 5 秒用 TCP 连接探测各台，连续 2 次失败即停用，连续 2 次成功即恢复；客户端连接某台失败时立即停用该台并改连下一台。UDP 会话在所用服务器停用时迁移到可用的服务器，主备模式下首选服务器恢复后迁回。
- **内网地址**：服务器填写内网地址后，链路的某一跳可以选“上一跳走内网地址连过来”，最后一跳也可走内网连接落地，适合 IPLC/IEPL 专线或同一内网。每段连接的发送方必须填写实际来源 IP；仅有域名无法生成来源限制时会拒绝保存。
- **防火墙**：首跳端口对所有来源开放；中间跳只放行上一跳服务器的地址（走内网时为内网地址，否则为填写的公网 IPv4/IPv6 和 Agent 检测到的地址）；落地节点未开启“允许直连”时，端口只放行以它为终点的链路最后一跳，没有链路时不对外开放。服务器的出口 IP 与填写的公网 IP 不一致时（例如 NAT 机），请把出口 IP 填进公网 IPv4，否则下一跳会拒绝它的连接。
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
- Snell 服务端使用 sing-box v5 入站。sing-box 出站配置输出 v4，这是官方说明的相同线协议；Snell v5 的 QUIC Proxy Mode 不支持。
- AnyTLS 需要有效证书，客户端订阅使用域名进行 TLS 校验。证书目前由管理员上传和更新。
- sing-box 下载内容是节点出站 JSON，供支持导入出站片段的客户端使用；Surge 下载内容是 `[Proxy]` 片段。
- 订阅流量按独立登录用户采样，能分别统计同节点的不同订阅；客户流量为其当前关联订阅的合计。订阅链接轮换只换下载令牌，不轮换节点登录凭据。停用、删除或到期会排队移除该订阅的用户；Agent 离线时连接凭据要等 Agent 恢复并应用配置后才失效。节点级流量还包括管理员直接分享节点产生的流量，因此节点合计可高于订阅合计。
- 节点流量是 sing-box 入站处理字节，不等于云服务商计费流量。断电前最后一次采样可能丢失。没有目标 Linux 服务器时，无法替代真实客户端连通性及 UFW 联调。
- 转发流量为转发进程成功写入两侧连接的字节累计值，不含 TCP/IP 头部和握手。进程异常退出前尚未上报的最后一段流量可能丢失。目标地址可达性在建立连接时决定；“已生效”表示监听成功，不表示目标服务一直健康。自有程序也不能保证不会被安全软件误判。

## 验证

```bash
go test ./...
cd web && npm run build
```

接口级测试覆盖接入令牌、任务领取与回报、节点与转发状态、流量入库与去重、订阅、节点删除确认、强制删除、限速、密码与 TOTP 管理；Agent 的 UFW 规则排序与差异计算、Snell 订阅兼容字段及统计 API 编码另有单元测试。转发器另有 TCP/UDP 回环测试。接口测试只在 SQLite 上运行，PostgreSQL 路径需在部署环境中验证。目标机安装后仍应分别用 SS、Snell、AnyTLS 客户端检查 TCP/UDP 连通、流量增长、UFW 规则和订阅导入，并测试转发目标的实际可达性。
