import { useMemo } from "react";
import { bytes, canHostNodes, mutation, type InstallGuide, type Server } from "../api";
import { useApp } from "../app/context";
import { countryFlag, manualFirewall, rolesText, serverFilterValues, supportsGitHubUpgrade } from "../app/helpers";
import { ActionMenu, Empty, HelpTip, parseSort, SortHeader, sortRows, Status, TableWrap, useSelection } from "../app/ui";
import { useUrlParam } from "../app/url";

export default function Servers() {
  const { servers, nodes, forwards, operations, agentReleases, coreReleases, upgradingAgentIDs, updatingAgentIDs, serverWarnings, goTo, act, copy, runBatch, setConfirmation, setAgentDownloads, setOfflineServer, openServer, showInstall, deleteServer, matches, protect } = useApp();
  const [q, setQ] = useUrlParam("q"), [country, setCountry] = useUrlParam("country"), [provider, setProvider] = useUrlParam("provider"),
    [region, setRegion] = useUrlParam("region"), [city, setCity] = useUrlParam("city"), [status, setStatus] = useUrlParam("status"), [sortValue, setSort] = useUrlParam("sort");
  const sort = parseSort(sortValue, setSort, "name");
  const filters = [
    ["国家代码", "country", country, setCountry], ["服务商", "provider", provider, setProvider],
    ["地区", "region", region, setRegion], ["城市", "city", city, setCity],
  ] as const;
  const filtered = !!(q || country || provider || region || city || status);
  const visibleServers = useMemo(() => sortRows(servers.filter((s) =>
    matches(q, s.name, s.ipv4, s.ipv6, s.domain, s.internalAddress, s.provider, s.tags, s.notes) &&
    (!country || s.country?.trim() === country) && (!provider || s.provider?.trim() === provider) &&
    (!region || s.region?.trim() === region) && (!city || s.city?.trim() === city) && (!status || s.status === status),
  ), sort, {
    name: (s) => s.name, country: (s) => s.country, address: (s) => s.domain || s.ipv4 || s.ipv6 || "", status: (s) => s.status,
    traffic: (s) => (s.networkRx || 0) + (s.networkTx || 0), nodes: (s) => nodes.filter((n) => n.serverId === s.id).length,
    forwards: (s) => forwards.filter((f) => f.serverId === s.id && !f.deleting).length,
  }), [servers, nodes, forwards, q, country, provider, region, city, status, sort.key, sort.descending, matches]);
  const selection = useSelection(visibleServers.map((s) => s.id));
  const picked = servers.filter((s) => selection.has(s.id));
  const upgrading = (s: Server) => operations.some((o) => o.serverId === s.id && ["agent.upgrade", "core.upgrade"].includes(o.kind) && ["queued", "running", "activating"].includes(o.status));
  const gitHubReady = (s: Server) => !agentReleases.releaseVersion || supportsGitHubUpgrade(s.agentVersion || "");
  const agentUpgradable = (s: Server) => s.status !== "revoked" && s.agentSelfUpdate && gitHubReady(s) && !!agentReleases[s.arch] && s.agentBuild !== agentReleases[s.arch] && !upgrading(s);
  const coreUpgradable = (s: Server) => s.status !== "revoked" && s.coreSelfUpdate && gitHubReady(s) && !!s.coreBuild && !!coreReleases[s.arch] && s.coreBuild !== coreReleases[s.arch] && !upgrading(s);
  const batchUpgrade = (title: string, eligible: Server[], path: string, warning: string) => setConfirmation({
    title,
    message: `已选 ${picked.length} 台，其中 ${eligible.length} 台可升级：${eligible.map((s) => s.name).join("、")}。${picked.length > eligible.length ? "其余服务器已是最新、离线或暂不支持，会被跳过。" : ""}${warning}`,
    confirmLabel: "开始升级",
    onConfirm: () => { selection.clear(); void runBatch(title, eligible, (s) => s.name, (s) => mutation("/api/servers/" + s.id + path, "POST")); },
  });
  const batchDelete = () => setConfirmation({
    title: "批量删除服务器",
    message: `确定删除这 ${picked.length} 台服务器？\n${picked.map((s) => s.name).join("、")}\n离线且仍有节点、转发或规则的服务器不会在这里删除，请逐台确认强制删除。此操作无法撤销。`,
    confirmLabel: "删除",
    onConfirm: () => { selection.clear(); void runBatch("批量删除服务器", picked, (s) => s.name, (s) => mutation("/api/servers/" + s.id, "DELETE")); },
  });
  return protect(
          <section className="panel">
            <div className="panelHead">
              <div>
                <h2>服务器列表</h2>
                <p>管理服务器档案、Agent 与 UFW 状态</p>
              </div>
              <div className="headerActions">
                <button className="ghost" onClick={() => setAgentDownloads({ arch: "amd64" })}>下载 Agent</button>
                <button className="primary" onClick={() => openServer()}>新建服务器</button>
              </div>
            </div>
            <div className="filters serverFilters">
              {filters.map(([label, field, value, set]) => (
                <select key={field} aria-label={`按${label}筛选服务器`} value={value} onChange={(e) => set(e.target.value)}>
                  <option value="">全部{label}</option>
                  {serverFilterValues(servers, field).map((item) => <option key={item} value={item}>{item}</option>)}
                </select>
              ))}
              <select aria-label="按状态筛选服务器" value={status} onChange={(e) => setStatus(e.target.value)}>
                <option value="">全部状态</option>
                <option value="online">在线</option>
                <option value="offline">离线</option>
                <option value="pending">等待接入</option>
                <option value="revoked">已吊销</option>
              </select>
              {filtered && <button type="button" className="ghost" onClick={() => { setQ(""); setCountry(""); setProvider(""); setRegion(""); setCity(""); setStatus(""); }}>清空筛选</button>}
              {filtered && <span className="hint" role="status">{q && `已定位：${q} · `}显示 {visibleServers.length} / {servers.length} 台</span>}
            </div>
            {selection.selected.length > 0 && <div className="batchBar" role="toolbar" aria-label="批量操作">
              <strong>已选 {selection.selected.length} 台</strong>
              <button disabled={!picked.some(agentUpgradable)} onClick={() => batchUpgrade("批量升级 Agent", picked.filter(agentUpgradable), "/agent/upgrade", "节点服务继续运行。")}>升级 Agent</button>
              <button disabled={!picked.some(coreUpgradable)} onClick={() => batchUpgrade("批量升级 sing-box", picked.filter(coreUpgradable), "/core/upgrade", "\n升级时核心会重启，这些服务器上所有节点的连接将中断数秒。")}>升级 sing-box</button>
              <button className="dangerText" onClick={batchDelete}>删除</button>
              <button className="textButton" onClick={selection.clear}>取消选择</button>
            </div>}
            <TableWrap>
              <table className="serverListTable">
                <thead>
                  <tr>
                    <th className="selectCell"><input type="checkbox" aria-label="选择全部服务器" checked={selection.all} onChange={selection.toggleAll} /></th>
                    <SortHeader sort={sort} id="name" label="服务器" />
                    <SortHeader sort={sort} id="country" label="国家 / 服务商 / 地区" />
                    <SortHeader sort={sort} id="address" label="公网地址" />
                    <SortHeader sort={sort} id="status" label="Agent" />
                    <th>UFW</th>
                    <SortHeader sort={sort} id="traffic" label="整机累计流量" title="Agent 开始采样后的默认网卡累计收发量，包含系统流量、SSH、程序下载和 Agent 通信；不是节点或订阅用量。" />
                    <SortHeader sort={sort} id="nodes" label="节点" />
                    <SortHeader sort={sort} id="forwards" label="转发" title="包含停用和链路自动生成的转发规则；不包含正在删除的规则。" />
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {visibleServers.map((s) => (
                    <tr key={s.id}>
                      <td className="selectCell"><input type="checkbox" aria-label={`选择 ${s.name}`} checked={selection.has(s.id)} onChange={() => selection.toggle(s.id)} /></td>
                      <td>
                        <span className="serverNameLine"><strong title={s.name}>{s.name}</strong>{serverWarnings(s).length > 0 && <HelpTip label={`${s.name} 的 ${serverWarnings(s).length} 项提醒`} text={serverWarnings(s).join("\n")} warning />}</span>
                        <small>{s.managementMode === "external" ? "卖家节点" : s.managementMode === "offline" ? "离线管理" : s.os || "待接入"}{s.arch && ` · ${s.arch}`}</small>
                      </td>
                      <td>
                        <span className="serverCountry">{countryFlag(s.country) && <span className="serverFlag" aria-hidden="true">{countryFlag(s.country)}</span>}{s.country}</span>
                        <small title={[s.provider, s.region, s.city].filter(Boolean).join(" · ")}>{[s.provider, s.region, s.city].filter(Boolean).join(" · ") || "—"}</small>
                      </td>
                      <td className="mono"><span className="serverAddress" title={s.domain || s.ipv4 || s.ipv6}>{s.domain || s.ipv4 || s.ipv6 || "—"}</span>{(s.autoSyncPublicIp || s.internalAddress || s.domain && (s.ipv4 || s.ipv6)) && <HelpTip label={`${s.name} 的地址`} text={[s.domain && `域名：${s.domain}`, s.ipv4 && `IPv4：${s.ipv4}`, s.ipv6 && `IPv6：${s.ipv6}`, s.internalAddress && `内网：${s.internalAddress}`, s.autoSyncPublicIp && "公网 IP 自动同步"].filter(Boolean).join("\n")} />}</td>
                      <td>
                        <span className="serverAgentLine"><Status value={s.managementMode !== "offline" && s.managementMode !== "external" && s.status === "online" ? upgradingAgentIDs.has(s.id) ? "upgrading" : updatingAgentIDs.has(s.id) ? "updating" : s.status : s.status} /><HelpTip label={`${s.name} 的管理状态`} text={s.managementMode === "external"
                          ? "外部节点由卖家运行；面板不安装 Agent、不修改防火墙，也无法确认服务状态或统计其流量。"
                          : s.managementMode === "offline"
                          ? [s.offlineExportedAt ? `已导出版本 ${s.offlineExportedRevision}` : "尚未导出配置", (!s.offlineExportedAt || s.offlineExportedRevision !== s.revision) && `配置待导出 · 版本 ${s.revision || 1}`, "实时连通性未知"].filter(Boolean).join("\n")
                          : [
                            `Agent：${s.agentVersion || "未接入"}`,
                            upgradingAgentIDs.has(s.id) ? "Agent 升级中，等待新版上报" :
                              s.agentSelfUpdate && agentReleases[s.arch] ? s.agentBuild === agentReleases[s.arch] ? "Agent 已是当前构建" : "Agent 有可用升级" :
                                !s.agentSelfUpdate && s.agentVersion ? "需先人工升级 Agent 一次" : "",
                            updatingAgentIDs.has(s.id) && "节点配置更新中，等待 Agent 应用",
                            s.agentVersion && (s.releaseKeyPinned ? "升级需发布签名" : "升级未启用签名校验"),
                            `类型：${rolesText(s.roles)}`,
                            `sing-box 安装：${s.coreBuild ? s.coreVersion || "版本待上报" : "未安装"}`,
                            s.coreBuild && "这里显示已安装的二进制版本，不代表 sing-box 服务正在运行；无启用节点时 Agent 0.6.22 会停用服务。",
                            s.coreSelfUpdate && s.coreBuild && coreReleases[s.arch] ? s.coreBuild === coreReleases[s.arch] ? "核心已是当前构建" : "核心有可用升级" : !s.coreSelfUpdate && s.agentVersion ? "升级 Agent 后可一键升级核心" : "",
                            operations.some((o) => o.serverId === s.id && ["agent.upgrade", "core.upgrade"].includes(o.kind) && ["queued", "running", "activating"].includes(o.status)) && "程序升级进行中，详情见操作记录",
                          ].filter(Boolean).join("\n")} /></span>
                        <small>{s.managementMode === "external" ? "连接信息由卖家提供" : s.managementMode === "offline" ? (!s.offlineExportedAt || s.offlineExportedRevision !== s.revision ? "配置待导出" : `已导出 v${s.offlineExportedRevision}`) : `Agent ${s.agentVersion || "未接入"} · sing-box ${s.coreBuild ? `已安装 ${s.coreVersion || "版本待上报"}` : "未安装"}`}</small>
                      </td>
                      <td>
                        <button type="button" className="serverListLink" title={`查看「${s.name}」的防火墙`} aria-label={`查看「${s.name}」的防火墙`} onClick={() => {
                          goTo("firewall", s.id);
                        }}>
                          <Status value={manualFirewall(s) ? "manual" : s.firewallConflict ? "conflict" : s.ufwStatus} />
                        </button>
                      </td>
                      <td className="serverTraffic" title="↓ 网卡接收，↑ 网卡发送。包含本机所有经过默认网卡的流量。">
                        {s.managementMode === "offline" || s.managementMode === "external" ? "—" : <span>↓ {bytes(s.networkRx || 0)}<br />↑ {bytes(s.networkTx || 0)}</span>}
                      </td>
                      <td><button type="button" className="serverListLink" title={`查看「${s.name}」的节点`} aria-label={`查看「${s.name}」的节点`} onClick={() => {
                        goTo("nodes", s.id, {});
                      }}>{nodes.filter((n) => n.serverId === s.id).length}</button></td>
                      <td><button type="button" className="serverListLink" title={`查看「${s.name}」的转发`} aria-label={`查看「${s.name}」的转发`} onClick={() => {
                        goTo("forwards", s.id, {});
                      }}>{forwards.filter((f) => f.serverId === s.id && !f.deleting).length}</button></td>
                      <td>
                        <div className="actions">
                          <button onClick={() => openServer(s)}>编辑</button>
                          {s.managementMode === "offline" && <button onClick={() => setOfflineServer(s)}>离线配置</button>}
                          <ActionMenu>
                          {s.managementMode !== "offline" && s.managementMode !== "external" && <>
                          <button
                            disabled={s.status === "revoked" || !s.agentSelfUpdate || !!agentReleases.releaseVersion && !supportsGitHubUpgrade(s.agentVersion || "") || !agentReleases[s.arch] || s.agentBuild === agentReleases[s.arch] || operations.some((o) => o.serverId === s.id && ["agent.upgrade", "core.upgrade"].includes(o.kind) && ["queued", "running", "activating"].includes(o.status))}
                            title={s.status === "revoked" ? "凭据已吊销，请重新接入后升级" : !s.agentSelfUpdate ? "当前 Agent 不支持自更新；请先手动安装新版一次"
                              : agentReleases.releaseVersion && !supportsGitHubUpgrade(s.agentVersion || "") ? "当前 Agent 不支持 GitHub 直下升级，请先用新版接入命令重装一次"
                              : !agentReleases[s.arch] ? agentReleases[s.arch + "Error"] || "该架构的 Agent 发布文件不可用"
                              : s.agentBuild === agentReleases[s.arch] ? "已是当前发布构建"
                              : operations.some((o) => o.serverId === s.id && ["agent.upgrade", "core.upgrade"].includes(o.kind) && ["queued", "running", "activating"].includes(o.status)) ? "已有升级任务在进行，详情见操作记录"
                              : agentReleases.releaseVersion ? "从 GitHub Release 下载并校验新版本，节点服务继续运行" : "下载并校验新版本，节点服务继续运行"}
                            onClick={() => act(() => mutation("/api/servers/" + s.id + "/agent/upgrade", "POST"), "Agent 升级已排队；重启上报新构建后才会显示成功")}
                          >
                            一键升级 Agent
                          </button>
                          <button
                            disabled={s.status === "revoked" || !s.coreSelfUpdate || !!agentReleases.releaseVersion && !supportsGitHubUpgrade(s.agentVersion || "") || !coreReleases[s.arch] || s.coreBuild === coreReleases[s.arch] || operations.some((o) => o.serverId === s.id && ["agent.upgrade", "core.upgrade"].includes(o.kind) && ["queued", "running", "activating"].includes(o.status))}
                            title={s.status === "revoked" ? "凭据已吊销，请重新接入后安装或升级" : !s.coreSelfUpdate ? "请先将 Agent 升级到支持 sing-box 自更新的版本" : agentReleases.releaseVersion && !supportsGitHubUpgrade(s.agentVersion || "") ? "当前 Agent 不支持 GitHub 直下升级，请先用新版接入命令重装一次" : !coreReleases[s.arch] ? coreReleases[s.arch + "Error"] || "该架构的 sing-box 发布文件不可用" : s.coreBuild ? "先验证新核心和现有配置，再重启核心；该服务器的节点连接将短暂中断，失败会恢复旧版本" : "下载并验证 sing-box，然后安装到该服务器"}
                            onClick={() => {
                              const run = () => { void act(() => mutation("/api/servers/" + s.id + "/core/upgrade", "POST"), s.coreBuild ? "sing-box 升级已排队" : "sing-box 安装已排队"); };
                              if (!s.coreBuild) return run();
                              setConfirmation({
                                title: "升级 sing-box",
                                message: `升级「${s.name}」的 sing-box？\n升级时核心会重启，这台服务器上所有节点的连接将中断数秒。新核心无法启动时会自动恢复旧版本。`,
                                confirmLabel: "升级",
                                onConfirm: run,
                              });
                            }}
                          >
                            {s.coreBuild ? "一键升级 sing-box" : canHostNodes(s) ? "安装 sing-box" : "安装 sing-box 并设为落地"}
                          </button>
                          <button
                            onClick={() =>
                              act(async () => {
                                const v = await mutation<InstallGuide>(
                                  "/api/servers/" + s.id + "/enrollment",
                                  "POST",
                                );
                                showInstall(v, s.name, "online", s.arch);
                              }, "首次接入 / 手动修复命令已生成")
                            }
                          >
                            首次接入 / 手动修复
                          </button>
                          <button
                            disabled={manualFirewall(s) || s.ufwStatus === "active" || s.status !== "online"}
                            title={manualFirewall(s) ? "手动管理模式不操作 UFW" : s.ufwStatus === "active" ? "UFW 已启用" : s.status !== "online" ? "服务器不在线" : ""}
                            onClick={() =>
                              setConfirmation({
                                title: "初始化 UFW",
                                message: `在「${s.name}」上启用 UFW？\n启用后默认拒绝 SSH 以外的所有入站连接：这台机器上的其他对外服务会立刻无法访问，直到为它们添加允许规则。\nSSH 端口会先被放行；如果 2 分钟内 Agent 无法向面板确认，UFW 会自动关闭。`,
                                confirmLabel: "启用 UFW",
                                onConfirm: () => {
                                  void act(() => mutation("/api/servers/" + s.id + "/ufw/init", "POST"), "UFW 初始化已排队");
                                },
                              })
                            }
                          >
                            初始化 UFW
                          </button>
                          <button
                            onClick={() => {
                              setConfirmation({
                                title: "吊销 Agent 凭据",
                                message: `吊销「${s.name}」的 Agent 凭据？面板会立即拒绝旧凭据；Agent 0.6.21 起会停止请求。已在服务器上运行的节点和转发不会被远程停用，需要停机时请复制卸载命令并在目标服务器执行。重新接入需生成新命令。`,
                                confirmLabel: "吊销凭据",
                                onConfirm: () => {
                                  void act(
                                    () =>
                                      mutation(
                                        "/api/servers/" + s.id + "/revoke",
                                        "POST",
                                      ),
                                    "Agent 凭据已吊销",
                                  );
                                },
                              });
                            }}
                          >
                            吊销 Agent
                          </button>
                          <button onClick={() => void copy(`(
set -eu
mui_uninstall=$(mktemp)
trap 'rm -f "$mui_uninstall"' EXIT HUP INT TERM
curl -fsSL '${window.location.origin}/download/uninstall.sh' -o "$mui_uninstall"
if [ "$(id -u)" -eq 0 ]; then sh "$mui_uninstall"; else sudo sh "$mui_uninstall"; fi
)`)} title="复制后在目标服务器运行；停止并删除 MUI Agent、转发和 sing-box 服务，不改动 UFW 规则">
                            复制卸载命令
                          </button>
                          </>}
                          <button
                            className="dangerText"
                            onClick={() => deleteServer(s)}
                          >
                            删除
                          </button>
                          </ActionMenu>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!visibleServers.length && <Empty text={servers.length ? "没有符合筛选条件的服务器" : "还没有服务器，点击右上角添加"} />}
            </TableWrap>
          </section>,
  );
}
