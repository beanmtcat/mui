import { useMemo } from "react";
import { bytes, mutation } from "../api";
import { useApp } from "../app/context";
import { forwardDisplayStatus, manualFirewall } from "../app/helpers";
import { Empty, parseSort, SortHeader, sortRows, Status, statusLabels, TableWrap } from "../app/ui";
import { useServerParam, useUrlParam } from "../app/url";

export default function Forwards() {
  const { servers, routes, forwards, forwardServerIDs, serverName, act, goTo, setAgentDownloads, setOfflineServer, openForward, deleteItem, matches, protect } = useApp();
  const [serverId, setServerId] = useServerParam();
  const [query, setQuery] = useUrlParam("q"), [network, setNetwork] = useUrlParam("network"), [source, setSource] = useUrlParam("source"),
    [status, setStatus] = useUrlParam("status"), [sortValue, setSort] = useUrlParam("sort");
  const sort = parseSort(sortValue, setSort);
  const forwardFilters = { query, serverId, network, source, status };
  const forwardServers = useMemo(() => new Map(servers.map((s) => [s.id, s])), [servers]);
  const forwardRoutes = useMemo(() => new Map(routes.map((r) => [r.id, r])), [routes]);
  const forwardStatuses = useMemo(() => [...new Set(forwards.map((f) =>
    forwardDisplayStatus(f, forwardServers.get(f.serverId)) || "unknown",
  ))].sort(), [forwards, forwardServers]);
  const forwardFiltersActive = Object.values(forwardFilters).some(Boolean);
  const visibleForwards = useMemo(() => sortRows(forwards.filter((f) => {
    const server = forwardServers.get(f.serverId);
    return (!forwardFilters.serverId || f.serverId === forwardFilters.serverId) &&
      (!forwardFilters.network || f.network === forwardFilters.network) &&
      (!forwardFilters.source || (forwardFilters.source === "route" ? !!f.routeId : !f.routeId)) &&
      (!forwardFilters.status || (forwardDisplayStatus(f, server) || "unknown") === forwardFilters.status) &&
      matches(forwardFilters.query, f.name, server?.name, server?.ipv4, server?.ipv6,
        f.listen, String(f.port), forwardRoutes.get(f.routeId || "")?.name,
        ...f.targets.map((t) => `${t.host}:${t.port}`));
  }), sort, {
    name: (f) => f.name, server: (f) => serverName(f.serverId), port: (f) => f.port, traffic: (f) => (f.uplink || 0) + (f.downlink || 0),
    status: (f) => forwardDisplayStatus(f, forwardServers.get(f.serverId)),
  }), [forwards, query, serverId, network, source, status, sort.key, sort.descending, forwardServers, forwardRoutes, matches, serverName]);
  return protect(
          <section className="panel">
            <div className="panelHead">
              <div>
                <h2>端口转发</h2>
                <p>支持 TCP、UDP 或 TCP + UDP；双协议共用监听端口与目标，流量合并统计。</p>
              </div>
              <div className="headerActions">
                <button className="ghost" onClick={() => setAgentDownloads({ arch: "amd64" })}>下载 Agent</button>
                <button className="primary" onClick={() => openForward()} disabled={!servers.some((s) => s.managementMode !== "external")}>新建转发</button>
              </div>
            </div>
            {servers.some((s) => forwardServerIDs.has(s.id) && s.managementMode !== "offline" && !manualFirewall(s) && s.ufwStatus && s.ufwStatus !== "active") && (
              <div className="banner warning">有 UFW 托管服务器尚未启用 UFW；请初始化 UFW，或将对应服务器设置为手动管理防火墙。</div>
            )}
            {servers.some((s) => forwardServerIDs.has(s.id) && s.managementMode !== "offline" && !manualFirewall(s) && !!s.firewallConflict) && (
              <div className="banner error">检测到其他防火墙工具正在管理防火墙，面板已停止写入 UFW；请先停用它。</div>
            )}
            <div className="filters forwardFilters">
              <input type="search" value={forwardFilters.query} onChange={(e) => setQuery(e.target.value)} placeholder="搜索名称、IP、端口或链路" aria-label="搜索端口转发" />
              <select aria-label="按服务器筛选转发" value={forwardFilters.serverId} onChange={(e) => setServerId(e.target.value)}>
                <option value="">全部服务器</option>
                {servers.map((s) => <option key={s.id} value={s.id}>{s.name}{s.managementMode === "offline" ? "（离线管理）" : ""}</option>)}
              </select>
              <select aria-label="按协议筛选转发" value={forwardFilters.network} onChange={(e) => setNetwork(e.target.value)}>
                <option value="">全部协议</option>
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="tcp+udp">TCP + UDP</option>
              </select>
              <select aria-label="按规则来源筛选转发" value={forwardFilters.source} onChange={(e) => setSource(e.target.value)}>
                <option value="">全部规则来源</option>
                <option value="manual">手动创建</option>
                <option value="route">链路自动生成</option>
              </select>
              <select aria-label="按状态筛选转发" value={forwardFilters.status} onChange={(e) => setStatus(e.target.value)}>
                <option value="">全部状态</option>
                {[...new Set([...forwardStatuses, ...(forwardFilters.status ? [forwardFilters.status] : [])])].map((status) => <option key={status} value={status}>{statusLabels[status]?.[0] || status}</option>)}
              </select>
              {forwardFiltersActive && <button type="button" className="ghost" onClick={() => { setQuery(""); setNetwork(""); setSource(""); setStatus(""); setServerId(""); }}>清空筛选</button>}
              <span className="hint" role="status">显示 {visibleForwards.length} / {forwards.length} 条</span>
            </div>
            <TableWrap>
              <table>
                <thead><tr>
                  <SortHeader sort={sort} id="name" label="名称" /><SortHeader sort={sort} id="server" label="服务器" /><SortHeader sort={sort} id="port" label="监听" /><th>目标</th>
                  <SortHeader sort={sort} id="traffic" label="已转发" /><th>放行来源</th><SortHeader sort={sort} id="status" label="状态" /><th>操作</th>
                </tr></thead>
                <tbody>
                  {visibleForwards.map((f) => {
                    const server = servers.find((s) => s.id === f.serverId);
                    const offline = server?.managementMode === "offline";
                    return (
                      <tr key={f.id}>
                        <td><strong>{f.name}</strong>{f.routeId && <small>链路自动生成</small>}</td>
                        <td><button type="button" className="textButton rowLink" onClick={() => goTo("servers", "", { q: serverName(f.serverId) })}>{serverName(f.serverId)}</button>{offline && <small>离线管理</small>}</td>
                        <td className="mono">{f.network.toUpperCase().replace("+", " + ")} {f.listen || "0.0.0.0"}:{f.port}</td>
                        <td className="mono">{f.targets.map((t) => `${t.host}:${t.port}`).join("、")}{f.targets.length > 1 && <small>{f.balance === "round-robin" ? "轮询" : "主备"}</small>}</td>
                        <td>{offline ? <small title="离线机器不向面板回传转发流量">无法远程获取</small> : <>↑ {bytes(f.uplink || 0)} · ↓ {bytes(f.downlink || 0)}</>}</td>
                        <td className="mono">{manualFirewall(server) ? "外部管理" : f.firewallPolicy === "closed" ? "不开放" : f.firewallPolicy === "manual" ? "手动管理" : f.firewallPolicy === "restricted" ? f.firewallSources.split(",").join("、") : "任意来源"}</td>
                        <td title={offline ? "离线配置需手动在目标机应用；面板无法确认应用结果或实时连通性" : undefined}>
                          <Status value={forwardDisplayStatus(f, server)} />
                          {offline ? <small><button className="textButton" onClick={() => setOfflineServer(server)}>离线配置</button></small> : <>
                            {f.error && <small className="hint">{f.error}</small>}
                            {f.network === "tcp+udp" && !server?.forwardTcpUdp && <small className="hint">需升级 Agent 至 0.6.7</small>}
                            {!server?.forwardSupport && <small className="hint">等待 Agent 更新</small>}
                          </>}
                        </td>
                        <td>{f.routeId ? <button className="textButton" style={{ whiteSpace: "nowrap" }} onClick={() => goTo("routes", "", { q: forwardRoutes.get(f.routeId || "")?.name || "" })}>在链路中管理</button> : <div className="actions">
                          <button disabled={f.deleting} onClick={() => openForward(f)}>编辑</button>
                          <button disabled={f.deleting} onClick={() => void act(() => mutation("/api/forwards/" + f.id, "PATCH", { ...f, enabled: !f.enabled }), offline ? "转发配置已保存，请重新导出并在离线目标机应用" : f.enabled ? "转发已停用" : "转发已启用")}>{f.enabled ? "停用" : "启用"}</button>
                          <button className="dangerText" onClick={() => deleteItem("/api/forwards/" + f.id, "转发", offline ? { message: "确定删除这条离线转发？保存后还需导出完整配置并在目标机应用，才会停止该机上的转发。", success: "删除配置已保存，请重新导出并在离线目标机应用" } : undefined)}>删除</button>
                        </div>}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              {!visibleForwards.length && <Empty text={forwardFiltersActive ? "没有匹配的转发规则，请调整或清空筛选" : "暂无转发规则"} />}
            </TableWrap>
          </section>,
  );
}
