import { useMemo } from "react";
import { mutation } from "../api";
import { useApp } from "../app/context";
import { manualFirewall } from "../app/helpers";
import { ActionMenu, Empty, HelpTip, parseSort, SortHeader, sortRows, Status, statusLabels, TableWrap } from "../app/ui";
import { useUrlParam } from "../app/url";

export default function Routes() {
  const { nodes, routes, servers, serverName, routePath, act, goTo, openRoute, deleteItem, matches, protect } = useApp();
  const [q, setQ] = useUrlParam("q"), [status, setStatus] = useUrlParam("status");
  const [entry, setEntry] = useUrlParam("entry"), [exit, setExit] = useUrlParam("exit"), [sortValue, setSort] = useUrlParam("sort");
  const sort = parseSort(sortValue, setSort);
  const filtered = !!(q || status || entry || exit);
  const exitByNode = useMemo(() => new Map(nodes.map((n) => [n.id, n.serverId])), [nodes]);
  const entryOptions = useMemo(() => [...new Set([...routes.map((r) => r.entryServerId), entry].filter(Boolean))]
    .sort((a, b) => serverName(a).localeCompare(serverName(b))), [routes, entry, serverName]);
  const exitOptions = useMemo(() => [...new Set([...routes.map((r) => exitByNode.get(r.nodeId) || ""), exit].filter(Boolean))]
    .sort((a, b) => serverName(a).localeCompare(serverName(b))), [routes, exit, exitByNode, serverName]);
  const visible = useMemo(() => sortRows(routes.filter((r) =>
    (!status || (r.status || "pending") === status) && (!entry || r.entryServerId === entry) &&
    (!exit || exitByNode.get(r.nodeId) === exit) && matches(q, r.name, r.notes, String(r.port), routePath(r)),
  ), sort, {
    name: (r) => r.name, port: (r) => r.port, status: (r) => r.status || "pending", node: (r) => nodes.find((n) => n.id === r.nodeId)?.name || "",
  }), [routes, nodes, q, status, entry, exit, exitByNode, sort.key, sort.descending, matches, routePath]);
  return protect(
          <section className="panel">
            <div className="panelHead">
              <div>
                <h2>链路</h2>
                <p>入口或线路 → 中转（每跳可多台负载均衡）→ 落地节点。面板在每一跳自动生成转发，整条链路使用同一个端口。</p>
              </div>
              <button className="primary" onClick={() => openRoute()} disabled={!nodes.length}>新建链路</button>
            </div>
            <div className="filters">
              <select aria-label="按入口服务器筛选链路" value={entry} onChange={(e) => setEntry(e.target.value)}>
                <option value="">全部入口服务器</option>
                {entryOptions.map((id) => <option key={id} value={id}>{serverName(id)}</option>)}
              </select>
              <select aria-label="按落地服务器筛选链路" value={exit} onChange={(e) => setExit(e.target.value)}>
                <option value="">全部落地服务器</option>
                {exitOptions.map((id) => <option key={id} value={id}>{serverName(id)}</option>)}
              </select>
              <select aria-label="按状态筛选链路" value={status} onChange={(e) => setStatus(e.target.value)}>
                <option value="">全部状态</option>
                {[...new Set(routes.map((item) => item.status || "pending"))].sort().map((value) => <option key={value} value={value}>{statusLabels[value]?.[0] || value}</option>)}
              </select>
              {filtered && <button type="button" className="ghost" onClick={() => { setQ(""); setStatus(""); setEntry(""); setExit(""); }}>清空筛选</button>}
              {filtered && <span className="hint" role="status">{q && `已定位：${q} · `}显示 {visible.length} / {routes.length} 条</span>}
            </div>
            <TableWrap>
              <table>
                <thead><tr>
                  <SortHeader sort={sort} id="name" label="名称" /><th>路径 <HelpTip label="链路延迟说明" text="每个数值由上一跳 Agent 每分钟测量到下一跳 TCP 端口的建连时间。它不是整条链路或代理协议的往返延迟；无新数据时显示待测。" /></th><SortHeader sort={sort} id="port" label="端口" />
                  <SortHeader sort={sort} id="node" label="落地节点" /><SortHeader sort={sort} id="status" label="状态" /><th>操作</th>
                </tr></thead>
                <tbody>
                  {visible.map((r) => {
                    const node = nodes.find((n) => n.id === r.nodeId);
                    const entryRestricted = r.entryFirewallPolicy === "restricted";
                    const entryManual = manualFirewall(servers.find((s) => s.id === r.entryServerId));
                    const entrySourceCount = r.entryFirewallSources?.split(",").filter((source) => source.trim()).length || 0;
                    const groups = [[r.entryServerId], ...r.hops.map((hop) => hop.serverIds), node ? [node.serverId] : []];
                    const edges = groups.slice(0, -1).flatMap((group, i) => group.flatMap((from) => groups[i + 1].map((to) => ({
                      from, to, point: r.edgeLatencies?.find((point) => point.fromServerId === from && point.toServerId === to),
                    }))));
                    return (
                      <tr key={r.id}>
                        <td><strong>{r.name}</strong>{entryRestricted && <small className="routeEntryAccess">{entryManual ? "入口限制需手动配置" : `入口限制 ${entrySourceCount} 个来源`}</small>}{r.notes && <small>{r.notes}</small>}</td>
                        <td><div>{routePath(r)}</div>{r.enabled && edges.length > 0 && <div className="routeLatencies" aria-label="各跳 TCP 建连时间">{edges.map(({ from, to, point }) => <span key={`${from}-${to}`} className={`routeLatency ${point && !point.ok ? "routeLatencyFailed" : ""}`} title={point ? `测量于 ${new Date(point.at).toLocaleString()}` : "尚无有效测量数据"}>{serverName(from)} → {serverName(to)}：{point ? point.ok ? `${point.tcpMs} ms` : "超时/失败" : "待测"}</span>)}</div>}</td>
                        <td className="mono">{r.port}</td>
                        <td>{node ? <button type="button" className="textButton rowLink" onClick={() => goTo("nodes", node.serverId, { q: node.name })}>{node.name}</button> : "已删除"}{node && <small>{node.protocol.toUpperCase()} · {serverName(node.serverId)}</small>}</td>
                        <td><Status value={r.status || "pending"} />{r.error && <small role="alert">{r.error}</small>}</td>
                        <td><div className="actions">
                          <button onClick={() => openRoute(r)}>编辑</button>
                          <ActionMenu>
                            <button onClick={() => void act(() => mutation("/api/routes/" + r.id, "PATCH", { ...r, enabled: !r.enabled }), r.enabled ? "链路已停用" : "链路已启用")}>{r.enabled ? "停用" : "启用"}</button>
                            <button className="dangerText" onClick={() => deleteItem("/api/routes/" + r.id, "链路")}>删除</button>
                          </ActionMenu>
                        </div></td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              {!visible.length && <Empty text={filtered ? "没有符合筛选条件的链路" : "暂无链路，点击右上角新建"} />}
            </TableWrap>
          </section>,
  );
}
