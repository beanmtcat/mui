import { useMemo } from "react";
import { mutation } from "../api";
import { useApp } from "../app/context";
import { ActionMenu, Empty, parseSort, SortHeader, sortRows, Status, statusLabels, TableWrap } from "../app/ui";
import { useUrlParam } from "../app/url";

export default function Routes() {
  const { nodes, routes, serverName, routePath, act, goTo, openRoute, deleteItem, matches, protect } = useApp();
  const [q, setQ] = useUrlParam("q"), [status, setStatus] = useUrlParam("status"), [sortValue, setSort] = useUrlParam("sort");
  const sort = parseSort(sortValue, setSort);
  const filtered = !!(q || status);
  const visible = useMemo(() => sortRows(routes.filter((r) =>
    (!status || (r.status || "pending") === status) && matches(q, r.name, r.notes, String(r.port), routePath(r)),
  ), sort, {
    name: (r) => r.name, port: (r) => r.port, status: (r) => r.status || "pending", node: (r) => nodes.find((n) => n.id === r.nodeId)?.name || "",
  }), [routes, nodes, q, status, sort.key, sort.descending, matches, routePath]);
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
              <select aria-label="按状态筛选链路" value={status} onChange={(e) => setStatus(e.target.value)}>
                <option value="">全部状态</option>
                {[...new Set(routes.map((item) => item.status || "pending"))].sort().map((value) => <option key={value} value={value}>{statusLabels[value]?.[0] || value}</option>)}
              </select>
              {filtered && <button type="button" className="ghost" onClick={() => { setQ(""); setStatus(""); }}>清空筛选</button>}
              {filtered && <span className="hint" role="status">{q && `已定位：${q} · `}显示 {visible.length} / {routes.length} 条</span>}
            </div>
            <TableWrap>
              <table>
                <thead><tr>
                  <SortHeader sort={sort} id="name" label="名称" /><th>路径</th><SortHeader sort={sort} id="port" label="端口" />
                  <SortHeader sort={sort} id="node" label="落地节点" /><SortHeader sort={sort} id="status" label="状态" /><th>操作</th>
                </tr></thead>
                <tbody>
                  {visible.map((r) => {
                    const node = nodes.find((n) => n.id === r.nodeId);
                    return (
                      <tr key={r.id}>
                        <td><strong>{r.name}</strong>{r.notes && <small>{r.notes}</small>}</td>
                        <td>{routePath(r)}</td>
                        <td className="mono">{r.port}</td>
                        <td>{node ? <button type="button" className="textButton rowLink" onClick={() => goTo("nodes", node.serverId, { q: node.name })}>{node.name}</button> : "已删除"}{node && <small>{node.protocol.toUpperCase()} · {serverName(node.serverId)}</small>}</td>
                        <td><Status value={r.status || "pending"} /></td>
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
