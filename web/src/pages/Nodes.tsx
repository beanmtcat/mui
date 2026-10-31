import { useMemo } from "react";
import { api, bytes, mutation, type Node } from "../api";
import { useApp } from "../app/context";
import { ActionMenu, Empty, parseSort, SortHeader, sortRows, Status, statusLabels, TableWrap, useSelection } from "../app/ui";
import { useServerParam, useUrlParam } from "../app/url";

export default function Nodes() {
  const { servers, nodes, serverName, goTo, act, copy, runBatch, setConfirmation, setTrafficNode, openNode, openTemplate, deleteItem, matches, protect } = useApp();
  const [serverFilter, setServerFilter] = useServerParam();
  const [q, setQ] = useUrlParam("q"), [protocol, setProtocol] = useUrlParam("protocol"), [status, setStatus] = useUrlParam("status"), [sortValue, setSort] = useUrlParam("sort");
  const sort = parseSort(sortValue, setSort);
  const filtered = !!(q || protocol || status || serverFilter);
  const visibleNodes = useMemo(() => sortRows(nodes.filter((n) =>
    (!serverFilter || n.serverId === serverFilter) && (!protocol || n.protocol === protocol) &&
    (!status || (n.deleting ? "deleting" : n.status) === status) &&
    matches(q, n.name, n.id, serverName(n.serverId), String(n.port), n.publishAddress, n.tlsName, n.shadowTlsHost),
  ), sort, {
    name: (n) => n.name, server: (n) => serverName(n.serverId), port: (n) => n.port, up: (n) => n.uplink, down: (n) => n.downlink, status: (n) => n.status,
  }), [nodes, serverFilter, protocol, status, q, sort.key, sort.descending, matches, serverName]);
  const selection = useSelection(visibleNodes.filter((n) => !n.deleting).map((n) => n.id));
  const picked = nodes.filter((n) => selection.has(n.id));
  // Seller-run nodes have no local sing-box for a change to restart.
  const managed = (n: Node) => servers.find((s) => s.id === n.serverId)?.managementMode !== "external";
  const save = (n: Node, enabled: boolean) => mutation("/api/nodes/" + n.id, "PATCH", { ...n, enabled, password: "", shadowTlsPassword: "" });
  const setEnabled = (list: Node[], enabled: boolean) => {
    const changing = list.filter((n) => n.enabled !== enabled);
    if (!changing.length) return;
    const verb = enabled ? "启用" : "停用";
    setConfirmation({
      title: `${verb}节点`,
      message: `确定${verb}这 ${changing.length} 个节点？\n${changing.map((n) => n.name).join("、")}` + (changing.some(managed) ? "\n所在服务器的 sing-box 会重启，其上所有连接将中断数秒。" : ""),
      confirmLabel: verb,
      onConfirm: () => {
        selection.clear();
        if (changing.length === 1) void act(() => save(changing[0], enabled), `节点已${verb}，等待 Agent 应用`);
        else void runBatch(`批量${verb}节点`, changing, (n) => n.name, (n) => save(n, enabled));
      },
    });
  };
  const batchDelete = () => setConfirmation({
    title: "批量删除节点",
    message: `确定删除这 ${picked.length} 个节点？\n${picked.map((n) => n.name).join("、")}\n被链路使用的节点不会被删除，并会在结果中说明。此操作无法撤销。`,
    confirmLabel: "删除",
    onConfirm: () => { selection.clear(); void runBatch("批量删除节点", picked, (n) => n.name, (n) => mutation("/api/nodes/" + n.id, "DELETE")); },
  });
  return protect(
          <section className="panel">
            <div className="panelHead">
              <div>
                <h2>节点列表</h2>
                <p>SS、Snell、AnyTLS 与 SOCKS5 节点配置及流量</p>
              </div>
              <button className="primary" onClick={() => openNode()}>
                新建节点
              </button>
            </div>
            <div className="filters">
              <select aria-label="按服务器筛选节点" value={serverFilter} onChange={(e) => setServerFilter(e.target.value)}>
                <option value="">全部服务器</option>
                {servers.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name}
                  </option>
                ))}
              </select>
              <select aria-label="按协议筛选节点" value={protocol} onChange={(e) => setProtocol(e.target.value)}>
                <option value="">全部协议</option>
                <option value="ss">SS</option>
                <option value="snell">Snell</option>
                <option value="anytls">AnyTLS</option>
                <option value="socks5">SOCKS5</option>
              </select>
              <select aria-label="按状态筛选节点" value={status} onChange={(e) => setStatus(e.target.value)}>
                <option value="">全部状态</option>
                {[...new Set([...nodes.map((n) => n.deleting ? "deleting" : n.status), ...(status ? [status] : [])])].sort().map((value) => <option key={value} value={value}>{statusLabels[value]?.[0] || value}</option>)}
              </select>
              {filtered && <button type="button" className="ghost" onClick={() => { setQ(""); setProtocol(""); setStatus(""); setServerFilter(""); }}>清空筛选</button>}
              {filtered && <span className="hint" role="status">{q && `已定位：${q} · `}显示 {visibleNodes.length} / {nodes.length} 个</span>}
            </div>
            {selection.selected.length > 0 && <div className="batchBar" role="toolbar" aria-label="批量操作">
              <strong>已选 {selection.selected.length} 个</strong>
              <button disabled={!picked.some((n) => !n.enabled)} onClick={() => setEnabled(picked, true)}>启用</button>
              <button disabled={!picked.some((n) => n.enabled)} onClick={() => setEnabled(picked, false)}>停用</button>
              <button className="dangerText" onClick={batchDelete}>删除</button>
              <button className="textButton" onClick={selection.clear}>取消选择</button>
            </div>}
            <TableWrap>
              <table>
                <thead>
                  <tr>
                    <th className="selectCell"><input type="checkbox" aria-label="选择全部节点" checked={selection.all} onChange={selection.toggleAll} /></th>
                    <SortHeader sort={sort} id="name" label="节点" />
                    <SortHeader sort={sort} id="server" label="服务器" />
                    <SortHeader sort={sort} id="port" label="协议 / 端口" />
                    <SortHeader sort={sort} id="up" label="上行" />
                    <SortHeader sort={sort} id="down" label="下行" />
                    <SortHeader sort={sort} id="status" label="状态" />
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {visibleNodes.map((n) => (
                    <tr key={n.id}>
                      <td className="selectCell"><input type="checkbox" aria-label={`选择 ${n.name}`} checked={selection.has(n.id)} disabled={!!n.deleting} onChange={() => selection.toggle(n.id)} /></td>
                      <td>
                        <strong>{n.name}</strong>
                        <small className="mono">{n.id.slice(0, 8)}</small>
                      </td>
                      <td><button type="button" className="textButton rowLink" title="查看这台服务器" onClick={() => goTo("servers", "", { q: serverName(n.serverId) })}>{serverName(n.serverId)}</button></td>
                      <td>
                        <span className="chip">{n.protocol.toUpperCase()}</span>{" "}
                        <span className="mono">:{n.port}</span>
                        {n.protocol === "snell" && n.shadowTlsHost && <small>ShadowTLS v3 · {n.shadowTlsHost}</small>}
                        {n.protocol === "snell" && !n.shadowTlsHost && <small className="dangerText">旧节点未启用 ShadowTLS，请编辑节点升级</small>}
                        {n.singleUser && <small>单用户 · 共享节点凭据</small>}
                        <small>{n.direct ? "允许直连" : n.agentProxySources ? "链路 / Agent 访问" : "仅链路访问"}</small>
                      </td>
                      <td>{bytes(n.uplink)}</td>
                      <td>{bytes(n.downlink)}</td>
                      <td>
                        <Status value={n.deleting ? "deleting" : n.status} />
                        {n.error && (
                          <small className="dangerText">{n.error}</small>
                        )}
                      </td>
                      <td>
                        <div className="actions">
                          <button onClick={() => setTrafficNode(n)}>
                            流量
                          </button>
                          <button onClick={() => openNode(n)} disabled={!!n.deleting} title={n.deleting ? "节点正在删除" : ""}>编辑</button>
                          <ActionMenu>
                          <button disabled={!!n.deleting} onClick={() => setEnabled([n], !n.enabled)}>{n.enabled ? "停用" : "启用"}</button>
                          <button onClick={() => openTemplate(n)}>存为模板</button>
                          {n.protocol === "snell" ? (
                            <button onClick={() => goTo("subscriptions", "")}>
                              通过订阅获取
                            </button>
                          ) : (
                            <button
                              disabled={!n.direct}
                              title={!n.direct ? "该节点未开启允许直连；请编辑节点开启，或通过链路订阅使用" : "复制节点直连链接"}
                              onClick={() =>
                                act(async () => {
                                  const v = await api<{ uri: string }>(
                                    "/api/nodes/" + n.id + "/share",
                                  );
                                  await copy(v.uri);
                                }, "已复制节点链接")
                              }
                            >
                              复制链接
                            </button>
                          )}
                          <button
                            className="dangerText"
                            onClick={() =>
                              deleteItem("/api/nodes/" + n.id, "节点")
                            }
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
              {!visibleNodes.length && <Empty text={filtered ? "没有符合筛选条件的节点" : "暂无节点，点击右上角新建"} />}
            </TableWrap>
          </section>,
  );
}
