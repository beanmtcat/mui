import { useMemo } from "react";
import { api, bytes, mutation } from "../api";
import { useApp } from "../app/context";
import { ActionMenu, Empty, parseSort, SortHeader, sortRows, Status, TableWrap } from "../app/ui";
import { useUrlParam } from "../app/url";
import { MemoMaskedValue as MaskedValue } from "../components/secrets";

export default function Subscriptions() {
  const { subs, customers, issued, setIssued, preview, setPreview, act, copy, goTo, setConfirmation, setTrafficSub, openSubscription, pendingNodes, pendingSummary, sharedSubNodes, onlySharedSubNodes, restartNotice, subNodeIds, surgeImportHelp, matches, protect } = useApp();
  const [subQuery, setSubQuery] = useUrlParam("q"), [sortValue, setSort] = useUrlParam("sort");
  const sort = parseSort(sortValue, setSort);
  const customerName = (id?: string) => customers.find((c) => c.id === id)?.name || "";
  const visibleSubs = useMemo(() => sortRows(subs.filter((sub) => matches(subQuery, sub.name, customerName(sub.customerId))), sort, {
    name: (x) => x.name, customer: (x) => customerName(x.customerId), format: (x) => x.format,
    traffic: (x) => (x.uplink || 0) + (x.downlink || 0), expires: (x) => x.expiresAt ? new Date(x.expiresAt).getTime() : Number.MAX_SAFE_INTEGER,
  }), [subs, customers, subQuery, sort.key, sort.descending, matches]);
  return protect(
          <section className="panel">
            <div className="panelHead">
              <div>
                <h2>订阅管理</h2>
                <p>分发节点和链路；支持独立凭据统计及单用户共享凭据</p>
              </div>
              <button
                className="primary"
                onClick={() => openSubscription()}
              >
                新建订阅
              </button>
            </div>
            <div className="filters">
              <input type="search" value={subQuery} onChange={(e) => setSubQuery(e.target.value)} placeholder="搜索订阅名称或客户" aria-label="搜索订阅" />
              {subQuery && <span className="hint">{visibleSubs.length} / {subs.length}</span>}
            </div>
            <TableWrap>
              <table>
                <thead>
                  <tr>
                    <SortHeader sort={sort} id="name" label="名称" />
                    <SortHeader sort={sort} id="customer" label="客户" />
                    <SortHeader sort={sort} id="format" label="格式" />
                    <th>内容</th>
                    <SortHeader sort={sort} id="traffic" label="已用流量" />
                    <th>状态</th>
                    <SortHeader sort={sort} id="expires" label="到期" />
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {visibleSubs.map((s) => (
                    <tr key={s.id}>
                      <td>
                        <strong>{s.name}</strong>
                      </td>
                      <td>{s.customerId && customers.some((c) => c.id === s.customerId) ? <button type="button" className="textButton rowLink" onClick={() => goTo("customers", "", { q: customers.find((c) => c.id === s.customerId)?.name || "" })}>{customers.find((c) => c.id === s.customerId)?.name}</button> : "未关联"}</td>
                      <td>
                        <span className="chip">{s.format === "v2rayn" ? "v2rayN" : s.format}</span>
                      </td>
                      <td>{s.routeIds?.length || 0} 条链路<small>{s.nodeIds?.length || 0} 个直连节点</small></td>
                      <td>
                        {onlySharedSubNodes(s) ? <span className="hint">无法按订阅统计</span> : <button className="textButton" onClick={() => { setTrafficSub(s); }}>
                          {bytes((s.uplink || 0) + (s.downlink || 0))}
                        </button>}
                        {sharedSubNodes(s).length > 0 && <small>共享凭据节点的流量请在节点中查看{onlySharedSubNodes(s) ? "" : "；此处仅统计独立凭据节点"}</small>}
                      </td>
                      <td>
                        <Status value={!s.enabled ? "disabled" : s.expiresAt && new Date(s.expiresAt).getTime() <= Date.now() ? "expired" : pendingNodes(s).length ? "partial" : "active"} />
                        {s.enabled && pendingNodes(s).length > 0 && <small className="hint">尚未生效，暂不下发：{pendingSummary(s)}。其余节点正常提供。</small>}
                      </td>
                      <td>
                        {s.expiresAt
                          ? new Date(s.expiresAt).toLocaleDateString()
                          : "不过期"}
                      </td>
                      <td>
                        <div className="actions">
                          <button
                            onClick={() =>
                              act(async () => {
                                setPreview(
                                  await api(
                                    "/api/subscriptions/" + s.id + "/preview",
                                  ),
                                );
                              }, "预览已生成")
                            }
                          >
                            预览
                          </button>
                          <button
                            onClick={() => openSubscription(s)}
                          >
                            编辑
                          </button>
                          <button
                            onClick={() =>
                              act(async () => {
                                const result = await api<{ url: string }>("/api/subscriptions/" + s.id + "/link");
                                setIssued({ url: result.url, format: s.format });
                              }, "订阅链接已显示在下方")
                            }
                          >
                            查看链接
                          </button>
                          <ActionMenu>
                          <button
                            onClick={() =>
                              setConfirmation({
                                title: s.enabled ? "停用订阅" : "启用订阅",
                                message: (s.enabled
                                  ? `停用「${s.name}」？订阅下载链接立即失效。独立用户凭据在 Agent 应用配置后失效。${sharedSubNodes(s).length ? "共享凭据的节点仍可访问，撤销访问需更换节点密码。" : ""}`
                                  : `启用「${s.name}」？`) + restartNotice(subNodeIds(s)),
                                confirmLabel: s.enabled ? "停用" : "启用",
                                onConfirm: () => {
                                  void act(
                                    () => mutation("/api/subscriptions/" + s.id, "PATCH", { ...s, enabled: !s.enabled }),
                                    s.enabled ? "已停用" : "已启用",
                                  );
                                },
                              })
                            }
                          >
                            {s.enabled ? "停用" : "启用"}
                          </button>
                          <button
                            onClick={() =>
                              setConfirmation({
                                title: "轮换订阅链接",
                                message: `为「${s.name}」生成新链接？旧链接立即失效，客户需要用新链接重新导入。已导入的节点不受影响。`,
                                confirmLabel: "轮换",
                                onConfirm: () => {
                                  void act(async () => {
                                    const result = await mutation<{ url: string }>("/api/subscriptions/" + s.id + "/rotate", "POST");
                                    setIssued({ url: result.url, format: s.format });
                                  }, "订阅链接已轮换");
                                },
                              })
                            }
                          >
                            轮换链接
                          </button>
                          <button
                            className="dangerText"
                            onClick={() =>
                              setConfirmation({
                                title: "删除订阅",
                                message: `确定删除「${s.name}」？下载链接立即失效，独立用户凭据在 Agent 应用配置后失效。${sharedSubNodes(s).length ? "共享凭据的节点仍可访问，撤销访问需更换节点密码。" : ""}此操作无法撤销。` + restartNotice(subNodeIds(s)),
                                confirmLabel: "删除",
                                onConfirm: () => { void act(() => mutation("/api/subscriptions/" + s.id, "DELETE"), "订阅已删除"); },
                              })
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
              {!visibleSubs.length && <Empty text={subQuery ? "没有匹配的订阅" : "暂无订阅，点击右上角新建"} />}
            </TableWrap>
            {preview && (
              <div className="commandBox">
                <div>
                  <strong>订阅预览</strong>
                  <span>
                    {preview.excluded.length
                      ? preview.excluded.join("；")
                      : "所有所选节点均已输出"}
                  </span>
                </div>
                <MaskedValue value={preview.content} pre />
              </div>
            )}
            {issued && (
              <div className="commandBox">
                <div>
                  <strong>订阅链接</strong>
                  <span>可随时在订阅列表中再次查看</span>
                </div>
                <MaskedValue value={issued.url}><button type="button" onClick={() => copy(issued.url)}>复制</button></MaskedValue>
                {issued.format === "surge" && surgeImportHelp(issued.url)}
              </div>
            )}
          </section>,
  );
}
