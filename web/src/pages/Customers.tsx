import { useMemo } from "react";
import { bytes } from "../api";
import { useApp } from "../app/context";
import { Empty, parseSort, SortHeader, sortRows, TableWrap } from "../app/ui";
import { useUrlParam } from "../app/url";

export default function Customers() {
  const { customers, subs, goTo, openModal, deleteItem, sharedSubNodes, onlySharedSubNodes, matches, protect } = useApp();
  const [customerQuery, setCustomerQuery] = useUrlParam("q"), [sortValue, setSort] = useUrlParam("sort");
  const sort = parseSort(sortValue, setSort);
  const visibleCustomers = useMemo(() => sortRows(customers.filter((c) => matches(customerQuery, c.name, c.notes)), sort, {
    name: (c) => c.name, subs: (c) => subs.filter((s) => s.customerId === c.id).length,
    traffic: (c) => subs.filter((s) => s.customerId === c.id).reduce((sum, s) => sum + (s.uplink || 0) + (s.downlink || 0), 0),
  }), [customers, subs, customerQuery, sort.key, sort.descending, matches]);
  return protect(
            <section className="panel">
              <div className="panelHead">
                <div><h2>客户端管理</h2><p>创建客户后，在订阅中关联客户；原有订阅可在订阅管理中编辑。</p></div>
                <button className="primary" onClick={() => openModal({ kind: "customer", form: { name: "", notes: "" } })}>新建客户</button>
              </div>
              <div className="filters">
                <input type="search" value={customerQuery} onChange={(e) => setCustomerQuery(e.target.value)} placeholder="搜索客户名称或备注" aria-label="搜索客户" />
                {customerQuery && <span className="hint">{visibleCustomers.length} / {customers.length}</span>}
              </div>
              <TableWrap><table><thead><tr><SortHeader sort={sort} id="name" label="客户" /><th>备注</th><SortHeader sort={sort} id="subs" label="关联订阅" /><SortHeader sort={sort} id="traffic" label="已用流量" /><th>操作</th></tr></thead><tbody>
                {visibleCustomers.map((c) => {
                  const memberships = subs.filter((s) => s.customerId === c.id);
                  const shared = memberships.some((s) => sharedSubNodes(s).length > 0);
                  const onlyShared = memberships.length > 0 && memberships.every(onlySharedSubNodes);
                  return <tr key={c.id}>
                  <td><strong>{c.name}</strong></td><td>{c.notes || "—"}</td>
                  <td>{memberships.length ? memberships.map((s, i) => <span key={s.id}>{i > 0 && "、"}<button type="button" className="textButton rowLink" onClick={() => goTo("subscriptions", "", { q: s.name })}>{s.name}</button></span>) : "—"}</td>
                  <td>{onlyShared ? "无法按客户统计" : bytes(memberships.reduce((sum, s) => sum + (s.uplink || 0) + (s.downlink || 0), 0))}{shared && <small>共享凭据节点的流量请在节点中查看{onlyShared ? "" : "；此处仅统计独立凭据节点"}</small>}</td>
                  <td><div className="actions"><button onClick={() => openModal({ kind: "customer", form: { ...c } })}>编辑</button><button className="dangerText" onClick={() => deleteItem("/api/customers/" + c.id, "客户")}>删除</button></div></td>
                </tr>; })}
              </tbody></table>{!visibleCustomers.length && <Empty text={customerQuery ? "没有匹配的客户" : "暂无客户，点击右上角新建"} />}</TableWrap>
            </section>,
  );
}
