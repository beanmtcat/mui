import { useMemo } from "react";
import { mutation } from "../api";
import { useApp } from "../app/context";
import { Empty, parseSort, SortHeader, sortRows, TableWrap } from "../app/ui";
import { useUrlParam } from "../app/url";

export default function Certificates() {
  const { nodes, certificates, act, goTo, openModal, deleteItem, matches, protect } = useApp();
  const [q, setQ] = useUrlParam("q"), [sortValue, setSort] = useUrlParam("sort");
  const sort = parseSort(sortValue, setSort);
  const visible = useMemo(() => sortRows(certificates.filter((c) => matches(q, c.name, c.domain, ...(c.dnsNames || []))), sort, {
    name: (c) => c.name || c.domain, domain: (c) => c.domain, expires: (c) => new Date(c.expiresAt).getTime(),
    nodes: (c) => nodes.filter((n) => n.certificateId === c.id).length,
  }), [certificates, nodes, q, sort.key, sort.descending, matches]);
  return protect(
          <section className="panel">
            <div className="panelHead">
              <div>
                <h2>TLS 证书</h2>
                <p>统一证书库，可供多台服务器的 AnyTLS 节点复用，私钥加密保存</p>
              </div>
              <button
                className="primary"
                onClick={() => openModal({ kind: "certificate", form: { name: "", domain: "", pem: "", key: "" } })}
              >
                上传证书
              </button>
            </div>
            {q && <div className="filters">
              <button type="button" className="ghost" onClick={() => setQ("")}>清空筛选</button>
              <span className="hint" role="status">已定位：{q} · 显示 {visible.length} / {certificates.length} 张</span>
            </div>}
            <TableWrap>
              <table>
                <thead>
                  <tr>
                    <SortHeader sort={sort} id="name" label="名称" />
                    <SortHeader sort={sort} id="nodes" label="使用节点" />
                    <SortHeader sort={sort} id="domain" label="域名" />
                    <SortHeader sort={sort} id="expires" label="到期时间" />
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {visible.map((c) => (
                    <tr key={c.id}>
                      <td>
                        <strong>{c.name || c.domain}</strong>
                      </td>
                      <td>
                        <button type="button" className="textButton rowLink" onClick={() => goTo("nodes", "", { q: c.domain })}>{nodes.filter((n) => n.certificateId === c.id).length} 个节点</button>
                        {!!c.pendingServers?.length && <div className="certificatePending">
                          <span className="status warn" title={c.pendingServers.join("、")}>{c.pendingServers.length} 台服务器待应用</span>
                          <button type="button" className="textButton" onClick={() => void act(
                            () => mutation("/api/certificates/" + c.id, "PATCH", { name: c.name, domain: c.domain }),
                            "已重新排队下发证书",
                          )}>重新下发</button>
                        </div>}
                      </td>
                      <td className="mono">{c.domain}</td>
                      <td>{new Date(c.expiresAt).toLocaleDateString()}{c.expiringSoon && <span className="status bad">{c.daysUntilExpiry !== undefined && c.daysUntilExpiry < 0 ? "已过期" : c.daysUntilExpiry !== undefined ? `${c.daysUntilExpiry} 天后到期` : "即将到期"}</span>}</td>
                      <td>
                        <div className="actions certificateActions">
                          <button
                            onClick={() => openModal({ kind: "certificate", form: { id: c.id, name: c.name, domain: c.domain, pem: "", key: "" } })}
                          >
                            编辑
                          </button>
                          <button
                            className="dangerText"
                            onClick={() =>
                              deleteItem("/api/certificates/" + c.id, "证书")
                            }
                          >
                            删除
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!visible.length && <Empty text={q ? "没有匹配的证书" : "暂无证书，点击右上角上传"} />}
            </TableWrap>
          </section>,
  );
}
