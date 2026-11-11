import { useApp } from "../app/context";
import { Empty, TableWrap } from "../app/ui";

export default function Templates() {
  const { servers, templates, openTemplate, useTemplate, deleteItem, protect } = useApp();
  return protect(
          <section className="panel">
            <div className="panelHead">
              <div>
                <h2>节点模板</h2>
                <p>保存常用配置，新建节点时选择模板即可带入</p>
              </div>
              <button className="primary" onClick={() => openTemplate()}>
                新建模板
              </button>
            </div>
            <TableWrap>
              <table>
                <thead>
                  <tr>
                    <th>模板名称</th>
                    <th>协议</th>
                    <th>端口</th>
                    <th>主要设置</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {templates.map((t) => (
                    <tr key={t.id}>
                      <td><strong>{t.name}</strong></td>
                      <td><span className="chip">{t.protocol.toUpperCase()}</span></td>
                      <td className="mono">{t.port}</td>
                      <td className="mono">
                        {t.protocol === "ss" ? t.method : t.protocol === "socks5" ? `用户名：${t.username || "未设置"}` : t.protocol === "snell" ? `ShadowTLS v3 · ${t.shadowTlsHost || "未配置"}` : t.tlsName}
                      </td>
                      <td>
                        <div className="actions">
                          <button onClick={() => void useTemplate(t)} disabled={!servers.length}>使用模板</button>
                          <button onClick={() => openTemplate(t)}>编辑</button>
                          <button className="dangerText" onClick={() => deleteItem("/api/node-templates/" + t.id, "节点模板")}>删除</button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!templates.length && <Empty text="还没有模板，可以新建模板或从现有节点保存" />}
            </TableWrap>
          </section>,
  );
}
