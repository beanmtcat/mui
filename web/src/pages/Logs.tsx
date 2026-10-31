import { useState } from "react";
import { mutation, type AuditEntry, type ConnectionIP, type Operation, type SubscriptionAccess } from "../api";
import { useApp } from "../app/context";
import { setError } from "../app/feedback";
import { DateRange, Empty, kindLabel, kindLabels, Pager, Status, TableWrap, usePagedLog, type LogRange } from "../app/ui";
import { useServerParam, useUrlParam } from "../app/url";

const showError = (e: Error) => setError(e.message);
function useRange(): [LogRange, (range: LogRange) => void] {
  const [from, setFrom] = useUrlParam("from"), [to, setTo] = useUrlParam("to");
  return [{ from, to }, (range) => { setFrom(range.from); setTo(range.to); }];
}

export function Accesses() {
  const { customers, subs, refreshTick, pollTick, protect } = useApp();
  const [accessCustomer, setAccessCustomer] = useUrlParam("customer");
  const [accessRange, setAccessRange] = useRange();
  const accessLog = usePagedLog<SubscriptionAccess>("/api/clients/accesses?customerId=" + encodeURIComponent(accessCustomer), accessRange, showError, refreshTick, pollTick);
  return protect(
            <section className="panel">
              <div className="panelHead"><div><h2>订阅访问记录</h2><p>成功下载订阅时记录来源 IP、客户与订阅。按数据保留设置清理。</p></div></div>
              <div className="filters">
                <select value={accessCustomer} onChange={(e) => setAccessCustomer(e.target.value)} aria-label="按客户筛选访问记录">
                  <option value="">全部客户</option>
                  {customers.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
                </select>
                <DateRange value={accessRange} onChange={setAccessRange} />
              </div>
              <TableWrap cards={false}><table><thead><tr><th>时间</th><th>客户</th><th>订阅</th><th>来源 IP</th></tr></thead><tbody>
                {accessLog.items.map((item) => <tr key={item.id}>
                  <td>{new Date(item.at).toLocaleString()}</td>
                  <td>{customers.find((c) => c.id === item.customerId)?.name || "未关联 / 已删除"}</td>
                  <td>{subs.find((s) => s.id === item.subscriptionId)?.name || "已删除"}</td>
                  <td><code>{item.ip}</code></td>
                </tr>)}
              </tbody></table>{accessLog.empty && <Empty text="暂无订阅访问记录" />}</TableWrap>
              <Pager log={accessLog} />
            </section>,
  );
}

export function Connections() {
  const { servers, nodes, routes, serverName, refreshTick, pollTick, protect } = useApp();
  const [connectionServer, setConnectionServer] = useServerParam();
  const [connectionRange, setConnectionRange] = useRange();
  const connectionLog = usePagedLog<ConnectionIP>("/api/clients/connections?serverId=" + encodeURIComponent(connectionServer), connectionRange, showError, refreshTick, pollTick);
  return protect(
            <section className="panel">
              <div className="panelHead"><div><h2>节点连接 IP</h2><p>入口记录连接来源（TCP / UDP，需入口 Agent 0.6.13+），可能包含扫描、握手失败和正常访问；未验证节点身份，无法确定使用了哪个订阅。直连节点从 sing-box 采样；中转和 Agent 的对端地址单独标注。离线入口无法上报，历史记录无法还原。</p></div></div>
              <div className="filters">
                <select value={connectionServer} onChange={(e) => setConnectionServer(e.target.value)} aria-label="按采集服务器筛选连接 IP">
                  <option value="">全部服务器</option>
                  {servers.map((sv) => <option key={sv.id} value={sv.id}>{sv.name}</option>)}
                </select>
                <DateRange value={connectionRange} onChange={setConnectionRange} label="最近连接" />
              </div>
              <TableWrap cards={false}><table><thead><tr><th>最近连接</th><th>采集服务器</th><th>节点 / 链路</th><th>连接来源 IP</th><th>采集方式 / 对端地址</th></tr></thead><tbody>
                {connectionLog.items.map((item) => {
                  const sourceLabel = ({ entry: "入口连接来源（未验证）", direct: "节点直连采样", relay: "中转 / 服务器对端", agent: "Agent 代理连接", unknown: "仅有落地对端，无法确认客户端" } as Record<string, string>)[item.sourceKind || "unknown"];
                  return <tr key={item.serverId + item.nodeId + item.ip + (item.routeId || "")}>
                    <td>{new Date(item.lastSeen).toLocaleString()}</td>
                    <td>{serverName(item.serverId)}</td>
                    <td>{nodes.find((n) => n.id === item.nodeId)?.name || "已删除"}{item.routeId && <small>{routes.find((r) => r.id === item.routeId)?.name || "历史链路（已删除）"}</small>}</td>
                    <td>{item.clientIp ? <code>{item.clientIp}</code> : <span className="hint">无法获取</span>}</td>
                    <td>{sourceLabel}{item.peerIp && <small>对端：<code>{item.peerIp}</code></small>}</td>
                  </tr>;
                })}
              </tbody></table>{connectionLog.empty && <Empty text="暂无连接来源记录；链路请升级入口 Agent 至 0.6.13，离线入口无法上报" />}</TableWrap>
              <Pager log={connectionLog} />
            </section>,
  );
}

export function Operations() {
  const { servers, serverName, act, refreshTick, pollTick, protect } = useApp();
  const [opServer, setOpServer] = useServerParam();
  const [opKind, setOpKind] = useUrlParam("kind");
  const [opRange, setOpRange] = useRange();
  const opLog = usePagedLog<Operation>("/api/operations?serverId=" + encodeURIComponent(opServer) + "&kind=" + encodeURIComponent(opKind), opRange, showError, refreshTick, pollTick);
  return protect(
          <section className="panel">
            <div className="panelHead">
              <div>
                <h2>操作记录</h2>
                <p>查看配置下发、执行结果和失败原因</p>
              </div>
            </div>
            <div className="filters">
              <select value={opServer} onChange={(e) => setOpServer(e.target.value)} aria-label="按服务器筛选操作记录">
                <option value="">全部服务器</option>
                {servers.map((sv) => <option key={sv.id} value={sv.id}>{sv.name}</option>)}
              </select>
              <select value={opKind} onChange={(e) => setOpKind(e.target.value)} aria-label="按操作筛选操作记录">
                <option value="">全部操作</option>
                {Object.entries(kindLabels).map(([kind, label]) => <option key={kind} value={kind}>{label}</option>)}
              </select>
              <DateRange value={opRange} onChange={setOpRange} />
            </div>
            <TableWrap>
              <table>
                <thead>
                  <tr>
                    <th>时间</th>
                    <th>服务器</th>
                    <th>操作</th>
                    <th>状态</th>
                    <th>错误</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {opLog.items.map((o) => (
                    <tr key={o.id}>
                      <td>{new Date(o.createdAt).toLocaleString()}</td>
                      <td><button type="button" className="textButton rowLink" onClick={() => setOpServer(o.serverId)} title="只看这台服务器">{serverName(o.serverId)}</button></td>
                      <td>{kindLabel(o.kind)}</td>
                      <td>
                        <Status value={o.status} />
                      </td>
                      <td className="errorCell">{o.error || "—"}</td>
                      <td>
                        {o.status === "failed" && (
                          <button
                            onClick={() =>
                              act(
                                () =>
                                  mutation(
                                    "/api/operations/" + o.id + "/retry",
                                    "POST",
                                  ),
                                "已重新排队",
                              )
                            }
                          >
                            重试
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {opLog.empty && <Empty text={opServer || opKind || opRange.from || opRange.to ? "没有符合筛选条件的操作记录" : "暂无操作记录"} />}
            </TableWrap>
            <Pager log={opLog} />
          </section>,
  );
}

export function Audit() {
  const { auditTarget, refreshTick, pollTick, protect } = useApp();
  const [auditQuery, setAuditQuery] = useUrlParam("q");
  const [auditInput, setAuditInput] = useState(auditQuery);
  const [auditRange, setAuditRange] = useRange();
  const auditLog = usePagedLog<AuditEntry>("/api/audit?q=" + encodeURIComponent(auditQuery), auditRange, showError, refreshTick, pollTick);
  return protect(
          <section className="panel">
            <div className="panelHead">
              <div>
                <h2>审计日志</h2>
                <p>管理员在面板上做过的改动</p>
              </div>
            </div>
            <form className="filters" onSubmit={(e) => { e.preventDefault(); setAuditQuery(auditInput.trim()); }}>
              <input value={auditInput} onChange={(e) => setAuditInput(e.target.value)} type="search" placeholder="搜索动作、说明或 IP，如 node.delete" aria-label="搜索审计日志" />
              <button className="ghost">搜索</button>
              {auditQuery && <button type="button" className="textButton" onClick={() => { setAuditInput(""); setAuditQuery(""); }}>清除</button>}
              <DateRange value={auditRange} onChange={setAuditRange} />
            </form>
            <TableWrap>
              <table>
                <thead>
                  <tr><th>时间</th><th>操作 IP</th><th>动作</th><th>对象</th><th>说明</th></tr>
                </thead>
                <tbody>
                  {auditLog.items.map((entry) => (
                    <tr key={entry.id}>
                      <td>{new Date(entry.at).toLocaleString()}</td>
                      <td className="mono">{entry.ip || (entry.action === "admin.reset" || entry.action === "certificate.expiring" ? "系统" : "未记录")}</td>
                      <td className="mono">{entry.action}</td>
                      <td>{auditTarget(entry.target)}</td>
                      <td>{entry.detail || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {auditLog.empty && <Empty text={auditQuery ? "没有匹配的审计记录" : "暂无审计记录"} />}
            </TableWrap>
            <Pager log={auditLog} />
          </section>,
  );
}
