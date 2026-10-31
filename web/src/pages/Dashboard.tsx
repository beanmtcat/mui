import { lazy, Suspense, useCallback, useMemo, useState } from "react";
import { bytes } from "../api";
import { useApp } from "../app/context";
import type { Usage } from "../app/helpers";
import { Empty, kindLabel, Status } from "../app/ui";

const TrafficChart = lazy(() => import("../components/TrafficChart"));

// Shown until the first server, node and subscription exist. Dismissing it is
// a preference of this browser, not something the panel needs to remember.
function Onboarding() {
  const { servers, nodes, subs, goTo, openServer, openNode, openSubscription } = useApp();
  const [hidden, setHidden] = useState(() => { try { return localStorage.getItem("mui-onboarding-hidden") === "1"; } catch { return false; } });
  const steps = [
    { done: servers.length > 0, title: "添加服务器", detail: "录入服务器，并在目标机运行接入命令", action: () => { goTo("servers"); openServer(); } },
    { done: servers.some((s) => s.status === "online" || s.managementMode === "external" || s.managementMode === "offline"), title: "等待服务器上线", detail: "在线 Agent 接入后这里会自动更新", action: () => goTo("servers") },
    { done: nodes.length > 0, title: "创建节点", detail: "在落地或中转服务器上建节点", action: () => { goTo("nodes"); openNode(); } },
    { done: subs.length > 0, title: "创建订阅", detail: "把节点或链路分发给客户端", action: () => { goTo("subscriptions"); openSubscription(); } },
  ];
  if (hidden || steps.every((step) => step.done)) return null;
  const next = steps.find((step) => !step.done);
  return <section className="panel onboarding">
    <div className="panelHead">
      <div><h2>开始使用</h2><p>按顺序完成下面几步，就能得到第一条可用的订阅</p></div>
      <button className="textButton" onClick={() => { try { localStorage.setItem("mui-onboarding-hidden", "1"); } catch { /* A session-only dismissal is fine. */ } setHidden(true); }}>不再显示</button>
    </div>
    <ol className="onboardingSteps">
      {steps.map((step) => <li key={step.title} className={step.done ? "done" : step === next ? "current" : ""}>
        <div><strong>{step.title}</strong><small>{step.detail}</small></div>
        {step === next && <button className="primary" onClick={step.action}>去完成</button>}
      </li>)}
    </ol>
  </section>;
}

export default function Dashboard() {
  const { servers, nodes, subs, customers, operations, summary, dashSeries, ranking, attention, unreadAttention, readItems, markRead, markUnread, liveSubs, failedNodes, split, activeNodes, onlineServers, agentServers, goTo, serverName, protect } = useApp();
  const total = useCallback((v: Usage) => v.uplink + v.downlink, []);
  const topNodes = useMemo(() => [...ranking.nodes].sort((x, y) => total(y) - total(x)).slice(0, 5), [ranking, total]);
  const topSubs = useMemo(() => [...ranking.subscriptions].sort((x, y) => total(y) - total(x)).slice(0, 5), [ranking, total]);
  const todayByServer = useCallback((id: string) =>
    ranking.nodes.filter((u) => nodes.find((n) => n.id === u.id)?.serverId === id).reduce((sum, u) => sum + total(u), 0), [ranking, nodes, total]);
  const [showRead, setShowRead] = useState(false);
  const totalTraffic = useMemo(() => nodes.reduce((sum, n) => sum + n.uplink + n.downlink, 0), [nodes]);
  const statCards = useMemo(() => [
    {
      label: "在线服务器",
      value: `${onlineServers.length} / ${agentServers.length}`,
      note: agentServers.length === onlineServers.length ? "全部在线" : `${agentServers.length - onlineServers.length} 台离线或未接入`,
    },
    {
      label: "运行中节点",
      value: `${activeNodes.length} / ${nodes.length}`,
      note: failedNodes.length ? `${failedNodes.length} 个应用失败` : `${nodes.filter((n) => !n.enabled).length} 个已停用`,
    },
    {
      label: "有效订阅",
      value: `${liveSubs.length} / ${subs.length}`,
      note: `${customers.length} 个客户`,
    },
    { label: "今日流量", value: bytes(summary.today.uplink + summary.today.downlink), note: split(summary.today) },
    { label: "本月流量", value: bytes(summary.month.uplink + summary.month.downlink), note: split(summary.month) },
    { label: "累计流量", value: bytes(totalTraffic), note: "全部节点" },
  ], [onlineServers, agentServers, activeNodes, nodes, failedNodes, liveSubs, subs, customers, summary, split, totalTraffic]);
  return protect(<>
    <Onboarding />
            <section className="panel">
              <div className="panelHead">
                <h2>需要关注</h2>
                <div className="attentionTools">
                  {unreadAttention.length > 0 && <span className="hint">{unreadAttention.length} 项未读</span>}
                  {unreadAttention.length > 1 && <button className="textButton" onClick={() => markRead(unreadAttention.map((item) => item.key))}>全部已读</button>}
                  {readItems.length > 0 && <button className="textButton" aria-expanded={showRead} onClick={() => setShowRead(!showRead)}>{showRead ? "隐藏已读" : `已读 ${readItems.length} 项`}</button>}
                </div>
              </div>
              {unreadAttention.length ? (
                unreadAttention.slice(0, 12).map((item) => (
                  <div className="listRow attention" key={item.key}>
                    <span className={"status " + (item.tone === "info" ? "idle" : item.tone)} aria-label={item.tone === "bad" ? "严重" : item.tone === "warn" ? "警告" : "提示"} />
                    <div className="grow">{item.text}</div>
                    <button className="textButton" onClick={() => goTo(item.tab, item.server ?? "", item.q ? { q: item.q } : {})}>查看</button>
                    <button className="textButton" onClick={() => markRead([item.key])}>已读</button>
                  </div>
                ))
              ) : (
                <div className="listRow attention"><span className="status good" /><div className="grow">{attention.length ? "没有未读事项。" : "一切正常，没有需要处理的事项。"}</div></div>
              )}
              {unreadAttention.length > 12 && <div className="listRow attention"><div className="grow hint">另有 {unreadAttention.length - 12} 项未显示</div></div>}
              {showRead && readItems.map((item) => (
                <div className="listRow attention attentionRead" key={item.key}>
                  <span className="status idle" aria-label="已读" />
                  <div className="grow">{item.text}</div>
                  <button className="textButton" onClick={() => goTo(item.tab, item.server ?? "", item.q ? { q: item.q } : {})}>查看</button>
                  <button className="textButton" onClick={() => markUnread(item.key)}>标为未读</button>
                </div>
              ))}
            </section>
            <div className="statGrid">
              {statCards.map((c) => (
                <div className="statCard" key={c.label}>
                  <span>{c.label}</span>
                  <strong>{c.value}</strong>
                  <small>{c.note}</small>
                </div>
              ))}
            </div>
            <section className="panel">
              <div className="panelHead"><h2>全部节点流量</h2></div>
              {dashSeries.length ? <Suspense fallback={<div className="trafficChart"><Empty text="正在加载图表…" /></div>}><TrafficChart points={dashSeries} /></Suspense> : <div className="trafficChart"><Empty text="暂无流量样本" /></div>}
            </section>
            <div className="twoCol">
              <section className="panel">
                <div className="panelHead">
                  <h2>今日节点流量排行</h2>
                  <button className="textButton" onClick={() => goTo("nodes", "")}>全部节点 →</button>
                </div>
                {topNodes.length ? (
                  <table><tbody>
                    {topNodes.map((u, index) => {
                      const node = nodes.find((n) => n.id === u.id);
                      return (
                        <tr key={u.id}>
                          <td className="rank">{index + 1}</td>
                          <td><strong>{node?.name || "已删除的节点"}</strong><small>{node ? serverName(node.serverId) : "—"}</small></td>
                          <td className="num">{bytes(total(u))}<small>{split(u)}</small></td>
                        </tr>
                      );
                    })}
                  </tbody></table>
                ) : <Empty text="今天还没有流量" />}
              </section>
              <section className="panel">
                <div className="panelHead">
                  <h2>今日订阅流量排行</h2>
                  <button className="textButton" onClick={() => goTo("subscriptions")}>全部订阅 →</button>
                </div>
                {topSubs.length ? (
                  <table><tbody>
                    {topSubs.map((u, index) => {
                      const sub = subs.find((item) => item.id === u.id);
                      return (
                        <tr key={u.id}>
                          <td className="rank">{index + 1}</td>
                          <td><strong>{sub?.name || (u.id === "direct" ? "节点直连链接" : "已删除的订阅")}</strong><small>{customers.find((c) => c.id === sub?.customerId)?.name || "未关联客户"}</small></td>
                          <td className="num">{bytes(total(u))}<small>{split(u)}</small></td>
                        </tr>
                      );
                    })}
                  </tbody></table>
                ) : <Empty text="今天还没有订阅流量" />}
              </section>
            </div>
            <div className="twoCol">
              <section className="panel">
                <div className="panelHead">
                  <h2>服务器</h2>
                  <button className="textButton" onClick={() => goTo("servers")}>查看全部 →</button>
                </div>
                {servers.length ? (
                  <table>
                    <thead><tr><th>服务器</th><th>状态</th><th>节点</th><th className="num">今日流量</th></tr></thead>
                    <tbody>
                      {servers.slice(0, 8).map((sv) => (
                        <tr key={sv.id}>
                          <td><button type="button" className="textButton rowLink" onClick={() => goTo("servers", "", { q: sv.name })}><strong>{sv.name}</strong></button><small>{sv.country} · {sv.domain || sv.ipv4 || sv.ipv6}</small></td>
                          <td><Status value={sv.status} /></td>
                          <td>{nodes.filter((n) => n.serverId === sv.id && n.enabled && n.status === "active").length} / {nodes.filter((n) => n.serverId === sv.id).length}</td>
                          <td className="num">{bytes(todayByServer(sv.id))}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <Empty text="暂无服务器" />
                )}
              </section>
              <section className="panel">
                <div className="panelHead">
                  <h2>最近任务</h2>
                  <button className="textButton" onClick={() => goTo("operations")}>查看全部 →</button>
                </div>
                {operations.length ? (
                  operations.slice(0, 7).map((o) => (
                    <div className="listRow" key={o.id}>
                      <div className="grow">
                        <strong>{kindLabel(o.kind)}</strong>
                        <small>
                          {serverName(o.serverId)} ·{" "}
                          {new Date(o.createdAt).toLocaleString()}
                        </small>
                      </div>
                      <Status value={o.status} />
                    </div>
                  ))
                ) : (
                  <Empty text="暂无任务记录" />
                )}
              </section>
            </div>
  </>);
}
