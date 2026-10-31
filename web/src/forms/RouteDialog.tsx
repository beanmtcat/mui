import { useState } from "react";
import { mutation, type Route, type RouteHop, type RouteSourceFamily, type RouteSourceMode, type Server } from "../api";
import { useApp } from "../app/context";
import { manualFirewall, rolesText } from "../app/helpers";
import { Field, SubmitButton, useBusy } from "../app/ui";
import { Dialog } from "./Dialog";
import { ItemPicker } from "./ItemPicker";

export default function RouteDialog({ initial }: { initial: Partial<Route> }) {
  const { servers, nodes, serverName, act, closeModal } = useApp();
  const [routeForm, setRouteForm] = useState(initial);
  const { busy, run } = useBusy();
  const submitRoute = (e: React.FormEvent) => {
    e.preventDefault();
    const path = "/api/routes" + (routeForm.id ? "/" + routeForm.id : "");
    void run(async () => {
      if (await act(() => mutation(path, routeForm.id ? "PATCH" : "POST", routeForm), "链路已保存，各跳转发等待 Agent 应用")) closeModal();
    });
  };
              const hops = routeForm.hops || [];
              const node = nodes.find((n) => n.id === routeForm.nodeId);
              const setHop = (i: number, patch: Partial<RouteHop>) =>
                setRouteForm({ ...routeForm, hops: hops.map((h, j) => (j === i ? { ...h, ...patch } : h)) });
              // A server appears once per route, and the exit is never a hop.
              const taken = (i: number) => new Set([
                routeForm.entryServerId || "",
                node?.serverId || "",
                ...hops.flatMap((h, j) => (j === i ? [] : h.serverIds)),
              ]);
              const connectionSettings = (
                senderIds: string[], receiverIds: string[], internal: boolean, sourceMode: RouteSourceMode | undefined,
                sourceFamily: RouteSourceFamily | undefined,
                setInternal: (value: boolean) => void, setSource: (value: RouteSourceMode) => void,
                setFamily: (value: RouteSourceFamily | undefined) => void,
              ) => {
                const senders = servers.filter((s) => senderIds.includes(s.id));
                const receivers = servers.filter((s) => receiverIds.includes(s.id));
                const sourceInternal = sourceMode === "internal" || (!sourceMode || sourceMode === "auto") && internal;
                const targetAddress = (s: Server) => internal ? s.internalAddress : s.domain || s.ipv4 || s.ipv6;
                const targets = receivers.map(targetAddress);
                const useV4 = targets.some((v) => !v || !v.includes(":"));
                const useV6 = targets.some((v) => !v || v.includes(":") || !/^\d+\.\d+\.\d+\.\d+$/.test(v));
                const allowV4 = useV4 && sourceFamily !== "ipv6";
                const allowV6 = useV6 && sourceFamily !== "ipv4";
                const sourceAddresses = (s: Server) => sourceInternal
                  ? (s.internalAddress && (s.internalAddress.includes(":") ? allowV6 : allowV4) ? s.internalAddress : "未填写匹配地址族的内网 IP")
                  : [...new Set([...(allowV4 ? [s.ipv4, s.detectedIpv4] : []), ...(allowV6 ? [s.ipv6, s.detectedIpv6] : [])].filter(Boolean))].join("、") || "未填写匹配地址族的公网 IP";
                const managed = !receivers.length || receivers.some((s) => !manualFirewall(s));
                return (
                  <fieldset className="routeConnection">
                    <legend>{senders.map((s) => s.name).join(" / ") || "请选择发送方"} → {receivers.map((s) => s.name).join(" / ") || "请选择接收方"}</legend>
                    <div className="formGrid">
                      <Field label="防火墙来源：放行发送方的哪个 IP？">
                        <div className="routeSourceSelectors">
                          <select disabled={!managed} value={sourceMode || "auto"} onChange={(e) => setSource(e.target.value as RouteSourceMode)}>
                            <option value="auto">自动（{internal ? "内网 IP" : "公网 IP"}）</option>
                            <option value="public">公网 IP</option>
                            <option value="internal">内网 IP</option>
                          </select>
                          <select aria-label="防火墙来源地址族" disabled={!managed} value={sourceFamily || ""} onChange={(e) => setFamily(e.target.value ? e.target.value as RouteSourceFamily : undefined)}>
                            {routeForm.id && <option value="">原设置</option>}
                            <option value="ipv4">IPv4（默认）</option>
                            <option value="ipv6">IPv6</option>
                            <option value="both">IPv4 + IPv6</option>
                          </select>
                        </div>
                        {managed ? senders.map((s) => <small className="connectionAddress" key={s.id}>{s.name}：{sourceAddresses(s)}</small>) : <small className="connectionAddress">接收方防火墙为手动管理，请自行放行。</small>}
                      </Field>
                      <Field label="连接地址：接收方的哪个地址？">
                        <select value={internal ? "internal" : "public"} onChange={(e) => setInternal(e.target.value === "internal")}>
                          <option value="public">公网地址</option>
                          <option value="internal">内网地址</option>
                        </select>
                        {receivers.map((s) => <small className="connectionAddress" key={s.id}>{s.name}：{targetAddress(s) || "未填写该地址"}</small>)}
                      </Field>
                    </div>
                    {managed && <p className="hint">按接收方实际看到的来源 IP 选择；此设置只生成放行规则，不改变发送方的出口或路由。</p>}
                  </fieldset>
                );
              };
  return <Dialog title={routeForm.id ? "编辑链路" : "新建链路"} value={routeForm} initial={initial} busy={busy}>
                <form onSubmit={submitRoute}>
                  <div className="formGrid">
                    <Field label="名称 *"><input required maxLength={100} value={routeForm.name || ""} onChange={(e) => setRouteForm({ ...routeForm, name: e.target.value })} /></Field>
                    <Field label="首跳（入口 / 线路） *">
                      <select required value={routeForm.entryServerId || ""} onChange={(e) => setRouteForm({ ...routeForm, entryServerId: e.target.value })}>
                        <option value="">选择服务器</option>
                        {servers.filter((s) => s.roles?.some((r) => r === "entry" || r === "line")).map((s) => <option key={s.id} value={s.id}>{s.name}（{rolesText(s.roles)}）</option>)}
                      </select>
                    </Field>
                    <Field label="落地节点 *">
                      <select required value={routeForm.nodeId || ""} onChange={(e) => setRouteForm({ ...routeForm, nodeId: e.target.value })}>
                        <option value="">选择节点</option>
                        {nodes.filter((n) => !n.deleting).map((n) => <option key={n.id} value={n.id}>{n.name}（{n.protocol.toUpperCase()} · {serverName(n.serverId)}）</option>)}
                      </select>
                    </Field>
                    <Field label="端口（留空自动）"><input type="number" min={1024} max={65535} value={routeForm.port || ""} placeholder="优先使用落地节点端口" onChange={(e) => setRouteForm({ ...routeForm, port: Number(e.target.value) || 0 })} /></Field>
                    <Field label="备注"><input maxLength={200} value={routeForm.notes || ""} onChange={(e) => setRouteForm({ ...routeForm, notes: e.target.value })} /></Field>
                    <Field label="状态"><label className="check"><input type="checkbox" checked={!!routeForm.enabled} onChange={(e) => setRouteForm({ ...routeForm, enabled: e.target.checked })} /> 启用链路</label></Field>
                  </div>
                  <div className="field">
                    <span>中间跳（按顺序，可为空）</span>
                    <div className="hopList">
                      {hops.map((hop, i) => (
                        <div className="hop" key={i}>
                          <div className="hopHead">
                            <strong>第 {i + 1} 个中转</strong>
                            <select aria-label={`第 ${i + 1} 跳的模式`} value={hop.balance} onChange={(e) => setHop(i, { balance: e.target.value as RouteHop["balance"] })}>
                              <option value="failover">主备</option>
                              <option value="round-robin">轮询</option>
                            </select>
                            <button type="button" onClick={() => setRouteForm({ ...routeForm, hops: hops.filter((_, j) => j !== i) })}>移除</button>
                          </div>
                          <ItemPicker
                            compact
                            label={`第 ${i + 1} 个中转的服务器`}
                            emptyText="未选择服务器"
                            addText="选择服务器"
                            noneText="没有可选的中转或线路服务器"
                            items={servers.filter((s) => s.roles?.some((r) => r === "transit" || r === "line") && (!taken(i).has(s.id) || hop.serverIds.includes(s.id))).map((s) => ({
                              id: s.id, name: s.name, details: [rolesText(s.roles) + (s.internalAddress ? ` · 内网 ${s.internalAddress}` : "")],
                            }))}
                            selected={hop.serverIds}
                            onChange={(serverIds) => setHop(i, { serverIds })}
                          />
                          {connectionSettings(i === 0 ? [routeForm.entryServerId || ""] : hops[i - 1].serverIds, hop.serverIds,
                            !!hop.internal, hop.sourceMode, hop.sourceFamily,
                            (internal) => setHop(i, { internal }), (sourceMode) => setHop(i, { sourceMode }), (sourceFamily) => setHop(i, { sourceFamily }))}
                        </div>
                      ))}
                      <button type="button" onClick={() => setRouteForm({ ...routeForm, hops: [...hops, { serverIds: [], balance: "failover", internal: false, sourceFamily: "ipv4" }] })}>添加一跳</button>
                    </div>
                  </div>
                  <h3 className="routeExitTitle">连接落地</h3>
                  {connectionSettings(hops.length ? hops[hops.length - 1].serverIds : [routeForm.entryServerId || ""], node ? [node.serverId] : [],
                    !!routeForm.nodeInternal, routeForm.nodeSourceMode, routeForm.nodeSourceFamily,
                    (nodeInternal) => setRouteForm({ ...routeForm, nodeInternal }), (nodeSourceMode) => setRouteForm({ ...routeForm, nodeSourceMode }),
                    (nodeSourceFamily) => setRouteForm({ ...routeForm, nodeSourceFamily }))}
                  <p className="hint">一跳选多台服务器即为负载均衡组：主备优先用第一台可用的，轮询把新连接轮流分配；故障服务器自动停用，恢复后自动启用。</p>
                  <p className="hint">例如入口通过专线访问中转的公网地址：连接地址选“公网地址”，防火墙来源选“内网 IP”。新建链路默认只放行 IPv4；需要 IPv6 时单独选择，地址族不会改变发送方的出口或 DNS 解析。</p>
                  <SubmitButton busy={busy} label="保存链路" />
                </form>
  </Dialog>;
}
