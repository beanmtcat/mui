import { useMemo, useState } from "react";
import { bytes, mutation, type Route, type RouteHop, type RouteSourceFamily, type RouteSourceMode, type RouteTrafficLimitType, type Server } from "../api";
import { useApp } from "../app/context";
import { setError } from "../app/feedback";
import { manualFirewall, rolesText } from "../app/helpers";
import { Field, SubmitButton, useBusy } from "../app/ui";
import { Dialog } from "./Dialog";
import { ItemPicker } from "./ItemPicker";

const GB_BYTES = 1024 ** 3;
const TB_BYTES = 1024 ** 4;
const MAX_TRAFFIC_LIMIT_BYTES = 2 ** 53;

function formatUnitValue(bytesVal: number, unitBytes: number): string {
  const raw = bytesVal / unitBytes;
  if (Math.abs(raw - Math.round(raw)) < 1e-6) return String(Math.round(raw));
  return String(Number(raw.toFixed(2)));
}

function routeLimitDraft(initial: Partial<Route>) {
  const limit = initial.trafficLimit ?? 0;
  let trafficLimit = "";
  let trafficLimitUnit: "GB" | "TB" = "GB";
  if (limit > 0) {
    const tbVal = limit / TB_BYTES;
    if (limit >= TB_BYTES && Math.abs(tbVal * 100 - Math.round(tbVal * 100)) < 1e-4) {
      trafficLimitUnit = "TB";
      trafficLimit = formatUnitValue(limit, TB_BYTES);
    } else {
      trafficLimitUnit = "GB";
      trafficLimit = formatUnitValue(limit, GB_BYTES);
    }
  }
  return {
    trafficLimit,
    trafficLimitUnit,
    trafficResetDay: initial.trafficResetDay && initial.trafficResetDay > 0 ? String(initial.trafficResetDay) : "",
    upSpeedLimitMbps: initial.upSpeedLimitMbps && initial.upSpeedLimitMbps > 0 ? String(initial.upSpeedLimitMbps) : "",
    downSpeedLimitMbps: initial.downSpeedLimitMbps && initial.downSpeedLimitMbps > 0 ? String(initial.downSpeedLimitMbps) : "",
  };
}

function previewCycleWindow(resetDay: number): { start: string; end: string } {
  const now = new Date();
  const d = resetDay >= 1 && resetDay <= 31 ? resetDay : 1;
  const clampDate = (y: number, m: number) => {
    const last = new Date(y, m + 1, 0).getDate();
    return new Date(y, m, Math.min(d, last), 0, 0, 0);
  };
  let start = clampDate(now.getFullYear(), now.getMonth());
  let end: Date;
  if (now < start) {
    end = start;
    start = clampDate(now.getFullYear(), now.getMonth() - 1);
  } else {
    end = clampDate(now.getFullYear(), now.getMonth() + 1);
  }
  const fmt = (dt: Date) => `${dt.getFullYear()}-${String(dt.getMonth() + 1).padStart(2, "0")}-${String(dt.getDate()).padStart(2, "0")} 00:00`;
  return { start: fmt(start), end: fmt(end) };
}

export default function RouteDialog({ initial }: { initial: Partial<Route> }) {
  const { servers, nodes, serverName, act, closeModal } = useApp();
  // Format stored CIDRs for the editor once; keep subsequent typing untouched.
  const displayInitial = { ...initial, entryFirewallSources: initial.entryFirewallSources?.replaceAll(",", "\n") };
  const initialLimitDraft = useMemo(() => routeLimitDraft(initial), [initial]);
  const [routeForm, setRouteForm] = useState(displayInitial);
  const [limitDraft, setLimitDraft] = useState(initialLimitDraft);
  const { busy, run } = useBusy();
  const submitRoute = (e: React.FormEvent) => {
    e.preventDefault();
    let trafficLimit = 0;
    const limitRaw = limitDraft.trafficLimit.trim();
    if (limitRaw !== "" && limitRaw !== "0") {
      if (!/^\d+(?:\.\d{1,4})?$/.test(limitRaw)) {
        setError("周期流量配额请填写有效数字（最多 4 位小数）");
        return;
      }
      const mul = limitDraft.trafficLimitUnit === "TB" ? TB_BYTES : GB_BYTES;
      const computed = Math.round(Number(limitRaw) * mul);
      if (!Number.isFinite(computed) || computed < 0 || computed > MAX_TRAFFIC_LIMIT_BYTES) {
        setError("周期流量配额超出有效范围");
        return;
      }
      trafficLimit = computed;
    }
    let trafficResetDay = 0;
    const resetRaw = limitDraft.trafficResetDay.trim();
    if (resetRaw !== "") {
      if (!/^\d+$/.test(resetRaw)) {
        setError("每月重置日需填写 1–31 之间的整数");
        return;
      }
      trafficResetDay = Number.parseInt(resetRaw, 10);
      if (trafficResetDay < 0 || trafficResetDay > 31) {
        setError("每月重置日需在 0–31 之间");
        return;
      }
    }
    const parseSpeed = (raw: string, label: string): number | null => {
      const s = raw.trim();
      if (s === "" || s === "0") return 0;
      if (!/^\d+(?:\.\d{1,2})?$/.test(s)) {
        setError(`${label}请填写有效数字（最多两位小数）`);
        return null;
      }
      const val = Number(s);
      if (!Number.isFinite(val) || val < 0 || val > 100000) {
        setError(`${label}需在 0–100000 Mbps 之间`);
        return null;
      }
      return val;
    };
    const upSpeedLimitMbps = parseSpeed(limitDraft.upSpeedLimitMbps, "上传限速");
    if (upSpeedLimitMbps === null) return;
    const downSpeedLimitMbps = parseSpeed(limitDraft.downSpeedLimitMbps, "下载限速");
    if (downSpeedLimitMbps === null) return;

    const payload: Partial<Route> = {
      ...routeForm,
      trafficLimit,
      trafficLimitType: (routeForm.trafficLimitType || "sum") as RouteTrafficLimitType,
      trafficResetDay,
      upSpeedLimitMbps,
      downSpeedLimitMbps,
      cycleTraffic: undefined,
      enforcementCapability: undefined,
      enforcementNote: undefined,
    };
    const path = "/api/routes" + (routeForm.id ? "/" + routeForm.id : "");
    void run(async () => {
      if (await act(() => mutation(path, routeForm.id ? "PATCH" : "POST", payload), "链路已保存，各跳转发等待 Agent 应用")) closeModal();
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
                sourceFamily: RouteSourceFamily | undefined, addressModes: RouteHop["addressModes"] | undefined,
                setInternal: (value: boolean) => void, setSource: (value: RouteSourceMode) => void,
                setFamily: (value: RouteSourceFamily | undefined) => void,
                setReceiverAddress?: (serverId: string, mode: "public" | "internal") => void,
              ) => {
                const findServers = (ids: string[]) => ids.map((id) => servers.find((s) => s.id === id)).filter((s): s is Server => !!s);
                const senders = findServers(senderIds);
                const receivers = findServers(receiverIds);
                const targetInternal = (s: Server) => addressModes?.[s.id] ? addressModes[s.id] === "internal" : internal;
                const targetAddress = (s: Server) => targetInternal(s) ? s.internalAddress : (s.autoSyncPublicIp && s.domain) || s.ipv4 || s.ipv6 || s.domain;
                const mixed = receivers.some((s) => targetInternal(s) !== internal);
                const manualReceivers = receivers.filter(manualFirewall);
                const managed = !receivers.length || manualReceivers.length !== receivers.length;
                const sourceAddresses = (sender: Server, receiver: Server) => {
                  const target = targetAddress(receiver);
                  const allowV4 = (!target || !target.includes(":")) && sourceFamily !== "ipv6";
                  const allowV6 = (!target || target.includes(":") || !/^\d+\.\d+\.\d+\.\d+$/.test(target)) && sourceFamily !== "ipv4";
                  const sourceInternal = sourceMode === "internal" || (!sourceMode || sourceMode === "auto") && targetInternal(receiver);
                  return sourceInternal
                    ? (sender.internalAddress && (sender.internalAddress.includes(":") ? allowV6 : allowV4) ? sender.internalAddress : "未填写匹配地址族的内网 IP")
                    : [...new Set([...(allowV4 ? [sender.ipv4, sender.detectedIpv4] : []), ...(allowV6 ? [sender.ipv6, sender.detectedIpv6] : [])].filter(Boolean))].join("、") || "未填写匹配地址族的公网 IP";
                };
                return (
                  <fieldset className="routeConnection">
                    <legend>{senders.map((s) => s.name).join(" / ") || "请选择发送方"} → {receivers.map((s) => s.name).join(" / ") || "请选择接收方"}</legend>
                    <div className="formGrid">
                      <Field label="防火墙来源：放行发送方的哪个 IP？">
                        <div className="routeSourceSelectors">
                          <select aria-label="防火墙来源地址" value={sourceMode || "auto"} onChange={(e) => setSource(e.target.value as RouteSourceMode)}>
                            <option value="auto">自动（{mixed ? "跟随各台连接地址" : internal ? "内网 IP" : "公网 IP"}）</option>
                            <option value="public">公网 IP</option>
                            <option value="internal">内网 IP</option>
                          </select>
                          <select aria-label="防火墙来源地址族" value={sourceFamily || ""} onChange={(e) => setFamily(e.target.value ? e.target.value as RouteSourceFamily : undefined)}>
                            {routeForm.id && <option value="">原设置</option>}
                            <option value="ipv4">IPv4（默认）</option>
                            <option value="ipv6">IPv6</option>
                            <option value="both">IPv4 + IPv6</option>
                          </select>
                        </div>
                        {manualReceivers.length > 0 && <small className="connectionAddress">{manualReceivers.map((s) => s.name).join(" / ")} 的防火墙为手动管理；以下来源仅供参考，面板不生成规则，请自行放行：</small>}
                        {receivers.flatMap((receiver) => senders.map((sender) => <small className="connectionAddress" key={`${receiver.id}-${sender.id}`}>{receivers.length > 1 && `${receiver.name} ← `}{sender.name}：{sourceAddresses(sender, receiver)}</small>))}
                      </Field>
                      <Field label="连接地址：接收方的哪个地址？">
                        <select value={internal ? "internal" : "public"} onChange={(e) => setInternal(e.target.value === "internal")}>
                          <option value="public">{setReceiverAddress ? "全部走公网" : "公网地址"}</option>
                          <option value="internal">{setReceiverAddress ? "全部走内网" : "内网地址"}</option>
                        </select>
                        {receivers.map((s) => <div className={setReceiverAddress && receivers.length > 1 ? "routeReceiverChoice" : ""} key={s.id}>
                          <small className="connectionAddress">{s.name}：{targetAddress(s) || "未填写该地址"}</small>
                          {setReceiverAddress && receivers.length > 1 && <select aria-label={`${s.name} 的连接地址`} value={targetInternal(s) ? "internal" : "public"} onChange={(e) => setReceiverAddress(s.id, e.target.value as "public" | "internal")}>
                            <option value="public">公网</option><option value="internal">内网</option>
                          </select>}
                        </div>)}
                      </Field>
                    </div>
                    <p className="hint">按接收方实际看到的来源 IP 选择；{managed ? "托管防火墙据此生成放行规则" : "手动防火墙仅显示来源供自行配置"}，不改变发送方的出口或路由。</p>
                  </fieldset>
                );
              };
  const entryServer = servers.find((s) => s.id === routeForm.entryServerId);
  const resetDayPreview = Number.parseInt(limitDraft.trafficResetDay.trim() || "1", 10) || 1;
  const cyclePreview = previewCycleWindow(resetDayPreview);
  const entryCapabilityHint = !entryServer
    ? ""
    : entryServer.managementMode === "external"
      ? "所选首跳为外部节点服务器，无法在本机执行链路流量配额或限速。"
      : entryServer.managementMode === "offline"
        ? "所选首跳为离线管理模式：导出并应用离线配置后，由入口本机转发器独立执行计量、限速与超额阻断；面板无法实时回传用量。"
        : !entryServer.forwardTrafficLimitSupport
          ? "警告：所选入口服务器 Agent 版本过旧，不支持链路流量配额与合计限速；保存后状态将显示“需升级 Agent”，请先升级入口 Agent。"
          : manualFirewall(entryServer)
            ? "所选入口防火墙为手动管理；链路流量计量、限速与超额阻断仍由入口本机转发器直接执行。"
            : "入口 Agent 支持本机持续计量、合计限速与超额自动阻断（面板暂时不可达时继续生效）。";
  return <Dialog title={routeForm.id ? "编辑链路" : "新建链路"} value={{ routeForm, limitDraft }} initial={{ routeForm: displayInitial, limitDraft: initialLimitDraft }} busy={busy}>
                <form onSubmit={submitRoute}>
                  <div className="formGrid">
                    <Field label="名称 *"><input required maxLength={100} value={routeForm.name || ""} onChange={(e) => setRouteForm({ ...routeForm, name: e.target.value })} /></Field>
                    <Field label="首跳（入口 / 线路） *">
                      <select required value={routeForm.entryServerId || ""} onChange={(e) => setRouteForm({ ...routeForm, entryServerId: e.target.value })}>
                        <option value="">选择服务器</option>
                        {servers.filter((s) => s.roles?.some((r) => r === "entry" || r === "line")).map((s) => <option key={s.id} value={s.id}>{s.name}（{rolesText(s.roles)}）</option>)}
                      </select>
                    </Field>
                    <Field label="入口放行来源" help="限制客户端能从哪些 IP 连接首跳端口；不影响中转之间的放行规则。指定来源后，其他来源即使有主机的宽泛放行规则，也会被链路优先规则拦住。UFW 默认入站策略必须是 deny 或 reject，否则配置应用会失败。">
                      <select value={routeForm.entryFirewallPolicy || "all"} onChange={(e) => setRouteForm({ ...routeForm, entryFirewallPolicy: e.target.value as "all" | "restricted", entryFirewallSources: e.target.value === "restricted" ? routeForm.entryFirewallSources : "" })}>
                        <option value="all">允许所有来源（默认）</option>
                        <option value="restricted">只允许指定 IP / 网段</option>
                      </select>
                      {routeForm.entryFirewallPolicy === "restricted" && <textarea required rows={3} placeholder="每行一个 IP 或 CIDR，例如 183.129.141.26/32" value={routeForm.entryFirewallSources || ""} onChange={(e) => setRouteForm({ ...routeForm, entryFirewallSources: e.target.value })} />}
                      {manualFirewall(servers.find((s) => s.id === routeForm.entryServerId)) && <small className="hint">入口防火墙为手动管理，面板不会写入 UFW；请在主机防火墙中自行限制来源。</small>}
                    </Field>
                    <Field label="落地节点 *">
                      <select required value={routeForm.nodeId || ""} onChange={(e) => setRouteForm({ ...routeForm, nodeId: e.target.value })}>
                        <option value="">选择节点</option>
                        {nodes.filter((n) => !n.deleting).map((n) => <option key={n.id} value={n.id}>{n.name}（{n.protocol.toUpperCase()} · {serverName(n.serverId)}）</option>)}
                      </select>
                    </Field>
                    <Field label="端口（留空自动）" help="同一中转的公网／内网连接方式、转发目标和后续路径相同时，可共用监听；上一跳负载组的成员和顺序可以不同。中转上已有相同目标的手动转发，且协议和监听地址兼容时，也可复用；原有放行来源会保留。入口仍单独监听。"><input type="number" min={1024} max={65535} value={routeForm.port || ""} placeholder="优先使用落地节点端口" onChange={(e) => setRouteForm({ ...routeForm, port: Number(e.target.value) || 0 })} /></Field>
                    <Field label="备注"><input maxLength={200} value={routeForm.notes || ""} onChange={(e) => setRouteForm({ ...routeForm, notes: e.target.value })} /></Field>
                    <Field label="状态"><label className="check"><input type="checkbox" checked={!!routeForm.enabled} onChange={(e) => setRouteForm({ ...routeForm, enabled: e.target.checked })} /> 启用链路</label></Field>
                  </div>
                  <fieldset className="routeConnection">
                    <legend>流量与限速（首跳入口本机执行）</legend>
                    <div className="formGrid">
                      <Field label="周期流量配额" help="留空或 0 表示不限。达到额度后自动暂停该链路并终止已有 TCP 连接与 UDP 会话，到下一周期满足恢复条件后自动恢复。仅在首跳对链路业务字节计量，TCP 与 UDP 合并计数，中间跳和落地不重复计入。">
                        <div className="inputWithUnit">
                          <input
                            inputMode="decimal"
                            placeholder="留空或 0 表示不限"
                            value={limitDraft.trafficLimit}
                            onChange={(e) => setLimitDraft({ ...limitDraft, trafficLimit: e.target.value })}
                          />
                          <select
                            aria-label="链路流量配额单位"
                            value={limitDraft.trafficLimitUnit}
                            onChange={(e) => setLimitDraft({ ...limitDraft, trafficLimitUnit: e.target.value as "GB" | "TB" })}
                          >
                            <option value="GB">GB</option>
                            <option value="TB">TB</option>
                          </select>
                        </div>
                      </Field>
                      <Field label="计量方向" help="上传指客户端 → 上游方向的业务字节，下载指上游 → 客户端方向的业务字节。">
                        <select
                          aria-label="链路计量方向"
                          value={routeForm.trafficLimitType || "sum"}
                          onChange={(e) => setRouteForm({ ...routeForm, trafficLimitType: e.target.value as RouteTrafficLimitType })}
                        >
                          <option value="sum">上行 + 下载（双向合计）</option>
                          <option value="up">仅上传（客户端 → 上游）</option>
                          <option value="down">仅下载（上游 → 客户端）</option>
                        </select>
                      </Field>
                      <Field label="每月重置日（1–31）" help="按面板时区确定每月重置边界；当月无该日时取月末。留空默认每月 1 号 00:00 重置。">
                        <input
                          inputMode="numeric"
                          placeholder="默认 1 号"
                          value={limitDraft.trafficResetDay}
                          onChange={(e) => setLimitDraft({ ...limitDraft, trafficResetDay: e.target.value })}
                        />
                      </Field>
                      <Field label="本周期起止时间">
                        <small className="connectionAddress">
                          {routeForm.cycleTraffic
                            ? `${routeForm.cycleTraffic.startAt.slice(0, 16).replace("T", " ")} 至 ${routeForm.cycleTraffic.resetAt.slice(0, 16).replace("T", " ")}（已用 ${bytes(routeForm.cycleTraffic.used)}）`
                            : `${cyclePreview.start} 至 ${cyclePreview.end}`}
                        </small>
                        {routeForm.cycleTraffic?.hasHistoricalGap && routeForm.cycleTraffic.meteringStartedAt && (
                          <small className="connectionAddress">
                            本次周期计量起点：{routeForm.cycleTraffic.meteringStartedAt.slice(0, 16).replace("T", " ")}（此前累计历史转发流量不计入本周期）
                          </small>
                        )}
                      </Field>
                      <Field label="上传合计限速（Mbps）" help="留空或 0 表示不限。针对整条链路所有并发连接（TCP + UDP）的合计上传速度上限。">
                        <input
                          inputMode="decimal"
                          placeholder="留空或 0 表示不限"
                          value={limitDraft.upSpeedLimitMbps}
                          onChange={(e) => setLimitDraft({ ...limitDraft, upSpeedLimitMbps: e.target.value })}
                        />
                      </Field>
                      <Field label="下载合计限速（Mbps）" help="留空或 0 表示不限。针对整条链路所有并发连接（TCP + UDP）的合计下载速度上限。">
                        <input
                          inputMode="decimal"
                          placeholder="留空或 0 表示不限"
                          value={limitDraft.downSpeedLimitMbps}
                          onChange={(e) => setLimitDraft({ ...limitDraft, downSpeedLimitMbps: e.target.value })}
                        />
                      </Field>
                    </div>
                    <p className="hint">一人一条专用链路可独立限制，多人共用则共享额度和速度。用户手动导入链路连接信息到客户端同样受本限制约束。</p>
                    <p className="hint">链路端口属于计量边界，落地凭据仍决定访问权限；若多条链路或直连节点共享同一落地凭据，请勿向同一用户暴露其他未限流入口。</p>
                    {entryCapabilityHint && <p className={`hint${entryServer && !entryServer.forwardTrafficLimitSupport && entryServer.managementMode !== "offline" && entryServer.managementMode !== "external" ? " dangerText" : ""}`}>{entryCapabilityHint}</p>}
                  </fieldset>
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
                            onChange={(serverIds) => {
                              const addressModes = Object.fromEntries(Object.entries(hop.addressModes || {}).filter(([id]) => serverIds.includes(id)));
                              setHop(i, { serverIds, addressModes: Object.keys(addressModes).length ? addressModes : undefined });
                            }}
                          />
                          {connectionSettings(i === 0 ? [routeForm.entryServerId || ""] : hops[i - 1].serverIds, hop.serverIds,
                            !!hop.internal, hop.sourceMode, hop.sourceFamily, hop.addressModes,
                            (internal) => setHop(i, { internal, addressModes: undefined }), (sourceMode) => setHop(i, { sourceMode }), (sourceFamily) => setHop(i, { sourceFamily }),
                            (serverId, mode) => {
                              const addressModes = { ...hop.addressModes };
                              if ((mode === "internal") === !!hop.internal) delete addressModes[serverId];
                              else addressModes[serverId] = mode;
                              setHop(i, { addressModes: Object.keys(addressModes).length ? addressModes : undefined });
                            })}
                        </div>
                      ))}
                      <button type="button" onClick={() => setRouteForm({ ...routeForm, hops: [...hops, { serverIds: [], balance: "failover", internal: false, sourceFamily: "ipv4" }] })}>添加一跳</button>
                    </div>
                  </div>
                  <h3 className="routeExitTitle">连接落地</h3>
                  {connectionSettings(hops.length ? hops[hops.length - 1].serverIds : [routeForm.entryServerId || ""], node ? [node.serverId] : [],
                    !!routeForm.nodeInternal, routeForm.nodeSourceMode, routeForm.nodeSourceFamily, undefined,
                    (nodeInternal) => setRouteForm({ ...routeForm, nodeInternal }), (nodeSourceMode) => setRouteForm({ ...routeForm, nodeSourceMode }),
                    (nodeSourceFamily) => setRouteForm({ ...routeForm, nodeSourceFamily }))}
                  <p className="hint">一跳选多台服务器即为负载均衡组：主备优先用第一台可用的，轮询把新连接轮流分配；每台可单独选择公网或内网连接地址。</p>
                  <p className="hint">例如入口通过专线访问中转的公网地址：连接地址选“公网地址”，防火墙来源选“内网 IP”。新建链路默认只放行 IPv4；需要 IPv6 时单独选择，地址族不会改变发送方的出口或 DNS 解析。</p>
                  <SubmitButton busy={busy} label="保存链路" />
                </form>
  </Dialog>;
}
