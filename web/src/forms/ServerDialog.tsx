import { useMemo, useState } from "react";
import {
  canHostNodes,
  mutation,
  roleLabels,
  type BillingCycle,
  type InstallGuide,
  type Server,
  type TrafficLimitType,
} from "../api";
import { useApp } from "../app/context";
import { setError } from "../app/feedback";
import {
  billingCycleLabels,
  manualFirewall,
  roleOrder,
  supportsGitHubUpgrade,
  trafficLimitTypeLabels,
  type ServerForm,
} from "../app/helpers";
import { Advanced, Field, HelpTip, SubmitButton, useBusy } from "../app/ui";
import { Dialog } from "./Dialog";

const GB_BYTES = 1024 ** 3;
const TB_BYTES = 1024 ** 4;
const MAX_TRAFFIC_LIMIT_BYTES = 2 ** 53;

type BillingDrafts = {
  price: string;
  billingCycleDays: string;
  trafficLimit: string;
  trafficLimitUnit: "GB" | "TB";
  trafficResetDay: string;
  sortWeight: string;
};

function formatUnitValue(bytesVal: number, unitBytes: number): string {
  const raw = bytesVal / unitBytes;
  if (Math.abs(raw - Math.round(raw)) < 1e-6) return String(Math.round(raw));
  return String(Number(raw.toFixed(2)));
}

function draftsFromServer(s: ServerForm): BillingDrafts {
  const limit = s.trafficLimit ?? 0;
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
    price: s.price && s.price > 0 ? String(s.price) : "",
    billingCycleDays: s.billingCycleDays && s.billingCycleDays > 0 ? String(s.billingCycleDays) : "30",
    trafficLimit,
    trafficLimitUnit,
    trafficResetDay: s.trafficResetDay && s.trafficResetDay > 0 ? String(s.trafficResetDay) : "",
    sortWeight: s.sortWeight ? String(s.sortWeight) : "",
  };
}

export default function ServerDialog({ initial }: { initial: ServerForm }) {
  const { servers, nodes, operations, agentReleases, coreReleases, refreshing, refresh, act, closeModal, goTo, setOfflineServer, showInstall } = useApp();
  const initialDrafts = useMemo(() => draftsFromServer(initial), [initial]);
  const [serverForm, setServerForm] = useState(initial);
  const [drafts, setDrafts] = useState<BillingDrafts>(initialDrafts);
  const { busy, run } = useBusy();
  const existingGroups = useMemo(
    () =>
      [...new Set(servers.map((s) => s.group?.trim()).filter((g): g is string => !!g))].sort((a, b) =>
        a.localeCompare(b, "zh-Hans-CN"),
      ),
    [servers],
  );
  const selectedFormServer = servers.find((s) => s.id === serverForm.id);
  const serverManagementChanged = !!selectedFormServer && (selectedFormServer.managementMode === "offline") !== (serverForm.managementMode === "offline");
  const serverProxyEnabled = !["offline", "external"].includes(serverForm.managementMode || "online");
  const serverProxyOptions = nodes.filter((n) => n.protocol === "socks5").map((node) => {
    const host = servers.find((s) => s.id === node.serverId);
    const reason = node.serverId === serverForm.id ? "不能代理自身" : node.deleting ? "正在删除" : !node.enabled ? "已停用" :
      !host ? "服务器不存在" : host.managementMode === "offline" ? "代理服务器为离线管理" :
      manualFirewall(host) ? "代理服务器需 UFW 托管" : host.ufwStatus !== "active" ? "代理服务器未启用 UFW" :
      host.firewallConflict ? "代理服务器存在防火墙冲突" : node.firewallPolicy === "manual" ? "节点端口需由 UFW 管理" :
      node.status !== "active" ? "配置尚未成功应用" : "";
    return { node, host, reason };
  });
  const serverFormCoreMissing = !!serverForm.id && !!serverForm.agentVersion && canHostNodes(serverForm) && !selectedFormServer?.coreBuild;
  const serverFormCoreInstalling = operations.some((o) => o.serverId === serverForm.id &&
    ["agent.upgrade", "core.upgrade"].includes(o.kind) && ["queued", "running", "activating"].includes(o.status));
  const submitServer = (e: React.FormEvent) => {
    e.preventDefault();

    const priceRaw = drafts.price.trim();
    let price = 0;
    if (priceRaw !== "") {
      if (!/^\d+(?:\.\d{1,2})?$/.test(priceRaw)) {
        setError("价格需为非负数字，且最多保留两位小数");
        return;
      }
      price = Number(priceRaw);
      if (!Number.isFinite(price) || price < 0 || price > 1_000_000) {
        setError("价格需在 0–1000000 之间");
        return;
      }
    }

    const currency = (serverForm.currency ?? "").trim() || "$";
    if ([...currency].length > 8) {
      setError("货币符号或代码不能超过 8 个字符");
      return;
    }

    const billingCycle = (serverForm.billingCycle || "") as BillingCycle;
    let billingCycleDays = 0;
    if (billingCycle === "days") {
      const daysRaw = drafts.billingCycleDays.trim();
      if (!/^\d+$/.test(daysRaw)) {
        setError("自定义计费周期天数需填写 1–3650 之间的整数");
        return;
      }
      billingCycleDays = Number.parseInt(daysRaw, 10);
      if (billingCycleDays < 1 || billingCycleDays > 3650) {
        setError("自定义计费周期天数需在 1–3650 之间");
        return;
      }
    }

    const limitRaw = drafts.trafficLimit.trim();
    let trafficLimit = 0;
    if (limitRaw !== "" && limitRaw !== "0") {
      if (!/^\d+(?:\.\d{1,4})?$/.test(limitRaw)) {
        setError("流量限额请填写有效数字（最多 4 位小数）");
        return;
      }
      const unitMul = drafts.trafficLimitUnit === "TB" ? TB_BYTES : GB_BYTES;
      const computed = Math.round(Number(limitRaw) * unitMul);
      if (!Number.isFinite(computed) || computed < 0 || computed > MAX_TRAFFIC_LIMIT_BYTES) {
        setError("流量限额超出有效范围");
        return;
      }
      trafficLimit = computed;
    }

    const resetRaw = drafts.trafficResetDay.trim();
    let trafficResetDay = 0;
    if (resetRaw !== "") {
      if (!/^\d+$/.test(resetRaw)) {
        setError("流量重置日需填写 0–31 之间的整数");
        return;
      }
      trafficResetDay = Number.parseInt(resetRaw, 10);
      if (trafficResetDay < 0 || trafficResetDay > 31) {
        setError("流量重置日需在 0–31 之间");
        return;
      }
    }

    const group = (serverForm.group ?? "").trim();
    if ([...group].length > 40) {
      setError("分组名不能超过 40 个字符");
      return;
    }

    const weightRaw = drafts.sortWeight.trim();
    let sortWeight = 0;
    if (weightRaw !== "") {
      if (!/^-?\d+$/.test(weightRaw)) {
        setError("排序权重需填写 -9999 至 9999 之间的整数");
        return;
      }
      sortWeight = Number.parseInt(weightRaw, 10);
      if (sortWeight < -9999 || sortWeight > 9999) {
        setError("排序权重需在 -9999 至 9999 之间");
        return;
      }
    }

    const payload: ServerForm = {
      ...serverForm,
      price,
      currency,
      billingCycle,
      billingCycleDays,
      autoRenew: !!serverForm.autoRenew,
      trafficLimit,
      trafficLimitType: (serverForm.trafficLimitType || "sum") as TrafficLimitType,
      trafficResetDay,
      group,
      sortWeight,
      alertMuted: !!serverForm.alertMuted,
      cycleTraffic: undefined,
    };

    void run(async () => {
    const ok = await act(async () => {
      if (payload.id) {
        const saved = await mutation<Server>("/api/servers/" + payload.id, "PATCH", {
          ...payload,
          initialExpiresAt: initial.expiresAt ?? null,
        });
        if (serverManagementChanged) {
          closeModal();
          if (saved.managementMode === "offline") { setOfflineServer(saved); return; }
          const guide = await mutation<InstallGuide>("/api/servers/" + saved.id + "/enrollment", "POST");
          showInstall(guide, saved.name, "offline", saved.arch);
        }
      } else {
        const result = await mutation<InstallGuide & { server: Server }>(
          "/api/servers",
          "POST",
          payload,
        );
        closeModal();
        if (payload.managementMode === "offline") { setOfflineServer(result.server); return; }
        if (payload.managementMode === "external") { goTo("nodes", result.server.id, {}); return; }
        showInstall(result, payload.name || "新服务器", "online", "amd64");
        return;
      }
    }, serverManagementChanged ? "管理方式已保存；请按迁移指南在目标机完成切换" : payload.managementMode === "external" ? "外部节点服务器已保存；请录入卖家提供的节点" : serverFormCoreMissing ? "服务器类型已保存；尚未安装 sing-box，请在服务器列表安装后创建节点" : "服务器已保存");
    if (ok && payload.id) closeModal();
    });
  };
  const external = serverForm.managementMode === "external";
  const hasBillingInitial = !!(
    initial.expiresAt ||
    (initial.price && initial.price > 0) ||
    initial.billingCycle ||
    initial.autoRenew ||
    (initial.trafficLimit && initial.trafficLimit > 0) ||
    (initial.trafficResetDay && initial.trafficResetDay > 0)
  );
  const hasOrganizeInitial = !!(initial.group || initial.sortWeight || initial.alertMuted);
  return <Dialog title={serverForm.id ? "编辑服务器" : "新建服务器"} value={{ serverForm, drafts }} initial={{ serverForm: initial, drafts: initialDrafts }} busy={busy}>
              <form className="serverForm" onSubmit={submitServer}>
                <section className="serverFormSection" aria-labelledby="server-basic-title">
                  <h3 id="server-basic-title">基本信息</h3>
                  <div className="formGrid">
                    <Field label="服务器名 *">
                      <input
                        required
                        value={serverForm.name || ""}
                        onChange={(e) =>
                          setServerForm({ ...serverForm, name: e.target.value })
                        }
                      />
                    </Field>
                    <Field label="国家代码 *">
                      <input
                        required
                        maxLength={2}
                        value={serverForm.country || ""}
                        onChange={(e) =>
                          setServerForm({
                            ...serverForm,
                            country: e.target.value.toUpperCase(),
                          })
                        }
                      />
                    </Field>
                    <div className="serverFormWide">
                      <Field label="管理方式" help="在线 Agent 由面板部署；离线管理需在本机应用导出配置；外部节点仅保存卖家提供的连接信息，不安装 Agent 或 sing-box。">
                        <select aria-label="管理方式" value={serverForm.managementMode || "online"} onChange={(e) => {
                          const offline = e.target.value === "offline";
                          const external = e.target.value === "external";
                          const roles = (serverForm.roles || []).filter((r) => r !== "exit");
                          setServerForm({
                            ...serverForm,
                            managementMode: external ? "external" : offline ? "offline" : "online",
                            agentProxyNodeId: offline || external ? "" : serverForm.agentProxyNodeId,
                            agentProxyInternal: offline || external ? false : serverForm.agentProxyInternal,
                            firewallMode: offline || external ? "manual" : "ufw",
                            roles: external ? ["exit"] : offline ? (roles.length ? roles : ["entry"]) : serverForm.roles?.length ? serverForm.roles : ["exit"],
                            outboundInterface: external ? "" : serverForm.outboundInterface,
                            autoSyncPublicIp: external ? false : serverForm.autoSyncPublicIp,
                          });
                        }}>
                          <option value="online" disabled={!!serverForm.id && serverForm.managementMode === "external"}>在线 Agent（连接面板）</option>
                          <option value="offline" disabled={!!serverForm.id && serverForm.managementMode === "external"}>离线管理（导出配置 / 本地应用）</option>
                          <option value="external" disabled={!!serverForm.id && serverForm.managementMode !== "external"}>外部节点（卖家提供，无需安装）</option>
                        </select>
                      </Field>
                      {serverManagementChanged && <p className="banner warning" role="status">保存后旧 Agent 凭据失效，页面会打开迁移指南。需在目标机停用旧服务并重新安装；保留服务器档案、链路和转发，安装期间会中断转发。已有节点须先删除才能改为离线管理。</p>}
                    </div>
                    <div className="serverFormWide">
                      <fieldset className="serverRoles">
                        <legend><span className="fieldLabelRow">类型（可多选） * <HelpTip label="服务器类型" text="入口、线路可作为首跳；中转、线路可作为中间跳；在线中转和落地都可搭建节点。中转服务器建节点前需在列表安装 sing-box，安装后保留中转类型。" /></span></legend>
                        <div className="checkRow">
                          {roleOrder.map((role) => (
                            <label className="check" key={role}>
                              <input
                                type="checkbox"
                                disabled={serverForm.managementMode === "offline" && role === "exit" || serverForm.managementMode === "external"}
                                checked={serverForm.roles?.includes(role) || false}
                                onChange={(e) => setServerForm({
                                  ...serverForm,
                                  roles: e.target.checked ? [...(serverForm.roles || []), role] : (serverForm.roles || []).filter((r) => r !== role),
                                })}
                              />
                              {roleLabels[role]}
                            </label>
                          ))}
                        </div>
                      </fieldset>
                      {serverFormCoreMissing && <div className="banner warning serverCoreHint" role="status">
                        <div>
                          <p>可以保存服务器类型。该服务器尚未安装 sing-box，建节点前需先安装。</p>
                          <button type="button" className="ghost" disabled={!selectedFormServer?.coreSelfUpdate || !!agentReleases.releaseVersion && !supportsGitHubUpgrade(selectedFormServer?.agentVersion || "") || !coreReleases[selectedFormServer?.arch || ""] || serverFormCoreInstalling}
                            onClick={() => act(() => mutation("/api/servers/" + serverForm.id + "/core/upgrade", "POST"), "sing-box 安装已排队，完成后点击刷新安装状态")}>{serverFormCoreInstalling ? "核心安装或升级进行中" : "安装 sing-box"}</button>
                          <button type="button" className="ghost" disabled={refreshing} onClick={() => void refresh(true)}>{refreshing ? "刷新中…" : "刷新安装状态"}</button>
                          {!selectedFormServer?.coreSelfUpdate && <p>请先接入支持核心安装的 Agent。</p>}
                          {!!agentReleases.releaseVersion && !!selectedFormServer?.coreSelfUpdate && !supportsGitHubUpgrade(selectedFormServer.agentVersion || "") && <p>先用新版接入命令重装 Agent，才能从 GitHub 安装 sing-box。</p>}
                          {!!selectedFormServer?.coreSelfUpdate && !coreReleases[selectedFormServer?.arch || ""] && <p>该架构的 sing-box 发布文件不可用。</p>}
                        </div>
                      </div>}

                    </div>
                  </div>
                </section>
                <section className="serverFormSection" aria-labelledby="server-network-title">
                  <h3 id="server-network-title" className="fieldLabelRow">网络与防火墙 <HelpTip label="网络与防火墙" text="公网 IP 或订阅用域名至少填写一项。" /></h3>
                  <div className="formGrid">
                    <Field label="公网 IPv4">
                      <input
                        value={serverForm.ipv4 || ""}
                        onChange={(e) =>
                          setServerForm({ ...serverForm, ipv4: e.target.value })
                        }
                      />
                    </Field>
                    <Field label="公网 IPv6">
                      <input
                        value={serverForm.ipv6 || ""}
                        onChange={(e) =>
                          setServerForm({ ...serverForm, ipv6: e.target.value })
                        }
                      />
                    </Field>
                    <Field label="订阅与链路用域名">
                      <input
                        value={serverForm.domain || ""}
                        onChange={(e) =>
                          setServerForm({ ...serverForm, domain: e.target.value })
                        }
                      />
                    </Field>
                    <Field label="内网地址">
                      <input
                        value={serverForm.internalAddress || ""}
                        placeholder="内网 / 专线互通时填写，如 10.0.0.2"
                        onChange={(e) =>
                          setServerForm({ ...serverForm, internalAddress: e.target.value })
                        }
                      />
                    </Field>
                    <div className="serverFormWide">
                      <Field label="防火墙管理" help={serverForm.managementMode === "external" ? "卖家管理这台服务器的防火墙；面板不会修改端口或来源规则。" : manualFirewall(serverForm) ? "节点和转发可正常部署。面板不修改现有防火墙，端口放行及来源限制需自行配置。" : "由面板管理 UFW 规则，部署节点和转发前需初始化 UFW。"}>
                        <select disabled={serverForm.managementMode !== "online"} value={serverForm.firewallMode || "ufw"} onChange={(e) => setServerForm({ ...serverForm, firewallMode: e.target.value as "ufw" | "manual" })}>
                          <option value="ufw">UFW 托管</option>
                          <option value="manual" disabled={!!serverForm.agentVersion && !serverForm.manualFirewallSupport && !manualFirewall(serverForm)}>手动管理（宿主机 / 安全组 / 其他防火墙）</option>
                        </select>
                      </Field>
                      {!!serverForm.agentVersion && !serverForm.manualFirewallSupport && <p className="serverFieldHelp dangerText">启用手动管理前，请先升级 Agent 至 0.6.4。</p>}
                    </div>
                  </div>
                </section>
                {!external && <Advanced title="高级网络：公网 IP 同步、出口网卡" open={!!initial.autoSyncPublicIp || !!initial.outboundInterface}>
                  <div className="formGrid">
                    {serverForm.managementMode !== "external" && <div className="serverToggleRow serverFormWide">
                      <label className="check">
                        <input type="checkbox" checked={!!serverForm.autoSyncPublicIp} onChange={(e) => setServerForm({ ...serverForm, autoSyncPublicIp: e.target.checked })} />
                        自动同步 Agent 检测到的公网 IPv4 / IPv6
                      </label>
                      <HelpTip label="自动同步公网 IP" text="本机网卡上的公网 IPv4 可填入空白地址；开启自动同步后，地址变化也会更新已有 IPv4。NAT 后面板观察到的出口 IPv4 用于检测和防火墙来源，不会填入空白的 IPv4；仅当现有 IPv4 等于上次检测值时才随新观察值更新。若已做端口映射但 IPv4 仍为空，请手工填写。Agent 每 5 分钟经 IPv4 探测面板，不访问第三方查 IP 服务；面板域名须有可直连的 A 记录。探测失败会保留上次观察值；使用 SOCKS5 时清除观察值，避免把代理出口当作本机地址。" />
                    </div>}
                    {serverForm.managementMode === "online" && <div className="serverFormWide">
                      <Field label="节点默认出口网卡" help="仅控制这台服务器上 sing-box 节点的出口，节点可单独覆盖。修改后会重新应用配置并重启 sing-box；指定网卡不存在或未启用时，保留原配置并报错。">
                        <input maxLength={15} placeholder="留空使用系统路由，例如 ppp0" value={serverForm.outboundInterface || ""} onChange={(e) => setServerForm({ ...serverForm, outboundInterface: e.target.value })} />
                      </Field>
                      {!!serverForm.outboundInterface?.trim() && !!serverForm.agentVersion && !serverForm.outboundBindingSupport && <p className="serverFieldHelp dangerText">配置可保存；请先升级 Agent 至 0.6.12 后应用出口网卡设置。</p>}
                    </div>}
                  </div>
                </Advanced>}
                {!external && <Advanced title="Agent 连接代理（SOCKS5）" open={!!initial.agentProxyNodeId}>
                  <div className="formGrid">
                    {serverForm.managementMode !== "external" && <div className="serverFormWide">
                      <Field label="Agent 连接面板的 SOCKS5 节点" help="代理用于 Agent 接入、心跳、任务与下载，与节点“允许直连”无关。候选节点须已启用、配置已生效，且其服务器已启用 UFW、没有防火墙冲突。面板按所选本机来源 IP 自动放行；经过 NAT 时请填写实际出口 IP。所有在线服务器均可使用代理，需 Agent 0.6.10 或更高版本。">
                        <select aria-label="Agent 连接面板的 SOCKS5 节点" disabled={!serverProxyEnabled} value={serverForm.agentProxyNodeId || ""} onChange={(e) => setServerForm({ ...serverForm, agentProxyNodeId: e.target.value, agentProxyInternal: false })}>
                          <option value="">直接连接面板（不使用代理）</option>
                          {serverProxyOptions.map(({ node, host, reason }) => <option value={node.id} key={node.id} disabled={!!reason}>{node.name} · {host?.name || "未知服务器"} :{node.port}{reason ? `（${reason}）` : ""}</option>)}
                        </select>
                      </Field>
                      {!serverProxyEnabled && <p className="serverFieldHelp">离线管理不连接面板；切换为在线 Agent 后即可使用 SOCKS5，与服务器类型无关。</p>}
                      {!serverProxyOptions.length && <p className="serverFieldHelp">暂无 SOCKS5 节点。请先在已启用 UFW 的在线中转或落地服务器创建 SOCKS5 节点。</p>}
                      {!!serverProxyOptions.length && !serverProxyOptions.some((o) => !o.reason) && <p className="serverFieldHelp">当前 SOCKS5 节点均不可用，请按各选项后的原因修复，再点击右上角刷新。</p>}
                      {serverForm.agentProxyNodeId && <Field label="本机连接 SOCKS5 的地址">
                        <select aria-label="本机连接 SOCKS5 的地址" value={serverForm.agentProxyInternal ? "internal" : "public"} onChange={(e) => setServerForm({ ...serverForm, agentProxyInternal: e.target.value === "internal" })}>
                          <option value="public">SOCKS5 节点发布地址（公网 / 域名）</option>
                          <option value="internal" disabled={!servers.find((s) => s.id === nodes.find((n) => n.id === serverForm.agentProxyNodeId)?.serverId)?.internalAddress}>SOCKS5 所在服务器的内网地址</option>
                        </select>
                      </Field>}
                      {serverForm.agentProxyNodeId && <Field label="SOCKS5 防火墙放行来源" help="这是 SOCKS5 服务器实际看到的入口来源 IP，可独立于上方连接地址选择。选择内网来源时，请在下方填写这台服务器的内网 IP。仅改来源规则无需重装或重启本机 Agent。">
                        <select aria-label="SOCKS5 防火墙放行来源" value={serverForm.agentProxySourceMode || "auto"} onChange={(e) => setServerForm({ ...serverForm, agentProxySourceMode: e.target.value as Server["agentProxySourceMode"] })}>
                          <option value="auto">跟随连接地址类型</option>
                          <option value="public">本机公网 IP</option>
                          <option value="internal">本机内网 IP</option>
                        </select>
                      </Field>}
                    </div>}
                  </div>
                </Advanced>}
                <Advanced title="计费与流量" open={hasBillingInitial}>
                  <div className="formGrid">
                    <Field label="到期日" help="用于监控卡片与服务器列表展示、流量周期锚点及 Telegram 到期提醒。留空表示不限期。">
                      <input
                        type="date"
                        value={serverForm.expiresAt ? serverForm.expiresAt.slice(0, 10) : ""}
                        onChange={(e) =>
                          setServerForm({
                            ...serverForm,
                            expiresAt: e.target.value ? `${e.target.value}T00:00:00Z` : undefined,
                          })
                        }
                      />
                    </Field>
                    <Field label="计费周期">
                      <select
                        aria-label="计费周期"
                        value={serverForm.billingCycle || ""}
                        onChange={(e) =>
                          setServerForm({
                            ...serverForm,
                            billingCycle: e.target.value as BillingCycle,
                          })
                        }
                      >
                        <option value="">未设置</option>
                        {(Object.entries(billingCycleLabels) as [Exclude<BillingCycle, "">, string][]).map(([key, label]) => (
                          <option key={key} value={key}>{label}</option>
                        ))}
                      </select>
                    </Field>
                    {serverForm.billingCycle === "days" && (
                      <Field label="自定义周期天数（1–3650） *">
                        <input
                          required
                          inputMode="numeric"
                          placeholder="例如 30"
                          value={drafts.billingCycleDays}
                          onChange={(e) => setDrafts({ ...drafts, billingCycleDays: e.target.value })}
                        />
                      </Field>
                    )}
                    <Field label="周期价格" help="每个计费周期的费用，最多两位小数；留空或 0 表示未填写。">
                      <input
                        inputMode="decimal"
                        placeholder="留空或 0 表示未填"
                        value={drafts.price}
                        onChange={(e) => setDrafts({ ...drafts, price: e.target.value })}
                      />
                    </Field>
                    <Field label="货币符号或代码" help="最多 8 个字符，留空默认使用 $（例如 $、¥、€、HKD）。">
                      <input
                        maxLength={8}
                        placeholder="默认 $"
                        value={serverForm.currency ?? "$"}
                        onChange={(e) => setServerForm({ ...serverForm, currency: e.target.value })}
                      />
                    </Field>
                    <div className="serverToggleRow serverFormWide">
                      <label className="check">
                        <input
                          type="checkbox"
                          checked={!!serverForm.autoRenew}
                          onChange={(e) => setServerForm({ ...serverForm, autoRenew: e.target.checked })}
                        />
                        到期后自动顺延一个计费周期
                      </label>
                      <HelpTip label="自动续期规则" text="需同时填写到期日与计费周期。在线管理服务器还要求最近 24 小时内有上报（长期离线视为可能已退订，不自动续期）；离线管理与外部节点到期直接顺延。开启后在到期前 3 天提醒“即将自动续期”，续期后发送通知。" />
                    </div>
                    <Field label="周期流量限额" help="按采样网卡流量统计，留空或 0 表示不限流量。仅用于展示与告警，超限不会自动停机。">
                      <div className="inputWithUnit">
                        <input
                          inputMode="decimal"
                          placeholder="留空或 0 表示不限"
                          value={drafts.trafficLimit}
                          onChange={(e) => setDrafts({ ...drafts, trafficLimit: e.target.value })}
                        />
                        <select
                          aria-label="流量限额单位"
                          value={drafts.trafficLimitUnit}
                          onChange={(e) =>
                            setDrafts({ ...drafts, trafficLimitUnit: e.target.value as "GB" | "TB" })
                          }
                        >
                          <option value="GB">GB</option>
                          <option value="TB">TB</option>
                        </select>
                      </div>
                    </Field>
                    <Field label="流量计费方向">
                      <select
                        aria-label="流量计费方向"
                        value={serverForm.trafficLimitType || "sum"}
                        onChange={(e) =>
                          setServerForm({
                            ...serverForm,
                            trafficLimitType: e.target.value as TrafficLimitType,
                          })
                        }
                      >
                        {(Object.entries(trafficLimitTypeLabels) as [TrafficLimitType, string][]).map(([key, label]) => (
                          <option key={key} value={key}>{label}</option>
                        ))}
                      </select>
                    </Field>
                    <Field label="每月流量重置日（0–31）" help="1–31 表示每月对应日期 0 点重置（当月无该日时取月末）；0 或留空表示跟随到期日的“几号”（未填到期日时按 1 号）。">
                      <input
                        inputMode="numeric"
                        placeholder="0 表示跟随到期日"
                        value={drafts.trafficResetDay}
                        onChange={(e) => setDrafts({ ...drafts, trafficResetDay: e.target.value })}
                      />
                    </Field>
                  </div>
                </Advanced>
                <Advanced title="整理" open={hasOrganizeInitial}>
                  <div className="formGrid">
                    <Field label="分组名" help="监控页与服务器列表按分组归类显示；留空归入“未分组”（最多 40 字符）。">
                      <input
                        maxLength={40}
                        list="server-group-options"
                        placeholder="例如：主力线路 / 备用落地"
                        value={serverForm.group || ""}
                        onChange={(e) => setServerForm({ ...serverForm, group: e.target.value })}
                      />
                      {existingGroups.length > 0 && (
                        <datalist id="server-group-options">
                          {existingGroups.map((g) => (
                            <option key={g} value={g} />
                          ))}
                        </datalist>
                      )}
                    </Field>
                    <Field label="排序权重（-9999–9999）" help="同一分组内按权重从大到小排列，相同时按名称排序；默认 0。">
                      <input
                        inputMode="numeric"
                        placeholder="默认 0（数值大的在前）"
                        value={drafts.sortWeight}
                        onChange={(e) => setDrafts({ ...drafts, sortWeight: e.target.value })}
                      />
                    </Field>
                    <div className="serverToggleRow serverFormWide">
                      <label className="check">
                        <input
                          type="checkbox"
                          checked={!!serverForm.alertMuted}
                          onChange={(e) => setServerForm({ ...serverForm, alertMuted: e.target.checked })}
                        />
                        静音离线与资源告警
                      </label>
                      <HelpTip label="静音离线与资源告警" text="开启后不再发送该服务器的离线恢复及 CPU / 内存 / 磁盘高占用告警；到期提醒与流量限额告警不受影响。" />
                    </div>
                  </div>
                </Advanced>
                <Advanced title="其他信息：服务商、地区、标签、备注" open={!!(initial.provider || initial.region || initial.city || initial.tags || initial.notes)}>
                  <div className="formGrid">
                    <Field label="服务商">
                      <input
                        value={serverForm.provider || ""}
                        onChange={(e) =>
                          setServerForm({
                            ...serverForm,
                            provider: e.target.value,
                          })
                        }
                      />
                    </Field>
                    <Field label="地区">
                      <input
                        value={serverForm.region || ""}
                        onChange={(e) =>
                          setServerForm({ ...serverForm, region: e.target.value })
                        }
                      />
                    </Field>
                    <Field label="城市">
                      <input
                        value={serverForm.city || ""}
                        onChange={(e) =>
                          setServerForm({ ...serverForm, city: e.target.value })
                        }
                      />
                    </Field>
                    <Field label="标签">
                      <input
                        value={serverForm.tags || ""}
                        onChange={(e) =>
                          setServerForm({ ...serverForm, tags: e.target.value })
                        }
                      />
                    </Field>
                    <div className="serverFormWide">
                      <Field label="备注">
                        <textarea
                          rows={2}
                          value={serverForm.notes || ""}
                          onChange={(e) =>
                            setServerForm({ ...serverForm, notes: e.target.value })
                          }
                        />
                      </Field>
                    </div>
                  </div>
                </Advanced>
                <div className="serverFormActions">
                  <SubmitButton busy={busy} label="保存服务器" className="primary" />
                </div>
              </form>
  </Dialog>;
}
