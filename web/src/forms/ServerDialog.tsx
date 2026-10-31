import { useState } from "react";
import { canHostNodes, mutation, roleLabels, type InstallGuide, type Server } from "../api";
import { useApp } from "../app/context";
import { manualFirewall, roleOrder, supportsGitHubUpgrade, type ServerForm } from "../app/helpers";
import { Advanced, Field, HelpTip, SubmitButton, useBusy } from "../app/ui";
import { Dialog } from "./Dialog";

export default function ServerDialog({ initial }: { initial: ServerForm }) {
  const { servers, nodes, operations, agentReleases, coreReleases, refreshing, refresh, act, closeModal, goTo, setOfflineServer, showInstall } = useApp();
  const [serverForm, setServerForm] = useState(initial);
  const { busy, run } = useBusy();
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
    void run(async () => {
    const ok = await act(async () => {
      if (serverForm.id) {
        const saved = await mutation<Server>("/api/servers/" + serverForm.id, "PATCH", serverForm);
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
          serverForm,
        );
        closeModal();
        if (serverForm.managementMode === "offline") { setOfflineServer(result.server); return; }
        if (serverForm.managementMode === "external") { goTo("nodes", result.server.id, {}); return; }
        showInstall(result, serverForm.name || "新服务器", "online", "amd64");
        return;
      }
    }, serverManagementChanged ? "管理方式已保存；请按迁移指南在目标机完成切换" : serverForm.managementMode === "external" ? "外部节点服务器已保存；请录入卖家提供的节点" : serverFormCoreMissing ? "服务器类型已保存；尚未安装 sing-box，请在服务器列表安装后创建节点" : "服务器已保存");
    if (ok && serverForm.id) closeModal();
    });
  };
  const external = serverForm.managementMode === "external";
  return <Dialog title={serverForm.id ? "编辑服务器" : "新建服务器"} value={serverForm} initial={initial} busy={busy}>
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
                            komariToken: external ? "" : serverForm.komariToken,
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
                      <HelpTip label="自动同步公网 IP" text="适用于公网地址会变化的服务器。优先使用 Agent 检测到的公网地址；本机 IPv4 在 NAT 后且直接连接面板时，用面板看到的连接来源回填 IPv4。使用 SOCKS5 代理时不会把代理出口当成本机地址。暂时检测不到的地址不会清空。请确认出站地址也能接受客户端或链路入站连接；CGNAT 无法靠回填开放入站端口。" />
                    </div>}
                    {serverForm.managementMode === "online" && <div className="serverFormWide">
                      <Field label="节点默认出口网卡" help="仅控制这台服务器上 sing-box 节点的出口，节点可单独覆盖。修改后会重新应用配置并重启 sing-box；指定网卡不存在或未启用时，保留原配置并报错。">
                        <input maxLength={15} placeholder="留空使用系统路由，例如 ppp0" value={serverForm.outboundInterface || ""} onChange={(e) => setServerForm({ ...serverForm, outboundInterface: e.target.value })} />
                      </Field>
                      {!!serverForm.outboundInterface?.trim() && !!serverForm.agentVersion && !serverForm.outboundBindingSupport && <p className="serverFieldHelp dangerText">配置可保存；请先升级 Agent 至 0.6.12 后应用出口网卡设置。</p>}
                    </div>}
                  </div>
                </Advanced>}
                {!external && <Advanced title="Agent 代理与 Komari 监控" open={!!initial.agentProxyNodeId || !!initial.komariTokenSet}>
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
                    {serverForm.managementMode !== "external" && <div className="serverFormWide">
                      <Field label="Komari Agent token" help="从 Komari 面板取得此服务器的 Agent token。安装后由 MUI 面板自动下发；没有 token 就不会启动 Komari 监控。编辑时留空会保留原 token。">
                        <input type="password" autoComplete="off" placeholder={serverForm.komariTokenSet ? "已配置；留空保持不变" : "选填，留空不启动 Komari"} value={serverForm.komariToken || ""} onChange={(e) => setServerForm({ ...serverForm, komariToken: e.target.value || undefined })} />
                      </Field>
                      <div className="serverFieldHelp">{serverForm.komariTokenSet ? "已配置 token" : "未配置 token"}{serverForm.komariTokenSet && <button type="button" className="ghost" onClick={() => setServerForm({ ...serverForm, komariToken: "", komariTokenSet: false })}>清除 token</button>}</div>
                    </div>}
                  </div>
                </Advanced>}
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
