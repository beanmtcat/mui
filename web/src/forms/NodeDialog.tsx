import { useRef, useState } from "react";
import { canHostNodes, mutation, type Node, type NodeTemplate } from "../api";
import { useApp } from "../app/context";
import { setError } from "../app/feedback";
import { generatePassword, generatePort, manualFirewall, supportsGitHubUpgrade, type NodeForm } from "../app/helpers";
import { Advanced, Field, HelpTip, Icon, SubmitButton, useBusy } from "../app/ui";
import { MemoSecretField as SecretField } from "../components/secrets";
import { Dialog } from "./Dialog";

export default function NodeDialog({ initial, templateId }: { initial: NodeForm; templateId: string }) {
  const { servers, nodes, forwards, templates, certificates, operations, agentReleases, coreReleases, refreshing, refresh, act, closeModal, matchingCertificate, templateNodeForm } = useApp();
  const [nodeForm, setNodeForm] = useState(initial);
  const [selectedTemplate, setSelectedTemplate] = useState(templateId);
  const [templateLoading, setTemplateLoading] = useState(false);
  const templateRequest = useRef(0);
  const { busy, run } = useBusy();
  const selectedNodeServer = servers.find((s) => s.id === nodeForm.serverId);
  const externalNode = selectedNodeServer?.managementMode === "external";
  const nodeCoreMissing = !!selectedNodeServer && !externalNode && canHostNodes(selectedNodeServer) && !selectedNodeServer.coreBuild &&
    (!!selectedNodeServer.agentVersion || !selectedNodeServer.roles?.includes("exit"));
  const nodeCoreInstalling = operations.some((o) => o.serverId === nodeForm.serverId &&
    ["agent.upgrade", "core.upgrade"].includes(o.kind) && ["queued", "running", "activating"].includes(o.status));
  const nodeFirewallUnsupported = !externalNode && !!nodeForm.firewallPolicy && nodeForm.firewallPolicy !== "all" &&
    !servers.find((s) => s.id === nodeForm.serverId)?.nodeFirewallPolicies;
  const clearSelectedTemplate = () => {
    templateRequest.current++;
    setTemplateLoading(false);
    setSelectedTemplate("");
  };
  const applyTemplate = async (template: NodeTemplate) => {
    const request = ++templateRequest.current;
    setError("");
    setTemplateLoading(true);
    try {
      const form = await templateNodeForm(template, nodeForm.serverId || "");
      if (request !== templateRequest.current) return;
      setNodeForm(form);
      setSelectedTemplate(template.id);
    } catch (e) {
      if (request === templateRequest.current) setError((e as Error).message);
    } finally {
      if (request === templateRequest.current) setTemplateLoading(false);
    }
  };
  const randomizeNodePort = () => {
    const server = servers.find((s) => s.id === nodeForm.serverId);
    const occupied = new Set([
      nodeForm.port || 0,
      nodeForm.protocol === "snell" ? nodeForm.snellPort || 0 : 0,
      ...nodes.filter((n) => n.serverId === nodeForm.serverId).flatMap((n) => [n.port, n.protocol === "snell" ? n.snellPort || 20000 + n.port % 10000 : 0]),
      ...forwards.filter((f) => f.serverId === nodeForm.serverId && f.enabled && !f.deleting).map((f) => f.port),
      ...(server?.sshPorts || []),
    ]);
    try {
      setNodeForm({ ...nodeForm, port: generatePort(occupied) });
    } catch (e) {
      setError((e as Error).message);
    }
  };
  const submitNode = (e: React.FormEvent) => {
    e.preventDefault();
    void run(async () => {
    if (
      await act(
        () =>
          mutation(
            "/api/nodes" + (nodeForm.id ? "/" + nodeForm.id : ""),
            nodeForm.id ? "PATCH" : "POST",
            { ...nodeForm, ...(nodeForm.id ? {} : { templateId: selectedTemplate }), ...(manualFirewall(servers.find((s) => s.id === nodeForm.serverId)) ? { firewallPolicy: "manual", firewallSources: "" } : {}) },
          ),
        externalNode ? "外部节点已保存；面板不会配置卖家服务器或采集其流量" : nodeFirewallUnsupported || nodeForm.protocol === "snell" && !servers.find((s) => s.id === nodeForm.serverId)?.snellFixedPort
          ? "配置已保存，等待 Agent 更新后应用；原 UFW 规则仍会生效"
          : "配置已保存，等待 Agent 应用",
      )
    )
      closeModal();
    });
  };
  return <Dialog title={nodeForm.id ? "编辑节点" : "新建节点"} value={nodeForm} initial={initial} busy={busy}>
              <form onSubmit={submitNode}>
                <div className="formGrid">
                  <Field label="服务器 *">
                    <select
                      required
                      value={nodeForm.serverId || ""}
                      disabled={!!nodeForm.id}
                      onChange={(e) => setNodeForm({
                        ...nodeForm,
                        serverId: e.target.value,
                        singleUser: servers.find((s) => s.id === e.target.value)?.managementMode === "external",
                        direct: servers.find((s) => s.id === e.target.value)?.managementMode === "external" ? true : nodeForm.direct,
                        certificateId: nodeForm.protocol === "anytls"
                          ? nodeForm.certificateId || matchingCertificate(nodeForm.tlsName || "")
                          : "",
                      })}
                    >
                      <option value="">选择中转、落地或外部节点服务器</option>
                      {servers.filter((s) => canHostNodes(s) || s.id === nodeForm.serverId).map((s) => (
                        <option key={s.id} value={s.id}>
                          {s.name}
                        </option>
                      ))}
                    </select>
                  </Field>
                  {!nodeForm.id && selectedNodeServer && !canHostNodes(selectedNodeServer) && <p className="hint">当前服务器不能创建节点；请选择在线中转、落地或外部节点服务器。</p>}
                  {!nodeForm.id && (
                    <Field label="节点模板">
                      <select
                        value={selectedTemplate}
                        disabled={templateLoading}
                        onChange={(e) => {
                          const template = templates.find((t) => t.id === e.target.value);
                          if (template) void applyTemplate(template);
                          else clearSelectedTemplate();
                        }}
                      >
                        <option value="">手动填写</option>
                        {templates.map((t) => (
                          <option key={t.id} value={t.id}>
                            {t.name} · {t.protocol.toUpperCase()} :{t.port}
                          </option>
                        ))}
                      </select>
                    </Field>
                  )}
                  <Field label="节点名 *">
                    <input
                      required
                      value={nodeForm.name || ""}
                      onChange={(e) =>
                        setNodeForm({ ...nodeForm, name: e.target.value })
                      }
                    />
                  </Field>
                  <Field label="协议">
                    <select
                      value={nodeForm.protocol}
                      onChange={(e) => {
                        clearSelectedTemplate();
                        setNodeForm({
                          ...nodeForm,
                          protocol: e.target.value as Node["protocol"],
                          snellVersion: e.target.value === "snell" ? 6 : 0,
                          password: "",
                          shadowTlsHost: "",
                          shadowTlsPassword: "",
                        });
                      }}
                    >
                      <option value="ss">Shadowsocks</option>
                      <option value="snell">Snell</option>
                      <option value="anytls">AnyTLS</option>
                      <option value="socks5">SOCKS5</option>
                    </select>
                  </Field>
                  <Field label="端口 *（1–65535）">
                    <div className="inputWithAction">
                      <input
                        required
                        type="number"
                        min={1}
                        max={65535}
                        value={nodeForm.port || ""}
                        onChange={(e) => setNodeForm({ ...nodeForm, port: Number(e.target.value) })}
                      />
                      {!externalNode && <button className="iconButton" type="button" title="随机端口（50000–60000）" aria-label="随机端口（50000–60000）" onClick={randomizeNodePort}><Icon name="dice" /></button>}
                    </div>
                  </Field>
                  {nodeForm.protocol === "socks5" && <>
                    <Field label="SOCKS5 用户名 *"><input required autoComplete="off" maxLength={255} value={nodeForm.username || ""} onChange={(e) => setNodeForm({ ...nodeForm, username: e.target.value })} /></Field>
                  </>}
                  {nodeForm.protocol === "ss" && (
                    <Field label="加密方式">
                      <select
                        value={nodeForm.method}
                        onChange={(e) => {
                          clearSelectedTemplate();
                          setNodeForm({ ...nodeForm, method: e.target.value, password: "" });
                        }}
                      >
                        {[
                          "2022-blake3-aes-128-gcm",
                          "2022-blake3-aes-256-gcm",
                          "2022-blake3-chacha20-poly1305",
                          "aes-128-gcm",
                          "aes-256-gcm",
                          "chacha20-ietf-poly1305",
                        ].map((v) => (
                          <option key={v}>{v}</option>
                        ))}
                      </select>
                    </Field>
                  )}
                  {nodeForm.protocol === "snell" && (
                    <>
                      <Field label="Snell 版本">
                        <select value={nodeForm.snellVersion || 5} onChange={(e) => setNodeForm({ ...nodeForm, snellVersion: Number(e.target.value), obfs: "none" })}>
                          <option value={6}>v6</option><option value={5}>v5</option>
                        </select>
                        {(nodeForm.snellVersion || 5) === 6 && <small>PSK 需要 12–255 字节；使用默认流量整形，不使用 HTTP 混淆。</small>}
                        {(nodeForm.snellVersion || 5) === 6 && nodeForm.serverId && !externalNode && !servers.find((s) => s.id === nodeForm.serverId)?.snellV6 && <small className="dangerText">需升级 Agent 至 0.6.11 后应用 v6 配置。</small>}
                      </Field>
                      {!externalNode && <Field label="Snell 内层端口 *">
                        <input required type="number" min={1} max={65535} value={nodeForm.snellPort || ""} onChange={(e) => setNodeForm({ ...nodeForm, snellPort: Number(e.target.value) })} />
                        <small>固定监听 127.0.0.1，不对公网开放；须与其他监听端口不同。</small>
                        {nodeForm.serverId && !servers.find((s) => s.id === nodeForm.serverId)?.snellFixedPort && <small className="dangerText">配置可保存；需升级 Agent 至 0.6.2 或更高版本后才会应用固定内层端口。</small>}
                      </Field>}
                      {(nodeForm.snellVersion || 5) === 5 && <Field label="混淆模式">
                        <select value={nodeForm.obfs || "none"} onChange={(e) => setNodeForm({ ...nodeForm, obfs: e.target.value })}>
                          <option value="none">无</option>
                          <option value="http">HTTP</option>
                        </select>
                      </Field>}
                      <Field label={externalNode ? "ShadowTLS v3 SNI / 握手域名（卖家有提供时填写）" : "ShadowTLS v3 SNI / 握手域名 *"}>
                        <input required={!externalNode} placeholder="例如 www.example.com（TLS 站点）" value={nodeForm.shadowTlsHost || ""} onChange={(e) => { clearSelectedTemplate(); setNodeForm({ ...nodeForm, shadowTlsHost: e.target.value }); }} />
                      </Field>
                      {(!externalNode || !!nodeForm.shadowTlsHost) && <Field label={externalNode ? nodeForm.id ? "卖家提供的 ShadowTLS 密码（留空不修改）" : "卖家提供的 ShadowTLS 密码 *" : nodeForm.id ? "ShadowTLS v3 密码（留空不修改）" : selectedTemplate ? "ShadowTLS v3 密码（已填入，可修改）" : "ShadowTLS v3 密码（留空生成）"}>
                        <SecretField value={nodeForm.shadowTlsPassword || ""} onChange={(v) => setNodeForm({ ...nodeForm, shadowTlsPassword: v })} action={externalNode ? undefined : <button className="iconButton" type="button" title="生成 ShadowTLS 密码" aria-label="生成 ShadowTLS 密码" onClick={() => setNodeForm({ ...nodeForm, shadowTlsPassword: generatePassword("snell") })}><Icon name="generate" /></button>} />
                      </Field>}
                    </>
                  )}
                  {nodeForm.protocol === "anytls" && (
                    <>
                      <Field label="TLS 域名 *">
                        <input
                          required
                          value={nodeForm.tlsName || ""}
                          onChange={(e) =>
                            setNodeForm({
                              ...nodeForm,
                              tlsName: e.target.value,
                              certificateId: matchingCertificate(e.target.value),
                            })
                          }
                        />
                      </Field>
                      {!externalNode && <Field label="证书 *">
                        <select
                          required
                          value={nodeForm.certificateId || ""}
                          onChange={(e) =>
                            setNodeForm({
                              ...nodeForm,
                              certificateId: e.target.value,
                            })
                          }
                        >
                          <option value="">选择证书</option>
                          {certificates
                            .map((c) => (
                              <option key={c.id} value={c.id}>
                                {c.name ? `${c.name} · ${c.domain}` : c.domain}{new Date(c.expiresAt).getTime() <= Date.now() ? "（已过期）" : ""}
                              </option>
                            ))}
                        </select>
                      </Field>}
                    </>
                  )}
                  <Field
                    label={
                      nodeForm.id
                        ? "新密码（留空不修改）"
                        : externalNode ? "卖家提供的密码 / PSK *" : selectedTemplate ? "密码 / PSK（已填入，可修改）" : "密码 / PSK（留空生成）"
                    }
                  >
                    <SecretField value={nodeForm.password || ""} onChange={(v) => setNodeForm({ ...nodeForm, password: v })} action={externalNode ? undefined : <button className="iconButton" type="button" title="生成密码 / PSK" aria-label="生成密码 / PSK" onClick={() => setNodeForm({ ...nodeForm, password: generatePassword(nodeForm.protocol || "ss", nodeForm.method) })}><Icon name="generate" /></button>} />
                  </Field>
                  <Field label="访问方式">
                    <label className="check">
                      <input type="checkbox" checked={!!nodeForm.direct} onChange={(e) => setNodeForm({ ...nodeForm, direct: e.target.checked })} />
                      允许直连（可直接加入订阅）
                    </label>
                  </Field>
                  {nodeForm.direct && !externalNode && <Field label="节点端口 UFW 规则">
                    <select
                      value={manualFirewall(servers.find((s) => s.id === nodeForm.serverId)) ? "manual" : nodeForm.firewallPolicy || "all"}
                      disabled={manualFirewall(servers.find((s) => s.id === nodeForm.serverId))}
                      onChange={(e) => setNodeForm({ ...nodeForm, firewallPolicy: e.target.value as Node["firewallPolicy"], firewallSources: "" })}
                    >
                      <option value="all">自动放行所有来源</option>
                      <option value="restricted">仅自动放行指定 IP / CIDR</option>
                      <option value="manual" disabled={nodeForm.protocol === "socks5"}>不生成自动规则，手动管理</option>
                    </select>
                  </Field>}
                  {!manualFirewall(servers.find((s) => s.id === nodeForm.serverId)) && !nodeForm.direct && <p className="hint">未开启客户端直连：仅放行链路最后一跳和使用此 SOCKS5 的 Agent。{nodeForm.routeSources ? `链路来源：${nodeForm.routeSources.split(",").join("、")}。` : ""}{nodeForm.agentProxySources ? `Agent 来源：${nodeForm.agentProxySources.split(",").join("、")}。` : ""}{!nodeForm.routeSources && !nodeForm.agentProxySources ? "未被链路或 Agent 使用时，端口不对外开放。" : ""}</p>}
                  {!manualFirewall(servers.find((s) => s.id === nodeForm.serverId)) && nodeForm.direct && nodeForm.firewallPolicy === "restricted" && (
                    <Field label="允许的来源 IP / CIDR *">
                      <textarea
                        required
                        rows={2}
                        placeholder="203.0.113.4, 2001:db8::/32"
                        value={nodeForm.firewallSources || ""}
                        onChange={(e) => setNodeForm({ ...nodeForm, firewallSources: e.target.value })}
                      />
                    </Field>
                  )}
                  {nodeForm.id && (
                    <Field label="状态">
                      <label className="check">
                        <input
                          type="checkbox"
                          checked={nodeForm.enabled ?? true}
                          onChange={(e) =>
                            setNodeForm({
                              ...nodeForm,
                              enabled: e.target.checked,
                            })
                          }
                        />{" "}
                        启用节点
                      </label>
                    </Field>
                  )}
                </div>
                <Advanced key={externalNode ? "external" : "managed"} title="高级设置：单用户、监听与发布地址、节点出口" open={externalNode || !!initial.singleUser || !!initial.publishAddress || (initial.listen || "0.0.0.0") !== "0.0.0.0" || (initial.outboundMode || "inherit") !== "inherit"}>
                  <div className="formGrid">
                  <div className="serverToggleRow nodeSingleUserRow">
                    <label className="check">
                      <input type="checkbox" checked={externalNode || !!nodeForm.singleUser} disabled={externalNode} onChange={(e) => setNodeForm({ ...nodeForm, singleUser: e.target.checked })} />
                      单用户（订阅共用节点原有凭据）
                    </label>
                    <HelpTip label="单用户" text="订阅和复制链接均使用节点的原有密码。流量只能按节点统计；停用或删除订阅不会使已导入客户端的节点凭据失效，需更换节点密码。" />
                  </div>
                  {!externalNode && <Field label="监听地址">
                    <input
                      value={nodeForm.listen || ""}
                      onChange={(e) =>
                        setNodeForm({ ...nodeForm, listen: e.target.value })
                      }
                    />
                  </Field>}
                  <Field label={externalNode ? "节点地址覆盖（与服务器地址不同时填写）" : "发布地址覆盖"}>
                    <input
                      value={nodeForm.publishAddress || ""}
                      onChange={(e) =>
                        setNodeForm({
                          ...nodeForm,
                          publishAddress: e.target.value,
                        })
                      }
                    />
                  </Field>
                  {!externalNode && <Field label="节点出口">
                    <select aria-label="节点出口" value={nodeForm.outboundMode || "inherit"} onChange={(e) => setNodeForm({ ...nodeForm, outboundMode: e.target.value as Node["outboundMode"], outboundInterface: "" })}>
                      <option value="inherit">继承服务器（{servers.find((s) => s.id === nodeForm.serverId)?.outboundInterface || "系统路由"}）</option>
                      <option value="system">使用系统路由</option>
                      <option value="interface">指定出口网卡</option>
                    </select>
                    <small>仅影响此节点的 sing-box 流量及 ShadowTLS 握手，不改变 Agent 或端口转发的出口。</small>
                  </Field>}
                  {!externalNode && nodeForm.outboundMode === "interface" && <Field label="出口网卡 *">
                    <input required maxLength={15} placeholder="例如 ppp0、eth0" value={nodeForm.outboundInterface || ""} onChange={(e) => setNodeForm({ ...nodeForm, outboundInterface: e.target.value })} />
                    <small>须为目标服务器已启用的网卡；不可用时应用失败，不自动改用其他出口。</small>
                  </Field>}
                  {!externalNode && (nodeForm.outboundMode === "interface" || ((nodeForm.outboundMode || "inherit") === "inherit" && !!servers.find((s) => s.id === nodeForm.serverId)?.outboundInterface)) && !servers.find((s) => s.id === nodeForm.serverId)?.outboundBindingSupport && <p className="hint dangerText">配置可保存；需升级 Agent 至 0.6.12 后应用出口网卡设置。</p>}
                  </div>
                </Advanced>
                <p className="hint">{externalNode ? "外部节点由卖家运行。面板仅保存连接信息用于订阅和链路，不会修改卖家服务器，也无法确认实时连通和流量。请填写卖家提供的原始端口、协议和密码。" : "节点连接配置改变时会重启 sing-box；只修改 UFW 放行来源不会重启。"}</p>
                {!manualFirewall(servers.find((s) => s.id === nodeForm.serverId)) && nodeForm.firewallPolicy === "restricted" && <p className="hint">Agent 0.6.14 起，节点来源限制优先于主机已有的同端口 UFW 规则；其他来源会被拒绝。</p>}
                {!manualFirewall(servers.find((s) => s.id === nodeForm.serverId)) && nodeForm.firewallPolicy === "manual" && <p className="hint">手动管理模式不会开放节点端口，请先在自定义规则中添加需要的允许来源。</p>}
                {manualFirewall(servers.find((s) => s.id === nodeForm.serverId)) && !externalNode && <p className="hint">该服务器的防火墙由外部管理。允许直连开关仅决定能否加入直连订阅；实际端口放行、来源白名单和仅链路访问限制请自行配置。</p>}
                {nodeForm.protocol === "socks5" && !!servers.find((s) => s.id === nodeForm.serverId)?.agentVersion && !servers.find((s) => s.id === nodeForm.serverId)?.agentProxySupport && <div className="banner warning" role="status">配置可以保存；请先将服务器 Agent 升级至 0.6.10，之后才会应用 SOCKS5 节点。</div>}
                {nodeFirewallUnsupported && <div className="banner warning" role="status">可以保存配置，但该服务器的 Agent 尚未上报支持新规则。更新 Agent 前不会应用此配置，现有 UFW 放行规则仍然生效。</div>}
                {nodeCoreMissing && <div className="banner warning" role="status">
                  <p>该服务器需要先安装 sing-box，安装成功后即可创建节点。</p>
                  <button type="button" className="ghost" disabled={!selectedNodeServer?.coreSelfUpdate || !!agentReleases.releaseVersion && !supportsGitHubUpgrade(selectedNodeServer?.agentVersion || "") || !coreReleases[selectedNodeServer?.arch || ""] || nodeCoreInstalling}
                    onClick={() => act(() => mutation("/api/servers/" + nodeForm.serverId + "/core/upgrade", "POST"), "sing-box 安装已排队；点击刷新安装状态，完成后提交节点")}>{nodeCoreInstalling ? "sing-box 安装或升级进行中" : "安装 sing-box"}</button>
                  <button type="button" className="ghost" disabled={refreshing} onClick={() => void refresh(true)}>{refreshing ? "刷新中…" : "刷新安装状态"}</button>
                  {!selectedNodeServer?.coreSelfUpdate && <p>请先接入支持核心安装的 Agent。</p>}
                  {!!agentReleases.releaseVersion && !!selectedNodeServer?.coreSelfUpdate && !supportsGitHubUpgrade(selectedNodeServer.agentVersion || "") && <p>先用新版接入命令重装 Agent，才能从 GitHub 安装 sing-box。</p>}
                  {!!selectedNodeServer?.coreSelfUpdate && !coreReleases[selectedNodeServer?.arch || ""] && <p>该架构的 sing-box 发布文件不可用。</p>}
                </div>}
                {nodeForm.protocol === "socks5" && !externalNode && <p className="hint">SOCKS5 支持 TCP，强制用户名密码认证，服务器必须启用 UFW。所有在线服务器的 Agent 均可独立使用此节点，无需打开“允许直连”，面板会为它的来源 IP 自动添加放行规则。仅在可信网络中使用，SOCKS5 本身不加密。</p>}
                {nodeForm.protocol === "socks5" && !externalNode && (manualFirewall(servers.find((s) => s.id === nodeForm.serverId)) || servers.find((s) => s.id === nodeForm.serverId)?.ufwStatus !== "active") && <div className="banner warning" role="status">请先将该服务器设置为 UFW 托管，并在服务器列表安全初始化防火墙，再提交 SOCKS5 节点。</div>}
                {templateLoading && <p className="hint">正在读取模板密码…</p>}
                <SubmitButton busy={busy} label="提交配置" disabled={templateLoading || nodeCoreMissing || !!selectedNodeServer && !canHostNodes(selectedNodeServer) || (!externalNode && nodeForm.protocol === "socks5" && (manualFirewall(servers.find((s) => s.id === nodeForm.serverId)) || servers.find((s) => s.id === nodeForm.serverId)?.ufwStatus !== "active"))} />
              </form>
  </Dialog>;
}
