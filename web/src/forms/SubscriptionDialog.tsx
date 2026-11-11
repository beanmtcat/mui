import { useId, useState } from "react";
import { mutation, type Subscription } from "../api";
import { useApp } from "../app/context";
import { sharedSubscriptionPassword, subscriptionDirectNodeIssue, subscriptionNodeEligible, subscriptionNodeIssue } from "../app/helpers";
import { Field, localDate, SubmitButton, useBusy } from "../app/ui";
import { MemoMaskedValue as MaskedValue } from "../components/secrets";
import { Dialog } from "./Dialog";
import { ItemPicker } from "./ItemPicker";

export default function SubscriptionDialog({ initial }: { initial: Partial<Subscription> }) {
  const { nodes, routes, customers, surgeTemplates, surgeTemplatesStatus, refreshing, refresh, serverName, routePath, sharedSubNodes, subMemberNodes, surgeImportHelp, act, copy, closeModal } = useApp();
  const [subForm, setSubForm] = useState(initial);
  const surgeTemplateSelectId = useId();
  // Once created, the dialog only hands over the link: saving again would
  // create a second subscription.
  const [created, setCreated] = useState<{ url: string; format: string } | null>(null);
  const { busy, run } = useBusy();
  const hasCustomSurgeTemplate = Boolean(subForm.surgeTemplateId && subForm.surgeTemplateId !== "default");
  const selectedSurgeTemplateValue = hasCustomSurgeTemplate ? subForm.surgeTemplateId! : "default";
  const submitSub = (e: React.FormEvent) => {
    e.preventDefault();
    if (created) return;
    void run(async () => {
      if (subForm.id) {
        if (await act(() => mutation("/api/subscriptions/" + subForm.id, "PATCH", subForm), "订阅已保存")) closeModal();
        return;
      }
      await act(async () => {
        const result = await mutation<Subscription>("/api/subscriptions", "POST", subForm);
        setCreated({ url: result.url || "", format: subForm.format || "" });
      }, "订阅已创建");
    });
  };
  return <Dialog title={subForm.id ? "编辑订阅" : "新建订阅"} value={created ? initial : subForm} initial={initial} busy={busy}>
              <form onSubmit={submitSub}>
                <div className="formGrid">
                  <Field label="订阅名称 *">
                    <input
                      required
                      value={subForm.name || ""}
                      onChange={(e) =>
                        setSubForm({ ...subForm, name: e.target.value })
                      }
                    />
                  </Field>
                  <Field label="关联客户">
                    <select value={subForm.customerId || ""} onChange={(e) => setSubForm({ ...subForm, customerId: e.target.value })}>
                      <option value="">未关联</option>
                      {customers.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
                    </select>
                  </Field>
                  <Field label="客户端格式">
                    <select
                      value={subForm.format}
                      onChange={(e) =>
                        setSubForm({
                          ...subForm,
                          format: e.target.value,
                          surgeTemplateId: e.target.value === "surge" ? subForm.surgeTemplateId : "",
                          nodeIds: (subForm.nodeIds || []).filter((id) => {
                            const node = nodes.find((item) => item.id === id);
                            return !!node && subscriptionNodeEligible(e.target.value, node);
                          }),
                          routeIds: (subForm.routeIds || []).filter((id) => {
                            const node = nodes.find((item) => item.id === routes.find((r) => r.id === id)?.nodeId);
                            return !!node && subscriptionNodeEligible(e.target.value, node);
                          }),
                        })
                      }
                    >
                      <option value="sing-box">sing-box JSON</option>
                      <option value="surge">Surge 节点订阅（代理组）</option>
                      <option value="v2rayn">v2rayN 订阅</option>
                    </select>
                  </Field>
                  {subForm.format === "surge" && <div className="field">
                    <label htmlFor={surgeTemplateSelectId}>Surge 完整配置模板</label>
                    <select id={surgeTemplateSelectId} value={selectedSurgeTemplateValue} disabled={!surgeTemplates.length} onChange={(e) => setSubForm({ ...subForm, surgeTemplateId: e.target.value === "default" ? "" : e.target.value })}>
                      {!surgeTemplates.length && <option value={selectedSurgeTemplateValue}>{hasCustomSurgeTemplate ? (surgeTemplatesStatus === "error" ? "保留当前模板（模板列表加载失败）" : "保留当前模板（正在加载模板…）") : (surgeTemplatesStatus === "error" ? "默认模板（模板列表加载失败）" : "正在加载模板…")}</option>}
                      {surgeTemplates.length > 0 && hasCustomSurgeTemplate && !surgeTemplates.some((item) => item.id === selectedSurgeTemplateValue) && <option value={selectedSurgeTemplateValue}>当前已选模板（已不存在，请重新选择）</option>}
                      {surgeTemplates.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
                    </select>
                    {surgeTemplatesStatus === "error" && !surgeTemplates.length && <small className="dangerText">Surge 模板列表加载失败；直接保存将保留当前模板设置，或 <button type="button" className="textButton" disabled={refreshing} onClick={() => void refresh(true)}>{refreshing ? "正在重试…" : "重新加载模板"}</button>。</small>}
                    <small>只影响“完整配置链接”；节点列表链接不受模板影响。模板在左侧“Surge 模板”管理。</small>
                  </div>}
                  <Field label="到期日（留空不过期）">
                    <input
                      type="date"
                      value={
                        subForm.expiresAt
                          ? localDate(new Date(subForm.expiresAt))
                          : ""
                      }
                      onChange={(e) =>
                        setSubForm({
                          ...subForm,
                          // The link works through the end of the chosen day.
                          expiresAt: e.target.value
                            ? new Date(
                                e.target.value + "T23:59:59",
                              ).toISOString()
                            : undefined,
                        })
                      }
                    />
                  </Field>
                </div>
                <div className="field">
                  <span>选择链路</span>
                  <ItemPicker
                    label="选择链路"
                    emptyText="未选择链路"
                    addText="选择链路"
                    noneText="暂无链路，请先在“链路”中创建并选择落地节点。“端口转发”里的手动规则不会自动成为订阅链路。"
                    items={routes.map((r) => {
                      const node = nodes.find((n) => n.id === r.nodeId);
                      return {
                        id: r.id, name: r.name,
                        details: [routePath(r), ...(node && sharedSubscriptionPassword(node) ? ["共享节点凭据 · 无法按订阅统计流量"] : [])],
                        issue: !r.enabled ? "链路已停用" : !node ? "落地节点已删除" : subscriptionNodeIssue(subForm.format, node),
                      };
                    })}
                    selected={subForm.routeIds || []}
                    onChange={(routeIds) => setSubForm({ ...subForm, routeIds })}
                  />
                </div>
                <div className="field">
                  <span>直连节点</span>
                  <ItemPicker
                    label="选择直连节点"
                    emptyText="未选择直连节点"
                    addText="选择节点"
                    noneText="没有开启“允许直连”的节点。"
                    // A node without direct access is not an option at all; one
                    // already chosen stays so it can be seen and removed.
                    items={nodes.filter((n) => n.direct || subForm.nodeIds?.includes(n.id)).map((n) => ({
                      id: n.id, name: n.name,
                      details: [
                        `${n.protocol.toUpperCase()} · ${serverName(n.serverId)}`,
                        ...(!subscriptionDirectNodeIssue(subForm.format, n) && n.status !== "active" ? [n.status === "error" ? "配置应用失败，请检查操作记录；可先加入订阅，生效后下发" : "配置待应用；可先加入订阅，生效后下发"] : []),
                        ...(sharedSubscriptionPassword(n) ? ["共享节点凭据 · 无法按订阅统计流量"] : []),
                      ],
                      issue: subscriptionDirectNodeIssue(subForm.format, n),
                    }))}
                    selected={subForm.nodeIds || []}
                    onChange={(nodeIds) => setSubForm({ ...subForm, nodeIds })}
                  />
                  <p className="hint">待应用的节点可以先选入订阅，配置在服务器上生效后才会出现在订阅下载中。不兼容当前客户端格式的节点会显示具体原因。</p>
                </div>
                {subForm.format === "surge" && <p className="hint">Surge 格式输出节点列表，支持传统 SS（如 aes-256-gcm）、AES-GCM 的 SS 2022、ShadowTLS Snell 和 AnyTLS。创建后或在列表“查看链接”中，可复制用于“从 URL 安装配置”的完整配置链接，或复制引用到已有配置的代理组配置。AnyTLS 需要 Surge Mac 6.4.3+ 或 iOS 5.17.0+，默认校验证书。</p>}
                {subForm.format === "v2rayn" && <p className="hint">v2rayN 格式支持 SS 和 AnyTLS 节点及其链路。复制订阅链接，在 v2rayN 中添加订阅分组并更新订阅；AnyTLS 请使用支持该协议的新版 v2rayN，并选择 sing-box 内核。v2rayN 不支持 Snell / ShadowTLS。</p>}
                {sharedSubNodes(subForm).length > 0 && <p className="hint">以下节点沿用节点凭据：{sharedSubNodes(subForm).map((n) => n.name).join("、")}。流量只能按节点统计，无法单独撤销某条订阅的节点访问；禁用、到期或轮换订阅链接仅影响订阅下载，撤销已导入客户端的访问需更换节点密码。</p>}
                <p className="hint">链路的订阅地址是首跳服务器的地址和链路端口，协议与登录凭据来自落地节点。</p>
                {subMemberNodes(subForm).some((n) => !sharedSubscriptionPassword(n)) && <p className="hint">调整节点、链路或订阅状态后，使用独立凭据的节点所在服务器可能重启 sing-box 更新登录凭据，连接将短暂中断；只更换 Surge 模板不会重启。订阅到期时也会自动更新凭据。</p>}
                {created ? <div className="commandBox">
                    <strong>请保存订阅链接：</strong>
                    <span>新凭据需等待 Agent 应用配置后才能下载使用。</span>
                    <MaskedValue value={created.url}><button type="button" onClick={() => copy(created.url)}>复制</button></MaskedValue>
                    {created.format === "surge" && surgeImportHelp(created.url)}
                    <button type="button" className="primary submit" onClick={closeModal}>完成</button>
                  </div> : <SubmitButton busy={busy} label={subForm.id ? "保存订阅" : "创建订阅"} />}
              </form>
  </Dialog>;
}
