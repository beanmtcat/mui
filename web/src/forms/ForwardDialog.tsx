import { useState } from "react";
import { mutation, type ForwardRule } from "../api";
import { useApp } from "../app/context";
import { manualFirewall, parseTargets } from "../app/helpers";
import { Field, SubmitButton, useBusy } from "../app/ui";
import { Dialog } from "./Dialog";

export default function ForwardDialog({ initial, targets }: { initial: Partial<ForwardRule>; targets: string }) {
  const { servers, act, closeModal, setConfirmation } = useApp();
  const [forwardForm, setForwardForm] = useState(initial);
  const [forwardTargets, setForwardTargets] = useState(targets);
  const { busy, run } = useBusy();
  const doSubmitForward = () => run(async () => {
    const path = "/api/forwards" + (forwardForm.id ? "/" + forwardForm.id : "");
    const body = { ...forwardForm, targets: parseTargets(forwardTargets), ...(manualFirewall(servers.find((s) => s.id === forwardForm.serverId)) ? { firewallPolicy: "manual", firewallSources: "" } : {}) };
    const server = servers.find((s) => s.id === forwardForm.serverId);
    const message = server?.managementMode === "offline" ? "转发已保存，请导出离线配置并在目标机应用" : body.network === "tcp+udp" && !server?.forwardTcpUdp ? "转发已保存，请先升级 Agent 至 0.6.7" : "转发配置已提交，等待 Agent 应用";
    if (await act(() => mutation(path, forwardForm.id ? "PATCH" : "POST", body), message)) closeModal();
  });
  const submitForward = async (e: React.FormEvent) => {
    e.preventDefault();
    // Opening a forward to the whole internet needs an explicit confirm.
    if (forwardForm.firewallPolicy === "all" && !manualFirewall(servers.find((s) => s.id === forwardForm.serverId))) {
      setConfirmation({
        title: "确认公开转发",
        message: `转发「${forwardForm.name || ""}」将放行所有来源，目标 ${forwardTargets.split("\n").filter(Boolean).join("、")} 会暴露给全网。确定公开吗？如只需特定来源，请改用“仅放行指定 IP / CIDR”。`,
        confirmLabel: "确认公开",
        onConfirm: () => { void doSubmitForward(); },
      });
      return;
    }
    await doSubmitForward();
  };
  return <Dialog title={forwardForm.id ? "编辑端口转发" : "新建端口转发"} value={[forwardForm, forwardTargets]} initial={[initial, targets]} busy={busy}>
              <form onSubmit={submitForward}>
                <div className="formGrid">
                  <Field label="服务器 *"><select required value={forwardForm.serverId || ""} disabled={!!forwardForm.id} onChange={(e) => setForwardForm({ ...forwardForm, serverId: e.target.value })}><option value="">选择服务器</option>{servers.filter((s) => s.managementMode !== "external" || s.id === forwardForm.serverId).map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</select></Field>
                  <Field label="名称 *"><input required maxLength={100} value={forwardForm.name || ""} onChange={(e) => setForwardForm({ ...forwardForm, name: e.target.value })} /></Field>
                  <Field label="协议"><select value={forwardForm.network || "tcp"} onChange={(e) => setForwardForm({ ...forwardForm, network: e.target.value as ForwardRule["network"], healthCheck: "" })}><option value="tcp">TCP</option><option value="udp">UDP</option><option value="tcp+udp">TCP + UDP</option></select></Field>
                  <Field label="监听 IP"><input required value={forwardForm.listen || ""} onChange={(e) => setForwardForm({ ...forwardForm, listen: e.target.value })} placeholder="0.0.0.0" /></Field>
                  <Field label="监听端口 *"><input required type="number" min={1024} max={65535} value={forwardForm.port || ""} onChange={(e) => setForwardForm({ ...forwardForm, port: Number(e.target.value) })} /></Field>
                  <Field label="目标（每行一个 地址:端口） *"><textarea required rows={3} value={forwardTargets} onChange={(e) => setForwardTargets(e.target.value)} placeholder={"203.0.113.10:443\nexample.com:443\n[2001:db8::1]:443"} /></Field>
                  {parseTargets(forwardTargets).length > 1 && <Field label="多目标模式"><select value={forwardForm.balance || "failover"} onChange={(e) => setForwardForm({ ...forwardForm, balance: e.target.value as ForwardRule["balance"] })}><option value="failover">主备：优先第一个可用目标</option><option value="round-robin">轮询：新连接轮流分配</option></select></Field>}
                  {(forwardForm.network === "udp" || forwardForm.network === "tcp+udp") && parseTargets(forwardTargets).length > 1 && <Field label="健康检查">
                    <select value={forwardForm.healthCheck || ""} onChange={(e) => setForwardForm({ ...forwardForm, healthCheck: e.target.value as "tcp" | "none" | "" })}>
                      <option value="">{forwardForm.network === "tcp+udp" ? "按协议默认：TCP 主动探测 / UDP 被动检查" : "默认：被动检查（纯 UDP 服务）"}</option>
                      <option value="none">不主动探测（通过连接 / 套接字错误切换）</option>
                      <option value="tcp">TCP 探测（目标须有同端口 TCP 服务）</option>
                    </select>
                  </Field>}
                  <Field label="UFW 规则"><select disabled={manualFirewall(servers.find((s) => s.id === forwardForm.serverId))} value={manualFirewall(servers.find((s) => s.id === forwardForm.serverId)) ? "manual" : forwardForm.firewallPolicy || "all"} onChange={(e) => setForwardForm({ ...forwardForm, firewallPolicy: e.target.value as ForwardRule["firewallPolicy"], firewallSources: e.target.value === "restricted" ? forwardForm.firewallSources : "" })}><option value="all">自动放行所有来源</option><option value="restricted">仅放行指定 IP / CIDR</option><option value="manual">手动管理</option></select></Field>
                  {!manualFirewall(servers.find((s) => s.id === forwardForm.serverId)) && forwardForm.firewallPolicy === "all" && <p className="hint">公开转发会把目标暴露给全网；如无必要请改用“仅放行指定 IP / CIDR”。提交时会再次确认。</p>}
                  {!manualFirewall(servers.find((s) => s.id === forwardForm.serverId)) && forwardForm.firewallPolicy === "restricted" && <Field label="允许的来源 IP / CIDR *"><textarea required value={forwardForm.firewallSources || ""} onChange={(e) => setForwardForm({ ...forwardForm, firewallSources: e.target.value })} placeholder="每行一个 IP 或 CIDR" /></Field>}
                  <Field label="状态"><label className="check"><input type="checkbox" checked={!!forwardForm.enabled} onChange={(e) => setForwardForm({ ...forwardForm, enabled: e.target.checked })} /> 启用转发</label></Field>
                </div>
                {forwardForm.network === "tcp+udp" && <p className="hint">TCP 和 UDP 使用同一监听端口、目标及防火墙来源，一起启停和删除，用量合并统计。需要 Agent 0.6.7 或更高版本。</p>}
                {forwardForm.network === "tcp+udp" && servers.find((s) => s.id === forwardForm.serverId)?.managementMode !== "offline" && !servers.find((s) => s.id === forwardForm.serverId)?.forwardTcpUdp && <p className="hint">服务器尚未上报双协议转发能力。配置可先保存，请升级 Agent 后再应用。</p>}
                {forwardForm.serverId && !servers.find((s) => s.id === forwardForm.serverId)?.forwardSupport && servers.find((s) => s.id === forwardForm.serverId)?.managementMode !== "offline" && <p className="hint">这台服务器的 Agent 尚未上报端口转发能力。规则可以先保存；升级 Agent 后会自动应用。</p>}
                {servers.find((s) => s.id === forwardForm.serverId)?.managementMode === "offline" && <p className="hint">此机离线管理：保存后到服务器列表导出完整配置，再在目标机应用。</p>}
                {manualFirewall(servers.find((s) => s.id === forwardForm.serverId)) && <p className="hint">该服务器为手动管理防火墙，面板只部署转发进程，入口端口与来源限制请自行配置。</p>}
                <p className="hint">目标服务器需允许来自转发服务器的连接；UFW 规则只控制本机入口。</p>
                <p className="hint">目标可以填域名：转发进程每 30 秒重新解析一次，域名指向新地址后新连接会跟着走。修改或删除一条转发只影响它自己的连接。</p>
                <p className="hint">多目标 TCP 或已选择 TCP 探测的 UDP 规则，每 5 秒探测一次，连续 2 次失败停用、2 次成功恢复。纯 UDP 默认通过套接字错误切换目标，10 秒后允许重试；仅无响应无法判断故障。</p>
                <SubmitButton busy={busy} label="提交配置" />
              </form>
  </Dialog>;
}
