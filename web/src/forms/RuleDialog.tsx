import { useState } from "react";
import { mutation, type FirewallRule } from "../api";
import { useApp } from "../app/context";
import type { RuleForm } from "../app/helpers";
import { Field, SubmitButton, useBusy } from "../app/ui";
import { Dialog } from "./Dialog";

export default function RuleDialog({ initial }: { initial: RuleForm }) {
  const { servers, act, closeModal } = useApp();
  const [ruleForm, setRuleForm] = useState(initial);
  const { busy, run } = useBusy();
  const submitRule = (e: React.FormEvent) => {
    e.preventDefault();
    void run(async () => {
      if (await act(
        () => mutation("/api/firewall" + (ruleForm.id ? "/" + ruleForm.id : ""), ruleForm.id ? "PATCH" : "POST", ruleForm),
        ruleForm.id ? "规则已修改，等待 Agent 应用" : ruleForm.replaceHostRule ? "已提交：先删除主机原规则，再由面板创建新规则" : "UFW 规则已提交",
      )) closeModal();
    });
  };
  return <Dialog title={ruleForm.id ? "修改 UFW 规则" : ruleForm.replaceHostRule ? "接管主机规则" : "新建 UFW 规则"} value={ruleForm} initial={initial} busy={busy}>
              <form onSubmit={submitRule}>
                <div className="formGrid">
                  <Field label="服务器 *">
                    <select
                      required
                      value={ruleForm.serverId || ""}
                      disabled={!!ruleForm.id || !!ruleForm.replaceHostRule}
                      onChange={(e) =>
                        setRuleForm({ ...ruleForm, serverId: e.target.value })
                      }
                    >
                      <option value="">选择服务器</option>
                      {servers.map((s) => (
                        <option key={s.id} value={s.id}>
                          {s.name}
                        </option>
                      ))}
                    </select>
                  </Field>
                  <Field label="协议">
                    <select
                      value={ruleForm.network}
                      onChange={(e) =>
                        setRuleForm({ ...ruleForm, network: e.target.value })
                      }
                    >
                      <option value="tcp">TCP</option>
                      <option value="udp">UDP</option>
                      {ruleForm.replaceHostRule && <option value="tcp+udp">TCP + UDP（保存为两条规则）</option>}
                    </select>
                  </Field>
                  <Field label="地址族">
                    <select
                      value={ruleForm.family || ""}
                      onChange={(e) => setRuleForm({ ...ruleForm, family: e.target.value as FirewallRule["family"] })}
                    >
                      <option value="">IPv4 + IPv6</option>
                      <option value="ipv4">仅 IPv4</option>
                      <option value="ipv6">仅 IPv6</option>
                    </select>
                  </Field>
                  <Field label="起始端口">
                    <input
                      required
                      type="number"
                      min={1}
                      max={65535}
                      value={ruleForm.portFrom || ""}
                      onChange={(e) =>
                        setRuleForm({
                          ...ruleForm,
                          portFrom: Number(e.target.value),
                        })
                      }
                    />
                  </Field>
                  <Field label="结束端口">
                    <input
                      required
                      type="number"
                      min={1}
                      max={65535}
                      value={ruleForm.portTo || ""}
                      onChange={(e) =>
                        setRuleForm({
                          ...ruleForm,
                          portTo: Number(e.target.value),
                        })
                      }
                    />
                  </Field>
                  <Field label="来源 IP / CIDR（留空任意）">
                    <input
                      value={ruleForm.source || ""}
                      onChange={(e) =>
                        setRuleForm({ ...ruleForm, source: e.target.value })
                      }
                    />
                  </Field>
                  <Field label="动作">
                    <select
                      value={ruleForm.action}
                      onChange={(e) =>
                        setRuleForm({ ...ruleForm, action: e.target.value })
                      }
                    >
                      <option value="allow">允许</option>
                      <option value="deny">拒绝</option>
                    </select>
                  </Field>
                  <Field label="备注">
                    <input
                      value={ruleForm.comment || ""}
                      onChange={(e) =>
                        setRuleForm({ ...ruleForm, comment: e.target.value })
                      }
                    />
                  </Field>
                </div>
                <p className="hint">填写来源 IP / CIDR 时，规则只作用于该来源所属的地址族，所选地址族须与来源一致。</p>
                {ruleForm.replaceHostRule && <p className="hint">保存后先删除主机上的这一条原规则（同端口的另一地址族规则不受影响）：<span className="mono">{ruleForm.replaceHostRule}</span>，再由面板创建上面的规则并在以后管理它。TCP + UDP 会创建两条可分别编辑的规则。</p>}
                <SubmitButton busy={busy} label={ruleForm.id ? "保存修改" : "提交规则"} />
              </form>
  </Dialog>;
}
