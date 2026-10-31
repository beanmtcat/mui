import { useState } from "react";
import { mutation, type Node } from "../api";
import { useApp } from "../app/context";
import { generatePassword, generatePort, type TemplateForm } from "../app/helpers";
import { Field, Icon, SubmitButton, useBusy } from "../app/ui";
import { MemoSecretField as SecretField } from "../components/secrets";
import { Dialog } from "./Dialog";

export default function TemplateDialog({ initial }: { initial: TemplateForm }) {
  const { act, closeModal } = useApp();
  const [templateForm, setTemplateForm] = useState(initial);
  const { busy, run } = useBusy();
  const submitTemplate = (e: React.FormEvent) => {
    e.preventDefault();
    void run(async () => {
      if (await act(
        () => mutation("/api/node-templates" + (templateForm.id ? "/" + templateForm.id : ""), templateForm.id ? "PATCH" : "POST", templateForm),
        "节点模板已保存",
      )) closeModal();
    });
  };
  return <Dialog title={templateForm.id ? "编辑节点模板" : "新建节点模板"} value={templateForm} initial={initial} busy={busy}>
              <form onSubmit={submitTemplate}>
                <div className="formGrid">
                  <Field label="模板名称 *">
                    <input
                      required
                      maxLength={100}
                      value={templateForm.name || ""}
                      onChange={(e) => setTemplateForm({ ...templateForm, name: e.target.value })}
                    />
                  </Field>
                  <Field label="协议">
                    <select
                      value={templateForm.protocol}
                      onChange={(e) => setTemplateForm({ ...templateForm, protocol: e.target.value as Node["protocol"], snellVersion: e.target.value === "snell" ? 6 : 0, password: "", shadowTlsHost: "", shadowTlsPassword: "" })}
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
                        value={templateForm.port || ""}
                        onChange={(e) => setTemplateForm({ ...templateForm, port: Number(e.target.value) })}
                      />
                      <button className="iconButton" type="button" title="随机端口（50000–60000）" aria-label="随机端口（50000–60000）" onClick={() => setTemplateForm({ ...templateForm, port: generatePort(new Set([templateForm.port || 0])) })}><Icon name="dice" /></button>
                    </div>
                  </Field>
                  <Field label="监听地址">
                    <input
                      value={templateForm.listen || ""}
                      onChange={(e) => setTemplateForm({ ...templateForm, listen: e.target.value })}
                    />
                  </Field>
                  {templateForm.protocol === "socks5" && <Field label="SOCKS5 用户名 *"><input required autoComplete="off" maxLength={255} value={templateForm.username || ""} onChange={(e) => setTemplateForm({ ...templateForm, username: e.target.value })} /></Field>}
                  {templateForm.protocol === "ss" && (
                    <Field label="加密方式">
                      <select
                        value={templateForm.method}
                        onChange={(e) => setTemplateForm({ ...templateForm, method: e.target.value, password: "" })}
                      >
                        {[
                          "2022-blake3-aes-128-gcm",
                          "2022-blake3-aes-256-gcm",
                          "2022-blake3-chacha20-poly1305",
                          "aes-128-gcm",
                          "aes-256-gcm",
                          "chacha20-ietf-poly1305",
                        ].map((v) => <option key={v}>{v}</option>)}
                      </select>
                    </Field>
                  )}
                  {templateForm.protocol === "snell" && (
                    <>
                      <Field label="Snell 版本">
                        <select value={templateForm.snellVersion || 5} onChange={(e) => setTemplateForm({ ...templateForm, snellVersion: Number(e.target.value), obfs: "none" })}>
                          <option value={6}>v6</option><option value={5}>v5</option>
                        </select>
                        {(templateForm.snellVersion || 5) === 6 && <small>PSK 需要 12–255 字节；使用默认流量整形，不使用 HTTP 混淆。</small>}
                      </Field>
                      <Field label="Snell 内层端口 *">
                        <input required type="number" min={1} max={65535} value={templateForm.snellPort || ""} onChange={(e) => setTemplateForm({ ...templateForm, snellPort: Number(e.target.value) })} />
                        <small>仅监听 127.0.0.1；同一服务器上的节点不能共用。</small>
                      </Field>
                      {(templateForm.snellVersion || 5) === 5 && <Field label="混淆模式">
                        <select value={templateForm.obfs || "none"} onChange={(e) => setTemplateForm({ ...templateForm, obfs: e.target.value })}>
                          <option value="none">无</option>
                          <option value="http">HTTP</option>
                        </select>
                      </Field>}
                      <Field label="ShadowTLS v3 SNI / 握手域名 *">
                        <input required placeholder="例如 www.example.com（TLS 站点）" value={templateForm.shadowTlsHost || ""} onChange={(e) => setTemplateForm({ ...templateForm, shadowTlsHost: e.target.value })} />
                      </Field>
                      <Field label="ShadowTLS v3 密码（留空时节点单独生成）">
                        <SecretField value={templateForm.shadowTlsPassword || ""} onChange={(v) => setTemplateForm({ ...templateForm, shadowTlsPassword: v })} action={<button className="iconButton" type="button" title="生成 ShadowTLS 密码" aria-label="生成 ShadowTLS 密码" onClick={() => setTemplateForm({ ...templateForm, shadowTlsPassword: generatePassword("snell") })}><Icon name="generate" /></button>} />
                      </Field>
                    </>
                  )}
                  {templateForm.protocol === "anytls" && (
                    <Field label="TLS 域名 *">
                      <input
                        required
                        value={templateForm.tlsName || ""}
                        onChange={(e) => setTemplateForm({ ...templateForm, tlsName: e.target.value })}
                      />
                    </Field>
                  )}
                  <Field label="密码 / PSK（留空时节点单独生成）">
                    <SecretField value={templateForm.password || ""} onChange={(v) => setTemplateForm({ ...templateForm, password: v })} action={<button className="iconButton" type="button" title="生成密码 / PSK" aria-label="生成密码 / PSK" onClick={() => setTemplateForm({ ...templateForm, password: generatePassword(templateForm.protocol || "ss", templateForm.method) })}><Icon name="generate" /></button>} />
                  </Field>
                </div>
                <p className="hint">SS 2022 密钥按加密方式生成 16 或 32 字节的 Base64。模板密码会加密保存，使用模板创建的节点共享该密码；留空则每个节点独立生成。Snell 的 ShadowTLS 域名应是服务器可访问的真实 TLS 站点（443 端口），ShadowTLS 密码与 Snell PSK 分开。AnyTLS 会按 TLS 域名从统一证书库匹配证书。</p>
                <SubmitButton busy={busy} label="保存模板" />
              </form>
  </Dialog>;
}
