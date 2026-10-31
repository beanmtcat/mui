import { useState } from "react";
import { mutation } from "../api";
import { useApp } from "../app/context";
import { setError } from "../app/feedback";
import type { CertificateForm } from "../app/helpers";
import { Field, SubmitButton, useBusy } from "../app/ui";
import CertificateFileField from "../components/CertificateFileField";
import { Dialog } from "./Dialog";

export default function CertificateDialog({ initial }: { initial: CertificateForm }) {
  const { act, closeModal } = useApp();
  const [certForm, setCertForm] = useState(initial);
  const [certFilesBusy, setCertFilesBusy] = useState({ pem: false, key: false });
  const { busy, run } = useBusy();
  const submitCert = (e: React.FormEvent) => {
    e.preventDefault();
    const hasPem = !!certForm.pem?.trim();
    const hasKey = !!certForm.key?.trim();
    if ((!certForm.id && (!hasPem || !hasKey)) || hasPem !== hasKey) {
      setError(certForm.id ? "更换证书时，请同时选择证书和私钥文件。" : "请选择证书 .pem 和私钥 .key 文件，或粘贴对应的 PEM 内容。");
      return;
    }
    const payload = { name: certForm.name || "", domain: certForm.domain || "", pem: certForm.pem || "", key: certForm.key || "" };
    void run(async () => {
      if (await act(
        () => mutation("/api/certificates" + (certForm.id ? "/" + certForm.id : ""), certForm.id ? "PATCH" : "POST", payload),
        certForm.id ? hasPem ? "证书已更新，相关在线服务器已排队应用" : "证书信息已更新" : "证书已添加",
      )) closeModal();
    });
  };
  return <Dialog title={certForm.id ? "编辑证书" : "上传证书"} value={certForm} initial={initial} busy={busy}>
              <form className="certificateForm" onSubmit={submitCert}>
                <p className="hint">{certForm.id ? "更换证书时请同时选择新的证书和私钥；只修改名称或域名时，文件留空即可保留原证书。保存后，使用该证书的在线服务器会自动应用新证书，期间节点显示为待应用。" : "和 Nginx 一样，选择证书文件和对应私钥文件即可，无需转换格式或选择服务器。"}</p>
                <CertificateFileField key={certForm.id ? certForm.id + "-pem" : "new-pem"} kind="certificate" required={!certForm.id} value={certForm.pem || ""} onChange={(pem) => setCertForm((f) => ({ ...f, pem }))} onBusy={(busy) => setCertFilesBusy((s) => ({ ...s, pem: busy }))} />
                <CertificateFileField key={certForm.id ? certForm.id + "-key" : "new-key"} kind="key" required={!certForm.id} value={certForm.key || ""} onChange={(key) => setCertForm((f) => ({ ...f, key }))} onBusy={(busy) => setCertFilesBusy((s) => ({ ...s, key: busy }))} />
                <div className="formGrid">
                  <Field label="名称">
                    <input
                      value={certForm.name || ""}
                      onChange={(e) =>
                        setCertForm({ ...certForm, name: e.target.value })
                      }
                    />
                  </Field>
                  <Field label="域名（留空从证书读取）">
                    <input
                      value={certForm.domain || ""}
                      onChange={(e) =>
                        setCertForm({ ...certForm, domain: e.target.value })
                      }
                    />
                  </Field>
                </div>
                <p className="hint">证书可供多台服务器复用。更新证书会重新应用相关服务器配置，连接可能短暂中断；新证书须覆盖所有引用节点的 TLS 域名。</p>
                <SubmitButton busy={busy} label={certFilesBusy.pem || certFilesBusy.key ? "正在读取文件…" : "保存证书"} disabled={certFilesBusy.pem || certFilesBusy.key || (!certForm.id && (!certForm.pem?.trim() || !certForm.key?.trim())) || (!!certForm.pem?.trim() !== !!certForm.key?.trim())} />
              </form>
  </Dialog>;
}
