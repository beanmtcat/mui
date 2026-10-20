import { useEffect, useRef, useState } from "react";
import { MemoSecretTextarea } from "./secrets";

export default function CertificateFileField({ kind, value, onChange, onBusy }: {
  kind: "certificate" | "key"; value: string; onChange: (value: string) => void; onBusy: (busy: boolean) => void;
}) {
  const key = kind === "key";
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const request = useRef(0);
  useEffect(() => () => { request.current++; }, []);
  const choose = async (file?: File) => {
    const current = ++request.current;
    setError(""); onChange("");
    if (!file) { setBusy(false); onBusy(false); return; }
    if (file.size > 512 * 1024) { setError("文件不能超过 512 KiB"); setBusy(false); onBusy(false); return; }
    setBusy(true); onBusy(true);
    try {
      const text = (await file.text()).replace(/^\uFEFF/, "").trim();
      if (current !== request.current) return;
      if (key && /-----BEGIN ENCRYPTED PRIVATE KEY-----|Proc-Type:\s*4,ENCRYPTED/.test(text)) throw new Error("请选择未加密的 PEM 私钥；当前 Agent 无法交互输入私钥口令。");
      if (!(key ? /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/ : /-----BEGIN CERTIFICATE-----/).test(text)) {
        throw new Error(key ? "文件中没有 PEM 私钥，请选择 ssl_certificate_key 对应的 .key 文件。" : "文件中没有 PEM 证书，请选择 ssl_certificate 对应的 .pem / .crt 文件。");
      }
      onChange(text + "\n");
    } catch (e) {
      if (current === request.current) setError((e as Error).message || "读取文件失败，请重新选择。");
    } finally {
      if (current === request.current) { setBusy(false); onBusy(false); }
    }
  };
  const paste = (text: string) => { request.current++; setBusy(false); onBusy(false); setError(""); onChange(text); };
  return <div className="certificateFileField">
    <label>
      <span>{key ? "私钥文件（.key）*" : "证书文件（.pem / .crt）*"}</span>
      <input type="file" aria-label={key ? "私钥文件" : "证书文件"} accept={key ? ".key,.pem,text/plain,application/x-pem-file" : ".pem,.crt,.cer,text/plain,application/x-pem-file"} onChange={(e) => void choose(e.target.files?.[0])} />
    </label>
    <p className="hint">{key ? <>对应 Nginx 的 <code>ssl_certificate_key</code>。支持 RSA PKCS#1、PKCS#8 和 EC 私钥。</> : <>对应 Nginx 的 <code>ssl_certificate</code>。一个 PEM 可包含证书和中间证书链，保持服务器证书在最前。</>}</p>
    {busy && <p className="hint" role="status">正在读取文件…</p>}
    {!busy && value && !error && <p className="certificateFileReady" role="status">{key ? "私钥已读取，内容默认隐藏" : "证书内容已读取"}</p>}
    {error && <p className="dangerText" role="alert">{error}</p>}
    <details>
      <summary>{key ? "或粘贴私钥内容" : "或粘贴证书内容"}</summary>
      {key ? <MemoSecretTextarea rows={5} value={value} onChange={paste} /> : <textarea aria-label="证书 PEM 内容" rows={5} value={value} onChange={(e) => paste(e.target.value)} />}
    </details>
  </div>;
}
