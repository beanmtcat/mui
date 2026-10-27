import { useEffect, useState } from "react";
import { bytes } from "../api";
import { screenshotView } from "./screenshot";

const fileNames = ["mui-agent", "SHA256SUMS", "SHA256SUMS.sig"] as const;
type FileName = typeof fileNames[number];
type FileState = { available: boolean; message: string; size?: number };
const descriptions: Record<FileName, string> = {
  "mui-agent": "Linux Agent 程序，入口 / 中转不需要 sing-box",
  SHA256SUMS: "文件摘要，必须与程序一起下载",
  "SHA256SUMS.sig": "发布签名，启用签名校验时需要",
};

export default function AgentDownloads({ initialArch = "amd64", releaseVersion = "", releaseBuilds = {}, onClose, onCopy, screenshotMode, redact }: {
  initialArch?: string; onClose: () => void; onCopy: (value: string) => void;
  releaseVersion?: string; releaseBuilds?: Record<string, string>;
  screenshotMode: boolean; redact: (value: string) => string;
}) {
  const [arch, setArch] = useState(initialArch === "arm64" ? "arm64" : "amd64");
  const [files, setFiles] = useState<Partial<Record<FileName, FileState>>>({});
  const [checkedArch, setCheckedArch] = useState("");
  const [attempt, setAttempt] = useState(0);
  // Check only when this dialog opens, the architecture changes, or the user
  // retries. HEAD does not transfer the large binary and needs no enrollment.
  useEffect(() => {
    if (releaseVersion) return;
    const controller = new AbortController();
    let disposed = false;
    const timeout = setTimeout(() => controller.abort(), 15000);
    setCheckedArch("");
    void Promise.all(fileNames.map(async (name): Promise<[FileName, FileState]> => {
      try {
        const res = await fetch(`/download/${arch}/${name}`, { method: "HEAD", credentials: "same-origin", cache: "no-store", signal: controller.signal });
        if (!res.ok) return [name, { available: false, message: res.status === 404 ? "未发布" : res.status === 429 ? "请求过于频繁，请稍后重试" : `暂不可用（HTTP ${res.status}）` }];
        if (res.headers.get("Content-Type")?.includes("text/html")) return [name, { available: false, message: "下载路径未正确转发到后端" }];
        const size = Number(res.headers.get("Content-Length"));
        return [name, { available: true, message: "可下载", size: Number.isFinite(size) && size > 0 ? size : undefined }];
      } catch {
        return [name, { available: false, message: controller.signal.aborted ? "检查超时，请重试" : "检查失败，请重试" }];
      }
    })).then((entries) => {
      clearTimeout(timeout);
      if (!disposed) { setFiles(Object.fromEntries(entries)); setCheckedArch(arch); }
    });
    return () => { disposed = true; clearTimeout(timeout); controller.abort(); };
  }, [arch, attempt, releaseVersion]);
  const loading = !releaseVersion && checkedArch !== arch;
  const ready = releaseVersion ? true : !loading && !!files["mui-agent"]?.available && !!files.SHA256SUMS?.available;
  const downloadDir = `mui-install-${arch}`;
  const archiveName = `mui-agent-${releaseVersion}-linux-${arch}.tar.gz`;
  const archiveURL = `https://github.com/beanmtcat/mui/releases/download/v${releaseVersion}/${archiveName}`;
  const command = releaseVersion
    ? `(\nset -eu\nmkdir -p '${downloadDir}'\ncurl -fL --retry 3 --connect-timeout 15 '${archiveURL}' -o '${downloadDir}/${archiveName}'\ntar -xzf '${downloadDir}/${archiveName}' -C '${downloadDir}' --strip-components=1 '${arch}/mui-agent' '${arch}/SHA256SUMS' '${arch}/SHA256SUMS.sig'\n)`
    : `(\nset -eu\nmkdir -p '${downloadDir}'\n${fileNames.filter((name) => files[name]?.available).map((name) => `curl -fL --retry 3 --connect-timeout 15 '${location.origin}/download/${arch}/${name}' -o '${downloadDir}/${name}'`).join("\n")}\n)`;
  const view = <div className="overlay" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }} onKeyDown={(e) => { if (e.key === "Escape") { e.stopPropagation(); onClose(); } }}>
    <div className="modal installModal" role="dialog" aria-modal="true" aria-labelledby="agent-download-title">
      <div className="modalHead"><h2 id="agent-download-title">下载 Agent</h2><button className="closeButton" aria-label="关闭" onClick={onClose}>×</button></div>
      <div className="offlineInstall">
        <p className="hint">在可联网的电脑下载后，上传到目标机的 ~/mui-install/。请选择目标服务器的架构，与当前电脑的架构无关。</p>
        <label className="field">目标服务器架构
          <select value={arch} onChange={(e) => setArch(e.target.value)}>
            <option value="amd64">amd64（x86_64 / Intel / AMD）</option>
            <option value="arm64">arm64（aarch64 / ARM）</option>
          </select>
        </label>
        <p className="hint">在目标机执行 <code>uname -m</code> 可以确认架构。</p>
        <div className="agentDownloadList" aria-live="polite">
          {releaseVersion ? <div className="agentDownloadRow">
            <div><strong>{archiveName}</strong><small>GitHub Release 归档，包含 Agent、sing-box、摘要和签名</small></div>
            <a href={archiveURL} target="_blank" rel="noreferrer">从 GitHub 下载</a>
          </div> : fileNames.map((name) => <div className="agentDownloadRow" key={name}>
            <div><strong>{name}</strong><small>{descriptions[name]}</small></div>
            {loading ? <span className="hint">检查中…</span> : files[name]?.available ? <a href={`/download/${arch}/${name}`} download={name}>下载{files[name]?.size ? `（${bytes(files[name]!.size!)}）` : ""}</a> : <span className="hint">{files[name]?.message || "不可用"}</span>}
          </div>)}
        </div>
        {!loading && !ready && <p className="hint">该架构的发布文件暂不可用，请确认 GitHub Release 归档已发布且摘要、签名有效。</p>}
        {!!releaseVersion && !releaseBuilds[arch] && <p className="hint">面板尚未验证该架构的 GitHub 归档：{releaseBuilds[arch + "Error"] || "请确认文件已发布"}。下载后仍需核对摘要与签名。</p>}
        {!releaseVersion && !loading && ready && !files["SHA256SUMS.sig"]?.available && <p className="hint">签名文件未提供。已固定发布公钥的目标机需要有效签名文件才能安装或升级。</p>}
        <div className="headerActions">
          <button className="primary" disabled={!ready} onClick={() => onCopy(command)}>复制本机下载命令</button>
          <button className="ghost" disabled={loading} onClick={() => setAttempt((n) => n + 1)}>重新检查</button>
        </div>
        <p className="hint">下载命令用于联网的 macOS / Linux 电脑。离线服务器的安装命令请在“离线配置”中获取；在线服务器请使用“首次接入 / 手动修复”。</p>
      </div>
    </div>
  </div>;
  return screenshotMode ? screenshotView(view, redact, new Set()) : view;
}
