import { screenshotView } from "./screenshot";
import { useState } from "react";
import { mutation, type Server, type OfflineInstallGuide } from "../api";
import ManagementMigration from "./ManagementMigration";

type Exported = {
  bundle: { revision: number; serverId: string; [key: string]: unknown };
  install: OfflineInstallGuide;
};

function downloadJSON(value: unknown) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2) + "\n"], { type: "application/json" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = "mui-offline.json";
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export default function OfflineManager({ server, onClose, onExported, onCopy, onDownloadAgent, screenshotMode, redact }: {
  server: Server; onClose: () => void; onExported: () => Promise<void>;
  onCopy: (value: string) => void; onDownloadAgent: () => void; screenshotMode: boolean; redact: (value: string) => string;
}) {
  const [exported, setExported] = useState<Exported | null>(null);
  const [arch, setArch] = useState("amd64");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const run = async (fn: () => Promise<void>) => {
    setBusy(true); setError(""); setNotice("");
    try { await fn(); } catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  };
  const files = exported?.install.downloads.find((d) => d.arch === arch);
  const view = <div className="overlay" onMouseDown={(e) => { if (e.target === e.currentTarget && !busy) onClose(); }} onKeyDown={(e) => { if (e.key === "Escape" && !busy) onClose(); }}>
    <div className="modal installModal offlineManager" role="dialog" aria-modal="true" aria-labelledby="offline-manager-title">
      <div className="modalHead"><h2 id="offline-manager-title">离线配置 · {server.name}</h2><button className="closeButton" aria-label="关闭" disabled={busy} onClick={onClose}>×</button></div>
      <div className="offlineInstall">
      <p className="hint">先在面板保存链路或端口转发，再导出这台服务器的完整配置。配置只包含本机转发，无需连接面板，也不安装 sing-box。防火墙端口、来源限制需要自行配置；TCP + UDP 转发需 Agent 0.6.7 或更高版本。</p>
      {error && <div className="banner error" role="alert">{error}</div>}
      {notice && <div className="banner success" role="status">{notice}</div>}
      <section className="offlineStep">
        <h3>1. 导出配置</h3>
        <p className="hint">每次修改链路或转发后，都需要重新导出并在目标机应用。导出后相关链路可进入订阅；面板无法确认目标机是否已应用或连通。请妥善保管签名配置文件。</p>
        <button className="primary" disabled={busy} onClick={() => void run(async () => {
          const v = await mutation<Exported>(`/api/servers/${server.id}/offline/export`, "POST");
          setExported(v); downloadJSON(v.bundle); await onExported();
          setNotice(`已导出版本 ${v.bundle.revision}，保存为 mui-offline.json。`);
        })}>导出并下载配置</button>
        {exported && <button className="ghost" disabled={busy} onClick={() => downloadJSON(exported.bundle)}>重新下载版本 {exported.bundle.revision}</button>}
      </section>
      {!exported && <section className="offlineStep"><h3>2. 上传并应用</h3><p className="hint">导出配置后，这里会显示二进制下载链接和目标机安装、更新命令。</p><button className="ghost" onClick={onDownloadAgent}>下载 Agent（无需先导出配置）</button></section>}
      {exported && <section className="offlineStep">
        <h3>2. 上传并应用</h3>
        <p className="hint">首次安装或升级：在可联网的电脑下载以下文件，连同 mui-offline.json 上传到目标机的 ~/mui-install/。按目标机架构选择；x86_64 选 amd64，aarch64 选 arm64。</p>
        <select aria-label="目标机架构" value={arch} onChange={(e) => setArch(e.target.value)}><option>amd64</option><option>arm64</option></select>
        <div className="installDownloads">{files?.files.map((f) => <a href={f.url} key={f.name} download={f.name}>{f.name}</a>)}</div>
        <ManagementMigration command={exported.install.migrationCommand} onCopy={onCopy} />
        <p className="hint">在目标机执行（自动识别 root / sudo）：</p>
        <pre className="installCommand">{exported.install.command}</pre>
        <button className="ghost" onClick={() => onCopy(exported.install.command)}>复制安装命令</button>
        <p className="hint">已经安装时，只需上传新配置并以 root 执行：</p>
        <pre className="installCommand">mui-agent offline apply ~/mui-install/mui-offline.json</pre>
        <p className="hint">本地命令会等待转发进程确认加载，失败时恢复原配置。执行成功后即可使用，无需向面板回传文件；请自行检查端口和链路连通性。</p>
      </section>}
      </div>
    </div>
  </div>;
  return screenshotMode ? screenshotView(view, redact, new Set()) : view;
}
