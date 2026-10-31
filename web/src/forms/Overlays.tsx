import { lazy, Suspense, useEffect, useState } from "react";
import { api, bytes } from "../api";
import { useApp } from "../app/context";
import { setError } from "../app/feedback";
import type { TrafficPoint } from "../app/helpers";
import { Empty, Field, ModalShell } from "../app/ui";
import ManagementMigration from "../components/ManagementMigration";
import { MemoMaskedValue as MaskedValue } from "../components/secrets";

const TrafficChart = lazy(() => import("../components/TrafficChart"));
const chart = (points: TrafficPoint[]) => points.length
  ? <Suspense fallback={<div className="trafficChart"><Empty text="正在加载图表…" /></div>}><TrafficChart points={points} /></Suspense>
  : <div className="trafficChart"><Empty text="暂无流量样本" /></div>;

export function InstallDialog() {
  const { installInfo, setInstallInfo, installMethod, setInstallMethod, installArch, setInstallArch, copy, setConfirmation, protect } = useApp();
  if (!installInfo) return null;
  const localInstallGuide = installMethod === "standalone" ? installInfo.standaloneInstall : installInfo.offlineInstall;
  return protect(<ModalShell title="首次接入 / 手动修复" labelledBy="install-modal-title" dirty={false} wide onClose={() => setInstallInfo(null)} onConfirm={setConfirmation}>
            <div className="installMethods" role="group" aria-label="安装方式">
              <button type="button" aria-pressed={installMethod === "online"} onClick={() => setInstallMethod("online")}>在线安装</button>
              <button type="button" disabled={!installInfo.offlineInstall} title={!installInfo.offlineInstall ? "请更新后端后重新生成接入命令" : ""} aria-pressed={installMethod === "offline"} onClick={() => setInstallMethod("offline")}>手工安装</button>
              <button type="button" disabled={!installInfo.standaloneInstall} title={!installInfo.standaloneInstall ? "请更新后端后重新生成接入命令" : ""} aria-pressed={installMethod === "standalone"} onClick={() => setInstallMethod("standalone")}>完全离线转发</button>
            </div>
            {installMethod !== "standalone" && installInfo.offlineInstall?.proxyNotice && <p className="hint commandBox">{installInfo.offlineInstall.proxyNotice}</p>}
            {installMethod !== "standalone" && <ManagementMigration command={installInfo.offlineInstall?.migrationCommand} onCopy={(v) => void copy(v)} />}
            {installMethod === "online" ? <div className="commandBox">
              <strong>在「{installInfo.serverName}」服务器上运行以下命令</strong>
              <p className="hint">命令 10 分钟内有效。运行后会从面板下载并校验文件、接入 Agent；修复时 Agent 会重启，运行中的 sing-box 也可能重启。</p>
              <MaskedValue value={installInfo.installCommand} pre><button className="primary" autoFocus type="button" onClick={() => copy(installInfo.installCommand)}>复制命令</button></MaskedValue>
            </div> : <div className="offlineInstall">
              <p className="hint">{installMethod === "standalone" ? "完全离线转发使用 Agent 0.6.7 的本地模式，无需接入令牌和面板连接，仅安装 mui-forward 服务。此标签用于独立手写配置。需要面板编排链路和订阅时，请将服务器设为“离线管理”，使用列表中的“离线配置”。" : `先在本机下载，再上传到「${installInfo.serverName}」。目标机不下载二进制，但仍需访问面板完成接入和心跳。`}</p>
              <section className="installStep">
                <h3>1. 在本机下载文件</h3>
                <Field label="目标服务器架构">
                  <select value={installArch} onChange={(e) => setInstallArch(e.target.value)}>
                    <option value="amd64">amd64（x86_64 / Intel / AMD）</option>
                    <option value="arm64">arm64（aarch64 / ARM）</option>
                  </select>
                </Field>
                <p className="hint">按目标服务器选择，和本机架构无关。可在目标机执行 <code>uname -m</code> 确认。</p>
                <div className="installDownloads">
                  {localInstallGuide?.downloads.find((d) => d.arch === installArch)?.files.map((file) => <a key={file.name} href={file.url} download={file.name}>{file.name}</a>)}
                </div>
                <button className="ghost" type="button" onClick={() => copy(localInstallGuide!.downloads.find((d) => d.arch === installArch)!.command)}>复制本机下载命令（macOS / Linux）</button>
                <p className="hint">本机下载命令统一保存到 <code>~/mui-install/</code>。</p>
              </section>
              <section className="installStep">
                <h3>2. 上传到目标服务器{installMethod === "standalone" ? "并配置转发" : ""}</h3>
                <p className="hint">通过 SFTP / SCP 将以上文件上传到目标机的 <code>~/mui-install/</code>，全部放在同一目录并保留原文件名。{installMethod === "standalone" ? "离线转发不需要 sing-box，也不操作 UFW。" : "落地服务器包含 sing-box，其他类型只安装 Agent。"}</p>
                <button className="ghost" type="button" onClick={() => copy("mkdir -p ~/mui-install")}>复制目标机建目录命令</button>
                {installMethod === "standalone" && <>
                  <p className="hint">将下面 JSON 保存为 <code>~/mui-install/forwards.json</code>，把 <code>10.0.0.2</code> 改为入口机能访问的下一跳地址，并调整端口。示例使用一条规则同时转发 TCP 和 UDP。</p>
                  <div className="commandBox">
                    <pre>{localInstallGuide?.exampleConfig}</pre>
                    <button className="ghost" type="button" onClick={() => copy(localInstallGuide?.exampleConfig || "")}>复制转发配置示例</button>
                  </div>
                </>}
              </section>
              <section className="installStep">
                <h3>3. 在目标服务器安装</h3>
                <p className="hint">用上传文件的同一用户执行，自动识别 root / sudo。{localInstallGuide?.signed ? "校验摘要及发布签名后安装服务" : "校验摘要后安装服务（面板未配置发布签名）"}；{installMethod === "standalone" ? "重复安装会重启转发服务，现有连接会中断。修改规则请用 offline apply 命令。" : "修复会重启 Agent，运行中的 sing-box 也可能重启。"}</p>
                {installMethod !== "standalone" && <p className="hint">接入令牌 10 分钟有效，且只能使用一次；每次重新打开“首次接入 / 手动修复”都会使旧命令立即失效。若已过期，请关闭后重新生成命令；同一发布版本的文件无需重复下载。</p>}
                <div className="commandBox">
                  <MaskedValue value={localInstallGuide?.command || ""} pre><button className="primary" type="button" onClick={() => copy(localInstallGuide!.command)}>{installMethod === "standalone" ? "复制离线安装命令" : "复制手工安装命令"}</button></MaskedValue>
                </div>
                {installMethod === "standalone" && <p className="hint">之后修改配置：<code>mui-agent offline apply ~/mui-install/forwards.json</code>。首次安装和应用以 root 执行；端口放行与下一跳来源白名单需自行配置。</p>}
              </section>
            </div>}
  </ModalShell>);
}

export function NodeTraffic() {
  const { trafficNode, setTrafficNode, setConfirmation, protect } = useApp();
  const [traffic, setTraffic] = useState<TrafficPoint[]>([]);
  useEffect(() => {
    if (!trafficNode) return;
    api<TrafficPoint[]>("/api/traffic/series?hours=24&nodeId=" + trafficNode.id).then(setTraffic).catch((e) => setError(e.message));
  }, [trafficNode?.id]);
  if (!trafficNode) return null;
  return protect(<ModalShell title={`${trafficNode.name} · 流量`} labelledBy="node-traffic-title" dirty={false} onClose={() => setTrafficNode(null)} onConfirm={setConfirmation}>
    <div className="trafficTotals">
      <div>累计上行<strong>{bytes(trafficNode.uplink)}</strong></div>
      <div>累计下行<strong>{bytes(trafficNode.downlink)}</strong></div>
    </div>
    {chart(traffic)}
  </ModalShell>);
}

export function SubscriptionTraffic() {
  const { trafficSub, setTrafficSub, setConfirmation, sharedSubNodes, protect } = useApp();
  const [traffic, setTraffic] = useState<TrafficPoint[]>([]);
  useEffect(() => {
    if (!trafficSub) return;
    setTraffic([]);
    api<TrafficPoint[]>("/api/subscriptions/" + trafficSub.id + "/traffic/series?hours=24").then(setTraffic).catch((e) => setError(e.message));
  }, [trafficSub?.id]);
  if (!trafficSub) return null;
  return protect(<ModalShell title={`${trafficSub.name} · 订阅流量`} labelledBy="sub-traffic-title" dirty={false} onClose={() => setTrafficSub(null)} onConfirm={setConfirmation}>
    {sharedSubNodes(trafficSub).length > 0 && <p className="hint">共享凭据节点无法按订阅统计，以下数据只包含独立凭据节点。共享节点总流量请在节点列表查看。</p>}
    <div className="trafficTotals">
      <div>累计上行<strong>{bytes(trafficSub.uplink || 0)}</strong></div>
      <div>累计下行<strong>{bytes(trafficSub.downlink || 0)}</strong></div>
    </div>
    {chart(traffic)}
  </ModalShell>);
}

// Progress and the outcome of a batch action, row by row where it matters.
export function BatchDialog() {
  const { batch, setBatch, setConfirmation, protect } = useApp();
  if (!batch) return null;
  const succeeded = batch.done - batch.failures.length;
  return protect(<ModalShell title={batch.title} labelledBy="batch-title" dirty={false} busy={!batch.finished} onClose={() => setBatch(null)} onConfirm={setConfirmation}>
    <div className="batchResult" role="status">
      <progress max={batch.total} value={batch.done} />
      <p>{batch.finished ? `已完成：成功 ${succeeded} 项${batch.failures.length ? `，失败 ${batch.failures.length} 项` : ""}。任务已排队，Agent 执行进度见列表状态和操作记录。` : `正在提交 ${batch.done} / ${batch.total}…`}</p>
      {batch.failures.length > 0 && <ul className="batchFailures">{batch.failures.map((failure) => <li key={failure}>{failure}</li>)}</ul>}
      {batch.finished && <button className="primary" autoFocus onClick={() => setBatch(null)}>知道了</button>}
    </div>
  </ModalShell>);
}
