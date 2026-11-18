import { useEffect, useState } from "react";
import { api, mutation, type RelayOverride, type RelayStatus } from "../api";
import { useApp } from "../app/context";
import { relayAutoDescription, relayStatsDescription, relayStatusLabels } from "../app/relayHealth";
import { Field, SubmitButton, useBusy } from "../app/ui";
import { Dialog } from "./Dialog";

const hoursByDuration = { "1": 1, "6": 6, "24": 24, "168": 168 } as const;
type Duration = keyof typeof hoursByDuration | "forever" | "unchanged";
type Draft = { state: RelayStatus | ""; duration: Duration; note: string };

export default function RelayOverrideDialog({ from = "", to, routeId, onClose }: {
  from?: string; to: string; routeId?: string; onClose?: () => void;
}) {
  const { act, closeModal, nodes, routes, serverName } = useApp();
  const [draft, setDraft] = useState<Draft | null>(null);
  const [loaded, setLoaded] = useState<{ current?: RelayOverride; inherited?: RelayOverride; initial: Draft } | null>(null);
  const [loadError, setLoadError] = useState("");
  const [attempt, setAttempt] = useState(0);
  const { busy, run } = useBusy();
  const close = onClose ?? closeModal;

  useEffect(() => {
    let currentRequest = true;
    api<RelayOverride[]>("/api/relay-overrides").then((items) => {
      if (!currentRequest) return;
      const current = items.find((item) => item.toServerId === to && item.fromServerId === from);
      const inherited = from ? items.find((item) => item.toServerId === to && !item.fromServerId) : undefined;
      const initial: Draft = { state: current?.state || "", duration: current?.until ? "unchanged" : "forever", note: current?.note || "" };
      setLoaded({ current, inherited, initial });
      setDraft(initial);
    }).catch((e: Error) => { if (currentRequest) setLoadError(e.message); });
    return () => { currentRequest = false; };
  }, [from, to, attempt]);

  const affected = routes.filter((route) => {
    if (!route.enabled) return false;
    const landing = nodes.find((node) => node.id === route.nodeId)?.serverId;
    const groups = [[route.entryServerId], ...route.hops.map((hop) => hop.serverIds), landing ? [landing] : []];
    return groups.some((group, i) => i > 0 && group.includes(to) && (!from || groups[i - 1].includes(from)));
  }).length;

  const report = routes.find((route) => route.id === routeId)?.relayEdges
    ?.find((edge) => edge.fromServerId === from && edge.toServerId === to)?.reported;
  const serverOverride = loaded?.inherited;

  const save = (e: React.FormEvent) => {
    e.preventDefault();
    if (!draft || !loaded) return;
    void run(async () => {
      if (!draft.state) {
        const query = new URLSearchParams({ from, to });
        if (await act(() => mutation("/api/relay-overrides?" + query, "DELETE"), "已清除手动覆盖")) close();
        return;
      }
      let until = loaded.current?.until;
      if (draft.duration === "forever") until = undefined;
      else if (draft.duration !== "unchanged") until = new Date(Date.now() + hoursByDuration[draft.duration] * 3600000).toISOString();
      if (await act(() => mutation("/api/relay-overrides", "PUT", { fromServerId: from, toServerId: to, state: draft.state, until, note: draft.note }), "中转状态已保存")) close();
    });
  };

  return <Dialog title={from ? "线路状态" : "作为中转"} value={draft} initial={loaded?.initial ?? null} busy={busy} onClose={close}>
    <div className="relayDialogSummary">
      <p>{from ? `${serverName(from)} → ${serverName(to)}` : serverName(to)} · {affected} 条启用链路</p>
      {from && <>
        <p>服务器级设置：{loaded ? serverOverride ? `${relayStatusLabels[serverOverride.state]} · ${serverOverride.until ? `至 ${new Date(serverOverride.until).toLocaleString()}` : "永久"}` : "自动" : "读取中"}</p>
        {serverOverride?.note && <p>备注：{serverOverride.note}</p>}
        <p>最近自动判断：{report ? `${relayAutoDescription(report)} · 自 ${new Date(report.autoSince || report.since).toLocaleString()}` : "暂无上报"}</p>
        {report?.stats && <p>{relayStatsDescription(report)}</p>}
      </>}
    </div>
    {!loaded || !draft ? loadError ? <div role="alert">
      <p className="bad">{loadError}</p>
      <button type="button" className="ghost" onClick={() => { setLoadError(""); setAttempt(attempt + 1); }}>重试</button>
    </div> : <p role="status" className="hint">正在读取手动状态…</p> : <form onSubmit={save}>
      <div className="formGrid">
        <Field label="状态">
          <select value={draft.state} onChange={(e) => setDraft({ ...draft, state: e.target.value as Draft["state"] })}>
            <option value="">{loaded.inherited ? "清除线路覆盖，跟随服务器" : "恢复自动"}</option>
            <option value="normal">设为正常</option>
            <option value="degraded">设为降级</option>
            <option value="down">设为故障</option>
          </select>
        </Field>
        {draft.state && <>
          <Field label="时长">
            <select value={draft.duration} onChange={(e) => setDraft({ ...draft, duration: e.target.value as Duration })}>
              {loaded.current?.until && <option value="unchanged">保持到期时间 ({new Date(loaded.current.until).toLocaleString()})</option>}
              <option value="1">1 小时</option><option value="6">6 小时</option><option value="24">24 小时</option><option value="168">7 天</option><option value="forever">永久</option>
            </select>
          </Field>
          <Field label="备注"><input value={draft.note} maxLength={200} onChange={(e) => setDraft({ ...draft, note: e.target.value })} /></Field>
        </>}
      </div>
      <p className="hint">{from ? "线路设置优先于服务器设置。" : "单独设置过的线路优先。"} 需要上一跳运行 Agent 0.6.32 或更新版本。离线管理的上一跳无法即时应用。</p>
      <SubmitButton busy={busy} disabled={!draft.state && !loaded.current} label={draft.state ? "保存" : "清除手动设置"} />
    </form>}
  </Dialog>;
}
