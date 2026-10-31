import { lazy, Suspense, useState } from "react";
import { mutation } from "../api";
import AgentDownloads from "../components/AgentDownloads";
import HelpPage from "../components/HelpPage";
import OfflineManager from "../components/OfflineManager";
import { AppContext } from "./context";
import { clearFeedback, setError, setNotice, useFeedback } from "./feedback";
import type { Tab } from "./helpers";
import { useAppState, type App as AppState } from "./state";
import { ConfirmDialog, Icon, type IconName } from "./ui";

type SubPage = "accesses" | "connections" | "audit";
type Entry = { id: Exclude<Tab, SubPage>; label: string; icon: IconName; children?: { id: Tab; label: string }[] };
// An entry with children opens its first page, and its pages are listed
// beneath it while one of them is showing.
const groups: { title: string; entries: Entry[] }[] = [
  { title: "", entries: [{ id: "dashboard", label: "总览", icon: "dashboard" }] },
  { title: "资源", entries: [
    { id: "servers", label: "服务器", icon: "servers" },
    { id: "nodes", label: "节点", icon: "nodes" },
    { id: "templates", label: "节点模板", icon: "templates" },
    { id: "certificates", label: "证书", icon: "certificates" },
    { id: "firewall", label: "防火墙", icon: "firewall" },
  ] },
  { title: "流量", entries: [
    { id: "routes", label: "链路", icon: "routes" },
    { id: "forwards", label: "端口转发", icon: "forwards" },
  ] },
  { title: "用户", entries: [
    { id: "subscriptions", label: "订阅", icon: "subscriptions" },
    { id: "customers", label: "客户端管理", icon: "customers", children: [
      { id: "customers", label: "客户" },
      { id: "accesses", label: "订阅访问记录" },
      { id: "connections", label: "节点连接 IP" },
    ] },
  ] },
  { title: "系统", entries: [
    { id: "operations", label: "操作记录", icon: "operations", children: [
      { id: "operations", label: "任务记录" },
      { id: "audit", label: "审计日志" },
    ] },
    { id: "settings", label: "设置", icon: "settings" },
    { id: "help", label: "帮助", icon: "help" },
  ] },
];
const entries = groups.flatMap((group) => group.entries);

const Dashboard = lazy(() => import("../pages/Dashboard"));
const Servers = lazy(() => import("../pages/Servers"));
const Nodes = lazy(() => import("../pages/Nodes"));
const Templates = lazy(() => import("../pages/Templates"));
const Certificates = lazy(() => import("../pages/Certificates"));
const Firewall = lazy(() => import("../pages/Firewall"));
const Routes = lazy(() => import("../pages/Routes"));
const Forwards = lazy(() => import("../pages/Forwards"));
const Subscriptions = lazy(() => import("../pages/Subscriptions"));
const Customers = lazy(() => import("../pages/Customers"));
const Settings = lazy(() => import("../pages/Settings"));
const Accesses = lazy(() => import("../pages/Logs").then((m) => ({ default: m.Accesses })));
const Connections = lazy(() => import("../pages/Logs").then((m) => ({ default: m.Connections })));
const Operations = lazy(() => import("../pages/Logs").then((m) => ({ default: m.Operations })));
const Audit = lazy(() => import("../pages/Logs").then((m) => ({ default: m.Audit })));
const Dialogs = lazy(() => import("../forms/Dialogs"));

function Page({ tab, onCopy }: { tab: Tab; onCopy: (value: string) => void }) {
  switch (tab) {
    case "dashboard": return <Dashboard />;
    case "servers": return <Servers />;
    case "nodes": return <Nodes />;
    case "templates": return <Templates />;
    case "certificates": return <Certificates />;
    case "firewall": return <Firewall />;
    case "routes": return <Routes />;
    case "forwards": return <Forwards />;
    case "subscriptions": return <Subscriptions />;
    case "customers": return <Customers />;
    case "accesses": return <Accesses />;
    case "connections": return <Connections />;
    case "operations": return <Operations />;
    case "audit": return <Audit />;
    case "help": return <HelpPage onCopy={onCopy} />;
    case "settings": return <Settings />;
  }
}

// Messages float over the page: they never push the table down. Inside an
// editing dialog an error shows there instead, next to the form.
function Toasts({ app }: { app: AppState }) {
  const { error, notice } = useFeedback();
  const inDialog = !!app.modal;
  return app.protect(<div className="toasts">
    {error && !inDialog && <div className="banner error" role="alert">
      <span>{error}</span>
      <button type="button" aria-label="关闭错误提示" onClick={() => setError("")}>×</button>
    </div>}
    {notice && !inDialog && <div className="banner success" role="status">
      <span>{notice}</span>
      <button type="button" aria-label="关闭操作提示" onClick={() => setNotice("")}>×</button>
    </div>}
  </div>);
}

function Login({ app }: { app: AppState }) {
  const { error } = useFeedback();
  const [password, setPassword] = useState(""), [code, setCode] = useState(""), [busy, setBusy] = useState(false);
  return (
    <div className="loginShell">
      <div className="loginCard">
        <h1>MUI 节点管理面板</h1>
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            if (busy) return;
            setBusy(true);
            clearFeedback();
            try {
              const result = await mutation<{ totpEnabled: boolean }>("/api/login", "POST", { password, code });
              app.setTotpEnabled(result.totpEnabled);
              app.setAuthed(true);
              await app.refresh();
            } catch (err) {
              setError((err as Error).message);
            } finally {
              setBusy(false);
            }
          }}
        >
          <label>
            管理员密码
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required autoFocus />
          </label>
          <label>
            动态验证码（未启用请留空）
            <input value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" maxLength={6} />
          </label>
          {error && <div className="error">{error}</div>}
          <button className="primary" type="submit" disabled={busy}>{busy ? "登录中…" : "登录"}</button>
        </form>
      </div>
    </div>
  );
}

export default function App() {
  const app = useAppState();
  const { tab, goTo, refresh, refreshing, screenshotMode, setScreenshotMode, theme, setTheme, expiring, unreadAttention, servers, confirmation, setConfirmation, offlineServer, setOfflineServer, agentDownloads, setAgentDownloads, agentReleases, copy, redactScreenshot, protect } = app;
  const [menuOpen, setMenuOpen] = useState(false);
  if (app.authed === null) return <div className="loading">正在加载面板…</div>;
  if (!app.authed) return <Login app={app} />;
  const pageTitle = entries.flatMap((t) => t.children || []).find((child) => child.id === tab)?.label || entries.find((t) => t.id === tab)?.label;
  const urgent = unreadAttention.filter((item) => item.tone !== "info").length;
  const open = (target: Tab) => { goTo(target); setMenuOpen(false); };
  return <AppContext.Provider value={app}>
    {protect(<div className="app">
      <aside className={"sidebar" + (menuOpen ? " menuOpen" : "")}>
        <div className="brand">MUI 节点管理面板</div>
        <button type="button" className="iconButton menuButton" aria-label="打开菜单" aria-expanded={menuOpen} onClick={() => setMenuOpen(!menuOpen)}><Icon name="menu" /></button>
        <nav>
          {groups.map((group) => <div className="navGroup" key={group.title}>
            {group.title && <div className="navTitle">{group.title}</div>}
            {group.entries.map((t) => {
              const expanded = !!t.children?.some((child) => child.id === tab);
              return <div key={t.id}>
                <button className={t.children ? (expanded ? "open" : "") : tab === t.id ? "active" : ""} aria-expanded={t.children ? expanded : undefined} onClick={() => open(t.id)}>
                  <Icon name={t.icon} />
                  {t.label}
                  {t.id === "dashboard" && urgent > 0 && <span className="navBadge" title={`${urgent} 项需要关注`}>{urgent}</span>}
                </button>
                {expanded && t.children!.map((child) => (
                  <button key={child.id} className={"child" + (tab === child.id ? " active" : "")} onClick={() => open(child.id)}>{child.label}</button>
                ))}
              </div>;
            })}
          </div>)}
        </nav>
        <div className="sideBottom">
          <button
            onClick={async () => {
              try {
                await mutation("/api/logout", "POST");
                app.setAuthed(false);
                clearFeedback();
              } catch (e) {
                setError((e as Error).message);
              }
            }}
          >
            <Icon name="logout" />
            退出登录
          </button>
        </div>
      </aside>
      <main>
        <header>
          <h1>{pageTitle}</h1>
          <div className="headerActions">
            <span className="headerRefreshStatus" role="status" aria-live="polite">{refreshing ? "刷新中…" : ""}</span>
            <button className={"iconButton" + (refreshing ? " refreshing" : "")} type="button" disabled={refreshing} aria-busy={refreshing} onClick={() => void refresh(true)} aria-label={refreshing ? "刷新中" : "刷新"} title={refreshing ? "刷新中…" : "刷新"}><Icon name="refresh" /></button>
            <button className="iconButton" type="button" aria-pressed={screenshotMode} onClick={() => { const enabled = !screenshotMode; setScreenshotMode(enabled); localStorage.setItem("mui-screenshot-mode", String(enabled)); }} title={screenshotMode ? "关闭截图脱敏" : "开启截图脱敏"} aria-label={screenshotMode ? "关闭截图脱敏" : "开启截图脱敏"}><Icon name="privacy" /></button>
            <button className="iconButton" type="button" onClick={() => setTheme(theme === "dark" ? "light" : "dark")} aria-label={theme === "dark" ? "切换浅色模式" : "切换深色模式"} title={theme === "dark" ? "切换浅色模式" : "切换深色模式"}><Icon name={theme === "dark" ? "sun" : "moon"} /></button>
          </div>
        </header>
        {screenshotMode && <div className="banner warning" role="status">截图脱敏已开启：名称、地址、凭据已隐藏，表单暂时只读。关闭后恢复显示。</div>}
        {expiring.length > 0 && <div className="banner warning">{expiring.length} 张 TLS 证书已过期或将在 30 天内到期，请尽快更新。</div>}
        <Suspense fallback={<div className="loading">正在加载…</div>}>
          <Page tab={tab} onCopy={(value) => void copy(value)} />
        </Suspense>
      </main>
      {offlineServer && <OfflineManager server={servers.find((s) => s.id === offlineServer.id) || offlineServer} onClose={() => setOfflineServer(null)} onExported={() => refresh()} onCopy={(v) => void copy(v)} onDownloadAgent={() => setAgentDownloads({ arch: offlineServer.arch || "amd64" })} screenshotMode={screenshotMode} redact={redactScreenshot} />}
      {agentDownloads && <AgentDownloads initialArch={agentDownloads.arch} releaseVersion={agentReleases.releaseVersion || ""} releaseBuilds={agentReleases} onClose={() => setAgentDownloads(null)} onCopy={(v) => void copy(v)} screenshotMode={screenshotMode} redact={redactScreenshot} />}
      <Suspense fallback={null}><Dialogs /></Suspense>
      {confirmation && <ConfirmDialog confirmation={confirmation} onCancel={() => setConfirmation(null)} onConfirm={() => { setConfirmation(null); confirmation.onConfirm(); }} />}
    </div>)}
    <Toasts app={app} />
  </AppContext.Provider>;
}
