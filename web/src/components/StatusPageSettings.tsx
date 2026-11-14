import { useEffect, useState } from "react";
import { api, mutation, type StatusPageSettings } from "../api";
import { useApp } from "../app/context";
import { setError } from "../app/feedback";
import { useBusy } from "../app/ui";

const defaultSettings: StatusPageSettings = {
  enabled: false,
  title: "服务状态",
  description: "",
  showTraffic: true,
  showPing: true,
  listenConfigured: false,
  statusUrl: "",
};

function normalizeLoadedSettings(v: StatusPageSettings): StatusPageSettings {
  return {
    enabled: !!v.enabled,
    title: v.title ?? "服务状态",
    description: v.description ?? "",
    showTraffic: v.showTraffic !== false,
    showPing: v.showPing !== false,
    listenConfigured: !!v.listenConfigured,
    statusUrl: v.statusUrl ?? "",
  };
}

export default function StatusPageSettingsCard() {
  const { refreshTick, act, copy } = useApp();
  const { busy, run } = useBusy();
  const [loaded, setLoaded] = useState(false);
  const [form, setForm] = useState<StatusPageSettings>(defaultSettings);

  useEffect(() => {
    api<StatusPageSettings>("/api/settings/status-page")
      .then((raw) => {
        setForm(normalizeLoadedSettings(raw));
        setLoaded(true);
      })
      .catch((e) => setError((e as Error).message));
  }, [refreshTick]);

  const onSave = (e: React.FormEvent) => {
    e.preventDefault();
    const title = form.title.trim();
    const description = form.description.trim();
    if ([...title].length > 60) {
      setError("状态页标题不能超过 60 个字符");
      return;
    }
    if ([...description].length > 300) {
      setError("状态页说明不能超过 300 个字符");
      return;
    }
    void run(async () => {
      await act(async () => {
        const rawNext = await mutation<StatusPageSettings>("/api/settings/status-page", "PUT", {
          enabled: form.enabled,
          title,
          description,
          showTraffic: form.showTraffic,
          showPing: form.showPing,
        });
        setForm(normalizeLoadedSettings(rawNext));
      }, "公开状态页设置已保存");
    });
  };

  return (
    <div className="telegramSettingsCard statusPageSettingsCard">
      <h2>公开状态页</h2>
      <p>
        通过独立监听与独立前端对外展示已勾选“公开展示”的服务器监控状态，不暴露面板地址、公网 IP、域名或管理接口。
      </p>
      {loaded && !form.listenConfigured && (
        <div className="banner warning" role="status">
          未配置独立入口（MUI_STATUS_LISTEN），状态页当前不可访问。请在服务端环境变量配置 MUI_STATUS_LISTEN 并通过独立域名反代 mui-status 容器。
        </div>
      )}
      {form.statusUrl && (
        <div className="statusPageUrlRow">
          <div className="statusPageUrlMeta">
            <strong>对外访问链接</strong>
            <code>{form.statusUrl}</code>
          </div>
          <div className="statusPageUrlActions">
            <button type="button" className="ghost" onClick={() => copy(form.statusUrl)}>
              复制链接
            </button>
          </div>
        </div>
      )}
      <form className="telegramSettingsForm" onSubmit={onSave}>
        <label className="check telegramMasterSwitch">
          <input
            type="checkbox"
            checked={form.enabled}
            onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
          />
          <span>启用公开状态页</span>
        </label>

        <div className="telegramFieldsGrid">
          <div className="telegramField telegramFieldWide">
            <label htmlFor="status-page-title">页面标题（最多 60 字符）</label>
            <input
              id="status-page-title"
              maxLength={60}
              placeholder="留空默认显示“服务状态”"
              value={form.title}
              onChange={(e) => setForm({ ...form, title: e.target.value })}
            />
          </div>

          <div className="telegramField telegramFieldWide">
            <label htmlFor="status-page-desc">页面说明（可选，纯文本，最多 300 字符）</label>
            <textarea
              id="status-page-desc"
              rows={2}
              maxLength={300}
              placeholder="显示在公开状态页标题下方，勿填敏感信息"
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
            />
          </div>
        </div>

        <fieldset className="telegramEventsBox">
          <legend>展示内容</legend>

          <div className="telegramEventRow">
            <label className="check">
              <input
                type="checkbox"
                checked={form.showTraffic}
                onChange={(e) => setForm({ ...form, showTraffic: e.target.checked })}
              />
              <span>展示累计流量与周期流量配额</span>
            </label>
          </div>

          <div className="telegramEventRow">
            <label className="check">
              <input
                type="checkbox"
                checked={form.showPing}
                onChange={(e) => setForm({ ...form, showPing: e.target.checked })}
              />
              <span>展示延迟监测曲线（仅公开任务名称，不返回探测目标地址）</span>
            </label>
          </div>
        </fieldset>

        <div className="telegramActions">
          <button type="submit" className="primary" disabled={busy}>
            保存状态页设置
          </button>
        </div>
      </form>
    </div>
  );
}
