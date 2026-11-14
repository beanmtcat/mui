import { useEffect, useState } from "react";
import { api, mutation, type TelegramEvents, type TelegramSettings } from "../api";
import { useApp } from "../app/context";
import { setError } from "../app/feedback";
import { useBusy } from "../app/ui";

const defaultEvents: TelegramEvents = {
  serverOffline: { enabled: true, offlineMinutes: 3 },
  applyFailed: { enabled: true },
  certExpiring: { enabled: true },
  subscriptionExpiring: { enabled: false },
  serverExpiring: { enabled: true },
  serverRenewed: { enabled: true },
  resource: { enabled: false, minutes: 5, threshold: 90 },
  trafficLimit: { enabled: true, threshold: 80 },
  trafficReport: { daily: false, weekly: false, monthly: false },
  security: { enabled: true },
};

const defaultSettings: TelegramSettings = {
  enabled: false,
  botTokenSet: false,
  chatId: "",
  threadId: 0,
  apiBase: "",
  events: defaultEvents,
};

function normalizeLoadedSettings(v: TelegramSettings): TelegramSettings {
  return {
    ...v,
    events: {
      ...defaultEvents,
      ...v.events,
      serverOffline: { ...defaultEvents.serverOffline, ...v.events?.serverOffline },
      applyFailed: { ...defaultEvents.applyFailed, ...v.events?.applyFailed },
      certExpiring: { ...defaultEvents.certExpiring, ...v.events?.certExpiring },
      subscriptionExpiring: { ...defaultEvents.subscriptionExpiring, ...v.events?.subscriptionExpiring },
      serverExpiring: { ...defaultEvents.serverExpiring, ...v.events?.serverExpiring },
      serverRenewed: { ...defaultEvents.serverRenewed, ...v.events?.serverRenewed },
      resource: { ...defaultEvents.resource, ...v.events?.resource },
      trafficLimit: { ...defaultEvents.trafficLimit, ...v.events?.trafficLimit },
      trafficReport: { ...defaultEvents.trafficReport, ...v.events?.trafficReport },
      security: { ...defaultEvents.security, ...v.events?.security },
    },
  };
}

type NumberDrafts = {
  threadId: string;
  offlineMinutes: string;
  resourceMinutes: string;
  resourceThreshold: string;
  trafficThreshold: string;
};

function draftsFromSettings(s: TelegramSettings): NumberDrafts {
  return {
    threadId: s.threadId > 0 ? String(s.threadId) : "",
    offlineMinutes: String(s.events.serverOffline.offlineMinutes),
    resourceMinutes: String(s.events.resource.minutes),
    resourceThreshold: String(s.events.resource.threshold),
    trafficThreshold: String(s.events.trafficLimit.threshold),
  };
}

function parseRangeInt(raw: string, min: number, max: number): number | null {
  const trimmed = raw.trim();
  if (!/^\d+$/.test(trimmed)) return null;
  const n = Number.parseInt(trimmed, 10);
  if (!Number.isSafeInteger(n) || n < min || n > max) return null;
  return n;
}

function snapshotForm(s: TelegramSettings, d: NumberDrafts) {
  return JSON.stringify({
    enabled: s.enabled,
    chatId: s.chatId,
    threadId: d.threadId.trim(),
    apiBase: s.apiBase,
    serverOfflineEnabled: s.events.serverOffline.enabled,
    offlineMinutes: d.offlineMinutes.trim(),
    applyFailed: s.events.applyFailed.enabled,
    certExpiring: s.events.certExpiring.enabled,
    subscriptionExpiring: s.events.subscriptionExpiring.enabled,
    serverExpiring: s.events.serverExpiring.enabled,
    serverRenewed: s.events.serverRenewed.enabled,
    resourceEnabled: s.events.resource.enabled,
    resourceMinutes: d.resourceMinutes.trim(),
    resourceThreshold: d.resourceThreshold.trim(),
    trafficLimitEnabled: s.events.trafficLimit.enabled,
    trafficThreshold: d.trafficThreshold.trim(),
    trafficReportDaily: s.events.trafficReport.daily,
    trafficReportWeekly: s.events.trafficReport.weekly,
    trafficReportMonthly: s.events.trafficReport.monthly,
    security: s.events.security.enabled,
  });
}

export default function TelegramSettingsCard() {
  const { refreshTick, act } = useApp();
  const { busy, run } = useBusy();
  const [saved, setSaved] = useState<TelegramSettings>(defaultSettings);
  const [form, setForm] = useState<TelegramSettings>(defaultSettings);
  const [drafts, setDrafts] = useState<NumberDrafts>(() => draftsFromSettings(defaultSettings));
  const [botToken, setBotToken] = useState("");
  const [clearToken, setClearToken] = useState(false);

  useEffect(() => {
    api<TelegramSettings>("/api/settings/telegram")
      .then((raw) => {
        const v = normalizeLoadedSettings(raw);
        setSaved(v);
        setForm(v);
        setDrafts(draftsFromSettings(v));
        setBotToken("");
        setClearToken(false);
      })
      .catch((e) => setError((e as Error).message));
  }, [refreshTick]);

  const savedDrafts = draftsFromSettings(saved);
  const isDirty =
    botToken !== "" ||
    clearToken ||
    snapshotForm(form, drafts) !== snapshotForm(saved, savedDrafts);

  const updateEvents = (patch: Partial<TelegramEvents>) => {
    setForm((prev) => ({
      ...prev,
      events: { ...prev.events, ...patch },
    }));
  };

  const onSave = (e: React.FormEvent) => {
    e.preventDefault();
    const offlineMinutes = parseRangeInt(drafts.offlineMinutes, 2, 60);
    if (offlineMinutes === null) {
      setError("服务器离线时长阈值需填写 2–60 之间的整数");
      return;
    }
    const resourceMinutes = parseRangeInt(drafts.resourceMinutes, 1, 60);
    if (resourceMinutes === null) {
      setError("资源高占用持续时长需填写 1–60 之间的整数");
      return;
    }
    const resourceThreshold = parseRangeInt(drafts.resourceThreshold, 1, 100);
    if (resourceThreshold === null) {
      setError("资源使用率阈值需填写 1–100 之间的整数");
      return;
    }
    const trafficThreshold = parseRangeInt(drafts.trafficThreshold, 50, 100);
    if (trafficThreshold === null) {
      setError("流量告警阈值需填写 50–100 之间的整数");
      return;
    }
    let threadId = 0;
    if (drafts.threadId.trim() !== "") {
      const parsedThread = parseRangeInt(drafts.threadId, 1, 2147483647);
      if (parsedThread === null) {
        setError("话题 ID 需为正整数，不使用请留空");
        return;
      }
      threadId = parsedThread;
    }

    const nextEvents: TelegramEvents = {
      ...form.events,
      serverOffline: { ...form.events.serverOffline, offlineMinutes },
      resource: { ...form.events.resource, minutes: resourceMinutes, threshold: resourceThreshold },
      trafficLimit: { ...form.events.trafficLimit, threshold: trafficThreshold },
    };

    void run(async () => {
      const payload: Record<string, unknown> = {
        enabled: form.enabled,
        chatId: form.chatId,
        threadId,
        apiBase: form.apiBase,
        events: nextEvents,
      };
      if (clearToken) {
        payload.botToken = "";
      } else if (botToken !== "") {
        payload.botToken = botToken;
      }
      await act(async () => {
        const rawNext = await mutation<TelegramSettings>("/api/settings/telegram", "PUT", payload);
        const next = normalizeLoadedSettings(rawNext);
        setSaved(next);
        setForm(next);
        setDrafts(draftsFromSettings(next));
        setBotToken("");
        setClearToken(false);
      }, "Telegram 告警设置已保存");
    });
  };

  const onTest = () => {
    if (isDirty) {
      setError("有未保存的修改，请先点击“保存 Telegram 设置”后再发送测试消息");
      return;
    }
    if (!saved.botTokenSet || !saved.chatId.trim()) {
      setError("请先填写并保存 Bot Token 与 Chat ID");
      return;
    }
    void run(async () => {
      await act(
        () => mutation<{ ok: boolean }>("/api/settings/telegram/test", "POST"),
        "测试消息已发送，请检查 Telegram 会话",
      );
    });
  };

  const tokenPlaceholder = clearToken
    ? "保存后将清除已设置的 Bot Token"
    : saved.botTokenSet
      ? "已设置（留空保留原值）"
      : "例如 123456789:ABCdef...";

  return (
    <div className="telegramSettingsCard">
      <h2>Telegram 告警</h2>
      <p>通过 Telegram Bot 推送服务器离线、操作失败、证书或订阅到期与安全事件通知。</p>
      <form className="telegramSettingsForm" onSubmit={onSave}>
        <label className="check telegramMasterSwitch">
          <input
            type="checkbox"
            checked={form.enabled}
            onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
          />
          <span>启用 Telegram 告警</span>
        </label>

        <div className="telegramFieldsGrid">
          <div className="telegramField telegramFieldWide">
            <div className="telegramFieldHead">
              <label htmlFor="tg-bot-token">Bot Token</label>
              {saved.botTokenSet && (
                <button
                  type="button"
                  className="telegramLinkBtn"
                  onClick={() => {
                    setBotToken("");
                    setClearToken((v) => !v);
                  }}
                >
                  {clearToken ? "保留原 Token" : "清除已保存 Token"}
                </button>
              )}
            </div>
            <input
              id="tg-bot-token"
              type="password"
              autoComplete="new-password"
              placeholder={tokenPlaceholder}
              value={botToken}
              onChange={(e) => {
                setBotToken(e.target.value);
                if (e.target.value !== "") setClearToken(false);
              }}
            />
          </div>

          <div className="telegramField">
            <label htmlFor="tg-chat-id">Chat ID</label>
            <input
              id="tg-chat-id"
              placeholder="-1001234567890 或 @channel_name"
              value={form.chatId}
              onChange={(e) => setForm({ ...form, chatId: e.target.value })}
            />
          </div>

          <div className="telegramField">
            <label htmlFor="tg-thread-id">话题 ID（可选）</label>
            <input
              id="tg-thread-id"
              type="number"
              min={1}
              step={1}
              placeholder="话题群 message_thread_id"
              value={drafts.threadId}
              onChange={(e) => setDrafts({ ...drafts, threadId: e.target.value })}
            />
          </div>

          <div className="telegramField telegramFieldWide">
            <label htmlFor="tg-api-base">API 地址（可选）</label>
            <input
              id="tg-api-base"
              type="url"
              placeholder="https://api.telegram.org"
              value={form.apiBase}
              onChange={(e) => setForm({ ...form, apiBase: e.target.value })}
            />
            <small>留空默认使用 https://api.telegram.org；自建反代地址必须使用 https 且不含查询参数。</small>
          </div>
        </div>

        <fieldset className="telegramEventsBox">
          <legend>事件与阈值</legend>

          <div className="telegramEventRow">
            <label className="check">
              <input
                type="checkbox"
                checked={form.events.serverOffline.enabled}
                onChange={(e) =>
                  updateEvents({
                    serverOffline: { ...form.events.serverOffline, enabled: e.target.checked },
                  })
                }
              />
              <span>服务器离线与恢复</span>
            </label>
            <label className="telegramInlineThreshold">
              <span>离线超过</span>
              <input
                type="number"
                min={2}
                max={60}
                value={drafts.offlineMinutes}
                onChange={(e) => setDrafts({ ...drafts, offlineMinutes: e.target.value })}
              />
              <span>分钟</span>
            </label>
          </div>

          <div className="telegramEventRow">
            <label className="check">
              <input
                type="checkbox"
                checked={form.events.applyFailed.enabled}
                onChange={(e) => updateEvents({ applyFailed: { enabled: e.target.checked } })}
              />
              <span>配置下发、防火墙与程序升级失败</span>
            </label>
          </div>

          <div className="telegramEventRow">
            <label className="check">
              <input
                type="checkbox"
                checked={form.events.certExpiring.enabled}
                onChange={(e) => updateEvents({ certExpiring: { enabled: e.target.checked } })}
              />
              <span>TLS 证书即将到期（进入阈值、剩 3 天、剩 1 天）</span>
            </label>
          </div>

          <div className="telegramEventRow">
            <label className="check">
              <input
                type="checkbox"
                checked={form.events.subscriptionExpiring.enabled}
                onChange={(e) => updateEvents({ subscriptionExpiring: { enabled: e.target.checked } })}
              />
              <span>订阅即将到期与已到期</span>
            </label>
          </div>

          <div className="telegramEventRow">
            <label className="check">
              <input
                type="checkbox"
                checked={form.events.serverExpiring.enabled}
                onChange={(e) => updateEvents({ serverExpiring: { enabled: e.target.checked } })}
              />
              <span>服务器到期日提醒（剩 7 天、3 天、1 天；自动续期提前 3 天提醒）</span>
            </label>
          </div>

          <div className="telegramEventRow">
            <label className="check">
              <input
                type="checkbox"
                checked={form.events.serverRenewed.enabled}
                onChange={(e) => updateEvents({ serverRenewed: { enabled: e.target.checked } })}
              />
              <span>服务器已自动续期通知</span>
            </label>
          </div>

          <div className="telegramEventRow">
            <label className="check">
              <input
                type="checkbox"
                checked={form.events.resource.enabled}
                onChange={(e) =>
                  updateEvents({
                    resource: { ...form.events.resource, enabled: e.target.checked },
                  })
                }
              />
              <span>主机 CPU / 内存 / 磁盘高占用与恢复</span>
            </label>
            <div className="telegramInlineThreshold">
              <span>连续</span>
              <input
                type="number"
                min={1}
                max={60}
                aria-label="资源高占用持续分钟数"
                value={drafts.resourceMinutes}
                onChange={(e) => setDrafts({ ...drafts, resourceMinutes: e.target.value })}
              />
              <span>分钟高于</span>
              <input
                type="number"
                min={1}
                max={100}
                aria-label="资源使用率百分比阈值"
                value={drafts.resourceThreshold}
                onChange={(e) => setDrafts({ ...drafts, resourceThreshold: e.target.value })}
              />
              <span>%</span>
            </div>
          </div>

          <div className="telegramEventRow">
            <label className="check">
              <input
                type="checkbox"
                checked={form.events.trafficLimit.enabled}
                onChange={(e) =>
                  updateEvents({
                    trafficLimit: { ...form.events.trafficLimit, enabled: e.target.checked },
                  })
                }
              />
              <span>服务器周期流量告警（达到阈值、90%、100%）</span>
            </label>
            <label className="telegramInlineThreshold">
              <span>阈值</span>
              <input
                type="number"
                min={50}
                max={100}
                aria-label="流量告警百分比阈值"
                value={drafts.trafficThreshold}
                onChange={(e) => setDrafts({ ...drafts, trafficThreshold: e.target.value })}
              />
              <span>%</span>
            </label>
          </div>

          <div className="telegramEventRow">
            <span className="telegramReportLabel">定期流量报告（09:00 汇总）</span>
            <div className="telegramReportChecks">
              <label className="check">
                <input
                  type="checkbox"
                  checked={form.events.trafficReport.daily}
                  onChange={(e) =>
                    updateEvents({
                      trafficReport: { ...form.events.trafficReport, daily: e.target.checked },
                    })
                  }
                />
                <span>每日</span>
              </label>
              <label className="check">
                <input
                  type="checkbox"
                  checked={form.events.trafficReport.weekly}
                  onChange={(e) =>
                    updateEvents({
                      trafficReport: { ...form.events.trafficReport, weekly: e.target.checked },
                    })
                  }
                />
                <span>每周一</span>
              </label>
              <label className="check">
                <input
                  type="checkbox"
                  checked={form.events.trafficReport.monthly}
                  onChange={(e) =>
                    updateEvents({
                      trafficReport: { ...form.events.trafficReport, monthly: e.target.checked },
                    })
                  }
                />
                <span>每月 1 号</span>
              </label>
            </div>
          </div>

          <div className="telegramEventRow">
            <label className="check">
              <input
                type="checkbox"
                checked={form.events.security.enabled}
                onChange={(e) => updateEvents({ security: { enabled: e.target.checked } })}
              />
              <span>安全事件（管理员登录、密码修改、TOTP 关闭/锁定、密码重置）</span>
            </label>
          </div>
        </fieldset>

        <div className="telegramActions">
          <button type="submit" className="primary" disabled={busy}>
            保存 Telegram 设置
          </button>
          <button type="button" className="ghost" disabled={busy} onClick={onTest}>
            发送测试消息
          </button>
        </div>
      </form>
    </div>
  );
}
