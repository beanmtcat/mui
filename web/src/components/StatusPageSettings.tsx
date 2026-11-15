import { useRef, useEffect, useState, type ChangeEvent, type FormEvent } from "react";
import { api, mutation, type StatusPageSettings } from "../api";
import { useApp } from "../app/context";
import { setError } from "../app/feedback";
import { useBusy } from "../app/ui";

const MAX_BG_BYTES = 3 * 1024 * 1024;
const ALLOWED_BG_TYPES = new Set(["image/jpeg", "image/png", "image/webp"]);
const ALLOWED_BG_EXT_RE = /\.(jpe?g|png|webp)$/i;

type BackgroundMutationResult = {
  ok: boolean;
  backgroundSet: boolean;
  backgroundVersion: string;
};

const defaultSettings: StatusPageSettings = {
  enabled: false,
  title: "服务状态",
  description: "",
  showTraffic: true,
  showPing: true,
  cardOpacity: 100,
  backgroundBlur: 0,
  backgroundSet: false,
  backgroundVersion: "",
  listenConfigured: false,
  statusUrl: "",
};

function clampInt(value: unknown, min: number, max: number, fallback: number): number {
  if (typeof value !== "number" || !Number.isFinite(value)) return fallback;
  const rounded = Math.round(value);
  if (rounded < min || rounded > max) return fallback;
  return rounded;
}

function normalizeLoadedSettings(v: StatusPageSettings): StatusPageSettings {
  return {
    enabled: !!v.enabled,
    title: v.title ?? "服务状态",
    description: v.description ?? "",
    showTraffic: v.showTraffic !== false,
    showPing: v.showPing !== false,
    cardOpacity: clampInt(v.cardOpacity, 40, 100, 100),
    backgroundBlur: clampInt(v.backgroundBlur, 0, 20, 0),
    backgroundSet: !!v.backgroundSet,
    backgroundVersion: v.backgroundVersion ?? "",
    listenConfigured: !!v.listenConfigured,
    statusUrl: v.statusUrl ?? "",
  };
}

function isSupportedImageFile(file: File): boolean {
  const mime = (file.type || "").toLowerCase().trim();
  if (mime) {
    return ALLOWED_BG_TYPES.has(mime);
  }
  return ALLOWED_BG_EXT_RE.test(file.name);
}

async function uploadStatusBackground(file: File): Promise<BackgroundMutationResult> {
  const path = "/api/settings/status-page/background";
  const res = await fetch(path, {
    method: "PUT",
    credentials: "same-origin",
    headers: {
      "Content-Type": file.type || "application/octet-stream",
      "X-Requested-With": "XMLHttpRequest",
    },
    body: file,
  });
  const body = await res.json().catch(() => ({ error: "服务器响应无效" }));
  if (!res.ok) {
    if (res.status === 401) {
      window.dispatchEvent(new Event("mui:session-expired"));
    }
    const detail = body.error === "服务器响应无效" ? `HTTP ${res.status}` : body.error || `HTTP ${res.status}`;
    throw new Error(`${path}: ${detail}`);
  }
  return body as BackgroundMutationResult;
}

export default function StatusPageSettingsCard() {
  const { refreshTick, act, copy } = useApp();
  const { busy, run } = useBusy();
  const [loaded, setLoaded] = useState(false);
  const [form, setForm] = useState<StatusPageSettings>(defaultSettings);
  const [previewFailed, setPreviewFailed] = useState(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    api<StatusPageSettings>("/api/settings/status-page")
      .then((raw) => {
        setForm(normalizeLoadedSettings(raw));
        setPreviewFailed(false);
        setLoaded(true);
      })
      .catch((e) => setError((e as Error).message));
  }, [refreshTick]);

  const onSave = (e: FormEvent) => {
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
          cardOpacity: form.cardOpacity,
          backgroundBlur: form.backgroundBlur,
        });
        setForm(normalizeLoadedSettings(rawNext));
      }, "公开状态页设置已保存");
    });
  };

  const onFileChange = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;

    if (!isSupportedImageFile(file)) {
      setError("仅支持上传 JPEG、PNG 或 WebP 格式的图片");
      return;
    }
    if (file.size <= 0) {
      setError("所选图片文件为空");
      return;
    }
    if (file.size > MAX_BG_BYTES) {
      setError("背景图片大小不能超过 3 MiB");
      return;
    }

    void run(async () => {
      await act(async () => {
        const res = await uploadStatusBackground(file);
        setPreviewFailed(false);
        setForm((prev) => ({
          ...prev,
          backgroundSet: !!res.backgroundSet,
          backgroundVersion: res.backgroundVersion || "",
        }));
      }, "背景图片已上传");
    });
  };

  const onRemoveBackground = () => {
    void run(async () => {
      await act(async () => {
        const res = await mutation<BackgroundMutationResult>("/api/settings/status-page/background", "DELETE");
        setPreviewFailed(false);
        setForm((prev) => ({
          ...prev,
          backgroundSet: !!res.backgroundSet,
          backgroundVersion: res.backgroundVersion || "",
        }));
      }, "背景图片已移除");
    });
  };

  const previewUrl = form.backgroundSet
    ? `/api/settings/status-page/background?v=${encodeURIComponent(form.backgroundVersion)}`
    : "";

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

        <fieldset className="telegramEventsBox statusBgBox">
          <legend>背景图片</legend>

          <div className="statusBgRow">
            <input
              ref={fileInputRef}
              className="statusBgFileInput"
              type="file"
              accept="image/jpeg,image/png,image/webp"
              onChange={onFileChange}
            />
            <div className="statusBgActions">
              <button
                type="button"
                className="ghost"
                disabled={busy}
                onClick={() => fileInputRef.current?.click()}
              >
                {form.backgroundSet ? "更换背景图片" : "上传背景图片"}
              </button>
              {form.backgroundSet && (
                <button
                  type="button"
                  className="ghost dangerText"
                  disabled={busy}
                  onClick={onRemoveBackground}
                >
                  移除背景
                </button>
              )}
            </div>
            <p className="hint statusBgHint">
              支持 JPEG、PNG、WebP，大小不超过 3 MiB，宽高不超过 6000 像素；关闭状态页不会删除已上传的背景图。
            </p>
          </div>

          {form.backgroundSet && previewUrl && !previewFailed && (
            <div className="statusBgPreview">
              <img
                className="statusBgPreviewImg"
                src={previewUrl}
                alt="当前背景图片预览"
                onError={() => setPreviewFailed(true)}
              />
            </div>
          )}

          <div className="statusSliderRow">
            <div className="statusSliderHead">
              <label htmlFor="status-card-opacity">卡片不透明度</label>
              <strong>{form.cardOpacity}%</strong>
            </div>
            <input
              id="status-card-opacity"
              type="range"
              min={40}
              max={100}
              step={1}
              value={form.cardOpacity}
              onChange={(e) => setForm({ ...form, cardOpacity: Number(e.target.value) })}
            />
          </div>

          <div className="statusSliderRow">
            <div className="statusSliderHead">
              <label htmlFor="status-bg-blur">背景模糊</label>
              <strong>{form.backgroundBlur} px</strong>
            </div>
            <input
              id="status-bg-blur"
              type="range"
              min={0}
              max={20}
              step={1}
              value={form.backgroundBlur}
              onChange={(e) => setForm({ ...form, backgroundBlur: Number(e.target.value) })}
            />
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
