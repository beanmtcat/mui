import { lazy, Suspense, useState } from "react";
import { mutation } from "../api";
import { useApp } from "../app/context";
import { useUrlParam } from "../app/url";
import { MemoMaskedValue as MaskedValue } from "../components/secrets";
import StatusPageSettingsCard from "../components/StatusPageSettings";
import TelegramSettingsCard from "../components/TelegramSettings";

const QRCode = lazy(() => import("../components/QRCode"));

const SETTINGS_TABS = [
  { id: "notify", label: "通知" },
  { id: "status", label: "状态页" },
  { id: "security", label: "账户安全" },
] as const;
type SettingsTab = (typeof SETTINGS_TABS)[number]["id"];

export default function Settings() {
  const { totpEnabled, setTotpEnabled, expiring, act, copy, protect } = useApp();
  const [passwordForm, setPasswordForm] = useState({ current: "", next: "" }),
    [totpOff, setTotpOff] = useState({ password: "", code: "" }),
    [code, setCode] = useState(""),
    [totpSetup, setTotpSetup] = useState<{ secret: string; uri: string } | null>(null);
  const [tabParam, setTabParam] = useUrlParam("section");
  const tab: SettingsTab = SETTINGS_TABS.some((t) => t.id === tabParam) ? (tabParam as SettingsTab) : "notify";
  return protect(
          <section className="panel settings">
            {expiring.length > 0 && (
              <div className="banner warning" role="status">
                {expiring.length} 张 TLS 证书已过期或将在 30 天内到期（{expiring.map((c) => c.domain).join("、")}），请尽快更新证书。
              </div>
            )}
            <div className="settingsTabs" role="tablist" aria-label="设置分类">
              {SETTINGS_TABS.map((t) => (
                <button
                  key={t.id}
                  type="button"
                  role="tab"
                  id={`settings-tab-${t.id}`}
                  aria-selected={tab === t.id}
                  aria-controls={`settings-panel-${t.id}`}
                  className={tab === t.id ? "active" : ""}
                  onClick={() => setTabParam(t.id === "notify" ? "" : t.id)}
                >
                  {t.label}
                </button>
              ))}
            </div>
            {/* Panels stay mounted so unsaved edits survive switching tabs. */}
            <div className="settingsTabPanel" role="tabpanel" id="settings-panel-notify" aria-labelledby="settings-tab-notify" hidden={tab !== "notify"}>
              <TelegramSettingsCard />
            </div>
            <div className="settingsTabPanel" role="tabpanel" id="settings-panel-status" aria-labelledby="settings-tab-status" hidden={tab !== "status"}>
              <StatusPageSettingsCard />
            </div>
            <div className="settingsTabPanel" role="tabpanel" id="settings-panel-security" aria-labelledby="settings-tab-security" hidden={tab !== "security"}>
            <h2>账户安全</h2>
            <p>建议启用动态验证码以保护管理面板。</p>
            <div className="settingRow">
              <div>
                <strong>TOTP 双因素认证</strong>
                <small>{totpEnabled ? "已启用" : "未启用"}</small>
              </div>
              {!totpEnabled && (
                <button
                  className="ghost"
                  onClick={() =>
                    act(async () => {
                      const v = await mutation<{ secret: string; uri: string }>(
                        "/api/totp/setup",
                        "POST",
                      );
                      setTotpSetup(v);
                    }, "请在验证器中添加密钥")
                  }
                >
                  设置
                </button>
              )}
            </div>
            {totpSetup && (
              <div className="totpBox">
                <p>用验证器应用扫描二维码，或手动添加下面的密钥：</p>
                <Suspense fallback={<div className="hint">正在加载二维码…</div>}><QRCode text={totpSetup.uri} /></Suspense>
                <MaskedValue value={totpSetup.secret}><button type="button" onClick={() => copy(totpSetup.secret)}>复制密钥</button></MaskedValue>
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    act(async () => {
                      await mutation("/api/totp/enable", "POST", { code });
                      setTotpEnabled(true);
                      setTotpSetup(null);
                    }, "双因素认证已启用");
                  }}
                >
                  <input
                    value={code}
                    onChange={(e) => setCode(e.target.value)}
                    placeholder="输入 6 位验证码"
                    maxLength={6}
                  />
                  <button className="primary">启用</button>
                </form>
              </div>
            )}
            {totpEnabled && (
              <form
                className="totpBox"
                onSubmit={async (e) => {
                  e.preventDefault();
                  if (
                    await act(
                      () => mutation("/api/totp/disable", "POST", totpOff),
                      "双因素认证已关闭",
                    )
                  ) {
                    setTotpEnabled(false);
                    setTotpOff({ password: "", code: "" });
                  }
                }}
              >
                <p>关闭双因素认证需要当前密码和一个有效验证码：</p>
                <input
                  type="password"
                  required
                  autoComplete="current-password"
                  placeholder="当前密码"
                  value={totpOff.password}
                  onChange={(e) =>
                    setTotpOff({ ...totpOff, password: e.target.value })
                  }
                />
                <input
                  required
                  inputMode="numeric"
                  maxLength={6}
                  placeholder="6 位验证码"
                  value={totpOff.code}
                  onChange={(e) =>
                    setTotpOff({ ...totpOff, code: e.target.value })
                  }
                />
                <button className="ghost">关闭双因素认证</button>
              </form>
            )}
            <div className="settingRow">
              <div>
                <strong>管理员密码</strong>
                <small>修改后其他已登录的会话会失效</small>
              </div>
            </div>
            <form
              className="totpBox"
              onSubmit={async (e) => {
                e.preventDefault();
                if (
                  await act(
                    () =>
                      mutation("/api/password", "POST", {
                        current: passwordForm.current,
                        new: passwordForm.next,
                      }),
                    "密码已修改",
                  )
                )
                  setPasswordForm({ current: "", next: "" });
              }}
            >
              <input
                type="password"
                required
                autoComplete="current-password"
                placeholder="当前密码"
                value={passwordForm.current}
                onChange={(e) =>
                  setPasswordForm({ ...passwordForm, current: e.target.value })
                }
              />
              <input
                type="password"
                required
                minLength={12}
                maxLength={72}
                autoComplete="new-password"
                placeholder="新密码（至少 12 个字符）"
                value={passwordForm.next}
                onChange={(e) =>
                  setPasswordForm({ ...passwordForm, next: e.target.value })
                }
              />
              <button className="primary">修改密码</button>
            </form>
            <p className="hint">
              忘记密码或丢失验证器：按 README“忘记密码”一节的一次性命令重置（不要把 MUI_ADMIN_RESET 写进 .env 或 compose 文件）。
            </p>
            </div>
          </section>,
  );
}
