import { lazy, Suspense, useEffect, useState } from "react";
import { api, mutation } from "../api";
import { useApp } from "../app/context";
import { MemoMaskedValue as MaskedValue } from "../components/secrets";

const QRCode = lazy(() => import("../components/QRCode"));

type SurgeProfile = { template: string; custom: boolean; defaultTemplate: string };

export default function Settings() {
  const { totpEnabled, setTotpEnabled, komariEndpoint, setKomariEndpoint, expiring, act, copy, protect } = useApp();
  const [passwordForm, setPasswordForm] = useState({ current: "", next: "" }),
    [totpOff, setTotpOff] = useState({ password: "", code: "" }),
    [code, setCode] = useState(""),
    [totpSetup, setTotpSetup] = useState<{ secret: string; uri: string } | null>(null),
    [surge, setSurge] = useState<SurgeProfile | null>(null),
    [surgeText, setSurgeText] = useState("");
  useEffect(() => {
    api<SurgeProfile>("/api/settings/surge-profile").then((v) => { setSurge(v); setSurgeText(v.template); }, () => undefined);
  }, []);
  const saveSurge = (template: string, done: string) => act(async () => {
    const saved = await mutation<SurgeProfile>("/api/settings/surge-profile", "PUT", { template });
    setSurge(saved);
    setSurgeText(saved.template);
  }, done);
  return protect(
          <section className="panel settings">
            <h2>Komari 监控</h2>
            <p>所有服务器共用一个 Komari 面板地址；每台服务器的 Agent token 在服务器配置中填写。</p>
            <form className="komariSettingsForm" onSubmit={(e) => {
              e.preventDefault();
              void act(async () => {
                const saved = await mutation<{ endpoint: string }>("/api/settings/komari", "PUT", { endpoint: komariEndpoint });
                setKomariEndpoint(saved.endpoint);
              }, "Komari 面板地址已保存");
            }}>
              <label htmlFor="komari-endpoint">Komari 面板地址</label>
              <input id="komari-endpoint" type="url" placeholder="https://komari.example.com" value={komariEndpoint} onChange={(e) => setKomariEndpoint(e.target.value)} />
              <small>留空会停用 Komari 上报；有地址但服务器未填写 token 时，该服务器也不会启动 Komari 监控。配置变更会自动下发。</small>
              <button className="primary">保存 Komari 地址</button>
            </form>
            <h2>Surge 完整配置模板</h2>
            <p>Surge 订阅的完整配置链接（以 ?profile=1 结尾）按这份模板生成，所有 Surge 订阅共用。{"{{PROXIES}}"} 替换为订阅节点行，{"{{PROXY_NAMES}}"} 替换为逗号分隔的节点名；#!MANAGED-CONFIG 行由面板自动添加。</p>
            {surge && <form className="surgeProfileForm" onSubmit={(e) => { e.preventDefault(); void saveSurge(surgeText, "Surge 配置模板已保存"); }}>
              <label htmlFor="surge-profile">{surge.custom ? "自定义模板" : "默认模板"}</label>
              <textarea id="surge-profile" spellCheck={false} rows={18} value={surgeText} onChange={(e) => setSurgeText(e.target.value)} />
              <small>[Rule] 段必须以 FINAL 结尾。名称与模板中代理组或内置策略相同的节点不会放入配置。默认模板的分流规则引用 GitHub 上的 blackmatrix7 规则集，Surge 首次下载需要能访问 GitHub。保存后，客户端在下次自动更新（每 12 小时）或手动更新时生效。</small>
              <div className="surgeProfileActions">
                <button className="primary" disabled={surgeText === surge.template}>保存模板</button>
                {surge.custom && <button type="button" className="ghost" onClick={() => void saveSurge("", "已恢复默认 Surge 配置模板")}>恢复默认</button>}
              </div>
            </form>}
            <h2>账户安全</h2>
            <p>建议启用动态验证码以保护管理面板。</p>
            {expiring.length > 0 && (
              <div className="banner warning" role="status">
                {expiring.length} 张 TLS 证书已过期或将在 30 天内到期（{expiring.map((c) => c.domain).join("、")}），请尽快更新证书。
              </div>
            )}
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
          </section>,
  );
}
