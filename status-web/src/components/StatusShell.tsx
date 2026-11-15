import { useState, type CSSProperties, type ReactNode } from "react";
import type { PublicStatusBackground } from "../monitor/publicCard";
import type { StatusTheme } from "../theme";
import { StatusBackgroundLayer } from "./StatusBackgroundLayer";
import { MoonIcon, SunIcon } from "./ThemeIcons";

export function StatusShell({
  title,
  description,
  theme,
  onToggleTheme,
  disconnected,
  hasData,
  background,
  children,
}: {
  title: string;
  description?: string;
  theme: StatusTheme;
  onToggleTheme: () => void;
  disconnected: boolean;
  hasData: boolean;
  background?: PublicStatusBackground;
  children: ReactNode;
}) {
  const [bgActive, setBgActive] = useState(false);

  const hasBgVersion = Boolean(background?.version?.trim());
  const isBgActive = hasBgVersion && bgActive;
  const rawOpacity = background?.cardOpacity ?? 100;
  const clampedOpacity = Math.min(
    100,
    Math.max(40, Math.round(Number.isFinite(rawOpacity) ? rawOpacity : 100)),
  );
  const rawBlur = background?.blur ?? 0;
  const clampedBlur = Math.min(
    20,
    Math.max(0, Math.round(Number.isFinite(rawBlur) ? rawBlur : 0)),
  );
  const isTranslucent = isBgActive && clampedOpacity < 100;
  const surfaceAlpha = Math.min(96, clampedOpacity + 8);
  const bgScale = clampedBlur > 0 ? (1 + clampedBlur * 0.006).toFixed(3) : "1";

  const pageStyle: CSSProperties | undefined = isBgActive
    ? ({
        "--status-card-alpha": `${clampedOpacity}%`,
        "--status-surface-alpha": `${surfaceAlpha}%`,
        "--status-bg-blur": `${clampedBlur}px`,
        "--status-bg-scale": bgScale,
      } as CSSProperties)
    : undefined;

  return (
    <div
      className="statusPage monScope"
      data-has-bg={isBgActive ? "true" : undefined}
      data-translucent={isTranslucent ? "true" : undefined}
      style={pageStyle}
    >
      <StatusBackgroundLayer background={background} onActiveChange={setBgActive} />
      <div className="statusShell">
        <header className="statusBrandBar">
          <div className="statusBrandTitleGroup">
            <h1 className="statusBrandTitle">{title || "服务状态"}</h1>
            {description && <p className="statusBrandDesc">{description}</p>}
          </div>

          <button
            type="button"
            className="statusThemeToggle"
            onClick={onToggleTheme}
            aria-label={theme === "dark" ? "切换为浅色外观" : "切换为深色外观"}
            title={theme === "dark" ? "浅色外观" : "深色外观"}
          >
            {theme === "dark" ? <SunIcon /> : <MoonIcon />}
            <span>{theme === "dark" ? "浅色" : "深色"}</span>
          </button>
        </header>

        {disconnected && (
          <div className="statusBanner" role="alert">
            <strong>连接中断</strong>
            <span>
              {hasData
                ? "暂时无法刷新最新状态，当前展示上一份数据。"
                : "暂时无法连接状态服务，正在自动重试…"}
            </span>
          </div>
        )}

        {children}
      </div>
    </div>
  );
}
