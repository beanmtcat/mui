import type { ReactNode } from "react";
import type { StatusTheme } from "../theme";
import { MoonIcon, SunIcon } from "./ThemeIcons";

export function StatusShell({
  title,
  description,
  theme,
  onToggleTheme,
  disconnected,
  hasData,
  children,
}: {
  title: string;
  description?: string;
  theme: StatusTheme;
  onToggleTheme: () => void;
  disconnected: boolean;
  hasData: boolean;
  children: ReactNode;
}) {
  return (
    <div className="statusPage monScope">
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
