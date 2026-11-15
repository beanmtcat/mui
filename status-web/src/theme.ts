export type StatusTheme = "light" | "dark";

const STORAGE_KEY = "status-theme";

export function readInitialStatusTheme(): StatusTheme {
  try {
    const saved = window.localStorage.getItem(STORAGE_KEY);
    if (saved === "light" || saved === "dark") {
      return saved;
    }
  } catch {
    // Ignore storage access errors in restricted browsing modes.
  }
  return "dark";
}

export function syncStatusTheme(theme: StatusTheme) {
  document.documentElement.dataset.theme = theme;
  document.documentElement.style.colorScheme = theme;
}

export function applyStatusTheme(theme: StatusTheme) {
  syncStatusTheme(theme);
  try {
    window.localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    // Ignore storage access errors.
  }
}
