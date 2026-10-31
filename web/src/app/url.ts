import { useCallback, useSyncExternalStore } from "react";
import type { Tab } from "./helpers";

// The URL hash is the single source of truth for the page, its server context
// and its filters, so a reload or the browser's back button restores them.
// Example: #nodes?server=abc&q=tokyo&sort=name
export const tabIds = new Set<string>([
  "dashboard", "servers", "nodes", "templates", "certificates", "firewall", "forwards", "routes",
  "subscriptions", "customers", "accesses", "connections", "operations", "audit", "help", "settings",
]);

const listeners = new Set<() => void>();
const notify = () => listeners.forEach((listener) => listener());
function subscribe(listener: () => void) {
  listeners.add(listener);
  window.addEventListener("popstate", listener);
  window.addEventListener("hashchange", listener);
  return () => {
    listeners.delete(listener);
    window.removeEventListener("popstate", listener);
    window.removeEventListener("hashchange", listener);
  };
}

export function parseHash(hash = location.hash): { tab: Tab; params: URLSearchParams } {
  const raw = hash.slice(1);
  const question = raw.indexOf("?");
  let id = "";
  try {
    id = decodeURIComponent(question < 0 ? raw : raw.slice(0, question));
  } catch {
    // A malformed hash falls back to the dashboard.
  }
  return { tab: tabIds.has(id) ? id as Tab : "dashboard", params: new URLSearchParams(question < 0 ? "" : raw.slice(question + 1)) };
}

function hashOf(tab: Tab, params: URLSearchParams) {
  const query = params.toString();
  return `#${tab}${query ? "?" + query : ""}`;
}

// Filters survive a visit to another page, as they did before they moved here.
const remembered = new Map<Tab, URLSearchParams>();

// Moves to a page and adds a history entry. `server` is the server context;
// `filters`, when given, replaces whatever that page last had.
export function navigate(tab: Tab, server: string, filters?: Record<string, string>) {
  const current = parseHash();
  remembered.set(current.tab, current.params);
  const params = new URLSearchParams(filters ? "" : remembered.get(tab) ?? "");
  // Another server's text and status filters would hide what was asked for.
  if (!filters && (params.get("server") || "") !== server) for (const key of [...params.keys()]) params.delete(key);
  for (const [key, value] of Object.entries(filters || {})) if (value) params.set(key, value);
  if (server) params.set("server", server); else params.delete("server");
  const next = hashOf(tab, params);
  if (next !== location.hash) history.pushState(null, "", next);
  notify();
}

// Filter edits replace the entry: one keystroke must not be one Back press.
function setParam(key: string, value: string) {
  const { tab, params } = parseHash();
  if (value) params.set(key, value); else params.delete(key);
  history.replaceState(null, "", hashOf(tab, params));
  notify();
}

export function useTab() {
  return useSyncExternalStore(subscribe, () => parseHash().tab);
}

export function useUrlParam(key: string): [string, (value: string) => void] {
  const value = useSyncExternalStore(subscribe, () => parseHash().params.get(key) || "");
  return [value, useCallback((next: string) => setParam(key, next), [key])];
}

export function useServerParam() {
  return useUrlParam("server");
}
