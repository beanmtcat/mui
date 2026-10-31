import React, { memo, useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { api } from "../api";
import type { Confirmation, Tab } from "./helpers";

type SubPage = "accesses" | "connections" | "audit";
export type IconName = "privacy" | "refresh" | "sun" | "moon" | "generate" | "dice" | "menu" | Exclude<Tab, SubPage> | "logout";

export function Icon({ name }: { name: IconName }) {
  const paths = {
    privacy: <><path d="M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6l-8-3Z" /><path d="m8 12 3 3 5-6" /></>,
    refresh: <><path d="M20 11a8 8 0 1 0-2.2 6" /><path d="M20 4v7h-7" /></>,
    sun: <><circle cx="12" cy="12" r="4" /><path d="M12 2v2m0 16v2M4.93 4.93l1.42 1.42m11.3 11.3 1.42 1.42M2 12h2m16 0h2M4.93 19.07l1.42-1.42m11.3-11.3 1.42-1.42" /></>,
    moon: <path d="M20.9 13a9 9 0 0 1-9.9-9.9A9 9 0 1 0 20.9 13Z" />,
    generate: <><path d="m12 3 1.7 5.3L19 10l-5.3 1.7L12 17l-1.7-5.3L5 10l5.3-1.7L12 3Z" /><path d="m19 16 .7 2.3L22 19l-2.3.7L19 22l-.7-2.3L16 19l2.3-.7L19 16Z" /></>,
    dice: <><rect x="3" y="3" width="18" height="18" rx="3" /><circle cx="8" cy="8" r="1" fill="currentColor" stroke="none" /><circle cx="16" cy="8" r="1" fill="currentColor" stroke="none" /><circle cx="12" cy="12" r="1" fill="currentColor" stroke="none" /><circle cx="8" cy="16" r="1" fill="currentColor" stroke="none" /><circle cx="16" cy="16" r="1" fill="currentColor" stroke="none" /></>,
    dashboard: <><rect x="3" y="3" width="8" height="8" rx="1" /><rect x="13" y="3" width="8" height="5" rx="1" /><rect x="13" y="10" width="8" height="11" rx="1" /><rect x="3" y="13" width="8" height="8" rx="1" /></>,
    servers: <><rect x="3" y="3" width="18" height="8" rx="2" /><rect x="3" y="13" width="18" height="8" rx="2" /><path d="M7 7h.01M7 17h.01M11 7h7M11 17h7" /></>,
    nodes: <><circle cx="5" cy="12" r="2" /><circle cx="19" cy="5" r="2" /><circle cx="19" cy="19" r="2" /><path d="m7 11 10-5M7 13l10 5" /></>,
    templates: <><rect x="5" y="3" width="14" height="18" rx="2" /><path d="M9 8h6M9 12h6M9 16h4" /></>,
    certificates: <><path d="M12 2 4 5v7c0 5 3.5 8 8 10 4.5-2 8-5 8-10V5l-8-3Z" /><path d="m9 12 2 2 4-4" /></>,
    firewall: <><path d="M4 3h16v18H4V3ZM4 9h16M4 15h16M9 3v6m6 0v6m-6 0v6" /></>,
    forwards: <><path d="M3 7h12m0 0-3-3m3 3-3 3M21 17H9m0 0 3-3m-3 3 3 3" /></>,
    routes: <><circle cx="4" cy="12" r="2" /><circle cx="12" cy="12" r="2" /><circle cx="20" cy="12" r="2" /><path d="M6 12h4m4 0h4" /></>,
    subscriptions: <><path d="M4 7a13 13 0 0 1 13 13M4 12a8 8 0 0 1 8 8" /><circle cx="5" cy="19" r="1" fill="currentColor" stroke="none" /></>,
    customers: <><circle cx="9" cy="8" r="3" /><path d="M3 20v-2a6 6 0 0 1 12 0v2H3Z" /><circle cx="18" cy="9" r="2" /><path d="M17 15a5 5 0 0 1 4 5" /></>,
    operations: <><path d="M4 4v6h6M4.8 10a8 8 0 1 1-.2 5M12 7v5l3 2" /></>,
    settings: <><circle cx="12" cy="12" r="3" /><path d="M10 2h4l.6 2.2 2 .8 2-.9 2.8 2.8-.9 2 .8 2L23 11v4l-2.2.6-.8 2 .9 2-2.8 2.8-2-.9-2 .8L14 24h-4l-.6-2.2-2-.8-2 .9-2.8-2.8.9-2-.8-2L1 15v-4l2.2-.6.8-2-.9-2L6.9 3.6l2 .9 2-.8L10 2Z" transform="translate(0 -1) scale(1 .95)" /></>,
    help: <><path d="M3 4h7a4 4 0 0 1 4 4v13a4 4 0 0 0-4-2H3V4Zm18 0h-5a4 4 0 0 0-4 4v13a4 4 0 0 1 4-2h5V4Z" /></>,
    menu: <path d="M4 6h16M4 12h16M4 18h16" />,
    logout: <><path d="M10 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h5M14 17l5-5-5-5M19 12H9" /></>,
  };
  return <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name]}</svg>;
}
export function ConfirmDialog({
  confirmation,
  onCancel,
  onConfirm,
}: {
  confirmation: Confirmation;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const cancelButton = useRef<HTMLButtonElement>(null);
  const confirmButton = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    cancelButton.current?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onCancel();
      } else if (event.key === "Tab") {
        if (event.shiftKey && document.activeElement === cancelButton.current) {
          event.preventDefault();
          confirmButton.current?.focus();
        } else if (!event.shiftKey && document.activeElement === confirmButton.current) {
          event.preventDefault();
          cancelButton.current?.focus();
        }
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      previousFocus?.focus();
    };
  }, []);
  return (
    <div className="overlay confirmationOverlay" onMouseDown={(event) => {
      if (event.target === event.currentTarget) onCancel();
    }}>
      <div className="modal confirmModal" role="alertdialog" aria-modal="true" aria-labelledby="confirm-title" aria-describedby="confirm-message">
        <div className="modalHead">
          <h2 id="confirm-title">{confirmation.title}</h2>
        </div>
        <p className="confirmMessage" id="confirm-message">{confirmation.message}</p>
        <div className="confirmActions">
          <button type="button" className="ghost" ref={cancelButton} onClick={onCancel}>取消</button>
          <button type="button" className="primary" ref={confirmButton} onClick={onConfirm}>{confirmation.confirmLabel}</button>
        </div>
      </div>
    </div>
  );
}
export function HelpTip({ label, text, warning = false }: { label: string; text: string; warning?: boolean }) {
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLSpanElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const panel = useRef<HTMLSpanElement>(null);
  const [position, setPosition] = useState({ top: 0, left: 0 });
  const id = useId();
  useLayoutEffect(() => {
    if (!open || !button.current || !panel.current) return;
    const anchor = button.current.getBoundingClientRect();
    const width = panel.current.offsetWidth;
    const height = panel.current.offsetHeight;
    setPosition({
      left: Math.max(12, Math.min(anchor.left, window.innerWidth - width - 12)),
      top: anchor.bottom + height + 8 > window.innerHeight - 12 && anchor.top > height + 20 ? anchor.top - height - 8 : anchor.bottom + 8,
    });
  }, [open, text]);
  useEffect(() => {
    if (!open) return;
    const closeOutside = (event: PointerEvent) => {
      if (!root.current?.contains(event.target as globalThis.Node) && !panel.current?.contains(event.target as globalThis.Node)) setOpen(false);
    };
    const closeEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    const closeOnScroll = () => setOpen(false);
    document.addEventListener("pointerdown", closeOutside);
    document.addEventListener("keydown", closeEscape);
    document.addEventListener("scroll", closeOnScroll, true);
    window.addEventListener("resize", closeOnScroll);
    return () => {
      document.removeEventListener("pointerdown", closeOutside);
      document.removeEventListener("keydown", closeEscape);
      document.removeEventListener("scroll", closeOnScroll, true);
      window.removeEventListener("resize", closeOnScroll);
    };
  }, [open]);
  return <span className="helpTip" ref={root}>
    <button ref={button} type="button" className={`helpTipButton${warning ? " helpTipWarning" : ""}`} aria-label={warning ? label : `${label}说明`} aria-expanded={open} aria-controls={open ? id : undefined} aria-describedby={open ? id : undefined} onClick={() => setOpen(!open)}>{warning ? "!" : "?"}</button>
    {open && createPortal(<span className="helpTipPanel" id={id} role="tooltip" ref={panel} style={position}>{text}</span>, document.body)}
  </span>;
}
export const Field = memo(function Field({
  label,
  children,
  help,
}: {
  label: string;
  children: React.ReactNode;
  help?: string;
}) {
  const id = useId();
  if (help) {
    const controlId = React.isValidElement<{ id?: string }>(children) ? children.props.id || id : id;
    const control = React.isValidElement<{ id?: string }>(children) ? React.cloneElement(children, { id: controlId }) : children;
    return <div className="field">
      <div className="fieldLabelRow"><label htmlFor={controlId}>{label}</label><HelpTip label={label} text={help} /></div>
      {control}
    </div>;
  }
  return (
    <label className="field">
      <span>{label}</span>
      {children}
    </label>
  );
});
export const statusLabels: Record<string, [string, "good" | "bad" | "warn" | "idle"]> =
  {
    online: ["在线", "good"],
    active: ["正常", "good"],
    success: ["成功", "good"],
    offline: ["离线", "bad"],
    "offline-managed": ["离线管理", "idle"],
    external: ["外部节点", "idle"],
    "offline-export-pending": ["配置待导出", "warn"],
    "offline-disable-export-pending": ["停用待导出", "warn"],
    "offline-delete-pending": ["删除待导出", "warn"],
    "offline-exported": ["配置已导出", "idle"],
    "offline-disabled-exported": ["停用已导出", "idle"],
    exported: ["离线配置已导出", "idle"],
    failed: ["失败", "bad"],
    error: ["出错", "bad"],
    unavailable: ["不可用", "bad"],
    conflict: ["冲突", "bad"],
    pending: ["等待中", "warn"],
    queued: ["排队中", "warn"],
    running: ["执行中", "warn"],
    activating: ["等待新版上线", "warn"],
    upgrading: ["升级中", "warn"],
    updating: ["更新中", "warn"],
    revoked: ["已吊销", "bad"],
    deleting: ["删除中", "warn"],
    inactive: ["未启用", "warn"],
    manual: ["手动管理", "idle"],
    disabled: ["已停用", "idle"],
    expired: ["已到期", "idle"],
    partial: ["部分生效", "warn"],
    superseded: ["已被替代", "idle"],
    idle: ["空闲", "idle"],
    unsupported: ["不支持", "idle"],
    unknown: ["未知", "idle"],
  };
export const Status = memo(function Status({ value }: { value: string }) {
  const [label, tone] = statusLabels[value] || [value || "未知", "idle"];
  return <span className={"status " + tone}>{label}</span>;
});
export const kindLabels: Record<string, string> = {
  "agent.upgrade": "升级 Agent",
  "core.upgrade": "升级 sing-box",
  "nodes.apply": "应用节点配置",
  "subscriptions.apply": "应用订阅用户",
  "forwards.apply": "应用转发规则",
  "firewall.apply": "应用防火墙规则",
  "ufw.init": "初始化 UFW",
  "ufw.delete": "删除主机规则",
};
export function kindLabel(kind: string) {
  return kindLabels[kind] || kind;
}
export function localDate(d: Date) {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}
export type LogRange = { from: string; to: string }; // dates as YYYY-MM-DD, "" for open
export const noRange: LogRange = { from: "", to: "" };
// Whole local days: from the start of the first to the end of the last.
function rangeQuery(range: LogRange) {
  let q = "";
  if (range.from) q += "&fromMs=" + new Date(range.from + "T00:00:00").getTime();
  if (range.to) q += "&toMs=" + new Date(range.to + "T23:59:59.999").getTime();
  return q;
}
export type PagedLog<T> = {
  items: T[]; total: number; page: number; pageSize: number; busy: boolean; empty: boolean;
  setPage: (page: number) => void; setPageSize: (size: number) => void; reload: () => void;
};

// usePagedLog shows a log one numbered page at a time, counted on the server.
// `base` is the listing URL with its filters, or null while the list is not on
// screen; changing it or the date range goes back to the first page.
export function usePagedLog<T>(base: string | null, range: LogRange, onError: (e: Error) => void, refreshTick = 0, pollTick = 0): PagedLog<T> {
  const [items, setItems] = useState<T[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [busy, setBusy] = useState(false);
  // Known to be empty only once a page has actually come back.
  const [loaded, setLoaded] = useState(false);
  const request = useRef(0);
  const filters = base === null ? null : base + rangeQuery(range);
  const url = filters === null ? null : `${filters}&page=${page}&pageSize=${pageSize}`;
  const load = () => {
    if (!url) return;
    const current = ++request.current;
    setBusy(true);
    api<{ items?: T[]; total?: number }>(url)
      .then((body) => {
        // A newer request (another page, filter or refresh) has taken over.
        if (current !== request.current) return;
        setItems(body.items ?? []);
        setTotal(body.total ?? 0);
        setLoaded(true);
      })
      .catch((e) => { if (current === request.current) onError(e as Error); })
      .finally(() => { if (current === request.current) setBusy(false); });
  };
  useEffect(() => { setPage(1); }, [filters]);
  useEffect(() => { load(); }, [url, refreshTick]);
  // Leave a list alone once the reader has paged into older entries.
  useEffect(() => { if (pollTick && page === 1) load(); }, [pollTick]);
  return {
    items, total, page, pageSize, busy, empty: loaded && !busy && !items.length,
    setPage, setPageSize: (size) => { setPageSize(size); setPage(1); }, reload: load,
  };
}

// Pager: total, numbered pages around the current one, and the page size.
export function Pager<T>({ log }: { log: PagedLog<T> }) {
  if (!log.total) return null;
  const pages = Math.max(1, Math.ceil(log.total / log.pageSize));
  const shown = [...new Set([1, log.page - 2, log.page - 1, log.page, log.page + 1, log.page + 2, pages])]
    .filter((p) => p >= 1 && p <= pages)
    .sort((a, b) => a - b);
  return (
    <div className="pager">
      <span className="hint">共 {log.total} 条，第 {log.page} / {pages} 页</span>
      <div className="pages">
        <button className="ghost" disabled={log.busy || log.page <= 1} onClick={() => log.setPage(log.page - 1)}>上一页</button>
        {shown.map((p, i) => (
          <React.Fragment key={p}>
            {i > 0 && p - shown[i - 1] > 1 && <span className="hint">…</span>}
            <button className={p === log.page ? "primary" : "ghost"} disabled={log.busy} aria-current={p === log.page ? "page" : undefined} onClick={() => log.setPage(p)}>{p}</button>
          </React.Fragment>
        ))}
        <button className="ghost" disabled={log.busy || log.page >= pages} onClick={() => log.setPage(log.page + 1)}>下一页</button>
        <select value={log.pageSize} onChange={(e) => log.setPageSize(Number(e.target.value))} aria-label="每页条数">
          {[20, 50, 100, 200].map((n) => <option key={n} value={n}>{n} 条/页</option>)}
        </select>
      </div>
    </div>
  );
}

// DateRange filters a log by whole days; either end may stay open.
export function DateRange({ value, onChange, label = "日期" }: { value: LogRange; onChange: (v: LogRange) => void; label?: string }) {
  return (
    <span className="dateRange">
      <input type="date" aria-label={`${label}起`} value={value.from} max={value.to || undefined} onChange={(e) => onChange({ ...value, from: e.target.value })} />
      <span className="hint">至</span>
      <input type="date" aria-label={`${label}止`} value={value.to} min={value.from || undefined} onChange={(e) => onChange({ ...value, to: e.target.value })} />
      {(value.from || value.to) && <button type="button" className="textButton" onClick={() => onChange(noRange)}>清除日期</button>}
    </span>
  );
}

// ActionMenu keeps a row's occasional and destructive actions one click away.
// The list is positioned against the viewport rather than the table, whose
// horizontal scroll container would clip an ordinary absolutely placed menu.
export function ActionMenu({ children }: { children: React.ReactNode }) {
  const [place, setPlace] = useState<React.CSSProperties | null>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const list = useRef<HTMLDivElement>(null);
  const items = () =>
    Array.from(list.current?.querySelectorAll<HTMLButtonElement>("button:not(:disabled)") || []);
  const close = (refocus = false) => {
    setPlace(null);
    if (refocus) trigger.current?.focus();
  };
  const toggle = () => {
    if (place) return close();
    const box = trigger.current!.getBoundingClientRect();
    const right = Math.max(8, window.innerWidth - box.right);
    // Open upwards when the row sits near the bottom of the window.
    setPlace(
      window.innerHeight - box.bottom < 260 && box.top > window.innerHeight - box.bottom
        ? { right, bottom: window.innerHeight - box.top + 4 }
        : { right, top: box.bottom + 4 },
    );
  };
  useEffect(() => {
    if (!place) return;
    // preventScroll: moving focus must not itself cause the scroll that dismisses the list.
    items()[0]?.focus({ preventScroll: true });
    const outside = (event: MouseEvent) => {
      const target = event.target as globalThis.Node;
      if (!list.current?.contains(target) && !trigger.current?.contains(target)) close();
    };
    const dismiss = (event: Event) => {
      if (event.target instanceof globalThis.Node && list.current?.contains(event.target)) return;
      close();
    };
    document.addEventListener("mousedown", outside);
    // A fixed list would otherwise stay put while its row scrolls away.
    window.addEventListener("scroll", dismiss, true);
    window.addEventListener("resize", dismiss);
    return () => {
      document.removeEventListener("mousedown", outside);
      window.removeEventListener("scroll", dismiss, true);
      window.removeEventListener("resize", dismiss);
    };
  }, [place]);
  const onKeyDown = (event: React.KeyboardEvent) => {
    if (event.key === "Escape") {
      event.stopPropagation();
      return close(true);
    }
    if (event.key !== "ArrowDown" && event.key !== "ArrowUp") return;
    event.preventDefault();
    const all = items();
    const at = all.indexOf(document.activeElement as HTMLButtonElement);
    all[(at + (event.key === "ArrowDown" ? 1 : all.length - 1)) % all.length]?.focus();
  };
  return (
    <span className="actionMenu">
      <button type="button" ref={trigger} aria-haspopup="menu" aria-expanded={!!place} onClick={toggle}>
        更多
      </button>
      {place && (
        <div className="menuList" role="menu" ref={list} style={place} onClick={() => close()} onKeyDown={onKeyDown}>
          {children}
        </div>
      )}
    </span>
  );
}
export const Empty = memo(function Empty({ text }: { text: string }) {
  return <div className="empty">{text}</div>;
});

// Mirrors each column's heading onto its cells, which the narrow-screen card
// layout prints in place of the table header it hides.
export function TableWrap({ children, cards = true }: { children: React.ReactNode; cards?: boolean }) {
  const root = useRef<HTMLDivElement>(null);
  useLayoutEffect(() => {
    if (!cards) return;
    root.current?.querySelectorAll("table").forEach((table) => {
      const headings = Array.from(table.querySelectorAll("thead th"), (th) => th.textContent?.trim() || "");
      table.querySelectorAll("tbody tr").forEach((row) => {
        Array.from(row.children).forEach((cell, index) => cell.setAttribute("data-label", headings[index] || ""));
      });
    });
  });
  return <div className={"tableWrap" + (cards ? " cardTable" : "")} ref={root}>{children}</div>;
}

// Sorting is one URL parameter such as "name" or "-traffic" (descending).
export type SortState = { key: string; descending: boolean; toggle: (key: string) => void };
export function parseSort(value: string, set: (value: string) => void, fallback = ""): SortState {
  const current = value || fallback;
  const descending = current.startsWith("-");
  const key = descending ? current.slice(1) : current;
  return {
    key, descending,
    toggle: (next) => set(key !== next ? next : descending ? "" : "-" + next),
  };
}
export function SortHeader({ sort, id, label, title, className }: { sort: SortState; id: string; label: string; title?: string; className?: string }) {
  const active = sort.key === id;
  return <th className={className} title={title} aria-sort={active ? (sort.descending ? "descending" : "ascending") : "none"}>
    <button type="button" className="sortButton" onClick={() => sort.toggle(id)}>
      {label}<span aria-hidden="true">{active ? (sort.descending ? " ↓" : " ↑") : ""}</span>
    </button>
  </th>;
}
export const collator = new Intl.Collator("zh-Hans-CN", { numeric: true, sensitivity: "base" });
export function sortRows<T>(rows: T[], sort: SortState, values: Record<string, (row: T) => string | number>): T[] {
  const value = values[sort.key];
  if (!value) return rows;
  const direction = sort.descending ? -1 : 1;
  return [...rows].sort((a, b) => {
    const x = value(a), y = value(b);
    return direction * (typeof x === "number" && typeof y === "number" ? x - y : collator.compare(String(x), String(y)));
  });
}

// Selection for batch actions. Rows that left the list drop out by themselves.
export function useSelection(visibleIds: string[]) {
  const [picked, setPicked] = useState<string[]>([]);
  const selected = picked.filter((id) => visibleIds.includes(id));
  return {
    selected,
    has: (id: string) => selected.includes(id),
    toggle: (id: string) => setPicked(selected.includes(id) ? selected.filter((v) => v !== id) : [...selected, id]),
    all: visibleIds.length > 0 && selected.length === visibleIds.length,
    toggleAll: () => setPicked(selected.length === visibleIds.length ? [] : visibleIds),
    clear: () => setPicked([]),
  };
}

// A form's submit button. `busy` keeps a slow save from being sent twice.
export function SubmitButton({ busy, label, disabled, className = "primary submit" }: { busy: boolean; label: string; disabled?: boolean; className?: string }) {
  return <button className={className} type="submit" disabled={busy || disabled} aria-busy={busy}>{busy ? "保存中…" : label}</button>;
}
export function useBusy() {
  const running = useRef(false);
  const [busy, setBusy] = useState(false);
  const run = async <T,>(task: () => Promise<T>): Promise<T | undefined> => {
    if (running.current) return undefined;
    running.current = true;
    setBusy(true);
    try {
      return await task();
    } finally {
      running.current = false;
      setBusy(false);
    }
  };
  return { busy, run };
}

// Optional settings stay folded. A field that fails validation or already has
// a non-default value must not stay hidden, so both open the section.
export function Advanced({ title, open: initiallyOpen = false, children }: { title: string; open?: boolean; children: React.ReactNode }) {
  const [open, setOpen] = useState(initiallyOpen);
  return <details className="advanced" open={open}
    onToggle={(e) => setOpen(e.currentTarget.open)}
    // Synchronous: the browser focuses the invalid field right after this event.
    onInvalidCapture={(e) => { e.currentTarget.open = true; setOpen(true); }}>
    <summary>{title}</summary>
    <div className="advancedBody">{children}</div>
  </details>;
}

// The frame shared by the editing dialogs. Unsaved input survives a stray
// click outside or Escape: leaving then asks first.
export function ModalShell({ title, labelledBy = "edit-modal-title", dirty, busy = false, onClose, onConfirm, feedback, wide, children }: {
  title: string; labelledBy?: string; dirty: boolean; busy?: boolean; onClose: () => void;
  onConfirm: (confirmation: Confirmation) => void; feedback?: React.ReactNode; wide?: boolean; children: React.ReactNode;
}) {
  const box = useRef<HTMLDivElement>(null);
  const request = useRef(() => {});
  request.current = () => {
    if (busy) return;
    if (!dirty) return onClose();
    onConfirm({ title: "放弃修改", message: "填写的内容还没有保存，确定放弃吗？", confirmLabel: "放弃修改", onConfirm: onClose });
  };
  useEffect(() => {
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    if (!box.current?.contains(document.activeElement)) box.current?.querySelector<HTMLElement>("input:not([type=hidden]):not(:disabled), select:not(:disabled), textarea:not(:disabled)")?.focus({ preventScroll: true });
    return () => previousFocus?.focus({ preventScroll: true });
  }, []);
  return <div className="overlay" onMouseDown={(e) => { if (e.target === e.currentTarget) request.current(); }}
    onKeyDown={(e) => {
      // A confirmation, tooltip or menu on top handles its own Escape.
      if (e.key === "Escape" && !e.defaultPrevented && !document.querySelector(".confirmationOverlay, .menuList, .helpTipPanel, .pickerPanel")) { e.preventDefault(); request.current(); }
    }}>
    <div className={"modal" + (wide ? " installModal" : "")} role="dialog" aria-modal="true" aria-labelledby={labelledBy} ref={box}>
      <div className="modalHead">
        <div><h2 id={labelledBy}>{title}</h2></div>
        <button type="button" className="closeButton" aria-label="关闭" onClick={() => request.current()}>×</button>
      </div>
      {feedback}
      {children}
    </div>
  </div>;
}
