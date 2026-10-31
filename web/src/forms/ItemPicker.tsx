import { useEffect, useRef, useState } from "react";
import { useApp } from "../app/context";

export type PickerItem = {
  id: string;
  name: string;
  details?: string[];
  // Why it cannot be chosen, or why a chosen one no longer works.
  issue?: string;
};

// The chosen items in order, with the full list floating above the form only
// while choosing. It runs its own screenshot pass: nothing here is part of the
// form's element tree. Not inside a <label>, which would forward clicks.
export function ItemPicker({ label, emptyText, addText, noneText, items, selected, onChange, compact = false }: {
  label: string; emptyText: string; addText: string; noneText: string; items: PickerItem[];
  selected: string[]; onChange: (ids: string[]) => void; compact?: boolean;
}) {
  const { protect } = useApp();
  const [place, setPlace] = useState<React.CSSProperties | null>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const panel = useRef<HTMLDivElement>(null);
  const close = (refocus = false) => {
    setPlace(null);
    if (refocus) trigger.current?.focus();
  };
  const toggle = () => {
    if (place) return close();
    const box = trigger.current!.getBoundingClientRect();
    const width = compact ? 300 : 420, height = 320;
    const left = Math.max(8, Math.min(box.left, window.innerWidth - width - 8));
    const below = window.innerHeight - box.bottom - 12;
    setPlace(below >= 160 || below >= box.top - 12
      ? { left, width, top: box.bottom + 4, maxHeight: Math.min(height, below) }
      : { left, width, bottom: window.innerHeight - box.top + 4, maxHeight: Math.min(height, box.top - 12) });
  };
  useEffect(() => {
    if (!place) return;
    panel.current?.querySelector<HTMLInputElement>("input:not(:disabled)")?.focus({ preventScroll: true });
    const outside = (event: MouseEvent) => {
      const target = event.target as globalThis.Node;
      if (!panel.current?.contains(target) && !trigger.current?.contains(target)) close();
    };
    // A fixed panel would otherwise stay put while the form scrolls away.
    const dismiss = (event: Event) => {
      if (!(event.target instanceof globalThis.Node && panel.current?.contains(event.target))) close();
    };
    document.addEventListener("mousedown", outside);
    window.addEventListener("scroll", dismiss, true);
    window.addEventListener("resize", dismiss);
    return () => {
      document.removeEventListener("mousedown", outside);
      window.removeEventListener("scroll", dismiss, true);
      window.removeEventListener("resize", dismiss);
    };
  }, [place]);
  const item = (id: string) => items.find((candidate) => candidate.id === id);
  const broken = selected.flatMap((id) => { const chosen = item(id); return chosen?.issue ? [chosen] : []; });
  return protect(<div className="itemPicker" onKeyDown={(e) => { if (e.key === "Escape" && place) { e.preventDefault(); e.stopPropagation(); close(true); } }}>
    <div className="itemPickerRow">
      {selected.map((id) => <span className={"serverChip" + (item(id)?.issue ? " chipIssue" : "")} key={id}>
        {item(id)?.name || id.slice(0, 8)}
        <button type="button" aria-label={`移除 ${item(id)?.name || id.slice(0, 8)}`} onClick={() => onChange(selected.filter((value) => value !== id))}>×</button>
      </span>)}
      {!selected.length && <span className="hint">{emptyText}</span>}
      <button type="button" className="ghost" ref={trigger} aria-haspopup="true" aria-expanded={!!place} aria-label={label} onClick={toggle}>{selected.length ? "修改" : addText}</button>
    </div>
    {broken.map((chosen) => <small className="routeChoiceIssue" key={chosen.id}>{chosen.name}：{chosen.issue}；请移除或调整配置</small>)}
    {place && <div className={"pickerPanel" + (compact ? " pickerCompact" : "")} role="group" aria-label={label} ref={panel} style={place}>
      {items.map((candidate) => {
        const chosen = selected.includes(candidate.id);
        return <label className="check" key={candidate.id}>
          <input type="checkbox" checked={chosen} disabled={!!candidate.issue && !chosen} onChange={(e) => onChange(e.target.checked ? [...selected, candidate.id] : selected.filter((id) => id !== candidate.id))} />
          <span className="pickerText">
            <span>{candidate.name}</span>
            {candidate.details?.map((detail) => <small key={detail}>{detail}</small>)}
            {candidate.issue && <small className="routeChoiceIssue">{candidate.issue}</small>}
          </span>
        </label>;
      })}
      {!items.length && <p className="hint">{noneText}</p>}
    </div>}
  </div>);
}
