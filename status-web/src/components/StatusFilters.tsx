import { memo, useEffect, useRef, useState } from "react";
import { countryFlag } from "../monitor/format";

export type GroupFilterOption = {
  value: string;
  label: string;
};

export type RegionFilterOption = {
  code: string;
  count: number;
};

function SearchIcon() {
  return (
    <svg
      width="13"
      height="13"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.1"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <circle cx="11" cy="11" r="8" />
      <path d="m21 21-4.3-4.3" />
    </svg>
  );
}

export const StatusFilters = memo(function StatusFilters({
  groupOptions,
  groupFilter,
  onGroupChange,
  regionOptions,
  countryFilter,
  onCountryChange,
  search,
  onSearchChange,
}: {
  groupOptions: GroupFilterOption[];
  groupFilter: string;
  onGroupChange: (next: string) => void;
  regionOptions: RegionFilterOption[];
  countryFilter: string;
  onCountryChange: (next: string) => void;
  search: string;
  onSearchChange: (next: string) => void;
}) {
  const [searchOpen, setSearchOpen] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const isSearchExpanded = searchOpen || Boolean(search);

  useEffect(() => {
    if (!searchOpen) return;
    const frame = window.requestAnimationFrame(() => {
      inputRef.current?.focus();
    });
    return () => window.cancelAnimationFrame(frame);
  }, [searchOpen]);

  return (
    <div
      className="statusToolbarInner"
      data-search-open={isSearchExpanded ? "true" : "false"}
    >
      <span className="statusToolbarSpacer" aria-hidden="true" />

      <div className="statusToolbarCenter">
        <div className="home-group-tabs" role="tablist" aria-label="服务器分组筛选">
          <button
            type="button"
            role="tab"
            aria-selected={groupFilter === ""}
            data-active={groupFilter === "" ? "true" : "false"}
            onClick={() => onGroupChange("")}
          >
            全部
          </button>
          {groupOptions.map((opt) => {
            const active = groupFilter === opt.value;
            return (
              <button
                key={opt.value}
                type="button"
                role="tab"
                aria-selected={active}
                data-active={active ? "true" : "false"}
                onClick={() => onGroupChange(active ? "" : opt.value)}
              >
                {opt.label}
              </button>
            );
          })}
        </div>

        {regionOptions.length > 0 && (
          <>
            <span className="statusToolbarDivider" aria-hidden="true" />
            <div className="home-region-chips" role="tablist" aria-label="国家与地区筛选">
              {regionOptions.map((region) => {
                const active = countryFilter === region.code;
                const flag = countryFlag(region.code);
                return (
                  <button
                    key={region.code}
                    type="button"
                    role="tab"
                    className="home-region-chip"
                    aria-selected={active}
                    data-active={active ? "true" : "false"}
                    onClick={() => onCountryChange(active ? "" : region.code)}
                  >
                    {flag && (
                      <span className="home-region-chip-flag" aria-hidden="true">
                        {flag}
                      </span>
                    )}
                    <span className="home-region-chip-code">{region.code}</span>
                    <span className="home-region-chip-count monTabular">{region.count}</span>
                  </button>
                );
              })}
            </div>
          </>
        )}
      </div>

      <div className="statusToolbarRight">
        <button
          type="button"
          className="statusSearchTrigger"
          aria-label="展开搜索"
          aria-expanded={isSearchExpanded}
          onClick={() => setSearchOpen(true)}
        >
          <SearchIcon />
        </button>

        <label className="statusSearchBox" data-has-value={search ? "true" : "false"}>
          <SearchIcon />
          <input
            ref={inputRef}
            type="search"
            className="statusSearchInput"
            placeholder="搜索节点…"
            aria-label="搜索节点"
            value={search}
            onChange={(e) => onSearchChange(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Escape") {
                onSearchChange("");
                setSearchOpen(false);
                inputRef.current?.blur();
              }
            }}
            onBlur={() => {
              if (!search) {
                setSearchOpen(false);
              }
            }}
          />
          <button
            type="button"
            className="statusSearchClear"
            aria-label={search ? "清空搜索" : "收起搜索"}
            onMouseDown={(e) => e.preventDefault()}
            onClick={() => {
              onSearchChange("");
              setSearchOpen(false);
              inputRef.current?.blur();
            }}
          >
            ×
          </button>
        </label>
      </div>
    </div>
  );
});
