package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maxStatusTitleRunes       = 60
	maxStatusDescriptionRunes = 300
)

type storedStatusPageSettings struct {
	Enabled     bool   `json:"enabled"`
	Title       string `json:"title"`
	Description string `json:"description"`
	ShowTraffic bool   `json:"showTraffic"`
	ShowPing    bool   `json:"showPing"`
}

type StatusPageSettingsResponse struct {
	Enabled          bool   `json:"enabled"`
	Title            string `json:"title"`
	Description      string `json:"description"`
	ShowTraffic      bool   `json:"showTraffic"`
	ShowPing         bool   `json:"showPing"`
	ListenConfigured bool   `json:"listenConfigured"`
	StatusURL        string `json:"statusUrl"`
}

type statusPageSettingsInput struct {
	Enabled     *bool   `json:"enabled"`
	Title       *string `json:"title"`
	Description *string `json:"description"`
	ShowTraffic *bool   `json:"showTraffic"`
	ShowPing    *bool   `json:"showPing"`
}

func defaultStoredStatusPageSettings() storedStatusPageSettings {
	return storedStatusPageSettings{
		Enabled:     false,
		Title:       "服务状态",
		Description: "",
		ShowTraffic: true,
		ShowPing:    true,
	}
}

func parseStatusURL(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", nil
	}
	u, err := url.Parse(s)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(s, "#") || u.Opaque != "" {
		return "", fmt.Errorf("MUI_STATUS_URL contains an invalid HTTP(S) URL: %q", raw)
	}
	u.Host = canonicalPublicHost(u.Host, u.Scheme)
	if u.Host == "" {
		return "", fmt.Errorf("MUI_STATUS_URL contains an invalid host: %q", raw)
	}
	u.Path, u.RawPath = strings.TrimRight(u.Path, "/"), strings.TrimRight(u.RawPath, "/")
	return u.String(), nil
}

func normalizeStatusTitle(raw string) (string, error) {
	clean := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == '\t' {
			return ' '
		}
		return r
	}, raw)
	clean = strings.TrimSpace(clean)
	if utf8.RuneCountInString(clean) > maxStatusTitleRunes {
		return "", fmt.Errorf("标题不能超过 %d 个字符", maxStatusTitleRunes)
	}
	if clean == "" {
		clean = "服务状态"
	}
	return clean, nil
}

func normalizeStatusDescription(raw string) (string, error) {
	clean := strings.ReplaceAll(raw, "\r\n", "\n")
	clean = strings.ReplaceAll(clean, "\r", "\n")
	clean = strings.TrimSpace(clean)
	if utf8.RuneCountInString(clean) > maxStatusDescriptionRunes {
		return "", fmt.Errorf("说明不能超过 %d 个字符", maxStatusDescriptionRunes)
	}
	return clean, nil
}

func (s *Store) loadStoredStatusPageSettings() (storedStatusPageSettings, error) {
	cfg := defaultStoredStatusPageSettings()
	var raw string
	err := s.DB.QueryRow(`SELECT value FROM mui_settings WHERE key='status_page'`).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return defaultStoredStatusPageSettings(), nil
	}
	if strings.TrimSpace(cfg.Title) == "" {
		cfg.Title = "服务状态"
	}
	return cfg, nil
}

func (s *Store) saveStoredStatusPageSettings(cfg storedStatusPageSettings) error {
	_, err := s.DB.Exec(
		`INSERT INTO mui_settings(key,value) VALUES('status_page',$1) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		Marshal(cfg),
	)
	return err
}

func (a *App) cachedStatusPageSettings() (storedStatusPageSettings, error) {
	a.statusCacheMu.RLock()
	if a.statusCfgLoaded {
		cfg := a.statusCfg
		a.statusCacheMu.RUnlock()
		return cfg, nil
	}
	a.statusCacheMu.RUnlock()

	cfg, err := a.Store.loadStoredStatusPageSettings()
	if err != nil {
		return cfg, err
	}
	a.statusCacheMu.Lock()
	if !a.statusCfgLoaded {
		a.statusCfg = cfg
		a.statusCfgLoaded = true
	} else {
		cfg = a.statusCfg
	}
	a.statusCacheMu.Unlock()
	return cfg, nil
}

func (a *App) invalidatePublicStatusCache() {
	a.statusCacheMu.Lock()
	a.statusCacheGen++
	a.statusCfgLoaded = false
	a.statusSnapshotBody = nil
	a.statusSnapshotExpires = time.Time{}
	a.statusPingSummary = publicPingSummary{}
	a.statusPingExpires = time.Time{}
	a.statusPingCacheReady = false
	a.statusHistoryCache = nil
	a.statusCacheMu.Unlock()
}

func (a *App) invalidatePublicStatusSnapshot() {
	a.statusCacheMu.Lock()
	a.statusCacheGen++
	a.statusSnapshotBody = nil
	a.statusSnapshotExpires = time.Time{}
	a.statusPingSummary = publicPingSummary{}
	a.statusPingExpires = time.Time{}
	a.statusPingCacheReady = false
	a.statusHistoryCache = nil
	a.statusCacheMu.Unlock()
}

func (a *App) toStatusPageSettingsResponse(cfg storedStatusPageSettings) StatusPageSettingsResponse {
	return StatusPageSettingsResponse{
		Enabled:          cfg.Enabled,
		Title:            cfg.Title,
		Description:      cfg.Description,
		ShowTraffic:      cfg.ShowTraffic,
		ShowPing:         cfg.ShowPing,
		ListenConfigured: a.statusListenConfigured,
		StatusURL:        a.statusURL,
	}
}

func (a *App) statusPageSetting(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		cfg, err := a.Store.loadStoredStatusPageSettings()
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, a.toStatusPageSettingsResponse(cfg))
		return
	}

	var in statusPageSettingsInput
	if !readJSON(w, r, &in) {
		return
	}

	cfg, err := a.Store.loadStoredStatusPageSettings()
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if in.Enabled != nil {
		cfg.Enabled = *in.Enabled
	}
	if in.Title != nil {
		title, err := normalizeStatusTitle(*in.Title)
		if err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
		cfg.Title = title
	}
	if in.Description != nil {
		desc, err := normalizeStatusDescription(*in.Description)
		if err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
		cfg.Description = desc
	}
	if in.ShowTraffic != nil {
		cfg.ShowTraffic = *in.ShowTraffic
	}
	if in.ShowPing != nil {
		cfg.ShowPing = *in.ShowPing
	}

	if err := a.Store.saveStoredStatusPageSettings(cfg); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.statusCacheMu.Lock()
	a.statusCacheGen++
	a.statusCfg = cfg
	a.statusCfgLoaded = true
	a.statusSnapshotBody = nil
	a.statusSnapshotExpires = time.Time{}
	a.statusPingSummary = publicPingSummary{}
	a.statusPingExpires = time.Time{}
	a.statusPingCacheReady = false
	a.statusHistoryCache = nil
	a.statusCacheMu.Unlock()

	detail := fmt.Sprintf("enabled=%v showTraffic=%v showPing=%v", cfg.Enabled, cfg.ShowTraffic, cfg.ShowPing)
	a.auditRequest(r, "settings.status_page", "status_page", detail)
	writeJSON(w, 200, a.toStatusPageSettingsResponse(cfg))
}
