package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"mui/internal/shared"
)

const (
	maxStatusTitleRunes       = 60
	maxStatusDescriptionRunes = 300
	maxPublicMonitorPoints    = 720
	publicStatusCacheTTL      = 2 * time.Second
	publicHistoryCacheTTL     = 30 * time.Second
	maxPublicHistoryEntries   = 512
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

type PublicMonitorSample struct {
	At           time.Time `json:"at"`
	CPU          float64   `json:"cpu"`
	Load1        float64   `json:"load1"`
	Load5        float64   `json:"load5"`
	Load15       float64   `json:"load15"`
	RAMUsed      int64     `json:"ramUsed"`
	RAMTotal     int64     `json:"ramTotal"`
	SwapUsed     int64     `json:"swapUsed"`
	SwapTotal    int64     `json:"swapTotal"`
	DiskUsed     int64     `json:"diskUsed"`
	DiskTotal    int64     `json:"diskTotal"`
	NetUp        int64     `json:"netUp"`
	NetDown      int64     `json:"netDown"`
	NetTotalUp   *int64    `json:"netTotalUp,omitempty"`
	NetTotalDown *int64    `json:"netTotalDown,omitempty"`
	TCP          int       `json:"tcp"`
	UDP          int       `json:"udp"`
	Process      int       `json:"process"`
	Uptime       int64     `json:"uptime"`
}

type PublicCycleTraffic struct {
	StartAt time.Time `json:"startAt"`
	ResetAt time.Time `json:"resetAt"`
	Used    int64     `json:"used"`
	Limit   int64     `json:"limit"`
	Type    string    `json:"type"`
}

type PublicServerItem struct {
	ID             string               `json:"id"`
	Name           string               `json:"name"`
	Group          string               `json:"group"`
	Country        string               `json:"country"`
	Region         string               `json:"region,omitempty"`
	City           string               `json:"city,omitempty"`
	Online         bool                 `json:"online"`
	HostMonitor    bool                 `json:"hostMonitor"`
	OS             string               `json:"os,omitempty"`
	Arch           string               `json:"arch,omitempty"`
	Virtualization string               `json:"virtualization,omitempty"`
	CPUName        string               `json:"cpuName,omitempty"`
	CPUCores       int                  `json:"cpuCores,omitempty"`
	MemTotal       int64                `json:"memTotal,omitempty"`
	SwapTotal      int64                `json:"swapTotal,omitempty"`
	DiskTotal      int64                `json:"diskTotal,omitempty"`
	Sample         *PublicMonitorSample `json:"sample,omitempty"`
	CycleTraffic   *PublicCycleTraffic  `json:"cycleTraffic,omitempty"`
	ExpiresAt      *time.Time           `json:"expiresAt,omitempty"`
	PublicNote     string               `json:"publicNote,omitempty"`
}

type PublicStatusResponse struct {
	Title       string             `json:"title"`
	Description string             `json:"description"`
	ShowTraffic bool               `json:"showTraffic"`
	ShowPing    bool               `json:"showPing"`
	GeneratedAt time.Time          `json:"generatedAt"`
	Servers     []PublicServerItem `json:"servers"`
}

type PublicMonitorRecord struct {
	At          time.Time `json:"at"`
	CPU         float64   `json:"cpu"`
	Load1       float64   `json:"load1"`
	RAMUsed     int64     `json:"ramUsed"`
	RAMTotal    int64     `json:"ramTotal"`
	SwapUsed    int64     `json:"swapUsed"`
	DiskUsed    int64     `json:"diskUsed"`
	DiskTotal   int64     `json:"diskTotal"`
	NetUp       int64     `json:"netUp"`
	NetDown     int64     `json:"netDown"`
	NetUpPeak   int64     `json:"netUpPeak"`
	NetDownPeak int64     `json:"netDownPeak"`
	TotalUp     *int64    `json:"totalUp,omitempty"`
	TotalDown   *int64    `json:"totalDown,omitempty"`
	TCP         int       `json:"tcp"`
	UDP         int       `json:"udp"`
	Process     int       `json:"process"`
}

type PublicPingPoint struct {
	At    time.Time `json:"at"`
	MsAvg int       `json:"msAvg"`
	MsMax int       `json:"msMax"`
	Sent  int       `json:"sent"`
	Lost  int       `json:"lost"`
}

type PublicPingTaskSeries struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	IntervalSeconds int               `json:"intervalSeconds"`
	Records         []PublicPingPoint `json:"records"`
}

type publicHistoryCacheEntry struct {
	body      []byte
	expiresAt time.Time
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
	a.statusCfgLoaded = false
	a.statusSnapshotBody = nil
	a.statusSnapshotExpires = time.Time{}
	a.statusHistoryCache = nil
	a.statusCacheMu.Unlock()
}

func (a *App) invalidatePublicStatusSnapshot() {
	a.statusCacheMu.Lock()
	a.statusSnapshotBody = nil
	a.statusSnapshotExpires = time.Time{}
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
	a.statusCfg = cfg
	a.statusCfgLoaded = true
	a.statusSnapshotBody = nil
	a.statusSnapshotExpires = time.Time{}
	a.statusHistoryCache = nil
	a.statusCacheMu.Unlock()

	detail := fmt.Sprintf("enabled=%v showTraffic=%v showPing=%v", cfg.Enabled, cfg.ShowTraffic, cfg.ShowPing)
	a.auditRequest(r, "settings.status_page", "status_page", detail)
	writeJSON(w, 200, a.toStatusPageSettingsResponse(cfg))
}

// StatusHandler returns the isolated HTTP handler bound to MUI_STATUS_LISTEN.
// It registers ONLY /api/public/* and /healthz; every other route and non-GET
// method returns 404.
func (a *App) StatusHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/public/status", a.publicStatus)
	mux.HandleFunc("GET /api/public/servers/{publicId}/records", a.publicServerRecords)
	mux.HandleFunc("GET /api/public/servers/{publicId}/pings", a.publicServerPings)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{"status": "ok"})
	})
	return a.StatusSecurityHeaders(mux)
}

func (a *App) StatusSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Robots-Tag", "noindex")
		if a.requestScheme(r) == "https" {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func validPublicID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func validPublicRange(raw string) (string, bool) {
	switch strings.TrimSpace(raw) {
	case "", "24h":
		return "24h", true
	case "1h":
		return "1h", true
	case "6h":
		return "6h", true
	case "7d":
		return "7d", true
	default:
		return "", false
	}
}

func (a *App) checkPublicStatusGate(w http.ResponseWriter, r *http.Request) (storedStatusPageSettings, bool) {
	if !a.statusListenConfigured {
		http.NotFound(w, r)
		return storedStatusPageSettings{}, false
	}
	cfg, err := a.cachedStatusPageSettings()
	if err != nil {
		errorJSON(w, 500, "internal error")
		return storedStatusPageSettings{}, false
	}
	if !cfg.Enabled {
		http.NotFound(w, r)
		return storedStatusPageSettings{}, false
	}
	if a.rateCount(r, "status", 1) > 120 {
		errorJSON(w, 429, "请求过于频繁，请稍后再试")
		return storedStatusPageSettings{}, false
	}
	return cfg, true
}

func writeCachedJSONBytes(w http.ResponseWriter, cacheControl string, body []byte) {
	w.Header().Set("Cache-Control", cacheControl)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (a *App) resolvePublicServer(publicID string) (shared.Server, bool, error) {
	if !validPublicID(publicID) {
		return shared.Server{}, false, nil
	}
	servers, err := a.Store.Servers()
	if err != nil {
		return shared.Server{}, false, err
	}
	for _, s := range servers {
		if !s.PublicVisible || s.Status == "revoked" {
			continue
		}
		if a.Store.Fingerprint("status-page", s.ID) == publicID {
			return s, true, nil
		}
	}
	return shared.Server{}, false, nil
}

func publicDisplayName(s shared.Server) string {
	if p := strings.TrimSpace(s.PublicName); p != "" {
		return p
	}
	return strings.TrimSpace(s.Name)
}

func (a *App) publicStatus(w http.ResponseWriter, r *http.Request) {
	cfg, ok := a.checkPublicStatusGate(w, r)
	if !ok {
		return
	}
	now := a.nowMonitorUTC()

	a.statusCacheMu.RLock()
	if len(a.statusSnapshotBody) > 0 && now.Before(a.statusSnapshotExpires) {
		body := a.statusSnapshotBody
		a.statusCacheMu.RUnlock()
		writeCachedJSONBytes(w, "public, max-age=2", body)
		return
	}
	a.statusCacheMu.RUnlock()

	allServers, err := a.Store.Servers()
	if err != nil {
		errorJSON(w, 500, "internal error")
		return
	}
	visible := make([]shared.Server, 0, len(allServers))
	for _, s := range allServers {
		if s.PublicVisible && s.Status != "revoked" {
			visible = append(visible, s)
		}
	}
	slices.SortFunc(visible, func(x, y shared.Server) int {
		if x.SortWeight != y.SortWeight {
			if x.SortWeight > y.SortWeight {
				return -1
			}
			return 1
		}
		nx, ny := publicDisplayName(x), publicDisplayName(y)
		if nx != ny {
			return strings.Compare(nx, ny)
		}
		return strings.Compare(x.ID, y.ID)
	})

	hosts, err := a.Store.MonitorHosts()
	if err != nil {
		errorJSON(w, 500, "internal error")
		return
	}

	var cycleMap map[string]shared.CycleTrafficSummary
	if cfg.ShowTraffic && len(visible) > 0 {
		cycleMap, err = a.Store.CycleTrafficMap(visible, now)
		if err != nil {
			errorJSON(w, 500, "internal error")
			return
		}
	}

	a.monitorMu.RLock()
	samples := make(map[string]latestMonitorSample, len(a.latestSamples))
	for k, v := range a.latestSamples {
		samples[k] = v
	}
	a.monitorMu.RUnlock()

	items := make([]PublicServerItem, 0, len(visible))
	for _, s := range visible {
		publicID := a.Store.Fingerprint("status-page", s.ID)
		noAgent := shared.NoAgentManaged(s)
		entry, hasSample := samples[s.ID]
		host, hasHost := hosts[s.ID]

		online := false
		hostMonitor := false
		if !noAgent {
			seenOnline := s.LastSeen != nil && now.Sub(*s.LastSeen) <= 90*time.Second
			sampleOnline := hasSample && now.Sub(entry.receivedAt) <= 30*time.Second
			online = seenOnline || sampleOnline
			hostMonitor = s.HostMonitor || hasSample || hasHost
		}

		osName := strings.TrimSpace(host.OS)
		if osName == "" {
			osName = strings.TrimSpace(s.OS)
		}
		archName := strings.TrimSpace(host.Arch)
		if archName == "" {
			archName = strings.TrimSpace(s.Arch)
		}
		memTotal := host.MemTotal
		swapTotal := host.SwapTotal
		diskTotal := host.DiskTotal
		if hasSample && !noAgent {
			if memTotal == 0 {
				memTotal = entry.sample.RAMTotal
			}
			if swapTotal == 0 {
				swapTotal = entry.sample.SwapTotal
			}
			if diskTotal == 0 {
				diskTotal = entry.sample.DiskTotal
			}
		}

		item := PublicServerItem{
			ID:             publicID,
			Name:           publicDisplayName(s),
			Group:          strings.TrimSpace(s.Group),
			Country:        strings.ToUpper(strings.TrimSpace(s.Country)),
			Region:         strings.TrimSpace(s.Region),
			City:           strings.TrimSpace(s.City),
			Online:         online,
			HostMonitor:    hostMonitor,
			OS:             osName,
			Arch:           archName,
			Virtualization: strings.TrimSpace(host.Virtualization),
			CPUName:        strings.TrimSpace(host.CPUName),
			CPUCores:       host.CPUCores,
			MemTotal:       memTotal,
			SwapTotal:      swapTotal,
			DiskTotal:      diskTotal,
			ExpiresAt:      s.ExpiresAt,
			PublicNote:     strings.TrimSpace(s.PublicNote),
		}

		if hasSample && !noAgent {
			raw := entry.sample
			pubSample := &PublicMonitorSample{
				At:        raw.At,
				CPU:       raw.CPU,
				Load1:     raw.Load1,
				Load5:     raw.Load5,
				Load15:    raw.Load15,
				RAMUsed:   raw.RAMUsed,
				RAMTotal:  raw.RAMTotal,
				SwapUsed:  raw.SwapUsed,
				SwapTotal: raw.SwapTotal,
				DiskUsed:  raw.DiskUsed,
				DiskTotal: raw.DiskTotal,
				NetUp:     raw.NetUp,
				NetDown:   raw.NetDown,
				TCP:       raw.TCP,
				UDP:       raw.UDP,
				Process:   raw.Process,
				Uptime:    raw.Uptime,
			}
			if cfg.ShowTraffic {
				up := raw.NetTotalUp
				down := raw.NetTotalDown
				pubSample.NetTotalUp = &up
				pubSample.NetTotalDown = &down
			}
			item.Sample = pubSample
		}

		if cfg.ShowTraffic {
			ct := cycleMap[s.ID]
			item.CycleTraffic = &PublicCycleTraffic{
				StartAt: ct.StartAt,
				ResetAt: ct.ResetAt,
				Used:    ct.Used,
				Limit:   ct.Limit,
				Type:    ct.Type,
			}
		}

		items = append(items, item)
	}

	resp := PublicStatusResponse{
		Title:       cfg.Title,
		Description: cfg.Description,
		ShowTraffic: cfg.ShowTraffic,
		ShowPing:    cfg.ShowPing,
		GeneratedAt: now,
		Servers:     items,
	}
	body, err := json.Marshal(resp)
	if err != nil {
		errorJSON(w, 500, "internal error")
		return
	}

	a.statusCacheMu.Lock()
	a.statusSnapshotBody = body
	a.statusSnapshotExpires = now.Add(publicStatusCacheTTL)
	a.statusCacheMu.Unlock()

	writeCachedJSONBytes(w, "public, max-age=2", body)
}

func (a *App) getPublicHistoryCache(key string, now time.Time) ([]byte, bool) {
	a.statusCacheMu.RLock()
	defer a.statusCacheMu.RUnlock()
	if a.statusHistoryCache == nil {
		return nil, false
	}
	entry, ok := a.statusHistoryCache[key]
	if !ok || !now.Before(entry.expiresAt) {
		return nil, false
	}
	return entry.body, true
}

func (a *App) putPublicHistoryCache(key string, body []byte, now time.Time) {
	a.statusCacheMu.Lock()
	defer a.statusCacheMu.Unlock()
	if a.statusHistoryCache == nil {
		a.statusHistoryCache = make(map[string]publicHistoryCacheEntry)
	}
	if len(a.statusHistoryCache) >= maxPublicHistoryEntries {
		for k, v := range a.statusHistoryCache {
			if !now.Before(v.expiresAt) {
				delete(a.statusHistoryCache, k)
			}
		}
		if len(a.statusHistoryCache) >= maxPublicHistoryEntries {
			var oldestKey string
			var oldestExp time.Time
			for k, v := range a.statusHistoryCache {
				if oldestKey == "" || v.expiresAt.Before(oldestExp) {
					oldestKey = k
					oldestExp = v.expiresAt
				}
			}
			if oldestKey != "" {
				delete(a.statusHistoryCache, oldestKey)
			}
		}
	}
	a.statusHistoryCache[key] = publicHistoryCacheEntry{
		body:      body,
		expiresAt: now.Add(publicHistoryCacheTTL),
	}
}

func (a *App) publicServerRecords(w http.ResponseWriter, r *http.Request) {
	cfg, ok := a.checkPublicStatusGate(w, r)
	if !ok {
		return
	}
	rangeKey, ok := validPublicRange(r.URL.Query().Get("range"))
	if !ok {
		errorJSON(w, 400, "invalid range")
		return
	}
	publicID := r.PathValue("publicId")
	now := a.nowMonitorUTC()
	cacheKey := fmt.Sprintf("records:%s:%s:%t", publicID, rangeKey, cfg.ShowTraffic)
	if cached, hit := a.getPublicHistoryCache(cacheKey, now); hit {
		writeCachedJSONBytes(w, "public, max-age=30", cached)
		return
	}

	srv, found, err := a.resolvePublicServer(publicID)
	if err != nil {
		errorJSON(w, 500, "internal error")
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}

	var records []MonitorRecord
	if !shared.NoAgentManaged(srv) {
		records, err = a.Store.MonitorRecords(srv.ID, rangeKey, now, maxPublicMonitorPoints)
		if err != nil {
			errorJSON(w, 500, "internal error")
			return
		}
		if table, dur, specErr := monitorRangeSpec(rangeKey); specErr == nil && table == "mui_monitor_minutes" {
			if live, liveOK := a.currentMinuteMonitorRecord(srv.ID, now.Add(-dur)); liveOK {
				if len(records) == 0 || live.At.After(records[len(records)-1].At) {
					records = downsampleSlice(append(records, live), maxPublicMonitorPoints)
				}
			}
		}
	}

	out := make([]PublicMonitorRecord, 0, len(records))
	for _, rec := range records {
		item := PublicMonitorRecord{
			At:          rec.At,
			CPU:         rec.CPU,
			Load1:       rec.Load1,
			RAMUsed:     rec.RAMUsed,
			RAMTotal:    rec.RAMTotal,
			SwapUsed:    rec.SwapUsed,
			DiskUsed:    rec.DiskUsed,
			DiskTotal:   rec.DiskTotal,
			NetUp:       rec.NetUp,
			NetDown:     rec.NetDown,
			NetUpPeak:   rec.NetUpPeak,
			NetDownPeak: rec.NetDownPeak,
			TCP:         rec.TCP,
			UDP:         rec.UDP,
			Process:     rec.Process,
		}
		if cfg.ShowTraffic {
			up := rec.TotalUp
			down := rec.TotalDown
			item.TotalUp = &up
			item.TotalDown = &down
		}
		out = append(out, item)
	}

	body, err := json.Marshal(out)
	if err != nil {
		errorJSON(w, 500, "internal error")
		return
	}
	a.putPublicHistoryCache(cacheKey, body, now)
	writeCachedJSONBytes(w, "public, max-age=30", body)
}

func (a *App) publicServerPings(w http.ResponseWriter, r *http.Request) {
	cfg, ok := a.checkPublicStatusGate(w, r)
	if !ok {
		return
	}
	if !cfg.ShowPing {
		http.NotFound(w, r)
		return
	}
	rangeKey, ok := validPublicRange(r.URL.Query().Get("range"))
	if !ok {
		errorJSON(w, 400, "invalid range")
		return
	}
	publicID := r.PathValue("publicId")
	now := a.nowMonitorUTC()
	cacheKey := fmt.Sprintf("pings:%s:%s", publicID, rangeKey)
	if cached, hit := a.getPublicHistoryCache(cacheKey, now); hit {
		writeCachedJSONBytes(w, "public, max-age=30", cached)
		return
	}

	srv, found, err := a.resolvePublicServer(publicID)
	if err != nil {
		errorJSON(w, 500, "internal error")
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}

	out := []PublicPingTaskSeries{}
	if !shared.NoAgentManaged(srv) {
		tasks, err := a.cachedPingTasks()
		if err != nil {
			errorJSON(w, 500, "internal error")
			return
		}
		dur, _ := pingRangeDuration(rangeKey)
		for _, task := range tasks {
			if len(task.ServerIDs) > 0 && !slices.Contains(task.ServerIDs, srv.ID) {
				continue
			}
			recs, err := a.Store.PingRecords(task.ID, srv.ID, rangeKey, now, maxPublicMonitorPoints)
			if err != nil {
				errorJSON(w, 500, "internal error")
				return
			}
			if dur > 0 {
				live := a.currentMinutePingRecords(task.ID, srv.ID, now.Add(-dur))
				if len(live) > 0 {
					seen := make(map[int64]bool, len(recs))
					for _, rec := range recs {
						seen[rec.At.UnixMilli()] = true
					}
					for _, rec := range live {
						if !seen[rec.At.UnixMilli()] {
							recs = append(recs, rec)
						}
					}
					recs = downsampleSlice(recs, maxPublicMonitorPoints)
				}
			}
			points := make([]PublicPingPoint, 0, len(recs))
			for _, rec := range recs {
				points = append(points, PublicPingPoint{
					At:    rec.At,
					MsAvg: rec.MsAvg,
					MsMax: rec.MsMax,
					Sent:  rec.Sent,
					Lost:  rec.Lost,
				})
			}
			out = append(out, PublicPingTaskSeries{
				ID:              a.Store.Fingerprint("status-page-ping", task.ID),
				Name:            task.Name,
				IntervalSeconds: task.IntervalSeconds,
				Records:         points,
			})
		}
	}

	body, err := json.Marshal(out)
	if err != nil {
		errorJSON(w, 500, "internal error")
		return
	}
	a.putPublicHistoryCache(cacheKey, body, now)
	writeCachedJSONBytes(w, "public, max-age=30", body)
}
