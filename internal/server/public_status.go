package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"mui/internal/shared"
)

const (
	maxPublicMonitorPoints  = 720
	publicStatusCacheTTL    = 2 * time.Second
	publicHistoryCacheTTL   = 30 * time.Second
	maxPublicHistoryEntries = 512
)

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
	ID             string                   `json:"id"`
	Name           string                   `json:"name"`
	Group          string                   `json:"group"`
	Country        string                   `json:"country"`
	Region         string                   `json:"region,omitempty"`
	City           string                   `json:"city,omitempty"`
	Online         bool                     `json:"online"`
	HostMonitor    bool                     `json:"hostMonitor"`
	IPv4           bool                     `json:"ipv4"`
	IPv6           bool                     `json:"ipv6"`
	OS             string                   `json:"os,omitempty"`
	Arch           string                   `json:"arch,omitempty"`
	Virtualization string                   `json:"virtualization,omitempty"`
	CPUName        string                   `json:"cpuName,omitempty"`
	CPUCores       int                      `json:"cpuCores,omitempty"`
	MemTotal       int64                    `json:"memTotal,omitempty"`
	SwapTotal      int64                    `json:"swapTotal,omitempty"`
	DiskTotal      int64                    `json:"diskTotal,omitempty"`
	Sample         *PublicMonitorSample     `json:"sample,omitempty"`
	CycleTraffic   *PublicCycleTraffic      `json:"cycleTraffic,omitempty"`
	Ping           []PublicServerPingBucket `json:"ping,omitempty"`
	PingLines      []PublicServerPingLine   `json:"pingLines,omitempty"`
	ExpiresAt      *time.Time               `json:"expiresAt,omitempty"`
	PublicNote     string                   `json:"publicNote,omitempty"`
}

type PublicStatusBackground struct {
	Version     string `json:"version"`
	CardOpacity int    `json:"cardOpacity"`
	Blur        int    `json:"blur"`
}

type PublicStatusResponse struct {
	Title       string                  `json:"title"`
	Description string                  `json:"description"`
	ShowTraffic bool                    `json:"showTraffic"`
	ShowPing    bool                    `json:"showPing"`
	GeneratedAt time.Time               `json:"generatedAt"`
	Background  *PublicStatusBackground `json:"background,omitempty"`
	Servers     []PublicServerItem      `json:"servers"`
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

// StatusHandler returns the isolated HTTP handler bound to MUI_STATUS_LISTEN.
// It registers ONLY /api/public/* and /healthz; every other route and non-GET
// method returns 404.
func (a *App) StatusHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/public/status", a.publicStatus)
	mux.HandleFunc("GET /api/public/background", a.publicBackground)
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

type publicFlightResult struct {
	status int
	body   []byte
}

type publicFlightCall struct {
	done chan struct{}
	res  publicFlightResult
	err  error
}

// doPublicFlight coalesces concurrent cache-miss rebuilds for the same key
// using only the Go standard library. Waiters share the result (including
// errors) and are guaranteed to unblock via defer even if fn fails or panics.
func (a *App) doPublicFlight(key string, fn func() (publicFlightResult, error)) (publicFlightResult, error) {
	a.statusFlightsMu.Lock()
	if a.statusFlights == nil {
		a.statusFlights = make(map[string]*publicFlightCall)
	}
	if c, ok := a.statusFlights[key]; ok {
		a.statusFlightsMu.Unlock()
		<-c.done
		return c.res, c.err
	}
	c := &publicFlightCall{done: make(chan struct{})}
	a.statusFlights[key] = c
	a.statusFlightsMu.Unlock()

	defer func() {
		a.statusFlightsMu.Lock()
		delete(a.statusFlights, key)
		a.statusFlightsMu.Unlock()
		close(c.done)
	}()

	c.res, c.err = fn()
	return c.res, c.err
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

	res, err := a.doPublicFlight("status", func() (publicFlightResult, error) {
		recheckNow := a.nowMonitorUTC()
		a.statusCacheMu.RLock()
		if len(a.statusSnapshotBody) > 0 && recheckNow.Before(a.statusSnapshotExpires) {
			body := a.statusSnapshotBody
			a.statusCacheMu.RUnlock()
			return publicFlightResult{status: http.StatusOK, body: body}, nil
		}
		gen := a.statusCacheGen
		a.statusCacheMu.RUnlock()

		a.statusSnapshotBuilds.Add(1)
		if hook := a.statusBuildHook; hook != nil {
			hook("status")
		}

		body, err := a.buildPublicStatusSnapshot(cfg, recheckNow)
		if err != nil {
			return publicFlightResult{}, err
		}

		a.statusCacheMu.Lock()
		if a.statusCacheGen == gen {
			a.statusSnapshotBody = body
			a.statusSnapshotExpires = recheckNow.Add(publicStatusCacheTTL)
		}
		a.statusCacheMu.Unlock()
		return publicFlightResult{status: http.StatusOK, body: body}, nil
	})
	if err != nil {
		errorJSON(w, 500, "internal error")
		return
	}
	writeCachedJSONBytes(w, "public, max-age=2", res.body)
}

func (a *App) buildPublicStatusSnapshot(cfg storedStatusPageSettings, now time.Time) ([]byte, error) {
	allServers, err := a.Store.Servers()
	if err != nil {
		return nil, err
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
		return nil, err
	}

	var cycleMap map[string]shared.CycleTrafficSummary
	if cfg.ShowTraffic && len(visible) > 0 {
		cycleMap, err = a.Store.CycleTrafficMap(visible, now)
		if err != nil {
			return nil, err
		}
	}

	var pingMap publicPingSummary
	if cfg.ShowPing && len(visible) > 0 {
		pingMap, err = a.cachedPublicPingSummary(visible, now)
		if err != nil {
			return nil, err
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
			IPv4:           strings.TrimSpace(s.IPv4) != "" || strings.TrimSpace(s.DetectedIPv4) != "",
			IPv6:           strings.TrimSpace(s.IPv6) != "" || strings.TrimSpace(s.DetectedIPv6) != "",
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

		if cfg.ShowPing {
			if buckets := pingMap.buckets[s.ID]; len(buckets) > 0 {
				item.Ping = buckets
			}
			// One line per probe task; a single task adds nothing over the average.
			if lines := pingMap.lines[s.ID]; len(lines) > 1 {
				item.PingLines = lines
			}
		}

		items = append(items, item)
	}

	bg, err := a.cachedStatusBackground()
	if err != nil {
		return nil, err
	}
	var bgResp *PublicStatusBackground
	if bg != nil {
		bgResp = &PublicStatusBackground{
			Version:     bg.ETag,
			CardOpacity: cfg.CardOpacity,
			Blur:        cfg.BackgroundBlur,
		}
	}

	resp := PublicStatusResponse{
		Title:       cfg.Title,
		Description: cfg.Description,
		ShowTraffic: cfg.ShowTraffic,
		ShowPing:    cfg.ShowPing,
		GeneratedAt: now,
		Background:  bgResp,
		Servers:     items,
	}
	return json.Marshal(resp)
}

func (a *App) getPublicHistoryCacheLocked(key string, now time.Time) ([]byte, bool) {
	if a.statusHistoryCache == nil {
		return nil, false
	}
	entry, ok := a.statusHistoryCache[key]
	if !ok || !now.Before(entry.expiresAt) {
		return nil, false
	}
	return entry.body, true
}

func (a *App) getPublicHistoryCache(key string, now time.Time) ([]byte, bool) {
	a.statusCacheMu.RLock()
	defer a.statusCacheMu.RUnlock()
	return a.getPublicHistoryCacheLocked(key, now)
}

func (a *App) putPublicHistoryCache(key string, body []byte, now time.Time, gen uint64) {
	a.statusCacheMu.Lock()
	defer a.statusCacheMu.Unlock()
	if a.statusCacheGen != gen {
		return
	}
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
	if !validPublicID(publicID) {
		http.NotFound(w, r)
		return
	}
	now := a.nowMonitorUTC()
	cacheKey := fmt.Sprintf("records:%s:%s:%t", publicID, rangeKey, cfg.ShowTraffic)
	if cached, hit := a.getPublicHistoryCache(cacheKey, now); hit {
		writeCachedJSONBytes(w, "public, max-age=30", cached)
		return
	}

	res, err := a.doPublicFlight(cacheKey, func() (publicFlightResult, error) {
		recheckNow := a.nowMonitorUTC()
		a.statusCacheMu.RLock()
		if cached, hit := a.getPublicHistoryCacheLocked(cacheKey, recheckNow); hit {
			a.statusCacheMu.RUnlock()
			return publicFlightResult{status: http.StatusOK, body: cached}, nil
		}
		gen := a.statusCacheGen
		a.statusCacheMu.RUnlock()

		a.statusHistoryBuilds.Add(1)
		if hook := a.statusBuildHook; hook != nil {
			hook(cacheKey)
		}

		srv, found, err := a.resolvePublicServer(publicID)
		if err != nil {
			return publicFlightResult{}, err
		}
		if !found {
			return publicFlightResult{status: http.StatusNotFound}, nil
		}

		var records []MonitorRecord
		if !shared.NoAgentManaged(srv) {
			records, err = a.Store.MonitorRecords(srv.ID, rangeKey, recheckNow, maxPublicMonitorPoints)
			if err != nil {
				return publicFlightResult{}, err
			}
			if table, dur, specErr := monitorRangeSpec(rangeKey); specErr == nil && table == "mui_monitor_minutes" {
				if live, liveOK := a.currentMinuteMonitorRecord(srv.ID, recheckNow.Add(-dur)); liveOK {
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
			return publicFlightResult{}, err
		}
		a.putPublicHistoryCache(cacheKey, body, recheckNow, gen)
		return publicFlightResult{status: http.StatusOK, body: body}, nil
	})
	if err != nil {
		errorJSON(w, 500, "internal error")
		return
	}
	if res.status == http.StatusNotFound {
		http.NotFound(w, r)
		return
	}
	writeCachedJSONBytes(w, "public, max-age=30", res.body)
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
	if !validPublicID(publicID) {
		http.NotFound(w, r)
		return
	}
	now := a.nowMonitorUTC()
	cacheKey := fmt.Sprintf("pings:%s:%s", publicID, rangeKey)
	if cached, hit := a.getPublicHistoryCache(cacheKey, now); hit {
		writeCachedJSONBytes(w, "public, max-age=30", cached)
		return
	}

	res, err := a.doPublicFlight(cacheKey, func() (publicFlightResult, error) {
		recheckNow := a.nowMonitorUTC()
		a.statusCacheMu.RLock()
		if cached, hit := a.getPublicHistoryCacheLocked(cacheKey, recheckNow); hit {
			a.statusCacheMu.RUnlock()
			return publicFlightResult{status: http.StatusOK, body: cached}, nil
		}
		gen := a.statusCacheGen
		a.statusCacheMu.RUnlock()

		a.statusHistoryBuilds.Add(1)
		if hook := a.statusBuildHook; hook != nil {
			hook(cacheKey)
		}

		srv, found, err := a.resolvePublicServer(publicID)
		if err != nil {
			return publicFlightResult{}, err
		}
		if !found {
			return publicFlightResult{status: http.StatusNotFound}, nil
		}

		out := []PublicPingTaskSeries{}
		if !shared.NoAgentManaged(srv) {
			tasks, err := a.cachedPingTasks()
			if err != nil {
				return publicFlightResult{}, err
			}
			dur, _ := pingRangeDuration(rangeKey)
			for _, task := range tasks {
				if len(task.ServerIDs) > 0 && !slices.Contains(task.ServerIDs, srv.ID) {
					continue
				}
				recs, err := a.Store.PingRecords(task.ID, srv.ID, rangeKey, recheckNow, maxPublicMonitorPoints)
				if err != nil {
					return publicFlightResult{}, err
				}
				if dur > 0 {
					live := a.currentMinutePingRecords(task.ID, srv.ID, recheckNow.Add(-dur))
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
			return publicFlightResult{}, err
		}
		a.putPublicHistoryCache(cacheKey, body, recheckNow, gen)
		return publicFlightResult{status: http.StatusOK, body: body}, nil
	})
	if err != nil {
		errorJSON(w, 500, "internal error")
		return
	}
	if res.status == http.StatusNotFound {
		http.NotFound(w, r)
		return
	}
	writeCachedJSONBytes(w, "public, max-age=30", res.body)
}
