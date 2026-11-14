package server

import (
	"database/sql"
	"errors"
	"log"
	"math"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"mui/internal/shared"
)

const (
	maxMonitorInt        int64 = 1 << 53
	maxMonitorCount      int   = 10_000_000
	maxMonitorCores      int   = 65_536
	maxMonitorStrBytes   int   = 128
	maxMonitorPingsBatch int   = 64
	maxPingTasksCount    int   = 32
	maxMonitorPoints     int   = 1500
)

var serverMonitorCGNAT = netip.MustParsePrefix("100.64.0.0/10")

type latestMonitorSample struct {
	sample     shared.MonitorSample
	receivedAt time.Time
}

type monitorMinuteAccum struct {
	minuteMs    int64
	count       int64
	cpuSum      float64
	load1Sum    float64
	ramUsedSum  int64
	ramTotal    int64
	swapUsedSum int64
	diskUsedSum int64
	diskTotal   int64
	netUpSum    int64
	netDownSum  int64
	netUpPeak   int64
	netDownPeak int64
	totalUp     int64
	totalDown   int64
	tcpSum      int64
	udpSum      int64
	processSum  int64
}

func (b *monitorMinuteAccum) add(s shared.MonitorSample) {
	b.count++
	b.cpuSum += s.CPU
	b.load1Sum += s.Load1
	b.ramUsedSum += s.RAMUsed
	b.ramTotal = s.RAMTotal
	b.swapUsedSum += s.SwapUsed
	b.diskUsedSum += s.DiskUsed
	b.diskTotal = s.DiskTotal
	b.netUpSum += s.NetUp
	b.netDownSum += s.NetDown
	if s.NetUp > b.netUpPeak {
		b.netUpPeak = s.NetUp
	}
	if s.NetDown > b.netDownPeak {
		b.netDownPeak = s.NetDown
	}
	b.totalUp = s.NetTotalUp
	b.totalDown = s.NetTotalDown
	b.tcpSum += int64(s.TCP)
	b.udpSum += int64(s.UDP)
	b.processSum += int64(s.Process)
}

func (b *monitorMinuteAccum) record() MonitorRecord {
	if b.count <= 0 {
		return MonitorRecord{At: time.UnixMilli(b.minuteMs).UTC()}
	}
	n := float64(b.count)
	return MonitorRecord{
		At:          time.UnixMilli(b.minuteMs).UTC(),
		CPU:         b.cpuSum / n,
		Load1:       b.load1Sum / n,
		RAMUsed:     int64(math.Round(float64(b.ramUsedSum) / n)),
		RAMTotal:    b.ramTotal,
		SwapUsed:    int64(math.Round(float64(b.swapUsedSum) / n)),
		DiskUsed:    int64(math.Round(float64(b.diskUsedSum) / n)),
		DiskTotal:   b.diskTotal,
		NetUp:       int64(math.Round(float64(b.netUpSum) / n)),
		NetDown:     int64(math.Round(float64(b.netDownSum) / n)),
		NetUpPeak:   b.netUpPeak,
		NetDownPeak: b.netDownPeak,
		TotalUp:     b.totalUp,
		TotalDown:   b.totalDown,
		TCP:         int(math.Round(float64(b.tcpSum) / n)),
		UDP:         int(math.Round(float64(b.udpSum) / n)),
		Process:     int(math.Round(float64(b.processSum) / n)),
	}
}

type pingMinuteAccum struct {
	taskID   string
	serverID string
	minuteMs int64
	sent     int
	lost     int
	okSum    int64
	msMax    int
}

func (p *pingMinuteAccum) add(ms int) {
	p.sent++
	if ms < 0 {
		p.lost++
		return
	}
	p.okSum += int64(ms)
	if ms > p.msMax {
		p.msMax = ms
	}
}

func (p *pingMinuteAccum) avg() int {
	ok := p.sent - p.lost
	if ok <= 0 {
		return 0
	}
	return int(math.Round(float64(p.okSum) / float64(ok)))
}

func clampMonitorInt64(v int64) int64 {
	if v < 0 {
		return 0
	}
	if v > maxMonitorInt {
		return maxMonitorInt
	}
	return v
}

func clampMonitorCount(v, hi int) int {
	if v < 0 {
		return 0
	}
	if v > hi {
		return hi
	}
	return v
}

func clipUTF8Bytes(s string, maxBytes int) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxBytes {
		return s
	}
	s = s[:maxBytes]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

func sanitizeMonitorSample(in shared.MonitorSample, now time.Time) (shared.MonitorSample, bool) {
	for _, f := range []float64{in.CPU, in.Load1, in.Load5, in.Load15} {
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return shared.MonitorSample{}, false
		}
	}
	clampFloat := func(v, lo, hi float64) float64 {
		if v < lo {
			return lo
		}
		if v > hi {
			return hi
		}
		return v
	}
	out := shared.MonitorSample{
		At:           now.UTC(),
		CPU:          clampFloat(in.CPU, 0, 100),
		Load1:        clampFloat(in.Load1, 0, 1_000_000),
		Load5:        clampFloat(in.Load5, 0, 1_000_000),
		Load15:       clampFloat(in.Load15, 0, 1_000_000),
		RAMUsed:      clampMonitorInt64(in.RAMUsed),
		RAMTotal:     clampMonitorInt64(in.RAMTotal),
		SwapUsed:     clampMonitorInt64(in.SwapUsed),
		SwapTotal:    clampMonitorInt64(in.SwapTotal),
		DiskUsed:     clampMonitorInt64(in.DiskUsed),
		DiskTotal:    clampMonitorInt64(in.DiskTotal),
		NetUp:        clampMonitorInt64(in.NetUp),
		NetDown:      clampMonitorInt64(in.NetDown),
		NetTotalUp:   clampMonitorInt64(in.NetTotalUp),
		NetTotalDown: clampMonitorInt64(in.NetTotalDown),
		TCP:          clampMonitorCount(in.TCP, maxMonitorCount),
		UDP:          clampMonitorCount(in.UDP, maxMonitorCount),
		Process:      clampMonitorCount(in.Process, maxMonitorCount),
		Uptime:       clampMonitorInt64(in.Uptime),
	}
	if out.RAMTotal > 0 && out.RAMUsed > out.RAMTotal {
		out.RAMUsed = out.RAMTotal
	}
	if out.SwapTotal > 0 && out.SwapUsed > out.SwapTotal {
		out.SwapUsed = out.SwapTotal
	}
	if out.DiskTotal > 0 && out.DiskUsed > out.DiskTotal {
		out.DiskUsed = out.DiskTotal
	}
	return out, true
}

func sanitizeMonitorHost(in shared.MonitorHost) shared.MonitorHost {
	return shared.MonitorHost{
		CPUName:          clipUTF8Bytes(in.CPUName, maxMonitorStrBytes),
		CPUCores:         clampMonitorCount(in.CPUCores, maxMonitorCores),
		CPUPhysicalCores: clampMonitorCount(in.CPUPhysicalCores, maxMonitorCores),
		Arch:             clipUTF8Bytes(in.Arch, maxMonitorStrBytes),
		OS:               clipUTF8Bytes(in.OS, maxMonitorStrBytes),
		Kernel:           clipUTF8Bytes(in.Kernel, maxMonitorStrBytes),
		Virtualization:   clipUTF8Bytes(in.Virtualization, maxMonitorStrBytes),
		MemTotal:         clampMonitorInt64(in.MemTotal),
		SwapTotal:        clampMonitorInt64(in.SwapTotal),
		DiskTotal:        clampMonitorInt64(in.DiskTotal),
	}
}

func allowedPingPublicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsValid() && ip.Zone() == "" && ip.IsGlobalUnicast() && !ip.IsPrivate() &&
		!ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified() && !serverMonitorCGNAT.Contains(ip)
}

func validPingHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	lower := strings.ToLower(strings.TrimSuffix(host, "."))
	if lower == "" || lower == "localhost" ||
		strings.HasSuffix(lower, ".localhost") ||
		strings.HasSuffix(lower, ".local") ||
		strings.HasSuffix(lower, ".internal") {
		return false
	}
	labels := strings.Split(lower, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}

func validatePingTarget(raw string) (string, error) {
	target := strings.TrimSpace(raw)
	if target == "" || len(target) > 260 || strings.ContainsAny(target, "/@% \t\r\n") {
		return "", errors.New("监测目标格式无效，请填写公网 host:port")
	}
	host, portStr, err := net.SplitHostPort(target)
	if err != nil || host == "" {
		return "", errors.New("监测目标需包含端口（例如 1.1.1.1:443 或 example.com:443）")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", errors.New("监测目标端口必须在 1–65535 之间")
	}
	if ip, parseErr := netip.ParseAddr(host); parseErr == nil {
		if !allowedPingPublicIP(ip) {
			return "", errors.New("监测目标只允许公网地址，不能使用内网、回环、链路本地或 CGNAT 地址")
		}
		return net.JoinHostPort(ip.Unmap().String(), strconv.Itoa(port)), nil
	}
	if strings.Contains(host, ":") || !validPingHostname(host) {
		return "", errors.New("监测目标主机名无效")
	}
	return net.JoinHostPort(strings.ToLower(strings.TrimSuffix(host, ".")), strconv.Itoa(port)), nil
}

func (a *App) invalidatePingTasksCache() {
	a.pingTasksMu.Lock()
	a.pingTasksLoaded = false
	a.pingTasksCache = nil
	a.pingTasksMu.Unlock()
}

func (a *App) cachedPingTasks() ([]MonitorPingTask, error) {
	a.pingTasksMu.RLock()
	if a.pingTasksLoaded {
		out := make([]MonitorPingTask, len(a.pingTasksCache))
		copy(out, a.pingTasksCache)
		a.pingTasksMu.RUnlock()
		return out, nil
	}
	a.pingTasksMu.RUnlock()

	tasks, err := a.Store.PingTasks()
	if err != nil {
		return nil, err
	}
	a.pingTasksMu.Lock()
	a.pingTasksCache = tasks
	a.pingTasksLoaded = true
	out := make([]MonitorPingTask, len(tasks))
	copy(out, tasks)
	a.pingTasksMu.Unlock()
	return out, nil
}

func (a *App) latestMonitorSample(serverID string) (latestMonitorSample, bool) {
	a.monitorMu.RLock()
	defer a.monitorMu.RUnlock()
	entry, ok := a.latestSamples[serverID]
	return entry, ok
}

func (a *App) clearServerMonitorState(serverID string) {
	a.monitorMu.Lock()
	delete(a.latestSamples, serverID)
	a.monitorMu.Unlock()

	a.minuteAccumMu.Lock()
	delete(a.minuteAccums, serverID)
	a.minuteAccumMu.Unlock()

	a.pingAccumMu.Lock()
	suffix := "\x00" + serverID
	for k := range a.pingAccums {
		if strings.HasSuffix(k, suffix) {
			delete(a.pingAccums, k)
		}
	}
	a.pingAccumMu.Unlock()

	a.invalidatePingTasksCache()
}

func (a *App) clearPingTaskMemory(taskID string) {
	a.pingAccumMu.Lock()
	prefix := taskID + "\x00"
	for k := range a.pingAccums {
		if strings.HasPrefix(k, prefix) {
			delete(a.pingAccums, k)
		}
	}
	a.pingAccumMu.Unlock()
	a.invalidatePingTasksCache()
}

func (a *App) nowMonitorUTC() time.Time {
	if a.monitorNow != nil {
		return a.monitorNow().UTC()
	}
	return time.Now().UTC()
}

func (a *App) logMonitorError(op string, err error) {
	if err == nil {
		return
	}
	now := a.nowMonitorUTC()
	a.monitorErrMu.Lock()
	if a.monitorErrLast == nil {
		a.monitorErrLast = map[string]time.Time{}
	}
	last := a.monitorErrLast[op]
	shouldLog := last.IsZero() || !now.Before(last.Add(time.Minute))
	if shouldLog {
		a.monitorErrLast[op] = now
	}
	a.monitorErrMu.Unlock()
	if shouldLog {
		log.Printf("monitor %s: %v", op, err)
	}
}

// FlushMonitorBuckets writes any in-memory sample and ping minute buckets whose
// minute precedes now's UTC minute, so servers that stop reporting do not leave
// their final minute stranded in memory.
func (a *App) FlushMonitorBuckets(now time.Time) {
	cutoffMs := now.UTC().Truncate(time.Minute).UnixMilli()

	type flushedSample struct {
		serverID string
		minuteMs int64
		rec      MonitorRecord
	}
	var sampleFlushes []flushedSample

	a.minuteAccumMu.Lock()
	for serverID, cur := range a.minuteAccums {
		if cur != nil && cur.minuteMs < cutoffMs {
			sampleFlushes = append(sampleFlushes, flushedSample{
				serverID: serverID,
				minuteMs: cur.minuteMs,
				rec:      cur.record(),
			})
			delete(a.minuteAccums, serverID)
		}
	}
	a.minuteAccumMu.Unlock()

	for _, f := range sampleFlushes {
		if err := a.Store.PutMonitorMinute(f.serverID, f.minuteMs, f.rec); err != nil {
			a.logMonitorError("put_minute", err)
		}
	}

	var pingFlushes []pingMinuteAccum
	a.pingAccumMu.Lock()
	for key, acc := range a.pingAccums {
		if acc != nil && acc.minuteMs < cutoffMs {
			pingFlushes = append(pingFlushes, *acc)
			delete(a.pingAccums, key)
		}
	}
	a.pingAccumMu.Unlock()

	for _, fp := range pingFlushes {
		if err := a.Store.UpsertPingMinute(fp.taskID, fp.serverID, fp.minuteMs, fp.avg(), fp.msMax, fp.sent, fp.lost); err != nil {
			a.logMonitorError("put_ping_minute", err)
		}
	}
}

// agentMonitor handles POST /agent/monitor without acquiring lockServer or a.mu
// and without reading or writing mui_servers documents.
func (a *App) agentMonitor(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Agent-Signature") == "" {
		errorJSON(w, 401, "agent signature required")
		return
	}
	serverID := r.Header.Get("X-Server-ID")
	var in shared.MonitorRequest
	if !readJSON(w, r, &in) {
		return
	}
	now := a.nowMonitorUTC()
	sample, ok := sanitizeMonitorSample(in.Sample, now)
	if !ok {
		errorJSON(w, 400, "invalid monitor sample")
		return
	}

	a.monitorMu.Lock()
	if a.latestSamples == nil {
		a.latestSamples = map[string]latestMonitorSample{}
	}
	a.latestSamples[serverID] = latestMonitorSample{
		sample:     sample,
		receivedAt: now,
	}
	a.monitorMu.Unlock()

	nowMinuteMs := now.Truncate(time.Minute).UnixMilli()
	var flushSample *MonitorRecord
	var flushSampleAt int64

	a.minuteAccumMu.Lock()
	if a.minuteAccums == nil {
		a.minuteAccums = map[string]*monitorMinuteAccum{}
	}
	cur := a.minuteAccums[serverID]
	switch {
	case cur == nil:
		b := &monitorMinuteAccum{minuteMs: nowMinuteMs}
		b.add(sample)
		a.minuteAccums[serverID] = b
	case nowMinuteMs == cur.minuteMs:
		cur.add(sample)
	default:
		rec := cur.record()
		flushSample = &rec
		flushSampleAt = cur.minuteMs
		b := &monitorMinuteAccum{minuteMs: nowMinuteMs}
		b.add(sample)
		a.minuteAccums[serverID] = b
	}
	a.minuteAccumMu.Unlock()

	if flushSample != nil {
		if err := a.Store.PutMonitorMinute(serverID, flushSampleAt, *flushSample); err != nil {
			a.logMonitorError("put_minute", err)
		}
	}

	if in.Host != nil {
		cleanHost := sanitizeMonitorHost(*in.Host)
		if err := a.Store.PutMonitorHost(serverID, cleanHost, now); err != nil {
			a.logMonitorError("put_host", err)
		}
	}

	allTasks, err := a.cachedPingTasks()
	if err != nil {
		a.logMonitorError("ping_tasks", err)
	}
	assigned := make([]shared.PingTask, 0, len(allTasks))
	assignedIDs := make(map[string]bool, len(allTasks))
	for _, t := range allTasks {
		if len(t.ServerIDs) == 0 || slices.Contains(t.ServerIDs, serverID) {
			assigned = append(assigned, shared.PingTask{
				ID:              t.ID,
				Target:          t.Target,
				IntervalSeconds: t.IntervalSeconds,
			})
			assignedIDs[t.ID] = true
		}
	}

	pings := in.Pings
	if len(pings) > maxMonitorPingsBatch {
		pings = pings[:maxMonitorPingsBatch]
	}

	var flushPings []pingMinuteAccum
	a.pingAccumMu.Lock()
	if a.pingAccums == nil {
		a.pingAccums = map[string]*pingMinuteAccum{}
	}
	for _, p := range pings {
		if len(p.TaskID) == 0 || len(p.TaskID) > maxMonitorStrBytes || !assignedIDs[p.TaskID] {
			continue
		}
		ms := p.Ms
		if ms < 0 {
			ms = -1
		} else if ms > 60_000 {
			ms = 60_000
		}
		key := p.TaskID + "\x00" + serverID
		acc := a.pingAccums[key]
		switch {
		case acc == nil:
			next := &pingMinuteAccum{taskID: p.TaskID, serverID: serverID, minuteMs: nowMinuteMs}
			next.add(ms)
			a.pingAccums[key] = next
		case nowMinuteMs == acc.minuteMs:
			acc.add(ms)
		default:
			flushPings = append(flushPings, *acc)
			next := &pingMinuteAccum{taskID: p.TaskID, serverID: serverID, minuteMs: nowMinuteMs}
			next.add(ms)
			a.pingAccums[key] = next
		}
	}
	suffix := "\x00" + serverID
	for key, acc := range a.pingAccums {
		if strings.HasSuffix(key, suffix) && nowMinuteMs != acc.minuteMs {
			flushPings = append(flushPings, *acc)
			delete(a.pingAccums, key)
		}
	}
	a.pingAccumMu.Unlock()

	for _, fp := range flushPings {
		if err := a.Store.UpsertPingMinute(fp.taskID, fp.serverID, fp.minuteMs, fp.avg(), fp.msMax, fp.sent, fp.lost); err != nil {
			a.logMonitorError("put_ping_minute", err)
		}
	}

	writeJSON(w, 200, shared.MonitorResponse{Pings: assigned})
}

type monitorOverviewItem struct {
	ServerID     string                      `json:"serverId"`
	Online       bool                        `json:"online"`
	HostMonitor  bool                        `json:"hostMonitor"`
	Sample       *shared.MonitorSample       `json:"sample,omitempty"`
	Host         *shared.MonitorHost         `json:"host,omitempty"`
	CycleTraffic *shared.CycleTrafficSummary `json:"cycleTraffic,omitempty"`
}

func (a *App) monitorOverview(w http.ResponseWriter, _ *http.Request) {
	servers, err := a.Store.Servers()
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	hosts, err := a.Store.MonitorHosts()
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	now := a.nowMonitorUTC()
	cycleMap, err := a.Store.CycleTrafficMap(servers, now)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.monitorMu.RLock()
	samples := make(map[string]latestMonitorSample, len(a.latestSamples))
	for k, v := range a.latestSamples {
		samples[k] = v
	}
	a.monitorMu.RUnlock()

	items := make([]monitorOverviewItem, 0, len(servers))
	for _, s := range servers {
		ct := cycleMap[s.ID]
		if shared.NoAgentManaged(s) {
			items = append(items, monitorOverviewItem{
				ServerID:     s.ID,
				Online:       false,
				HostMonitor:  false,
				CycleTraffic: &ct,
			})
			continue
		}
		entry, hasSample := samples[s.ID]
		host, hasHost := hosts[s.ID]
		online := serverStatus(s) == "online" || (s.Status != "revoked" && hasSample && now.Sub(entry.receivedAt) <= 30*time.Second)
		item := monitorOverviewItem{
			ServerID:     s.ID,
			Online:       online,
			HostMonitor:  s.HostMonitor || hasSample || hasHost,
			CycleTraffic: &ct,
		}
		if hasSample {
			samp := entry.sample
			item.Sample = &samp
		}
		if hasHost {
			h := host
			item.Host = &h
		}
		items = append(items, item)
	}
	writeJSON(w, 200, items)
}

func (a *App) currentMinuteMonitorRecord(serverID string, since time.Time) (MonitorRecord, bool) {
	a.minuteAccumMu.Lock()
	defer a.minuteAccumMu.Unlock()
	b := a.minuteAccums[serverID]
	if b == nil || b.count == 0 {
		return MonitorRecord{}, false
	}
	rec := b.record()
	if rec.At.Before(since) {
		return MonitorRecord{}, false
	}
	return rec, true
}

func (a *App) monitorServerRecords(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("serverId")
	if !validServerID(id) || !a.serverExists(id) {
		errorJSON(w, 404, "服务器不存在")
		return
	}
	rangeKey := r.URL.Query().Get("range")
	now := a.nowMonitorUTC()
	records, err := a.Store.MonitorRecords(id, rangeKey, now, maxMonitorPoints)
	if err != nil {
		if errors.Is(err, errInvalidMonitorRange) {
			errorJSON(w, 400, err.Error())
			return
		}
		errorJSON(w, 500, err.Error())
		return
	}
	if table, dur, specErr := monitorRangeSpec(rangeKey); specErr == nil && table == "mui_monitor_minutes" {
		if live, ok := a.currentMinuteMonitorRecord(id, now.Add(-dur)); ok {
			if len(records) == 0 || live.At.After(records[len(records)-1].At) {
				records = downsampleSlice(append(records, live), maxMonitorPoints)
			}
		}
	}
	writeJSON(w, 200, records)
}

type pingTaskInput struct {
	Name            *string   `json:"name"`
	Target          *string   `json:"target"`
	IntervalSeconds *int      `json:"intervalSeconds"`
	ServerIDs       *[]string `json:"serverIds"`
}

func (a *App) validatePingServerIDs(ids []string) ([]string, error) {
	if len(ids) == 0 {
		return []string{}, nil
	}
	if len(ids) > 500 {
		return nil, errors.New("所选服务器数量过多")
	}
	servers, err := a.Store.Servers()
	if err != nil {
		return nil, err
	}
	valid := make(map[string]shared.Server, len(servers))
	for _, s := range servers {
		valid[s.ID] = s
	}
	seen := make(map[string]bool, len(ids))
	clean := make([]string, 0, len(ids))
	for _, raw := range ids {
		id := strings.TrimSpace(raw)
		if id == "" || seen[id] {
			continue
		}
		srv, ok := valid[id]
		if !ok {
			return nil, errors.New("所选服务器不存在")
		}
		if shared.NoAgentManaged(srv) {
			return nil, errors.New("离线或外部服务器不支持 TCP 延迟监测")
		}
		seen[id] = true
		clean = append(clean, id)
	}
	return clean, nil
}

func (a *App) pingTasks(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tasks, err := a.cachedPingTasks()
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, tasks)
		return
	}

	existing, err := a.Store.PingTasks()
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if len(existing) >= maxPingTasksCount {
		errorJSON(w, 400, "延迟监测任务最多创建 32 个")
		return
	}

	var in pingTaskInput
	if !readJSON(w, r, &in) {
		return
	}
	name := ""
	if in.Name != nil {
		name = strings.TrimSpace(*in.Name)
	}
	if name == "" || utf8.RuneCountInString(name) > 80 {
		errorJSON(w, 400, "任务名称必填且不超过 80 个字符")
		return
	}
	rawTarget := ""
	if in.Target != nil {
		rawTarget = *in.Target
	}
	target, err := validatePingTarget(rawTarget)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	interval := 60
	if in.IntervalSeconds != nil {
		interval = *in.IntervalSeconds
	}
	if interval < 30 || interval > 3600 {
		errorJSON(w, 400, "检测间隔必须在 30–3600 秒之间")
		return
	}
	var rawServerIDs []string
	if in.ServerIDs != nil {
		rawServerIDs = *in.ServerIDs
	}
	serverIDs, err := a.validatePingServerIDs(rawServerIDs)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}

	task := MonitorPingTask{
		ID:              ID(),
		Name:            name,
		Target:          target,
		IntervalSeconds: interval,
		ServerIDs:       serverIDs,
	}
	if err := a.Store.PutPingTask(task); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.invalidatePingTasksCache()
	a.auditRequest(r, "ping-task.create", task.ID, task.Name+" ("+task.Target+")")
	writeJSON(w, 201, task)
}

func (a *App) pingTaskByID(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validServerID(id) {
		errorJSON(w, 404, "监测任务不存在")
		return
	}
	if r.Method == http.MethodDelete {
		old, err := a.Store.PingTask(id)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				errorJSON(w, 404, "监测任务不存在")
				return
			}
			errorJSON(w, 500, err.Error())
			return
		}
		if err := a.Store.DeletePingTask(id); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		a.clearPingTaskMemory(id)
		a.auditRequest(r, "ping-task.delete", id, old.Name)
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}

	cur, err := a.Store.PingTask(id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			errorJSON(w, 404, "监测任务不存在")
			return
		}
		errorJSON(w, 500, err.Error())
		return
	}
	var in pingTaskInput
	if !readJSON(w, r, &in) {
		return
	}
	if in.Name != nil {
		name := strings.TrimSpace(*in.Name)
		if name == "" || utf8.RuneCountInString(name) > 80 {
			errorJSON(w, 400, "任务名称必填且不超过 80 个字符")
			return
		}
		cur.Name = name
	}
	if in.Target != nil {
		target, err := validatePingTarget(*in.Target)
		if err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
		cur.Target = target
	}
	if in.IntervalSeconds != nil {
		if *in.IntervalSeconds < 30 || *in.IntervalSeconds > 3600 {
			errorJSON(w, 400, "检测间隔必须在 30–3600 秒之间")
			return
		}
		cur.IntervalSeconds = *in.IntervalSeconds
	}
	if in.ServerIDs != nil {
		serverIDs, err := a.validatePingServerIDs(*in.ServerIDs)
		if err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
		cur.ServerIDs = serverIDs
	}

	if err := a.Store.PutPingTask(cur); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.invalidatePingTasksCache()
	a.auditRequest(r, "ping-task.update", cur.ID, cur.Name+" ("+cur.Target+")")
	writeJSON(w, 200, cur)
}

func (a *App) currentMinutePingRecords(taskID, serverID string, since time.Time) []PingMinuteRecord {
	a.pingAccumMu.Lock()
	defer a.pingAccumMu.Unlock()
	prefix := taskID + "\x00"
	var out []PingMinuteRecord
	for k, acc := range a.pingAccums {
		if !strings.HasPrefix(k, prefix) || acc.sent == 0 {
			continue
		}
		if serverID != "" && acc.serverID != serverID {
			continue
		}
		at := time.UnixMilli(acc.minuteMs).UTC()
		if at.Before(since) {
			continue
		}
		out = append(out, PingMinuteRecord{
			ServerID: acc.serverID,
			At:       at,
			MsAvg:    acc.avg(),
			MsMax:    acc.msMax,
			Sent:     acc.sent,
			Lost:     acc.lost,
		})
	}
	slices.SortFunc(out, func(a, b PingMinuteRecord) int {
		if !a.At.Equal(b.At) {
			if a.At.Before(b.At) {
				return -1
			}
			return 1
		}
		if a.ServerID < b.ServerID {
			return -1
		}
		if a.ServerID > b.ServerID {
			return 1
		}
		return 0
	})
	return out
}

func (a *App) pingTaskRecords(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validServerID(id) {
		errorJSON(w, 404, "监测任务不存在")
		return
	}
	if _, err := a.Store.PingTask(id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			errorJSON(w, 404, "监测任务不存在")
			return
		}
		errorJSON(w, 500, err.Error())
		return
	}
	serverID := strings.TrimSpace(r.URL.Query().Get("serverId"))
	if serverID != "" && !validServerID(serverID) {
		errorJSON(w, 400, "服务器 ID 无效")
		return
	}
	rangeKey := r.URL.Query().Get("range")
	now := a.nowMonitorUTC()
	records, err := a.Store.PingRecords(id, serverID, rangeKey, now, maxMonitorPoints)
	if err != nil {
		if errors.Is(err, errInvalidMonitorRange) {
			errorJSON(w, 400, err.Error())
			return
		}
		errorJSON(w, 500, err.Error())
		return
	}
	if dur, durErr := pingRangeDuration(rangeKey); durErr == nil {
		live := a.currentMinutePingRecords(id, serverID, now.Add(-dur))
		if len(live) > 0 {
			seen := make(map[string]bool, len(records))
			for _, rec := range records {
				seen[rec.ServerID+"\x00"+strconv.FormatInt(rec.At.UnixMilli(), 10)] = true
			}
			for _, rec := range live {
				if !seen[rec.ServerID+"\x00"+strconv.FormatInt(rec.At.UnixMilli(), 10)] {
					records = append(records, rec)
				}
			}
			records = downsampleSlice(records, maxMonitorPoints)
		}
	}
	writeJSON(w, 200, records)
}
