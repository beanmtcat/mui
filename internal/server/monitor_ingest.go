package server

import (
	"log"
	"math"
	"net/http"
	"slices"
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
)

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
