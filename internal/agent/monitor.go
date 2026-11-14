package agent

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	komariunit "github.com/komari-monitor/komari-agent/monitoring/unit"

	"mui/internal/shared"
)

const (
	monitorNormalInterval  = 5 * time.Second
	monitorBackoffInterval = 30 * time.Second
	monitorHostInterval    = 10 * time.Minute
	maxMonitorValue        = int64(1) << 53
	maxPendingPingResults  = 64
	maxAgentMonitorTasks   = 32
)

func clampMonitorUint64(v uint64) int64 {
	if v > uint64(maxMonitorValue) {
		return maxMonitorValue
	}
	return int64(v)
}

func sanitizeAgentFloat(v, minV, maxV float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	if v < minV {
		return minV
	}
	if v > maxV {
		return maxV
	}
	return v
}

func clipAgentUTF8Bytes(s string, limit int) string {
	s = strings.TrimSpace(s)
	if len(s) <= limit {
		return s
	}
	s = s[:limit]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

func buildMonitorSample(
	now time.Time,
	cpu komariunit.CpuInfo,
	load komariunit.LoadInfo,
	ram, swap komariunit.RamInfo,
	disk komariunit.DiskInfo,
	totalUp, totalDown, upSpeed, downSpeed uint64,
	tcpCount, udpCount, procCount int,
	uptime uint64,
) shared.MonitorSample {
	if tcpCount < 0 {
		tcpCount = 0
	}
	if udpCount < 0 {
		udpCount = 0
	}
	if procCount < 0 {
		procCount = 0
	}
	return shared.MonitorSample{
		At:           now.UTC(),
		CPU:          sanitizeAgentFloat(cpu.CPUUsage, 0, 100),
		Load1:        sanitizeAgentFloat(load.Load1, 0, 1_000_000),
		Load5:        sanitizeAgentFloat(load.Load5, 0, 1_000_000),
		Load15:       sanitizeAgentFloat(load.Load15, 0, 1_000_000),
		RAMUsed:      clampMonitorUint64(ram.Used),
		RAMTotal:     clampMonitorUint64(ram.Total),
		SwapUsed:     clampMonitorUint64(swap.Used),
		SwapTotal:    clampMonitorUint64(swap.Total),
		DiskUsed:     clampMonitorUint64(disk.Used),
		DiskTotal:    clampMonitorUint64(disk.Total),
		NetUp:        clampMonitorUint64(upSpeed),
		NetDown:      clampMonitorUint64(downSpeed),
		NetTotalUp:   clampMonitorUint64(totalUp),
		NetTotalDown: clampMonitorUint64(totalDown),
		TCP:          tcpCount,
		UDP:          udpCount,
		Process:      procCount,
		Uptime:       clampMonitorUint64(uptime),
	}
}

func collectMonitorSample(now time.Time) shared.MonitorSample {
	cpu := komariunit.Cpu()
	load := komariunit.Load()
	ram := komariunit.Ram()
	swap := komariunit.Swap()
	disk := komariunit.Disk()
	totalUp, totalDown, upSpeed, downSpeed, _ := komariunit.NetworkSpeed()
	tcpCount, udpCount, _ := komariunit.ConnectionsCount()
	procCount := komariunit.ProcessCount()
	uptime, _ := komariunit.Uptime()
	return buildMonitorSample(now, cpu, load, ram, swap, disk, totalUp, totalDown, upSpeed, downSpeed, tcpCount, udpCount, procCount, uptime)
}

func buildMonitorHost(
	cpu komariunit.CpuInfo,
	ram, swap komariunit.RamInfo,
	disk komariunit.DiskInfo,
	arch, osName, kernel, virt string,
) shared.MonitorHost {
	cores := cpu.CPUCores
	if cores < 0 {
		cores = 0
	}
	phys := cpu.CPUPhysicalCores
	if phys < 0 {
		phys = 0
	}
	return shared.MonitorHost{
		CPUName:          clipAgentUTF8Bytes(cpu.CPUName, 128),
		CPUCores:         cores,
		CPUPhysicalCores: phys,
		Arch:             clipAgentUTF8Bytes(arch, 128),
		OS:               clipAgentUTF8Bytes(osName, 128),
		Kernel:           clipAgentUTF8Bytes(kernel, 128),
		Virtualization:   clipAgentUTF8Bytes(virt, 128),
		MemTotal:         clampMonitorUint64(ram.Total),
		SwapTotal:        clampMonitorUint64(swap.Total),
		DiskTotal:        clampMonitorUint64(disk.Total),
	}
}

func collectMonitorHost() shared.MonitorHost {
	return buildMonitorHost(
		komariunit.CpuStaticInfo(),
		komariunit.Ram(),
		komariunit.Swap(),
		komariunit.Disk(),
		runtime.GOARCH,
		komariunit.OSName(),
		komariunit.KernelVersion(),
		komariunit.Virtualized(),
	)
}

func monitorPollInterval(consecutiveFailures int) time.Duration {
	if consecutiveFailures >= 2 {
		return monitorBackoffInterval
	}
	return monitorNormalInterval
}

type runningPingTask struct {
	spec shared.PingTask
	stop context.CancelFunc
}

type monitorPingRunner struct {
	mu      sync.Mutex
	tasks   map[string]runningPingTask
	results []shared.PingResult
	pingFn  func(context.Context, string) int
}

func newMonitorPingRunner(pingFn func(context.Context, string) int) *monitorPingRunner {
	if pingFn == nil {
		pingFn = tcpPingMonitor
	}
	return &monitorPingRunner{
		tasks:  map[string]runningPingTask{},
		pingFn: pingFn,
	}
}

func (r *monitorPingRunner) stopAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, t := range r.tasks {
		t.stop()
		delete(r.tasks, id)
	}
}

func (r *monitorPingRunner) update(parent context.Context, list []shared.PingTask) {
	if len(list) > maxAgentMonitorTasks {
		list = list[:maxAgentMonitorTasks]
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	keep := make(map[string]shared.PingTask, len(list))
	for _, item := range list {
		if item.ID == "" || strings.TrimSpace(item.Target) == "" {
			continue
		}
		if item.IntervalSeconds < 30 {
			item.IntervalSeconds = 30
		}
		if item.IntervalSeconds > 3600 {
			item.IntervalSeconds = 3600
		}
		keep[item.ID] = item
	}
	for id, cur := range r.tasks {
		next, ok := keep[id]
		if !ok || next.Target != cur.spec.Target || next.IntervalSeconds != cur.spec.IntervalSeconds {
			cur.stop()
			delete(r.tasks, id)
		}
	}
	for id, spec := range keep {
		if _, exists := r.tasks[id]; exists {
			continue
		}
		taskCtx, cancel := context.WithCancel(parent)
		r.tasks[id] = runningPingTask{spec: spec, stop: cancel}
		go r.loopTask(taskCtx, spec)
	}
}

func (r *monitorPingRunner) loopTask(ctx context.Context, spec shared.PingTask) {
	runOnce := func() {
		ms := r.pingFn(ctx, spec.Target)
		if ctx.Err() != nil {
			return
		}
		r.record(shared.PingResult{
			TaskID: spec.ID,
			At:     time.Now().UTC(),
			Ms:     ms,
		})
	}
	runOnce()
	ticker := time.NewTicker(time.Duration(spec.IntervalSeconds) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runOnce()
		}
	}
}

func (r *monitorPingRunner) record(res shared.PingResult) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.results) >= maxPendingPingResults {
		copy(r.results, r.results[1:])
		r.results[len(r.results)-1] = res
		return
	}
	r.results = append(r.results, res)
}

func (r *monitorPingRunner) drain() []shared.PingResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.results) == 0 {
		return nil
	}
	out := make([]shared.PingResult, len(r.results))
	copy(out, r.results)
	r.results = r.results[:0]
	return out
}

// runMonitorLoop samples local host metrics and posts them to /agent/monitor on
// its own timer, completely isolated from job polling and /agent/report.
func runMonitorLoop(ctx context.Context, c Config) {
	client, err := panelHTTPClient(c.AgentProxy, 10*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, "monitor client:", err)
		return
	}
	defer func() { client.CloseIdleConnections() }()

	refreshClient := func() {
		next, err := ReadConfig()
		if err != nil {
			return
		}
		if next.URL != c.URL || next.ServerID != c.ServerID || next.Token != c.Token {
			return
		}
		if proxyEqual(next.AgentProxy, c.AgentProxy) {
			return
		}
		replacement, err := panelHTTPClient(next.AgentProxy, 10*time.Second)
		if err != nil {
			return
		}
		client.CloseIdleConnections()
		client, c = replacement, next
	}

	pings := newMonitorPingRunner(tcpPingMonitor)
	defer pings.stopAll()

	var lastHostAt time.Time
	consecutiveFailures := 0
	endpoint := strings.TrimRight(c.URL, "/") + "/agent/monitor"

	sendOnce := func() bool {
		refreshClient()
		now := time.Now()
		req := shared.MonitorRequest{
			Sample: collectMonitorSample(now),
			Pings:  pings.drain(),
		}
		includeHost := lastHostAt.IsZero() || now.Sub(lastHostAt) >= monitorHostInterval
		if includeHost {
			h := collectMonitorHost()
			req.Host = &h
		}
		headers := map[string]string{
			"X-Server-ID":   c.ServerID,
			"Authorization": "Bearer " + c.Token,
		}
		callCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		var resp shared.MonitorResponse
		if err := sendJSON(callCtx, client, http.MethodPost, endpoint, req, headers, &resp, c.Token); err != nil {
			var statusErr *serverStatusError
			if errors.As(err, &statusErr) && statusErr.Status == http.StatusGone {
				return false
			}
			consecutiveFailures++
			if consecutiveFailures == 1 {
				fmt.Fprintln(os.Stderr, "monitor:", err)
			}
			return true
		}
		consecutiveFailures = 0
		if includeHost {
			lastHostAt = now
		}
		pings.update(ctx, resp.Pings)
		return true
	}

	if !sendOnce() {
		return
	}
	timer := time.NewTimer(monitorPollInterval(consecutiveFailures))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if !sendOnce() {
				return
			}
			timer.Reset(monitorPollInterval(consecutiveFailures))
		}
	}
}

var monitorCGNAT = netip.MustParsePrefix("100.64.0.0/10")

func allowedMonitorPingIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsValid() && ip.Zone() == "" && ip.IsGlobalUnicast() && !ip.IsPrivate() &&
		!ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified() && !monitorCGNAT.Contains(ip)
}

// Resolve once, inspect every answer, then dial only the approved literal IP.
// Rejecting a mixed public/private answer prevents a panel-controlled name
// from selecting an internal address or changing DNS between check and dial.
func resolveMonitorTCPTarget(ctx context.Context, target string, lookup func(context.Context, string, string) ([]netip.Addr, error)) ([]string, error) {
	target = strings.TrimSpace(target)
	if target == "" || strings.ContainsAny(target, "/@% \t\r\n") {
		return nil, errors.New("invalid target")
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		if ip, parseErr := netip.ParseAddr(target); parseErr == nil && ip.Zone() == "" {
			host, port = ip.String(), "80"
		} else if strings.Contains(target, ":") {
			return nil, errors.New("invalid host or port")
		} else {
			host, port = target, "80"
		}
	}
	if host == "" {
		return nil, errors.New("empty host")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return nil, errors.New("invalid port")
	}
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip}
	} else {
		ips, err = lookup(ctx, "ip", host)
		if err != nil || len(ips) == 0 {
			return nil, errors.New("DNS lookup failed")
		}
	}
	addresses := make([]string, 0, len(ips))
	for _, ip := range ips {
		if !allowedMonitorPingIP(ip) {
			return nil, errors.New("target address is not public")
		}
		addresses = append(addresses, net.JoinHostPort(ip.Unmap().String(), port))
	}
	return addresses, nil
}

func tcpPingMonitorWith(
	ctx context.Context,
	target string,
	lookup func(context.Context, string, string) ([]netip.Addr, error),
	dial func(context.Context, string, string) (net.Conn, error),
) int {
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	addresses, err := resolveMonitorTCPTarget(call, target, lookup)
	if err != nil {
		return -1
	}
	for _, address := range addresses {
		start := time.Now()
		conn, err := dial(call, "tcp", address)
		if err == nil {
			_ = conn.Close()
			ms := int(time.Since(start).Milliseconds())
			if ms < 0 {
				ms = 0
			}
			return ms
		}
	}
	return -1
}

func tcpPingMonitor(ctx context.Context, target string) int {
	return tcpPingMonitorWith(ctx, target, net.DefaultResolver.LookupNetIP, (&net.Dialer{}).DialContext)
}
