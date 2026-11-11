package agent

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	"mui/internal/shared"
)

// coreVersionCache caches CoreVersion for 5 minutes: the worker reports it on
// every full report but sing-box rarely changes. A core.upgrade invalidates it.
type coreVersionCache struct {
	mu  sync.Mutex
	val string
	at  time.Time
}

func (c *coreVersionCache) get() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.val != "" && time.Since(c.at) < 5*time.Minute {
		return c.val
	}
	c.val = CoreVersion()
	c.at = time.Now()
	return c.val
}

func (c *coreVersionCache) invalidate() {
	c.mu.Lock()
	c.val = ""
	c.at = time.Time{}
	c.mu.Unlock()
}

// backoffDelays is the failure backoff ladder: 5s, 10s, 30s, then 60s.
var backoffDelays = []time.Duration{5 * time.Second, 10 * time.Second, 30 * time.Second, 60 * time.Second}

func backoffDelay(failures int) time.Duration {
	idx := failures - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(backoffDelays) {
		idx = len(backoffDelays) - 1
	}
	base := backoffDelays[idx]
	// ±25% jitter so a fleet of agents does not retry in lockstep.
	var jitterByte [1]byte
	if _, err := rand.Read(jitterByte[:]); err != nil {
		return base
	}
	factor := 0.75 + 0.5*float64(jitterByte[0])/255.0
	return time.Duration(float64(base) * factor)
}

func waitBackoff(ctx context.Context, failures int) {
	select {
	case <-ctx.Done():
	case <-time.After(backoffDelay(failures)):
	}
}

func Run(ctx context.Context) error {
	c, err := ReadConfig()
	if err != nil {
		return err
	}
	// Strict panel URL check, mirroring validatePanelURL in upgrade_linux.go
	// (which this file cannot call: it is Linux-only, while the worker also
	// builds on other platforms). Reject userinfo, query and fragment; only
	// https, or http on loopback, is accepted.
	if _, err := checkPanelURL(c.URL); err != nil {
		return err
	}
	client, err := panelHTTPClient(c.AgentProxy, 15*time.Second)
	if err != nil {
		return err
	}
	defer func() { client.CloseIdleConnections() }()
	komariCtx, stopKomari := context.WithCancel(ctx)
	defer stopKomari()
	go runKomariManager(komariCtx, c)
	latencyCtx, stopLatency := context.WithCancel(ctx)
	defer stopLatency()
	latencies := &routeLatencySampler{}
	go latencies.run(latencyCtx)
	revoked := false
	markRevoked := func(err error) {
		var response *serverStatusError
		if errors.As(err, &response) && response.Status == http.StatusGone {
			revoked = true
			stopKomari()
			stopLatency()
		}
	}
	waitAfterRevocation := func() error {
		fmt.Fprintln(os.Stderr, "Agent 凭据已由面板吊销；停止通信，等待本机重新接入或卸载。")
		client.CloseIdleConnections()
		<-ctx.Done()
		return ctx.Err()
	}
	refreshClient := func() {
		next, err := ReadConfig()
		if err != nil {
			fmt.Fprintln(os.Stderr, "reload agent config:", err)
			return
		}
		if next.URL != c.URL || next.ServerID != c.ServerID || next.Token != c.Token {
			return
		}
		if proxyEqual(next.AgentProxy, c.AgentProxy) {
			return
		}
		replacement, err := panelHTTPClient(next.AgentProxy, 15*time.Second)
		if err != nil {
			return
		}
		client.CloseIdleConnections()
		client, c = replacement, next
	}
	build, err := BinarySHA256E()
	if err != nil {
		fmt.Fprintln(os.Stderr, "agent build digest:", err)
	}
	coreBuild, err := CoreBuildE()
	if err != nil {
		fmt.Fprintln(os.Stderr, "core build digest:", err)
	}
	coreVersions := &coreVersionCache{}
	state := loadTraffic()
	lastSample := time.Time{}
	lastConnectionSample := time.Time{}
	pendingConnections := []shared.ConnectionPoint{}
	statsStatus := "unknown"
	host := QueryHostStatus()
	supportedWarned := false
	if !host.Supported {
		fmt.Fprintln(os.Stderr, "warning: host status reports unsupported; capability bits may be incomplete")
		supportedWarned = true
	}
	var ipv4, ipv6 string
	var autoSyncPublicIP bool
	var lastIPv4Probe time.Time
	var cachedObservedIPv4 string
	var ipv4ProbeFailed bool
	// confirmedBuild remembers what this process already confirmed through
	// the helper, so a successful report does not re-confirm every 30s.
	confirmedBuild := ""

	// reportJobResult sends one executed job's result. On success it clears
	// the pending file and runs the post-acknowledgement confirmations.
	reportJobResult := func(result shared.AgentReport, job shared.Job) (sent bool) {
		headers := map[string]string{"X-Server-ID": c.ServerID, "Authorization": "Bearer " + c.Token}
		if err := sendJSON(ctx, client, "POST", c.URL+"/agent/report", result, headers, nil, c.Token); err != nil {
			markRevoked(err)
			fmt.Fprintln(os.Stderr, "job report:", err)
			// The panel refused this result for good (the job is gone, or it
			// predates the current job protocol). Resending it every cycle would
			// keep the worker in failure backoff forever; drop it.
			var refused *serverStatusError
			if errors.As(err, &refused) && refused.Status >= 400 && refused.Status < 500 && refused.Status != 401 && refused.Status != 408 && refused.Status != 429 {
				_ = os.Remove(pendingJobPath)
				return true
			}
			return false
		}
		if err := os.Remove(pendingJobPath); err != nil && !os.IsNotExist(err) {
			fmt.Fprintln(os.Stderr, "clear job:", err)
			return false
		}
		if result.JobKind == "ufw.init" && result.JobStatus == "success" {
			confirmUFWRollback(ctx)
		}
		return true
	}

	// executeJob runs one claimed job through the helper and persists the
	// result before attempting to report it.
	executeJob := func(job shared.Job) shared.AgentReport {
		result := shared.AgentReport{JobID: job.ID, JobKind: job.Kind, JobStatus: "success", FencingToken: job.FencingToken}
		if err := CallHelperJob(job); err != nil {
			result.JobStatus = "failed"
			result.JobError = err.Error()
		}
		refreshClient()
		if job.Kind == "core.upgrade" {
			coreVersions.invalidate()
			if digest, err := CoreBuildE(); err == nil {
				coreBuild = digest
			} else {
				fmt.Fprintln(os.Stderr, "core build digest:", err)
			}
			result.CoreBuild = coreBuild
			result.CoreDigest = coreBuild
			result.CoreVersion = coreVersions.get()
		}
		if job.Kind != "agent.upgrade" {
			host = QueryHostStatus()
			result.UFWStatus, result.HostReported, result.SSHPorts, result.FirewallConflict, result.UFWRules = host.UFW, true, host.SSHPorts, host.Conflict, host.Rules
		}
		return result
	}

	failures := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		refreshClient()
		loopFailed := false
		sampleDue := time.Since(lastSample) >= 30*time.Second
		if sampleDue {
			if err := sampleServerTraffic(&state); err != nil {
				fmt.Fprintln(os.Stderr, "network:", err)
			}
			if len(ReadCurrent().Nodes) == 0 {
				statsStatus = "idle"
			} else if err := sampleTraffic(ctx, &state); err != nil {
				fmt.Fprintln(os.Stderr, "stats:", err)
				statsStatus = "unavailable"
			} else {
				statsStatus = "active"
			}
			host = QueryHostStatus()
			if host.UFW == "active" {
				// Keep SSH reachable when sshd moved to another port since
				// UFW was initialised; see ensureSSHAllowed.
				if err := CallHelper("ufw.ssh", shared.DesiredState{}); err != nil {
					fmt.Fprintln(os.Stderr, "ssh firewall:", err)
				}
			}
			if !host.Supported && !supportedWarned {
				fmt.Fprintln(os.Stderr, "warning: host status reports unsupported; capability bits may be incomplete")
				supportedWarned = true
			}
			ipv4, ipv6 = publicAddress("udp4", "192.0.2.1:9"), publicAddress("udp6", "[2001:db8::1]:9")
			if ipv4 == "" && autoSyncPublicIP && (c.AgentProxy == nil || c.AgentProxy.Host == "") {
				if time.Since(lastIPv4Probe) >= 5*time.Minute {
					lastIPv4Probe = time.Now()
					observed := panelObservedIPv4(ctx, c)
					cachedObservedIPv4 = nextObservedIPv4(cachedObservedIPv4, observed, true)
					if observed == "" && !ipv4ProbeFailed {
						fmt.Fprintln(os.Stderr, "public IPv4 probe unavailable: check panel IPv4 access and trusted proxy IP forwarding")
					}
					ipv4ProbeFailed = observed == ""
				}
			} else {
				// A SOCKS5 path, disabled sync, or a local public IPv4 makes
				// the previous panel observation inapplicable.
				cachedObservedIPv4 = nextObservedIPv4(cachedObservedIPv4, "", false)
				ipv4ProbeFailed = false
			}
			lastSample = time.Now()
		}
		if time.Since(lastConnectionSample) >= 10*time.Second {
			if len(ReadCurrent().Nodes) > 0 {
				if current, e := ActiveConnections(ctx); e == nil {
					pendingConnections = append(pendingConnections, current...)
					if len(pendingConnections) > 500 {
						pendingConnections = truncatePending(pendingConnections, 500)
					}
				} else {
					fmt.Fprintln(os.Stderr, "connections:", e)
				}
			}
			lastConnectionSample = time.Now()
		}
		state.Pending = truncatePending(state.Pending, maxPendingPoints)
		state.UserPending = truncatePending(state.UserPending, maxPendingPoints)
		state.NetworkPending = truncatePending(state.NetworkPending, maxPendingPoints)

		// Full reports are aligned with the 30s sampling cycle; job polling
		// and pending job results stay on the fast 5s loop below.
		if sampleDue {
			batchSize := len(state.Pending)
			if batchSize > 500 {
				batchSize = 500
			}
			userBatch := len(state.UserPending)
			if userBatch > 500 {
				userBatch = 500
			}
			networkBatch := len(state.NetworkPending)
			if networkBatch > 500 {
				networkBatch = 500
			}
			now := time.Now()
			report := shared.AgentReport{OS: osRelease(), Arch: runtime.GOARCH, AgentVersion: Version, AgentBuild: build, BuildDigest: build,
				ManualFirewallSupport: host.ManualFirewallSupport, AgentSelfUpdate: host.AgentSelfUpdate, NodeFirewallPolicies: host.NodeFirewallPolicies, NodeDomainBlock: host.NodeDomainBlock, NodeSOCKSOutbound: host.NodeSOCKSOutbound, MultiUserStats: host.MultiUserStats, ForwardSupport: host.ForwardSupport, ForwardTCPUDP: host.ForwardTCPUDP, ShadowTLSAuth: host.ShadowTLSAuth, SnellFixedPort: host.SnellFixedPort, SnellV6: host.SnellV6, AgentProxySupport: host.AgentProxySupport, OutboundBindingSupport: host.OutboundBindingSupport, ReleaseKeyPinned: host.ReleaseKeyPinned,
				CoreVersion: coreVersions.get(), CoreBuild: coreBuild, CoreDigest: coreBuild, CoreSelfUpdate: host.CoreSelfUpdate,
				UFWStatus: host.UFW, StatsStatus: statsStatus, Traffic: state.Pending[:batchSize], UserTraffic: state.UserPending[:userBatch], ForwardTraffic: host.ForwardTraffic, ServerTraffic: state.NetworkPending[:networkBatch], Connections: pendingConnections, ForwardConnections: host.ForwardConnections, RouteLatencies: latencies.snapshot(),
				IPv4: ipv4, ObservedIPv4: cachedObservedIPv4, IPv6: ipv6, AgentTime: &now, HostReported: true, SSHPorts: host.SSHPorts, FirewallConflict: host.Conflict, UFWRules: host.Rules}
			headers := map[string]string{"X-Server-ID": c.ServerID, "Authorization": "Bearer " + c.Token}
			var reply struct {
				AutoSyncPublicIP bool `json:"autoSyncPublicIp"`
			}
			if err := sendJSON(ctx, client, "POST", c.URL+"/agent/report", report, headers, &reply, c.Token); err == nil {
				autoSyncPublicIP = reply.AutoSyncPublicIP
				// Confirm the running build through the root helper, never by
				// writing the root-owned confirmation file directly.
				if build != "" && build != confirmedBuild {
					// The watchdog of an upgrade started by an older agent runs
					// that agent's binary, which only reads this file in the
					// agent's own data directory. Without it, that watchdog would
					// roll the new build back.
					_ = os.WriteFile(DataDir+"/upgrade-confirmed", []byte(build), 0600)
					if err := CallHelper("upgrade.confirm", shared.DesiredState{UpgradeSHA256: build}); err != nil {
						fmt.Fprintln(os.Stderr, "upgrade confirm:", err)
					} else {
						confirmedBuild = build
					}
				}
				pendingConnections = nil
				state.Pending = copySlice(state.Pending[batchSize:])
				state.UserPending = copySlice(state.UserPending[userBatch:])
				state.NetworkPending = copySlice(state.NetworkPending[networkBatch:])
				_ = saveTraffic(state)
			} else {
				markRevoked(err)
				fmt.Fprintln(os.Stderr, "report:", err)
				loopFailed = true
			}
		}
		if revoked {
			return waitAfterRevocation()
		}

		// Pending job: a persisted result is (re)sent every loop; a
		// persisted claim without a result is executed again after a restart.
		if pending := loadPendingJob(); pending.Report.JobID != "" || pending.Job.ID != "" {
			if pending.Report.JobStatus == "" && pending.Job.ID != "" {
				result := executeJob(pending.Job)
				if err := savePendingJob(result); err != nil {
					return fmt.Errorf("persist job result: %w", err)
				}
				if !reportJobResult(result, pending.Job) {
					loopFailed = true
				}
			} else if pending.Report.JobID != "" && pending.Report.JobStatus != "" {
				if !reportJobResult(pending.Report, pending.Job) {
					loopFailed = true
				}
			}
		}
		if revoked {
			return waitAfterRevocation()
		}

		// Job poll stays on the fast loop.
		var job shared.Job
		{
			headers := map[string]string{"X-Server-ID": c.ServerID, "Authorization": "Bearer " + c.Token}
			if err := sendJSON(ctx, client, "GET", c.URL+"/agent/job", nil, headers, &job, c.Token); err != nil {
				markRevoked(err)
				fmt.Fprintln(os.Stderr, "poll:", err)
				loopFailed = true
			}
		}
		if revoked {
			return waitAfterRevocation()
		}
		if job.ID != "" {
			if job.ServerID != c.ServerID {
				fmt.Fprintf(os.Stderr, "job %s for server %q does not match local server %q; skipping\n", job.ID, job.ServerID, c.ServerID)
			} else if pending := loadPendingJob(); pending.Report.JobID == job.ID && pending.Report.JobStatus != "" {
				// Already executed; the pending-result branch above resends it.
				fmt.Fprintf(os.Stderr, "job %s already executed; awaiting acknowledgement\n", job.ID)
			} else {
				// Persist the claim before executing, so a crash mid-job does
				// not lose the job and a restart re-executes it once.
				if err := saveClaimedJob(job); err != nil {
					return fmt.Errorf("persist claimed job: %w", err)
				}
				result := executeJob(job)
				if err := savePendingJob(result); err != nil {
					return fmt.Errorf("persist job result: %w", err)
				}
				if !reportJobResult(result, job) {
					loopFailed = true
				}
			}
		}

		if loopFailed {
			failures++
		} else {
			failures = 0
		}
		if failures > 0 {
			waitBackoff(ctx, failures)
		} else {
			waitCycle(ctx)
		}
	}
}

// confirmUFWRollback cancels the automatic "ufw disable" once the panel has
// acknowledged the result. It never blocks the job loop: if the helper stays
// unreachable the timer fires, UFW goes back to inactive and the next status
// report says so.
func confirmUFWRollback(ctx context.Context) {
	for attempt := 0; attempt < 3; attempt++ {
		err := CallHelper("ufw.confirm", shared.DesiredState{})
		if err == nil {
			return
		}
		fmt.Fprintln(os.Stderr, "ufw confirm:", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

// A failed probe is not evidence that the previously observed NAT egress
// disappeared. Only a change in how the address is obtained clears it.
func nextObservedIPv4(previous, observed string, probing bool) string {
	if !probing {
		return ""
	}
	if observed != "" {
		return observed
	}
	return previous
}

// publicAddress returns the source address the host would use for outbound
// traffic, if that address is publicly routable. No packet is sent.
func publicAddress(network, probe string) string {
	conn, err := net.Dial(network, probe)
	if err != nil {
		return ""
	}
	defer conn.Close()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return ""
	}
	if network == "udp4" {
		return validPublicIPv4(addr.IP.String())
	}
	if !addr.IP.IsGlobalUnicast() || addr.IP.IsPrivate() {
		return ""
	}
	return addr.IP.String()
}

func waitCycle(ctx context.Context) {
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
	}
}
