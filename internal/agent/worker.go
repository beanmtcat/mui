package agent

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"mui/internal/shared"
)

type Config struct {
	URL        string              `json:"url"`
	ServerID   string              `json:"serverId"`
	Token      string              `json:"token"`
	AgentProxy *shared.SOCKS5Proxy `json:"agentProxy,omitempty"`
}
type trafficState struct {
	InstanceID        string                      `json:"instanceId"`
	Sequence          int64                       `json:"sequence"`
	Last              map[string][2]int64         `json:"last"`
	Pending           []shared.TrafficPoint       `json:"pending"`
	LastUsers         map[string][2]int64         `json:"lastUsers"`
	UserPending       []shared.UserTrafficPoint   `json:"userPending"`
	NetworkBoot       string                      `json:"networkBoot"`
	NetworkKernelBoot string                      `json:"networkKernelBoot"`
	NetworkIface      string                      `json:"networkIface"`
	NetworkSequence   int64                       `json:"networkSequence"`
	NetworkLast       [2]int64                    `json:"networkLast"`
	NetworkPending    []shared.ServerTrafficPoint `json:"networkPending"`
}

const pendingJobPath = DataDir + "/pending-job.json"

// Samples wait here while the panel is unreachable. Thirty-second samples of a
// busy host fill this in about a week; beyond that the oldest are dropped.
const maxPendingPoints = 20000

// ReadConfig distinguishes a malformed file from a file that parses but is
// missing fields, so a corrupt config is not misreported as merely empty.
func ReadConfig() (Config, error) {
	b, err := os.ReadFile(ConfigDir + "/config.json")
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return Config{}, fmt.Errorf("parse agent config: %w", err)
	}
	var missing []string
	if c.URL == "" {
		missing = append(missing, "url")
	}
	if c.ServerID == "" {
		missing = append(missing, "serverId")
	}
	if c.Token == "" {
		missing = append(missing, "token")
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("agent config incomplete: missing %s", strings.Join(missing, ", "))
	}
	if err := shared.ValidateAgentProxy(c.AgentProxy); err != nil {
		return Config{}, err
	}
	return c, nil
}

// serverStatusError carries the HTTP status of a failed panel call so callers
// can tell "not implemented" (404/501) apart from a transient failure.
type serverStatusError struct {
	Status int
	Body   string
}

func (e *serverStatusError) Error() string {
	return fmt.Sprintf("server %d: %s", e.Status, e.Body)
}

// signHeaders builds the per-request authentication headers for one /agent/*
// call. The signature covers method, path, timestamp, nonce and the SHA-256 of
// the body, keyed by SHA-256(keyMaterial), so a captured request cannot be
// replayed against another path or body.
func signHeaders(method, rawURL string, body []byte, keyMaterial string) (map[string]string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("sign request URL: %w", err)
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	var nonceBytes [16]byte
	if _, err := rand.Read(nonceBytes[:]); err != nil {
		return nil, fmt.Errorf("sign request nonce: %w", err)
	}
	nonce := hex.EncodeToString(nonceBytes[:])
	bodyHash := sha256.Sum256(body)
	key := sha256.Sum256([]byte(keyMaterial))
	mac := hmac.New(sha256.New, key[:])
	fmt.Fprintf(mac, "%s\n%s\n%s\n%s\n%s", method, path, timestamp, nonce, hex.EncodeToString(bodyHash[:]))
	return map[string]string{
		"X-Agent-Timestamp": timestamp,
		"X-Agent-Nonce":     nonce,
		"X-Agent-Signature": hex.EncodeToString(mac.Sum(nil)),
	}, nil
}

// Enroll exchanges an enrollment token for an agent token. It uses its own
// client with a 30s timeout rather than http.DefaultClient, and signs the
// request with the enrollment token as key material. The panel may also
// return its public key, which the installer pins for upgrade verification.
func Enroll(url, serverID, token string, proxies ...*shared.SOCKS5Proxy) (agentToken, panelPublicKey string, err error) {
	var out struct {
		AgentToken     string `json:"agentToken"`
		PanelPublicKey string `json:"panelPublicKey"`
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var p *shared.SOCKS5Proxy
	if len(proxies) > 0 {
		p = proxies[0]
	}
	client, err := panelHTTPClient(p, 30*time.Second)
	if err != nil {
		return "", "", err
	}
	if err := sendJSON(ctx, client, "POST", strings.TrimRight(url, "/")+"/agent/enroll", map[string]string{"serverId": serverID, "token": token}, nil, &out, token); err != nil {
		return "", "", err
	}
	if out.AgentToken == "" {
		return "", "", errors.New("enroll: panel returned an empty agent token")
	}
	return out.AgentToken, out.PanelPublicKey, nil
}

// sendJSON performs one panel call. When signKey is non-empty the request is
// signed with signHeaders using signKey as key material; pass "" only for
// calls that carry no /agent/* authentication.
func sendJSON(ctx context.Context, client *http.Client, method, rawURL string, in any, headers map[string]string, out any, signKey string) error {
	var body []byte
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = raw
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if signKey != "" {
		signed, err := signHeaders(method, rawURL, body, signKey)
		if err != nil {
			return err
		}
		for k, v := range signed {
			req.Header.Set(k, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 204 {
		return nil
	}
	if resp.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &serverStatusError{Status: resp.StatusCode, Body: string(message)}
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out)
	}
	return nil
}

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

// osRelease is computed once: the distribution does not change under a
// running agent.
var osReleaseCached = sync.OnceValue(func() string {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return runtime.GOOS
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
		}
	}
	return runtime.GOOS
})

func osRelease() string { return osReleaseCached() }

// copySlice returns a fresh backing array holding the same elements, so a
// truncated pending slice does not keep the old, larger array alive.
func copySlice[T any](s []T) []T {
	out := make([]T, len(s))
	copy(out, s)
	return out
}

// truncatePending keeps at most max newest elements, copied into a new slice.
func truncatePending[T any](s []T, max int) []T {
	if len(s) <= max {
		return s
	}
	return copySlice(s[len(s)-max:])
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
	// confirmedBuild remembers what this process already confirmed through
	// the helper, so a successful report does not re-confirm every 30s.
	confirmedBuild := ""

	// reportJobResult sends one executed job's result. On success it clears
	// the pending file and runs the post-acknowledgement confirmations.
	reportJobResult := func(result shared.AgentReport, job shared.Job) (sent bool) {
		headers := map[string]string{"X-Server-ID": c.ServerID, "Authorization": "Bearer " + c.Token}
		if err := sendJSON(ctx, client, "POST", c.URL+"/agent/report", result, headers, nil, c.Token); err != nil {
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
				ManualFirewallSupport: host.ManualFirewallSupport, AgentSelfUpdate: host.AgentSelfUpdate, NodeFirewallPolicies: host.NodeFirewallPolicies, MultiUserStats: host.MultiUserStats, ForwardSupport: host.ForwardSupport, ForwardTCPUDP: host.ForwardTCPUDP, ShadowTLSAuth: host.ShadowTLSAuth, SnellFixedPort: host.SnellFixedPort, SnellV6: host.SnellV6, AgentProxySupport: host.AgentProxySupport, ReleaseKeyPinned: host.ReleaseKeyPinned,
				CoreVersion: coreVersions.get(), CoreBuild: coreBuild, CoreDigest: coreBuild, CoreSelfUpdate: host.CoreSelfUpdate,
				UFWStatus: host.UFW, StatsStatus: statsStatus, Traffic: state.Pending[:batchSize], UserTraffic: state.UserPending[:userBatch], ForwardTraffic: host.ForwardTraffic, ServerTraffic: state.NetworkPending[:networkBatch], Connections: pendingConnections,
				IPv4: ipv4, IPv6: ipv6, AgentTime: &now, HostReported: true, SSHPorts: host.SSHPorts, FirewallConflict: host.Conflict, UFWRules: host.Rules}
			headers := map[string]string{"X-Server-ID": c.ServerID, "Authorization": "Bearer " + c.Token}
			if err := sendJSON(ctx, client, "POST", c.URL+"/agent/report", report, headers, nil, c.Token); err == nil {
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
				fmt.Fprintln(os.Stderr, "report:", err)
				loopFailed = true
			}
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

		// Job poll stays on the fast loop.
		var job shared.Job
		{
			headers := map[string]string{"X-Server-ID": c.ServerID, "Authorization": "Bearer " + c.Token}
			if err := sendJSON(ctx, client, "GET", c.URL+"/agent/job", nil, headers, &job, c.Token); err != nil {
				fmt.Fprintln(os.Stderr, "poll:", err)
				loopFailed = true
			}
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

// checkPanelURL is the strict panel URL check shared in spirit with
// validatePanelURL in upgrade_linux.go: no userinfo, query or fragment; only
// https, or http on loopback.
func checkPanelURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.User != nil {
		return nil, errors.New("panel URL must not contain userinfo")
	}
	if u.RawQuery != "" || u.ForceQuery {
		return nil, errors.New("panel URL must not contain a query")
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return nil, errors.New("panel URL must not contain a fragment")
	}
	if u.Scheme == "https" {
		// ok
	} else if u.Scheme == "http" && u.Hostname() == "127.0.0.1" {
		// ok
	} else {
		return nil, errors.New("agent requires HTTPS panel URL")
	}
	if u.Host == "" {
		return nil, errors.New("panel URL must contain a host")
	}
	return u, nil
}

// writeFileAtomic writes data to path via a temp file in the same directory,
// fsyncs the file, renames it over path, and fsyncs the directory.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".mui-tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return fsyncDir(dir)
}

func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
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

// publicAddress returns the source address the host would use for outbound
// traffic, if that address is publicly routable. No packet is sent.
func publicAddress(network, probe string) string {
	conn, err := net.Dial(network, probe)
	if err != nil {
		return ""
	}
	defer conn.Close()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || !addr.IP.IsGlobalUnicast() || addr.IP.IsPrivate() {
		return ""
	}
	return addr.IP.String()
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func waitCycle(ctx context.Context) {
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
	}
}

// claimedJob is the on-disk form of pending-job.json. Claimed marks a job
// that was accepted but not yet executed; Report holds the executed result
// awaiting acknowledgement. Job carries the full claimed job (including the
// DesiredState) so a restart can re-execute a claim that never ran.
type claimedJob struct {
	Claimed bool               `json:"claimed"`
	Report  shared.AgentReport `json:"report"`
	Job     shared.Job         `json:"job,omitempty"`
}

func loadPendingJob() claimedJob {
	data, err := os.ReadFile(pendingJobPath)
	if err != nil {
		return claimedJob{}
	}
	var claimed claimedJob
	if err := json.Unmarshal(data, &claimed); err == nil && (claimed.Claimed || claimed.Report.JobID != "" || claimed.Job.ID != "") {
		return claimed
	}
	// Old format: a bare AgentReport holding an executed result.
	var report shared.AgentReport
	if err := json.Unmarshal(data, &report); err == nil && report.JobID != "" {
		return claimedJob{Claimed: true, Report: report}
	}
	return claimedJob{}
}

func writePendingJob(claimed claimedJob) error {
	data, err := json.Marshal(claimed)
	if err != nil {
		return err
	}
	tmp := pendingJobPath + ".tmp"
	if err = os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, pendingJobPath)
}

// savePendingJob persists an executed job's result. It keeps the original
// signature: callers pass the result report.
func savePendingJob(report shared.AgentReport) error {
	return writePendingJob(claimedJob{Claimed: true, Report: report})
}

// saveClaimedJob persists a job claim before it is executed.
func saveClaimedJob(job shared.Job) error {
	return writePendingJob(claimedJob{Claimed: true, Job: job, Report: shared.AgentReport{JobID: job.ID, JobKind: job.Kind, FencingToken: job.FencingToken}})
}

func loadTraffic() trafficState {
	var s trafficState
	s.Last = map[string][2]int64{}
	s.LastUsers = map[string][2]int64{}
	b, err := os.ReadFile(DataDir + "/traffic.json")
	if err == nil {
		_ = json.Unmarshal(b, &s)
	}
	if s.Last == nil {
		s.Last = map[string][2]int64{}
	}
	if s.LastUsers == nil {
		s.LastUsers = map[string][2]int64{}
	}
	return s
}
func saveTraffic(s trafficState) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	// Skip the write when nothing changed, so an idle agent does not rewrite
	// traffic.json on every successful report.
	// Still write if the file went missing, so a deleted traffic.json is recreated.
	if lastTrafficBytes != nil && bytes.Equal(b, lastTrafficBytes) {
		if _, err := os.Stat(DataDir + "/traffic.json"); err == nil {
			return nil
		}
	}
	tmp := DataDir + "/traffic.json.tmp"
	if err = os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	if err = os.Rename(tmp, DataDir+"/traffic.json"); err != nil {
		return err
	}
	lastTrafficBytes = b
	return nil
}

var lastTrafficBytes []byte

func sampleTraffic(ctx context.Context, state *trafficState) error {
	current := ReadCurrent()
	if len(current.Nodes) == 0 {
		return nil
	}
	stats, err := ReadStats(ctx)
	if err != nil {
		return err
	}
	instance := coreInstanceID()
	if instance == "" {
		return errors.New("sing-box process not running")
	}
	if state.InstanceID != instance {
		state.InstanceID = instance
		state.Last = map[string][2]int64{}
		state.LastUsers = map[string][2]int64{}
	}
	for _, item := range current.Nodes {
		n := item.Node
		if !n.Enabled {
			continue
		}
		pair := stats.Nodes[n.ID]
		last := state.Last[n.ID]
		up := pair[0] - last[0]
		down := pair[1] - last[1]
		if up < 0 {
			up = pair[0]
		}
		if down < 0 {
			down = pair[1]
		}
		state.Last[n.ID] = pair
		if up == 0 && down == 0 {
			continue
		}
		state.Sequence++
		state.Pending = append(state.Pending, shared.TrafficPoint{NodeID: n.ID, InstanceID: instance, Sequence: state.Sequence, Uplink: up, Downlink: down, At: time.Now()})
	}
	for _, item := range current.Nodes {
		if !item.Node.Enabled {
			continue
		}
		for _, user := range item.Users {
			pair, ok := stats.Users[user.Name]
			if !ok {
				continue
			}
			last := state.LastUsers[user.Name]
			up, down := pair[0]-last[0], pair[1]-last[1]
			if up < 0 {
				up = pair[0]
			}
			if down < 0 {
				down = pair[1]
			}
			state.LastUsers[user.Name] = pair
			if up == 0 && down == 0 {
				continue
			}
			state.Sequence++
			state.UserPending = append(state.UserPending, shared.UserTrafficPoint{NodeID: item.Node.ID, SubscriptionID: user.SubscriptionID, InstanceID: instance, Sequence: state.Sequence, Uplink: up, Downlink: down, At: time.Now()})
		}
	}
	return saveTraffic(*state)
}
func coreInstanceID() string {
	pid := coreMainPID()
	if pid == "" || pid == "0" {
		return ""
	}
	stat, err := os.ReadFile("/proc/" + pid + "/stat")
	if err != nil {
		return pid
	}
	parts := strings.Fields(string(stat))
	if len(parts) > 21 {
		return pid + "-" + parts[21]
	}
	return pid
}

// CheckConfigURL validates the saved URL without contacting the panel.
func CheckConfigURL(raw string) error {
	_, err := checkPanelURL(raw)
	return err
}
