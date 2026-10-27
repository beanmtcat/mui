//go:build linux

package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"mui/internal/shared"
)

// The panel hands a claimed job to another poll after five minutes, so a helper
// call has to give up before that.
const helperTimeout = 4 * time.Minute

// helperWriteMu serializes every helper write operation (ufw.init,
// ufw.confirm, ufw.delete, ufw.ssh, all *.apply kinds, agent.upgrade,
// core.upgrade, upgrade.confirm). Two applies must never interleave: each
// one reads the live state, rewrites it, and rolls back on failure. The
// read-only status kind is exempt; ufw.ssh skips rather than waits.
var helperWriteMu sync.Mutex

// helperConnSem caps concurrent helper connections. ServeHelper blocks
// acquiring a slot before Accept, so a flood of connections applies
// backpressure instead of spawning unbounded handler goroutines.
var helperConnSem = make(chan struct{}, 16)

// upgradeDedup records upgrades this helper already completed, keyed by
// kind + SHA-256, so a redelivered job does not download and swap the
// binary a second time.
var upgradeDedupMu sync.Mutex
var upgradeDedup = map[string]time.Time{}

type helperRequest struct {
	Kind            string              `json:"kind"`
	ProtocolVersion int                 `json:"protocolVersion"`
	State           shared.DesiredState `json:"state"`
	// StateRaw is a job's state as the panel sent it. When present, State is
	// decoded from it and the signature is checked over it.
	StateRaw json.RawMessage `json:"stateRaw,omitempty"`
}
type helperResponse struct {
	Error           string      `json:"error,omitempty"`
	ProtocolVersion int         `json:"protocolVersion,omitempty"`
	Status          *HostStatus `json:"status,omitempty"`
}

func command(name string, args ...string) (string, error) {
	return commandTimeout(name, 60*time.Second, args...)
}

func ServeHelper() error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("helper must run as root on Linux")
	}
	if err := os.MkdirAll(filepath.Dir(SocketPath), 0755); err != nil {
		return err
	}
	_ = os.Remove(SocketPath)
	listener, err := net.Listen("unix", SocketPath)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err = os.Chmod(SocketPath, 0660); err != nil {
		return err
	}
	if err = chownMui(SocketPath); err != nil {
		return err
	}
	for {
		helperConnSem <- struct{}{}
		conn, err := listener.Accept()
		if err != nil {
			<-helperConnSem
			return err
		}
		go func() {
			defer func() { <-helperConnSem }()
			handleHelper(conn)
		}()
	}
}

func handleHelper(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(helperTimeout))
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return
	}
	var peerUID uint32
	var sockErr error
	_ = raw.Control(func(fd uintptr) {
		var cred *syscall.Ucred
		cred, sockErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if sockErr == nil {
			peerUID = cred.Uid
		}
	})
	if sockErr != nil {
		return
	}
	uid, err := userID(agentUser)
	if err != nil || peerUID != uint32(uid) {
		_ = json.NewEncoder(conn).Encode(helperResponse{Error: "unauthorized peer", ProtocolVersion: 1})
		return
	}
	var req helperRequest
	if err = json.NewDecoder(io.LimitReader(conn, 8<<20)).Decode(&req); err != nil {
		_ = json.NewEncoder(conn).Encode(helperResponse{Error: err.Error(), ProtocolVersion: 1})
		return
	}
	if req.ProtocolVersion != 1 {
		_ = json.NewEncoder(conn).Encode(helperResponse{Error: "unsupported helper protocol version", ProtocolVersion: 1})
		return
	}
	if len(req.StateRaw) > 0 {
		req.State = shared.DesiredState{}
		if err = json.Unmarshal(req.StateRaw, &req.State); err != nil {
			_ = json.NewEncoder(conn).Encode(helperResponse{Error: "invalid job state: " + err.Error(), ProtocolVersion: 1})
			return
		}
	}
	resp := helperResponse{ProtocolVersion: 1}
	// Every write kind runs under the write lock. Status is read-only and
	// exempt, so status queries keep working while an apply is in flight.
	switch req.Kind {
	case "status":
	case "ufw.ssh":
		// The periodic SSH check never waits behind an apply, which runs the
		// same check when it syncs UFW; waiting would stall the agent's
		// reports for as long as the apply takes.
		if !helperWriteMu.TryLock() {
			_ = json.NewEncoder(conn).Encode(resp)
			return
		}
		defer helperWriteMu.Unlock()
	default:
		helperWriteMu.Lock()
		defer helperWriteMu.Unlock()
	}
	switch req.Kind {
	case "status":
		status := hostStatus()
		resp.Status = &status
	case "ufw.init":
		err = initUFW()
	case "ufw.confirm":
		confirmUFW()
	case "ufw.ssh":
		err = ensureSSHAllowed()
	case "ufw.delete":
		err = deleteHostRules(req.State, req.StateRaw)
	// Apply kinds are strictly separated: firewall.apply reconciles UFW
	// rules only and never touches sing-box, certificates, or forwards;
	// the other apply kinds run the full apply. No apply kind ever
	// triggers a binary upgrade, and no upgrade kind ever changes
	// configuration or firewall rules.
	// Every apply kind runs the full apply. The panel supersedes queued jobs
	// with the newest one, which carries the whole desired state: a
	// firewall-only apply would silently drop a node change it superseded.
	// ApplyDesired restarts nothing whose configuration did not change.
	case "nodes.apply", "firewall.apply", "forwards.apply", "subscriptions.apply":
		err = ApplyDesired(req.State, req.StateRaw)
	case "agent.upgrade":
		err = runUpgradeOnce("agent.upgrade", req.State.UpgradeSHA256, func() error { return upgradeAgent(req.State.UpgradeSHA256, req.State.UpgradeRelease) })
	case "core.upgrade":
		err = runUpgradeOnce("core.upgrade", req.State.CoreUpgradeSHA256, func() error { return upgradeCore(req.State.CoreUpgradeSHA256, req.State.UpgradeRelease) })
	case "upgrade.confirm":
		err = writeUpgradeConfirmation(UpgradeConfirmedPath, req.State.UpgradeSHA256)
	default:
		err = errors.New("unsupported helper operation")
	}
	if err != nil {
		resp.Error = err.Error()
	}
	_ = json.NewEncoder(conn).Encode(resp)
}

// runUpgradeOnce executes an upgrade at most once per kind + SHA-256 per
// hour. A job redelivered after its first execution already succeeded
// returns success without downloading and swapping the binary again. It
// runs under the helper write lock.
func runUpgradeOnce(kind, sha string, run func() error) error {
	if sha == "" {
		return run()
	}
	key := kind + "\x00" + sha
	upgradeDedupMu.Lock()
	if at, ok := upgradeDedup[key]; ok && time.Since(at) < time.Hour {
		upgradeDedupMu.Unlock()
		return nil
	}
	upgradeDedupMu.Unlock()
	if err := run(); err != nil {
		return err
	}
	upgradeDedupMu.Lock()
	defer upgradeDedupMu.Unlock()
	for k, at := range upgradeDedup {
		if time.Since(at) >= time.Hour {
			delete(upgradeDedup, k)
		}
	}
	upgradeDedup[key] = time.Now()
	return nil
}

// writeUpgradeConfirmation records a build the panel has confirmed as
// healthy after an upgrade, so the rollback watchdog stands down.
func writeUpgradeConfirmation(path, sha string) error {
	if len(sha) != 64 {
		return errors.New("invalid upgrade SHA-256")
	}
	if _, err := hex.DecodeString(sha); err != nil {
		return errors.New("invalid upgrade SHA-256")
	}
	if err := os.WriteFile(path, []byte(sha), 0600); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}

func callHelper(kind string, state shared.DesiredState) (helperResponse, error) {
	return callHelperRaw(kind, state, nil)
}

func callHelperRaw(kind string, state shared.DesiredState, raw json.RawMessage) (helperResponse, error) {
	var resp helperResponse
	conn, err := net.DialTimeout("unix", SocketPath, 5*time.Second)
	if err != nil {
		return resp, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(helperTimeout))
	if err = json.NewEncoder(conn).Encode(helperRequest{Kind: kind, ProtocolVersion: 1, State: state, StateRaw: raw}); err != nil {
		return resp, err
	}
	if err = json.NewDecoder(conn).Decode(&resp); err != nil {
		return resp, err
	}
	if resp.Error != "" {
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}

func CallHelper(kind string, state shared.DesiredState) error {
	_, err := callHelper(kind, state)
	return err
}

// CallHelperJob runs a panel job, handing over the state's bytes as received
// so the helper checks the signature over exactly what the panel signed.
func CallHelperJob(job shared.Job) error {
	_, err := callHelperRaw(job.Kind, job.State, job.StateRaw)
	return err
}

// QueryHostStatus asks the root helper for the firewall state; `ufw status`
// and `sshd -T` both refuse to run as the unprivileged agent account.
func QueryHostStatus() HostStatus {
	resp, err := callHelper("status", shared.DesiredState{})
	if err != nil || resp.Status == nil {
		return HostStatus{UFW: "unavailable"}
	}
	return *resp.Status
}

func hostStatus() HostStatus {
	status := HostStatus{UFW: UFWStatus(), Conflict: firewallConflict(), ManualFirewallSupport: true, Supported: true, AgentSelfUpdate: true, ForwardSupport: true, ForwardTCPUDP: true, ShadowTLSAuth: true, SnellFixedPort: true, SnellV6: true, AgentProxySupport: true, OutboundBindingSupport: true, MultiUserStats: true, NodeFirewallPolicies: true, CoreSelfUpdate: true, ReleaseKeyPinned: fileExists(ReleaseKeyPath)}
	if file, err := os.Open(ForwardStats); err == nil {
		var traffic []shared.ForwardTrafficPoint
		_ = json.NewDecoder(io.LimitReader(file, 1<<20)).Decode(&traffic)
		_ = file.Close()
		now := time.Now()
		for _, point := range traffic {
			// A point without a timestamp predates the field; keep it. A
			// point older than 60s is from a dead forwarder instance.
			if !point.UpdatedAt.IsZero() && now.Sub(point.UpdatedAt) > 60*time.Second {
				continue
			}
			status.ForwardTraffic = append(status.ForwardTraffic, point)
		}
		if len(status.ForwardTraffic) > 500 {
			status.ForwardTraffic = status.ForwardTraffic[:500]
		}
	}
	status.ForwardConnections = readForwardConnections()
	if ports, err := sshPorts(); err == nil {
		for port := range ports {
			status.SSHPorts = append(status.SSHPorts, port)
		}
		sort.Ints(status.SSHPorts)
	}
	if out, err := command("ufw", "status", "numbered"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "[") && len(status.Rules) < 300 {
				status.Rules = append(status.Rules, line)
			}
		}
	}
	warnDirectFirewallRules()
	return status
}

// warnDirectFirewallRules logs iptables/nft rules that bypass UFW to stderr.
// They are a warning only: the panel still manages the mui rules, and a
// foreign rule never lands in HostStatus.Conflict, so it cannot block an
// apply that only touches UFW-managed rules.
func warnDirectFirewallRules() {
	if out, err := command("iptables", "-S", "INPUT"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "-A INPUT") {
				continue
			}
			// UFW owns its own chains; a jump from INPUT to anything
			// else is a rule UFW did not write.
			if idx := strings.Index(line, " -j "); idx >= 0 {
				target := strings.Fields(line[idx+4:])
				if len(target) > 0 && !strings.HasPrefix(target[0], "ufw-") && target[0] != "RETURN" {
					fmt.Fprintln(os.Stderr, "warning: direct iptables INPUT rule not managed by UFW:", line)
				}
			}
		}
	}
	if out, err := command("nft", "list", "ruleset"); err == nil {
		if trimmed := strings.TrimSpace(out); trimmed != "" && !strings.Contains(trimmed, "ufw") {
			fmt.Fprintln(os.Stderr, "warning: nftables ruleset contains rules not managed by UFW")
		}
	}
}

// firewallConflict names another service that manages the host firewall. Writing
// UFW rules next to it would leave the host in a state neither tool describes.
func firewallConflict() string {
	for _, unit := range []string{"firewalld", "nftables", "netfilter-persistent", "shorewall"} {
		if _, err := serviceCommand("is-active", "--quiet", unit+".service"); err == nil {
			return unit
		}
	}
	return ""
}

func conflictError(name string) error {
	return fmt.Errorf("检测到 %s 正在管理主机防火墙，已停止写入；请先停用它或手动处理冲突", name)
}

func userID(name string) (int, error) {
	out, err := command("id", "-u", name)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(out))
}
func groupID(name string) (int, error) {
	out, err := command("id", "-g", name)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(out))
}
func chownMui(path string) error {
	uid, err := userID(agentUser)
	if err != nil {
		return err
	}
	gid, err := groupID(agentUser)
	if err != nil {
		return err
	}
	return os.Chown(path, uid, gid)
}
func chownRootGroup(path, group string) error {
	gid, err := groupID(group)
	if err != nil {
		return err
	}
	return os.Chown(path, 0, gid)
}

func UFWStatus() string {
	out, err := command("ufw", "status")
	if err != nil {
		return "unavailable"
	}
	if strings.Contains(out, "Status: active") {
		return "active"
	}
	if strings.Contains(out, "Status: inactive") {
		return "inactive"
	}
	return "unknown"
}

func initUFW() error {
	if conflict := firewallConflict(); conflict != "" {
		return conflictError(conflict)
	}
	if UFWStatus() == "active" {
		return nil
	}
	ports, err := sshPorts()
	if err != nil {
		return err
	}
	for port := range ports {
		if _, err := command("ufw", "allow", strconv.Itoa(port)+"/tcp", "comment", "mui-ssh"); err != nil {
			return err
		}
	}
	confirmUFW()
	ufwPath, err := exec.LookPath("ufw")
	if err != nil {
		return err
	}
	if err := scheduleServiceJob("mui-ufw-rollback", 2*time.Minute, ufwPath, "--force", "disable"); err != nil {
		return fmt.Errorf("cannot arm UFW rollback: %w", err)
	}
	if _, err := command("ufw", "--force", "enable"); err != nil {
		confirmUFW()
		return err
	}
	if UFWStatus() != "active" {
		_, _ = command("ufw", "--force", "disable")
		confirmUFW()
		return errors.New("UFW did not become active")
	}
	if openRC() {
		if _, err := serviceCommand("enable", "ufw"); err != nil {
			_, _ = command("ufw", "--force", "disable")
			confirmUFW()
			return fmt.Errorf("enable UFW at boot: %w", err)
		}
	}
	return nil
}

// confirmUFW cancels the pending rollback. It has nothing to report: if the timer
// already fired, the unit is gone and the next status report shows UFW as inactive.
func confirmUFW() {
	cancelServiceJob("mui-ufw-rollback")
}

func sshPorts() (map[int]bool, error) {
	return detectSSHPorts(command)
}

func coreActive() bool {
	_, err := serviceCommand("is-active", "--quiet", "mui-sing-box.service")
	return err == nil
}

func coreInstalled() bool {
	info, err := os.Stat(CoreBinaryPath)
	return err == nil && info.Mode().IsRegular()
}

func needsCore(state shared.DesiredState) bool {
	for _, item := range state.Nodes {
		if item.Node.Enabled && !item.Node.Deleting {
			return true
		}
	}
	return false
}

func forwardActive() bool {
	_, err := serviceCommand("is-active", "--quiet", "mui-forward.service")
	return err == nil
}

func forwardEnabled() bool {
	_, err := serviceCommand("is-enabled", "--quiet", "mui-forward.service")
	return err == nil
}

// ApplyDesired applies the desired state with a 9-minute overall timeout. A
// timeout is not a failure: the apply keeps running in the background, and
// the caller must learn the outcome from a later job/status query instead
// of dispatching the job again.
func ApplyDesired(state shared.DesiredState, raw []byte) error {
	done := make(chan error, 1)
	go func() { done <- applyDesiredInternal(state, raw) }()
	select {
	case err := <-done:
		return err
	case <-time.After(9 * time.Minute):
		return errors.New("apply timed out after 9 minutes; it may still be running — check job status instead of re-dispatching")
	}
}

func applyDesiredInternal(state shared.DesiredState, raw []byte) (retErr error) {
	if err := verifyDesiredSignature(state, raw); err != nil {
		return err
	}
	if err := validateDesired(state); err != nil {
		return err
	}
	if err := checkOutboundInterfaces(state); err != nil {
		return err
	}
	if err := prepareAgentProxy(state, raw); err != nil {
		return err
	}
	hasCore := coreInstalled()
	if needsCore(state) && !hasCore {
		return errors.New("该服务器未安装 sing-box；请先在服务器列表点击安装 sing-box")
	}
	forwardConfig := runtimeForwards(state)
	needsForward := len(forwardConfig) > 0
	wasForwardActive := forwardActive()
	wasForwardEnabled := forwardEnabled()
	previousForward, _ := os.ReadFile(ForwardConfig)
	forwardConfigEmpty := len(previousForward) == 0 || bytes.Equal(bytes.TrimSpace(previousForward), []byte("[]"))
	current, err := readCurrentChecked()
	if err != nil {
		return err
	}
	if current.Revision == state.Revision && state.Revision > 0 {
		forwardReady := (needsForward && wasForwardActive && wasForwardEnabled) || (!needsForward && !wasForwardActive && !wasForwardEnabled && forwardConfigEmpty)
		if (shared.ManualFirewall(state.FirewallMode) || UFWStatus() == "active") && (!hasCore || coreActive()) && forwardReady && !driftDetected(state, hasCore) && proxyMatches(state.AgentProxy) {
			return nil
		}
	}
	if current.Revision > state.Revision {
		return fmt.Errorf("stale configuration revision %d (current %d)", state.Revision, current.Revision)
	}
	if !shared.ManualFirewall(state.FirewallMode) {
		if conflict := firewallConflict(); conflict != "" {
			return conflictError(conflict)
		}
		if UFWStatus() != "active" {
			return errors.New("UFW 未启用；请初始化 UFW 或在服务器设置中选择手动管理防火墙")
		}
		if err := checkRouteUFWSSH(state); err != nil {
			return err
		}
		if err := checkManualUFWBypass(state); err != nil {
			return err
		}
		if restrictedNodesNeedDeny(state) {
			status, err := command("ufw", "status", "verbose")
			if err != nil || !defaultIncomingDeny.MatchString(status) {
				return errors.New("指定来源模式要求 UFW 默认入站策略为 deny 或 reject")
			}
		}
	}
	coreUnitChanged := false
	restoreCoreUnit := func() {}
	if hasCore {
		path, unit, mode := serviceFile("mui-sing-box.service", coreUnitForState(state))
		previousUnit, readErr := os.ReadFile(path)
		if readErr != nil && !os.IsNotExist(readErr) {
			return readErr
		}
		coreUnitChanged = !bytes.Equal(previousUnit, []byte(unit))
		if coreUnitChanged {
			restored := false
			restoreCoreUnit = func() {
				if restored {
					return
				}
				restored = true
				if os.IsNotExist(readErr) {
					_ = os.Remove(path)
				} else {
					_ = writeFileAtomic(path, previousUnit, mode)
				}
				_, _ = serviceCommand("daemon-reload")
			}
			defer func() {
				if retErr != nil {
					restoreCoreUnit()
				}
			}()
		}
		if err := ensureCoreUnit(state); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(DataDir, 0750); err != nil {
		return err
	}
	if err := chownMui(DataDir); err != nil {
		return err
	}
	forwardUnitChanged := false
	if needsForward {
		var err error
		if forwardUnitChanged, err = ensureForwardUnit(); err != nil {
			return err
		}
	}
	if err := checkNewPorts(current, state); err != nil {
		return err
	}

	// Certificates are replaced in place; remember what was there so a failed
	// apply leaves the previous configuration with its own certificates.
	certBackup := map[string][]byte{}
	restoreCerts := func() {
		for path, old := range certBackup {
			if old == nil {
				_ = os.Remove(path)
			} else {
				_ = writeOwned(path, old, 0640, coreUser)
			}
		}
	}
	for _, item := range state.Nodes {
		if item.Node.Protocol != "anytls" || !item.Node.Enabled {
			continue
		}
		if item.CertificatePEM == "" || item.CertificateKey == "" {
			restoreCerts()
			return fmt.Errorf("node %s missing certificate", item.Node.ID)
		}
		for path, content := range map[string]string{CertDir + "/" + item.Node.ID + ".crt": item.CertificatePEM, CertDir + "/" + item.Node.ID + ".key": item.CertificateKey} {
			old, err := os.ReadFile(path)
			if err == nil && bytes.Equal(old, []byte(content)) {
				continue
			}
			if err != nil {
				old = nil
			}
			certBackup[path] = old
			if err := writeOwned(path, []byte(content), 0640, coreUser); err != nil {
				restoreCerts()
				return err
			}
		}
	}
	var config []byte
	if hasCore {
		config, err = shared.SingBoxConfig(state.Nodes, CertDir, state.OutboundInterface)
		if err != nil {
			restoreCerts()
			return err
		}
	}
	previous, _ := os.ReadFile(CoreConfig)
	forwardRaw, err := json.Marshal(forwardConfig)
	if err != nil {
		return err
	}
	forwardChanged := (needsForward && (!bytes.Equal(previousForward, forwardRaw) || !wasForwardActive || !wasForwardEnabled)) || (!needsForward && (wasForwardActive || wasForwardEnabled || !forwardConfigEmpty))
	oldState := readCurrentRaw()
	// Restarting the core drops every connection on the host, so only do it when
	// what the core reads has actually changed. Firewall-only jobs skip it.
	coreChanged := hasCore && (coreUnitChanged || len(certBackup) > 0 || !bytes.Equal(previous, config) || !coreActive())
	tmp := CoreConfig + ".next"
	if coreChanged {
		if err := writeOwned(tmp, config, 0640, coreUser); err != nil {
			restoreCerts()
			return err
		}
		if _, err := command(CoreBinaryPath, "check", "-c", tmp); err != nil {
			_ = os.Remove(tmp)
			restoreCerts()
			return err
		}
	}
	if err = syncUFW(state); err != nil {
		_ = os.Remove(tmp)
		if !shared.ManualFirewall(state.FirewallMode) {
			if rollbackErr := restoreUFW(oldState); rollbackErr != nil {
				err = fmt.Errorf("%w; restore previous UFW policy: %v", err, rollbackErr)
			}
		}
		restoreCerts()
		return err
	}
	forwardTouched := false
	rollbackForward := func() error {
		rollbackRaw := previousForward
		if len(rollbackRaw) == 0 && wasForwardActive {
			rollbackRaw = []byte("[]")
		}
		if len(rollbackRaw) > 0 {
			if err := writeOwned(ForwardConfig, rollbackRaw, 0640, forwardUser); err != nil {
				return err
			}
		} else if err := os.Remove(ForwardConfig); err != nil && !os.IsNotExist(err) {
			return err
		}
		_ = os.Remove(ForwardReady)
		if wasForwardEnabled {
			if _, err := serviceCommand("enable", "mui-forward.service"); err != nil {
				return err
			}
		} else if _, err := serviceCommand("disable", "mui-forward.service"); err != nil {
			return err
		}
		if !wasForwardActive {
			_, err := serviceCommand("stop", "mui-forward.service")
			return err
		}
		// A failed reload can leave some new rules running. Reload the old file
		// in place first so rules that never changed keep their connections.
		if forwardActive() && !forwardUnitChanged {
			if _, err := serviceCommand("reload", "mui-forward.service"); err == nil {
				if err = waitForwardReady(rollbackRaw); err == nil {
					return nil
				}
			}
		}
		if _, err := serviceCommand("restart", "mui-forward.service"); err != nil {
			return err
		}
		return waitForwardReady(rollbackRaw)
	}
	fail := func(err error) error {
		restoreCerts()
		if forwardTouched {
			if rollbackErr := rollbackForward(); rollbackErr != nil {
				err = fmt.Errorf("%w; restore previous forward configuration: %v", err, rollbackErr)
			}
		}
		if coreChanged {
			restoreCoreUnit()
			rollbackCore(previous)
		}
		if !shared.ManualFirewall(state.FirewallMode) {
			if rollbackErr := restoreUFW(oldState); rollbackErr != nil {
				err = fmt.Errorf("%w; restore previous UFW policy: %v", err, rollbackErr)
			}
		}
		return err
	}
	if coreChanged {
		if err = os.Rename(tmp, CoreConfig); err != nil {
			return fail(err)
		}
		if _, err = serviceCommand("restart", "mui-sing-box.service"); err != nil {
			return fail(err)
		}
		if !coreActive() {
			return fail(errors.New("sing-box did not stay running after restart"))
		}
		if err = verifyNodeListeners(state); err != nil {
			return fail(err)
		}
		if _, err = serviceCommand("enable", "mui-sing-box.service"); err != nil {
			return fail(err)
		}
	}
	if forwardChanged {
		forwardTouched = true
		if needsForward {
			if err = writeOwned(ForwardConfig, forwardRaw, 0640, forwardUser); err != nil {
				return fail(err)
			}
			_ = os.Remove(ForwardReady)
			if _, err = serviceCommand("enable", "mui-forward.service"); err != nil {
				return fail(err)
			}
			// A running forwarder applies the new rules in place, so connections of
			// rules that did not change survive. A process started from an older
			// unit file may not know how to, and a stopped one has to be started.
			action := "restart"
			if wasForwardActive && !forwardUnitChanged {
				action = "reload"
			}
			if _, err = serviceCommand(action, "mui-forward.service"); err != nil {
				return fail(err)
			}
			err = waitForwardReady(forwardRaw)
			if err != nil {
				return fail(err)
			}
		} else {
			if len(previousForward) > 0 {
				if err = os.WriteFile(ForwardConfig, forwardRaw, 0640); err != nil {
					return fail(err)
				}
			}
			if _, err = serviceCommand("disable", "--now", "mui-forward.service"); err != nil {
				return fail(err)
			}
		}
	}
	currentJSON, err := mustJSON(sanitizeStateForStorage(state))
	if err != nil {
		return fail(err)
	}
	// Commit the proxy before acknowledging this revision. If committing the
	// revision fails, restore the previous connection settings atomically.
	var oldAgentConfig []byte
	proxyChanged := state.AgentProxy != nil && !proxyMatches(state.AgentProxy)
	if proxyChanged {
		oldAgentConfig, err = os.ReadFile(ConfigDir + "/config.json")
		if err != nil {
			return fail(err)
		}
		if err = saveAgentProxy(state.AgentProxy); err != nil {
			return fail(err)
		}
	}
	if err = writeOwned(CurrentState, []byte(currentJSON), 0640, agentUser); err != nil {
		if proxyChanged {
			if restoreErr := writeOwned(ConfigDir+"/config.json", oldAgentConfig, 0640, agentUser); restoreErr != nil {
				err = fmt.Errorf("%w; restore Agent proxy: %v", err, restoreErr)
			}
		}
		return fail(err)
	}
	_ = os.Remove(legacyCurrentState)
	if err := removeStaleCerts(state); err != nil {
		return err
	}
	return nil
}

// verifyDesiredSignature checks a panel signature over the desired state. The
// signature covers the state with the Signature field cleared, so the panel
// signs exactly what the helper verifies. The signature itself is base64,
// the same encoding the release manifest signatures use. Unsigned states
// are still accepted while panels roll out signing, and a signature without
// a pinned panel key is accepted as well; both cases log a warning so the
// gap is visible instead of silent.
func verifyDesiredSignature(state shared.DesiredState, raw []byte) error {
	panelKey, err := panelPublicKey()
	if err != nil {
		return err
	}
	if state.Signature == "" {
		if panelKey != nil {
			fmt.Fprintln(os.Stderr, "warning: desired state is not signed, but a panel public key is pinned; accepting for compatibility")
		}
		return nil
	}
	if panelKey == nil {
		fmt.Fprintln(os.Stderr, "warning: desired state carries a signature, but no panel public key is pinned; accepting without verification")
		return nil
	}
	// The bytes as received are what the panel signed. Re-encoding with
	// this agent's own types would drop fields it does not know yet.
	if len(raw) > 0 {
		return shared.VerifyDesiredStateRaw(panelKey, raw)
	}
	return shared.VerifyDesiredState(panelKey, state)
}

func panelPublicKey() (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(PanelPublicKeyPath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return shared.ParseReleaseKey(string(raw))
}

// sanitizeStateForStorage strips secrets from a state before it is written
// to disk. CurrentState is readable by the agent account, so passwords and
// private keys must never land there; Name/SubscriptionID stay so traffic
// can still be attributed to subscriptions.
func sanitizeStateForStorage(state shared.DesiredState) shared.DesiredState {
	out := state
	out.AgentProxy = nil
	out.Nodes = make([]shared.ManagedNode, len(state.Nodes))
	for i, item := range state.Nodes {
		item.Password = ""
		item.ShadowTLSPassword = ""
		item.CertificatePEM = ""
		item.CertificateKey = ""
		item.Users = make([]shared.NodeUser, len(item.Users))
		for j, user := range state.Nodes[i].Users {
			user.Password = ""
			user.ShadowTLSPassword = ""
			item.Users[j] = user
		}
		out.Nodes[i] = item
	}
	return out
}

// driftDetected reports whether on-disk state diverged from the desired
// state. Revision equality alone cannot prove convergence: a hand-edited
// core config, a replaced certificate, or a missing UFW rule all keep the
// revision, so the early return must check the artifacts themselves.
func driftDetected(state shared.DesiredState, hasCore bool) bool {
	if hasCore {
		path, unit, _ := serviceFile("mui-sing-box.service", coreUnitForState(state))
		if current, err := os.ReadFile(path); err != nil || !bytes.Equal(current, []byte(unit)) {
			return true
		}
		want, err := shared.SingBoxConfig(state.Nodes, CertDir, state.OutboundInterface)
		if err != nil {
			return true
		}
		have, err := os.ReadFile(CoreConfig)
		if err != nil || sha256.Sum256(have) != sha256.Sum256(want) {
			return true
		}
	}
	for _, item := range state.Nodes {
		if item.Node.Protocol != "anytls" || !item.Node.Enabled {
			continue
		}
		crt, err := os.ReadFile(CertDir + "/" + item.Node.ID + ".crt")
		if err != nil || !bytes.Equal(crt, []byte(item.CertificatePEM)) {
			return true
		}
		key, err := os.ReadFile(CertDir + "/" + item.Node.ID + ".key")
		if err != nil || !bytes.Equal(key, []byte(item.CertificateKey)) {
			return true
		}
	}
	if shared.ManualFirewall(state.FirewallMode) {
		return false
	}
	out, err := command("ufw", "status", "numbered")
	if err != nil {
		return true
	}
	if routeUFWDrift(out, state) {
		return true
	}
	present := map[string]bool{}
	for _, line := range append(parseMuiLines(out), parseLegacyLines(out)...) {
		present[line.ID] = true
	}
	wanted := map[string]bool{}
	for _, rule := range baseUFWRules(state) {
		wanted[rule.ID] = true
	}
	for _, rule := range routeUFWRules(state) {
		wanted[rule.ID] = true
	}
	if len(present) != len(wanted) {
		return true
	}
	for id := range wanted {
		if !present[id] {
			return true
		}
	}
	return false
}

type ufwStatusRule struct {
	action   string
	allowAll bool
	ports    []portProto
}

// parseUFWStatusRule parses one `ufw status numbered` rule line, e.g.
// "[ 2] 8000:8010/tcp ALLOW IN Anywhere". An "Anywhere" port spec means
// the rule opens every port; a spec without "/proto" is treated as both
// TCP and UDP, matching ufw's own display.
func parseUFWStatusRule(line string) (ufwStatusRule, bool) {
	close := strings.Index(line, "]")
	if close < 0 {
		return ufwStatusRule{}, false
	}
	fields := strings.Fields(line[close+1:])
	if len(fields) < 2 {
		return ufwStatusRule{}, false
	}
	rule := ufwStatusRule{}
	for _, field := range fields[1:] {
		if field == "ALLOW" || field == "DENY" {
			rule.action = field
			break
		}
	}
	if rule.action == "" {
		return ufwStatusRule{}, false
	}
	spec := fields[0]
	if spec == "Anywhere" {
		rule.allowAll = true
		return rule, true
	}
	proto := ""
	if i := strings.LastIndex(spec, "/"); i >= 0 {
		proto = strings.ToLower(spec[i+1:])
		spec = spec[:i]
	}
	protos := []string{"tcp", "udp"}
	if proto == "tcp" || proto == "udp" {
		protos = []string{proto}
	}
	from, to := 0, 0
	if i := strings.Index(spec, ":"); i >= 0 {
		var err error
		from, err = strconv.Atoi(spec[:i])
		if err != nil {
			return ufwStatusRule{}, false
		}
		to, err = strconv.Atoi(spec[i+1:])
		if err != nil {
			return ufwStatusRule{}, false
		}
	} else {
		port, err := strconv.Atoi(spec)
		if err != nil {
			return ufwStatusRule{}, false
		}
		from, to = port, port
	}
	if from < 1 || to < from || to > 65535 {
		return ufwStatusRule{}, false
	}
	for port := from; port <= to; port++ {
		for _, p := range protos {
			rule.ports = append(rule.ports, portProto{port, p})
		}
	}
	return rule, true
}

// checkManualUFWBypass refuses an apply when a rule UFW does not manage
// already allows traffic to a port this batch manages. Such a rule sits
// outside the panel's model: it would silently bypass a deny rule or a
// restricted-source rule. Chain ports have a verified allow/deny prefix that
// takes precedence over host rules, so they do not need this refusal.
func checkManualUFWBypass(state shared.DesiredState) error {
	out, err := command("ufw", "status", "numbered")
	if err != nil {
		return err
	}
	managed := map[portProto]bool{}
	for _, item := range state.Nodes {
		n := item.Node
		if !n.Enabled || n.Deleting {
			continue
		}
		managed[portProto{n.Port, "tcp"}] = true
		if n.Protocol == "ss" {
			managed[portProto{n.Port, "udp"}] = true
		}
	}
	for _, f := range state.Forwards {
		if !f.Enabled || f.Deleting {
			continue
		}
		for _, network := range shared.ForwardNetworks(f.Network) {
			managed[portProto{f.Port, network}] = true
		}
	}
	for _, rule := range state.Rules {
		if rule.Deleting {
			continue
		}
		for port := rule.PortFrom; port <= rule.PortTo; port++ {
			managed[portProto{port, rule.Network}] = true
		}
	}
	for pp := range routeUFWPorts(state) {
		delete(managed, pp)
	}
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "[") {
			continue
		}
		// Tagged rules belong to mui or the legacy panel; only untagged
		// rules can be foreign bypasses.
		if strings.Contains(trimmed, "# mui-") || strings.Contains(trimmed, "# panel-") {
			continue
		}
		rule, ok := parseUFWStatusRule(trimmed)
		if !ok || rule.action != "ALLOW" {
			continue
		}
		if rule.allowAll && len(managed) > 0 {
			return fmt.Errorf("UFW 规则 %q 未经面板管理，却放行了全部端口；请先删除该规则", trimmed)
		}
		for _, pp := range rule.ports {
			if managed[pp] {
				return fmt.Errorf("UFW 规则 %q 未经面板管理，却放行了本批管理的端口 %d/%s；请先删除该规则", trimmed, pp.port, pp.proto)
			}
		}
	}
	return nil
}

func runtimeForwards(state shared.DesiredState) []shared.ForwardRule {
	out := make([]shared.ForwardRule, 0, len(state.Forwards))
	for _, f := range state.Forwards {
		if f.Enabled && !f.Deleting {
			// FirewallPolicy/FirewallSources ride along: the forward
			// process needs them for its own source filtering, and
			// syncUFW reads them when it builds the forward rules.
			out = append(out, shared.ForwardRule{ID: f.ID, Name: f.Name, Network: f.Network, Listen: f.Listen, Port: f.Port, Targets: f.Targets, Balance: f.Balance, HealthCheck: f.HealthCheck, RouteID: f.RouteID, ObserveClients: f.ObserveClients, ClientNodeID: f.ClientNodeID, FirewallPolicy: f.FirewallPolicy, FirewallSources: f.FirewallSources, Enabled: true})
		}
	}
	return out
}

func coreUnitForState(state shared.DesiredState) string {
	unit := coreUnit
	if len(shared.OutboundInterfaces(state.Nodes, state.OutboundInterface)) > 0 {
		// Older Linux kernels require NET_RAW for SO_BINDTODEVICE. Keep the
		// core unprivileged and grant it only while device binding is in use.
		unit = strings.ReplaceAll(unit, "=CAP_NET_BIND_SERVICE\n", "=CAP_NET_BIND_SERVICE CAP_NET_RAW\n")
	}
	return unit
}

func ensureCoreUnit(states ...shared.DesiredState) error {
	state, err := readCurrentChecked()
	if err != nil {
		return err
	}
	if len(states) > 0 {
		state = states[0]
	}
	if err := ensureServiceUser(coreUser, CoreDir); err != nil {
		return err
	}
	for _, dir := range []string{CoreDir, CertDir} {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return err
		}
		if err := chownRootGroup(dir, coreUser); err != nil {
			return err
		}
	}
	path, unit, mode := serviceFile("mui-sing-box.service", coreUnitForState(state))
	content, err := os.ReadFile(path)
	if err == nil && string(content) == unit {
		return nil
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := writeFileAtomic(path, []byte(unit), mode); err != nil {
		return err
	}
	if _, err := serviceCommand("daemon-reload"); err != nil {
		return err
	}
	_, err = serviceCommand("enable", "mui-sing-box.service")
	return err
}

// ensureForwardUnit reports whether it had to (re)write the unit file.
func ensureForwardUnit() (bool, error) {
	if err := ensureServiceUser(forwardUser, ForwardDir); err != nil {
		return false, err
	}
	if err := makeDirectory(ForwardDir, 0750); err != nil {
		return false, err
	}
	if err := chownRootGroup(ForwardDir, forwardUser); err != nil {
		return false, err
	}
	if _, err := os.Stat(ForwardConfig); os.IsNotExist(err) {
		if err := writeOwned(ForwardConfig, []byte("[]"), 0640, forwardUser); err != nil {
			return false, err
		}
	} else if err != nil {
		return false, err
	}
	path, unit, mode := serviceFile("mui-forward.service", forwardUnit)
	content, err := os.ReadFile(path)
	if err == nil && string(content) == unit {
		return false, nil
	}
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	if err := writeFileAtomic(path, []byte(unit), mode); err != nil {
		return false, err
	}
	if _, err := serviceCommand("daemon-reload"); err != nil {
		return false, err
	}
	return true, nil
}

func waitForwardReady(config []byte) error {
	digest := sha256.Sum256(config)
	want := hex.EncodeToString(digest[:])
	for i := 0; i < 20; i++ {
		if got, err := os.ReadFile(ForwardReady); err == nil && string(got) == want && forwardActive() {
			return nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	return errors.New("转发进程未能启动并监听端口，请查看 mui-forward.service 日志")
}

func verifyNodeListeners(state shared.DesiredState) error {
	for _, item := range state.Nodes {
		if !item.Node.Enabled {
			continue
		}
		host := item.Node.Listen
		if host == "" || host == "0.0.0.0" {
			host = "127.0.0.1"
		} else if host == "::" {
			host = "::1"
		}
		addr := net.JoinHostPort(host, strconv.Itoa(item.Node.Port))
		var conn net.Conn
		var err error
		for attempt := 0; attempt < 10; attempt++ {
			conn, err = net.DialTimeout("tcp", addr, 300*time.Millisecond)
			if err == nil {
				break
			}
			time.Sleep(300 * time.Millisecond)
		}
		if err != nil {
			return fmt.Errorf("节点 %q 未能监听端口 %d: %w", item.Node.Name, item.Node.Port, err)
		}
		_ = conn.Close()
	}
	return nil
}

// checkNewPorts probes forward ports before the forwarder reloads. A forward
// listener only binds at reload time, so this is the only early signal
// that another process already holds the port. It is best-effort: a port
// can be taken between this probe and the reload (TOCTOU), and the reload
// failure itself remains the authoritative check. Node ports are not probed
// here: binding a node port just to test it would steal it from the running
// core, and a node conflict surfaces through verifyNodeListeners after
// sing-box restarts.
func checkNewPorts(current, next shared.DesiredState) error {
	active := forwardActive()
	for _, f := range next.Forwards {
		if !f.Enabled || f.Deleting {
			continue
		}
		for _, network := range shared.ForwardNetworks(f.Network) {
			alreadyListening := false
			if active {
				for _, old := range current.Forwards {
					if old.Enabled && !old.Deleting && shared.ForwardNetworkIncludes(old.Network, network) && old.Port == f.Port && old.Listen == f.Listen {
						alreadyListening = true
						break
					}
				}
			}
			if alreadyListening {
				continue
			}
			listen := f.Listen
			if listen == "" {
				listen = "0.0.0.0"
			} else if listen == "::" {
				listen = ""
			}
			address := net.JoinHostPort(listen, strconv.Itoa(f.Port))
			if network == "tcp" {
				listener, err := net.Listen("tcp", address)
				if err != nil {
					return fmt.Errorf("转发 %q 的 TCP 端口 %d 无法监听: %w", f.Name, f.Port, err)
				}
				_ = listener.Close()
			} else {
				listener, err := net.ListenPacket("udp", address)
				if err != nil {
					return fmt.Errorf("转发 %q 的 UDP 端口 %d 无法监听: %w", f.Name, f.Port, err)
				}
				_ = listener.Close()
			}
		}
	}
	return nil
}

// removeStaleCerts deletes key material of nodes that no longer use it. A
// missing certificate directory means there is nothing to clean; any other
// read or remove failure is reported so a leftover private key cannot hide
// behind a silent error.
func removeStaleCerts(state shared.DesiredState) error {
	wanted := map[string]bool{}
	for _, item := range state.Nodes {
		if item.Node.Protocol == "anytls" && item.Node.Enabled {
			wanted[item.Node.ID+".crt"] = true
			wanted[item.Node.ID+".key"] = true
		}
	}
	entries, err := os.ReadDir(CertDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() && !wanted[entry.Name()] {
			if err := os.Remove(filepath.Join(CertDir, entry.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

// writeOwned atomically writes a root-owned file readable by the given account's group.
func writeOwned(path string, data []byte, mode os.FileMode, group string) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".mui-tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Chmod(tmp, mode); err != nil {
		return err
	}
	if err = chownRootGroup(tmp, group); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
func mustJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}
func rollbackCore(previous []byte) {
	if len(previous) > 0 {
		_ = writeOwned(CoreConfig, previous, 0640, coreUser)
		_, _ = serviceCommand("restart", "mui-sing-box.service")
	} else {
		_, _ = serviceCommand("stop", "mui-sing-box.service")
		_, _ = serviceCommand("disable", "mui-sing-box.service")
		_ = os.Remove(CoreConfig)
	}
}
func restoreUFW(oldState []byte) error {
	var state shared.DesiredState
	if len(oldState) > 0 {
		// A previous state that does not parse must fail loudly: rolling
		// UFW back to a half-decoded state would silently drop rules.
		if err := json.Unmarshal(oldState, &state); err != nil {
			return fmt.Errorf("cannot parse previous state for UFW restore: %w", err)
		}
	}
	return syncUFW(state)
}

func syncUFW(state shared.DesiredState) error {
	if shared.ManualFirewall(state.FirewallMode) {
		return nil
	}
	// ownedRulesError is the fail-closed gate: an illegal policy, action,
	// port, or source must stop the sync before any rule is written.
	if err := ownedRulesError(state); err != nil {
		return err
	}
	out, err := command("ufw", "status", "numbered")
	if err != nil {
		return err
	}
	if err := syncRouteUFW(state, out); err != nil {
		return err
	}
	out, err = command("ufw", "status", "numbered")
	if err != nil {
		return err
	}
	present := append(parseMuiLines(out), parseLegacyLines(out)...)
	base := present[:0]
	for _, line := range present {
		if !strings.HasPrefix(line.ID, routeUFWPrefix) {
			base = append(base, line)
		}
	}
	present = base
	sort.Slice(present, func(i, j int) bool { return present[i].Index < present[j].Index })
	rules := baseUFWRules(state)
	byID := map[string]shared.FirewallRule{}
	desired := make([]string, 0, len(rules))
	for _, rule := range rules {
		byID[rule.ID] = rule
		desired = append(desired, rule.ID)
	}
	// planUFW only produces the increment, so re-running syncUFW after a
	// failure resumes where it stopped instead of rebuilding everything;
	// every rule is applied idempotently.
	remove, add := planUFW(present, desired)
	indices := []int{}
	for _, line := range present {
		if remove[line.ID] {
			indices = append(indices, line.Index)
		}
	}
	// Highest number first: deleting a rule renumbers the ones after it.
	sort.Sort(sort.Reverse(sort.IntSlice(indices)))
	// One slow `ufw` invocation must not stall the whole sync: scale the
	// per-call budget with the number of rules being written.
	timeout := 60*time.Second + time.Duration(len(indices)+len(add))*2*time.Second
	if timeout > 10*time.Minute {
		timeout = 10 * time.Minute
	}
	for _, i := range indices {
		if _, err := commandTimeout("ufw", timeout, "--force", "delete", strconv.Itoa(i)); err != nil {
			return err
		}
	}
	for _, id := range add {
		if err := addUFWRule(byID[id], timeout); err != nil {
			return err
		}
	}
	return ensureSSHAllowedForMode(state.FirewallMode)
}

// ensureSSHAllowed opens every SSH port (listening or configured) that no
// allowing UFW rule covers. The rule written at UFW initialisation protects
// only the ports of that moment; without this, moving sshd to a new port
// would lock the host out at the next sshd restart. Nothing in the request
// steers it: the ports come from this host alone.
func ensureSSHAllowed() error {
	current, err := readCurrentChecked()
	if err != nil {
		return err
	}
	// Wait for a signed configuration before automatically writing rules.
	if current.Revision == 0 {
		return nil
	}
	return ensureSSHAllowedForMode(current.FirewallMode)
}

func ensureSSHAllowedForMode(mode string) error {
	if shared.ManualFirewall(mode) {
		return nil
	}
	if UFWStatus() != "active" {
		return nil
	}
	ports, err := sshPorts()
	if err != nil {
		return err
	}
	list := make([]int, 0, len(ports))
	for port := range ports {
		list = append(list, port)
	}
	out, err := command("ufw", "status", "numbered")
	if err != nil {
		return err
	}
	for _, port := range shared.UncoveredSSHPorts(out, list) {
		if _, err := command("ufw", "allow", strconv.Itoa(port)+"/tcp", "comment", "mui-ssh"); err != nil {
			return err
		}
	}
	return nil
}

// deleteHostRules removes rules that were added on the host outside the
// panel, each listed line on its own: removing an IPv6 line leaves the IPv4
// line of the same rule in place. It is signed like an apply, never
// touches a rule the panel manages, and refuses any rule that may admit SSH.
// The whole batch is checked before anything is deleted. Rules that are
// already gone are not an error.
func deleteHostRules(state shared.DesiredState, raw []byte) error {
	if err := verifyDesiredSignature(state, raw); err != nil {
		return err
	}
	current, err := readCurrentChecked()
	if err != nil {
		return err
	}
	if shared.ManualFirewall(state.FirewallMode) || shared.ManualFirewall(current.FirewallMode) {
		return errors.New("手动管理模式不允许通过面板删除 UFW 规则")
	}
	if len(state.HostRules) == 0 || len(state.HostRules) > 100 {
		return errors.New("invalid host rule batch")
	}
	want := map[string]bool{}
	for _, rule := range state.HostRules {
		key := shared.UFWRuleKey(rule)
		if key == "" || len(rule) > 300 {
			return errors.New("invalid host rule")
		}
		want[key] = true
	}
	out, err := command("ufw", "status", "numbered")
	if err != nil {
		return err
	}
	ports, err := sshPorts()
	if err != nil {
		return err
	}
	ssh := make([]int, 0, len(ports))
	for port := range ports {
		ssh = append(ssh, port)
	}
	var indices []int
	for _, raw := range strings.Split(out, "\n") {
		line, ok := shared.ParseUFWLine(raw)
		if !ok || !want[shared.UFWRuleKey(line.Rule)] {
			continue
		}
		if reason := shared.HostRuleError(line, ssh); reason != "" {
			return fmt.Errorf("%s: %s", line.Rule, reason)
		}
		indices = append(indices, line.Index)
	}
	// Highest number first: deleting a rule renumbers the ones after it.
	sort.Sort(sort.Reverse(sort.IntSlice(indices)))
	for _, i := range indices {
		if _, err := command("ufw", "--force", "delete", strconv.Itoa(i)); err != nil {
			return err
		}
	}
	return nil
}

func addUFWRule(rule shared.FirewallRule, timeout time.Duration) error {
	return addUFWRuleAt(rule, timeout, false)
}

func addUFWRuleAt(rule shared.FirewallRule, timeout time.Duration, routePriority bool) error {
	if rule.Action != "allow" && rule.Action != "deny" {
		return errors.New("invalid UFW action")
	}
	if rule.Network != "tcp" && rule.Network != "udp" {
		return errors.New("invalid UFW network")
	}
	if rule.PortFrom < 1 || rule.PortTo < rule.PortFrom || rule.PortTo > 65535 {
		return errors.New("invalid UFW port")
	}
	if rule.Action == "deny" && rule.Network == "tcp" {
		ports, err := sshPorts()
		if err != nil {
			return err
		}
		for port := range ports {
			if port >= rule.PortFrom && port <= rule.PortTo {
				return errors.New("refusing to deny active SSH port")
			}
		}
	}
	port := strconv.Itoa(rule.PortFrom)
	if rule.PortTo > rule.PortFrom {
		port += ":" + strconv.Itoa(rule.PortTo)
	}
	source := rule.Source
	if source == "" {
		// "any" covers both families; a single family is its whole range.
		switch rule.Family {
		case "ipv4":
			source = "0.0.0.0/0"
		case "ipv6":
			source = "::/0"
		default:
			source = "any"
		}
	} else {
		if _, _, err := net.ParseCIDR(source); err != nil {
			return err
		}
	}
	if strings.ContainsAny(rule.ID, " \t\n\r'\"") {
		return errors.New("invalid UFW rule ID")
	}
	args := []string{rule.Action, "from", source, "to", "any", "port", port, "proto", rule.Network, "comment", "mui-" + rule.ID}
	if routePriority {
		args = []string{"prepend", rule.Action, "from", source, "to", "any", "app", routeUFWApp(rule), "comment", "mui-" + rule.ID}
	}
	_, err := commandTimeout("ufw", timeout, args...)
	return err
}

// readCurrentRaw returns the applied state as stored, or nil. Installations
// from before the file moved are read from the old location until their next
// successful apply rewrites it.
func readCurrentRaw() []byte {
	if b, err := os.ReadFile(CurrentState); err == nil {
		return b
	}
	b, err := os.ReadFile(legacyCurrentState)
	if err != nil {
		return nil
	}
	return b
}

func ReadCurrent() shared.DesiredState {
	state, _ := readCurrentChecked()
	return sanitizeStateForStorage(state)
}

// readCurrentChecked fails closed: a CurrentState file that exists but does
// not parse must never be treated as an empty state, or an apply could
// silently drop the live configuration.
func readCurrentChecked() (shared.DesiredState, error) {
	var state shared.DesiredState
	raw := readCurrentRaw()
	if len(raw) == 0 {
		return state, nil
	}
	if err := json.Unmarshal(raw, &state); err != nil {
		return shared.DesiredState{}, fmt.Errorf("cannot parse applied state: %w", err)
	}
	return state, nil
}

// pinnedReleaseKey returns the release key fixed at install time, if any.
func pinnedReleaseKey() (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(ReleaseKeyPath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return shared.ParseReleaseKey(string(raw))
}
func CoreVersion() string {
	out, err := command(CoreBinaryPath, "version")
	if err != nil {
		return "unavailable"
	}
	return strings.TrimSpace(strings.Split(out, "\n")[0])
}
func CheckCoreBuild() error { return checkCoreBuildAt(CoreBinaryPath) }

func checkCoreBuildAt(path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	versionOut, err := exec.CommandContext(ctx, path, "version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("sing-box version check: %w: %s", err, strings.TrimSpace(string(versionOut)))
	}
	out := string(versionOut)
	if !strings.Contains(out, "with_v2ray_api") {
		return errors.New("sing-box must include with_v2ray_api build tag")
	}
	if !strings.Contains(out, "with_clash_api") {
		return errors.New("sing-box must include with_clash_api build tag")
	}
	version := regexp.MustCompile(`sing-box version (\d+)\.(\d+)\.(\d+)`).FindStringSubmatch(out)
	if len(version) != 4 {
		return errors.New("cannot determine sing-box version")
	}
	major, _ := strconv.Atoi(version[1])
	minor, _ := strconv.Atoi(version[2])
	if major < 1 || (major == 1 && minor < 14) {
		return errors.New("Snell requires sing-box 1.14 or newer")
	}
	return nil
}
