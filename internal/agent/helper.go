//go:build linux

package agent

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
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
	status := HostStatus{UFW: UFWStatus(), Conflict: firewallConflict(), NodeDomainBlock: true, NodeSOCKSOutbound: true, ManualFirewallSupport: true, Supported: true, AgentSelfUpdate: true, ForwardSupport: true, ForwardTCPUDP: true, ShadowTLSAuth: true, SnellFixedPort: true, SnellV6: true, AgentProxySupport: true, OutboundBindingSupport: true, MultiUserStats: true, NodeFirewallPolicies: true, CoreSelfUpdate: true, ReleaseKeyPinned: fileExists(ReleaseKeyPath)}
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
