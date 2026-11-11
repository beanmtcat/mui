//go:build linux

package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"mui/internal/shared"
)

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
	hasCore, wantCore := coreInstalled(), needsCore(state)
	if wantCore && !hasCore {
		return errors.New("该服务器未安装 sing-box；请先在服务器列表点击安装 sing-box")
	}
	wasCoreActive, wasCoreEnabled := coreActive(), coreEnabled()
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
		coreReady := (!wantCore && !wasCoreActive && !wasCoreEnabled) || (wantCore && wasCoreActive && wasCoreEnabled)
		if (shared.ManualFirewall(state.FirewallMode) || UFWStatus() == "active") && coreReady && forwardReady && !driftDetected(state, hasCore) && proxyMatches(state.AgentProxy) {
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
	if hasCore && wantCore {
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
	if hasCore && wantCore {
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
	coreChanged := hasCore && wantCore && (coreUnitChanged || len(certBackup) > 0 || !bytes.Equal(previous, config) || !wasCoreActive || !wasCoreEnabled)
	stopCore := hasCore && !wantCore && (wasCoreActive || wasCoreEnabled || len(previous) > 0)
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
	coreTouched := false
	fail := func(err error) error {
		restoreCerts()
		if forwardTouched {
			if rollbackErr := rollbackForward(); rollbackErr != nil {
				err = fmt.Errorf("%w; restore previous forward configuration: %v", err, rollbackErr)
			}
		}
		if coreTouched {
			restoreCoreUnit()
			rollbackCore(previous, wasCoreActive, wasCoreEnabled)
		}
		if !shared.ManualFirewall(state.FirewallMode) {
			if rollbackErr := restoreUFW(oldState); rollbackErr != nil {
				err = fmt.Errorf("%w; restore previous UFW policy: %v", err, rollbackErr)
			}
		}
		return err
	}
	if coreChanged {
		coreTouched = true
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
	} else if stopCore {
		coreTouched = true
		if _, err = serviceCommand("disable", "--now", "mui-sing-box.service"); err != nil {
			return fail(err)
		}
		if coreActive() || coreEnabled() {
			return fail(errors.New("sing-box 未能停用"))
		}
		if err = os.Remove(CoreConfig); err != nil && !os.IsNotExist(err) {
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
	if hasCore && !needsCore(state) && fileExists(CoreConfig) {
		return true
	}
	if hasCore && needsCore(state) {
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
