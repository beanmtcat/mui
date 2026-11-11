//go:build linux

package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"mui/internal/shared"
)

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
		// An allow limited to loopback or private sources (e.g. a Docker
		// bridge subnet) is unreachable from outside and bypasses nothing.
		if localUFWSource(rule.source) {
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
