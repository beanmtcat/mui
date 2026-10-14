package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"mui/internal/shared"
)

var validRuleID = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func validFirewallPolicy(policy string) bool {
	// Empty means "all": older states leave the policy unset and expect the
	// port open, so an empty policy is the default, not an unknown value.
	switch policy {
	case "", "all", "restricted", "manual":
		return true
	}
	return false
}

func validPort(port int) bool { return port >= 1 && port <= 65535 }

func validNetwork(network string) bool { return network == "tcp" || network == "udp" }

// validSource accepts an empty source ("anywhere") and otherwise requires a
// valid CIDR or a bare IP address.
func validSource(source string) bool {
	if source == "" {
		return true
	}
	if _, _, err := net.ParseCIDR(source); err == nil {
		return true
	}
	return net.ParseIP(source) != nil
}

// splitSources splits a comma-separated source list, trimming whitespace and
// dropping empty segments, so trailing commas and blank segments never
// produce an empty (anywhere) source rule.
func splitSources(sources string) []string {
	out := []string{}
	for _, segment := range strings.Split(sources, ",") {
		segment = strings.TrimSpace(segment)
		if segment != "" {
			out = append(out, segment)
		}
	}
	return out
}

func validateFirewallRule(rule shared.FirewallRule) error {
	if !validRuleID.MatchString(rule.ID) {
		return fmt.Errorf("firewall rule %q: invalid ID", rule.ID)
	}
	switch rule.Action {
	case "allow", "deny":
	default:
		return fmt.Errorf("firewall rule %q: unknown action %q", rule.ID, rule.Action)
	}
	if !validPort(rule.PortFrom) || !validPort(rule.PortTo) {
		return fmt.Errorf("firewall rule %q: port range %d-%d out of 1-65535", rule.ID, rule.PortFrom, rule.PortTo)
	}
	if !validNetwork(rule.Network) {
		return fmt.Errorf("firewall rule %q: unknown network %q", rule.ID, rule.Network)
	}
	if !validSource(rule.Source) {
		return fmt.Errorf("firewall rule %q: invalid source %q", rule.ID, rule.Source)
	}
	return nil
}

func validateNodeFirewall(n shared.Node) error {
	if !validFirewallPolicy(n.FirewallPolicy) {
		return fmt.Errorf("node %q: unknown firewall policy %q", n.ID, n.FirewallPolicy)
	}
	if !validRuleID.MatchString(n.ID) {
		return fmt.Errorf("node %q: invalid ID", n.ID)
	}
	if !validPort(n.Port) {
		return fmt.Errorf("node %q: port %d out of 1-65535", n.ID, n.Port)
	}
	if n.FirewallPolicy == "restricted" {
		for _, source := range splitSources(n.FirewallSources) {
			if !validSource(source) {
				return fmt.Errorf("node %q: invalid firewall source %q", n.ID, source)
			}
		}
	}
	return nil
}

func validateForwardFirewall(forward shared.ForwardRule) error {
	if !validFirewallPolicy(forward.FirewallPolicy) {
		return fmt.Errorf("forward %q: unknown firewall policy %q", forward.ID, forward.FirewallPolicy)
	}
	if !validRuleID.MatchString(forward.ID) {
		return fmt.Errorf("forward %q: invalid ID", forward.ID)
	}
	if !validPort(forward.Port) {
		return fmt.Errorf("forward %q: port %d out of 1-65535", forward.ID, forward.Port)
	}
	if !validNetwork(forward.Network) {
		return fmt.Errorf("forward %q: unknown network %q", forward.ID, forward.Network)
	}
	if forward.FirewallPolicy == "restricted" {
		for _, source := range splitSources(forward.FirewallSources) {
			if !validSource(source) {
				return fmt.Errorf("forward %q: invalid firewall source %q", forward.ID, source)
			}
		}
	}
	return nil
}

// ownedRulesError strictly validates every firewall-related entry in the
// desired state. Callers reject the state on any error; ownedRules itself is
// fail-closed and skips the offending entries instead.
func ownedRulesError(state shared.DesiredState) error {
	for _, rule := range state.Rules {
		if err := validateFirewallRule(rule); err != nil {
			return err
		}
	}
	for _, item := range state.Nodes {
		if err := validateNodeFirewall(item.Node); err != nil {
			return err
		}
	}
	for _, forward := range state.Forwards {
		if err := validateForwardFirewall(forward); err != nil {
			return err
		}
	}
	return nil
}

// ownedRules lists every UFW rule the panel wants on the host, in the order they
// must appear. UFW stops at the first match, so deny rules go first; allow rules
// follow by stable IDs, with each node's restricted sources kept together.
// Fail-closed: an invalid entry is skipped and never generates a rule, an
// invalid source segment is skipped on its own, and a restricted list that
// filters down to nothing generates no rule.
func ownedRules(state shared.DesiredState) []shared.FirewallRule {
	type keyed struct {
		key  string
		rule shared.FirewallRule
	}
	seen := map[string]bool{}
	var denies, allows []keyed
	add := func(list []keyed, key string, rule shared.FirewallRule) []keyed {
		if seen[rule.ID] {
			return list // Duplicate rule ID: keep the first occurrence.
		}
		seen[rule.ID] = true
		return append(list, keyed{key, rule})
	}
	for _, rule := range state.Rules {
		if err := validateFirewallRule(rule); err != nil {
			continue
		}
		if rule.Action == "deny" {
			denies = add(denies, rule.ID, rule)
		} else {
			allows = add(allows, rule.ID, rule)
		}
	}
	for _, item := range state.Nodes {
		n := item.Node
		if !n.Enabled || n.FirewallPolicy == "manual" {
			continue
		}
		if !validFirewallPolicy(n.FirewallPolicy) || !validRuleID.MatchString(n.ID) || !validPort(n.Port) {
			continue
		}
		sources := []string{""}
		if n.FirewallPolicy == "restricted" {
			sources = nil
			for _, source := range splitSources(n.FirewallSources) {
				if !validSource(source) {
					continue
				}
				sources = append(sources, source)
			}
			if len(sources) == 0 {
				continue // Restricted with no valid source must never open the port broadly.
			}
		}
		for i, source := range sources {
			suffix := ""
			if source != "" {
				digest := sha256.Sum256([]byte(source))
				suffix = "-" + hex.EncodeToString(digest[:8])
			}
			// Include the source in the ID so a changed restriction replaces the old rule.
			allows = add(allows, fmt.Sprintf("%s-%05d", n.ID, i*2), shared.FirewallRule{ID: fmt.Sprintf("node-%s-tcp-%d%s", n.ID, n.Port, suffix), PortFrom: n.Port, PortTo: n.Port, Network: "tcp", Source: source, Action: "allow", Owner: "node"})
			if n.Protocol == "ss" {
				allows = add(allows, fmt.Sprintf("%s-%05d", n.ID, i*2+1), shared.FirewallRule{ID: fmt.Sprintf("node-%s-udp-%d%s", n.ID, n.Port, suffix), PortFrom: n.Port, PortTo: n.Port, Network: "udp", Source: source, Action: "allow", Owner: "node"})
			}
		}
	}
	for _, forward := range state.Forwards {
		if !forward.Enabled || forward.FirewallPolicy == "manual" {
			continue
		}
		if !validFirewallPolicy(forward.FirewallPolicy) || !validRuleID.MatchString(forward.ID) || !validPort(forward.Port) || !validNetwork(forward.Network) {
			continue
		}
		sources := []string{""}
		if forward.FirewallPolicy == "restricted" {
			sources = nil
			for _, source := range splitSources(forward.FirewallSources) {
				if !validSource(source) {
					continue
				}
				sources = append(sources, source)
			}
			if len(sources) == 0 {
				continue
			}
		}
		for _, source := range sources {
			suffix := ""
			if source != "" {
				digest := sha256.Sum256([]byte(source))
				suffix = "-" + hex.EncodeToString(digest[:8])
			}
			id := fmt.Sprintf("forward-%s-%s-%d%s", forward.ID, forward.Network, forward.Port, suffix)
			allows = add(allows, id, shared.FirewallRule{ID: id, PortFrom: forward.Port, PortTo: forward.Port, Network: forward.Network, Source: source, Action: "allow", Owner: "forward"})
		}
	}
	sort.SliceStable(denies, func(i, j int) bool { return denies[i].key < denies[j].key })
	sort.SliceStable(allows, func(i, j int) bool { return allows[i].key < allows[j].key })
	rules := make([]shared.FirewallRule, 0, len(denies)+len(allows))
	for _, item := range append(denies, allows...) {
		rules = append(rules, item.rule)
	}
	return rules
}

type ufwLine struct {
	Index int
	ID    string
}

var muiRuleLine = regexp.MustCompile(`^\[\s*([0-9]+)\]\s.*#\s*mui-(\S+)\s*$`)
var legacyRuleLine = regexp.MustCompile(`^\[\s*([0-9]+)\]\s.*#\s*panel-(\S+)\s*$`)
var defaultIncomingDeny = regexp.MustCompile(`(?im)^[ \t]*Default:\s*(?:deny|reject)\s+\(incoming\)`)

func restrictedNodesNeedDeny(state shared.DesiredState) bool {
	for _, item := range state.Nodes {
		if item.Node.Enabled && item.Node.FirewallPolicy == "restricted" {
			return true
		}
	}
	for _, forward := range state.Forwards {
		if forward.Enabled && forward.FirewallPolicy == "restricted" {
			return true
		}
	}
	return false
}

// parseMuiLines extracts the mui-owned rules from `ufw status numbered`.
// The SSH rule added during initialisation is never touched.
func parseMuiLines(status string) []ufwLine {
	return parseTaggedLines(status, muiRuleLine)
}

func parseLegacyLines(status string) []ufwLine {
	return parseTaggedLines(status, legacyRuleLine)
}

func parseTaggedLines(status string, pattern *regexp.Regexp) []ufwLine {
	lines := []ufwLine{}
	for _, line := range strings.Split(status, "\n") {
		m := pattern.FindStringSubmatch(strings.TrimSpace(line))
		if len(m) != 3 || m[2] == "ssh" {
			continue
		}
		index, _ := strconv.Atoi(m[1])
		lines = append(lines, ufwLine{Index: index, ID: m[2]})
	}
	return lines
}

// planUFW compares the rule IDs present on the host (in host order, IPv4 and IPv6
// copies collapsed) with the desired order. Rules that survive are left alone and
// missing ones are appended, so open ports stay open. Only when the surviving
// rules are not a prefix of the desired order are all of them replaced.
func planUFW(present []ufwLine, desired []string) (remove map[string]bool, add []string) {
	wanted := map[string]bool{}
	for _, id := range desired {
		wanted[id] = true
	}
	remove = map[string]bool{}
	seen := map[string]bool{}
	keep := []string{}
	for _, line := range present {
		if seen[line.ID] {
			continue
		}
		seen[line.ID] = true
		if wanted[line.ID] {
			keep = append(keep, line.ID)
		} else {
			remove[line.ID] = true
		}
	}
	prefix := len(keep) <= len(desired)
	for i := 0; prefix && i < len(keep); i++ {
		prefix = keep[i] == desired[i]
	}
	if !prefix {
		for _, id := range keep {
			remove[id] = true
		}
		return remove, desired
	}
	return remove, desired[len(keep):]
}

// newListeners returns the enabled nodes whose port is not already held by the
// running core, i.e. the ones that could collide with another process on the host.
// Held listeners are keyed by (port, protocol): an ss node listens on both TCP
// and UDP, every other protocol only on TCP.
func newListeners(current, next shared.DesiredState) []shared.Node {
	type listenerKey struct {
		port     int
		protocol string
	}
	keysFor := func(n shared.Node) []listenerKey {
		keys := []listenerKey{{n.Port, "tcp"}}
		if n.Protocol == "ss" {
			keys = append(keys, listenerKey{n.Port, "udp"})
		}
		return keys
	}
	held := map[listenerKey]bool{}
	for _, item := range current.Nodes {
		if item.Node.Enabled {
			for _, key := range keysFor(item.Node) {
				held[key] = true
			}
		}
	}
	out := []shared.Node{}
	for _, item := range next.Nodes {
		if !item.Node.Enabled {
			continue
		}
		taken := false
		for _, key := range keysFor(item.Node) {
			if held[key] {
				taken = true
				break
			}
		}
		if !taken {
			out = append(out, item.Node)
		}
	}
	return out
}
