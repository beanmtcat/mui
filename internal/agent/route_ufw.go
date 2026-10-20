package agent

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"mui/internal/shared"
)

const routeUFWPrefix = "route-priority-"

type portProto struct {
	port  int
	proto string
}

// Node and chain-owned ports take precedence over existing host rules. Include
// closed nodes too: removing their last chain must not expose them through an
// older host allow. Manual forwards and manual firewalls retain their policy.
func routeUFWPorts(state shared.DesiredState) map[portProto]bool {
	ports := map[portProto]bool{}
	if shared.ManualFirewall(state.FirewallMode) {
		return ports
	}
	for _, item := range state.Nodes {
		n := item.Node
		if !n.Enabled || n.Deleting || n.FirewallPolicy == "manual" {
			continue
		}
		ports[portProto{n.Port, "tcp"}] = true
		if n.Protocol == "ss" {
			ports[portProto{n.Port, "udp"}] = true
		}
	}
	for _, f := range state.Forwards {
		if !f.Enabled || f.Deleting || f.RouteID == "" || f.FirewallPolicy == "manual" {
			continue
		}
		for _, proto := range shared.ForwardNetworks(f.Network) {
			ports[portProto{f.Port, proto}] = true
		}
	}
	return ports
}

func routeUFWApp(rule shared.FirewallRule) string {
	return fmt.Sprintf("MUI-Chain-%s-%d", rule.Network, rule.PortFrom)
}

func baseUFWRules(state shared.DesiredState) []shared.FirewallRule {
	ports := routeUFWPorts(state)
	var out []shared.FirewallRule
	for _, rule := range ownedRules(state) {
		if ports[portProto{rule.PortFrom, rule.Network}] && rule.PortFrom == rule.PortTo && (rule.Owner == "node" || rule.Owner == "forward") {
			continue // Supplied by the priority profile; do not adopt a foreign duplicate.
		}
		out = append(out, rule)
	}
	return out
}

// Per-port allows precede a catch-all deny. The latter prevents an existing
// broad host allow from bypassing the chain's previous-hop source restriction.
// Application profiles distinguish these rules from identical host port rules:
// UFW otherwise skips a prepend when an equivalent rule already exists later.
func routeUFWRules(state shared.DesiredState) []shared.FirewallRule {
	ports := routeUFWPorts(state)
	allows := map[portProto][]shared.FirewallRule{}
	for _, rule := range ownedRules(state) {
		pp := portProto{rule.PortFrom, rule.Network}
		if !ports[pp] || rule.PortFrom != rule.PortTo || rule.Action != "allow" || (rule.Owner != "node" && rule.Owner != "forward") {
			continue
		}
		rule.ID = routeUFWPrefix + rule.ID
		allows[pp] = append(allows[pp], rule)
	}
	ordered := make([]portProto, 0, len(ports))
	for pp := range ports {
		ordered = append(ordered, pp)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].port != ordered[j].port {
			return ordered[i].port < ordered[j].port
		}
		return ordered[i].proto < ordered[j].proto
	})
	var rules []shared.FirewallRule
	for _, pp := range ordered {
		// Merge identical allows if multiple chain resources share a port.
		seen := map[string]bool{}
		for _, r := range allows[pp] {
			key := r.Source + "/" + r.Family
			if seen[key] {
				continue
			}
			seen[key] = true
			// Stable identity depends on the policy, not which chain owns it.
			r.ID = fmt.Sprintf("%s%s-%d-%x", routeUFWPrefix, pp.proto, pp.port, sha256.Sum256([]byte(key)))
			rules = append(rules, r)
		}
		rules = append(rules, shared.FirewallRule{ID: fmt.Sprintf("%s%s-%d-deny", routeUFWPrefix, pp.proto, pp.port), Network: pp.proto, PortFrom: pp.port, PortTo: pp.port, Action: "deny"})
	}
	return rules
}

func routeUFWFamily(rule shared.FirewallRule, v6 bool) bool {
	if rule.Source != "" {
		addr, err := netip.ParseAddr(strings.Split(rule.Source, "/")[0])
		return err == nil && addr.Is6() == v6
	}
	return (rule.Family != "ipv4" || !v6) && (rule.Family != "ipv6" || v6)
}

func normalizedUFWSource(source string) string {
	if source == "Anywhere" || source == "" {
		return "any"
	}
	if addr, err := netip.ParseAddr(source); err == nil {
		return netip.PrefixFrom(addr, addr.BitLen()).String()
	}
	if prefix, err := netip.ParsePrefix(source); err == nil {
		if prefix.Bits() == 0 {
			return "any"
		}
		return prefix.Masked().String()
	}
	return source
}

// Check the prefix separately for each family, including foreign/SSH rules.
// Comparing only managed IDs would miss a newly prepended broad host allow.
func routeUFWAtHead(status string, rules []shared.FirewallRule, ipv6 bool) bool {
	for _, v6 := range []bool{false, true} {
		if v6 && !ipv6 {
			continue
		}
		var want []shared.FirewallRule
		for _, rule := range rules {
			if routeUFWFamily(rule, v6) {
				want = append(want, rule)
			}
		}
		at := 0
		for _, raw := range strings.Split(status, "\n") {
			if !strings.HasPrefix(strings.TrimSpace(raw), "[") || strings.Contains(raw, "(v6)") != v6 {
				continue
			}
			if at >= len(want) {
				break
			}
			line, ok := shared.ParseUFWLine(raw)
			r := want[at]
			app := strings.TrimSpace(strings.ReplaceAll(line.App, "(v6)", ""))
			if !ok || line.Tag != "mui-"+r.ID || app != routeUFWApp(r) || strings.ToLower(line.Action) != r.Action || normalizedUFWSource(line.Source) != normalizedUFWSource(r.Source) {
				return false
			}
			at++
		}
		if at != len(want) {
			return false
		}
	}
	return true
}

// Preserve profiles still referenced by old rules until those rules are
// removed. This also lets rollback replace the new policy with the old one.
func routeUFWProfiles(status string, rules []shared.FirewallRule) []byte {
	apps := map[string]bool{}
	for _, r := range rules {
		apps[routeUFWApp(r)] = true
	}
	for _, raw := range strings.Split(status, "\n") {
		line, ok := shared.ParseUFWLine(raw)
		if !ok || !strings.HasPrefix(line.Tag, "mui-"+routeUFWPrefix) {
			continue
		}
		app := strings.TrimSpace(strings.ReplaceAll(line.App, "(v6)", ""))
		parts := strings.Split(app, "-")
		if len(parts) == 4 && parts[0] == "MUI" && parts[1] == "Chain" && validNetwork(parts[2]) {
			port, err := strconv.Atoi(parts[3])
			if err == nil && validPort(port) {
				apps[app] = true
			}
		}
	}
	ordered := make([]string, 0, len(apps))
	for app := range apps {
		ordered = append(ordered, app)
	}
	sort.Strings(ordered)
	var b strings.Builder
	b.WriteString("# Generated by MUI. Chain rules take precedence over host port rules.\n")
	for _, app := range ordered {
		parts := strings.Split(app, "-")
		fmt.Fprintf(&b, "[%s]\ntitle=MUI chain %s %s\ndescription=MUI chain firewall policy\nports=%s/%s\n\n", app, parts[2], parts[3], parts[3], parts[2])
	}
	return []byte(b.String())
}
