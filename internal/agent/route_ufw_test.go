package agent

import (
	"fmt"
	"strings"
	"testing"

	"mui/internal/shared"
)

func routeUFWFixture() shared.DesiredState {
	return shared.DesiredState{Forwards: []shared.ForwardRule{{ID: "chain", RouteID: "route", Network: "tcp+udp", Port: 51993, Enabled: true, FirewallPolicy: "restricted", FirewallSources: "192.0.2.1/32,2001:db8::1/128"}}}
}

func routeUFWStatus(rules []shared.FirewallRule, ipv6 bool) string {
	var b strings.Builder
	index := 0
	for _, v6 := range []bool{false, true} {
		if v6 && !ipv6 {
			continue
		}
		for _, r := range rules {
			if !routeUFWFamily(r, v6) {
				continue
			}
			index++
			source := r.Source
			if source == "" {
				source = "Anywhere"
			}
			family := ""
			if v6 {
				family = " (v6)"
			}
			fmt.Fprintf(&b, "[%d] %s%s %s IN %s # mui-%s\n", index, routeUFWApp(r), family, strings.ToUpper(r.Action), source, r.ID)
		}
	}
	return b.String()
}

func TestRouteUFWPolicyGuardsEachTransportAndFamily(t *testing.T) {
	state := routeUFWFixture()
	rules := routeUFWRules(state)
	if len(rules) != 6 {
		t.Fatalf("want two source allows and a guard per protocol, got %v", rules)
	}
	for _, proto := range []string{"tcp", "udp"} {
		var group []shared.FirewallRule
		for _, r := range rules {
			if r.Network == proto {
				group = append(group, r)
			}
		}
		if len(group) != 3 || group[0].Action != "allow" || group[1].Action != "allow" || group[2].Action != "deny" || group[2].Source != "" {
			t.Fatalf("sources must precede catch-all deny: %v", group)
		}
	}
	if len(baseUFWRules(state)) != 0 {
		t.Fatal("normal port rules could adopt an identical foreign rule")
	}
	status := routeUFWStatus(rules, true)
	if !routeUFWAtHead(status, rules, true) {
		t.Fatal("valid IPv4/IPv6 prefix rejected")
	}
	if !routeUFWAtHead(status+"[99] Anywhere ALLOW IN Anywhere\n", rules, true) {
		t.Fatal("foreign broad allow after guarded ports must be preserved")
	}
	if routeUFWAtHead("[99] 51000:53000/tcp ALLOW IN Anywhere\n"+status, rules, true) {
		t.Fatal("foreign allow moved ahead of policy was missed")
	}
	if routeUFWAtHead(strings.Replace(status, "ALLOW", "DENY", 1), rules, true) || routeUFWAtHead(strings.Replace(status, "192.0.2.1/32", "192.0.2.9", 1), rules, true) {
		t.Fatal("modified priority rule was accepted")
	}
	if !routeUFWAtHead(routeUFWStatus(rules, false), rules, false) || routeUFWAtHead(routeUFWStatus(rules, false), rules, true) {
		t.Fatal("IPv6 enabled/disabled verification incorrect")
	}
}

func TestRouteUFWNodeRemovalDoesNotReopenLanding(t *testing.T) {
	state := shared.DesiredState{Nodes: []shared.ManagedNode{{Node: shared.Node{ID: "landing", Protocol: "ss", Enabled: true, Port: 52000, FirewallPolicy: "restricted", FirewallSources: "192.0.2.1/32", RouteSources: "192.0.2.1"}}}}
	if len(routeUFWRules(state)) != 4 {
		t.Fatal("landing is not guarded")
	}
	state.Nodes[0].Node.RouteSources = ""
	state.Nodes[0].Node.FirewallSources = ""
	state.Nodes[0].Node.FirewallPolicy = "closed"
	rules := routeUFWRules(state)
	if len(rules) != 2 || rules[0].Action != "deny" || rules[1].Action != "deny" {
		t.Fatal("removing the last chain reopened the node", rules)
	}
	state.Nodes[0].Node.FirewallPolicy = "manual"
	if len(routeUFWRules(state)) != 0 {
		t.Fatal("manual node policy overridden")
	}
	state = routeUFWFixture()
	state.Forwards[0].RouteID = ""
	if len(routeUFWRules(state)) != 0 || len(baseUFWRules(state)) != 4 {
		t.Fatal("ordinary forward unexpectedly overrides host rules")
	}
	state = routeUFWFixture()
	state.FirewallMode = "manual"
	if len(routeUFWRules(state)) != 0 {
		t.Fatal("manual server overridden")
	}
}

func TestRouteUFWProfilesRetainOldDefinitionsForRollback(t *testing.T) {
	rules := routeUFWRules(routeUFWFixture())
	status := "[1] MUI-Chain-tcp-52000 DENY IN Anywhere # mui-route-priority-old\n"
	profiles := string(routeUFWProfiles(status, rules))
	if !strings.Contains(profiles, "ports=52000/tcp") || !strings.Contains(profiles, "ports=51993/udp") {
		t.Fatal("missing old/new profile", profiles)
	}
	if strings.Contains(string(routeUFWProfiles("", rules)), "52000") {
		t.Fatal("obsolete profile was not pruned")
	}
}

func TestRouteUFWAllSourcesDoNotCollideWithDenyGuards(t *testing.T) {
	for _, tc := range []struct {
		name, policy, sources, guardFamily string
		allows, guards                     int
	}{
		{name: "all", policy: "all", allows: 2},
		{name: "default all", policy: "", allows: 2},
		{name: "IPv4 any", policy: "restricted", sources: "0.0.0.0/0", guardFamily: "ipv6", allows: 2, guards: 2},
		{name: "IPv6 any", policy: "restricted", sources: "::/0", guardFamily: "ipv4", allows: 2, guards: 2},
		{name: "both any", policy: "restricted", sources: "0.0.0.0/0,::/0", allows: 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := routeUFWFixture()
			state.Forwards[0].FirewallPolicy, state.Forwards[0].FirewallSources = tc.policy, tc.sources
			rules := routeUFWRules(state)
			allows, guards := 0, 0
			for _, r := range rules {
				if r.Action == "allow" {
					allows++
					continue
				}
				guards++
				if r.Family != tc.guardFamily {
					t.Fatal("guard overlaps an all-source allow", r)
				}
			}
			if allows != tc.allows || guards != tc.guards {
				t.Fatal("wrong allow/guard counts", rules)
			}
			// UFW displays a /0 source as Anywhere, scoped by (v6).
			status := strings.ReplaceAll(strings.ReplaceAll(routeUFWStatus(rules, true), "0.0.0.0/0", "Anywhere"), "::/0", "Anywhere")
			if !routeUFWAtHead(status, rules, true) {
				t.Fatal("all-source prefix rejected", status)
			}
		})
	}
}
