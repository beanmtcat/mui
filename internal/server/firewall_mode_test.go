package server

import (
	"strings"
	"testing"

	"mui/internal/shared"
)

func TestManualFirewallDeploysNodesForwardsAndSubscriptions(t *testing.T) {
	p := newTestMui(t)
	id, agent := p.enrollAs("manual", []string{shared.RoleExit}, map[string]any{"ipv4": "192.0.2.10", "firewallMode": "manual"})
	// A foreign firewall and missing/inactive UFW do not block manual mode.
	if code, out, _ := p.do("POST", "/agent/report", map[string]any{"hostReported": true, "ufwStatus": "unavailable", "firewallConflict": "nftables"}, agent); code != 200 {
		t.Fatalf("report: %d %v", code, out)
	}
	code, node, _ := p.do("POST", "/api/nodes", map[string]any{"serverId": id, "name": "SS", "protocol": "ss", "method": "2022-blake3-aes-128-gcm", "port": 50001, "direct": true}, nil)
	if code != 201 {
		t.Fatalf("node: %d %v", code, node)
	}
	code, out, _ := p.do("POST", "/api/forwards", map[string]any{"serverId": id, "name": "relay", "network": "tcp", "port": 50002, "targets": []map[string]any{{"host": "192.0.2.20", "port": 443}}, "firewallPolicy": "manual", "enabled": true}, nil)
	if code != 201 {
		t.Fatalf("forward: %d %v", code, out)
	}
	code, sub, _ := p.do("POST", "/api/subscriptions", map[string]any{"name": "subscriber", "format": "v2rayn", "nodeIds": []string{node["id"].(string)}}, nil)
	if code != 201 {
		t.Fatalf("subscription: %d %v", code, sub)
	}
	state, err := p.app.desired(id)
	if err != nil || state.FirewallMode != "manual" || len(state.Nodes) != 1 || len(state.Forwards) != 1 {
		t.Fatalf("manual state: %+v %v", state, err)
	}
	if state.Nodes[0].Node.FirewallPolicy != "manual" || state.Forwards[0].FirewallPolicy != "manual" {
		t.Fatal("manual configuration claimed automatic firewall protection")
	}
	p.applyAll(agent)
	if code, body := p.fetch(strings.TrimPrefix(sub["url"].(string), p.app.PublicURL)); code != 200 {
		t.Fatalf("manual subscription: %d %s", code, body)
	}
	if code, out, _ := p.do("POST", "/api/firewall", map[string]any{"serverId": id, "portFrom": 443, "portTo": 443, "network": "tcp", "action": "allow"}, nil); code != 400 {
		t.Fatalf("manual UFW mutation accepted: %d %v", code, out)
	}
	if code, out, _ := p.do("POST", "/api/servers/"+id+"/ufw/init", nil, nil); code != 409 {
		t.Fatalf("manual UFW init accepted: %d %v", code, out)
	}
}

func TestManualFirewallChangeRequiresAgentSupport(t *testing.T) {
	p := newTestMui(t)
	id, agent := p.enrollAs("legacy", []string{shared.RoleExit}, map[string]any{"ipv4": "192.0.2.10"})
	if code, _, _ := p.do("POST", "/agent/report", map[string]any{"agentVersion": "0.6.3", "manualFirewallSupport": false, "nodeFirewallPolicies": true, "multiUserStats": true}, agent); code != 200 {
		t.Fatal("report failed")
	}
	s, _ := p.store.Server(id)
	s.FirewallMode = "manual"
	if code, body, _ := p.do("PATCH", "/api/servers/"+id, s, nil); code != 409 {
		t.Fatalf("legacy agent allowed mode change: %d %v", code, body)
	}
	p.newAgent(agent)
	if code, body, _ := p.do("PATCH", "/api/servers/"+id, s, nil); code != 200 {
		t.Fatalf("capable agent mode change: %d %v", code, body)
	}
	p.applyAll(agent)
	stored, _ := p.store.Server(id)
	if stored.FirewallMode != "manual" {
		t.Fatal("mode not stored")
	}
	s.FirewallMode = "ufw"
	if code, body, _ := p.do("PATCH", "/api/servers/"+id, s, nil); code != 200 {
		t.Fatalf("return to managed mode: %d %v", code, body)
	}
	state, err := p.app.desired(id)
	if err != nil || state.FirewallMode != "ufw" {
		t.Fatalf("managed mode not restored: %v", err)
	}
}

func TestManualFirewallRoutesDoNotRequireKnownSourceIPs(t *testing.T) {
	l := newRouteLab(t)
	for _, id := range []string{l.entry, l.t1, l.t2, l.exit} {
		s, _ := l.p.store.Server(id)
		s.FirewallMode, s.Domain, s.IPv4, s.IPv6, s.DetectedIPv4, s.DetectedIPv6 = "manual", s.Name+".example.com", "", "", "", ""
		if code, out, _ := l.p.do("PATCH", "/api/servers/"+id, s, nil); code != 200 {
			t.Fatalf("mode change: %d %v", code, out)
		}
	}
	code, rt := l.route(map[string]any{"name": "manual route", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true, "hops": []map[string]any{{"serverIds": []string{l.t1}, "balance": "failover"}}})
	if code != 201 {
		t.Fatalf("manual route needs no source allowlist: %d %v", code, rt)
	}
	code, sub, _ := l.p.do("POST", "/api/subscriptions", map[string]any{"name": "route subscription", "format": "sing-box", "routeIds": []string{rt["id"].(string)}}, nil)
	if code != 201 {
		t.Fatalf("subscription: %d %v", code, sub)
	}
	l.applyAll()
	if code, body := l.p.fetch(strings.TrimPrefix(sub["url"].(string), l.p.app.PublicURL)); code != 200 {
		t.Fatalf("manual route not live: %d %s", code, body)
	}
}

func TestManualFirewallOlderEnrolledAgentCannotClaimApply(t *testing.T) {
	p := newTestMui(t)
	id, agent := p.enrollAs("manual", []string{shared.RoleExit}, map[string]any{"ipv4": "192.0.2.10", "firewallMode": "manual"})
	if err := p.app.queueApply(id, "nodes.apply"); err != nil {
		t.Fatal(err)
	}
	p.do("POST", "/agent/report", map[string]any{"agentVersion": "0.6.3", "manualFirewallSupport": false, "nodeFirewallPolicies": true}, agent)
	if code, job, _ := p.do("GET", "/agent/job", nil, agent); code != 204 {
		t.Fatalf("old agent received manual apply: %d %v", code, job)
	}
	p.newAgent(agent)
	if code, job, _ := p.do("GET", "/agent/job", nil, agent); code != 200 || job["kind"] != "nodes.apply" {
		t.Fatalf("new agent cannot claim pending manual apply: %d %v", code, job)
	}
}

func TestManualFirewallRejectsUFWMutationsAndPreservesPendingRules(t *testing.T) {
	p, id, agent := hostRuleServer(t)
	p.newAgent(agent)
	code, rule, _ := p.do("POST", "/api/firewall", map[string]any{"serverId": id, "portFrom": 9100, "portTo": 9100, "network": "tcp", "action": "allow"}, nil)
	if code != 201 {
		t.Fatalf("create rule: %d %v", code, rule)
	}
	s, _ := p.store.Server(id)
	s.FirewallMode = "manual"
	if code, out, _ := p.do("PATCH", "/api/servers/"+id, s, nil); code != 200 {
		t.Fatalf("switch: %d %v", code, out)
	}
	p.applyAll(agent)
	rules, _ := p.store.Rules(id)
	if len(rules) != 1 || rules[0].Status != "pending" {
		t.Fatalf("manual apply must not claim a pending firewall rule was applied: %+v", rules)
	}
	for _, method := range []string{"PATCH", "DELETE"} {
		if code, out, _ := p.do(method, "/api/firewall/"+rule["id"].(string), map[string]any{"portFrom": 9101, "portTo": 9101, "network": "tcp", "action": "allow"}, nil); code != 409 {
			t.Fatalf("manual %s rule: %d %v", method, code, out)
		}
	}
	for _, action := range []string{"delete", "adopt"} {
		if code, out, _ := p.do("POST", "/api/servers/"+id+"/ufw/"+action, map[string]any{"rules": []string{"8080                       ALLOW IN    Anywhere"}}, nil); code != 409 {
			t.Fatalf("manual host %s: %d %v", action, code, out)
		}
	}
	s.FirewallMode = "ufw"
	if code, out, _ := p.do("PATCH", "/api/servers/"+id, s, nil); code != 200 {
		t.Fatalf("restore managed: %d %v", code, out)
	}
	p.applyAll(agent)
	rules, _ = p.store.Rules(id)
	if len(rules) != 1 || rules[0].Status != "active" {
		t.Fatalf("managed apply should apply pending rule: %+v", rules)
	}
}

func TestManualFirewallChangeWaitsForExplicitUFWJobs(t *testing.T) {
	for _, kind := range []string{"ufw.init", "ufw.delete"} {
		t.Run(kind, func(t *testing.T) {
			p := newTestMui(t)
			id, agent := p.enrollAs("managed", []string{shared.RoleEntry}, map[string]any{"ipv4": "192.0.2.10"})
			if err := p.app.queueApply(id, kind); err != nil {
				t.Fatal(err)
			}
			s, _ := p.store.Server(id)
			s.FirewallMode = "manual"
			if code, out, _ := p.do("PATCH", "/api/servers/"+id, s, nil); code != 409 {
				t.Fatalf("switch with queued %s: %d %v", kind, code, out)
			}
			p.applyNext(agent, "success")
			if code, out, _ := p.do("PATCH", "/api/servers/"+id, s, nil); code != 200 {
				t.Fatalf("switch after %s: %d %v", kind, code, out)
			}
		})
	}
}

func TestManualFirewallRouteStillRequiresSourcesForManagedReceiver(t *testing.T) {
	l := newRouteLab(t)
	s, _ := l.p.store.Server(l.entry)
	s.FirewallMode, s.IPv4, s.IPv6, s.DetectedIPv4, s.DetectedIPv6 = "manual", "", "", "", ""
	if code, out, _ := l.p.do("PATCH", "/api/servers/"+l.entry, s, nil); code != 200 {
		t.Fatalf("switch: %d %v", code, out)
	}
	code, out := l.route(map[string]any{"name": "mixed", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true,
		"hops": []map[string]any{{"serverIds": []string{l.t1}}}})
	if code != 400 {
		t.Fatalf("managed receiver must require sender source IP: %d %v", code, out)
	}
}
