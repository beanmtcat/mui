package server

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"mui/internal/agent"
	"mui/internal/shared"
)

func TestRouteDesiredStatesPassAgentValidation(t *testing.T) {
	l := newRouteLab(t)
	code, rt := l.route(map[string]any{"name": "review", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true})
	if code != 201 {
		t.Fatalf("create: %d %v", code, rt)
	}
	for _, id := range []string{l.entry, l.exit} {
		state, err := l.p.app.desired(id)
		if err != nil {
			t.Fatal(err)
		}
		if err = agent.ValidateDesired(state); err != nil {
			t.Fatalf("server %s: %v", id, err)
		}
	}
}

func TestRouteOnlyNodeWithoutRoutesPassesAgentValidation(t *testing.T) {
	l := newRouteLab(t)
	state, err := l.p.app.desired(l.exit)
	if err != nil {
		t.Fatal(err)
	}
	if err = agent.ValidateDesired(state); err != nil {
		t.Fatalf("new default node cannot be applied: %v", err)
	}
}

func TestRouteMissingSourceCannotOpenMiddleHop(t *testing.T) {
	l := newRouteLab(t)
	entry, _ := l.p.store.Server(l.entry)
	entry.IPv4 = ""
	entry.DetectedIPv4 = ""
	entry.IPv6 = ""
	entry.DetectedIPv6 = "" // domain-only server is allowed
	if err := l.p.store.PutServer(entry); err != nil {
		t.Fatal(err)
	}
	code, out := l.route(map[string]any{"name": "review", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true, "hops": []map[string]any{{"serverIds": []string{l.t1}}}})
	if code != 400 {
		t.Fatalf("want source validation error, got %d %v", code, out)
	}
	// Background synchronisation must also fail closed if a previously known
	// address disappears after a route was created.
	rt := shared.Route{ID: ID(), Name: "existing", EntryServerID: l.entry, NodeID: l.nodeID, Port: 50010, Enabled: true, Hops: []shared.RouteHop{{ServerIDs: []string{l.t1}, Balance: "failover"}}}
	if err := l.p.store.PutRoute(rt); err != nil {
		t.Fatal(err)
	}
	if err := l.p.app.syncRoutes(); err != nil {
		t.Fatal(err)
	}
	for _, f := range l.forwards(l.t1) {
		if f.FirewallPolicy != "closed" || f.FirewallSources != "" {
			t.Fatalf("missing source did not close middle hop: %+v", f)
		}
	}
	state, err := l.p.app.desired(l.t1)
	if err != nil {
		t.Fatal(err)
	}
	if err = agent.ValidateDesired(state); err != nil {
		t.Fatal(err)
	}
}

func TestRouteProtocolChangeRechecksGeneratedForwardConflicts(t *testing.T) {
	l := newRouteLab(t)
	// Use a TCP-only landing node, then occupy UDP on the entry.
	patch := map[string]any{"name": "review", "protocol": "snell", "port": 50010, "shadowTlsHost": "www.example.com", "enabled": true}
	code, out, _ := l.p.do("PATCH", "/api/nodes/"+l.nodeID, patch, nil)
	if code != 200 {
		t.Fatalf("snell: %d %v", code, out)
	}
	code, out = l.route(map[string]any{"name": "review", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true})
	if code != 201 {
		t.Fatalf("route: %d %v", code, out)
	}
	code, out, _ = l.p.do("POST", "/api/forwards", map[string]any{"serverId": l.entry, "name": "manual-udp", "network": "udp", "port": 50010, "targets": []map[string]any{{"host": "192.0.2.9", "port": 53}}, "enabled": true}, nil)
	if code != 201 {
		t.Fatalf("udp: %d %v", code, out)
	}
	code, out, _ = l.p.do("PATCH", "/api/nodes/"+l.nodeID, map[string]any{"name": "review", "protocol": "ss", "port": 50010, "method": "2022-blake3-aes-128-gcm", "enabled": true}, nil)
	if code != 409 {
		t.Fatalf("conflicting protocol update: want 409, got %d %v", code, out)
	}
	node, err := l.p.store.Node(l.nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if node.Protocol != "snell" {
		t.Fatalf("failed edit changed stored node: %+v", node)
	}
	state, err := l.p.app.desired(l.entry)
	if err != nil {
		t.Fatal(err)
	}
	if err = agent.ValidateDesired(state); err != nil {
		t.Fatalf("failed edit corrupted desired state: %v", err)
	}
}

func TestRouteNewEntryWaitsForExitFirewall(t *testing.T) {
	l := newRouteLab(t)
	code, rt := l.route(map[string]any{"name": "first", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true})
	if code != 201 {
		t.Fatalf("route: %d %v", code, rt)
	}
	code, sub, _ := l.p.do("POST", "/api/subscriptions", map[string]any{"name": "s", "format": "sing-box", "routeIds": []string{rt["id"].(string)}}, nil)
	if code != 201 {
		t.Fatalf("subscription: %d %v", code, sub)
	}
	l.applyAll()
	next, agent := l.p.enrollAs("new-entry", []string{"entry"}, map[string]any{"ipv4": "198.51.100.9"})
	firstRoute := rt["id"].(string)
	code, rt = l.route(map[string]any{"name": "second", "entryServerId": next, "nodeId": l.nodeID, "enabled": true})
	if code != 201 {
		t.Fatalf("route2: %d %v", code, rt)
	}
	code, out, _ := l.p.do("PATCH", "/api/subscriptions/"+sub["id"].(string), map[string]any{"name": "s", "format": "sing-box", "routeIds": []string{firstRoute, rt["id"].(string)}, "enabled": true}, nil)
	if code != 200 {
		t.Fatalf("add route to subscription: %d %v", code, out)
	}
	l.p.applyAll(agent) // The exit has NOT applied the new firewall yet.
	world, err := l.p.app.loadRouteWorld()
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range world.routes {
		if route.ID == rt["id"].(string) {
			live, e := l.p.app.routeLive(route, world, sub["id"].(string))
			if e != nil {
				t.Fatal(e)
			}
			if live {
				t.Fatal("route is live before its new entry IP is allowed by exit firewall")
			}
		}
	}
	l.p.applyAll(l.agents[3])
	world, err = l.p.app.loadRouteWorld()
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range world.routes {
		if route.ID == rt["id"].(string) {
			live, e := l.p.app.routeLive(route, world, sub["id"].(string))
			if e != nil || !live {
				t.Fatalf("route not live after exit applies: %v %v", live, e)
			}
		}
	}

}

func TestRouteLastRemovalClosesExitWithoutBreakingApply(t *testing.T) {
	l := newRouteLab(t)
	code, rt := l.route(map[string]any{"name": "lifecycle", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true})
	if code != 201 {
		t.Fatalf("route: %d %v", code, rt)
	}
	l.applyAll()
	code, out, _ := l.p.do("DELETE", "/api/routes/"+rt["id"].(string), nil, nil)
	if code != 200 {
		t.Fatalf("delete: %d %v", code, out)
	}
	state, err := l.p.app.desired(l.exit)
	if err != nil {
		t.Fatal(err)
	}
	if n := state.Nodes[0].Node; n.FirewallPolicy != "closed" || n.FirewallSources != "" {
		t.Fatalf("last route removal left node open: %+v", n)
	}
	if err = agent.ValidateDesired(state); err != nil {
		t.Fatal(err)
	}
	l.applyAll()
}

func TestRouteSourceValidationChecksEveryMemberAndLink(t *testing.T) {
	l := newRouteLab(t)
	world, err := l.p.app.loadRouteWorld()
	if err != nil {
		t.Fatal(err)
	}
	rt := shared.Route{ID: ID(), Name: "sources", EntryServerID: l.entry, NodeID: l.nodeID, Enabled: true, Hops: []shared.RouteHop{{ServerIDs: []string{l.t1, l.t2}, Balance: "failover"}}}
	server := world.servers[l.t2]
	server.IPv4 = ""
	server.Domain = "t2.example.com"
	world.servers[l.t2] = server
	if err := world.checkRouteShape(rt); err == nil {
		t.Fatal("accepted unknown source within a partly known group")
	}
	rt.Hops = nil
	rt.NodeInternal = true
	entry := world.servers[l.entry]
	entry.InternalAddress = "entry.internal.example"
	world.servers[l.entry] = entry
	if err := world.checkRouteShape(rt); err == nil {
		t.Fatal("accepted hostname-only internal source")
	}
}

func TestRouteForwardsListenOnIPv6(t *testing.T) {
	l := newRouteLab(t)
	entry, _ := l.p.store.Server(l.entry)
	entry.IPv4 = ""
	entry.Domain = ""
	entry.IPv6 = "2001:db8::1"
	entry.DetectedIPv4 = "198.51.100.1" // Clients use IPv6; egress to the IPv4 exit uses IPv4.
	if err := l.p.store.PutServer(entry); err != nil {
		t.Fatal(err)
	}
	code, out := l.route(map[string]any{"name": "ipv6", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true})
	if code != 201 {
		t.Fatalf("create: %d %v", code, out)
	}
	for _, f := range l.forwards(l.entry) {
		if f.Listen != "::" {
			t.Fatalf("IPv6 route has IPv4-only listen: %+v", f)
		}
	}
	state, err := l.p.app.desired(l.entry)
	if err != nil {
		t.Fatal(err)
	}
	if err = agent.ValidateDesired(state); err != nil {
		t.Fatal(err)
	}
}

func TestServerEditCanReconcileItsOwnRouteForwards(t *testing.T) {
	l := newRouteLab(t)
	code, rt := l.route(map[string]any{"name": "reconcile", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true})
	if code != 201 {
		t.Fatalf("route: %d %v", code, rt)
	}
	f := l.forwards(l.entry)[0]
	f.Name = "stale name"
	if err := l.p.store.PutForward(f); err != nil {
		t.Fatal(err)
	}
	done := make(chan int, 1)
	go func() {
		code, _, _ := l.p.do("PATCH", "/api/servers/"+l.entry, map[string]any{"name": "edited", "roles": []string{"entry"}, "country": "SG", "ipv4": "198.51.100.1", "domain": "entry.example.com", "internalAddress": "10.0.0.1"}, nil)
		done <- code
	}()
	select {
	case code := <-done:
		if code != 200 {
			t.Fatalf("server edit: %d", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server edit deadlocked while applying its own route forwards")
	}
}

// Generated source lists are not bound by the 32 sources an administrator
// may type: a large load-balanced group must not break the exit's apply.
func TestRouteManySourcesStillApply(t *testing.T) {
	l := newRouteLab(t)
	// A hostname can resolve to either family; both upstream families are
	// needed here. Literal IPv4 destinations now correctly admit IPv4 only.
	exit, _ := l.p.store.Server(l.exit)
	exit.IPv4, exit.IPv6, exit.Domain = "", "", "exit.example.com"
	if err := l.p.store.PutServer(exit); err != nil {
		t.Fatal(err)
	}
	var group []string
	for i := range 16 {
		id, _ := l.p.enrollAs("lb", []string{"transit"}, map[string]any{"ipv4": fmt.Sprintf("198.51.101.%d", i+1), "ipv6": fmt.Sprintf("2001:db8:1::%d", i+1)})
		group = append(group, id)
	}
	for _, body := range []map[string]any{
		{"name": "big", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true, "hops": []map[string]any{{"serverIds": group}}},
		{"name": "direct-entry", "entryServerId": l.t2, "nodeId": l.nodeID, "enabled": true},
	} {
		if code, out := l.route(body); code != 201 {
			t.Fatalf("route %v: %d %v", body["name"], code, out)
		}
	}
	node, _ := l.p.store.Node(l.nodeID)
	if n := strings.Count(node.RouteSources, ",") + 1; n <= 32 {
		t.Fatalf("the test needs more than 32 sources, got %d", n)
	}
	for _, id := range []string{l.exit, group[0]} {
		state, err := l.p.app.desired(id)
		if err != nil {
			t.Fatal(err)
		}
		if err = agent.ValidateDesired(state); err != nil {
			t.Fatalf("server %s rejects its state: %v", id, err)
		}
	}
	// Administrators still get the 32-source limit.
	sources := make([]string, 33)
	for i := range sources {
		sources[i] = fmt.Sprintf("192.0.2.%d", i+1)
	}
	if code, out, _ := l.p.do("POST", "/api/forwards", map[string]any{"serverId": l.t1, "name": "m", "network": "tcp", "port": 52000,
		"targets": []map[string]any{{"host": "192.0.2.200", "port": 443}}, "firewallPolicy": "restricted", "firewallSources": strings.Join(sources, ","), "enabled": true}, nil); code != 400 {
		t.Fatalf("33 typed sources: %d %v", code, out)
	}
}

func TestRouteRefusesUnreachableAddresses(t *testing.T) {
	l := newRouteLab(t)
	if code, out, _ := l.p.do("PATCH", "/api/servers/"+l.t1, map[string]any{"name": "t1", "roles": []string{"transit"}, "country": "SG", "ipv4": "198.51.100.2", "internalAddress": "169.254.169.254"}, nil); code != 400 {
		t.Fatalf("metadata address accepted as internal address: %d %v", code, out)
	}
	if code, out, _ := l.p.do("PATCH", "/api/servers/"+l.t1, map[string]any{"name": "t1", "roles": []string{"transit"}, "country": "SG", "ipv4": "127.0.0.1"}, nil); code != 200 {
		t.Fatalf("server edit: %d %v", code, out)
	}
	if code, out := l.route(map[string]any{"name": "r", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true,
		"hops": []map[string]any{{"serverIds": []string{l.t1}}}}); code != 400 || !strings.Contains(out["error"].(string), "回环") {
		t.Fatalf("route through a loopback hop: %d %v", code, out)
	}
	if code, out := l.route(map[string]any{"name": "r", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true, "notes": strings.Repeat("备", 201)}); code != 400 {
		t.Fatalf("oversized notes: %d %v", code, out)
	}
}
