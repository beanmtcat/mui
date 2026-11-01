package server

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"mui/internal/shared"
)

// enrollAs creates and enrolls a server with the given roles and addresses,
// and reports a current agent for it.
func (p *testMui) enrollAs(name string, roles []string, fields map[string]any) (string, map[string]string) {
	p.t.Helper()
	body := map[string]any{"name": name, "roles": roles, "country": "SG"}
	for k, v := range fields {
		body[k] = v
	}
	code, out, _ := p.do("POST", "/api/servers", body, nil)
	if code != 201 {
		p.t.Fatalf("server %s: %d %v", name, code, out)
	}
	id := out["server"].(map[string]any)["id"].(string)
	code, agent, _ := p.do("POST", "/agent/enroll", map[string]string{"serverId": id, "token": out["enrollToken"].(string)}, nil)
	if code != 200 {
		p.t.Fatalf("enroll %s: %d %v", name, code, agent)
	}
	headers := map[string]string{"X-Server-ID": id, "Authorization": "Bearer " + agent["agentToken"].(string)}
	p.newAgent(headers)
	return id, headers
}

type routeLab struct {
	p                           *testMui
	entry, t1, t2, exit, nodeID string
	agents                      []map[string]string
}

// newRouteLab builds entry → [t1, t2] → exit with an SS node that does not
// allow direct use.
func newRouteLab(t *testing.T) *routeLab {
	p := newTestMui(t)
	l := &routeLab{p: p}
	var a1, a2, a3, a4 map[string]string
	l.entry, a1 = p.enrollAs("entry", []string{"entry"}, map[string]any{"ipv4": "198.51.100.1", "domain": "entry.example.com", "internalAddress": "10.0.0.1"})
	l.t1, a2 = p.enrollAs("t1", []string{"transit"}, map[string]any{"ipv4": "198.51.100.2"})
	l.t2, a3 = p.enrollAs("t2", []string{"line"}, map[string]any{"ipv4": "198.51.100.3", "internalAddress": "10.0.0.3"})
	l.exit, a4 = p.enrollAs("exit", []string{"exit", "line"}, map[string]any{"ipv4": "198.51.100.4", "internalAddress": "10.0.0.4"})
	l.agents = []map[string]string{a1, a2, a3, a4}
	code, node, _ := p.do("POST", "/api/nodes", map[string]any{"serverId": l.exit, "name": "hk-ss", "protocol": "ss", "port": 50010, "method": "2022-blake3-aes-128-gcm"}, nil)
	if code != 201 {
		t.Fatalf("node: %d %v", code, node)
	}
	l.nodeID = node["id"].(string)
	return l
}

func (l *routeLab) route(body map[string]any) (int, map[string]any) {
	l.p.t.Helper()
	code, out, _ := l.p.do("POST", "/api/routes", body, nil)
	return code, out
}

func (l *routeLab) forwards(serverID string) []shared.ForwardRule {
	l.p.t.Helper()
	list, err := l.p.store.Forwards(serverID)
	if err != nil {
		l.p.t.Fatal(err)
	}
	var out []shared.ForwardRule
	for _, f := range list {
		if !f.Deleting {
			out = append(out, f)
		}
	}
	return out
}

func (l *routeLab) applyAll() {
	for _, agent := range l.agents {
		l.p.applyAll(agent)
	}
}

func TestRouteGeneratesForwardsOnEveryHop(t *testing.T) {
	l := newRouteLab(t)
	code, rt := l.route(map[string]any{"name": "hk", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true,
		"hops": []map[string]any{{"serverIds": []string{l.t1, l.t2}, "balance": "round-robin"}}})
	if code != 201 {
		t.Fatalf("route: %d %v", code, rt)
	}
	if rt["port"] != float64(50010) {
		t.Fatalf("the route should keep the node's port when it is free everywhere: %v", rt["port"])
	}
	entry := l.forwards(l.entry)
	if len(entry) != 2 {
		t.Fatalf("an SS route needs TCP and UDP forwards on the entry: %+v", entry)
	}
	for _, f := range entry {
		want := []shared.ForwardTarget{{Host: "198.51.100.2", Port: 50010}, {Host: "198.51.100.3", Port: 50010}}
		if f.Port != 50010 || f.Balance != "round-robin" || !slices.Equal(f.Targets, want) || f.FirewallPolicy != "all" || f.RouteID == "" {
			t.Fatalf("entry forward: %+v", f)
		}
	}
	for _, id := range []string{l.t1, l.t2} {
		for _, f := range l.forwards(id) {
			if !slices.Equal(f.Targets, []shared.ForwardTarget{{Host: "198.51.100.4", Port: 50010}}) || f.FirewallPolicy != "restricted" || f.FirewallSources != "198.51.100.1" {
				t.Fatalf("middle hop forward: %+v", f)
			}
		}
	}
	node, _ := l.p.store.Node(l.nodeID)
	if node.RouteSources != "198.51.100.2,198.51.100.3" {
		t.Fatalf("the exit node must admit exactly the last hops: %q", node.RouteSources)
	}
	state, err := l.p.app.desired(l.exit)
	if err != nil {
		t.Fatal(err)
	}
	if n := state.Nodes[0].Node; n.FirewallPolicy != "restricted" || n.FirewallSources != "198.51.100.2/32,198.51.100.3/32" {
		t.Fatalf("a node without direct access gets the route sources as its firewall: %+v", n)
	}

	// Reaching the exit over its internal address changes the last hops'
	// targets; t1 has no internal address, so it cannot be reached that way.
	if code, out, _ := l.p.do("PATCH", "/api/routes/"+rt["id"].(string), map[string]any{"name": "hk", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true, "nodeInternal": true,
		"hops": []map[string]any{{"serverIds": []string{l.t1, l.t2}, "balance": "failover", "internal": true}}}, nil); code != 400 || !strings.Contains(out["error"].(string), "内网地址") {
		t.Fatalf("hop without internal address: %d %v", code, out)
	}
	if code, out, _ := l.p.do("PATCH", "/api/routes/"+rt["id"].(string), map[string]any{"name": "hk", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true, "nodeInternal": true,
		"hops": []map[string]any{{"serverIds": []string{l.t2}, "balance": "failover", "internal": true}}}, nil); code != 200 {
		t.Fatalf("internal route: %d %v", code, out)
	}
	if got := l.forwards(l.t2)[0]; got.Targets[0].Host != "10.0.0.4" {
		t.Fatalf("the last hop should reach the exit internally: %+v", got)
	}
	if len(l.forwards(l.t1)) != 0 {
		t.Fatal("a server taken out of the route must lose its forwards")
	}
	if got := l.forwards(l.entry)[0]; got.Targets[0].Host != "10.0.0.3" {
		t.Fatalf("the entry should reach t2 internally: %+v", got)
	}
	node, _ = l.p.store.Node(l.nodeID)
	if node.RouteSources != "10.0.0.3" {
		t.Fatalf("over a private link the exit admits the internal address: %q", node.RouteSources)
	}
}

func TestRoutePortAvoidsConflictsOnAnyHop(t *testing.T) {
	l := newRouteLab(t)
	if code, out, _ := l.p.do("POST", "/api/forwards", map[string]any{"serverId": l.t1, "name": "manual", "network": "tcp", "port": 50010,
		"targets": []map[string]any{{"host": "192.0.2.9", "port": 443}}, "enabled": true}, nil); code != 201 {
		t.Fatalf("manual forward: %d %v", code, out)
	}
	code, rt := l.route(map[string]any{"name": "r", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true,
		"hops": []map[string]any{{"serverIds": []string{l.t1}}}})
	if code != 201 {
		t.Fatalf("route: %d %v", code, rt)
	}
	port := int(rt["port"].(float64))
	if port == 50010 {
		t.Fatal("the route took a port already used on one hop")
	}
	for _, id := range []string{l.entry, l.t1} {
		for _, f := range l.forwards(id) {
			if f.RouteID != "" && f.Port != port {
				t.Fatalf("every hop must use the same port %d: %+v", port, f)
			}
		}
	}
	// An explicit port in use is refused.
	if code, out := l.route(map[string]any{"name": "r2", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true, "port": port}); code != 409 {
		t.Fatalf("taken port: %d %v", code, out)
	}
}

func TestRoutesShareFinalTransitListener(t *testing.T) {
	l := newRouteLab(t)
	entry2, agent2 := l.p.enrollAs("entry2", []string{"entry"}, map[string]any{"ipv4": "198.51.100.5"})
	l.agents = append(l.agents, agent2)
	create := func(name, entry string) string {
		t.Helper()
		code, route := l.route(map[string]any{"name": name, "entryServerId": entry, "nodeId": l.nodeID, "enabled": true,
			"port": 50000, "hops": []map[string]any{{"serverIds": []string{l.t1}}}})
		if code != 201 {
			t.Fatalf("create %s: %d %v", name, code, route)
		}
		return route["id"].(string)
	}
	first, second := create("Shanghai 1", l.entry), create("Shanghai 2", entry2)
	checkShared := func(sources string) {
		t.Helper()
		forwards := slices.DeleteFunc(l.forwards(l.t1), func(f shared.ForwardRule) bool { return !f.Enabled })
		if len(forwards) != 2 {
			t.Fatalf("final transit needs one TCP and one UDP listener: %+v", forwards)
		}
		for _, f := range forwards {
			if f.Port != 50000 || f.FirewallPolicy != "restricted" || f.FirewallSources != sources ||
				!slices.Equal(f.Targets, []shared.ForwardTarget{{Host: "198.51.100.4", Port: 50010}}) {
				t.Fatalf("shared transit forward: %+v", f)
			}
		}
		state, err := l.p.app.desired(l.t1)
		active := slices.DeleteFunc(state.Forwards, func(f shared.ForwardRule) bool { return !f.Enabled })
		if err != nil || len(active) != 2 {
			t.Fatalf("Agent received duplicate listeners: %+v %v", state.Forwards, err)
		}
		for _, f := range active {
			if len(f.RouteIDs) != 0 {
				t.Fatalf("panel-only route membership leaked to Agent: %+v", f)
			}
		}
	}
	checkShared("198.51.100.1,198.51.100.5")
	for _, id := range []string{l.entry, entry2} {
		if forwards := l.forwards(id); len(forwards) != 2 || forwards[0].ServerID != id {
			t.Fatalf("entry %s lost its own listener: %+v", id, forwards)
		}
	}
	for _, f := range l.forwards(l.t1) {
		if !slices.Equal(f.RouteIDs, []string{first, second}) {
			t.Fatalf("shared listener lost route membership: %+v", f)
		}
	}
	l.applyAll()
	checkLive := func(routeID string) {
		t.Helper()
		world, err := l.p.app.loadRouteWorld()
		if err != nil {
			t.Fatal(err)
		}
		for _, route := range world.routes {
			if route.ID != routeID {
				continue
			}
			live, err := l.p.app.routeLive(route, world, "")
			if err != nil || !live {
				t.Fatalf("route %s is not usable: live=%v err=%v", route.Name, live, err)
			}
			return
		}
		t.Fatalf("route %s disappeared", routeID)
	}
	for _, route := range l.p.list("/api/routes") {
		if route["status"] != "active" {
			t.Fatalf("shared route is not active: %+v", route)
		}
	}
	checkLive(first)
	checkLive(second)
	forward := l.forwards(l.t1)[0]
	if forward.Network != "tcp" {
		forward = l.forwards(l.t1)[1]
	}
	point := shared.RouteLatency{ForwardID: forward.ID, Host: forward.Targets[0].Host, Port: forward.Targets[0].Port, TCPMs: 42, OK: true, At: time.Now()}
	if code, out, _ := l.p.do("POST", "/agent/report", map[string]any{"hostReported": true, "agentVersion": "0.6.23", "forwardTcpUdp": true,
		"manualFirewallSupport": true, "multiUserStats": true, "nodeFirewallPolicies": true, "forwardSupport": true,
		"shadowTlsAuth": true, "snellFixedPort": true, "snellV6": true, "ufwStatus": "active",
		"routeLatencies": []shared.RouteLatency{point}}, l.agents[1]); code != 200 {
		t.Fatalf("shared transit latency report: %d %v", code, out)
	}
	for _, route := range l.p.list("/api/routes") {
		edges, _ := route["edgeLatencies"].([]any)
		if !slices.ContainsFunc(edges, func(edge any) bool {
			item := edge.(map[string]any)
			return item["fromServerId"] == l.t1 && item["toServerId"] == l.exit && item["tcpMs"] == float64(42)
		}) {
			t.Fatalf("shared transit latency is missing from a route: %+v", route)
		}
	}
	update := func(enabled bool) {
		t.Helper()
		if code, out, _ := l.p.do("PATCH", "/api/routes/"+first, map[string]any{"name": "Shanghai 1", "entryServerId": l.entry, "nodeId": l.nodeID,
			"enabled": enabled, "port": 50000, "hops": []map[string]any{{"serverIds": []string{l.t1}}}}, nil); code != 200 {
			t.Fatalf("change first route enabled=%v: %d %v", enabled, code, out)
		}
	}
	update(false)
	checkShared("198.51.100.5")
	l.applyAll()
	for _, route := range l.p.list("/api/routes") {
		if route["id"] == second && route["status"] != "active" {
			t.Fatalf("second route failed after the first was disabled: %+v", route)
		}
	}
	checkLive(second)
	update(true)
	checkShared("198.51.100.1,198.51.100.5")
	if code, out, _ := l.p.do("DELETE", "/api/routes/"+first, nil, nil); code != 200 {
		t.Fatalf("delete first route: %d %v", code, out)
	}
	checkShared("198.51.100.5")
	l.applyAll()
	routes := l.p.list("/api/routes")
	if len(routes) != 1 || routes[0]["id"] != second || routes[0]["status"] != "active" {
		t.Fatalf("second route failed after deleting the first: %+v", routes)
	}
	checkLive(second)
}

func TestRouteSharedPortRequiresSameExitNode(t *testing.T) {
	l := newRouteLab(t)
	entry2, _ := l.p.enrollAs("entry2", []string{"entry"}, map[string]any{"ipv4": "198.51.100.5"})
	if code, route := l.route(map[string]any{"name": "first", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true,
		"port": 50000, "hops": []map[string]any{{"serverIds": []string{l.t1}}}}); code != 201 {
		t.Fatalf("first route: %d %v", code, route)
	}
	transit, _ := l.p.store.Server(l.t1)
	transit.InternalAddress = "10.0.0.2"
	if err := l.p.store.PutServer(transit); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := l.p.do("POST", "/api/routes", map[string]any{"name": "different address mode", "entryServerId": entry2, "nodeId": l.nodeID,
		"enabled": true, "port": 50000, "nodeInternal": true, "hops": []map[string]any{{"serverIds": []string{l.t1}}}}, nil); code != 409 {
		t.Fatalf("different final-hop address mode shared the port: %d %v", code, out)
	}
	code, node, _ := l.p.do("POST", "/api/nodes", map[string]any{"serverId": l.exit, "name": "other", "protocol": "ss", "port": 50011, "method": "2022-blake3-aes-128-gcm"}, nil)
	if code != 201 {
		t.Fatalf("second node: %d %v", code, node)
	}
	if code, out, _ := l.p.do("POST", "/api/routes", map[string]any{"name": "different node", "entryServerId": entry2, "nodeId": node["id"],
		"enabled": true, "port": 50000, "hops": []map[string]any{{"serverIds": []string{l.t1}}}}, nil); code != 409 {
		t.Fatalf("different exit node shared the port: %d %v", code, out)
	}
}

func singleServerHops(ids ...string) []map[string]any {
	hops := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		hops = append(hops, map[string]any{"serverIds": []string{id}})
	}
	return hops
}

func createSharedTestRoute(t *testing.T, l *routeLab, name, entry string, hops []map[string]any) string {
	t.Helper()
	code, route := l.route(map[string]any{"name": name, "entryServerId": entry, "nodeId": l.nodeID, "enabled": true, "port": 50000, "hops": hops})
	if code != 201 {
		t.Fatalf("create %s: %d %v", name, code, route)
	}
	return route["id"].(string)
}

func requireSharedHop(t *testing.T, l *routeLab, serverID string, members []string, sources, target string) {
	t.Helper()
	active := slices.DeleteFunc(l.forwards(serverID), func(f shared.ForwardRule) bool { return !f.Enabled })
	if len(active) != 2 {
		t.Fatalf("server %s needs one TCP and one UDP listener: %+v", serverID, active)
	}
	for _, f := range active {
		wantPort := 50000
		if target == "198.51.100.4" {
			wantPort = 50010
		}
		if f.Port != 50000 || f.RouteID != members[0] || f.ID != routeForwardID(members[0], serverID, f.Network) ||
			f.FirewallPolicy != "restricted" || f.FirewallSources != sources ||
			!slices.Equal(f.Targets, []shared.ForwardTarget{{Host: target, Port: wantPort}}) {
			t.Fatalf("wrong shared forward on %s: %+v", serverID, f)
		}
		if len(members) > 1 && !slices.Equal(f.RouteIDs, members) || len(members) == 1 && len(f.RouteIDs) != 0 {
			t.Fatalf("wrong shared membership on %s: %+v", serverID, f)
		}
	}
	state, err := l.p.app.desired(serverID)
	if err != nil {
		t.Fatal(err)
	}
	active = slices.DeleteFunc(state.Forwards, func(f shared.ForwardRule) bool { return !f.Enabled })
	if len(active) != 2 {
		t.Fatalf("Agent has duplicate listeners on %s: %+v", serverID, state.Forwards)
	}
	for _, f := range state.Forwards {
		if len(f.RouteIDs) > 0 {
			t.Fatalf("Agent received panel-only routeIds: %+v", f)
		}
	}
}

func requireRouteLive(t *testing.T, l *routeLab, routeID string) {
	t.Helper()
	world, err := l.p.app.loadRouteWorld()
	if err != nil {
		t.Fatal(err)
	}
	for _, rt := range world.routes {
		if rt.ID == routeID {
			live, err := l.p.app.routeLive(rt, world, "")
			if err != nil || !live || routeStatus(rt, world.forwards) != "active" {
				t.Fatalf("route %s not live: live=%v err=%v status=%s", rt.Name, live, err, routeStatus(rt, world.forwards))
			}
			return
		}
	}
	t.Fatalf("route %s missing", routeID)
}

func TestRoutesShareMatchingSuffixAtEveryDepth(t *testing.T) {
	for _, depth := range []int{2, 4, 8} {
		t.Run(strconv.Itoa(depth)+" middle hops", func(t *testing.T) {
			l := newRouteLab(t)
			common := []string{l.t1, l.t2}
			addresses := []string{"198.51.100.2", "198.51.100.3"}
			for i := len(common); i < depth; i++ {
				ip := "198.51.100." + strconv.Itoa(i+20)
				id, agent := l.p.enrollAs("transit-"+strconv.Itoa(i), []string{"transit"}, map[string]any{"ipv4": ip})
				common, addresses = append(common, id), append(addresses, ip)
				l.agents = append(l.agents, agent)
			}
			entry2, agent2 := l.p.enrollAs("entry2", []string{"entry"}, map[string]any{"ipv4": "198.51.100.9"})
			l.agents = append(l.agents, agent2)
			first := createSharedTestRoute(t, l, "Shanghai 1", l.entry, singleServerHops(common...))
			second := createSharedTestRoute(t, l, "Shanghai 2", entry2, singleServerHops(common...))
			for i, id := range common {
				sources := "198.51.100.1,198.51.100.9"
				if i > 0 {
					sources = addresses[i-1]
				}
				target := "198.51.100.4"
				if i+1 < len(common) {
					target = addresses[i+1]
				}
				requireSharedHop(t, l, id, []string{first, second}, sources, target)
			}
			l.applyAll()
			requireRouteLive(t, l, first)
			requireRouteLive(t, l, second)
			if depth != 2 {
				return
			}
			// Changing the owner must shrink every shared hop's allowlist and
			// leave the other route usable; re-enabling restores the union.
			setFirst := func(enabled bool) {
				t.Helper()
				if code, out, _ := l.p.do("PATCH", "/api/routes/"+first, map[string]any{"name": "Shanghai 1", "entryServerId": l.entry,
					"nodeId": l.nodeID, "enabled": enabled, "port": 50000, "hops": singleServerHops(common...)}, nil); code != 200 {
					t.Fatalf("toggle first route: %d %v", code, out)
				}
			}
			setFirst(false)
			requireSharedHop(t, l, common[0], []string{second}, "198.51.100.9", addresses[1])
			requireSharedHop(t, l, common[1], []string{second}, addresses[0], "198.51.100.4")
			l.applyAll()
			requireRouteLive(t, l, second)
			setFirst(true)
			requireSharedHop(t, l, common[0], []string{first, second}, "198.51.100.1,198.51.100.9", addresses[1])
			requireSharedHop(t, l, common[1], []string{first, second}, addresses[0], "198.51.100.4")
			l.applyAll()
			requireRouteLive(t, l, first)
			if code, out, _ := l.p.do("DELETE", "/api/routes/"+first, nil, nil); code != 200 {
				t.Fatalf("delete first route: %d %v", code, out)
			}
			requireSharedHop(t, l, common[0], []string{second}, "198.51.100.9", addresses[1])
			requireSharedHop(t, l, common[1], []string{second}, addresses[0], "198.51.100.4")
			l.applyAll()
			requireRouteLive(t, l, second)
		})
	}
}

func TestRoutesShareAfterMeetingMidway(t *testing.T) {
	l := newRouteLab(t)
	hongKong, hkAgent := l.p.enrollAs("Hong Kong", []string{"transit"}, map[string]any{"ipv4": "198.51.100.6"})
	entry2, entryAgent := l.p.enrollAs("Shanghai 2", []string{"entry"}, map[string]any{"ipv4": "198.51.100.9"})
	l.agents = append(l.agents, hkAgent, entryAgent)
	first := createSharedTestRoute(t, l, "via Hong Kong", l.entry, singleServerHops(hongKong, l.t1, l.t2))
	second := createSharedTestRoute(t, l, "direct to Japan", entry2, singleServerHops(l.t1, l.t2))
	if got := l.forwards(hongKong); len(got) != 2 || got[0].RouteID != first || len(got[0].RouteIDs) != 0 {
		t.Fatalf("the route before the meeting point must remain separate: %+v", got)
	}
	requireSharedHop(t, l, l.t1, []string{first, second}, "198.51.100.6,198.51.100.9", "198.51.100.3")
	requireSharedHop(t, l, l.t2, []string{first, second}, "198.51.100.2", "198.51.100.4")
	l.applyAll()
	requireRouteLive(t, l, first)
	requireRouteLive(t, l, second)
	// Distinct measurements from both shared hops must appear on both paths.
	for _, sample := range []struct {
		server string
		agent  map[string]string
		ms     int64
	}{{l.t1, l.agents[1], 41}, {l.t2, l.agents[2], 53}} {
		var tcp shared.ForwardRule
		for _, f := range l.forwards(sample.server) {
			if f.Network == "tcp" {
				tcp = f
			}
		}
		point := shared.RouteLatency{ForwardID: tcp.ID, Host: tcp.Targets[0].Host, Port: tcp.Targets[0].Port, TCPMs: sample.ms, OK: true, At: time.Now()}
		if code, out, _ := l.p.do("POST", "/agent/report", map[string]any{"hostReported": true, "agentVersion": "0.6.23", "forwardTcpUdp": true,
			"manualFirewallSupport": true, "multiUserStats": true, "nodeFirewallPolicies": true, "forwardSupport": true,
			"shadowTlsAuth": true, "snellFixedPort": true, "snellV6": true, "ufwStatus": "active",
			"routeLatencies": []shared.RouteLatency{point}}, sample.agent); code != 200 {
			t.Fatalf("latency report: %d %v", code, out)
		}
	}
	for _, rt := range l.p.list("/api/routes") {
		edges := rt["edgeLatencies"].([]any)
		for _, want := range []struct {
			from string
			ms   float64
		}{{l.t1, 41}, {l.t2, 53}} {
			if !slices.ContainsFunc(edges, func(edge any) bool {
				item := edge.(map[string]any)
				return item["fromServerId"] == want.from && item["tcpMs"] == want.ms
			}) {
				t.Fatalf("route %s is missing shared-hop latency %s: %+v", rt["name"], want.from, edges)
			}
		}
	}
	// Editing a shared landing node uses the same prospective route checks.
	if code, out, _ := l.p.do("PATCH", "/api/nodes/"+l.nodeID, map[string]any{"name": "hk-ss", "protocol": "ss", "port": 50011,
		"method": "2022-blake3-aes-128-gcm", "enabled": true}, nil); code != 200 {
		t.Fatalf("shared node edit: %d %v", code, out)
	}
	for _, f := range l.forwards(l.t2) {
		if f.Enabled && f.Targets[0].Port != 50011 {
			t.Fatalf("shared target did not follow node edit: %+v", f)
		}
	}
	l.applyAll()
	requireRouteLive(t, l, first)
	requireRouteLive(t, l, second)
}

func TestThreeRoutesShareAllMiddleHops(t *testing.T) {
	l := newRouteLab(t)
	entry2, agent2 := l.p.enrollAs("entry2", []string{"entry"}, map[string]any{"ipv4": "198.51.100.5"})
	entry3, agent3 := l.p.enrollAs("entry3", []string{"entry"}, map[string]any{"ipv4": "198.51.100.6"})
	l.agents = append(l.agents, agent2, agent3)
	hops := singleServerHops(l.t1, l.t2)
	ids := []string{
		createSharedTestRoute(t, l, "first", l.entry, hops),
		createSharedTestRoute(t, l, "second", entry2, hops),
		createSharedTestRoute(t, l, "third", entry3, hops),
	}
	requireSharedHop(t, l, l.t1, ids, "198.51.100.1,198.51.100.5,198.51.100.6", "198.51.100.3")
	requireSharedHop(t, l, l.t2, ids, "198.51.100.2", "198.51.100.4")
	l.applyAll()
	for _, id := range ids {
		requireRouteLive(t, l, id)
	}
}

func TestRoutesShareMatchingLoadGroup(t *testing.T) {
	l := newRouteLab(t)
	backup, agent := l.p.enrollAs("backup B", []string{"transit"}, map[string]any{"ipv4": "198.51.100.6"})
	entry2, entryAgent := l.p.enrollAs("entry2", []string{"entry"}, map[string]any{"ipv4": "198.51.100.9"})
	l.agents = append(l.agents, agent, entryAgent)
	hops := []map[string]any{{"serverIds": []string{l.t1, backup}, "balance": "round-robin"}, {"serverIds": []string{l.t2}}}
	first := createSharedTestRoute(t, l, "first", l.entry, hops)
	second := createSharedTestRoute(t, l, "second", entry2, hops)
	for _, id := range []string{l.t1, backup} {
		requireSharedHop(t, l, id, []string{first, second}, "198.51.100.1,198.51.100.9", "198.51.100.3")
	}
	requireSharedHop(t, l, l.t2, []string{first, second}, "198.51.100.2,198.51.100.6", "198.51.100.4")
	l.applyAll()
	requireRouteLive(t, l, first)
	requireRouteLive(t, l, second)
}

func TestSharedHopRejectsDifferentSuffixes(t *testing.T) {
	for _, change := range []string{"later server", "server order", "balance", "internal", "node internal", "landing node", "load group", "same entry"} {
		t.Run(change, func(t *testing.T) {
			l := newRouteLab(t)
			entry2, _ := l.p.enrollAs("entry2", []string{"entry"}, map[string]any{"ipv4": "198.51.100.9"})
			d, _ := l.p.enrollAs("D", []string{"transit"}, map[string]any{"ipv4": "198.51.100.6", "internalAddress": "10.0.0.6"})
			e, _ := l.p.enrollAs("E", []string{"transit"}, map[string]any{"ipv4": "198.51.100.7", "internalAddress": "10.0.0.7"})
			b, _ := l.p.store.Server(l.t1)
			b.InternalAddress = "10.0.0.2"
			if err := l.p.store.PutServer(b); err != nil {
				t.Fatal(err)
			}
			baseHops := []map[string]any{{"serverIds": []string{l.t1}}, {"serverIds": []string{l.t2, d}}}
			createSharedTestRoute(t, l, "base", l.entry, baseHops)
			candidateHops := []map[string]any{{"serverIds": []string{l.t1}}, {"serverIds": []string{l.t2, d}}}
			candidate := map[string]any{"name": "candidate", "entryServerId": entry2, "nodeId": l.nodeID, "enabled": true, "port": 50000, "hops": candidateHops}
			switch change {
			case "later server":
				candidateHops[1]["serverIds"] = []string{l.t2, e}
			case "server order":
				candidateHops[1]["serverIds"] = []string{d, l.t2}
			case "balance":
				candidateHops[0]["balance"] = "round-robin"
			case "internal":
				candidateHops[1]["internal"] = true
			case "node internal":
				candidate["nodeInternal"] = true
			case "landing node":
				code, node, _ := l.p.do("POST", "/api/nodes", map[string]any{"serverId": l.exit, "name": "other", "protocol": "ss", "port": 50011,
					"method": "2022-blake3-aes-128-gcm"}, nil)
				if code != 201 {
					t.Fatalf("other node: %d %v", code, node)
				}
				candidate["nodeId"] = node["id"]
			case "load group":
				candidateHops[0]["serverIds"] = []string{l.t1, e}
			case "same entry":
				candidate["entryServerId"] = l.entry
			}
			if code, out, _ := l.p.do("POST", "/api/routes", candidate, nil); code != 409 {
				t.Fatalf("incompatible suffix accepted: %d %v", code, out)
			}
			if routes := l.p.list("/api/routes"); len(routes) != 1 {
				t.Fatalf("failed save left an incompatible route: %+v", routes)
			}
			if err := l.p.app.syncRoutes(); err != nil {
				t.Fatalf("failed validation blocked future sync: %v", err)
			}
		})
	}
}

func TestRouteEditRejectsSharedHopConflict(t *testing.T) {
	l := newRouteLab(t)
	entry2, _ := l.p.enrollAs("entry2", []string{"entry"}, map[string]any{"ipv4": "198.51.100.9"})
	d, _ := l.p.enrollAs("D", []string{"transit"}, map[string]any{"ipv4": "198.51.100.6"})
	first := createSharedTestRoute(t, l, "first", l.entry, singleServerHops(l.t1, l.t2))
	second := createSharedTestRoute(t, l, "second", entry2, singleServerHops(l.t1, l.t2))
	if code, out, _ := l.p.do("PATCH", "/api/routes/"+second, map[string]any{"name": "second", "entryServerId": entry2,
		"nodeId": l.nodeID, "enabled": true, "port": 50000, "hops": singleServerHops(l.t1, d)}, nil); code != 409 {
		t.Fatalf("editing a shared suffix to a different target succeeded: %d %v", code, out)
	}
	requireSharedHop(t, l, l.t1, []string{first, second}, "198.51.100.1,198.51.100.9", "198.51.100.3")
	if err := l.p.app.syncRoutes(); err != nil {
		t.Fatalf("rejected edit blocked route sync: %v", err)
	}
}

func TestSharedHopOfflineExportOmitsRouteIDs(t *testing.T) {
	l := newRouteLab(t)
	offline := createOfflineServer(l.p, "offline transit", "198.51.100.8")
	entry2, _ := l.p.enrollAs("entry2", []string{"entry"}, map[string]any{"ipv4": "198.51.100.9"})
	first := createSharedTestRoute(t, l, "first", l.entry, singleServerHops(offline))
	second := createSharedTestRoute(t, l, "second", entry2, singleServerHops(offline))
	for _, f := range l.forwards(offline) {
		if !slices.Equal(f.RouteIDs, []string{first, second}) {
			t.Fatalf("shared membership was not stored: %+v", f)
		}
	}
	bundle := exportOffline(l.p, offline)
	if len(bundle.Forwards) != 2 {
		t.Fatalf("offline export has duplicate listeners: %+v", bundle.Forwards)
	}
	for _, f := range bundle.Forwards {
		if len(f.RouteIDs) != 0 {
			t.Fatalf("offline export contains routeIds: %+v", f)
		}
	}
	raw, err := json.Marshal(bundle)
	if err != nil || strings.Contains(string(raw), `"routeIds"`) {
		t.Fatalf("offline JSON contains routeIds: %v %s", err, raw)
	}
}

func TestUnsharedRouteSyncKeepsForwardsAndRevision(t *testing.T) {
	l := newRouteLab(t)
	routeID := createSharedTestRoute(t, l, "existing", l.entry, singleServerHops(l.t1, l.t2))
	l.applyAll()
	ids := []string{l.entry, l.t1, l.t2, l.exit}
	beforeRevisions := map[string]int64{}
	beforeForwards := map[string]string{}
	for _, id := range ids {
		s, err := l.p.store.Server(id)
		if err != nil {
			t.Fatal(err)
		}
		beforeRevisions[id] = s.Revision
		forwards, err := l.p.store.Forwards(id)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(forwards)
		beforeForwards[id] = string(raw)
		for _, f := range forwards {
			if f.ID != routeForwardID(routeID, id, f.Network) || len(f.RouteIDs) != 0 {
				t.Fatalf("unshared forward changed its ID or gained routeIds: %+v", f)
			}
		}
	}
	if err := l.p.app.syncRoutes(); err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		s, _ := l.p.store.Server(id)
		forwards, _ := l.p.store.Forwards(id)
		raw, _ := json.Marshal(forwards)
		if s.Revision != beforeRevisions[id] || string(raw) != beforeForwards[id] {
			t.Fatalf("sync changed unshared server %s: revision %d→%d, forwards %s→%s", id,
				beforeRevisions[id], s.Revision, beforeForwards[id], raw)
		}
	}
}

func TestRouteRolesAndReferences(t *testing.T) {
	l := newRouteLab(t)
	// A transit server cannot be the first hop, and only an exit carries nodes.
	if code, out := l.route(map[string]any{"name": "x", "entryServerId": l.t1, "nodeId": l.nodeID, "enabled": true}); code != 400 {
		t.Fatalf("transit as entry: %d %v", code, out)
	}
	if code, out, _ := l.p.do("POST", "/api/nodes", map[string]any{"serverId": l.t1, "name": "n", "protocol": "ss", "port": 50020, "method": "2022-blake3-aes-128-gcm"}, nil); code != 409 {
		t.Fatalf("node on a transit server: %d %v", code, out)
	}
	// A node without direct access is subscribed only through routes.
	if code, out, _ := l.p.do("POST", "/api/subscriptions", map[string]any{"name": "s", "format": "sing-box", "nodeIds": []string{l.nodeID}}, nil); code != 400 {
		t.Fatalf("direct subscription of a route-only node: %d %v", code, out)
	}
	code, rt := l.route(map[string]any{"name": "r", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true})
	if code != 201 {
		t.Fatalf("route: %d %v", code, rt)
	}
	routeID := rt["id"].(string)
	code, sub, _ := l.p.do("POST", "/api/subscriptions", map[string]any{"name": "s", "format": "sing-box", "routeIds": []string{routeID}}, nil)
	if code != 201 {
		t.Fatalf("route subscription: %d %v", code, sub)
	}
	if code, out, _ := l.p.do("DELETE", "/api/nodes/"+l.nodeID, nil, nil); code != 409 {
		t.Fatalf("deleting a node a route ends at: %d %v", code, out)
	}
	if code, out, _ := l.p.do("DELETE", "/api/routes/"+routeID, nil, nil); code != 409 {
		t.Fatalf("deleting a subscribed route: %d %v", code, out)
	}
	if code, out, _ := l.p.do("PATCH", "/api/servers/"+l.entry, map[string]any{"name": "entry", "roles": []string{"transit"}, "country": "SG", "ipv4": "198.51.100.1"}, nil); code != 409 {
		t.Fatalf("taking the entry role from a route's entry: %d %v", code, out)
	}
	if code, out, _ := l.p.do("PATCH", "/api/forwards/"+l.forwards(l.entry)[0].ID, map[string]any{"name": "x"}, nil); code != 409 {
		t.Fatalf("editing a generated forward directly: %d %v", code, out)
	}
	// Removing the route from the subscription, then the route, removes its
	// forwards.
	if code, out, _ := l.p.do("PATCH", "/api/subscriptions/"+sub["id"].(string), map[string]any{"name": "s", "format": "sing-box", "enabled": true}, nil); code != 200 {
		t.Fatalf("subscription edit: %d %v", code, out)
	}
	if code, out, _ := l.p.do("DELETE", "/api/routes/"+routeID, nil, nil); code != 200 {
		t.Fatalf("route delete: %d %v", code, out)
	}
	if len(l.forwards(l.entry)) != 0 {
		t.Fatal("a deleted route must take its forwards along")
	}
}

func TestRouteSubscriptionServesEntryAddress(t *testing.T) {
	l := newRouteLab(t)
	code, rt := l.route(map[string]any{"name": "hk", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true,
		"hops": []map[string]any{{"serverIds": []string{l.t1}}}})
	if code != 201 {
		t.Fatalf("route: %d %v", code, rt)
	}
	code, sub, _ := l.p.do("POST", "/api/subscriptions", map[string]any{"name": "s", "format": "sing-box", "routeIds": []string{rt["id"].(string)}}, nil)
	if code != 201 {
		t.Fatalf("subscription: %d %v", code, sub)
	}
	path := strings.TrimPrefix(sub["url"].(string), "https://mui.example.test")
	if code, body := l.p.fetch(path); code != 503 {
		t.Fatalf("before the hops apply the route is pending: %d %s", code, body)
	}
	l.applyAll()
	code, body := l.p.fetch(path)
	if code != 200 {
		t.Fatalf("download: %d %s", code, body)
	}
	var config struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal([]byte(body), &config); err != nil || len(config.Outbounds) != 1 {
		t.Fatalf("config: %v %s", err, body)
	}
	out := config.Outbounds[0]
	if out["server"] != "entry.example.com" || out["server_port"] != float64(50010) || out["tag"] != "hk" {
		t.Fatalf("clients must dial the entry on the route port: %v", out)
	}
	if !strings.Contains(out["password"].(string), ":") {
		t.Fatalf("the exit node's per-subscription login is used: %v", out)
	}
	state, err := l.p.app.desired(l.exit)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(state.Nodes[0].Users, func(u shared.NodeUser) bool { return u.SubscriptionID == sub["id"].(string) }) {
		t.Fatal("the exit node must carry the subscription's login")
	}
}
