package server

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

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
