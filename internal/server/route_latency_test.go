package server

import (
	"slices"
	"testing"
	"time"

	"mui/internal/shared"
)

func TestRouteEdgeLatenciesMapOnlyCurrentFreshTargets(t *testing.T) {
	now := time.Now()
	rt := shared.Route{ID: "route", EntryServerID: "entry", Hops: []shared.RouteHop{{ServerIDs: []string{"hop"}}}, NodeID: "node", Port: 45678, Enabled: true}
	world := routeWorld{
		servers: map[string]shared.Server{
			"entry": {ID: "entry", RouteLatencies: []shared.RouteLatency{
				{ForwardID: routeForwardID(rt.ID, "entry", "tcp"), Host: "198.51.100.2", Port: rt.Port, TCPMs: 42, OK: true, At: now},
			}},
			"hop": {ID: "hop", IPv4: "198.51.100.2", RouteLatencies: []shared.RouteLatency{
				{ForwardID: routeForwardID(rt.ID, "hop", "tcp"), Host: "198.51.100.3", Port: 32123, TCPMs: 65, OK: true, At: now.Add(-3 * time.Minute)},
			}},
			"exit": {ID: "exit", IPv4: "198.51.100.3"},
		},
		nodes: map[string]shared.Node{"node": {ID: "node", ServerID: "exit", Port: 32123}},
	}
	edges := routeEdgeLatencies(rt, world, now)
	if len(edges) != 1 || edges[0].FromServerID != "entry" || edges[0].ToServerID != "hop" || edges[0].TCPMs != 42 {
		t.Fatalf("unexpected mapped edges: %+v", edges)
	}
	forward := shared.ForwardRule{ID: routeForwardID(rt.ID, "entry", "tcp"), RouteID: rt.ID, Network: "tcp", Enabled: true, Targets: []shared.ForwardTarget{{Host: "198.51.100.2", Port: rt.Port}}}
	points := []shared.RouteLatency{
		world.servers["entry"].RouteLatencies[0],
		{ForwardID: forward.ID, Host: "127.0.0.1", Port: rt.Port, At: now},
		{ForwardID: forward.ID, Host: "198.51.100.2", Port: rt.Port, TCPMs: 1, OK: true, At: now.Add(-3 * time.Minute)},
	}
	valid := validRouteLatencies(points, []shared.ForwardRule{forward}, now)
	if len(valid) != 1 || valid[0].TCPMs != 42 {
		t.Fatalf("invalid/stale points accepted: %+v", valid)
	}
}

func TestRouteLatencyReportAppearsInRouteList(t *testing.T) {
	l := newRouteLab(t)
	code, route := l.route(map[string]any{"name": "latency", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true})
	if code != 201 {
		t.Fatalf("create route: %d %v", code, route)
	}
	forwards := l.forwards(l.entry)
	index := slices.IndexFunc(forwards, func(f shared.ForwardRule) bool { return f.Network == "tcp" })
	if index < 0 {
		t.Fatalf("missing TCP route forward: %+v", forwards)
	}
	forward := forwards[index]
	point := shared.RouteLatency{ForwardID: forward.ID, Host: forward.Targets[0].Host, Port: forward.Targets[0].Port, TCPMs: 28, OK: true, At: time.Now()}
	if code, out, _ := l.p.do("POST", "/agent/report", map[string]any{"hostReported": true, "agentVersion": "0.6.23", "routeLatencies": []shared.RouteLatency{point}}, l.agents[0]); code != 200 {
		t.Fatalf("report: %d %v", code, out)
	}
	entry, err := l.p.store.Server(l.entry)
	if err != nil {
		t.Fatal(err)
	}
	routes := l.p.list("/api/routes")
	if len(routes) != 1 {
		t.Fatalf("route list: %+v", routes)
	}
	edges, ok := routes[0]["edgeLatencies"].([]any)
	if !ok || len(edges) != 1 || edges[0].(map[string]any)["tcpMs"] != float64(28) {
		t.Fatalf("latency missing from route view: route=%+v entry=%+v forward=%+v", routes[0], entry.RouteLatencies, forward)
	}
}

func TestRouteLatencyTimeoutRemainsVisible(t *testing.T) {
	l := newRouteLab(t)
	code, route := l.route(map[string]any{"name": "timeout", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true})
	if code != 201 {
		t.Fatalf("create route: %d %v", code, route)
	}
	forwards := l.forwards(l.entry)
	index := slices.IndexFunc(forwards, func(f shared.ForwardRule) bool { return f.Network == "tcp" })
	if index < 0 {
		t.Fatalf("missing TCP route forward: %+v", forwards)
	}
	forward := forwards[index]
	point := shared.RouteLatency{ForwardID: forward.ID, Host: forward.Targets[0].Host, Port: forward.Targets[0].Port, TCPMs: 3001, OK: false, At: time.Now()}
	if code, out, _ := l.p.do("POST", "/agent/report", map[string]any{"hostReported": true, "agentVersion": "0.6.23", "routeLatencies": []shared.RouteLatency{point}}, l.agents[0]); code != 200 {
		t.Fatalf("report: %d %v", code, out)
	}
	routes := l.p.list("/api/routes")
	if len(routes) != 1 {
		t.Fatalf("route list: %+v", routes)
	}
	edges, ok := routes[0]["edgeLatencies"].([]any)
	if !ok || len(edges) != 1 {
		t.Fatalf("timeout missing from route view: %+v", routes[0])
	}
	got := edges[0].(map[string]any)
	if got["ok"] != false || got["tcpMs"] != float64(3001) {
		t.Fatalf("timeout was not retained as failed: %+v", got)
	}
}

func TestReusedManualTCPUDPForwardReportsLatency(t *testing.T) {
	l := newRouteLab(t)
	code, manual, _ := l.p.do("POST", "/api/forwards", map[string]any{"serverId": l.t1, "name": "existing", "network": shared.ForwardTCPUDP,
		"port": 53611, "targets": []map[string]any{{"host": "198.51.100.4", "port": 50010}}, "firewallPolicy": "all", "enabled": true}, nil)
	if code != 201 {
		t.Fatalf("manual forward: %d %v", code, manual)
	}
	if code, rt := l.route(map[string]any{"name": "reused", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true,
		"port": 53611, "hops": singleServerHops(l.t1)}); code != 201 {
		t.Fatalf("route: %d %v", code, rt)
	}
	l.applyAll()
	state, err := l.p.app.desired(l.t1)
	if err != nil {
		t.Fatal(err)
	}
	if index := slices.IndexFunc(state.Forwards, func(f shared.ForwardRule) bool { return f.ID == manual["id"] }); index < 0 || state.Forwards[index].RouteID == "" {
		t.Fatalf("Agent cannot tell the reused forward belongs to a route: %+v", state.Forwards)
	}
	point := shared.RouteLatency{ForwardID: manual["id"].(string), Host: "198.51.100.4", Port: 50010, TCPMs: 17, OK: true, At: time.Now()}
	if code, out, _ := l.p.do("POST", "/agent/report", map[string]any{"hostReported": true, "routeLatencies": []shared.RouteLatency{point}}, l.agents[1]); code != 200 {
		t.Fatalf("report: %d %v", code, out)
	}
	route := l.p.list("/api/routes")[0]
	edges, _ := route["edgeLatencies"].([]any)
	if !slices.ContainsFunc(edges, func(edge any) bool {
		item := edge.(map[string]any)
		return item["fromServerId"] == l.t1 && item["tcpMs"] == float64(17)
	}) {
		t.Fatalf("reused TCP + UDP hop has no latency: %+v", route)
	}
}
