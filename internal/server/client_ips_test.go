package server

import (
	"mui/internal/shared"
	"testing"
	"time"
)

func TestEntryClientIPReportsAreScopedAndPeersNotClients(t *testing.T) {
	l := newRouteLab(t)
	p := l.p
	code, rt := l.route(map[string]any{"name": "client route", "entryServerId": l.entry, "nodeId": l.nodeID, "hops": []map[string]any{{"serverIds": []string{l.t1, l.t2}}}, "enabled": true})
	if code != 201 {
		t.Fatal(code, rt)
	}
	id := rt["id"].(string)
	state, err := p.app.desired(l.entry)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Forwards) != 2 || !state.Forwards[0].ObserveClients || state.Forwards[0].ClientNodeID != l.nodeID {
		t.Fatal("entry observation metadata missing")
	}
	middle, err := p.app.desired(l.t1)
	if err != nil || len(middle.Forwards) == 0 || middle.Forwards[0].ObserveClients {
		t.Fatal("middle hop captures clients", err)
	}
	points := []shared.ForwardConnectionPoint{}
	for _, f := range state.Forwards {
		points = append(points, shared.ForwardConnectionPoint{ForwardID: f.ID, RouteID: id, NodeID: l.nodeID, IP: "203.0.113.55", At: time.Now()})
	}
	if code, out, _ := p.do("POST", "/agent/report", map[string]any{"forwardConnections": points}, l.agents[0]); code != 200 {
		t.Fatal(code, out)
	}
	// Same client seen over TCP and UDP is a single route observation.
	rows := p.list("/api/clients/connections?serverId=" + l.entry)
	if len(rows) != 1 || rows[0]["clientIp"] != "203.0.113.55" || rows[0]["routeId"] != id || rows[0]["sourceKind"] != "entry" {
		t.Fatal(rows)
	}
	// A transit or unrelated server cannot claim the entry's client observations.
	points[0].IP = "203.0.113.99"
	if code, out, _ := p.do("POST", "/agent/report", map[string]any{"forwardConnections": points}, l.agents[1]); code != 200 {
		t.Fatal(code, out)
	}
	if got := p.list("/api/clients/connections?serverId=" + l.t1); len(got) != 0 {
		t.Fatal("foreign observations accepted", got)
	}
	points[0].NodeID = ID()
	if err = p.app.saveForwardConnectionIPs(l.entry, points[:1]); err != nil {
		t.Fatal(err)
	}
	if got := p.list("/api/clients/connections?serverId=" + l.entry); len(got) != 1 {
		t.Fatal("foreign node accepted", got)
	}
	if err = p.store.SaveConnectionIPs(l.exit, []shared.ConnectionPoint{{NodeID: l.nodeID, IP: "198.51.100.2"}, {NodeID: l.nodeID, IP: "198.51.100.80"}}); err != nil {
		t.Fatal(err)
	}
	rows = p.list("/api/clients/connections?serverId=" + l.exit)
	if len(rows) != 2 {
		t.Fatal(rows)
	}
	for _, row := range rows {
		if row["clientIp"] != nil {
			t.Fatal("landing peer misrepresented as client", row)
		}
		if row["peerIp"] == nil {
			t.Fatal("missing observed peer", row)
		}
	}
	// Pagination includes route identity; no duplicates or omissions.
	first := p.list("/api/clients/connections?limit=1")
	rest := p.list("/api/clients/connections?limit=5&before=" + first[0]["cursor"].(string))
	if len(rest) != 2 {
		t.Fatal(first, rest)
	}
}

func TestClientIPUpgradeRefreshesExistingEntryConfig(t *testing.T) {
	l := newRouteLab(t)
	code, out := l.route(map[string]any{"name": "old route", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true})
	if code != 201 {
		t.Fatal(code, out)
	}
	l.applyAll()
	// Simulate a stored route forward created before observation metadata.
	for _, f := range l.forwards(l.entry) {
		f.ObserveClients = false
		f.ClientNodeID = ""
		if err := l.p.store.PutForward(f); err != nil {
			t.Fatal(err)
		}
	}
	report := map[string]any{"agentVersion": "0.6.13", "forwardSupport": true, "forwardTcpUdp": true, "nodeFirewallPolicies": true, "multiUserStats": true, "shadowTlsAuth": true, "snellFixedPort": true, "snellV6": true, "manualFirewallSupport": true, "ufwStatus": "active"}
	if code, out, _ := l.p.do("POST", "/agent/report", report, l.agents[0]); code != 200 {
		t.Fatal(code, out)
	}
	code, job, _ := l.p.do("GET", "/agent/job", nil, l.agents[0])
	if code != 200 {
		t.Fatal("upgrade did not refresh entry", code, job)
	}
	for _, raw := range job["state"].(map[string]any)["forwards"].([]any) {
		f := raw.(map[string]any)
		if f["observeClients"] != true || f["clientNodeId"] != l.nodeID {
			t.Fatal("metadata missing from upgrade apply", f)
		}
	}
}

// Client observation is added to the entry's job, not stored on the route
// forward: storing it would rewrite every existing route forward (and bump
// every hop's revision, offline exports included) on a panel upgrade.
func TestRouteForwardObservationIsNotStored(t *testing.T) {
	l := newRouteLab(t)
	code, rt := l.route(map[string]any{"name": "observe", "entryServerId": l.entry, "nodeId": l.nodeID, "hops": []map[string]any{{"serverIds": []string{l.t1}}}, "enabled": true})
	if code != 201 {
		t.Fatal(code, rt)
	}
	l.applyAll()
	forwards, err := l.p.store.Forwards(l.entry)
	if err != nil || len(forwards) == 0 {
		t.Fatal(forwards, err)
	}
	for _, f := range forwards {
		if f.ObserveClients || f.ClientNodeID != "" {
			t.Fatal("observation stored on route forward", f)
		}
	}
	before := map[string]int64{}
	for _, id := range []string{l.entry, l.t1, l.exit} {
		s, _ := l.p.store.Server(id)
		before[id] = s.Revision
	}
	if err := l.p.app.syncRoutes(); err != nil {
		t.Fatal(err)
	}
	for id, rev := range before {
		if s, _ := l.p.store.Server(id); s.Revision != rev {
			t.Fatal("unchanged routes bumped a revision", id)
		}
	}
	state, err := l.p.app.desired(l.entry)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range state.Forwards {
		if f.RouteID == rt["id"] && (!f.ObserveClients || f.ClientNodeID != l.nodeID) {
			t.Fatal("entry job does not observe clients", f)
		}
	}
	state, _ = l.p.app.desired(l.t1)
	for _, f := range state.Forwards {
		if f.ObserveClients {
			t.Fatal("middle hop observes relayed addresses", f)
		}
	}
}
