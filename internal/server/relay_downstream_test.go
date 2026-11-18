package server

import (
	"slices"
	"testing"
	"time"

	"mui/internal/shared"
)

func TestRelayDownstreamReportsQueueOnlyPreviousHop(t *testing.T) {
	l := newRouteLab(t)
	p := l.p
	next, nextAgent := p.enrollAs("next", []string{"transit"}, map[string]any{"ipv4": "198.51.100.5"})
	l.agents = append(l.agents, nextAgent)
	for _, agent := range l.agents[:2] {
		if code, out, _ := p.do("POST", "/agent/report", map[string]any{
			"agentVersion": shared.RelayHealthVersion, "forwardSupport": true, "forwardTcpUdp": true,
			"multiUserStats": true, "manualFirewallSupport": true, "nodeFirewallPolicies": true,
		}, agent); code != 200 {
			t.Fatalf("upgrade: %d %v", code, out)
		}
	}
	code, out := l.route(map[string]any{"name": "two downstream targets", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true, "port": 50501,
		"hops": []map[string]any{{"serverIds": []string{l.t1}}, {"serverIds": []string{l.t2, next}, "balance": "round-robin"}}})
	if code != 201 {
		t.Fatalf("route: %d %v", code, out)
	}
	routeID := out["id"].(string)
	code, out = l.route(map[string]any{"name": "independent path via same relay", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true, "port": 50502,
		"hops": []map[string]any{{"serverIds": []string{l.t1}}}})
	if code != 201 {
		t.Fatalf("second route: %d %v", code, out)
	}
	l.applyAll()

	f, err := p.store.Forward(routeForwardID(routeID, l.t1, "tcp"))
	if err != nil || len(f.Targets) != 2 {
		t.Fatalf("relay TCP rule: %+v %v", f, err)
	}
	downA := shared.RelayState{ForwardID: f.ID, ServerID: l.t2, Host: f.Targets[0].Host, Port: f.Targets[0].Port, State: "down", Source: "auto", AutoState: "down", Reason: "dial_failed"}
	downB := shared.RelayState{ForwardID: f.ID, ServerID: next, Host: f.Targets[1].Host, Port: f.Targets[1].Port, State: "down", Source: "manual", AutoState: "normal", Reason: "manual"}
	upA, upB := downA, downB
	upA.State, upA.Source, upA.AutoState, upA.Reason = "normal", "auto", "normal", "healthy"
	upB.State, upB.Source, upB.AutoState, upB.Reason = "normal", "auto", "normal", "healthy"
	report := func(points ...shared.RelayState) {
		t.Helper()
		for i := range points {
			points[i].Since = time.Now()
		}
		if code, out, _ := p.do("POST", "/agent/report", map[string]any{"relayStates": points}, l.agents[1]); code != 200 {
			t.Fatalf("report: %d %v", code, out)
		}
	}
	check := func(want string) {
		t.Helper()
		state, err := p.app.desired(l.entry)
		if err != nil {
			t.Fatal(err)
		}
		if len(state.Forwards) != 4 {
			t.Fatalf("entry forwards: %+v", state.Forwards)
		}
		for _, rule := range state.Forwards {
			expected := ""
			if rule.Port == 50501 {
				expected = want
			}
			if rule.Targets[0].ServerID != l.t1 || rule.Targets[0].Downstream != expected {
				t.Fatalf("port %d desired %+v, want downstream %q", rule.Port, rule.Targets, expected)
			}
		}
	}
	entryBefore, _ := p.store.Server(l.entry)
	relayBefore, _ := p.store.Server(l.t1)
	report(downA)
	report(downA)
	check("")
	report(downB) // Complete one all-down round across report batches.
	check("")
	report(downA, downB)
	check(shared.RelayDown)
	entryAfter, _ := p.store.Server(l.entry)
	relayAfter, _ := p.store.Server(l.t1)
	if entryAfter.Revision != entryBefore.Revision+1 || relayAfter.Revision != relayBefore.Revision {
		t.Fatalf("revisions entry %d → %d, reporter %d → %d", entryBefore.Revision, entryAfter.Revision, relayBefore.Revision, relayAfter.Revision)
	}
	if code, job, _ := p.do("GET", "/agent/job", nil, l.agents[0]); code != 200 || job["kind"] != "forwards.apply" {
		t.Fatalf("signed apply not queued for previous hop: %d %v", code, job)
	} else if state, ok := job["state"].(map[string]any); !ok || state["signature"] == "" || state["signature"] == nil {
		t.Fatal("downstream apply was not signed")
	}
	report(upA, downB)
	report(downA, upB)
	check(shared.RelayDown) // Different targets cannot confirm recovery.
	report(downA, upB)
	check("")
	entryRecovered, _ := p.store.Server(l.entry)
	if entryRecovered.Revision != entryBefore.Revision+2 {
		t.Fatalf("recovery queued %d extra revisions, want 1", entryRecovered.Revision-entryAfter.Revision)
	}

	report(downA, downB)
	report(downA, downB)
	check(shared.RelayDown)
	if code, out, _ := p.do("POST", "/agent/report", map[string]any{"agentVersion": "0.6.31"}, l.agents[1]); code != 200 {
		t.Fatalf("older agent: %d %v", code, out)
	}
	check("")
}

func TestRelayDownstreamSlidingRateLimitAndRouteIndicator(t *testing.T) {
	now := time.Now()
	point := relayPointKey{forward: "forward", server: "next", host: "192.0.2.1", port: 443}
	group := downstreamGroup{keys: []relayPointKey{point}}
	var status shared.RelayDownstreamStatus
	tick := func(after time.Duration, state string) bool {
		return observeDownstream(&status, group, map[relayPointKey]string{point: state}, now.Add(after))
	}
	for i := range 6 {
		at := time.Duration(i) * 3 * time.Second
		state := shared.RelayDown
		if i%2 == 1 {
			state = shared.RelayNormal
		}
		if tick(at, state) || !tick(at+time.Second, state) || status.Down != (state == shared.RelayDown) {
			t.Fatalf("transition %d did not require two reports: %+v", i, status)
		}
	}
	if tick(time.Minute, shared.RelayDown) || tick(time.Minute+time.Second, shared.RelayDown) || status.Down ||
		status.FlappingUntil == nil || !status.FlappingUntil.Equal(now.Add(10*time.Minute+time.Second)) || len(status.Changes) != 6 {
		t.Fatalf("unexpected throttled state: %+v", status)
	}

	rt := shared.Route{ID: "route", Enabled: true, EntryServerID: "entry", Hops: []shared.RouteHop{{ServerIDs: []string{"relay"}}}, NodeID: "node"}
	world := routeWorld{
		servers: map[string]shared.Server{
			"entry": {ID: "entry"},
			"relay": {ID: "relay", AgentVersion: shared.RelayHealthVersion, RelayDownstream: map[string]shared.RelayDownstreamStatus{"key": status}},
			"exit":  {ID: "exit"},
		},
		nodes: map[string]shared.Node{"node": {ID: "node", ServerID: "exit"}},
	}
	index := downstreamTopology{routes: map[downstreamRouteKey]string{{"route", "relay"}: "key"}}
	edges := routeRelayEdges(rt, world, nil, now.Add(2*time.Minute), index)
	pos := slices.IndexFunc(edges, func(edge shared.RelayEdge) bool { return edge.ToServerID == "relay" && edge.DownstreamFlapping })
	if pos < 0 {
		t.Fatalf("no flapping indicator in route view: %+v", edges)
	}
	if tick(10*time.Minute+time.Second, shared.RelayDown) || !tick(10*time.Minute+2*time.Second, shared.RelayDown) || !status.Down ||
		status.FlappingUntil != nil || len(status.Changes) != 6 {
		t.Fatalf("rate limit did not reopen after earliest change aged out: %+v", status)
	}
}

func TestRelayDownstreamSharedListenerNeedsAllMemberPathsDown(t *testing.T) {
	w := routeWorld{
		servers: map[string]shared.Server{"relay": {ID: "relay", AgentVersion: shared.RelayHealthVersion,
			RelayDownstream: map[string]shared.RelayDownstreamStatus{"down": {Down: true}, "healthy": {Down: false}}}},
		routes: []shared.Route{{ID: "a", Enabled: true}, {ID: "b", Enabled: true}},
	}
	rule := shared.ForwardRule{RouteID: "a", RouteIDs: []string{"a", "b"}, Targets: []shared.ForwardTarget{{ServerID: "relay"}}}
	index := downstreamTopology{routes: map[downstreamRouteKey]string{{"a", "relay"}: "down", {"b", "relay"}: "healthy"}}
	w.assignRelayDownstream(&rule, index)
	if got := rule.Targets[0].Downstream; got != "" {
		t.Fatalf("one failing member poisoned the shared listener: %q", got)
	}
	index.routes[downstreamRouteKey{"b", "relay"}] = "down"
	w.assignRelayDownstream(&rule, index)
	if got := rule.Targets[0].Downstream; got != shared.RelayDown {
		t.Fatalf("agreed failure was not applied: %q", got)
	}
}

func TestRelayDownstreamPartialReportDoesNotReuseStaleFailures(t *testing.T) {
	now := time.Now()
	a, b := relayPointKey{server: "a"}, relayPointKey{server: "b"}
	group := downstreamGroup{keys: []relayPointKey{a, b}}
	var status shared.RelayDownstreamStatus
	observeDownstream(&status, group, map[relayPointKey]string{a: shared.RelayDown}, now)
	observeDownstream(&status, group, map[relayPointKey]string{a: shared.RelayDown}, now.Add(time.Minute))
	observeDownstream(&status, group, map[relayPointKey]string{b: shared.RelayDown}, now.Add(3*time.Minute))
	if status.LastAllDownAt != nil {
		t.Fatal("stale partial sample became a complete failure round")
	}
	if observeDownstream(&status, group, map[relayPointKey]string{a: shared.RelayDown, b: shared.RelayDown}, now.Add(3*time.Minute+time.Second)) {
		t.Fatal("one fresh all-down round was enough to propagate")
	}
}
