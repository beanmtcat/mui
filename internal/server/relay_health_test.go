package server

import (
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"mui/internal/shared"
)

func (l *routeLab) relayRoute(t *testing.T, name string, targets ...string) string {
	t.Helper()
	code, out := l.route(map[string]any{"name": name, "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true,
		"hops": []map[string]any{{"serverIds": targets, "balance": "round-robin"}}})
	if code != http.StatusCreated {
		t.Fatalf("route: %d %v", code, out)
	}
	return out["id"].(string)
}

func (l *routeLab) upgradeRelayAgent(t *testing.T) {
	t.Helper()
	if code, out, _ := l.p.do("POST", "/agent/report", map[string]any{
		"agentVersion": shared.RelayHealthVersion, "forwardSupport": true, "forwardTcpUdp": true, "multiUserStats": true,
		"manualFirewallSupport": true, "nodeFirewallPolicies": true,
	}, l.agents[0]); code != 200 {
		t.Fatalf("report: %d %v", code, out)
	}
}

func TestRelayOverridePrecedenceExpiryAndDownValidation(t *testing.T) {
	l := newRouteLab(t)
	l.relayRoute(t, "balanced", l.t1, l.t2)
	p := l.p
	api := func(from, to, state string, until *time.Time, want int) {
		t.Helper()
		code, out, _ := p.do("PUT", "/api/relay-overrides", shared.RelayOverride{FromServerID: from, ToServerID: to, State: state, Until: until}, nil)
		if code != want || code == 400 && (state == shared.RelayDown && !strings.Contains(out["error"].(string), "balanced")) {
			t.Fatalf("set %q to %q: %d %v, want %d", from, to, code, out, want)
		}
	}
	assertDesired := func(want string) {
		t.Helper()
		state, err := p.app.desired(l.entry)
		if err != nil {
			t.Fatal(err)
		}
		if len(state.Forwards) != 2 {
			t.Fatalf("entry forwards: %+v", state.Forwards)
		}
		for _, f := range state.Forwards {
			if f.Targets[0].ServerID != l.t1 || f.Targets[0].Override != want {
				t.Fatalf("wrong metadata: %+v, want %q", f.Targets[0], want)
			}
		}
	}

	api("", l.t1, shared.RelayDown, nil, 200)
	state, err := p.app.desired(l.entry)
	if err != nil || state.Forwards[0].Targets[0].ServerID != "" {
		t.Fatalf("old Agent given relay metadata: %+v %v", state.Forwards, err)
	}
	l.upgradeRelayAgent(t)
	assertDesired(shared.RelayDown)
	api(l.entry, l.t2, shared.RelayDown, nil, 400)
	until := time.Now().Add(time.Hour)
	api(l.entry, l.t1, shared.RelayNormal, &until, 200)
	assertDesired(shared.RelayNormal)
	// At expiry this would expose the permanent server-level down again.
	api(l.entry, l.t2, shared.RelayDown, nil, 400)

	now := time.Now()
	if _, err = p.store.DB.Exec(`UPDATE mui_relay_overrides SET until_ms=$1 WHERE from_server_id=$2`, now.Add(-time.Second).UnixMilli(), l.entry); err != nil {
		t.Fatal(err)
	}
	before, _ := p.store.Server(l.entry)
	otherBefore, _ := p.store.Server(l.t1)
	if err = p.app.ExpireRelayOverrides(); err != nil {
		t.Fatal(err)
	}
	after, _ := p.store.Server(l.entry)
	otherAfter, _ := p.store.Server(l.t1)
	overrides, err := p.store.relayOverrides()
	if err != nil || len(overrides) != 1 || after.Revision != before.Revision+1 || otherAfter.Revision != otherBefore.Revision {
		t.Fatalf("expiry state %v, source revision %d → %d, other %d → %d, error %v", overrides, before.Revision, after.Revision, otherBefore.Revision, otherAfter.Revision, err)
	}
	assertDesired(shared.RelayDown)
	for _, rule := range l.forwards(l.entry) {
		if rule.Targets[0].ServerID != "" || rule.Targets[0].Override != "" {
			t.Fatalf("runtime metadata leaked into stored rule: %+v", rule)
		}
	}
	api(l.t1, l.exit, shared.RelayDown, nil, 400)
}

func TestRelayOverrideRejectsRemovingLastCandidateAndEnablingBlockedHop(t *testing.T) {
	l := newRouteLab(t)
	id := l.relayRoute(t, "balanced", l.t1, l.t2)
	p := l.p
	for _, override := range []shared.RelayOverride{
		{FromServerID: l.entry, ToServerID: l.t1, State: shared.RelayNormal},
		{ToServerID: l.t1, State: shared.RelayDown},
		{ToServerID: l.t2, State: shared.RelayDown},
	} {
		if code, out, _ := p.do("PUT", "/api/relay-overrides", override, nil); code != 200 {
			t.Fatalf("set: %d %v", code, out)
		}
	}
	if code, out, _ := p.do("DELETE", "/api/relay-overrides?from="+l.entry+"&to="+l.t1, nil, nil); code != 400 {
		t.Fatalf("clear must not expose an all-down group: %d %v", code, out)
	}
	if code, out, _ := p.do("PATCH", "/api/routes/"+id, map[string]any{
		"name": "balanced", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true,
		"hops": []map[string]any{{"serverIds": []string{l.t2}}},
	}, nil); code != 400 {
		t.Fatalf("edit must not create a single down target: %d %v", code, out)
	}
	if code, out, _ := p.do("PUT", "/api/relay-overrides", shared.RelayOverride{
		FromServerID: l.exit, ToServerID: l.t2, State: shared.RelayDegraded,
	}, nil); code != 400 {
		t.Fatalf("unrelated line accepted: %d %v", code, out)
	}
}

func TestRelayReportRequiresAssignedForwardAndExactTarget(t *testing.T) {
	l := newRouteLab(t)
	l.relayRoute(t, "balanced", l.t1, l.t2)
	l.upgradeRelayAgent(t)
	l.applyAll()
	f := l.forwards(l.entry)[0]
	for _, candidate := range l.forwards(l.entry) {
		if candidate.Network == "tcp" {
			f = candidate
		}
	}
	point := shared.RelayState{ForwardID: f.ID, ServerID: l.t1, Host: f.Targets[0].Host, Port: f.Targets[0].Port,
		State: shared.RelayDegraded, Source: "manual", AutoState: shared.RelayDown, Reason: "manual", Since: time.Now()}
	forged, wrongTarget, wrongID, overlong := point, point, point, point
	forged.ForwardID = "other"
	wrongTarget.Host = "bad.example"
	wrongID.ServerID = l.t2
	overlong.Reason = strings.Repeat("x", 300)
	points := []shared.RelayState{forged, wrongTarget, wrongID, overlong, point}
	if code, out, _ := l.p.do("POST", "/agent/report", map[string]any{"relayStates": points}, l.agents[0]); code != 200 {
		t.Fatalf("report: %d %v", code, out)
	}
	server, err := l.p.store.Server(l.entry)
	if err != nil || len(server.RelayStates) != 1 || server.RelayStates[0].ServerID != l.t1 {
		t.Fatalf("accepted states = %+v, err %v", server.RelayStates, err)
	}
	world, _ := l.p.app.loadRouteWorld()
	edges := routeRelayEdges(world.routes[0], world, nil, time.Now(), downstreamTopology{})
	index := slices.IndexFunc(edges, func(edge shared.RelayEdge) bool { return edge.FromServerID == l.entry && edge.ToServerID == l.t1 })
	if index < 0 || edges[index].Reported == nil || edges[index].Reported.AutoState != shared.RelayDown {
		t.Fatalf("reported state missing from route edge: %+v", edges)
	}
}

func TestRelayTelegramGroupsFailuresAndSummarizesFlapping(t *testing.T) {
	l := newRouteLab(t)
	l.relayRoute(t, "balanced", l.t1, l.t2)
	l.upgradeRelayAgent(t)
	tg := newMockTelegram(t)
	configureTelegramForTest(t, l.p, tg.srv.URL, nil)
	if code, out, _ := l.p.do("PUT", "/api/relay-overrides", shared.RelayOverride{
		FromServerID: l.entry, ToServerID: l.t1, State: shared.RelayDegraded,
	}, nil); code != 200 {
		t.Fatalf("set: %d %v", code, out)
	}
	if !l.p.app.FlushTelegramForTest(2 * time.Second) {
		t.Fatal("flush timed out")
	}
	if calls := tg.takeCalls(); len(calls) != 1 || !strings.Contains(calls[0].Body["text"].(string), "永久") {
		t.Fatalf("manual notice: %+v", calls)
	}
	for _, note := range []string{"只改备注", "只改备注"} {
		if code, out, _ := l.p.do("PUT", "/api/relay-overrides", shared.RelayOverride{
			FromServerID: l.entry, ToServerID: l.t1, State: shared.RelayDegraded, Note: note,
		}, nil); code != 200 {
			t.Fatalf("set: %d %v", code, out)
		}
	}
	if !l.p.app.FlushTelegramForTest(2*time.Second) || len(tg.takeCalls()) != 0 {
		t.Fatal("note-only edit or identical save sent an alert")
	}
	now := time.Now()
	entry, err := l.p.store.Server(l.entry)
	if err != nil {
		t.Fatal(err)
	}
	l.p.app.recordRelayChanges(entry, []relayAutoChange{{l.t1, shared.RelayDown, ""}, {l.t2, shared.RelayDown, ""}}, now)
	l.p.app.recordRelayChanges(entry, []relayAutoChange{{l.t1, shared.RelayNormal, ""}}, now.Add(time.Minute))
	l.p.app.recordRelayChanges(entry, []relayAutoChange{{l.t1, shared.RelayDown, ""}}, now.Add(2*time.Minute))
	l.p.app.FlushRelayAlerts(now.Add(11 * time.Minute))
	if !l.p.app.FlushTelegramForTest(2 * time.Second) {
		t.Fatal("flush timed out")
	}
	calls := tg.takeCalls()
	if len(calls) != 2 || !strings.Contains(calls[0].Body["text"].(string), "t1、t2") ||
		!strings.Contains(calls[1].Body["text"].(string), "10 分钟内切换 3 次") {
		t.Fatalf("automatic notices: %+v", calls)
	}
}

func TestRelayQualityReportsValidateStatsAndPreserveAutoReason(t *testing.T) {
	now := time.Now()
	point := shared.RelayState{ForwardID: "r", ServerID: "t", Host: "203.0.113.1", Port: 50000,
		State: shared.RelayNormal, Source: "manual", AutoState: shared.RelayDegraded,
		Reason: "manual", AutoReason: "blackhole", Since: now, AutoSince: &now,
		Stats: &shared.RelayStats{ProbeSuccesses: 11, MedianMS: 90, BaselineMS: 24, PassiveBadPercent: 70, PassiveSamples: 22}}
	allowed := map[relayPointKey]bool{relayKey(point): true}
	bad := point
	bad.Stats = &shared.RelayStats{ProbeSuccesses: 13, PassiveSamples: 513}
	points, changes := mergeRelaySamples(nil, []shared.RelayState{bad, point}, allowed, now)
	if len(points) != 1 || points[0].State != shared.RelayNormal || points[0].Stats.PassiveSamples != 22 ||
		len(changes) != 1 || changes[0].state != shared.RelayDegraded || changes[0].reason != "blackhole" {
		t.Fatalf("points %+v, changes %+v", points, changes)
	}
	probation := point
	probation.State, probation.Source, probation.AutoState = shared.RelayProbation, "auto", shared.RelayProbation
	probation.Reason, probation.AutoReason = "recovering", ""
	points, changes = mergeRelaySamples(points, []shared.RelayState{probation}, allowed, now)
	if len(points) != 1 || points[0].State != shared.RelayProbation || len(changes) != 1 || changes[0].state != shared.RelayProbation {
		t.Fatalf("probation: points %+v, changes %+v", points, changes)
	}
}
