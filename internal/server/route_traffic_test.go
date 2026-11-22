package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"mui/internal/shared"
)

func TestRouteTrafficQuotaAndEntryProtectionPanelWorkflow(t *testing.T) {
	p := newTestMui(t)
	app := p.app
	now := time.Now().UTC()

	// Create entry (new agent), old-entry (legacy agent), transit, and exit servers.
	entry := shared.Server{
		ID: "srv-entry", Name: "entry-hk", Roles: []string{shared.RoleEntry}, Country: "HK",
		IPv4: "203.0.113.10", Status: "online", UFWStatus: "active",
		ForwardSupport: true, ForwardTCPUDP: true, ForwardTrafficLimitSupport: true,
		TrafficLimit: 100 << 30, TrafficLimitType: "sum", TrafficResetDay: 1,
		TrafficProtectionEnabled: true, TrafficProtectionThreshold: 95,
		LastSeen: &now, Revision: 1,
	}
	oldEntry := shared.Server{
		ID: "srv-old", Name: "entry-old", Roles: []string{shared.RoleEntry}, Country: "HK",
		IPv4: "203.0.113.11", Status: "online", UFWStatus: "active",
		ForwardSupport: true, ForwardTCPUDP: true, ForwardTrafficLimitSupport: false,
		LastSeen: &now, Revision: 1,
	}
	transit := shared.Server{
		ID: "srv-mid", Name: "mid-jp", Roles: []string{shared.RoleTransit}, Country: "JP",
		IPv4: "203.0.113.20", Status: "online", UFWStatus: "active",
		ForwardSupport: true, ForwardTCPUDP: true, ForwardTrafficLimitSupport: true,
		LastSeen: &now, Revision: 1,
	}
	exit := shared.Server{
		ID: "srv-exit", Name: "exit-us", Roles: []string{shared.RoleExit}, Country: "US",
		IPv4: "203.0.113.30", Status: "online", UFWStatus: "active",
		ForwardSupport: true, ForwardTCPUDP: true, ForwardTrafficLimitSupport: true,
		LastSeen: &now, Revision: 1,
	}
	for _, s := range []shared.Server{entry, oldEntry, transit, exit} {
		if _, err := app.Store.DB.Exec(`INSERT INTO mui_servers(id,data) VALUES($1,$2)`, s.ID, Marshal(s)); err != nil {
			t.Fatalf("insert server %s: %v", s.ID, err)
		}
	}
	node := shared.Node{
		ID: "node-exit", ServerID: exit.ID, Name: "us-ss", Protocol: "ss",
		Port: 8388, Listen: "0.0.0.0", Method: "2022-blake3-aes-128-gcm",
		FirewallPolicy: "restricted", Enabled: true, Status: "active",
	}
	if err := app.Store.PutNode(node, "test-password-123456"); err != nil {
		t.Fatalf("PutNode: %v", err)
	}

	// Route A and Route B share transit & exit, each with independent entry metering.
	meteringStart := now.Add(time.Minute) // mid-cycle metering start -> HasHistoricalGap
	routeA := shared.Route{
		ID: "rt-a", Name: "user-a", EntryServerID: entry.ID,
		Hops: []shared.RouteHop{{ServerIDs: []string{transit.ID}, Balance: "failover"}},
		NodeID: node.ID, Port: 20001, Enabled: true,
		TrafficLimit: 10 << 30, TrafficLimitType: "sum", TrafficResetDay: 1,
		UpSpeedLimitMbps: 20, DownSpeedLimitMbps: 50,
		TrafficMeteringStartedAt: &meteringStart,
	}
	routeB := shared.Route{
		ID: "rt-b", Name: "user-b", EntryServerID: entry.ID,
		Hops: []shared.RouteHop{{ServerIDs: []string{transit.ID}, Balance: "failover"}},
		NodeID: node.ID, Port: 20002, Enabled: true,
		TrafficLimit: 20 << 30, TrafficLimitType: "down", TrafficResetDay: 1,
	}
	// Route C on legacy Agent without ForwardTrafficLimitSupport.
	routeOld := shared.Route{
		ID: "rt-old", Name: "user-old", EntryServerID: oldEntry.ID,
		NodeID: node.ID, Port: 20003, Enabled: true,
		TrafficLimit: 5 << 30, TrafficLimitType: "sum",
	}
	// Route D manually disabled.
	routeDisabled := shared.Route{
		ID: "rt-dis", Name: "user-disabled", EntryServerID: entry.ID,
		NodeID: node.ID, Port: 20004, Enabled: false,
		TrafficLimit: 5 << 30, TrafficLimitType: "sum",
	}
	for _, rt := range []shared.Route{routeA, routeB, routeOld, routeDisabled} {
		if err := app.Store.PutRoute(rt); err != nil {
			t.Fatalf("PutRoute %s: %v", rt.ID, err)
		}
	}
	if err := app.syncRoutes(); err != nil {
		t.Fatalf("syncRoutes: %v", err)
	}

	// 1. Verify desired() attaches limits ONLY on entry hop, never on middle hop!
	entryDesired, err := app.desired(entry.ID)
	if err != nil {
		t.Fatalf("desired(entry): %v", err)
	}
	if entryDesired.EntryTrafficProtection == nil || !entryDesired.EntryTrafficProtection.Enabled || entryDesired.EntryTrafficProtection.ThresholdPercent != 95 {
		t.Fatalf("expected EntryTrafficProtection policy on entry desired state, got %+v", entryDesired.EntryTrafficProtection)
	}
	foundEntryA := false
	for _, f := range entryDesired.Forwards {
		if f.RouteID == routeA.ID {
			foundEntryA = true
			if !f.EntryHop || f.RouteTrafficLimit != routeA.TrafficLimit || f.RouteUpSpeedLimitBps != shared.MbpsToBytesPerSec(20) || f.RouteDownSpeedLimitBps != shared.MbpsToBytesPerSec(50) {
				t.Fatalf("entry forward missing route limits: %+v", f)
			}
		}
	}
	if !foundEntryA {
		t.Fatalf("expected entry forward for route A")
	}

	midDesired, err := app.desired(transit.ID)
	if err != nil {
		t.Fatalf("desired(transit): %v", err)
	}
	for _, f := range midDesired.Forwards {
		if f.EntryHop || f.RouteTrafficLimit != 0 || f.RouteUpSpeedLimitBps != 0 || f.RouteDownSpeedLimitBps != 0 {
			t.Fatalf("middle hop must NOT carry entry route limits: %+v", f)
		}
	}

	// 2. Duplicate reports & non-entry server ownership rejection.
	loc := app.Store.timeLocation()
	start, end := shared.MonthlyCycleBounds(now, 1, loc)
	report := []shared.RouteTrafficState{
		{
			RouteID: routeA.ID, CycleStartMs: start.UTC().UnixMilli(), CycleEndMs: end.UTC().UnixMilli(),
			Uplink: 4 << 30, Downlink: 6 << 30, Used: 10 << 30, Limit: routeA.TrafficLimit,
			LimitType: "sum", Paused: true, UpdatedAt: now,
		},
		{
			RouteID: routeB.ID, CycleStartMs: start.UTC().UnixMilli(), CycleEndMs: end.UTC().UnixMilli(),
			Uplink: 1 << 30, Downlink: 2 << 30, Used: 2 << 30, Limit: routeB.TrafficLimit,
			LimitType: "down", Paused: false, UpdatedAt: now,
		},
	}
	// Transit server attempting to report Route A traffic must be ignored!
	if err := app.Store.SaveRouteTrafficStates(transit.ID, report); err != nil {
		t.Fatalf("SaveRouteTrafficStates(transit): %v", err)
	}
	srvMap := map[string]shared.Server{entry.ID: entry, oldEntry.ID: oldEntry, transit.ID: transit, exit.ID: exit}
	cm0, _ := app.Store.RouteCycleTrafficMap([]shared.Route{routeA}, srvMap, now)
	if cm0[routeA.ID].Used != 0 {
		t.Fatalf("non-entry server report should be ignored, got used=%d", cm0[routeA.ID].Used)
	}

	// Entry server reports twice (duplicate report) -> must not double-count!
	if err := app.Store.SaveRouteTrafficStates(entry.ID, report); err != nil {
		t.Fatalf("SaveRouteTrafficStates 1: %v", err)
	}
	if err := app.Store.SaveRouteTrafficStates(entry.ID, report); err != nil {
		t.Fatalf("SaveRouteTrafficStates 2: %v", err)
	}
	cm, err := app.Store.RouteCycleTrafficMap([]shared.Route{routeA, routeB}, srvMap, now)
	if err != nil {
		t.Fatalf("RouteCycleTrafficMap: %v", err)
	}
	if cm[routeA.ID].Used != 10<<30 || !cm[routeA.ID].AutoPaused || cm[routeA.ID].PauseReason != "route_quota" || !cm[routeA.ID].HasHistoricalGap {
		t.Fatalf("unexpected routeA cycle summary: %+v", cm[routeA.ID])
	}
	if cm[routeB.ID].Used != 2<<30 || cm[routeB.ID].AutoPaused {
		t.Fatalf("unexpected routeB cycle summary (must be independent of routeA): %+v", cm[routeB.ID])
	}

	// 3. Mark forwards active and check GET /api/routes statuses:
	// routeA -> quota_exceeded, routeOld -> upgrade_required, routeDisabled -> disabled.
	forwards, _ := app.Store.Forwards("")
	for _, f := range forwards {
		f.Status = "active"
		_ = app.Store.PutForward(f)
	}
	_ = app.Store.SetAppliedDeployment(exit.ID, map[string]shared.NodeDeployment{
		node.ID: {FirewallPolicy: "all"},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/routes", nil)
	rec := httptest.NewRecorder()
	app.routes(rec, req)
	if rec.Code != 200 {
		t.Fatalf("GET /api/routes status=%d body=%s", rec.Code, rec.Body.String())
	}
	var listed []shared.Route
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode routes: %v", err)
	}
	byID := map[string]shared.Route{}
	for _, rt := range listed {
		byID[rt.ID] = rt
	}
	if byID[routeA.ID].Status != "quota_exceeded" {
		t.Fatalf("expected routeA status quota_exceeded, got %q", byID[routeA.ID].Status)
	}
	if byID[routeB.ID].Status != "active" {
		t.Fatalf("expected routeB status active, got %q", byID[routeB.ID].Status)
	}
	if byID[routeOld.ID].Status != "upgrade_required" || byID[routeOld.ID].EnforcementCapability != "upgrade_required" {
		t.Fatalf("expected routeOld status upgrade_required, got status=%q cap=%q", byID[routeOld.ID].Status, byID[routeOld.ID].EnforcementCapability)
	}
	if byID[routeDisabled.ID].Status != "disabled" {
		t.Fatalf("expected routeDisabled status disabled, got %q", byID[routeDisabled.ID].Status)
	}

	// 4. Trigger entry total traffic protection (96 GiB >= 95% of 100 GiB) -> routeB becomes entry_protected, routeDisabled stays disabled!
	if err := app.Store.SaveServerTraffic(entry.ID, []shared.ServerTrafficPoint{
		{BootID: "boot-1", Interface: "eth0", Sequence: 1, Rx: 48 << 30, Tx: 48 << 30, At: now},
	}); err != nil {
		t.Fatalf("SaveServerTraffic: %v", err)
	}
	sMap, _ := app.Store.CycleTrafficMap([]shared.Server{entry}, now)
	reconcileServerEntryProtection(&entry, []shared.Route{routeA, routeB, routeDisabled}, sMap[entry.ID], nil, now, loc)
	if entry.TrafficProtectionState == nil || !entry.TrafficProtectionState.Active {
		t.Fatalf("expected entry protection active at 96 GiB / 95 GiB threshold, got %+v", entry.TrafficProtectionState)
	}
	_ = app.Store.PutServer(entry)

	rec2 := httptest.NewRecorder()
	app.routes(rec2, httptest.NewRequest(http.MethodGet, "/api/routes", nil))
	var listed2 []shared.Route
	_ = json.Unmarshal(rec2.Body.Bytes(), &listed2)
	byID2 := map[string]shared.Route{}
	for _, rt := range listed2 {
		byID2[rt.ID] = rt
	}
	if byID2[routeB.ID].Status != "entry_protected" {
		t.Fatalf("expected routeB status entry_protected, got %q", byID2[routeB.ID].Status)
	}
	if byID2[routeDisabled.ID].Status != "disabled" {
		t.Fatalf("manual disable must stay disabled under entry protection, got %q", byID2[routeDisabled.ID].Status)
	}

	// 5. Legacy config defaults: unmarshaling JSON without new fields keeps unlimited / protection OFF.
	var legacyRoute shared.Route
	_ = json.Unmarshal([]byte(`{"id":"legacy","name":"old","entryServerId":"srv-entry","nodeId":"node-exit","port":10000,"enabled":true}`), &legacyRoute)
	if legacyRoute.TrafficLimit != 0 || legacyRoute.UpSpeedLimitMbps != 0 || legacyRoute.DownSpeedLimitMbps != 0 {
		t.Fatalf("legacy route should default to unlimited, got %+v", legacyRoute)
	}
	var legacyServer shared.Server
	_ = json.Unmarshal([]byte(`{"id":"legacy-srv","name":"old","trafficLimit":1073741824}`), &legacyServer)
	if legacyServer.TrafficProtectionEnabled {
		t.Fatalf("legacy server should default to entry protection OFF")
	}

	// 6. Per-cycle deduplicated route & entry-protection alerts.
	sink := setupTelegramRecorder(t, p, map[string]any{
		"trafficLimit": map[string]any{"enabled": true, "threshold": 80},
	})
	states, _ := app.Store.loadAlertStates()
	app.evaluateRouteAndEntryProtectionAlerts(now, TelegramThresholdEvent{Enabled: true, Threshold: 80}, []shared.Server{entry}, states)
	_ = app.FlushTelegramForTest(2 * time.Second)
	msgs := sink.take()
	if len(msgs) < 2 {
		t.Fatalf("expected route-paused and entry-protection alerts, got %d: %v", len(msgs), msgs)
	}
	hasRoutePaused := false
	hasEntryProt := false
	for _, msg := range msgs {
		if strings.Contains(msg, "链路达到流量配额已暂停") {
			hasRoutePaused = true
		}
		if strings.Contains(msg, "入口机总流量保护已触发") {
			hasEntryProt = true
		}
	}
	if !hasRoutePaused || !hasEntryProt {
		t.Fatalf("missing expected alert texts: %v", msgs)
	}
	// Re-evaluating in the same cycle must NOT send duplicates!
	states2, _ := app.Store.loadAlertStates()
	app.evaluateRouteAndEntryProtectionAlerts(now.Add(5*time.Minute), TelegramThresholdEvent{Enabled: true, Threshold: 80}, []shared.Server{entry}, states2)
	_ = app.FlushTelegramForTest(2 * time.Second)
	if dup := sink.take(); len(dup) != 0 {
		t.Fatalf("expected per-cycle dedup (no new alerts), got %v", dup)
	}
}

// TestOfflineExportIncludesRouteLimitsAndEntryProtection verifies Fix #6:
// offline export embeds entry-hop route quotas/speed caps and server entry
// total protection policy, raises MinAgentVersion so old offline agents refuse
// it, and verifies the signed bundle cleanly.
func TestOfflineExportIncludesRouteLimitsAndEntryProtection(t *testing.T) {
	l := newRouteLab(t)
	code, rt := l.route(map[string]any{
		"name": "offline-limited", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true,
		"trafficLimit": int64(1024), "trafficLimitType": "sum", "trafficResetDay": 15,
		"upSpeedLimitMbps": 1, "downSpeedLimitMbps": 2,
	})
	if code != 201 {
		t.Fatalf("create route %d %v", code, rt)
	}
	entry, err := l.p.store.Server(l.entry)
	if err != nil {
		t.Fatal(err)
	}
	entry.ManagementMode = "offline"
	entry.FirewallMode = "manual"
	entry.TrafficLimit = 50 << 30
	entry.TrafficProtectionEnabled = true
	entry.TrafficProtectionThreshold = 90
	if err = l.p.store.PutServer(entry); err != nil {
		t.Fatal(err)
	}

	bundle := exportOffline(l.p, l.entry)
	if bundle.MinAgentVersion != shared.OfflineBundleTrafficLimitMinAgent {
		t.Fatalf("expected MinAgentVersion=%q for limited offline bundle, got %q", shared.OfflineBundleTrafficLimitMinAgent, bundle.MinAgentVersion)
	}
	if err := bundle.CheckAgentVersion("0.6.7"); err == nil {
		t.Fatal("expected old offline agent 0.6.7 to reject bundle with traffic limits")
	}
	if err := bundle.CheckAgentVersion("0.6.32"); err == nil {
		t.Fatal("expected pre-feature offline agent 0.6.32 to reject bundle with traffic limits")
	}
	if err := bundle.CheckAgentVersion(shared.OfflineBundleTrafficLimitMinAgent); err != nil {
		t.Fatalf("expected current offline agent to accept bundle: %v", err)
	}
	if bundle.EntryTrafficProtection == nil || !bundle.EntryTrafficProtection.Enabled || bundle.EntryTrafficProtection.ThresholdPercent != 90 || bundle.EntryTrafficProtection.LimitBytes != 50<<30 {
		t.Fatalf("offline bundle missing EntryTrafficProtection: %+v", bundle.EntryTrafficProtection)
	}
	if len(bundle.Forwards) == 0 {
		t.Fatal("no exported forwards")
	}
	for _, f := range bundle.Forwards {
		if !f.EntryHop || f.RouteTrafficLimit != 1024 || f.RouteTrafficResetDay != 15 || f.RouteUpSpeedLimitBps != 125_000 || f.RouteDownSpeedLimitBps != 250_000 {
			t.Fatalf("offline export omitted limits: %+v", f)
		}
	}
}

// TestAlertLoopDoesNotOverwriteConcurrentServerEdits verifies Fix #7:
// evaluating alerts with a stale server snapshot acquires lockServer, reloads
// the latest server record, and never overwrites concurrent admin edits.
func TestAlertLoopDoesNotOverwriteConcurrentServerEdits(t *testing.T) {
	p := newTestMui(t)
	id, _ := p.enroll("original")
	stale, err := p.store.Server(id)
	if err != nil {
		t.Fatal(err)
	}
	stale.TrafficProtectionEnabled = true
	stale.TrafficLimit = 1000
	if err = p.store.PutServer(stale); err != nil {
		t.Fatal(err)
	}
	// Concurrent admin edit changes name and disables entry protection.
	fresh := stale
	fresh.Name = "edited-after-alert-snapshot"
	fresh.TrafficProtectionEnabled = false
	if err = p.store.PutServer(fresh); err != nil {
		t.Fatal(err)
	}
	p.app.evaluateRouteAndEntryProtectionAlerts(time.Now(), TelegramThresholdEvent{Threshold: 80}, []shared.Server{stale}, map[string]alertStateRow{})
	got, err := p.store.Server(id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != fresh.Name || got.TrafficProtectionEnabled {
		t.Fatalf("alert overwrote newer server edit: name=%q protection=%v", got.Name, got.TrafficProtectionEnabled)
	}
}

// TestOfflineExportLegacyStrictDecodeAndVersionGate verifies that an offline
// export with NO route limits and NO entry total protection omits all new
// ForwardRule fields so a pre-feature offline Agent using DisallowUnknownFields
// decodes it with zero errors.
func TestOfflineExportLegacyStrictDecodeAndVersionGate(t *testing.T) {
	l := newRouteLab(t)
	code, rt := l.route(map[string]any{
		"name": "unlimited-offline", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true,
	})
	if code != 201 {
		t.Fatalf("create route %d %v", code, rt)
	}
	entry, err := l.p.store.Server(l.entry)
	if err != nil {
		t.Fatal(err)
	}
	entry.ManagementMode = "offline"
	entry.FirewallMode = "manual"
	if err = l.p.store.PutServer(entry); err != nil {
		t.Fatal(err)
	}

	bundle := exportOffline(l.p, l.entry)
	if bundle.MinAgentVersion != shared.OfflineBundleMinAgent {
		t.Fatalf("expected legacy MinAgentVersion=%q for unlimited bundle, got %q", shared.OfflineBundleMinAgent, bundle.MinAgentVersion)
	}
	if bundle.EntryTrafficProtection != nil {
		t.Fatalf("expected nil EntryTrafficProtection for unlimited bundle, got %+v", bundle.EntryTrafficProtection)
	}
	rawForwards, err := json.Marshal(bundle.Forwards)
	if err != nil {
		t.Fatal(err)
	}

	// Exact pre-feature ForwardRule schema from git HEAD (0.6.32).
	type legacyForwardRule struct {
		ID                string                 `json:"id"`
		ServerID          string                 `json:"serverId"`
		Name              string                 `json:"name"`
		Network           string                 `json:"network"`
		Listen            string                 `json:"listen"`
		Port              int                    `json:"port"`
		Targets           []shared.ForwardTarget `json:"targets"`
		Balance           string                 `json:"balance"`
		HealthCheck       string                 `json:"healthCheck,omitempty"`
		RouteID           string                 `json:"routeId,omitempty"`
		RouteIDs          []string               `json:"routeIds,omitempty"`
		ManualBasePolicy  string                 `json:"manualBasePolicy,omitempty"`
		ManualBaseSources string                 `json:"manualBaseSources,omitempty"`
		ManualBaseTargets []shared.ForwardTarget `json:"manualBaseTargets,omitempty"`
		ObserveClients    bool                   `json:"observeClients,omitempty"`
		ClientNodeID      string                 `json:"clientNodeId,omitempty"`
		FirewallPolicy    string                 `json:"firewallPolicy"`
		FirewallSources   string                 `json:"firewallSources"`
		Enabled           bool                   `json:"enabled"`
		Deleting          bool                   `json:"deleting"`
		Status            string                 `json:"status"`
		Error             string                 `json:"error"`
		Uplink            int64                  `json:"uplink"`
		Downlink          int64                  `json:"downlink"`
	}
	var decoded []legacyForwardRule
	dec := json.NewDecoder(strings.NewReader(string(rawForwards)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&decoded); err != nil {
		t.Fatalf("legacy strict DisallowUnknownFields decode failed on unlimited offline export: %v\njson=%s", err, rawForwards)
	}
	if len(decoded) == 0 {
		t.Fatal("expected at least one decoded forward")
	}
}
