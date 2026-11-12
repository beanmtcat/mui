package server

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"mui/internal/shared"
)

func TestAgentEnrollServerLocksAndRateLimit(t *testing.T) {
	p := newTestMui(t)

	lockCount := func() int {
		p.app.serverLocksMu.Lock()
		defer p.app.serverLocksMu.Unlock()
		return len(p.app.serverLocks)
	}
	before := lockCount()

	sendUnauthEnroll := func(remoteAddr, serverID, token string) int {
		raw, _ := json.Marshal(map[string]string{"serverId": serverID, "token": token})
		req := httptest.NewRequest("POST", "/agent/enroll", bytes.NewReader(raw))
		req.RemoteAddr = remoteAddr
		rec := httptest.NewRecorder()
		p.handler.ServeHTTP(rec, req)
		return rec.Code
	}

	// 100 unauthenticated enroll attempts with distinct non-existent serverIds
	// (including oversized and malformed ones) across distinct source IPs so
	// rate limiting does not mask serverLocks growth.
	for i := 0; i < 100; i++ {
		var fakeID string
		switch {
		case i == 0:
			fakeID = ""
		case i == 1:
			fakeID = strings.Repeat("x", 65)
		case i == 2:
			fakeID = strings.Repeat("y", 128*1024)
		case i == 3:
			fakeID = "bad/id$with spaces"
		default:
			fakeID = fmt.Sprintf("missing-server-%03d-%s", i, strings.Repeat("a", 20))
		}
		ip := fmt.Sprintf("198.51.100.%d:40000", (i%200)+1)
		if code := sendUnauthEnroll(ip, fakeID, "bogus-token"); code != 401 {
			t.Fatalf("attempt %d (%d bytes): got status %d, want 401", i, len(fakeID), code)
		}
	}
	if got := lockCount(); got != before {
		t.Fatalf("serverLocks grew on unauthenticated invalid/missing enrolls: got %d, want %d", got, before)
	}

	// Authenticated admin endpoints that take path {id} must also not populate
	// serverLocks when the server does not exist.
	for _, call := range [][2]string{
		{"PATCH", "/api/servers/nonexistent-server-id"},
		{"DELETE", "/api/servers/nonexistent-server-id"},
		{"POST", "/api/servers/nonexistent-server-id/revoke"},
		{"POST", "/api/servers/nonexistent-server-id/offline/export"},
	} {
		if code, _, _ := p.do(call[0], call[1], map[string]any{"name": "x"}, nil); code != 404 {
			t.Fatalf("%s %s: got %d, want 404", call[0], call[1], code)
		}
	}
	if got := lockCount(); got != before {
		t.Fatalf("serverLocks grew on missing-server admin endpoints: got %d, want %d", got, before)
	}

	// Per-IP rate limit: > 30 requests within a minute from one IP returns 429.
	for i := 1; i <= 30; i++ {
		if code := sendUnauthEnroll("203.0.113.250:50000", "missing", "tok"); code != 401 {
			t.Fatalf("request %d before limit: got %d, want 401", i, code)
		}
	}
	if code := sendUnauthEnroll("203.0.113.250:50000", "missing", "tok"); code != 429 {
		t.Fatalf("request 31 from same IP: got %d, want 429", code)
	}

	// Legitimate enrollment from an unthrottled IP still works.
	code, created, _ := p.do("POST", "/api/servers", map[string]any{
		"name": "valid-enroll", "roles": []string{"exit"}, "country": "SG", "ipv4": "203.0.113.11",
	}, nil)
	if code != 201 {
		t.Fatalf("create server: %d %v", code, created)
	}
	srvID := created["server"].(map[string]any)["id"].(string)
	enrollTok := created["enrollToken"].(string)
	if code := sendUnauthEnroll("203.0.113.251:50000", srvID, enrollTok); code != 200 {
		t.Fatalf("valid enroll failed: %d", code)
	}
}

func TestTrafficAndOperationsIndexesExist(t *testing.T) {
	p := newTestMui(t)
	want := map[string]string{
		"mui_idx_traffic_at_ms":        "mui_traffic",
		"mui_idx_user_traffic_at_ms":   "mui_user_traffic",
		"mui_idx_server_traffic_at_ms": "mui_server_traffic",
		"mui_idx_ops_server_claimed":   "mui_operations",
	}
	for idx, table := range want {
		var sqlText string
		err := p.store.DB.QueryRow(`SELECT sql FROM sqlite_master WHERE type='index' AND name=$1 AND tbl_name=$2`, idx, table).Scan(&sqlText)
		if err != nil || sqlText == "" {
			t.Fatalf("missing index %s on %s: %v", idx, table, err)
		}
	}
}

func TestPruneOperationsKeepsNonTerminalAndRecent(t *testing.T) {
	p := newTestMui(t)
	serverID, _ := p.enroll("ops-prune")
	now := time.Now()
	oldTime := now.AddDate(0, 0, -100)
	recentTime := now.AddDate(0, 0, -10)

	makeID := func(ts time.Time, seq int) string {
		return fmt.Sprintf("%016x%020x", ts.UnixNano(), seq)
	}

	putOp := func(id, kind string, created time.Time) {
		op := shared.Operation{
			ID: id, ServerID: serverID, Kind: kind, Status: "queued",
			CreatedAt: created, UpdatedAt: created,
		}
		if err := p.store.PutOperation(op, shared.DesiredState{}); err != nil {
			t.Fatal(err)
		}
	}

	idOldSuccess := makeID(oldTime, 1)
	putOp(idOldSuccess, "nodes.apply", oldTime)
	if err := p.store.FinishJob(idOldSuccess, "success", ""); err != nil {
		t.Fatal(err)
	}

	idOldFailed := makeID(oldTime, 2)
	putOp(idOldFailed, "nodes.apply", oldTime)
	if err := p.store.FinishJob(idOldFailed, "failed", "boom"); err != nil {
		t.Fatal(err)
	}

	idOldSuperseded := makeID(oldTime, 3)
	putOp(idOldSuperseded, "nodes.apply", oldTime)
	if err := p.store.SupersedeQueuedApply(serverID); err != nil {
		t.Fatal(err)
	}

	idOldRunning := makeID(oldTime, 4)
	putOp(idOldRunning, "ufw.init", oldTime)
	if job, err := p.store.ClaimJob(serverID, true); err != nil || job == nil || job.ID != idOldRunning {
		t.Fatalf("claim running op: %v %+v", err, job)
	}

	idOldActivating := makeID(oldTime, 5)
	putOp(idOldActivating, "agent.upgrade", oldTime)
	if job, err := p.store.ClaimJob(serverID, true); err != nil || job == nil || job.ID != idOldActivating {
		t.Fatalf("claim activating op: %v %+v", err, job)
	}
	if err := p.store.MarkUpgradeActivating(idOldActivating); err != nil {
		t.Fatal(err)
	}

	idOldQueued := makeID(oldTime, 6)
	putOp(idOldQueued, "nodes.apply", oldTime)

	idRecentSuccess := makeID(recentTime, 7)
	putOp(idRecentSuccess, "nodes.apply", recentTime)
	if err := p.store.FinishJob(idRecentSuccess, "success", ""); err != nil {
		t.Fatal(err)
	}

	if err := p.store.PruneOperations(now.AddDate(0, 0, -90)); err != nil {
		t.Fatal(err)
	}

	for _, deletedID := range []string{idOldSuccess, idOldFailed, idOldSuperseded} {
		if _, err := p.store.Operation(deletedID); err == nil {
			t.Fatalf("old terminal operation %s should have been pruned", deletedID)
		}
	}
	for _, keptID := range []string{idOldQueued, idOldRunning, idOldActivating, idRecentSuccess} {
		if _, err := p.store.Operation(keptID); err != nil {
			t.Fatalf("operation %s should have been kept: %v", keptID, err)
		}
	}
}

func TestAgentJobThrottlesExpirySyncAndAppliesWithin30s(t *testing.T) {
	p := newTestMui(t)
	serverID, agent := p.enroll("job-throttle")
	p.newAgent(agent)

	code, node, _ := p.do("POST", "/api/nodes", map[string]any{
		"direct": true, "serverId": serverID, "name": "SS", "protocol": "ss",
		"port": 50111, "method": "2022-blake3-aes-128-gcm",
	}, nil)
	if code != 201 {
		t.Fatalf("node: %d %v", code, node)
	}
	p.applyAll(agent)

	exp := time.Now().Add(60 * time.Millisecond)
	code, sub, _ := p.do("POST", "/api/subscriptions", map[string]any{
		"name": "expiring", "format": "sing-box",
		"nodeIds":   []string{node["id"].(string)},
		"expiresAt": exp,
	}, nil)
	if code != 201 {
		t.Fatalf("subscription: %d %v", code, sub)
	}
	// Record a sync right before expiry and apply the initial subscription job.
	p.app.expirySyncAt.Store(0)
	job := p.applyNext(agent, "success")
	if len(job["state"].(map[string]any)["nodes"].([]any)[0].(map[string]any)["users"].([]any)) != 2 {
		t.Fatal("subscriber missing from initial apply")
	}

	// Wait until the subscription has expired.
	time.Sleep(90 * time.Millisecond)

	// Within the 30s throttle window, /agent/job skips syncExpiredSubscriptions.
	if code, _, _ := p.do("GET", "/agent/job", nil, agent); code != 204 {
		t.Fatalf("expected throttled poll to return 204, got %d", code)
	}

	// Simulate that the previous sync happened 5s before expiry, so at 25s after
	// expiry (< 30s after expiry!) 30s have elapsed since that last sync.
	p.app.expirySyncAt.Store(time.Now().Add(-expirySyncInterval - time.Millisecond).UnixNano())
	job = p.applyNext(agent, "success")
	if job["kind"] != "subscriptions.apply" {
		t.Fatalf("expected subscriptions.apply job within 30s of expiry, got %v", job["kind"])
	}
	if len(job["state"].(map[string]any)["nodes"].([]any)[0].(map[string]any)["users"].([]any)) != 1 {
		t.Fatal("expired subscriber was not removed")
	}

	// Subsequent poll is throttled again and nothing else is queued.
	if code, _, _ := p.do("GET", "/agent/job", nil, agent); code != 204 {
		t.Fatalf("expected 204 after expiry apply, got %d", code)
	}
}

func TestSessionLastSeenThrottleAndPruneSessions(t *testing.T) {
	p := newTestMui(t)
	tokenHash := Hash(p.cookie.Value)

	// First authenticated request updates last_seen_at from 0.
	if code, _, _ := p.do("GET", "/api/me", nil, nil); code != 200 {
		t.Fatalf("me: %d", code)
	}
	now := time.Now().Unix()
	recentSeen := now - 20
	if _, err := p.store.DB.Exec(`UPDATE mui_sessions SET last_seen_at=$1 WHERE token_hash=$2`, recentSeen, tokenHash); err != nil {
		t.Fatal(err)
	}
	// Within 60s, require must not write mui_sessions.
	if code, _, _ := p.do("GET", "/api/me", nil, nil); code != 200 {
		t.Fatalf("me within 60s: %d", code)
	}
	var gotSeen int64
	if err := p.store.DB.QueryRow(`SELECT last_seen_at FROM mui_sessions WHERE token_hash=$1`, tokenHash).Scan(&gotSeen); err != nil || gotSeen != recentSeen {
		t.Fatalf("last_seen_at rewritten within 60s: got %d, want %d (err=%v)", gotSeen, recentSeen, err)
	}

	// At >= 60s, require updates last_seen_at.
	staleSeen := time.Now().Unix() - 65
	if _, err := p.store.DB.Exec(`UPDATE mui_sessions SET last_seen_at=$1 WHERE token_hash=$2`, staleSeen, tokenHash); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := p.do("GET", "/api/me", nil, nil); code != 200 {
		t.Fatalf("me after 65s: %d", code)
	}
	if err := p.store.DB.QueryRow(`SELECT last_seen_at FROM mui_sessions WHERE token_hash=$1`, tokenHash).Scan(&gotSeen); err != nil || gotSeen <= staleSeen {
		t.Fatalf("last_seen_at not updated after 60s: got %d, stale %d (err=%v)", gotSeen, staleSeen, err)
	}

	// Seed expired, 24h-idle, and orphaned TOTP pending rows, then prune.
	nowUnix := time.Now().Unix()
	if _, err := p.store.DB.Exec(`INSERT INTO mui_sessions(token_hash,expires_at,last_seen_at) VALUES('expired-sess',$1,$2)`, nowUnix-10, nowUnix-20); err != nil {
		t.Fatal(err)
	}
	if _, err := p.store.DB.Exec(`INSERT INTO mui_sessions(token_hash,expires_at,last_seen_at) VALUES('idle-sess',$1,$2)`, nowUnix+3600, nowUnix-24*3600-10); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{tokenHash, "expired-sess", "idle-sess", "missing-sess"} {
		if _, err := p.store.DB.Exec(`INSERT INTO mui_totp_pending(session_hash,secret) VALUES($1,'sec')`, h); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.store.PruneSessions(time.Now()); err != nil {
		t.Fatal(err)
	}
	var sessCount, totpCount int
	_ = p.store.DB.QueryRow(`SELECT COUNT(*) FROM mui_sessions`).Scan(&sessCount)
	_ = p.store.DB.QueryRow(`SELECT COUNT(*) FROM mui_totp_pending`).Scan(&totpCount)
	if sessCount != 1 || totpCount != 1 {
		t.Fatalf("PruneSessions left %d sessions and %d totp_pending rows, want 1 and 1", sessCount, totpCount)
	}

	// 24h idle check in require remains enforced.
	if _, err := p.store.DB.Exec(`UPDATE mui_sessions SET last_seen_at=$1 WHERE token_hash=$2`, time.Now().Unix()-24*3600-5, tokenHash); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := p.do("GET", "/api/me", nil, nil); code != 401 {
		t.Fatalf("expected 401 for 24h-idle session, got %d", code)
	}
}

func TestOperationsGetDoesNotAcquireWriteLock(t *testing.T) {
	p := newTestMui(t)
	serverID, _ := p.enroll("ops-lockfree")
	if err := p.store.PutOperation(shared.Operation{
		ID: ID(), ServerID: serverID, Kind: "agent.upgrade", Status: "activating",
		TargetBuild: "new", UpdatedAt: time.Now().Add(-6 * time.Minute),
	}, shared.DesiredState{}); err != nil {
		t.Fatal(err)
	}
	// Hold App.mu while issuing GET /api/operations: if the handler still locked
	// App.mu, this call would deadlock.
	p.app.mu.Lock()
	defer p.app.mu.Unlock()
	req := httptest.NewRequest("GET", "/api/operations", nil)
	req.AddCookie(p.cookie)
	rec := httptest.NewRecorder()
	p.handler.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("GET /api/operations returned %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSubscriptionsListPendingMatchesSubscriptionItems(t *testing.T) {
	p := newTestMui(t)
	entryID, entryAgent := p.enroll("sub-entry")
	if code, out, _ := p.do("PATCH", "/api/servers/"+entryID, map[string]any{
		"name": "sub-entry", "roles": []string{"entry"}, "country": "SG", "ipv4": "198.51.100.10",
	}, nil); code != 200 {
		t.Fatalf("entry roles: %d %v", code, out)
	}
	p.newAgent(entryAgent)

	exitID, exitAgent := p.enroll("sub-exit")
	p.newAgent(exitAgent)

	createSS := func(name string, port int, direct bool) string {
		code, n, _ := p.do("POST", "/api/nodes", map[string]any{
			"serverId": exitID, "name": name, "protocol": "ss", "port": port,
			"method": "2022-blake3-aes-128-gcm", "direct": direct, "enabled": true,
		}, nil)
		if code != 201 {
			t.Fatalf("node %s: %d %v", name, code, n)
		}
		return n["id"].(string)
	}

	liveNode := createSS("live-direct", 51001, true)
	renameOnlyNode := createSS("rename-direct", 51002, true)
	portChangedNode := createSS("port-direct", 51003, true)
	routeExitNode := createSS("route-exit", 51004, false)

	code, activeRoute, _ := p.do("POST", "/api/routes", map[string]any{
		"name": "active-route", "entryServerId": entryID, "port": 52001,
		"nodeId": routeExitNode, "enabled": true,
	}, nil)
	if code != 201 {
		t.Fatalf("active route: %d %v", code, activeRoute)
	}

	code, sub1, _ := p.do("POST", "/api/subscriptions", map[string]any{
		"name": "sub-main", "format": "sing-box",
		"nodeIds":  []string{liveNode, renameOnlyNode, portChangedNode},
		"routeIds": []string{activeRoute["id"].(string)},
		"enabled":  true,
	}, nil)
	if code != 201 {
		t.Fatalf("sub1: %d %v", code, sub1)
	}

	p.applyAll(entryAgent)
	p.applyAll(exitAgent)

	// Now create unapplied changes:
	// 1. Rename-only edit on renameOnlyNode (client fingerprint unchanged -> still live).
	if code, out, _ := p.do("PATCH", "/api/nodes/"+renameOnlyNode, map[string]any{
		"name": "rename-direct-v2", "protocol": "ss", "port": 51002,
		"method": "2022-blake3-aes-128-gcm", "direct": true, "enabled": true,
	}, nil); code != 200 {
		t.Fatalf("rename edit: %d %v", code, out)
	}
	// 2. Port edit on portChangedNode (client fingerprint changed -> pending).
	if code, out, _ := p.do("PATCH", "/api/nodes/"+portChangedNode, map[string]any{
		"name": "port-direct", "protocol": "ss", "port": 51099,
		"method": "2022-blake3-aes-128-gcm", "direct": true, "enabled": true,
	}, nil); code != 200 {
		t.Fatalf("port edit: %d %v", code, out)
	}
	// 3. Brand-new pending direct node and brand-new pending route.
	newPendingNode := createSS("brand-new", 51005, true)
	code, pendingRoute, _ := p.do("POST", "/api/routes", map[string]any{
		"name": "pending-route", "entryServerId": entryID, "port": 52002,
		"nodeId": routeExitNode, "enabled": true,
	}, nil)
	if code != 201 {
		t.Fatalf("pending route: %d %v", code, pendingRoute)
	}

	// Second subscription (never applied yet, plus disabled subscription).
	code, sub2, _ := p.do("POST", "/api/subscriptions", map[string]any{
		"name": "sub-new", "format": "sing-box",
		"nodeIds":  []string{liveNode, newPendingNode},
		"routeIds": []string{activeRoute["id"].(string), pendingRoute["id"].(string)},
		"enabled":  true,
	}, nil)
	if code != 201 {
		t.Fatalf("sub2: %d %v", code, sub2)
	}
	if code, sub3, _ := p.do("POST", "/api/subscriptions", map[string]any{
		"name": "sub-disabled", "format": "sing-box",
		"nodeIds": []string{newPendingNode}, "enabled": false,
	}, nil); code != 201 {
		t.Fatalf("sub3: %d %v", code, sub3)
	}

	// Compute reference pendingNodeIds / pendingRouteIds via subscriptionItems.
	storedSubs, err := p.store.Subscriptions()
	if err != nil {
		t.Fatal(err)
	}
	world, err := p.app.loadRouteWorld()
	if err != nil {
		t.Fatal(err)
	}
	wantNodes := map[string][]string{}
	wantRoutes := map[string][]string{}
	for _, s := range storedSubs {
		if s.Enabled && (s.ExpiresAt == nil || time.Now().Before(*s.ExpiresAt)) {
			if _, _, pending, err := p.app.subscriptionItems(s, &world); err == nil {
				for _, id := range pending {
					if slices.Contains(s.RouteIDs, id) {
						wantRoutes[s.ID] = append(wantRoutes[s.ID], id)
					} else {
						wantNodes[s.ID] = append(wantNodes[s.ID], id)
					}
				}
			}
		}
	}

	// Corrupt liveNode's encrypted secret while its status remains active to
	// verify GET /api/subscriptions does not decrypt active node secrets.
	var origSecret string
	if err := p.store.DB.QueryRow(`SELECT secret FROM mui_nodes WHERE id=$1`, liveNode).Scan(&origSecret); err != nil {
		t.Fatal(err)
	}
	if _, err := p.store.DB.Exec(`UPDATE mui_nodes SET secret='not-valid-ciphertext' WHERE id=$1`, liveNode); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/api/subscriptions", nil)
	req.AddCookie(p.cookie)
	rec := httptest.NewRecorder()
	p.handler.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("GET /api/subscriptions: %d %s", rec.Code, rec.Body.String())
	}
	var gotSubs []shared.Subscription
	if err := json.Unmarshal(rec.Body.Bytes(), &gotSubs); err != nil {
		t.Fatal(err)
	}
	for _, s := range gotSubs {
		if !reflect.DeepEqual(s.PendingNodeIDs, wantNodes[s.ID]) {
			t.Fatalf("sub %s (%s) pendingNodeIds = %v, want %v", s.Name, s.ID, s.PendingNodeIDs, wantNodes[s.ID])
		}
		if !reflect.DeepEqual(s.PendingRouteIDs, wantRoutes[s.ID]) {
			t.Fatalf("sub %s (%s) pendingRouteIds = %v, want %v", s.Name, s.ID, s.PendingRouteIDs, wantRoutes[s.ID])
		}
	}

	// Restore liveNode secret and confirm download & preview still work.
	if _, err := p.store.DB.Exec(`UPDATE mui_nodes SET secret=$1 WHERE id=$2`, origSecret, liveNode); err != nil {
		t.Fatal(err)
	}
	path := strings.TrimPrefix(sub1["url"].(string), "https://mui.example.test")
	if code, body := p.fetch(path); code != 200 || !strings.Contains(body, "live-direct") || !strings.Contains(body, "rename-direct-v2") || strings.Contains(body, "port-direct") {
		t.Fatalf("download output unexpected: %d %s", code, body)
	}
}

func TestAgentReportTrafficBoundsAndClockSkew(t *testing.T) {
	p := newTestMui(t)
	serverID, agent := p.enroll("traffic-bounds")
	p.newAgent(agent)

	code, node, _ := p.do("POST", "/api/nodes", map[string]any{
		"direct": true, "serverId": serverID, "name": "SS", "protocol": "ss",
		"port": 51200, "method": "2022-blake3-aes-128-gcm",
	}, nil)
	if code != 201 {
		t.Fatalf("node: %d %v", code, node)
	}
	nodeID := node["id"].(string)

	code, fwd, _ := p.do("POST", "/api/forwards", map[string]any{
		"serverId": serverID, "name": "fwd", "network": "tcp", "port": 51201,
		"targets": []map[string]any{{"host": "198.51.100.88", "port": 443}}, "enabled": true,
	}, nil)
	if code != 201 {
		t.Fatalf("forward: %d %v", code, fwd)
	}
	fwdID := fwd["id"].(string)

	code, sub, _ := p.do("POST", "/api/subscriptions", map[string]any{
		"name": "valid-sub", "format": "sing-box", "nodeIds": []string{nodeID}, "enabled": true,
	}, nil)
	if code != 201 {
		t.Fatalf("sub: %d %v", code, sub)
	}
	subID := sub["id"].(string)

	now := time.Now()
	tooLong := strings.Repeat("x", 129)
	maxOK := strings.Repeat("y", 128)
	futureAt := now.Add(15 * time.Minute)
	ancientAt := now.AddDate(0, 0, -100)

	report := map[string]any{
		"traffic": []shared.TrafficPoint{
			{NodeID: nodeID, InstanceID: maxOK, Sequence: 1, Uplink: 11, Downlink: 22, At: now},
			{NodeID: nodeID, InstanceID: "future", Sequence: 2, Uplink: 999, Downlink: 999, At: futureAt},
			{NodeID: nodeID, InstanceID: "ancient", Sequence: 3, Uplink: 999, Downlink: 999, At: ancientAt},
			{NodeID: nodeID, InstanceID: tooLong, Sequence: 4, Uplink: 999, Downlink: 999, At: now},
		},
		"userTraffic": []shared.UserTrafficPoint{
			{NodeID: nodeID, SubscriptionID: subID, InstanceID: maxOK, Sequence: 1, Uplink: 33, Downlink: 44, At: now},
			{NodeID: nodeID, SubscriptionID: "nonexistent-sub-id", InstanceID: "ok", Sequence: 2, Uplink: 888, Downlink: 888, At: now},
			{NodeID: nodeID, SubscriptionID: subID, InstanceID: tooLong, Sequence: 3, Uplink: 888, Downlink: 888, At: now},
			{NodeID: nodeID, SubscriptionID: subID, InstanceID: "future", Sequence: 4, Uplink: 888, Downlink: 888, At: futureAt},
			{NodeID: nodeID, SubscriptionID: subID, InstanceID: "ancient", Sequence: 5, Uplink: 888, Downlink: 888, At: ancientAt},
		},
		"serverTraffic": []shared.ServerTrafficPoint{
			{BootID: maxOK, Interface: "eth0", Sequence: 1, Rx: 55, Tx: 66, At: now},
			{BootID: tooLong, Interface: "eth0", Sequence: 2, Rx: 777, Tx: 777, At: now},
			{BootID: "b", Interface: tooLong, Sequence: 3, Rx: 777, Tx: 777, At: now},
			{BootID: "b", Interface: "eth0", Sequence: 4, Rx: 777, Tx: 777, At: futureAt},
			{BootID: "b", Interface: "eth0", Sequence: 5, Rx: 777, Tx: 777, At: ancientAt},
		},
		"forwardTraffic": []shared.ForwardTrafficPoint{
			{ForwardID: fwdID, InstanceID: maxOK, Uplink: 77, Downlink: 88, UpdatedAt: now},
			{ForwardID: fwdID, InstanceID: tooLong, Uplink: 666, Downlink: 666, UpdatedAt: now},
		},
	}
	if code, out, _ := p.do("POST", "/agent/report", report, agent); code != 200 {
		t.Fatalf("mixed report failed: %d %v", code, out)
	}

	nodeTotals, err := p.store.NodeTotals()
	if err != nil || nodeTotals[nodeID] != [2]int64{11, 22} {
		t.Fatalf("nodeTotals = %v (err=%v), want [11 22]", nodeTotals[nodeID], err)
	}
	var userCount int
	var userUp, userDown int64
	_ = p.store.DB.QueryRow(`SELECT COUNT(*),COALESCE(SUM(uplink),0),COALESCE(SUM(downlink),0) FROM mui_user_totals`).Scan(&userCount, &userUp, &userDown)
	if userCount != 1 || userUp != 33 || userDown != 44 {
		t.Fatalf("user_totals count=%d up=%d down=%d, want 1, 33, 44", userCount, userUp, userDown)
	}
	servers, err := p.store.Servers()
	if err != nil || servers[0].NetworkRx != 55 || servers[0].NetworkTx != 66 {
		t.Fatalf("server network totals = %d/%d (err=%v), want 55/66", servers[0].NetworkRx, servers[0].NetworkTx, err)
	}
	for _, f := range mustForwards(t, p, serverID) {
		if f.ID == fwdID && (f.Uplink != 77 || f.Downlink != 88) {
			t.Fatalf("forward totals = %d/%d, want 77/88", f.Uplink, f.Downlink)
		}
	}

	// Verify unsigned legacy Agent with +2h clock skew does not lose normal data,
	// while timestamps beyond the ±24h skew cap are still dropped.
	legacyID, legacyHeaders := p.enroll("skewed-legacy")
	code, legacyNode, _ := p.do("POST", "/api/nodes", map[string]any{
		"direct": true, "serverId": legacyID, "name": "SS-legacy", "protocol": "ss",
		"port": 51202, "method": "2022-blake3-aes-128-gcm",
	}, nil)
	if code != 201 {
		t.Fatalf("legacy node: %d %v", code, legacyNode)
	}
	legacyNodeID := legacyNode["id"].(string)
	skewedNow := time.Now().Add(2 * time.Hour)
	rawBody, _ := json.Marshal(map[string]any{
		"agentTime": skewedNow,
		"traffic": []shared.TrafficPoint{
			{NodeID: legacyNodeID, InstanceID: "skew-ok", Sequence: 1, Uplink: 42, Downlink: 84, At: skewedNow},
			{NodeID: legacyNodeID, InstanceID: "skew-way-future", Sequence: 2, Uplink: 500, Downlink: 500, At: time.Now().Add(48 * time.Hour)},
		},
	})
	// Send unsigned request (as an older agent without X-Agent-Signature does).
	req := httptest.NewRequest("POST", "/agent/report", bytes.NewReader(rawBody))
	req.Header.Set("X-Server-ID", legacyHeaders["X-Server-ID"])
	req.Header.Set("Authorization", legacyHeaders["Authorization"])
	rec := httptest.NewRecorder()
	p.handler.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("unsigned skewed report: %d %s", rec.Code, rec.Body.String())
	}
	nodeTotals, _ = p.store.NodeTotals()
	if nodeTotals[legacyNodeID] != [2]int64{42, 84} {
		t.Fatalf("skewed legacy totals = %v, want [42 84]", nodeTotals[legacyNodeID])
	}
}

func mustForwards(t *testing.T, p *testMui, serverID string) []shared.ForwardRule {
	t.Helper()
	list, err := p.store.Forwards(serverID)
	if err != nil {
		t.Fatal(err)
	}
	return list
}

func TestSecurityHeadersHSTSOnlyOnHTTPS(t *testing.T) {
	t.Setenv("MUI_TRUSTED_PROXIES", "10.0.0.1")
	p := newTestMui(t)

	check := func(desc string, tlsState *tls.ConnectionState, remoteAddr, forwardedProto, want string) {
		t.Helper()
		req := httptest.NewRequest("GET", "/healthz", nil)
		req.TLS = tlsState
		req.RemoteAddr = remoteAddr
		if forwardedProto != "" {
			req.Header.Set("X-Forwarded-Proto", forwardedProto)
		}
		rec := httptest.NewRecorder()
		p.handler.ServeHTTP(rec, req)
		if got := rec.Header().Get("Strict-Transport-Security"); got != want {
			t.Fatalf("%s: Strict-Transport-Security = %q, want %q", desc, got, want)
		}
	}

	check("plain HTTP", nil, "198.51.100.10:1234", "", "")
	check("untrusted X-Forwarded-Proto https", nil, "198.51.100.10:1234", "https", "")
	check("trusted proxy HTTP", nil, "10.0.0.1:1234", "http", "")
	check("trusted proxy HTTPS", nil, "10.0.0.1:1234", "https", "max-age=31536000")
	check("direct TLS", &tls.ConnectionState{}, "198.51.100.10:1234", "", "max-age=31536000")

	routesConf, err := os.ReadFile(filepath.Join("..", "..", "deploy", "nginx", "routes.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(routesConf), "add_header Strict-Transport-Security $mui_hsts always;") ||
		!strings.Contains(string(routesConf), "proxy_hide_header Strict-Transport-Security;") {
		t.Fatalf("deploy/nginx/routes.conf missing conditional HSTS directives:\n%s", routesConf)
	}
	for _, rel := range []string{"default.conf.template", "mui-host.conf"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "nginx", rel))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "map $mui_forwarded_proto $mui_hsts") || !strings.Contains(string(raw), `https "max-age=31536000";`) {
			t.Fatalf("deploy/nginx/%s missing $mui_hsts map:\n%s", rel, raw)
		}
	}
}
