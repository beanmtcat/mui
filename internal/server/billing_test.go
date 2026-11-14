package server

import (
	"bytes"
	"fmt"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"mui/internal/shared"
)

func TestBillingRenewalEndOfMonthCatchupModesAndConcurrency(t *testing.T) {
	p := newTestMui(t)
	loc := time.FixedZone("CST", 8*3600)
	p.store.timeLoc = loc
	sink := setupTelegramRecorder(t, p, map[string]any{
		"serverExpiring": map[string]any{"enabled": true},
		"serverRenewed":  map[string]any{"enabled": true},
		"serverOffline":  map[string]any{"enabled": false},
	})

	// 1. Month-end non-leap & leap year without drift across separate renewals:
	// 2026-01-31 -> 2026-02-28 -> 2026-03-31, and 2028-01-31 -> 2028-02-29 -> 2028-03-31.
	jan31 := time.Date(2026, 1, 31, 0, 0, 0, 0, time.UTC)
	code, created, _ := p.do("POST", "/api/servers", map[string]any{
		"name":         "eom-srv",
		"roles":        []string{"exit"},
		"country":      "JP",
		"city":         "Tokyo",
		"ipv4":         "203.0.113.11",
		"expiresAt":    jan31.Format(time.RFC3339),
		"billingCycle": "month",
		"autoRenew":    true,
		"price":        5,
		"currency":     "$",
	}, nil)
	if code != 201 {
		t.Fatalf("create eom-srv: %d %v", code, created)
	}
	eomID := created["server"].(map[string]any)["id"].(string)

	setLastSeen := func(id string, seen time.Time) {
		srv, err := p.store.Server(id)
		if err != nil {
			t.Fatal(err)
		}
		srv.LastSeen = &seen
		if err := p.store.PutServer(srv); err != nil {
			t.Fatal(err)
		}
	}

	// At 6 days before expiry (2026-01-25): autoRenew server must NOT emit 7-day serverExpiring.
	t6d := time.Date(2026, 1, 25, 12, 0, 0, 0, time.UTC)
	setLastSeen(eomID, t6d)
	p.app.evaluateAlertsAt(t6d)
	_ = p.app.FlushTelegramForTest(2 * time.Second)
	if msgs := sink.take(); len(msgs) != 0 {
		t.Fatalf("autoRenew server should skip 7-day reminder, got %v", msgs)
	}

	// At 2 days before expiry (2026-01-29): emits "即将自动续期" exactly once.
	t2d := time.Date(2026, 1, 29, 12, 0, 0, 0, time.UTC)
	setLastSeen(eomID, t2d)
	p.app.evaluateAlertsAt(t2d)
	p.app.evaluateAlertsAt(t2d.Add(time.Hour))
	_ = p.app.FlushTelegramForTest(2 * time.Second)
	msgs := sink.take()
	if len(msgs) != 1 || !strings.Contains(msgs[0], "[MUI] 服务器即将自动续期") {
		t.Fatalf("expected single 即将自动续期 message, got %v", msgs)
	}

	// At 2026-02-01: auto-renews Jan 31 -> Feb 28 and sends "服务器已自动续期" once.
	feb1 := time.Date(2026, 2, 1, 1, 0, 0, 0, time.UTC)
	setLastSeen(eomID, feb1)
	p.app.evaluateAlertsAt(feb1)
	p.app.evaluateAlertsAt(feb1.Add(time.Minute))
	_ = p.app.FlushTelegramForTest(2 * time.Second)
	msgs = sink.take()
	if len(msgs) != 1 || !strings.Contains(msgs[0], "[MUI] 服务器已自动续期") || !strings.Contains(msgs[0], "2026-02-28") || !strings.Contains(msgs[0], "$5.00") {
		t.Fatalf("expected auto-renew to 2026-02-28 with $5.00, got %v", msgs)
	}

	// Next month at 2026-03-01: must renew Feb 28 -> Mar 31 (NO drift to Mar 28!).
	mar1 := time.Date(2026, 3, 1, 1, 0, 0, 0, time.UTC)
	setLastSeen(eomID, mar1)
	p.app.evaluateAlertsAt(mar1)
	_ = p.app.FlushTelegramForTest(2 * time.Second)
	msgs = sink.take()
	if len(msgs) != 1 || !strings.Contains(msgs[0], "2026-03-31") {
		t.Fatalf("expected second renewal to restore 31st (2026-03-31), got %v", msgs)
	}

	// Verify leap year 2028-01-31 -> 2028-02-29 -> 2028-03-31 via computeRenewedExpiry.
	leapExp := time.Date(2028, 1, 31, 0, 0, 0, 0, time.UTC)
	leapSrv := shared.Server{ExpiresAt: &leapExp, BillingCycle: "month"}
	r1, anchor, exceeded, err := computeRenewedExpiry(leapSrv, time.Date(2028, 2, 1, 0, 0, 0, 0, time.UTC))
	if err != nil || exceeded || formatExpiryDate(r1, loc) != "2028-02-29" {
		t.Fatalf("leap year step 1 got %v anchor=%d exceeded=%v err=%v", r1, anchor, exceeded, err)
	}
	leapSrv.ExpiresAt = &r1
	leapSrv.BillingAnchorDay = anchor
	r2, _, exceeded, err := computeRenewedExpiry(leapSrv, time.Date(2028, 3, 1, 0, 0, 0, 0, time.UTC))
	if err != nil || exceeded || formatExpiryDate(r2, loc) != "2028-03-31" {
		t.Fatalf("leap year step 2 got %v exceeded=%v err=%v", r2, exceeded, err)
	}

	// 2. Long-expired catchup in one pass + days cycle + manual renew (no Telegram).
	old2024 := time.Date(2024, 1, 31, 0, 0, 0, 0, time.UTC)
	code, catchupOut, _ := p.do("POST", "/api/servers", map[string]any{
		"name":           "offline-catchup",
		"managementMode": "offline",
		"firewallMode":   "manual",
		"roles":          []string{"entry"},
		"country":        "SG",
		"ipv4":           "203.0.113.12",
		"expiresAt":      old2024.Format(time.RFC3339),
		"billingCycle":   "month",
		"autoRenew":      true,
	}, nil)
	if code != 201 {
		t.Fatalf("create offline-catchup: %d %v", code, catchupOut)
	}
	catchupID := catchupOut["server"].(map[string]any)["id"].(string)
	// Offline-managed has no LastSeen and must still auto-renew directly into the future.
	nowCatchup := time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)
	p.app.evaluateAlertsAt(nowCatchup)
	_ = p.app.FlushTelegramForTest(2 * time.Second)
	_ = sink.take()
	gotCatchup, err := p.store.Server(catchupID)
	if err != nil || gotCatchup.ExpiresAt == nil || formatExpiryDate(*gotCatchup.ExpiresAt, loc) != "2026-03-31" {
		t.Fatalf("expected offline-managed catchup to 2026-03-31, got %+v err=%v", gotCatchup.ExpiresAt, err)
	}

	// Days cycle manual renew via POST /api/servers/{id}/renew: extends without Telegram, writes audit.
	daysStart := time.Date(2026, 5, 10, 0, 0, 0, 0, time.UTC)
	code, daysOut, _ := p.do("POST", "/api/servers", map[string]any{
		"name":             "days-srv",
		"managementMode":   "external",
		"firewallMode":     "manual",
		"roles":            []string{"exit"},
		"country":          "US",
		"ipv4":             "203.0.113.13",
		"expiresAt":        daysStart.Format(time.RFC3339),
		"billingCycle":     "days",
		"billingCycleDays": 15,
	}, nil)
	if code != 201 {
		t.Fatalf("create days-srv: %d %v", code, daysOut)
	}
	daysID := daysOut["server"].(map[string]any)["id"].(string)
	p.app.monitorNow = func() time.Time { return time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC) }
	code, renewedOut, _ := p.do("POST", "/api/servers/"+daysID+"/renew", nil, nil)
	if code != 200 {
		t.Fatalf("manual renew days-srv: %d %v", code, renewedOut)
	}
	_ = p.app.FlushTelegramForTest(2 * time.Second)
	if msgs := sink.take(); len(msgs) != 0 {
		t.Fatalf("manual renew must not send Telegram, got %v", msgs)
	}
	afterDays, _ := p.store.Server(daysID)
	if formatExpiryDate(*afterDays.ExpiresAt, loc) != "2026-05-25" {
		t.Fatalf("expected days manual renew to 2026-05-25, got %v", afterDays.ExpiresAt)
	}

	// 3. Long-offline (>24h) online server must NOT auto-renew and must emit "已到期" reminder instead.
	staleExp := time.Date(2026, 4, 10, 0, 0, 0, 0, time.UTC)
	code, staleOut, _ := p.do("POST", "/api/servers", map[string]any{
		"name":         "stale-online",
		"roles":        []string{"exit"},
		"country":      "DE",
		"ipv4":         "203.0.113.14",
		"expiresAt":    staleExp.Format(time.RFC3339),
		"billingCycle": "month",
		"autoRenew":    true,
	}, nil)
	if code != 201 {
		t.Fatalf("create stale-online: %d %v", code, staleOut)
	}
	staleID := staleOut["server"].(map[string]any)["id"].(string)
	evalStaleAt := time.Date(2026, 4, 11, 12, 0, 0, 0, time.UTC)
	setLastSeen(staleID, evalStaleAt.Add(-30*time.Hour)) // >24h ago
	p.app.evaluateAlertsAt(evalStaleAt)
	_ = p.app.FlushTelegramForTest(2 * time.Second)
	msgs = sink.take()
	staleSrv, _ := p.store.Server(staleID)
	if formatExpiryDate(*staleSrv.ExpiresAt, loc) != "2026-04-10" {
		t.Fatalf("long-offline server must not auto-renew, got %v", staleSrv.ExpiresAt)
	}
	foundStaleExpired := false
	for _, m := range msgs {
		if strings.Contains(m, "stale-online") && strings.Contains(m, "服务器已自动续期") {
			t.Fatalf("stale-online must not emit auto-renew message: %s", m)
		}
		if strings.Contains(m, "stale-online") && strings.Contains(m, "已到期") {
			foundStaleExpired = true
		}
	}
	if !foundStaleExpired {
		t.Fatalf("long-offline server should emit 已到期 alert, got %v", msgs)
	}

	// 4. Revoked server must NOT auto-renew or manually renew.
	revID, _, _ := enrollMonitorTestServer(t, p, "revoked-renew")
	revExp := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	if code, _, _ := p.do("PATCH", "/api/servers/"+revID, map[string]any{
		"name":         "revoked-renew",
		"roles":        []string{"exit"},
		"country":      "JP",
		"ipv4":         "203.0.113.10",
		"expiresAt":    revExp.Format(time.RFC3339),
		"billingCycle": "month",
		"autoRenew":    true,
	}, nil); code != 200 {
		t.Fatalf("patch revoked-renew: %d", code)
	}
	setLastSeen(revID, time.Date(2026, 4, 2, 0, 0, 0, 0, time.UTC))
	if code, _, _ := p.do("POST", "/api/servers/"+revID+"/revoke", nil, nil); code != 200 {
		t.Fatalf("revoke revID: %d", code)
	}
	p.app.evaluateAlertsAt(time.Date(2026, 4, 2, 1, 0, 0, 0, time.UTC))
	revSrv, _ := p.store.Server(revID)
	if formatExpiryDate(*revSrv.ExpiresAt, loc) != "2026-04-01" {
		t.Fatalf("revoked server must not auto-renew, got %v", revSrv.ExpiresAt)
	}
	if code, _, _ := p.do("POST", "/api/servers/"+revID+"/renew", nil, nil); code != 409 {
		t.Fatalf("expected 409 on manual renew of revoked server, got %d", code)
	}

	// 5. Concurrent Agent report + auto-renew must serialize via lockServer and preserve both writes.
	concID, _, concHeaders := enrollMonitorTestServer(t, p, "conc-srv")
	concExp := time.Now().UTC().Add(-time.Hour).Truncate(24 * time.Hour)
	if code, _, _ := p.do("PATCH", "/api/servers/"+concID, map[string]any{
		"name":         "conc-srv",
		"roles":        []string{"exit"},
		"country":      "JP",
		"ipv4":         "203.0.113.10",
		"expiresAt":    concExp.Format(time.RFC3339),
		"billingCycle": "month",
		"autoRenew":    true,
	}, nil); code != 200 {
		t.Fatalf("patch conc-srv: %d", code)
	}
	setLastSeen(concID, time.Now().UTC())

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			_, _, _ = p.do("POST", "/agent/report", shared.AgentReport{
				OS:           "Debian 13",
				Arch:         "amd64",
				AgentVersion: fmt.Sprintf("0.6.31-r%d", i),
				HostMonitor:  true,
			}, concHeaders)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			p.app.autoRenewServers(time.Now().UTC())
		}
	}()
	wg.Wait()

	finalConc, err := p.store.Server(concID)
	if err != nil {
		t.Fatal(err)
	}
	if !finalConc.ExpiresAt.After(time.Now().UTC()) {
		t.Fatalf("expected conc-srv ExpiresAt to remain renewed in the future, got %v", finalConc.ExpiresAt)
	}
	if !strings.HasPrefix(finalConc.AgentVersion, "0.6.31-r") || !finalConc.HostMonitor {
		t.Fatalf("expected concurrent AgentReport fields to be preserved, got version=%q hostMonitor=%v", finalConc.AgentVersion, finalConc.HostMonitor)
	}
}

func TestAutoRenewStaleOnlineFallsBackToNormalExpiryWarnings(t *testing.T) {
	p := newTestMui(t)
	sink := setupTelegramRecorder(t, p, map[string]any{
		"serverOffline":  map[string]any{"enabled": false, "offlineMinutes": 3},
		"serverExpiring": map[string]any{"enabled": true},
		"serverRenewed":  map[string]any{"enabled": true},
	})

	// Server A: online-managed, autoRenew=true, LastSeen=nil (never reported).
	code, outA, _ := p.do("POST", "/api/servers", map[string]any{
		"name":         "never-seen-autorenew",
		"roles":        []string{"exit"},
		"country":      "US",
		"ipv4":         "203.0.113.111",
		"expiresAt":    "2026-06-10T00:00:00Z",
		"billingCycle": "month",
		"autoRenew":    true,
	}, nil)
	if code != 201 {
		t.Fatalf("create never-seen: %d %v", code, outA)
	}

	// Server B: online-managed, autoRenew=true, LastSeen > 24h ago.
	code, outB, _ := p.do("POST", "/api/servers", map[string]any{
		"name":         "stale-seen-autorenew",
		"roles":        []string{"exit"},
		"country":      "DE",
		"ipv4":         "203.0.113.112",
		"expiresAt":    "2026-06-10T00:00:00Z",
		"billingCycle": "month",
		"autoRenew":    true,
	}, nil)
	if code != 201 {
		t.Fatalf("create stale-seen: %d %v", code, outB)
	}
	staleID := outB["server"].(map[string]any)["id"].(string)

	// At 5 days before expiry: stale LastSeen (30h old) and nil LastSeen must emit normal 7-day warning!
	t5d := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	srvB, _ := p.store.Server(staleID)
	seen30hAgo := t5d.Add(-30 * time.Hour)
	srvB.LastSeen = &seen30hAgo
	_ = p.store.PutServer(srvB)

	p.app.evaluateAlertsAt(t5d)
	_ = p.app.FlushTelegramForTest(2 * time.Second)
	msgs := sink.take()
	if len(msgs) != 2 {
		t.Fatalf("expected 2 normal 7-day expiry warnings for nil/stale online servers, got %d: %v", len(msgs), msgs)
	}
	for _, m := range msgs {
		if strings.Contains(m, "即将自动续期") || !strings.Contains(m, "[MUI] 服务器即将到期") {
			t.Fatalf("expected normal expiry warning instead of auto-renew notice, got %q", m)
		}
	}

	// At 2 days before expiry (< 3d): still offline >24h -> must emit normal 3-day warning, NOT "即将自动续期"!
	t2d := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	p.app.evaluateAlertsAt(t2d)
	_ = p.app.FlushTelegramForTest(2 * time.Second)
	msgs = sink.take()
	if len(msgs) != 2 {
		t.Fatalf("expected 2 normal 3-day expiry warnings, got %d: %v", len(msgs), msgs)
	}
	for _, m := range msgs {
		if strings.Contains(m, "即将自动续期") || !strings.Contains(m, "[MUI] 服务器即将到期") {
			t.Fatalf("expected normal 3-day expiry warning instead of auto-renew notice, got %q", m)
		}
	}
}

func TestServerPatchStaleDialogPreservesAutoRenewedExpiry(t *testing.T) {
	p := newTestMui(t)

	code, created, _ := p.do("POST", "/api/servers", map[string]any{
		"name":           "patch-race-srv",
		"managementMode": "offline",
		"firewallMode":   "manual",
		"roles":          []string{"entry"},
		"country":        "SG",
		"ipv4":           "203.0.113.120",
		"expiresAt":      "2026-01-31T00:00:00Z",
		"billingCycle":   "month",
		"autoRenew":      true,
	}, nil)
	if code != 201 {
		t.Fatalf("create server: %d %v", code, created)
	}
	id := created["server"].(map[string]any)["id"].(string)

	// User opens edit modal when expiresAt is 2026-01-31T00:00:00Z.
	// Before user clicks Save, autoRenew runs on Jan 31 and advances expiresAt to 2026-02-28T00:00:00Z (anchor 31).
	p.app.autoRenewServers(time.Date(2026, 1, 31, 1, 0, 0, 0, time.UTC))

	// User edits notes in the stale modal without changing expiresAt (expiresAt == initialExpiresAt).
	code, patched, _ := p.do("PATCH", "/api/servers/"+id, map[string]any{
		"name":             "patch-race-srv",
		"managementMode":   "offline",
		"firewallMode":     "manual",
		"roles":            []string{"entry"},
		"country":          "SG",
		"ipv4":             "203.0.113.120",
		"notes":            "edited while modal was open",
		"expiresAt":        "2026-01-31T00:00:00Z",
		"initialExpiresAt": "2026-01-31T00:00:00Z",
		"billingCycle":     "month",
		"autoRenew":        true,
	}, nil)
	if code != 200 {
		t.Fatalf("PATCH stale modal: %d %v", code, patched)
	}
	srv, err := p.store.Server(id)
	if err != nil {
		t.Fatal(err)
	}
	if srv.Notes != "edited while modal was open" {
		t.Fatalf("expected notes update to be saved, got %q", srv.Notes)
	}
	if got := srv.ExpiresAt.UTC().Format("2006-01-02"); got != "2026-02-28" {
		t.Fatalf("stale modal overwrote auto-renewed expiresAt: got %s, want 2026-02-28", got)
	}
	if srv.BillingAnchorDay != 31 {
		t.Fatalf("expected BillingAnchorDay=31 to be preserved, got %d", srv.BillingAnchorDay)
	}

	// Conversely, if the user explicitly changes expiresAt in the modal (expiresAt != initialExpiresAt), the new value takes effect!
	code, patched2, _ := p.do("PATCH", "/api/servers/"+id, map[string]any{
		"name":             "patch-race-srv",
		"managementMode":   "offline",
		"firewallMode":     "manual",
		"roles":            []string{"entry"},
		"country":          "SG",
		"ipv4":             "203.0.113.120",
		"expiresAt":        "2026-05-15T00:00:00Z",
		"initialExpiresAt": "2026-01-31T00:00:00Z",
		"billingCycle":     "month",
		"autoRenew":        true,
	}, nil)
	if code != 200 {
		t.Fatalf("PATCH explicit expiresAt change: %d %v", code, patched2)
	}
	srv2, _ := p.store.Server(id)
	if got := srv2.ExpiresAt.UTC().Format("2006-01-02"); got != "2026-05-15" || srv2.BillingAnchorDay != 15 {
		t.Fatalf("expected explicit expiresAt=2026-05-15 and anchor=15, got %s anchor=%d", got, srv2.BillingAnchorDay)
	}
}

func TestManualRenewLogsAndSucceedsWhenCycleRecalcFails(t *testing.T) {
	p := newTestMui(t)
	now := time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)
	p.app.monitorNow = func() time.Time { return now }

	code, created, _ := p.do("POST", "/api/servers", map[string]any{
		"name":             "renew-recalc-err",
		"managementMode":   "offline",
		"firewallMode":     "manual",
		"roles":            []string{"entry"},
		"country":          "JP",
		"ipv4":             "203.0.113.130",
		"expiresAt":        "2026-01-15T00:00:00Z",
		"billingCycle":     "days",
		"billingCycleDays": 10,
	}, nil)
	if code != 201 {
		t.Fatalf("create server: %d %v", code, created)
	}
	id := created["server"].(map[string]any)["id"].(string)

	// Force RecalcServerCurrentCycleTraffic to fail after PutServer succeeds.
	if _, err := p.store.DB.Exec(`DROP TABLE mui_server_cycle_traffic`); err != nil {
		t.Fatal(err)
	}

	var logBuf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(origOut)

	code, renewed, _ := p.do("POST", "/api/servers/"+id+"/renew", nil, nil)
	if code != 200 {
		t.Fatalf("expected manual renew to return 200 even when cycle recalc fails, got %d %v", code, renewed)
	}
	srv, _ := p.store.Server(id)
	if got := srv.ExpiresAt.UTC().Format("2006-01-02"); got != "2026-01-25" {
		t.Fatalf("expected renewed expiresAt=2026-01-25, got %s", got)
	}
	if !strings.Contains(logBuf.String(), "recalc server") {
		t.Fatalf("expected recalc failure to be logged, got %q", logBuf.String())
	}
}

func TestEvaluateAlertsSingleServersReadUnlessAutoRenewed(t *testing.T) {
	p := newTestMui(t)
	setupTelegramRecorder(t, p, nil)

	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	futureExp := now.Add(15 * 24 * time.Hour)
	code, created, _ := p.do("POST", "/api/servers", map[string]any{
		"name":           "Reuse-List-Node",
		"managementMode": "external",
		"firewallMode":   "manual",
		"roles":          []string{"exit"},
		"country":        "US",
		"ipv4":           "203.0.113.88",
		"autoRenew":      true,
		"billingCycle":   "month",
		"expiresAt":      futureExp.Format(time.RFC3339),
	}, nil)
	if code != 201 {
		t.Fatalf("create server: %d %v", code, created)
	}
	srvID := created["server"].(map[string]any)["id"].(string)

	// 1. No renewal happens -> evaluateAlertsAt must read Store.Servers() only once.
	beforeNoRenew := p.store.serversCalls.Load()
	p.app.evaluateAlertsAt(now)
	_ = p.app.FlushTelegramForTest(2 * time.Second)
	if got := p.store.serversCalls.Load() - beforeNoRenew; got != 1 {
		t.Fatalf("expected 1 Store.Servers() call when no server auto-renewed, got %d", got)
	}

	// 2. Server expires and auto-renews -> evaluateAlertsAt re-reads Store.Servers() once (total 2 calls).
	pastExp := now.Add(-time.Hour)
	srv, err := p.store.Server(srvID)
	if err != nil {
		t.Fatal(err)
	}
	srv.ExpiresAt = &pastExp
	if err := p.store.PutServer(srv); err != nil {
		t.Fatal(err)
	}

	beforeRenew := p.store.serversCalls.Load()
	p.app.evaluateAlertsAt(now)
	_ = p.app.FlushTelegramForTest(2 * time.Second)
	if got := p.store.serversCalls.Load() - beforeRenew; got != 2 {
		t.Fatalf("expected 2 Store.Servers() calls when auto-renewal occurred, got %d", got)
	}
}
