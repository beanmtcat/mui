package server

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"mui/internal/shared"
)

type capturedTelegramCall struct {
	Path string
	Body map[string]any
}

type mockTelegramServer struct {
	srv   *httptest.Server
	mu    sync.Mutex
	calls []capturedTelegramCall
	reply func(callIndex int, path string, body map[string]any, w http.ResponseWriter)
}

func newMockTelegram(t *testing.T) *mockTelegramServer {
	t.Helper()
	prevInsecure := testAllowInsecureTelegramAPI
	testAllowInsecureTelegramAPI = true
	t.Cleanup(func() { testAllowInsecureTelegramAPI = prevInsecure })

	m := &mockTelegramServer{}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)

		m.mu.Lock()
		idx := len(m.calls)
		m.calls = append(m.calls, capturedTelegramCall{Path: r.URL.Path, Body: body})
		reply := m.reply
		m.mu.Unlock()

		if reply != nil {
			reply(idx, r.URL.Path, body, w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":1}}`))
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockTelegramServer) takeCalls() []capturedTelegramCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]capturedTelegramCall, len(m.calls))
	copy(out, m.calls)
	m.calls = nil
	return out
}

func (m *mockTelegramServer) allCalls() []capturedTelegramCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]capturedTelegramCall, len(m.calls))
	copy(out, m.calls)
	return out
}

func TestTelegramSettingsTokenSecurityAndValidation(t *testing.T) {
	p := newTestMui(t)
	t.Cleanup(p.app.CloseTelegram)

	var logBuf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(origOut) })

	const secretToken = "99887766:SecretBotToken_NeverLeak123"

	// Production mode rejects plain http, userinfo, query, and fragment on apiBase.
	for _, badBase := range []string{
		"http://api.telegram.example",
		"https://user:pass@api.telegram.example",
		"https://api.telegram.example?x=1",
		"https://api.telegram.example#frag",
	} {
		code, _, _ := p.do("PUT", "/api/settings/telegram", map[string]any{
			"enabled":  false,
			"botToken": secretToken,
			"chatId":   "-1001234567890",
			"apiBase":  badBase,
		}, nil)
		if code != 400 {
			t.Fatalf("expected 400 for apiBase %q, got %d", badBase, code)
		}
	}

	// Invalid chatId and invalid offlineMinutes are rejected.
	if code, _, _ := p.do("PUT", "/api/settings/telegram", map[string]any{
		"enabled": false,
		"chatId":  "not-a-valid-chat",
	}, nil); code != 400 {
		t.Fatalf("expected 400 for bad chatId, got %d", code)
	}
	if code, _, _ := p.do("PUT", "/api/settings/telegram", map[string]any{
		"enabled": false,
		"events": map[string]any{
			"serverOffline": map[string]any{"enabled": true, "offlineMinutes": 1},
		},
	}, nil); code != 400 {
		t.Fatalf("expected 400 for offlineMinutes=1, got %d", code)
	}

	tg := newMockTelegram(t)

	// Save full settings with Bot Token.
	code, saved, _ := p.do("PUT", "/api/settings/telegram", map[string]any{
		"enabled":  true,
		"botToken": secretToken,
		"chatId":   "-100987654321",
		"threadId": 42,
		"apiBase":  tg.srv.URL,
	}, nil)
	if code != 200 || saved["botTokenSet"] != true {
		t.Fatalf("save telegram settings: %d %v", code, saved)
	}
	if strings.Contains(Marshal(saved), secretToken) {
		t.Fatalf("PUT response leaked bot token: %v", saved)
	}

	// Stored value in mui_settings must be encrypted, never plaintext.
	var rawSetting string
	if err := p.store.DB.QueryRow(`SELECT value FROM mui_settings WHERE key='telegram'`).Scan(&rawSetting); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rawSetting, secretToken) {
		t.Fatalf("mui_settings stored plaintext bot token: %s", rawSetting)
	}

	// GET never echoes botToken.
	code, got, _ := p.do("GET", "/api/settings/telegram", nil, nil)
	if code != 200 || got["botTokenSet"] != true || strings.Contains(Marshal(got), secretToken) {
		t.Fatalf("GET /api/settings/telegram leaked or lost token state: %d %v", code, got)
	}

	// PUT omitting botToken preserves the existing encrypted token.
	code, got2, _ := p.do("PUT", "/api/settings/telegram", map[string]any{
		"enabled":  true,
		"chatId":   "@valid_channel_name",
		"threadId": 42,
		"apiBase":  tg.srv.URL,
	}, nil)
	if code != 200 || got2["botTokenSet"] != true {
		t.Fatalf("PUT omitting botToken did not preserve token: %d %v", code, got2)
	}

	// POST /api/settings/telegram/test uses the preserved token, sends plain text (no parse_mode) and threadId.
	code, testOut, _ := p.do("POST", "/api/settings/telegram/test", nil, nil)
	if code != 200 || testOut["ok"] != true {
		t.Fatalf("telegram test send failed: %d %v", code, testOut)
	}
	calls := tg.takeCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 telegram call, got %d", len(calls))
	}
	if calls[0].Path != "/bot"+secretToken+"/sendMessage" {
		t.Fatalf("unexpected request path: %s", calls[0].Path)
	}
	if _, hasParseMode := calls[0].Body["parse_mode"]; hasParseMode {
		t.Fatalf("parse_mode must not be set: %v", calls[0].Body)
	}
	if calls[0].Body["disable_web_page_preview"] != true || calls[0].Body["message_thread_id"] != float64(42) {
		t.Fatalf("unexpected payload fields: %v", calls[0].Body)
	}

	// Error paths: Telegram returning description with token/URL, and connection failure after server closes.
	tg.reply = func(_ int, _ string, _ map[string]any, w http.ResponseWriter) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"ok":false,"description":"Bad Request: chat not found at ` + tg.srv.URL + `/bot` + secretToken + `"}`))
	}
	code, errOut, _ := p.do("POST", "/api/settings/telegram/test", nil, nil)
	if code != 502 {
		t.Fatalf("expected 502 on Telegram API error, got %d %v", code, errOut)
	}
	if strings.Contains(Marshal(errOut), secretToken) || strings.Contains(Marshal(errOut), tg.srv.URL) {
		t.Fatalf("error response leaked token or URL: %v", errOut)
	}

	tg.srv.Close()
	code, connErrOut, _ := p.do("POST", "/api/settings/telegram/test", nil, nil)
	if code != 502 || connErrOut["error"] != "连接失败" {
		t.Fatalf("expected sanitized 连接失败 on network error, got %d %v", code, connErrOut)
	}
	if strings.Contains(Marshal(connErrOut), secretToken) || strings.Contains(Marshal(connErrOut), "http") {
		t.Fatalf("network error leaked URL or token: %v", connErrOut)
	}

	// PUT with empty string clears Bot Token when disabled.
	code, cleared, _ := p.do("PUT", "/api/settings/telegram", map[string]any{
		"enabled":  false,
		"botToken": "",
	}, nil)
	if code != 200 || cleared["botTokenSet"] != false {
		t.Fatalf("clearing botToken failed: %d %v", code, cleared)
	}

	// Audit entries and server logs must never contain the token.
	var auditDump string
	rows, err := p.store.DB.Query(`SELECT action,target,detail FROM mui_audit`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var a, tgt, d string
		if err := rows.Scan(&a, &tgt, &d); err != nil {
			t.Fatal(err)
		}
		auditDump += a + "|" + tgt + "|" + d + "\n"
	}
	if strings.Contains(auditDump, secretToken) {
		t.Fatalf("audit log leaked bot token: %s", auditDump)
	}
	if strings.Contains(logBuf.String(), secretToken) {
		t.Fatalf("server log leaked bot token: %s", logBuf.String())
	}

	// Overlong multi-byte message truncates cleanly at 3500 runes without invalid UTF-8.
	longChinese := strings.Repeat("告警测试字符", 800) // 4800 runes
	truncated := truncateRunes(longChinese, telegramMaxMessageRunes)
	if !utf8.ValidString(truncated) || utf8.RuneCountInString(truncated) != telegramMaxMessageRunes {
		t.Fatalf("unexpected truncated rune count=%d valid=%v", utf8.RuneCountInString(truncated), utf8.ValidString(truncated))
	}
}

func configureTelegramForTest(t *testing.T, p *testMui, apiBase string, events map[string]any) {
	t.Helper()
	body := map[string]any{
		"enabled":  true,
		"botToken": "123456:TestBotTokenXYZ",
		"chatId":   "-10011223344",
		"apiBase":  apiBase,
	}
	if events != nil {
		body["events"] = events
	}
	code, out, _ := p.do("PUT", "/api/settings/telegram", body, nil)
	if code != 200 {
		t.Fatalf("configure telegram: %d %v", code, out)
	}
	if !p.app.FlushTelegramForTest(2 * time.Second) {
		t.Fatal("flush telegram queue timed out")
	}
}

func TestTelegramServerOfflineLifecycleGraceAndUpgrade(t *testing.T) {
	p := newTestMui(t)
	t.Cleanup(p.app.CloseTelegram)
	tg := newMockTelegram(t)
	configureTelegramForTest(t, p, tg.srv.URL, nil)
	_ = tg.takeCalls()

	base := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	lastSeen := base.Add(-5 * time.Minute)
	onlineSrv := shared.Server{
		ID:             ID(),
		Name:           "tokyo-1",
		Country:        "JP",
		City:           "东京",
		ManagementMode: "online",
		Roles:          []string{shared.RoleExit},
		Status:         "online",
		LastSeen:       &lastSeen,
	}
	offlineManagedSrv := shared.Server{
		ID:             ID(),
		Name:           "offline-managed",
		Country:        "SG",
		ManagementMode: "offline",
		Roles:          []string{shared.RoleEntry},
		LastSeen:       &lastSeen,
	}
	neverSeenSrv := shared.Server{
		ID:             ID(),
		Name:           "pending-srv",
		Country:        "US",
		ManagementMode: "online",
		Roles:          []string{shared.RoleExit},
	}
	for _, s := range []shared.Server{onlineSrv, offlineManagedSrv, neverSeenSrv} {
		if _, err := p.store.DB.Exec(`INSERT INTO mui_servers(id,data) VALUES($1,$2)`, s.ID, Marshal(s)); err != nil {
			t.Fatal(err)
		}
	}

	// 1. Within panel startup grace period (offlineMinutes + 1 = 4 min): must NOT alert.
	p.app.startedAt = base.Add(-3 * time.Minute)
	p.app.evaluateAlertsAt(base)
	p.app.FlushTelegramForTest(2 * time.Second)
	if got := tg.takeCalls(); len(got) != 0 {
		t.Fatalf("expected 0 alerts during startup grace period, got %d: %v", len(got), got)
	}

	// 2. Past grace period, but server has an active agent.upgrade (activating): must NOT alert.
	p.app.startedAt = base.Add(-10 * time.Minute)
	upOp := shared.Operation{
		ID:        ID(),
		ServerID:  onlineSrv.ID,
		Kind:      "agent.upgrade",
		Status:    "activating",
		CreatedAt: base,
		UpdatedAt: base,
	}
	if err := p.store.PutOperation(upOp, shared.DesiredState{}); err != nil {
		t.Fatal(err)
	}
	p.app.evaluateAlertsAt(base)
	p.app.FlushTelegramForTest(2 * time.Second)
	if got := tg.takeCalls(); len(got) != 0 {
		t.Fatalf("expected 0 alerts while agent.upgrade is activating, got %d", len(got))
	}

	// Finish the upgrade so the server is eligible for offline detection.
	if err := p.store.FinishJob(upOp.ID, "success", ""); err != nil {
		t.Fatal(err)
	}

	// 3. Server offline -> alerts exactly once.
	p.app.evaluateAlertsAt(base)
	p.app.FlushTelegramForTest(2 * time.Second)
	calls := tg.takeCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 offline alert, got %d", len(calls))
	}
	msg, _ := calls[0].Body["text"].(string)
	if !strings.Contains(msg, "[MUI] 服务器离线") || !strings.Contains(msg, "tokyo-1（JP · 东京）") {
		t.Fatalf("unexpected offline alert text: %s", msg)
	}

	// 4. Stays offline across repeated evaluations AND simulated panel restart -> no duplicate alert.
	p.app.evaluateAlertsAt(base.Add(2 * time.Minute))
	p.app.FlushTelegramForTest(2 * time.Second)
	if got := tg.takeCalls(); len(got) != 0 {
		t.Fatalf("expected 0 duplicate alerts while still offline, got %d", len(got))
	}

	restartedApp, err := NewApp(p.store, "https://mui.example.test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restartedApp.CloseTelegram)
	restartedApp.startedAt = base.Add(-20 * time.Minute)
	restartedApp.evaluateAlertsAt(base.Add(6 * time.Minute))
	restartedApp.FlushTelegramForTest(2 * time.Second)
	if got := tg.takeCalls(); len(got) != 0 {
		t.Fatalf("expected 0 duplicate alerts after panel restart, got %d", len(got))
	}

	// 5. Server reports back -> sends recovery notification once, then stays quiet.
	recoveredAt := base.Add(10 * time.Minute)
	onlineSrv.LastSeen = &recoveredAt
	if err := p.store.PutServer(onlineSrv); err != nil {
		t.Fatal(err)
	}
	restartedApp.evaluateAlertsAt(recoveredAt.Add(10 * time.Second))
	restartedApp.FlushTelegramForTest(2 * time.Second)
	recCalls := tg.takeCalls()
	if len(recCalls) != 1 {
		t.Fatalf("expected 1 recovery alert, got %d", len(recCalls))
	}
	recText, _ := recCalls[0].Body["text"].(string)
	if !strings.Contains(recText, "已恢复，离线了 15 分钟") {
		t.Fatalf("unexpected recovery text: %s", recText)
	}

	restartedApp.evaluateAlertsAt(recoveredAt.Add(30 * time.Second))
	restartedApp.FlushTelegramForTest(2 * time.Second)
	if got := tg.takeCalls(); len(got) != 0 {
		t.Fatalf("expected 0 duplicate recovery alerts, got %d", len(got))
	}
}

func TestTelegramRetry429AndRateLimitCoalescing(t *testing.T) {
	origDelays := telegramRetryDelays
	origMaxRetry := telegramMaxRetryAfter
	origWindow := telegramRateWindow
	origMaxPerMin := telegramMaxPerMinute
	telegramRetryDelays = []time.Duration{5 * time.Millisecond, 10 * time.Millisecond, 15 * time.Millisecond}
	telegramMaxRetryAfter = 20 * time.Millisecond
	telegramRateWindow = 10 * time.Second
	telegramMaxPerMinute = 20
	t.Cleanup(func() {
		telegramRetryDelays = origDelays
		telegramMaxRetryAfter = origMaxRetry
		telegramRateWindow = origWindow
		telegramMaxPerMinute = origMaxPerMin
	})

	p := newTestMui(t)
	t.Cleanup(p.app.CloseTelegram)
	tg := newMockTelegram(t)
	configureTelegramForTest(t, p, tg.srv.URL, nil)
	_ = tg.takeCalls()

	// 1. 429 retry_after + transient 500s -> retries 3 times and succeeds on 4th attempt.
	var attempts int
	tg.reply = func(_ int, _ string, _ map[string]any, w http.ResponseWriter) {
		attempts++
		w.Header().Set("Content-Type", "application/json")
		switch attempts {
		case 1:
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"ok":false,"error_code":429,"description":"Too Many Requests","parameters":{"retry_after":1}}`))
		case 2, 3:
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"ok":false,"description":"upstream error"}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
		}
	}
	p.app.notify("applyFailed", "op-retry", "[MUI] 操作执行失败\n重试测试")
	if !p.app.FlushTelegramForTest(3 * time.Second) {
		t.Fatal("flush timed out during retry test")
	}
	if got := len(tg.takeCalls()); got != 4 {
		t.Fatalf("expected 4 HTTP attempts (1 initial + 3 retries), got %d", got)
	}

	// 2. Rate-limit coalescing: reset window history, enqueue 25 applyFailed messages at once.
	tg.reply = nil
	p.app.tgMu.Lock()
	p.app.tgSentTimes = nil
	// Hold sender briefly by enqueueing under lock? No need: enqueue 25 while temporarily pausing via reply barrier on #1.
	p.app.tgMu.Unlock()

	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	var once sync.Once
	tg.reply = func(_ int, _ string, _ map[string]any, w http.ResponseWriter) {
		once.Do(func() {
			close(firstStarted)
			<-releaseFirst
		})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}

	p.app.notify("applyFailed", "burst-0", "[MUI] 操作执行失败 #0")
	<-firstStarted
	for i := 1; i < 25; i++ {
		p.app.notify("applyFailed", "burst", "[MUI] 操作执行失败")
	}
	close(releaseFirst)

	if !p.app.FlushTelegramForTest(3 * time.Second) {
		t.Fatal("flush timed out during rate-limit coalescing test")
	}
	burstCalls := tg.takeCalls()
	if len(burstCalls) != 20 {
		t.Fatalf("expected rate limiter to cap sends at 20 per window, got %d", len(burstCalls))
	}
	lastText, _ := burstCalls[19].Body["text"].(string)
	if !strings.Contains(lastText, "另有 5 条同类告警") {
		t.Fatalf("expected 20th message to coalesce remaining 5 alerts, got: %s", lastText)
	}
}

func TestTelegramCertAndSubscriptionExpiringAndCleanup(t *testing.T) {
	p := newTestMui(t)
	t.Cleanup(p.app.CloseTelegram)
	tg := newMockTelegram(t)
	configureTelegramForTest(t, p, tg.srv.URL, map[string]any{
		"subscriptionExpiring": map[string]any{"enabled": true},
	})
	_ = tg.takeCalls()

	exp := time.Date(2026, 12, 20, 12, 0, 0, 0, time.UTC)
	cert := shared.Certificate{
		ID:        ID(),
		Name:      "edge-cert",
		Domain:    "edge.example.com",
		ExpiresAt: exp,
	}
	if _, err := p.store.DB.Exec(`INSERT INTO mui_certificates(id,data,secret) VALUES($1,$2,'')`, cert.ID, Marshal(cert)); err != nil {
		t.Fatal(err)
	}

	// >30 days remaining: 0 reminders.
	p.app.evaluateAlertsAt(exp.Add(-35 * 24 * time.Hour))
	p.app.FlushTelegramForTest(2 * time.Second)
	if got := len(tg.takeCalls()); got != 0 {
		t.Fatalf("expected 0 cert alerts at 35d, got %d", got)
	}

	// Stage 1: enters <=30d threshold (25d) -> 1st reminder; 10d -> 0 reminders.
	p.app.evaluateAlertsAt(exp.Add(-25 * 24 * time.Hour))
	p.app.evaluateAlertsAt(exp.Add(-10 * 24 * time.Hour))
	p.app.FlushTelegramForTest(2 * time.Second)
	if got := len(tg.takeCalls()); got != 1 {
		t.Fatalf("expected 1 cert alert entering 30d window, got %d", got)
	}

	// Stage 2: <=3d (3d) -> 2nd reminder; 2d -> 0 reminders.
	p.app.evaluateAlertsAt(exp.Add(-3 * 24 * time.Hour))
	p.app.evaluateAlertsAt(exp.Add(-2 * 24 * time.Hour))
	p.app.FlushTelegramForTest(2 * time.Second)
	if got := len(tg.takeCalls()); got != 1 {
		t.Fatalf("expected 1 cert alert at 3d, got %d", got)
	}

	// Stage 3: <=1d (1d) -> 3rd reminder; 0d and -2d -> 0 reminders (max 3 total for same expiry date).
	p.app.evaluateAlertsAt(exp.Add(-24 * time.Hour))
	p.app.evaluateAlertsAt(exp.Add(-2 * time.Hour))
	p.app.evaluateAlertsAt(exp.Add(48 * time.Hour))
	p.app.FlushTelegramForTest(2 * time.Second)
	if got := len(tg.takeCalls()); got != 1 {
		t.Fatalf("expected 1 final cert alert at <=1d, got %d", got)
	}

	// Deleting the certificate cleans up its mui_alert_state rows.
	if code, _, _ := p.do("DELETE", "/api/certificates/"+cert.ID, nil, nil); code != 200 {
		t.Fatalf("delete cert: %d", code)
	}
	var certStateCount int
	if err := p.store.DB.QueryRow(`SELECT COUNT(*) FROM mui_alert_state WHERE key LIKE 'certExpiring:%'`).Scan(&certStateCount); err != nil || certStateCount != 0 {
		t.Fatalf("expected cert alert state rows cleaned up, got count=%d err=%v", certStateCount, err)
	}

	// Subscription expiring: <3d reminds once, expired reminds once, never leaks token.
	subExp := time.Date(2026, 12, 10, 0, 0, 0, 0, time.UTC)
	subToken := "super-secret-sub-download-token"
	sub := shared.Subscription{
		ID:        ID(),
		Name:      "VIP-Alice",
		Format:    "surge",
		Enabled:   true,
		ExpiresAt: &subExp,
	}
	sealedTok, err := p.store.Encrypt(subToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.store.DB.Exec(`INSERT INTO mui_subscriptions(id,data,token_hash,token_enc) VALUES($1,$2,$3,$4)`, sub.ID, Marshal(sub), Hash(subToken), sealedTok); err != nil {
		t.Fatal(err)
	}

	p.app.evaluateAlertsAt(subExp.Add(-48 * time.Hour))
	p.app.evaluateAlertsAt(subExp.Add(-24 * time.Hour))
	p.app.FlushTelegramForTest(2 * time.Second)
	soonCalls := tg.takeCalls()
	if len(soonCalls) != 1 || strings.Contains(Marshal(soonCalls), subToken) {
		t.Fatalf("expected 1 soon subscription alert without token, got %v", soonCalls)
	}

	p.app.evaluateAlertsAt(subExp.Add(time.Hour))
	p.app.evaluateAlertsAt(subExp.Add(5 * time.Hour))
	p.app.FlushTelegramForTest(2 * time.Second)
	expCalls := tg.takeCalls()
	if len(expCalls) != 1 || strings.Contains(Marshal(expCalls), subToken) {
		t.Fatalf("expected 1 expired subscription alert without token, got %v", expCalls)
	}

	// PruneAlertState removes old sent/resolved rows.
	if err := p.store.PruneAlertState(subExp.Add(10 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	var remaining int
	if err := p.store.DB.QueryRow(`SELECT COUNT(*) FROM mui_alert_state`).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("expected PruneAlertState to clean old sent rows, remaining=%d err=%v", remaining, err)
	}
}

func TestTelegramApplyFailedAndSecurityEvents(t *testing.T) {
	p := newTestMui(t)
	t.Cleanup(p.app.CloseTelegram)
	tg := newMockTelegram(t)
	configureTelegramForTest(t, p, tg.srv.URL, nil)
	_ = tg.takeCalls()

	// 1. Admin login & password change emit security alerts without leaking password or session cookie.
	newPass := "another-very-strong-password-123"
	if code, _, _ := p.do("POST", "/api/password", map[string]string{"current": testPassword, "new": newPass}, nil); code != 200 {
		t.Fatalf("change password: %d", code)
	}
	code, _, newCookie := p.do("POST", "/api/login", map[string]string{"password": newPass}, nil)
	if code != 200 || newCookie == nil {
		t.Fatalf("re-login: %d", code)
	}
	p.cookie = newCookie
	p.app.FlushTelegramForTest(2 * time.Second)
	secCalls := tg.takeCalls()
	if len(secCalls) != 2 {
		t.Fatalf("expected 2 security alerts (password change + login), got %d", len(secCalls))
	}
	if dump := Marshal(secCalls); strings.Contains(dump, newPass) || strings.Contains(dump, newCookie.Value) {
		t.Fatalf("security alert leaked credentials: %s", dump)
	}

	// 2. MUI_ADMIN_RESET=1 on startup emits security alert.
	t.Setenv("MUI_ADMIN_PASSWORD", testPassword)
	t.Setenv("MUI_ADMIN_RESET", "1")
	resetApp, err := NewApp(p.store, "https://mui.example.test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(resetApp.CloseTelegram)
	resetApp.FlushTelegramForTest(2 * time.Second)
	t.Setenv("MUI_ADMIN_RESET", "")
	resetCalls := tg.takeCalls()
	if len(resetCalls) != 1 || !strings.Contains(Marshal(resetCalls), "MUI_ADMIN_RESET") {
		t.Fatalf("expected MUI_ADMIN_RESET security alert, got %v", resetCalls)
	}

	// Re-login after reset.
	code, _, c := p.do("POST", "/api/login", map[string]string{"password": testPassword}, nil)
	if code != 200 || c == nil {
		t.Fatalf("login after reset: %d", code)
	}
	p.cookie = c
	p.app.FlushTelegramForTest(2 * time.Second)
	_ = tg.takeCalls()

	// 3. applyFailed via /agent/report truncates op.Error to 500 runes.
	code, created, _ := p.do("POST", "/api/servers", map[string]any{
		"name": "sg-node-1", "roles": []string{"exit"}, "country": "SG", "ipv4": "8.8.8.8",
	}, nil)
	if code != 201 {
		t.Fatalf("create server: %d", code)
	}
	srvID := created["server"].(map[string]any)["id"].(string)
	code, enrolled, _ := p.do("POST", "/agent/enroll", map[string]string{
		"serverId": srvID, "token": created["enrollToken"].(string),
	}, nil)
	if code != 200 {
		t.Fatalf("enroll: %d", code)
	}
	agentHdr := map[string]string{"X-Server-ID": srvID, "Authorization": "Bearer " + enrolled["agentToken"].(string)}

	op := shared.Operation{
		ID: ID(), ServerID: srvID, Kind: "nodes.apply", Status: "queued",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := p.store.PutOperation(op, shared.DesiredState{}); err != nil {
		t.Fatal(err)
	}
	code, jobOut, _ := p.do("GET", "/agent/job", nil, agentHdr)
	if code != 200 {
		t.Fatalf("claim job: %d %v", code, jobOut)
	}

	longErr := strings.Repeat("错误详情", 200) // 800 runes
	code, repOut, _ := p.do("POST", "/agent/report", map[string]any{
		"jobId": op.ID, "jobStatus": "failed", "jobError": longErr,
	}, agentHdr)
	if code != 200 {
		t.Fatalf("report failed job: %d %v", code, repOut)
	}
	p.app.FlushTelegramForTest(2 * time.Second)
	failCalls := tg.takeCalls()
	if len(failCalls) != 1 {
		t.Fatalf("expected 1 applyFailed alert, got %d", len(failCalls))
	}
	failText, _ := failCalls[0].Body["text"].(string)
	if !strings.Contains(failText, "nodes.apply") || strings.Contains(failText, longErr) {
		t.Fatalf("expected applyFailed text with truncated op.Error, got len=%d", utf8.RuneCountInString(failText))
	}
}

func TestTelegramStatefulExpiryRequeuesOnFailureAndDeliversOnce(t *testing.T) {
	origDelays := telegramRetryDelays
	telegramRetryDelays = []time.Duration{2 * time.Millisecond, 2 * time.Millisecond, 2 * time.Millisecond}
	t.Cleanup(func() { telegramRetryDelays = origDelays })

	p := newTestMui(t)
	t.Cleanup(p.app.CloseTelegram)
	tg := newMockTelegram(t)
	configureTelegramForTest(t, p, tg.srv.URL, nil)
	_ = tg.takeCalls()

	exp := time.Date(2026, 12, 1, 12, 0, 0, 0, time.UTC)
	cert := shared.Certificate{
		ID:        ID(),
		Name:      "recover-cert",
		Domain:    "recover.example.com",
		ExpiresAt: exp,
	}
	if _, err := p.store.DB.Exec(`INSERT INTO mui_certificates(id,data,secret) VALUES($1,$2,'')`, cert.ID, Marshal(cert)); err != nil {
		t.Fatal(err)
	}

	// Telegram fails every attempt during the first 2 evaluation rounds.
	tg.reply = func(_ int, _ string, _ map[string]any, w http.ResponseWriter) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"ok":false,"description":"upstream unavailable"}`))
	}

	// Round 0 (initial): all 4 attempts fail -> marked retry:1.
	p.app.evaluateAlertsAt(exp.Add(-20 * 24 * time.Hour))
	if !p.app.FlushTelegramForTest(2 * time.Second) {
		t.Fatal("flush timed out on round 0")
	}
	if got := len(tg.takeCalls()); got != 4 {
		t.Fatalf("expected 4 failed attempts on round 0, got %d", got)
	}

	// Round 1 (requeue #1): all 4 attempts fail -> marked retry:2.
	p.app.evaluateAlertsAt(exp.Add(-20*24*time.Hour + time.Minute))
	if !p.app.FlushTelegramForTest(2 * time.Second) {
		t.Fatal("flush timed out on round 1")
	}
	if got := len(tg.takeCalls()); got != 4 {
		t.Fatalf("expected 4 failed attempts on round 1, got %d", got)
	}

	// Telegram recovers! Round 2 (requeue #2) succeeds and delivers the reminder once.
	var deliveredTexts []string
	tg.reply = func(_ int, _ string, body map[string]any, w http.ResponseWriter) {
		if txt, ok := body["text"].(string); ok {
			deliveredTexts = append(deliveredTexts, txt)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}
	p.app.evaluateAlertsAt(exp.Add(-20*24*time.Hour + 2*time.Minute))
	if !p.app.FlushTelegramForTest(2 * time.Second) {
		t.Fatal("flush timed out on recovery round")
	}
	if len(deliveredTexts) != 1 || !strings.Contains(deliveredTexts[0], "recover.example.com") {
		t.Fatalf("expected certificate reminder delivered once upon recovery, got %v", deliveredTexts)
	}

	// Subsequent evaluations must NOT send duplicates.
	p.app.evaluateAlertsAt(exp.Add(-19 * 24 * time.Hour))
	p.app.evaluateAlertsAt(exp.Add(-15 * 24 * time.Hour))
	p.app.FlushTelegramForTest(2 * time.Second)
	if len(deliveredTexts) != 1 {
		t.Fatalf("expected no duplicate delivery after recovery, got %d deliveries", len(deliveredTexts))
	}

	// Certificate expired <24h ago (days == 0, ExpiresAt < now) must say "状态：已过期".
	deliveredTexts = nil
	p.app.evaluateAlertsAt(exp.Add(2 * time.Hour))
	p.app.FlushTelegramForTest(2 * time.Second)
	if len(deliveredTexts) != 1 || !strings.Contains(deliveredTexts[0], "状态：已过期") {
		t.Fatalf("expected '状态：已过期' when expired <24h, got %v", deliveredTexts)
	}

	// Long-term outage caps at 3 requeue rounds (initial + 3 requeues = 4 rounds total), not infinite.
	cert2 := shared.Certificate{
		ID:        ID(),
		Name:      "down-cert",
		Domain:    "down.example.com",
		ExpiresAt: exp,
	}
	if _, err := p.store.DB.Exec(`INSERT INTO mui_certificates(id,data,secret) VALUES($1,$2,'')`, cert2.ID, Marshal(cert2)); err != nil {
		t.Fatal(err)
	}
	_ = tg.takeCalls()
	tg.reply = func(_ int, _ string, _ map[string]any, w http.ResponseWriter) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"ok":false,"description":"down"}`))
	}
	for round := 0; round < 6; round++ {
		p.app.evaluateAlertsAt(exp.Add(-10*24*time.Hour + time.Duration(round)*time.Minute))
		p.app.FlushTelegramForTest(2 * time.Second)
	}
	// 4 rounds * 4 HTTP attempts per round = 16 calls; rounds 4 and 5 must not enqueue again.
	if got := len(tg.takeCalls()); got != 16 {
		t.Fatalf("expected cap at 4 rounds (16 HTTP attempts), got %d", got)
	}
}
