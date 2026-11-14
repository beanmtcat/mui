package server

import (
	"bytes"
	"log"
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"
)

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
