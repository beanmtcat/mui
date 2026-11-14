package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
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
