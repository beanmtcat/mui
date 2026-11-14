package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

func setupTelegramRecorder(t *testing.T, p *testMui, events map[string]any) *telegramTestSink {
	t.Helper()
	sink := &telegramTestSink{}
	p.app.tgClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			var payload map[string]any
			_ = json.NewDecoder(req.Body).Decode(&payload)
			sink.mu.Lock()
			sink.messages = append(sink.messages, fmt.Sprint(payload["text"]))
			sink.mu.Unlock()
			return &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
			}, nil
		}),
	}
	t.Cleanup(func() { p.app.CloseTelegram() })

	body := map[string]any{
		"enabled":  true,
		"botToken": "123456789:AAH_test_stage2b_billing_token",
		"chatId":   "-100987654",
	}
	if events != nil {
		body["events"] = events
	}
	if code, out, _ := p.do("PUT", "/api/settings/telegram", body, nil); code != 200 {
		t.Fatalf("save telegram settings: %d %v", code, out)
	}
	return sink
}

type telegramTestSink struct {
	mu       sync.Mutex
	messages []string
}

func (s *telegramTestSink) take() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]string(nil), s.messages...)
	s.messages = nil
	return out
}
