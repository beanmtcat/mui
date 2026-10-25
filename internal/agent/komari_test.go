package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	komariv2 "github.com/komari-monitor/komari-agent/protocol/v2"
)

type komariRoundTripFunc func(*http.Request) (*http.Response, error)

func (f komariRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestKomariConfigRequiresSecureEndpointAndBothCredentials(t *testing.T) {
	for _, config := range []KomariConfig{
		{Endpoint: "http://example.com", Token: "secret"},
		{Endpoint: "https://example.com"},
		{Endpoint: "https://example.com/?token=bad", Token: "secret"},
	} {
		if _, err := newKomariClient(config); err == nil {
			t.Fatalf("accepted unsafe config %+v", config)
		}
	}
	client, err := newKomariClient(KomariConfig{Endpoint: "https://komari.example.com", Token: "secret"})
	if err != nil || !strings.Contains(client.endpoint, "token=secret") {
		t.Fatalf("valid config: %+v %v", client, err)
	}
}

func TestFetchKomariConfigFromPanel(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/agent/komari" || r.Header.Get("X-Server-ID") != "server-1" || r.Header.Get("Authorization") != "Bearer mui-token" || r.Header.Get("X-Agent-Signature") == "" {
			t.Errorf("unexpected Agent request: %s %s", r.Method, r.URL.Path)
		}
		if calls.Add(1) == 1 {
			_, _ = io.WriteString(w, `{"endpoint":"https://komari.example.com","token":"private-token"}`)
		} else {
			_, _ = io.WriteString(w, `{"endpoint":"","token":""}`)
		}
	}))
	defer server.Close()
	config := Config{URL: server.URL, ServerID: "server-1", Token: "mui-token"}
	got, err := fetchKomariConfig(context.Background(), config)
	if err != nil || got.Endpoint != "https://komari.example.com" || got.Token != "private-token" {
		t.Fatalf("fetch configured Agent: %+v %v", got, err)
	}
	got, err = fetchKomariConfig(context.Background(), config)
	if err != nil || got != (KomariConfig{}) {
		t.Fatalf("tokenless Agent must stay disabled: %+v %v", got, err)
	}
}

func TestKomariRemoteControlEventsCannotTriggerHostActions(t *testing.T) {
	posts := 0
	client := &komariClient{endpoint: "https://komari.example.com/api/clients/v2/rpc?token=secret", http: &http.Client{Transport: komariRoundTripFunc(func(*http.Request) (*http.Response, error) {
		posts++
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","result":{"status":"success"}}`))}, nil
	})}}
	for _, method := range []string{
		komariv2.MethodAgentExec,
		komariv2.MethodAgentTerminal,
		komariv2.MethodAgentFile,
		komariv2.MethodAgentStartupConfig,
		komariv2.MethodAgentSwitchVersion,
	} {
		client.handleEvent(context.Background(), komariv2.Event{Method: method, Params: map[string]any{"command": "touch /tmp/should-not-exist"}})
	}
	if posts != 0 {
		t.Fatalf("remote-control events sent %d requests", posts)
	}
}

func TestKomariOnlyTCPTypeMayRunPing(t *testing.T) {
	var payload struct {
		Method string `json:"method"`
		Params struct {
			Type  string `json:"ping_type"`
			Value int    `json:"value"`
		} `json:"params"`
	}
	client := &komariClient{endpoint: "https://komari.example.com/api/clients/v2/rpc?token=secret", http: &http.Client{Transport: komariRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","result":{"status":"success"}}`))}, nil
	})}}
	client.handleEvent(context.Background(), komariv2.Event{Method: komariv2.MethodAgentPing, Params: map[string]any{"ping_task_id": 7, "ping_type": "icmp", "ping_target": "127.0.0.1"}})
	if payload.Method != komariv2.MethodAgentPingResult || payload.Params.Type != "icmp" || payload.Params.Value != -1 {
		t.Fatalf("unsupported ping was not rejected: %+v", payload)
	}
	if got := tcpPingKomari(context.Background(), "127.0.0.1:0"); got != -1 {
		t.Fatalf("invalid TCP port: %d", got)
	}
}

func TestKomariTCPPingReportsConnectLatency(t *testing.T) {
	const target = "example.com:443"
	var payload struct {
		Method string `json:"method"`
		Params struct {
			TaskID uint   `json:"task_id"`
			Type   string `json:"ping_type"`
			Value  int    `json:"value"`
		} `json:"params"`
	}
	client := &komariClient{endpoint: "https://komari.example.com/api/clients/v2/rpc?token=secret", tcpPing: func(_ context.Context, got string) int {
		if got != target {
			t.Fatalf("wrong TCP target: %q", got)
		}
		return 17
	}, http: &http.Client{Transport: komariRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","result":{"status":"success"}}`))}, nil
	})}}
	if !client.handleEvent(context.Background(), komariv2.Event{Method: komariv2.MethodAgentPing, Params: map[string]any{"ping_task_id": 11, "ping_type": "tcp", "ping_target": target}}) {
		t.Fatal("successful TCP Ping was not acknowledged")
	}
	if payload.Method != komariv2.MethodAgentPingResult || payload.Params.TaskID != 11 || payload.Params.Type != "tcp" || payload.Params.Value != 17 {
		t.Fatalf("wrong TCP Ping result: %+v", payload)
	}
}

func TestKomariFailedPingResultIsNotAcknowledged(t *testing.T) {
	client := &komariClient{endpoint: "https://komari.example.com/api/clients/v2/rpc?token=secret", http: &http.Client{Transport: komariRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("disconnected")
	})}}
	if client.handleEvent(context.Background(), komariv2.Event{Method: komariv2.MethodAgentPing, Params: map[string]any{"ping_task_id": 11, "ping_type": "tcp", "ping_target": "127.0.0.1:0"}}) {
		t.Fatal("failed Ping result was acknowledged")
	}
}

func TestKomariTransportErrorDoesNotExposeToken(t *testing.T) {
	client := &komariClient{endpoint: "https://komari.example.com/api/clients/v2/rpc?token=private-token", http: &http.Client{Transport: komariRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("https://komari.example.com/api/clients/v2/rpc?token=private-token: failed")
	})}}
	err := client.post(context.Background(), []byte(`{"jsonrpc":"2.0"}`), nil)
	if err == nil || strings.Contains(err.Error(), "private-token") {
		t.Fatalf("token leaked through request error: %v", err)
	}
}

func TestParseKomariPublicIP(t *testing.T) {
	for _, test := range []struct {
		body   string
		family string
		want   string
	}{
		{`{"ip":"202.187.152.50"}`, "tcp4", "202.187.152.50"},
		{`{"ip":"2001:b011:9801:f420:be24:11ff:fee3:6f98"}`, "tcp6", "2001:b011:9801:f420:be24:11ff:fee3:6f98"},
		{`{"ip":"192.168.1.1"}`, "tcp4", ""},
		{`{"ip":"202.187.152.50"}`, "tcp6", ""},
		{`{"ip":"broken"}`, "tcp4", ""},
	} {
		if got := parseKomariPublicIP(strings.NewReader(test.body), test.family); got != test.want {
			t.Errorf("body=%s family=%s: got %q, want %q", test.body, test.family, got, test.want)
		}
	}
}
