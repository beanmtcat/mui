package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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
			_, _ = io.WriteString(w, `{"endpoint":"https://komari.example.com","token":"private-token","ipv4":"8.8.8.8","ipv6":"2606:4700:4700::1111"}`)
		} else {
			_, _ = io.WriteString(w, `{"endpoint":"","token":""}`)
		}
	}))
	defer server.Close()
	config := Config{URL: server.URL, ServerID: "server-1", Token: "mui-token"}
	got, err := fetchKomariConfig(context.Background(), config)
	if err != nil || got.Endpoint != "https://komari.example.com" || got.Token != "private-token" || got.IPv4 != "8.8.8.8" || got.IPv6 != "2606:4700:4700::1111" {
		t.Fatalf("fetch configured Agent: %+v %v", got, err)
	}
	got, err = fetchKomariConfig(context.Background(), config)
	if err != nil || got != (KomariConfig{}) {
		t.Fatalf("tokenless Agent must stay disabled: %+v %v", got, err)
	}
}

func TestKomariPollInterval(t *testing.T) {
	if got := komariPollInterval(KomariConfig{}, true); got != 5*time.Minute {
		t.Fatalf("unconfigured interval: %v", got)
	}
	if got := komariPollInterval(KomariConfig{}, false); got != 30*time.Second {
		t.Fatalf("failed fetch retry interval: %v", got)
	}
	if got := komariPollInterval(KomariConfig{Token: "configured"}, true); got != 30*time.Second {
		t.Fatalf("configured interval: %v", got)
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

func TestKomariTCPPingRejectsInternalTargets(t *testing.T) {
	lookup := func(_ context.Context, _, host string) ([]netip.Addr, error) {
		switch host {
		case "public.example":
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		case "private.example":
			return []netip.Addr{netip.MustParseAddr("192.168.1.10")}, nil
		case "mixed.example":
			return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("169.254.169.254")}, nil
		default:
			return nil, errors.New("unexpected name")
		}
	}
	for _, target := range []string{
		"127.0.0.1:443", "[::1]:443", "10.0.0.2:443", "172.16.0.1:443",
		"192.168.1.1:443", "169.254.169.254:80", "[fe80::1]:80", "[fd00::1]:80",
		"100.64.0.1:443", "100.127.255.254:443", "0.0.0.0:80", "[::]:80",
		"private.example:443", "mixed.example:443",
	} {
		if addresses, err := resolveKomariTCPTarget(context.Background(), target, lookup); err == nil {
			t.Errorf("accepted blocked target %q: %v", target, addresses)
		}
	}
	for _, test := range []struct{ target, want string }{
		{"8.8.8.8:53", "8.8.8.8:53"},
		{"public.example:443", "8.8.8.8:443"},
		{"public.example", "8.8.8.8:80"},
		{"[2606:4700:4700::1111]:443", "[2606:4700:4700::1111]:443"},
	} {
		addresses, err := resolveKomariTCPTarget(context.Background(), test.target, lookup)
		if err != nil || len(addresses) != 1 || addresses[0] != test.want {
			t.Errorf("target %q: got %v, %v; want %q", test.target, addresses, err, test.want)
		}
	}
	if got := tcpPingKomari(context.Background(), "169.254.169.254:80"); got != -1 {
		t.Fatalf("metadata address returned %d", got)
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
		{`{"ip":"100.64.1.1"}`, "tcp4", ""},
		{`{"ip":"202.187.152.50"}`, "tcp6", ""},
		{`{"ip":"broken"}`, "tcp4", ""},
	} {
		if got := parseKomariPublicIP(strings.NewReader(test.body), test.family); got != test.want {
			t.Errorf("body=%s family=%s: got %q, want %q", test.body, test.family, got, test.want)
		}
	}
}

func TestKomariBasicIPsPreferPanelWithoutExternalLookup(t *testing.T) {
	queries := 0
	local := func(string, string) string { return "" }
	external := func(context.Context, string, string) string {
		queries++
		return "9.9.9.9"
	}
	ipv4, ipv6 := komariBasicIPs(context.Background(), KomariConfig{IPv4: "8.8.8.8", IPv6: "2606:4700:4700::1111"}, local, external)
	if ipv4 != "8.8.8.8" || ipv6 != "2606:4700:4700::1111" || queries != 0 {
		t.Fatalf("panel IPs not preferred: %q %q; external calls=%d", ipv4, ipv6, queries)
	}
	_, _ = komariBasicIPs(context.Background(), KomariConfig{IPv4: "8.8.8.8"}, local, external)
	if queries != 0 {
		t.Fatalf("external lookup ran while panel knows an address: %d", queries)
	}
	_, _ = komariBasicIPs(context.Background(), KomariConfig{}, local, external)
	if queries != 2 {
		t.Fatalf("missing panel IPs did not try both external lookups: %d", queries)
	}
}
