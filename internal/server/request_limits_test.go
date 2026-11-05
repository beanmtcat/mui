package server

import (
	"bytes"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAgentBodyIsBounded(t *testing.T) {
	p := newTestMui(t)
	_, agent := p.enroll("big")
	huge := `{"agentVersion":"` + strings.Repeat("a", maxAgentBody) + `"}`
	req := httptest.NewRequest("POST", "/agent/report", bytes.NewReader([]byte(huge)))
	for k, v := range agent {
		req.Header.Set(k, v)
	}
	signAgentRequest(t, req, strings.TrimPrefix(agent["Authorization"], "Bearer "), []byte(huge))
	rec := httptest.NewRecorder()
	p.handler.ServeHTTP(rec, req)
	if rec.Code != 413 {
		t.Fatalf("oversized Agent body: %d %s", rec.Code, rec.Body.String())
	}
}

func TestNonceQuotaIsPerServer(t *testing.T) {
	a := &App{nonces: map[string]map[string]time.Time{}}
	now := time.Now()
	for i := 0; i < noncesPerAgent; i++ {
		if err := a.rememberNonce("flooding", fmt.Sprintf("%032x", i), now); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.rememberNonce("flooding", "extra", now); err == nil {
		t.Fatal("a server exceeded its nonce quota")
	}
	if err := a.rememberNonce("other", "first", now); err != nil {
		t.Fatal("one server's flood blocked another server", err)
	}
	if err := a.rememberNonce("other", "first", now); err == nil {
		t.Fatal("replayed nonce accepted")
	}
	// Once the old nonces expire, the flooding server may continue.
	if err := a.rememberNonce("flooding", "later", now.Add(nonceTTL+time.Second)); err != nil {
		t.Fatal(err)
	}
}

func TestRateLimiterGroupsIPv6AndStopsGrowing(t *testing.T) {
	if rateKey("2001:db8:1:2:aaaa::1") != rateKey("2001:db8:1:2:bbbb::9") || rateKey("2001:db8:1:3::1") == rateKey("2001:db8:1:2::1") {
		t.Fatal("IPv6 clients must be limited per /64")
	}
	if rateKey("198.51.100.7") != "198.51.100.7" {
		t.Fatal("IPv4 key changed")
	}
	a := &App{rates: map[string]rateBucket{}}
	for i := 0; i < maxRateBuckets+50; i++ {
		r := httptest.NewRequest("POST", "/api/login", nil)
		r.RemoteAddr = fmt.Sprintf("10.%d.%d.%d:1000", i>>16&255, i>>8&255, i&255)
		a.rateCount(r, "login", 1)
	}
	if len(a.rates) > maxRateBuckets+1 {
		t.Fatalf("rate table grew to %d", len(a.rates))
	}
	if a.rates["login:overflow"].Count < 50 {
		t.Fatal("addresses beyond the table must share one bucket")
	}
}

func TestStateChangingAPINeedsPanelHeaders(t *testing.T) {
	p := newTestMui(t)
	for name, headers := range map[string]map[string]string{
		"no custom header":  nil,
		"sibling subdomain": {"X-Requested-With": "XMLHttpRequest", "Sec-Fetch-Site": "same-site"},
		"other site":        {"X-Requested-With": "XMLHttpRequest", "Sec-Fetch-Site": "cross-site"},
	} {
		req := httptest.NewRequest("POST", "/api/logout", nil)
		req.AddCookie(p.cookie)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		p.handler.ServeHTTP(rec, req)
		if rec.Code != 403 {
			t.Fatalf("%s: %d", name, rec.Code)
		}
	}
	if code, out, _ := p.do("POST", "/api/servers", map[string]any{"name": "ok", "roles": []string{"exit"}, "country": "SG", "ipv4": "203.0.113.9"}, map[string]string{"Sec-Fetch-Site": "same-origin"}); code != 201 {
		t.Fatal("the panel's own request was refused", code, out)
	}
}
