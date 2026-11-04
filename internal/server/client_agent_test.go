package server

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientName(t *testing.T) {
	for ua, want := range map[string]string{
		"Surge iOS/3348":          "Surge iOS 3348",
		"Surge Mac/2836":          "Surge Mac 2836",
		"Stash/2.4.0 Clash/1.9.0": "Stash 2.4.0",
		"Shadowrocket/2070 CFNetwork/1494.0.7 Darwin/23.4.0": "Shadowrocket 2070",
		"Quantumult%20X/1.4.1":                               "Quantumult X 1.4.1",
		"SFI/1.10.0 (iOS 17.5; sing-box 1.10.0)":             "sing-box iOS 1.10.0",
		"SFA/1.11.4 (Android 14; sing-box 1.11.4)":           "sing-box Android 1.11.4",
		"sing-box 1.12.0":                                    "sing-box 1.12.0",
		"clash-verge/v2.0.3":                                 "Clash Verge 2.0.3",
		"mihomo/1.18.5":                                      "mihomo 1.18.5",
		"v2rayNG/1.9.16":                                     "v2rayNG 1.9.16",
		"v2rayN/7.0.1":                                       "v2rayN 7.0.1",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)":    "浏览器",
		"curl/8.7.1":                                         "curl 8.7.1",
		"SomethingElse/1.0":                                  "",
		"":                                                   "",
	} {
		if got := clientName(ua); got != want {
			t.Errorf("clientName(%q) = %q, want %q", ua, got, want)
		}
	}
	if got := cleanUserAgent("  a\x00b\nc" + strings.Repeat("长", 200)); strings.ContainsAny(got, "\x00\n") || len(got) > maxUserAgent || !strings.HasPrefix(got, "abc长") {
		t.Fatalf("user agent not cleaned: %q", got)
	}
}

func TestSubscriptionAccessRecordsClient(t *testing.T) {
	l := newRouteLab(t)
	p := l.p
	_, node, _ := p.do("POST", "/api/nodes", map[string]any{"direct": true, "serverId": l.exit, "name": "n", "protocol": "ss", "port": 50001}, nil)
	_, sub, _ := p.do("POST", "/api/subscriptions", map[string]any{"name": "s", "format": "sing-box", "nodeIds": []string{node["id"].(string)}}, nil)
	l.applyAll()
	req := httptest.NewRequest("GET", strings.TrimPrefix(sub["url"].(string), "https://mui.example.test"), nil)
	req.Header.Set("User-Agent", "SFI/1.10.0 (iOS 17.5; sing-box 1.10.0)")
	rec := httptest.NewRecorder()
	p.handler.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatal(rec.Code, rec.Body.String())
	}
	list := p.list("/api/clients/accesses?subscriptionId=" + sub["id"].(string))
	if len(list) != 1 || list[0]["client"] != "sing-box iOS 1.10.0" || list[0]["userAgent"] != "SFI/1.10.0 (iOS 17.5; sing-box 1.10.0)" {
		t.Fatal("client not recorded", list)
	}
}
