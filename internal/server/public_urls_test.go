package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParsePublicURLs(t *testing.T) {
	urls, err := parsePublicURLs(" https://MUI.example.test:443/, https://alias.example.test\nhttp://127.0.0.1:5173/ https://mui.example.test ")
	if err != nil || len(urls) != 3 {
		t.Fatalf("parse: %v %v", urls, err)
	}
	if urls[0].String() != "https://mui.example.test" || urls[1].String() != "https://alias.example.test" || urls[2].String() != "http://127.0.0.1:5173" {
		t.Fatalf("normalization: %v", urls)
	}
	for _, raw := range []string{"", ", ,", "mui.example.test", "ftp://mui.example.test", "https://", "https://user:pass@mui.example.test", "https://mui.example.test?x=1", "https://mui.example.test?", "https://mui.example.test#", "https://mui.example.test:65536", "https://mui.example.test/a,https://mui.example.test/b"} {
		if _, err := parsePublicURLs(raw); err == nil {
			t.Errorf("invalid config accepted: %q", raw)
		}
	}
}

func multiURLApp(t *testing.T) *testMui {
	t.Helper()
	p := newTestMui(t)
	app, err := NewApp(p.store, "https://mui.example.test,https://alias.example.test,http://127.0.0.1:5173")
	if err != nil {
		t.Fatal(err)
	}
	p.app, p.handler = app, app.Handler()
	return p
}

func TestMultiplePublicURLsLoginAndOrigin(t *testing.T) {
	p := multiURLApp(t)
	for _, base := range []string{"https://mui.example.test", "https://alias.example.test", "http://127.0.0.1:5173"} {
		code, body, cookie := p.do("POST", base+"/api/login", map[string]string{"password": testPassword}, map[string]string{"Origin": base})
		if code != 200 || cookie == nil || cookie.Domain != "" || cookie.Secure != strings.HasPrefix(base, "https:") {
			t.Fatalf("login %s: %d %v; cookie: %+v", base, code, body, cookie)
		}
	}
	// Origin aliases must work even when a proxy overwrites Host.
	if code, body, _ := p.do("POST", "http://backend.internal/api/login", map[string]string{"password": testPassword}, map[string]string{"Origin": "https://alias.example.test"}); code != 200 {
		t.Fatalf("proxy login: %d %v", code, body)
	}
	for _, origin := range []string{"https://attacker.example", "https://alias.example.test.attacker.example", "null", "https://user@alias.example.test", "https://alias.example.test/path"} {
		if code, body, _ := p.do("POST", "http://backend.internal/api/login", map[string]string{"password": testPassword}, map[string]string{"Origin": origin, "X-Forwarded-Host": "alias.example.test"}); code != 403 {
			t.Fatalf("foreign origin accepted %s: %d %v", origin, code, body)
		}
	}
	// Keep Vite's same-host proxy path working with a different local port.
	if code, _, _ := p.do("POST", "http://127.0.0.1:5174/api/login", map[string]string{"password": testPassword}, map[string]string{"Origin": "http://127.0.0.1:5174"}); code != 200 {
		t.Fatalf("Vite same-origin login: %d", code)
	}
}

func TestMultiplePublicURLsGeneratedLinks(t *testing.T) {
	p := multiURLApp(t)
	alias := "https://alias.example.test"
	code, out, _ := p.do("POST", alias+"/api/servers", map[string]any{"name": "alias install", "roles": []string{"transit"}, "country": "SG", "ipv4": "192.0.2.10"}, map[string]string{"Origin": alias})
	if code != 201 {
		t.Fatalf("create: %d %v", code, out)
	}
	id := out["server"].(map[string]any)["id"].(string)
	checkGuide := func(out map[string]any, base string) {
		t.Helper()
		if !strings.Contains(out["installCommand"].(string), base+"/download/install.sh") {
			t.Fatalf("online install did not use %s", base)
		}
		manual := out["offlineInstall"].(map[string]any)
		if !strings.Contains(manual["command"].(string), "install '"+base+"'") {
			t.Fatalf("manual install did not use %s", base)
		}
		for _, raw := range manual["downloads"].([]any) {
			download := raw.(map[string]any)
			for _, file := range download["files"].([]any) {
				if !strings.HasPrefix(file.(map[string]any)["url"].(string), base+"/download/") {
					t.Fatalf("download did not use %s: %v", base, file)
				}
			}
		}
	}
	checkGuide(out, alias)
	for _, base := range []string{alias, p.app.PublicURL} {
		code, renewed, _ := p.do("POST", base+"/api/servers/"+id+"/enrollment", nil, map[string]string{"Origin": base})
		if code != 200 {
			t.Fatalf("renew: %d %v", code, renewed)
		}
		checkGuide(renewed, base)
	}
	code, sub, _ := p.do("POST", alias+"/api/subscriptions", map[string]any{"name": "alias subscription", "format": "sing-box"}, map[string]string{"Origin": alias})
	if code != 201 || !strings.HasPrefix(sub["url"].(string), alias+"/s/") {
		t.Fatalf("create subscription: %d %v", code, sub)
	}
	subID := sub["id"].(string)
	for _, base := range []string{alias, p.app.PublicURL} {
		if code, link, _ := p.do("GET", base+"/api/subscriptions/"+subID+"/link", nil, nil); code != 200 || !strings.HasPrefix(link["url"].(string), base+"/s/") {
			t.Fatalf("get link %s: %d %v", base, code, link)
		}
	}
	if code, link, _ := p.do("POST", alias+"/api/subscriptions/"+subID+"/rotate", nil, map[string]string{"Origin": alias}); code != 200 || !strings.HasPrefix(link["url"].(string), alias+"/s/") {
		t.Fatalf("rotate link: %d %v", code, link)
	}
}

func TestPublicURLDoesNotTrustUnknownHosts(t *testing.T) {
	p := multiURLApp(t)
	for _, target := range []string{"https://attacker.example/api/login", "http://backend.internal/api/login"} {
		r := httptest.NewRequest("GET", target, nil)
		r.Header.Set("X-Forwarded-Host", "attacker.example")
		r.Header.Set("Origin", "https://attacker.example")
		if got := p.app.publicURLForRequest(r); got != p.app.PublicURL {
			t.Fatalf("untrusted request supplied public URL: %s", got)
		}
	}
	r := httptest.NewRequest("GET", "http://backend.internal/api/login", nil)
	r.Header.Set("Origin", "https://alias.example.test")
	if got := p.app.publicURLForRequest(r); got != "https://alias.example.test" {
		t.Fatalf("configured origin fallback: %s", got)
	}
	// Public HTTP requests cannot forge HTTPS by supplying forwarding headers.
	r = httptest.NewRequest("GET", "http://127.0.0.1:5173/api/login", nil)
	r.RemoteAddr = "203.0.113.10:50000"
	r.Header.Set("X-Forwarded-Proto", "https")
	if scheme := p.app.requestScheme(r); scheme != "http" {
		t.Fatalf("untrusted forwarded proto: %s", scheme)
	}
	var called bool
	handler := p.app.SecurityHeaders(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	r = httptest.NewRequest("POST", "http://backend.internal/api/login", nil)
	r.Header.Set("Origin", "https://attacker.example")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, r)
	if called || rec.Code != 403 {
		t.Fatal("rejected origin reached the handler")
	}
}
