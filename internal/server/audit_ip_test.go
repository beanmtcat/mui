package server

import (
	"net"
	"testing"
)

func TestAuditRecordsTrustedRequestIP(t *testing.T) {
	p := newTestMui(t)
	if code, _, _ := p.do("POST", "/api/customers", map[string]string{"name": "direct"}, map[string]string{
		"RemoteAddr": "198.51.100.9:4321", "X-Forwarded-For": "203.0.113.17",
	}); code != 201 {
		t.Fatalf("create from direct address: %d", code)
	}
	entries := p.list("/api/audit?q=customer.create")
	if len(entries) != 1 || entries[0]["ip"] != "198.51.100.9" {
		t.Fatalf("untrusted forwarded address used: %v", entries)
	}

	_, trusted, err := net.ParseCIDR("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	p.app.trusted = []*net.IPNet{trusted}
	if code, _, _ := p.do("POST", "/api/customers", map[string]string{"name": "proxied"}, map[string]string{
		"RemoteAddr": "192.0.2.8:4321", "X-Forwarded-For": "203.0.113.18, 192.0.2.8",
	}); code != 201 {
		t.Fatalf("create through trusted proxy: %d", code)
	}
	entries = p.list("/api/audit?q=203.0.113.18")
	if len(entries) != 1 || entries[0]["ip"] != "203.0.113.18" {
		t.Fatalf("trusted client address missing: %v", entries)
	}

	p.store.Audit("test.system", "system", "")
	entries = p.list("/api/audit?q=test.system")
	if len(entries) != 1 || entries[0]["ip"] != "" {
		t.Fatalf("system audit should have no request IP: %v", entries)
	}
}
