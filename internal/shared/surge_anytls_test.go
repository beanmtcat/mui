package shared

import (
	"strings"
	"testing"
)

func TestSurgeAnyTLSAddressAndSNI(t *testing.T) {
	item := SubscriptionItem{Node: Node{ID: "anytls", Name: "AnyTLS 直连", Protocol: "anytls", Port: 50443, TLSName: "tls.example.com", Enabled: true, Status: "active"}, Server: Server{IPv4: "192.0.2.1"}, Password: "subscription-password"}
	for _, tc := range []struct{ name, publish, address string }{
		{"direct", "", "192.0.2.1"},
		{"route", "entry.example.net", "entry.example.net"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			item.Node.PublishAddress = tc.publish
			raw, excluded, err := RenderSubscription("surge", []SubscriptionItem{item})
			want := "[Proxy]\nAnyTLS 直连 = anytls, " + tc.address + ", 50443, password=subscription-password, sni=tls.example.com\n"
			if err != nil || len(excluded) != 0 || string(raw) != want {
				t.Fatalf("incorrect AnyTLS declaration: %s %v %v", raw, excluded, err)
			}
			if strings.Contains(string(raw), "skip-cert-verify") {
				t.Fatal("certificate verification must remain enabled")
			}
		})
	}
	for _, sni := range []string{"", "example.com,skip-cert-verify=true", "example.com\n[Rule]"} {
		item.Node.TLSName = sni
		raw, excluded, err := RenderSubscription("surge", []SubscriptionItem{item})
		if err != nil || len(excluded) != 1 || strings.Contains(string(raw), " = anytls,") {
			t.Fatal("invalid TLS name exported to Surge", excluded, err)
		}
	}
}
