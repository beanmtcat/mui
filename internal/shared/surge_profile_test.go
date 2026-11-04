package shared

import (
	"strings"
	"testing"
)

func TestSurgeProfileSkipsNodesNamedLikeGroups(t *testing.T) {
	if _, _, err := RenderSurgeProfile(nil, "https://mui.example.test/s/x?profile=1", ""); err == nil {
		t.Fatal("an empty profile would silently route everything directly")
	}
	node := func(name string) SubscriptionItem {
		return SubscriptionItem{
			Node:     Node{Name: name, Protocol: "ss", Method: "aes-256-gcm", Port: 8388, Enabled: true, Status: "active"},
			Server:   Server{IPv4: "198.51.100.9"},
			Password: "secret",
		}
	}
	body, excluded, err := RenderSurgeProfile([]SubscriptionItem{node("自动选择"), node("DIRECT"), node("东京")}, "https://mui.example.test/s/x?profile=1", "")
	if err != nil || len(excluded) != 2 || strings.Contains(string(body), "自动选择 = ss") || !strings.Contains(string(body), "自动选择 = url-test, 东京, interval") {
		t.Fatal("a node named like a group or built-in policy must be left out", err, excluded, string(body))
	}
}

func TestDefaultSurgeProfileTemplateIsValid(t *testing.T) {
	if _, err := ValidateSurgeProfileTemplate(DefaultSurgeProfileTemplate); err != nil {
		t.Fatal(err)
	}
}
