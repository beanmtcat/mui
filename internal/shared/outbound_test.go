package shared

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestNodeOutboundValidation(t *testing.T) {
	for _, name := range []string{"", "ppp0", "eth0", "enp1s0.123", "wg-test_1"} {
		if err := ValidateOutboundInterface(name); err != nil {
			t.Fatalf("valid interface %q: %v", name, err)
		}
	}
	for _, name := range []string{".", "..", "this-name-is-too-long", "eth0/1", "eth0;id", "ppp0\n", " ppp0", "网卡"} {
		if err := ValidateOutboundInterface(name); err == nil {
			t.Fatalf("accepted invalid interface %q", name)
		}
	}
	for _, n := range []Node{{OutboundMode: "other"}, {OutboundMode: "interface"}, {OutboundMode: "system", OutboundInterface: "ppp0"}, {OutboundInterface: "ppp0"}} {
		if err := ValidateNodeOutbound(n); err == nil {
			t.Fatalf("accepted invalid selection %+v", n)
		}
	}
}

func TestOutboundDefaultOverridesAndShadowTLS(t *testing.T) {
	var nodes []ManagedNode
	for i, settings := range []Node{
		{}, {OutboundMode: "system"}, {OutboundMode: "interface", OutboundInterface: "eth0"},
		{OutboundMode: "interface", OutboundInterface: "eth0"},
		{Protocol: "snell", SnellVersion: 6, SnellPort: 23001, ShadowTLSHost: "example.com", OutboundMode: "interface", OutboundInterface: "wg0"},
	} {
		settings.ID = string(rune('a' + i))
		settings.Name = settings.ID
		settings.Enabled = true
		settings.Port = 53000 + i
		settings.Listen = "0.0.0.0"
		if settings.Protocol == "" {
			settings.Protocol = "ss"
			settings.Method = "aes-256-gcm"
		}
		nodes = append(nodes, ManagedNode{Node: settings, Password: "a-test-password", ShadowTLSPassword: "a-shadow-password"})
	}
	nodes = append(nodes, ManagedNode{Node: Node{ID: "disabled", OutboundMode: "interface", OutboundInterface: "absent0"}})
	raw, err := SingBoxConfig(nodes, "/certs", "ppp0")
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Outbounds []struct {
			Tag       string `json:"tag"`
			Interface string `json:"bind_interface"`
		} `json:"outbounds"`
		Route struct {
			Final string `json:"final"`
			Rules []struct {
				Inbound  []string `json:"inbound"`
				Outbound string   `json:"outbound"`
			} `json:"rules"`
		} `json:"route"`
		Inbounds []map[string]any `json:"inbounds"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Outbounds) != 4 || cfg.Outbounds[0].Interface != "ppp0" || cfg.Route.Final != "direct" {
		t.Fatalf("wrong defaults/deduplication: %s", raw)
	}
	tags := map[string]string{}
	for _, o := range cfg.Outbounds {
		tags[o.Tag] = o.Interface
	}
	got := map[string]string{}
	for _, r := range cfg.Route.Rules {
		got[r.Inbound[0]] = tags[r.Outbound]
	}
	want := map[string]string{"node-b": "", "node-c": "eth0", "node-d": "eth0", "node-e": "wg0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("routes %v != %v", got, want)
	}
	if strings.Contains(string(raw), "absent0") {
		t.Fatal("disabled node emitted interface")
	}
	found := false
	for _, in := range cfg.Inbounds {
		if in["type"] == "shadowtls" {
			found = true
			if in["detour"] != "node-e" || in["handshake"].(map[string]any)["bind_interface"] != "wg0" {
				t.Fatalf("wrong ShadowTLS egress: %+v", in)
			}
		}
	}
	if !found {
		t.Fatal("missing ShadowTLS")
	}
	if got := OutboundInterfaces(nodes, "ppp0"); !reflect.DeepEqual(got, []string{"eth0", "ppp0", "wg0"}) {
		t.Fatal(got)
	}
	// No configured binding retains the original single direct outbound.
	raw, err = SingBoxConfig(nodes[:1], "/certs")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "bind_interface") || strings.Contains(string(raw), `"rules"`) {
		t.Fatal(string(raw))
	}
}
