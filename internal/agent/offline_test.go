package agent

import (
	"encoding/json"
	"mui/internal/shared"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOfflineForwardDefaultsAndValidation(t *testing.T) {
	base := `{"id":"entry","network":"tcp","port":50001,"targets":[{"host":"10.0.0.2","port":50002}]}`
	rules, raw, err := parseOfflineForwards([]byte("[" + base + "]"))
	if err != nil || len(rules) != 1 {
		t.Fatalf("minimal config: %v", err)
	}
	if !rules[0].Enabled || rules[0].FirewallPolicy != "manual" || rules[0].Name != "entry" || rules[0].Listen != "0.0.0.0" || rules[0].Balance != "failover" {
		t.Fatalf("unsafe or unusable defaults: %+v", rules[0])
	}
	if _, _, err := parseOfflineForwards(raw); err != nil {
		t.Fatalf("canonical config cannot be loaded again: %v", err)
	}
	for name, value := range map[string]string{
		"null":                  `null`,
		"object":                base,
		"trailing JSON":         "[" + base + "] []",
		"unknown field":         "[" + strings.Replace(base, `"network"`, `"netwrok"`, 1) + "]",
		"duplicate ID":          "[" + base + "," + base + "]",
		"port conflict":         "[" + base + "," + strings.Replace(base, `"entry"`, `"other"`, 1) + "]",
		"wildcard conflict":     "[" + base + "," + strings.Replace(strings.Replace(base, `"entry"`, `"other"`, 1), `"network"`, `"listen":"127.0.0.1","network"`, 1) + "]",
		"privileged listen":     "[" + strings.Replace(base, "50001", "80", 1) + "]",
		"loopback destination":  "[" + strings.Replace(base, "10.0.0.2", "127.0.0.1", 1) + "]",
		"metadata destination":  "[" + strings.Replace(base, "10.0.0.2", "169.254.169.254", 1) + "]",
		"misleading UFW policy": "[" + strings.Replace(base, `"network"`, `"firewallPolicy":"all","network"`, 1) + "]",
		"misleading source ACL": "[" + strings.Replace(base, `"network"`, `"firewallSources":"192.0.2.1","network"`, 1) + "]",
		"misleading deletion":   "[" + strings.Replace(base, `"network"`, `"deleting":true,"network"`, 1) + "]",
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseOfflineForwards([]byte(value)); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	// TCP and UDP can use the same port; explicit disabled rules stay disabled.
	udp := strings.Replace(strings.Replace(base, `"entry"`, `"udp"`, 1), `"tcp"`, `"udp"`, 1)
	disabled := strings.Replace(strings.Replace(base, `"entry"`, `"disabled"`, 1), `"network"`, `"enabled":false,"network"`, 1)
	rules, _, err = parseOfflineForwards([]byte("[" + base + "," + udp + "," + disabled + "]"))
	if err != nil || len(rules) != 3 || rules[2].Enabled {
		t.Fatalf("TCP/UDP or disabled rule: %+v %v", rules, err)
	}
	if _, _, err := parseOfflineForwards([]byte("[]")); err != nil {
		t.Fatalf("empty config must stop forwarding: %v", err)
	}
}

func TestOfflineInitDoesNotOverwriteAndExampleWorks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "forwards.json")
	if err := InitOfflineForwards(path); err != nil {
		t.Fatal(err)
	}
	rules, _, err := ReadOfflineForwards(path)
	if err != nil || len(rules) != 1 || rules[0].Network != shared.ForwardTCPUDP {
		t.Fatalf("generated example: %+v %v", rules, err)
	}
	custom := []byte("[]")
	if err := os.WriteFile(path, custom, 0600); err != nil {
		t.Fatal(err)
	}
	if err := InitOfflineForwards(path); !os.IsExist(err) {
		t.Fatalf("overwriting an existing config: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(custom) {
		t.Fatal("existing rules were overwritten")
	}
	var example any
	if err := json.Unmarshal([]byte(OfflineForwardExample), &example); err != nil {
		t.Fatal(err)
	}
}

func TestOfflineTCPUDPRuleAndConflicts(t *testing.T) {
	raw := []byte(`[{"id":"both","network":"tcp+udp","port":51000,"targets":[{"host":"192.0.2.1","port":51000}]}]`)
	rules, canonical, err := parseOfflineForwards(raw)
	if err != nil || len(rules) != 1 || rules[0].Network != shared.ForwardTCPUDP {
		t.Fatalf("combined offline: %+v %v", rules, err)
	}
	for _, network := range []string{"tcp", "udp"} {
		other := rules[0]
		other.ID = "conflict"
		other.Network = network
		input := append(append([]shared.ForwardRule{}, rules...), other)
		encoded, _ := json.Marshal(input)
		if _, _, err := parseOfflineForwards(encoded); err == nil {
			t.Fatalf("combined rule did not reserve %s", network)
		}
	}
	if _, _, err := parseOfflineForwards(canonical); err != nil {
		t.Fatal(err)
	}
}
