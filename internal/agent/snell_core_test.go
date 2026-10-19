package agent

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"mui/internal/shared"
)

// Check the actual release binary's version-specific JSON decoder, including
// legacy stored obfs settings, ShadowTLS detours and independent user keys.
func TestGeneratedSnellConfigsMatchCore(t *testing.T) {
	core := os.Getenv("MUI_TEST_SNELL_CORE")
	if core == "" {
		t.Skip("set MUI_TEST_SNELL_CORE to test the release core")
	}
	for _, version := range []int{5, 6} {
		for _, shadow := range []bool{false, true} {
			for _, obfs := range []string{"none", "http"} {
				t.Run(fmt.Sprintf("v%d/shadow-%t/obfs-%s", version, shadow, obfs), func(t *testing.T) {
					n := shared.Node{ID: "18df91c7975ff67b0585b209dad9949d2231", Name: "Snell", Protocol: "snell", SnellVersion: version, Port: 54321, SnellPort: 23456, Listen: "0.0.0.0", Obfs: obfs, Enabled: true, Status: "active"}
					if shadow {
						n.ShadowTLSHost = "example.com"
					}
					managed := shared.ManagedNode{Node: n, Password: "a-valid-snell-psk", ShadowTLSPassword: "valid-shadow-password", Users: []shared.NodeUser{{SubscriptionID: "sub", Name: "mui-test-sub", Password: "a-valid-user-secret", ShadowTLSPassword: "valid-shadow-user-password"}}}
					server, err := shared.SingBoxConfig([]shared.ManagedNode{managed}, t.TempDir())
					if err != nil {
						t.Fatal(err)
					}
					item := shared.SubscriptionItem{Node: n, Server: shared.Server{IPv4: "127.0.0.1"}, Password: managed.Password, ShadowTLSPassword: managed.Users[0].ShadowTLSPassword}
					if !shadow {
						item.UserKey = managed.Users[0].Password
					}
					client, excluded, err := shared.RenderSubscription("sing-box", []shared.SubscriptionItem{item})
					if err != nil || len(excluded) > 0 {
						t.Fatal(err, excluded)
					}
					for label, config := range map[string][]byte{"server": server, "client": client} {
						path := filepath.Join(t.TempDir(), label+".json")
						if err := os.WriteFile(path, config, 0600); err != nil {
							t.Fatal(err)
						}
						if output, err := exec.Command(core, "check", "-c", path).CombinedOutput(); err != nil {
							t.Fatalf("%s rejected: %v %s", label, err, output)
						}
					}
				})
			}
		}
	}
}
