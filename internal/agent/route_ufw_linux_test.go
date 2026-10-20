//go:build linux

package agent

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"mui/internal/shared"
)

// This test changes the firewall. Run ONLY in a disposable NET_ADMIN container
// with the explicit marker and a real SSH listener; never on a managed host.
func TestRouteUFWRealIntegration(t *testing.T) {
	if os.Getenv("MUI_UFW_INTEGRATION") != "1" {
		t.Skip("requires an isolated UFW test container")
	}
	if _, err := os.Stat("/run/.mui-ufw-integration"); err != nil || os.Geteuid() != 0 {
		t.Fatal("isolated root fixture marker missing")
	}
	run := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("ufw", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("ufw %v: %v: %s", args, err, out)
		}
		return string(out)
	}
	run("--force", "reset")
	run("default", "deny", "incoming")
	run("--force", "enable")
	// Exact duplicate, DENY, port range and all-port allows must be retained.
	run("allow", "51993/tcp", "comment", "foreign-exact")
	run("deny", "51993/udp", "comment", "foreign-deny")
	run("allow", "51000:53000/tcp", "comment", "foreign-range")
	run("allow", "from", "192.0.2.0/24", "comment", "foreign-broad")
	run("allow", "2222/tcp", "comment", "mui-ssh")
	original := run("show", "added")
	state := routeUFWFixture()
	if err := checkManualUFWBypass(state); err != nil {
		t.Fatal("foreign rule still blocks chain", err)
	}
	if err := syncUFW(state); err != nil {
		t.Fatal(err)
	}
	first := run("status", "numbered")
	if !routeUFWAtHead(first, routeUFWRules(state), routeUFWIPv6()) {
		t.Fatal("policy not first", first)
	}
	if err := syncUFW(state); err != nil {
		t.Fatal(err)
	}
	if second := run("status", "numbered"); first != second {
		t.Fatal("repeat apply duplicated or reordered rules", first, second)
	}
	// 0.6.14 left only the catch-all deny for all-source policies: UFW
	// silently skipped the subsequent equivalent allow. Recover that state,
	// and verify whole-family source lists do not have the same collision.
	for _, policy := range []struct{ mode, sources string }{
		{"closed", ""}, {"all", ""}, {"restricted", "0.0.0.0/0"},
		{"restricted", "::/0"}, {"restricted", "0.0.0.0/0,::/0"},
	} {
		next := routeUFWFixture()
		next.Forwards[0].FirewallPolicy, next.Forwards[0].FirewallSources = policy.mode, policy.sources
		if err := syncUFW(next); err != nil {
			t.Fatalf("policy %s %s: %v", policy.mode, policy.sources, err)
		}
		listed := run("status", "numbered")
		if !routeUFWAtHead(listed, routeUFWRules(next), routeUFWIPv6()) {
			t.Fatal("incorrect all-source policy", listed)
		}
		if err := syncUFW(next); err != nil {
			t.Fatal("all-source policy is not idempotent", err)
		}
	}
	if err := syncUFW(state); err != nil {
		t.Fatal(err)
	}
	if restored := run("status", "numbered"); first != restored {
		t.Fatal("switching back to restricted policy failed", restored)
	}
	// Changed sources replace the old allows, with no widening of policy.
	old, _ := json.Marshal(state)
	state.Forwards[0].FirewallSources = "192.0.2.2/32"
	if err := syncUFW(state); err != nil {
		t.Fatal(err)
	}
	if err := restoreUFW(old); err != nil {
		t.Fatal("rollback failed", err)
	}
	if restored := run("status", "numbered"); first != restored {
		t.Fatal("rollback did not restore policy and original rules", first, restored)
	}
	// Chain deletion leaves all pre-existing rules intact.
	if err := syncUFW(shared.DesiredState{}); err != nil {
		t.Fatal(err)
	}
	if got := run("show", "added"); original != got {
		t.Fatal("foreign or SSH rules changed", original, got)
	}
	state.Forwards[0].Port = 2222
	before := run("status", "numbered")
	if err := syncUFW(state); err == nil || !strings.Contains(err.Error(), "SSH") {
		t.Fatal("active non-22 SSH port was not protected", err)
	}
	if got := run("status", "numbered"); before != got {
		t.Fatal("SSH conflict modified rules before rejection")
	}
	// The old bypass gate remains for ordinary, manually created forwards.
	state = routeUFWFixture()
	state.Forwards[0].RouteID = ""
	if err := checkManualUFWBypass(state); err == nil {
		t.Fatal("ordinary forward silently bypassed its existing protection")
	}
}
