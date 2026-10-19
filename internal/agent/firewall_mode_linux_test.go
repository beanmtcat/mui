//go:build linux

package agent

import (
	"os"
	"path/filepath"
	"testing"

	"mui/internal/shared"
)

// Full helper apply in an isolated Linux fixture with no core, no forwards,
// and a ufw executable which fails if called. Tests the missing-UFW path and
// the periodic SSH writer as well as revision/idempotency handling.
func TestManualFirewallApplyWithoutUFW(t *testing.T) {
	if os.Getenv("MUI_TEST_MANUAL_FIREWALL") != "1" {
		t.Skip("requires isolated Linux fixture")
	}
	if os.Geteuid() != 0 {
		t.Fatal("fixture must run as root")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "ufw-called")
	for name, script := range map[string]string{
		"ufw":       "#!/bin/sh\nprintf called > '" + marker + "'\nexit 98\n",
		"systemctl": "#!/bin/sh\ncase \"$1\" in is-active|is-enabled) exit 1;; *) exit 0;; esac\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	if err := os.MkdirAll(ConfigDir, 0750); err != nil {
		t.Fatal(err)
	}
	state := shared.DesiredState{Revision: 1, ProtocolVersion: 1, FirewallMode: "manual"}
	if err := applyDesiredInternal(state, nil); err != nil {
		t.Fatalf("manual apply required UFW: %v", err)
	}
	if err := applyDesiredInternal(state, nil); err != nil {
		t.Fatalf("manual replay required UFW: %v", err)
	}
	if err := ensureSSHAllowed(); err != nil {
		t.Fatalf("manual SSH repair: %v", err)
	}
	current, err := readCurrentChecked()
	if err != nil || current.FirewallMode != "manual" {
		t.Fatalf("manual state not persisted: %+v %v", current, err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("manual mode invoked UFW")
	}
	state.FirewallMode, state.Revision = "ufw", 2
	if err := applyDesiredInternal(state, nil); err == nil {
		t.Fatal("managed mode accepted unavailable UFW")
	}
}
