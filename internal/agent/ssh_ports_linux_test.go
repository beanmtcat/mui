//go:build linux

package agent

import (
	"os"
	"testing"
)

// Run in an isolated Linux container with a real sshd bound to 22, but its
// on-disk sshd_config set to 12580. No firewall changes are performed.
func TestLiveSSHPortDetection(t *testing.T) {
	if os.Getenv("MUI_TEST_LIVE_SSH") != "1" {
		t.Skip("requires isolated Linux SSH fixture")
	}
	ports, err := sshPorts()
	if err != nil || !ports[22] || !ports[12580] {
		t.Fatalf("must protect actual port 22 and configured port 12580: ports=%v error=%v", ports, err)
	}
}
