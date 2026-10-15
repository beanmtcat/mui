//go:build linux || darwin

package agent

import (
	"testing"
	"time"
)

func TestCommandTimeoutKillsChildrenHoldingOutput(t *testing.T) {
	start := time.Now()
	out, err := commandTimeout("/bin/sh", 100*time.Millisecond, "-c", "printf ready; sleep 3 & wait")
	if err == nil {
		t.Fatal("command with a running child did not time out")
	}
	if out != "ready" {
		t.Fatalf("output = %q, want ready", out)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("timeout waited for the child's output pipe: %v", elapsed)
	}
}
