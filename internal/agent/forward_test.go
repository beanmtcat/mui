package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"mui/internal/forward"
	"mui/internal/shared"
)

func TestForwardTargetValidation(t *testing.T) {
	for _, tc := range []struct {
		host  string
		allow bool
	}{
		{"192.168.10.20", true}, {"10.1.2.3", true}, {"172.16.0.5", true},
		{"100.64.0.1", true}, {"100.100.100.201", true}, {"fd00:1234::1", true},
		{"2001:db8::1", true}, {"example.com", true},
		{"127.0.0.1", false}, {"::1", false}, {"::ffff:127.0.0.1", false},
		{"0.0.0.0", false}, {"::", false}, {"169.254.169.254", false},
		{"100.100.100.200", false}, {"fd00:ec2::254", false}, {"224.0.0.1", false},
		{"127.1", false}, {"2130706433", false}, {"https://example.com", false},
	} {
		t.Run(tc.host, func(t *testing.T) {
			rule := shared.ForwardRule{Name: "relay", Network: "tcp", Listen: "0.0.0.0", Port: 51000, TargetHost: tc.host, TargetPort: 443, Enabled: true}
			err := validateForwardRule(rule)
			if (err == nil) != tc.allow {
				t.Fatalf("allow=%v, error=%v", tc.allow, err)
			}
		})
	}
}

func TestIdleForwardStatsKeepHeartbeat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.json")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runForwardStats(ctx, path, "process-1", func() map[string]forward.Counter {
			return map[string]forward.Counter{"relay": {Uplink: 123, Downlink: 456}}
		}, 10*time.Millisecond)
	}()
	defer func() { cancel(); <-done }()
	read := func() shared.ForwardTrafficPoint {
		raw, _ := os.ReadFile(path)
		var points []shared.ForwardTrafficPoint
		if json.Unmarshal(raw, &points) != nil || len(points) != 1 {
			return shared.ForwardTrafficPoint{}
		}
		return points[0]
	}
	waitFor := func(condition func(shared.ForwardTrafficPoint) bool) shared.ForwardTrafficPoint {
		t.Helper()
		for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
			if point := read(); condition(point) {
				return point
			}
		}
		t.Fatal("idle stats heartbeat did not advance")
		return shared.ForwardTrafficPoint{}
	}
	first := waitFor(func(p shared.ForwardTrafficPoint) bool { return !p.UpdatedAt.IsZero() })
	next := waitFor(func(p shared.ForwardTrafficPoint) bool { return p.UpdatedAt.After(first.UpdatedAt) })
	if next.InstanceID != first.InstanceID || next.Uplink != 123 || next.Downlink != 456 {
		t.Fatalf("heartbeat changed cumulative counters or instance: %+v", next)
	}
}
