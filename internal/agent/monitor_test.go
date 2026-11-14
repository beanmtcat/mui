package agent

import (
	"context"
	"errors"
	"math"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	komariunit "github.com/komari-monitor/komari-agent/monitoring/unit"

	"mui/internal/shared"
)

func TestCollectMonitorSampleAndHostPopulation(t *testing.T) {
	now := time.Date(2026, 11, 14, 7, 0, 0, 0, time.UTC)
	sample := buildMonitorSample(
		now,
		komariunit.CpuInfo{CPUUsage: 37.5},
		komariunit.LoadInfo{Load1: 0.42, Load5: 0.35, Load15: 0.28},
		komariunit.RamInfo{Used: 2 << 30, Total: 8 << 30},
		komariunit.RamInfo{Used: 128 << 20, Total: 1 << 30},
		komariunit.DiskInfo{Used: 20 << 30, Total: 80 << 30},
		100_000_000, 250_000_000, 12_000, 48_000,
		42, 7, 130,
		86_400,
	)
	if !sample.At.Equal(now) || sample.CPU != 37.5 || sample.Load1 != 0.42 || sample.RAMUsed != 2<<30 || sample.RAMTotal != 8<<30 ||
		sample.NetUp != 12_000 || sample.NetDown != 48_000 || sample.NetTotalUp != 100_000_000 || sample.NetTotalDown != 250_000_000 ||
		sample.TCP != 42 || sample.UDP != 7 || sample.Process != 130 || sample.Uptime != 86_400 {
		t.Fatalf("unexpected MonitorSample population: %+v", sample)
	}

	host := buildMonitorHost(
		komariunit.CpuInfo{CPUName: "AMD EPYC 7763", CPUCores: 4, CPUPhysicalCores: 2},
		komariunit.RamInfo{Total: 8 << 30},
		komariunit.RamInfo{Total: 1 << 30},
		komariunit.DiskInfo{Total: 80 << 30},
		"amd64", "Debian GNU/Linux 13", "6.12.0-amd64", "kvm",
	)
	if host.CPUName != "AMD EPYC 7763" || host.CPUCores != 4 || host.CPUPhysicalCores != 2 ||
		host.Arch != "amd64" || host.OS != "Debian GNU/Linux 13" || host.Kernel != "6.12.0-amd64" ||
		host.Virtualization != "kvm" || host.MemTotal != 8<<30 || host.SwapTotal != 1<<30 || host.DiskTotal != 80<<30 {
		t.Fatalf("unexpected MonitorHost population: %+v", host)
	}
}

func TestMonitorPollIntervalBackoffAndClip(t *testing.T) {
	if got := monitorPollInterval(0); got != 5*time.Second {
		t.Fatalf("expected 5s normal interval, got %v", got)
	}
	if got := monitorPollInterval(1); got != 5*time.Second {
		t.Fatalf("expected single failure to keep 5s before consecutive failures, got %v", got)
	}
	if got := monitorPollInterval(2); got != 30*time.Second {
		t.Fatalf("expected consecutive failures to back off to 30s, got %v", got)
	}
	if got := monitorPollInterval(10); got != 30*time.Second {
		t.Fatalf("expected backoff to stay at 30s, got %v", got)
	}

	// Sanitize NaN / Inf and UTF-8 boundary clipping.
	if got := sanitizeAgentFloat(math.NaN(), 0, 100); got != 0 {
		t.Fatalf("NaN should sanitize to 0, got %v", got)
	}
	if got := sanitizeAgentFloat(150, 0, 100); got != 100 {
		t.Fatalf("expected clamp to 100, got %v", got)
	}
	clipped := clipAgentUTF8Bytes(strings.Repeat("测", 60), 128)
	if len(clipped) > 128 || clipped == "" {
		t.Fatalf("unexpected clipped UTF-8 length %d", len(clipped))
	}

	// Ping result buffer does not grow unboundedly when the panel is unreachable.
	runner := newMonitorPingRunner(func(context.Context, string) int { return 12 })
	for i := 0; i < 100; i++ {
		runner.record(shared.PingResult{TaskID: "t1", At: time.Now(), Ms: i})
	}
	drained := runner.drain()
	if len(drained) != maxPendingPingResults {
		t.Fatalf("expected bounded %d results, got %d", maxPendingPingResults, len(drained))
	}
	if len(runner.drain()) != 0 {
		t.Fatal("expected drain to clear pending results without resending")
	}
}

func TestMonitorTCPPingRejectsInternalMixedAndDNSRebinding(t *testing.T) {
	lookup := func(_ context.Context, _, host string) ([]netip.Addr, error) {
		switch host {
		case "public.example":
			return []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2606:4700:4700::1111")}, nil
		case "mixed.example":
			return []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("10.0.0.1")}, nil
		case "private.example":
			return []netip.Addr{netip.MustParseAddr("192.168.1.10")}, nil
		default:
			return nil, errors.New("no such host")
		}
	}
	for _, target := range []string{
		"",
		"127.0.0.1:80",
		"[::1]:80",
		"10.0.0.1:443",
		"172.16.0.1:443",
		"192.168.1.1:22",
		"100.64.0.1:80",
		"169.254.169.254:80",
		"[fe80::1]:80",
		"[fc00::1]:80",
		"[::ffff:127.0.0.1]:80",
		"private.example:443",
		"mixed.example:443",
		"public.example:0",
		"public.example:70000",
		"http://public.example:443",
	} {
		if addresses, err := resolveMonitorTCPTarget(context.Background(), target, lookup); err == nil {
			t.Fatalf("target %q resolved to %v, expected rejection", target, addresses)
		}
	}

	for _, test := range []struct {
		target string
		want   []string
	}{
		{"1.1.1.1:443", []string{"1.1.1.1:443"}},
		{"1.1.1.1", []string{"1.1.1.1:80"}},
		{"2606:4700:4700::1111", []string{"[2606:4700:4700::1111]:80"}},
		{"public.example:443", []string{"1.1.1.1:443", "[2606:4700:4700::1111]:443"}},
	} {
		addresses, err := resolveMonitorTCPTarget(context.Background(), test.target, lookup)
		if err != nil || !slices.Equal(addresses, test.want) {
			t.Fatalf("resolveMonitorTCPTarget(%q) = %v, %v; want %v", test.target, addresses, err, test.want)
		}
	}

	if got := tcpPingMonitor(context.Background(), "169.254.169.254:80"); got != -1 {
		t.Fatalf("metadata link-local ping returned %d, want -1", got)
	}

	// DNS rebinding guard: lookup is invoked once per ping, and Dial receives the
	// approved literal IP rather than the hostname (so a changed DNS record at
	// dial time cannot redirect the connection to 127.0.0.1).
	var lookups atomic.Int32
	rebindLookup := func(_ context.Context, _, _ string) ([]netip.Addr, error) {
		if lookups.Add(1) == 1 {
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	var dialed []string
	fakeDial := func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		c1, c2 := net.Pipe()
		_ = c2.Close()
		return c1, nil
	}
	first := tcpPingMonitorWith(context.Background(), "rebind.example:443", rebindLookup, fakeDial)
	if first < 0 || !slices.Equal(dialed, []string{"93.184.216.34:443"}) {
		t.Fatalf("expected literal public IP dial, got ms=%d dialed=%v", first, dialed)
	}
	second := tcpPingMonitorWith(context.Background(), "rebind.example:443", rebindLookup, fakeDial)
	if second != -1 || len(dialed) != 1 {
		t.Fatalf("expected rebound private answer to be rejected without dialing, got ms=%d dialed=%v", second, dialed)
	}
}
