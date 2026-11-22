package forward

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"mui/internal/shared"
)

func startEchoTCP(t *testing.T) (string, int, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port, func() { _ = ln.Close() }
}

func startSinkTCP(t *testing.T) (string, int, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen sink tcp: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(io.Discard, conn)
			}(c)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port, func() { _ = ln.Close() }
}

func startEchoUDP(t *testing.T) (string, int, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	addr := pc.LocalAddr().(*net.UDPAddr)
	return "127.0.0.1", addr.Port, func() { _ = pc.Close() }
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free tcp port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free udp port: %v", err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	_ = pc.Close()
	return port
}

// TestRouteAggregateSpeedLimitMultiConnTCPAndUDP verifies that multiple
// concurrent TCP connections + UDP traffic on the same route share ONE
// aggregate uplink speed budget (not N × cap).
func TestRouteAggregateSpeedLimitMultiConnTCPAndUDP(t *testing.T) {
	prev := TestAllowLoopbackTarget
	TestAllowLoopbackTarget = true
	defer func() { TestAllowLoopbackTarget = prev }()

	sinkHost, sinkPort, stopSink := startSinkTCP(t)
	defer stopSink()
	udpHost, udpPort, stopUDP := startEchoUDP(t)
	defer stopUDP()

	tcpListenPort := freeTCPPort(t)
	udpListenPort := freeUDPPort(t)
	// 2 Mbps aggregate uplink cap = 250,000 B/s
	const rateBps = 250_000

	svc, err := Start([]shared.ForwardRule{
		{
			ID: "r1-tcp", Name: "r1-tcp", RouteID: "route-speed", EntryHop: true,
			Network: "tcp", Listen: "127.0.0.1", Port: tcpListenPort,
			Targets: []shared.ForwardTarget{{Host: sinkHost, Port: sinkPort}},
			Enabled: true, RouteUpSpeedLimitBps: rateBps,
		},
		{
			ID: "r1-udp", Name: "r1-udp", RouteID: "route-speed", EntryHop: true,
			Network: "udp", Listen: "127.0.0.1", Port: udpListenPort,
			Targets: []shared.ForwardTarget{{Host: udpHost, Port: udpPort}},
			Enabled: true, RouteUpSpeedLimitBps: rateBps,
		},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer svc.Close()

	// Run 4 concurrent TCP writers + 1 UDP sender for 1.5s.
	const duration = 1500 * time.Millisecond
	deadline := time.Now().Add(duration)
	payload := bytes.Repeat([]byte("A"), 16*1024)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(tcpListenPort)), 2*time.Second)
			if err != nil {
				return
			}
			defer c.Close()
			for time.Now().Before(deadline) {
				_ = c.SetWriteDeadline(deadline)
				if _, err := c.Write(payload); err != nil {
					return
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := net.DialTimeout("udp", net.JoinHostPort("127.0.0.1", itoa(udpListenPort)), 2*time.Second)
		if err != nil {
			return
		}
		defer c.Close()
		pkt := bytes.Repeat([]byte("U"), 1024)
		for time.Now().Before(deadline) {
			_, _ = c.Write(pkt)
			time.Sleep(15 * time.Millisecond)
		}
	}()
	wg.Wait()
	time.Sleep(100 * time.Millisecond)

	snaps := svc.RouteTrafficSnapshot("inst-1")
	if len(snaps) != 1 {
		t.Fatalf("expected 1 shared route traffic state, got %d", len(snaps))
	}
	up := snaps[0].Uplink
	// Theoretical max in 1.5s = 1.5 * 250KB + burst(32KB) + up to 4*16KB in-flight ≈ 470KB.
	// Without aggregate limiting, 4 loopback TCP streams easily push > 50 MB in 1.5s.
	if up < 150_000 {
		t.Fatalf("aggregate uplink too low (%d bytes), rate limiter stalled traffic", up)
	}
	if up > 650_000 {
		t.Fatalf("aggregate uplink exceeded 2 Mbps cap across 4 TCP + UDP streams: got %d bytes in 1.5s", up)
	}
	t.Logf("measured 4×TCP + UDP aggregate uplink in 1.5s at 2 Mbps cap: %d bytes (%.2f Mbps)", up, float64(up)*8/1.5/1e6)
}

// TestRouteQuotaTerminatesActiveConnsAndIsolatesOtherRoutes verifies:
// 1. TCP+UDP share one quota budget on the entry route.
// 2. Reaching quota immediately terminates active long-lived TCP/UDP sessions and blocks new ones.
// 3. Another route on the same forwarder continues running unaffected.
func TestRouteQuotaTerminatesActiveConnsAndIsolatesOtherRoutes(t *testing.T) {
	prev := TestAllowLoopbackTarget
	TestAllowLoopbackTarget = true
	defer func() { TestAllowLoopbackTarget = prev }()

	echoHost, echoPort, stopEcho := startEchoTCP(t)
	defer stopEcho()
	udpHost, udpPort, stopUDP := startEchoUDP(t)
	defer stopUDP()

	portA := freeTCPPort(t)
	udpPortA := freeUDPPort(t)
	portB := freeTCPPort(t)

	const quotaBytes = 64 * 1024
	svc, err := Start([]shared.ForwardRule{
		{
			ID: "a-tcp", Name: "a-tcp", RouteID: "route-a", EntryHop: true,
			Network: "tcp", Listen: "127.0.0.1", Port: portA,
			Targets: []shared.ForwardTarget{{Host: echoHost, Port: echoPort}},
			Enabled: true, RouteTrafficLimit: quotaBytes, RouteTrafficLimitType: "sum",
		},
		{
			ID: "a-udp", Name: "a-udp", RouteID: "route-a", EntryHop: true,
			Network: "udp", Listen: "127.0.0.1", Port: udpPortA,
			Targets: []shared.ForwardTarget{{Host: udpHost, Port: udpPort}},
			Enabled: true, RouteTrafficLimit: quotaBytes, RouteTrafficLimitType: "sum",
		},
		{
			ID: "b-tcp", Name: "b-tcp", RouteID: "route-b", EntryHop: true,
			Network: "tcp", Listen: "127.0.0.1", Port: portB,
			Targets: []shared.ForwardTarget{{Host: echoHost, Port: echoPort}},
			Enabled: true,
		},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer svc.Close()

	// Open a long-lived idle TCP connection on Route A and one on Route B.
	longA, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(portA)), 2*time.Second)
	if err != nil {
		t.Fatalf("dial longA: %v", err)
	}
	defer longA.Close()
	longB, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(portB)), 2*time.Second)
	if err != nil {
		t.Fatalf("dial longB: %v", err)
	}
	defer longB.Close()

	// Send a UDP packet on Route A to verify UDP contributes to the shared quota.
	udpA, err := net.DialTimeout("udp", net.JoinHostPort("127.0.0.1", itoa(udpPortA)), 2*time.Second)
	if err != nil {
		t.Fatalf("dial udpA: %v", err)
	}
	defer udpA.Close()
	_, _ = udpA.Write(bytes.Repeat([]byte("u"), 1024))
	_ = udpA.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 2048)
	if _, err := udpA.Read(buf); err != nil {
		t.Fatalf("udpA echo before quota: %v", err)
	}

	// Push >64 KiB through a second TCP connection on Route A to exceed quota.
	pusher, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(portA)), 2*time.Second)
	if err != nil {
		t.Fatalf("dial pusher: %v", err)
	}
	defer pusher.Close()
	go func() {
		_, _ = io.Copy(io.Discard, pusher)
	}()
	_, _ = pusher.Write(bytes.Repeat([]byte("X"), 48*1024))

	// Long-lived connection on Route A must be terminated promptly!
	_ = longA.SetReadDeadline(time.Now().Add(2 * time.Second))
	one := make([]byte, 1)
	if _, err := longA.Read(one); err == nil {
		t.Fatalf("expected long-lived TCP connection on Route A to close on quota hit")
	}

	// New TCP connection on Route A must be closed immediately without echoing.
	newA, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(portA)), 2*time.Second)
	if err == nil {
		_, _ = newA.Write([]byte("hello"))
		_ = newA.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, rerr := newA.Read(one)
		_ = newA.Close()
		if rerr == nil && n > 0 {
			t.Fatalf("expected new TCP connection on quota-exceeded Route A to be rejected")
		}
	}

	// Route B must continue working normally!
	if _, err := longB.Write([]byte("pingB")); err != nil {
		t.Fatalf("write longB: %v", err)
	}
	_ = longB.SetReadDeadline(time.Now().Add(2 * time.Second))
	reply := make([]byte, 5)
	if _, err := io.ReadFull(longB, reply); err != nil || string(reply) != "pingB" {
		t.Fatalf("expected Route B to stay alive, got %q err=%v", string(reply), err)
	}
}

// TestRouteStatePersistenceAcrossRestartReloadAndCycleRollover verifies:
// 1. Counters & paused state persist across Reload (including speed limit edits) and full process restart.
// 2. Crossing into the next monthly cycle (including month-end day 31 -> Feb 28) resets usage and resumes.
func TestRouteStatePersistenceAcrossRestartReloadAndCycleRollover(t *testing.T) {
	prev := TestAllowLoopbackTarget
	TestAllowLoopbackTarget = true
	defer func() { TestAllowLoopbackTarget = prev }()

	echoHost, echoPort, stopEcho := startEchoTCP(t)
	defer stopEcho()
	portA := freeTCPPort(t)
	statePath := filepath.Join(t.TempDir(), "traffic-state.json")

	// Start on Jan 31, 2026 (reset day 31 -> cycle is Jan 31 .. Feb 28).
	var curNow atomic.Int64
	jan31 := time.Date(2026, 1, 31, 12, 0, 0, 0, time.UTC)
	curNow.Store(jan31.UnixNano())
	clock := func() time.Time { return time.Unix(0, curNow.Load()).UTC() }

	ruleSpec := shared.ForwardRule{
		ID: "p-tcp", Name: "p-tcp", RouteID: "route-persist", EntryHop: true,
		Network: "tcp", Listen: "127.0.0.1", Port: portA,
		Targets: []shared.ForwardTarget{{Host: echoHost, Port: echoPort}},
		Enabled: true, RouteTrafficLimit: 32 * 1024, RouteTrafficLimitType: "sum",
		RouteTrafficResetDay: 31, RouteTrafficTimezone: "UTC",
	}

	svc1, err := StartWithOptions(nil, statePath, "")
	if err != nil {
		t.Fatalf("StartWithOptions: %v", err)
	}
	svc1.SetClock(clock)
	if err := svc1.Reload([]shared.ForwardRule{ruleSpec}); err != nil {
		t.Fatalf("Reload svc1: %v", err)
	}

	// Transfer 20 KiB round-trip (= 40 KiB sum > 32 KiB quota).
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(portA)), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	go func() { _, _ = io.Copy(io.Discard, c) }()
	_, _ = c.Write(bytes.Repeat([]byte("P"), 20*1024))
	time.Sleep(150 * time.Millisecond)
	_ = c.Close()

	// Modify speed limit via Reload: used quota and paused state must remain intact!
	ruleSpec.RouteDownSpeedLimitBps = 500_000
	if err := svc1.Reload([]shared.ForwardRule{ruleSpec}); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	snap1 := svc1.RouteTrafficSnapshot("i1")
	if len(snap1) != 1 || !snap1[0].Paused || snap1[0].Used < 32*1024 {
		t.Fatalf("expected paused state after reload, got %+v", snap1)
	}
	svc1.Close()

	// Restart a fresh Service from the same statePath (simulating process restart without panel).
	svc2, err := StartWithOptions(nil, statePath, "")
	if err != nil {
		t.Fatalf("restart StartWithOptions: %v", err)
	}
	defer svc2.Close()
	svc2.SetClock(clock)
	if err := svc2.Reload([]shared.ForwardRule{ruleSpec}); err != nil {
		t.Fatalf("Reload svc2: %v", err)
	}

	snap2 := svc2.RouteTrafficSnapshot("i2")
	if len(snap2) != 1 || !snap2[0].Paused || snap2[0].Used < snap1[0].Used {
		t.Fatalf("expected paused state & counters preserved across restart, got %+v", snap2)
	}

	// Advance clock to Feb 28, 2026 00:01 UTC (month-end clamping for resetDay=31!).
	feb28 := time.Date(2026, 2, 28, 0, 1, 0, 0, time.UTC)
	curNow.Store(feb28.UnixNano())

	// Traffic should now be unblocked automatically and counters reset!
	c2, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(portA)), 2*time.Second)
	if err != nil {
		t.Fatalf("dial after rollover: %v", err)
	}
	defer c2.Close()
	if _, err := c2.Write([]byte("after-reset")); err != nil {
		t.Fatalf("write after rollover: %v", err)
	}
	_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, len("after-reset"))
	if _, err := io.ReadFull(c2, got); err != nil || string(got) != "after-reset" {
		t.Fatalf("expected auto-resume on Feb 28 rollover, got %q err=%v", string(got), err)
	}
}

// TestEntryProtectionBlocksEntryRoutesOnly verifies that activating entry total
// protection via the local signal file immediately terminates entry-hop routes
// while leaving non-entry middle-hop forwards untouched, and clearing resumes them.
func TestEntryProtectionBlocksEntryRoutesOnly(t *testing.T) {
	prev := TestAllowLoopbackTarget
	TestAllowLoopbackTarget = true
	defer func() { TestAllowLoopbackTarget = prev }()

	echoHost, echoPort, stopEcho := startEchoTCP(t)
	defer stopEcho()
	entryPort := freeTCPPort(t)
	middlePort := freeTCPPort(t)
	sigPath := filepath.Join(t.TempDir(), "entry-protection.json")

	svc, err := StartWithOptions([]shared.ForwardRule{
		{
			ID: "entry-r", Name: "entry-r", RouteID: "route-entry", EntryHop: true,
			Network: "tcp", Listen: "127.0.0.1", Port: entryPort,
			Targets: []shared.ForwardTarget{{Host: echoHost, Port: echoPort}},
			Enabled: true,
		},
		{
			ID: "mid-r", Name: "mid-r", RouteID: "route-mid", EntryHop: false,
			Network: "tcp", Listen: "127.0.0.1", Port: middlePort,
			Targets: []shared.ForwardTarget{{Host: echoHost, Port: echoPort}},
			Enabled: true,
		},
	}, "", sigPath)
	if err != nil {
		t.Fatalf("StartWithOptions: %v", err)
	}
	defer svc.Close()

	entryConn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(entryPort)), 2*time.Second)
	if err != nil {
		t.Fatalf("dial entry: %v", err)
	}
	defer entryConn.Close()
	midConn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(middlePort)), 2*time.Second)
	if err != nil {
		t.Fatalf("dial mid: %v", err)
	}
	defer midConn.Close()

	// Write active entry-protection signal file and poll it.
	raw, _ := json.Marshal(EntryProtectionSignal{Active: true, UpdatedAt: time.Now().UTC()})
	if err := os.WriteFile(sigPath, raw, 0600); err != nil {
		t.Fatalf("write signal: %v", err)
	}
	svc.pollEntryProtectionFile()

	// Entry connection must be terminated immediately.
	_ = entryConn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := entryConn.Read(make([]byte, 1)); err == nil {
		t.Fatalf("expected active entry connection to close when entry protection triggered")
	}

	// Non-entry middle hop must remain unaffected!
	if _, err := midConn.Write([]byte("midOK")); err != nil {
		t.Fatalf("write mid: %v", err)
	}
	_ = midConn.SetReadDeadline(time.Now().Add(time.Second))
	midBuf := make([]byte, 5)
	if _, err := io.ReadFull(midConn, midBuf); err != nil || string(midBuf) != "midOK" {
		t.Fatalf("expected non-entry forward to stay alive, got %q err=%v", string(midBuf), err)
	}

	// Clear protection signal -> entry resumes.
	raw, _ = json.Marshal(EntryProtectionSignal{Active: false, UpdatedAt: time.Now().UTC()})
	_ = os.WriteFile(sigPath, raw, 0600)
	svc.pollEntryProtectionFile()

	entryConn2, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(entryPort)), 2*time.Second)
	if err != nil {
		t.Fatalf("dial entry after clear: %v", err)
	}
	defer entryConn2.Close()
	_, _ = entryConn2.Write([]byte("back"))
	_ = entryConn2.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 4)
	if _, err := io.ReadFull(entryConn2, b); err != nil || string(b) != "back" {
		t.Fatalf("expected entry route to resume after protection cleared, got %q err=%v", string(b), err)
	}
}

// TestManyShortTCPConnectionsRespectAggregateRate verifies Fix #1: 128
// concurrent short-lived TCP connections cannot each send a free chunk and
// bypass the shared 1 Mbps aggregate cap.
func TestManyShortTCPConnectionsRespectAggregateRate(t *testing.T) {
	prev := TestAllowLoopbackTarget
	TestAllowLoopbackTarget = true
	defer func() { TestAllowLoopbackTarget = prev }()

	host, port, stop := startSinkTCP(t)
	defer stop()
	listen := freeTCPPort(t)
	const rate = 125_000 // 1 Mbps

	svc, err := Start([]shared.ForwardRule{{
		ID: "short-tcp", Name: "short-tcp", RouteID: "route-short", EntryHop: true,
		Network: "tcp", Listen: "127.0.0.1", Port: listen,
		Targets: []shared.ForwardTarget{{Host: host, Port: port}},
		Enabled: true, RouteUpSpeedLimitBps: rate,
	}})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer svc.Close()

	start := time.Now()
	var wg sync.WaitGroup
	payload := bytes.Repeat([]byte("x"), 16384)
	for i := 0; i < 128; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(listen)), time.Second)
			if err != nil {
				return
			}
			defer c.Close()
			_ = c.SetWriteDeadline(time.Now().Add(400 * time.Millisecond))
			_, _ = c.Write(payload)
		}()
	}
	wg.Wait()
	time.Sleep(150 * time.Millisecond)
	elapsed := time.Since(start)
	snaps := svc.RouteTrafficSnapshot("short")
	if len(snaps) != 1 {
		t.Fatalf("missing stats: %+v", snaps)
	}
	maxBudget := int64(elapsed.Seconds()*rate) + minBucketBurst + 32768
	if snaps[0].Uplink > maxBudget {
		t.Fatalf("1 Mbps cap bypassed by 128 short TCP conns: %d bytes in %s (budget %d bytes)", snaps[0].Uplink, elapsed, maxBudget)
	}
	t.Logf("128 short TCP conns at 1 Mbps cap: transferred %d bytes in %s (budget %d bytes)", snaps[0].Uplink, elapsed, maxBudget)
}

// TestUnchangedRateReloadPreservesRateDebt verifies Fix #1: reloading with the
// same rate keeps existing negative rate debt instead of refilling burst.
func TestUnchangedRateReloadPreservesRateDebt(t *testing.T) {
	now := time.Now()
	b := newTokenBucket(1000, now)
	b.mu.Lock()
	b.tokens = -100_000
	b.mu.Unlock()
	b.setRate(1000, now.Add(time.Millisecond))
	b.mu.Lock()
	tokens := b.tokens
	b.mu.Unlock()
	if tokens >= 0 {
		t.Fatalf("unchanged-rate reload discarded rate debt and granted %.0f bytes", tokens)
	}
}

// TestEntryProtectionRuleFlagClearsOnCycleRollover verifies Fix #3: an entry
// protection flag delivered via DesiredState clears automatically on cycle
// rollover even if the panel is unreachable.
func TestEntryProtectionRuleFlagClearsOnCycleRollover(t *testing.T) {
	now := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	start, end := shared.MonthlyCycleBounds(now, 1, time.UTC)
	g := newLimitGroup("cycle-clear", now)
	g.configure(shared.ForwardRule{
		EntryProtectionBlocked:    true,
		EntryProtectionCycleStart: start.UTC().UnixMilli(),
		EntryProtectionCycleEnd:   end.UTC().UnixMilli(),
		RouteTrafficTimezone:      "UTC",
	}, now)
	if blocked, _ := g.blocked(now.Add(time.Hour), false); !blocked {
		t.Fatal("expected blocked during active protection cycle")
	}
	nextCycle := time.Date(2026, 12, 1, 1, 0, 0, 0, time.UTC)
	if blocked, _ := g.blocked(nextCycle, false); blocked {
		t.Fatal("entry protection remained blocked after cycle rollover despite cleared local protection")
	}
}

// TestEntryProtectionPersistsAcrossForwardRestartAndExpiresNextCycle verifies
// Fix #2: a persistent signal file keeps protection active across forwarder
// restarts and automatically expires once CycleEndMs is reached.
func TestEntryProtectionPersistsAcrossForwardRestartAndExpiresNextCycle(t *testing.T) {
	prev := TestAllowLoopbackTarget
	TestAllowLoopbackTarget = true
	defer func() { TestAllowLoopbackTarget = prev }()

	echoHost, echoPort, stopEcho := startEchoTCP(t)
	defer stopEcho()
	port := freeTCPPort(t)
	sigPath := filepath.Join(t.TempDir(), "entry-protection.json")

	now := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	start, end := shared.MonthlyCycleBounds(now, 1, time.UTC)
	raw, _ := json.Marshal(EntryProtectionSignal{
		Active:       true,
		CycleStartMs: start.UTC().UnixMilli(),
		CycleEndMs:   end.UTC().UnixMilli(),
		UpdatedAt:    now,
	})
	if err := os.WriteFile(sigPath, raw, 0600); err != nil {
		t.Fatalf("write signal: %v", err)
	}

	var curNow atomic.Int64
	curNow.Store(now.UnixNano())
	clock := func() time.Time { return time.Unix(0, curNow.Load()).UTC() }

	ruleSpec := shared.ForwardRule{
		ID: "ep-restart", Name: "ep-restart", RouteID: "rt-ep", EntryHop: true,
		Network: "tcp", Listen: "127.0.0.1", Port: port,
		Targets: []shared.ForwardTarget{{Host: echoHost, Port: echoPort}},
		Enabled: true,
	}

	// Simulate fresh forwarder restart reading persistent signal file.
	svc, err := StartWithOptions(nil, "", sigPath)
	if err != nil {
		t.Fatalf("StartWithOptions: %v", err)
	}
	defer svc.Close()
	svc.SetClock(clock)
	svc.pollEntryProtectionFile()
	if err := svc.Reload([]shared.ForwardRule{ruleSpec}); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	// Connection must be blocked immediately after restart.
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(port)), time.Second)
	if err == nil {
		_, _ = c.Write([]byte("blocked"))
		_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, rerr := c.Read(make([]byte, 8))
		_ = c.Close()
		if rerr == nil && n > 0 {
			t.Fatal("expected restarted forwarder to keep entry protection active")
		}
	}

	// Advance into next cycle -> expired signal file must unblock automatically.
	curNow.Store(end.Add(time.Minute).UnixNano())
	svc.pollEntryProtectionFile()
	c2, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(port)), time.Second)
	if err != nil {
		t.Fatalf("dial after cycle end: %v", err)
	}
	defer c2.Close()
	_, _ = c2.Write([]byte("open"))
	_ = c2.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c2, buf); err != nil || string(buf) != "open" {
		t.Fatalf("expected entry protection signal to expire on next cycle, got %q err=%v", string(buf), err)
	}
}

// TestDisabledRouteRestartPreservesNonFirstDayAndTimezoneUsage verifies Fix #5:
// a disabled route with a non-1st reset day and non-local timezone retains its
// persisted cycle usage across forwarder restarts until its cycle ends.
func TestDisabledRouteRestartPreservesNonFirstDayAndTimezoneUsage(t *testing.T) {
	tz := time.FixedZone("UTC+8", 8*3600)
	now := time.Date(2026, 11, 22, 10, 0, 0, 0, tz)
	start, end := shared.MonthlyCycleBounds(now, 15, tz)
	path := filepath.Join(t.TempDir(), "state.json")
	raw, _ := json.Marshal(persistedLimitState{
		Version: 1,
		Routes: []shared.RouteTrafficState{{
			RouteID:      "disabled-rt",
			CycleStartMs: start.UTC().UnixMilli(),
			CycleEndMs:   end.UTC().UnixMilli(),
			Uplink:       123456,
			ResetDay:     15,
			Timezone:     "UTC+8",
			TZOffset:     8 * 3600,
		}},
	})
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	svc, err := StartWithOptions(nil, path, "")
	if err != nil {
		t.Fatal(err)
	}
	svc.SetClock(func() time.Time { return now })
	svc.Close()

	savedRaw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var saved persistedLimitState
	if err := json.Unmarshal(savedRaw, &saved); err != nil {
		t.Fatal(err)
	}
	if len(saved.Routes) != 1 || saved.Routes[0].Uplink != 123456 || saved.Routes[0].ResetDay != 15 {
		t.Fatalf("disabled route lost persisted usage or cycle context on restart: %s", savedRaw)
	}
}

// TestRouteHotReloadRaceWithActiveConnections verifies Fix #4 under -race:
// concurrent Reload() calls updating limits while TCP & UDP traffic is active
// produce zero data races.
func TestRouteHotReloadRaceWithActiveConnections(t *testing.T) {
	prev := TestAllowLoopbackTarget
	TestAllowLoopbackTarget = true
	defer func() { TestAllowLoopbackTarget = prev }()

	echoHost, echoPort, stopEcho := startEchoTCP(t)
	defer stopEcho()
	udpHost, udpPort, stopUDP := startEchoUDP(t)
	defer stopUDP()
	tcpListen := freeTCPPort(t)
	udpListen := freeUDPPort(t)

	rulesFor := func(rate int64) []shared.ForwardRule {
		return []shared.ForwardRule{
			{
				ID: "race-tcp", Name: "race-tcp", RouteID: "rt-race", EntryHop: true,
				Network: "tcp", Listen: "127.0.0.1", Port: tcpListen,
				Targets: []shared.ForwardTarget{{Host: echoHost, Port: echoPort}},
				Enabled: true, RouteUpSpeedLimitBps: rate, RouteDownSpeedLimitBps: rate,
				RouteTrafficLimit: 100 << 20,
			},
			{
				ID: "race-udp", Name: "race-udp", RouteID: "rt-race", EntryHop: true,
				Network: "udp", Listen: "127.0.0.1", Port: udpListen,
				Targets: []shared.ForwardTarget{{Host: udpHost, Port: udpPort}},
				Enabled: true, RouteUpSpeedLimitBps: rate, RouteDownSpeedLimitBps: rate,
				RouteTrafficLimit: 100 << 20,
			},
		}
	}

	svc, err := Start(rulesFor(500_000))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer svc.Close()

	stopTraffic := make(chan struct{})
	var wg sync.WaitGroup
	// Active TCP traffic
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(tcpListen)), time.Second)
		if err != nil {
			return
		}
		defer c.Close()
		go func() { _, _ = io.Copy(io.Discard, c) }()
		chunk := bytes.Repeat([]byte("R"), 4096)
		for {
			select {
			case <-stopTraffic:
				return
			default:
				_ = c.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
				if _, err := c.Write(chunk); err != nil {
					return
				}
			}
		}
	}()
	// Active UDP traffic
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := net.DialTimeout("udp", net.JoinHostPort("127.0.0.1", itoa(udpListen)), time.Second)
		if err != nil {
			return
		}
		defer c.Close()
		pkt := bytes.Repeat([]byte("U"), 512)
		for {
			select {
			case <-stopTraffic:
				return
			default:
				_, _ = c.Write(pkt)
				time.Sleep(5 * time.Millisecond)
			}
		}
	}()

	// Repeated hot reloads changing speed caps while traffic flows.
	for i := 0; i < 15; i++ {
		rate := int64(250_000 + (i%3)*250_000)
		if err := svc.Reload(rulesFor(rate)); err != nil {
			t.Fatalf("Reload %d: %v", i, err)
		}
		_ = svc.RouteTrafficSnapshot("race")
		time.Sleep(10 * time.Millisecond)
	}
	close(stopTraffic)
	wg.Wait()
}

// TestOfflineProtectionSurvivesOnlineSignalPoll verifies that online signal
// file polling (when the online signal file is absent in offline mode) never
// clears locally active offline entry protection.
func TestOfflineProtectionSurvivesOnlineSignalPoll(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "online-only-signal.json")
	svc, err := StartWithOptions(nil, "", missing)
	if err != nil {
		t.Fatalf("StartWithOptions: %v", err)
	}
	defer svc.Close()

	svc.SetEntryProtectionBlocked(true)
	if !svc.entryBlocked.Load() {
		t.Fatal("failed to enable offline entry protection")
	}
	// Wait past entryProtectionPollInterval (2s) so online poll executes.
	time.Sleep(2300 * time.Millisecond)
	if !svc.entryBlocked.Load() {
		t.Fatal("online signal poll cleared locally active offline entry protection")
	}
	// Clearing offline protection unblocks cleanly.
	svc.SetEntryProtectionBlocked(false)
	if svc.entryBlocked.Load() {
		t.Fatal("expected entryBlocked to clear when offline protection disabled")
	}
}

// TestIdleConnectionsCannotBankRateBudget verifies that 24 idle TCP
// connections cannot pre-reserve and bank rate tokens while idle and then
// burst simultaneously above the global aggregate cap.
func TestIdleConnectionsCannotBankRateBudget(t *testing.T) {
	prev := TestAllowLoopbackTarget
	TestAllowLoopbackTarget = true
	defer func() { TestAllowLoopbackTarget = prev }()

	host, port, stop := startSinkTCP(t)
	defer stop()
	listen := freeTCPPort(t)
	const rate = 125_000 // 1 Mbps

	svc, err := Start([]shared.ForwardRule{{
		ID: "idle-budget", Name: "idle-budget", RouteID: "idle-budget", EntryHop: true,
		Network: "tcp", Listen: "127.0.0.1", Port: listen,
		Targets: []shared.ForwardTarget{{Host: host, Port: port}},
		Enabled: true, RouteUpSpeedLimitBps: rate,
	}})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer svc.Close()

	var clients []net.Conn
	for i := 0; i < 24; i++ {
		c, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(listen)), time.Second)
		if e != nil {
			t.Fatal(e)
		}
		clients = append(clients, c)
		defer c.Close()
	}
	// Idle for 2s so any pre-read reservation would have refilled the bucket.
	time.Sleep(2 * time.Second)

	started := time.Now()
	var wg sync.WaitGroup
	payload := bytes.Repeat([]byte("x"), 16*1024)
	for _, c := range clients {
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			_, _ = c.Write(payload)
		}(c)
	}
	wg.Wait()
	time.Sleep(200 * time.Millisecond)
	elapsed := time.Since(started)
	snap := svc.RouteTrafficSnapshot("idle-test")
	if len(snap) != 1 {
		t.Fatalf("snapshot %v", snap)
	}
	allowed := int64(elapsed.Seconds()*rate) + 2*minBucketBurst
	if snap[0].Uplink > allowed {
		t.Fatalf("idle connections banked aggregate budget: %d bytes in %s, allowed %d", snap[0].Uplink, elapsed, allowed)
	}
	t.Logf("24 idle TCP conns burst at 1 Mbps cap: %d bytes in %s (allowed %d)", snap[0].Uplink, elapsed, allowed)
}

func itoa(n int) string {
	return string(bytes.TrimSpace([]byte(time.Duration(0).String()[:0]))) + func(v int) string {
		if v == 0 {
			return "0"
		}
		var d [16]byte
		i := len(d)
		for v > 0 {
			i--
			d[i] = byte('0' + v%10)
			v /= 10
		}
		return string(d[i:])
	}(n)
}
