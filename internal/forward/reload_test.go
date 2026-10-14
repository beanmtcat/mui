package forward

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"mui/internal/shared"
)

func TestMain(m *testing.M) {
	relayTick = 20 * time.Millisecond
	sweepInterval = 30 * time.Millisecond
	resolveInterval = 40 * time.Millisecond
	// The forward tests run their backends on loopback, which the
	// production SSRF guards must refuse. Enable the test-only escape
	// hatch for this package's tests; it stays false in production.
	TestAllowLoopbackTarget = true
	os.Exit(m.Run())
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("never happened: %s", what)
}

// tcpBackend answers every connection with its name and then echoes.
func tcpBackend(t *testing.T, address, name string) int {
	t.Helper()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Skipf("cannot listen on %s: %v", address, err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = conn.Write([]byte(name))
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}

// greet connects through a forward and returns the backend's one-byte name.
func greet(t *testing.T, port int) (net.Conn, string) {
	t.Helper()
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return nil, ""
	}
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	name := make([]byte, 1)
	if _, err = io.ReadFull(conn, name); err != nil {
		conn.Close()
		return nil, ""
	}
	return conn, string(name)
}

func echoes(conn net.Conn) bool {
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		return false
	}
	reply := make([]byte, 4)
	_, err := io.ReadFull(conn, reply)
	return err == nil && string(reply) == "ping"
}

func TestReloadKeepsUnchangedRulesAndTheirConnections(t *testing.T) {
	a, b, c := tcpBackend(t, "127.0.0.1:0", "A"), tcpBackend(t, "127.0.0.1:0", "B"), tcpBackend(t, "127.0.0.1:0", "C")
	keepPort, movePort, dropPort := freePort(t, "tcp"), freePort(t, "tcp"), freePort(t, "tcp")
	rule := func(id string, port, target int) shared.ForwardRule {
		return shared.ForwardRule{ID: id, Name: id, Network: "tcp", Listen: "127.0.0.1", Port: port, TargetHost: "127.0.0.1", TargetPort: target, Enabled: true}
	}
	service, err := Start([]shared.ForwardRule{rule("keep", keepPort, a), rule("move", movePort, b), rule("drop", dropPort, b)})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	kept, name := greet(t, keepPort)
	if name != "A" {
		t.Fatalf("keep rule reached %q", name)
	}
	defer kept.Close()
	moved, name := greet(t, movePort)
	if name != "B" {
		t.Fatalf("move rule reached %q", name)
	}
	defer moved.Close()
	eventually(t, "bytes counted before the reload", func() bool { return service.Snapshot()["keep"].Downlink == 1 })

	if err = service.Reload([]shared.ForwardRule{rule("keep", keepPort, a), rule("move", movePort, c)}); err != nil {
		t.Fatal(err)
	}
	if !echoes(kept) {
		t.Fatal("a connection of an unchanged rule did not survive the reload")
	}
	if echoes(moved) {
		t.Fatal("a connection to the old destination of a changed rule is still served")
	}
	if conn, name := greet(t, movePort); name != "C" {
		t.Fatalf("changed rule reaches %q, want C", name)
	} else {
		conn.Close()
	}
	if conn, _ := greet(t, dropPort); conn != nil {
		t.Fatal("a removed rule still accepts connections")
	}
	eventually(t, "counters continue across the reload", func() bool { return service.Snapshot()["keep"].Downlink == 5 })

	// A rule that cannot bind fails the reload and leaves the others running.
	busy, _ := net.Listen("tcp", "127.0.0.1:0")
	defer busy.Close()
	err = service.Reload([]shared.ForwardRule{rule("keep", keepPort, a), rule("move", movePort, b), rule("clash", busy.Addr().(*net.TCPAddr).Port, a)})
	if err == nil {
		t.Fatal("reload onto an occupied port reported success")
	}
	if !echoes(kept) {
		t.Fatal("a failed reload disturbed a running rule")
	}
	// The helper restores the previous file with another Reload. An unrelated
	// connection must survive both the failed change and its rollback.
	if err = service.Reload([]shared.ForwardRule{rule("keep", keepPort, a), rule("move", movePort, c)}); err != nil {
		t.Fatal(err)
	}
	if !echoes(kept) {
		t.Fatal("rollback interrupted a connection of an unchanged rule")
	}
	if conn, name := greet(t, movePort); name != "C" {
		t.Fatalf("rollback reached %q, want C", name)
	} else {
		conn.Close()
	}
}

func TestSlowDNSDoesNotDelayListeningOrShutdown(t *testing.T) {
	defer func(old func(context.Context, string, string) ([]netip.Addr, error)) { lookupNetIP = old }(lookupNetIP)
	var lookups atomic.Int64
	lookupNetIP = func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
		lookups.Add(1)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	port := freePort(t, "tcp")
	start := time.Now()
	service, err := Start([]shared.ForwardRule{{ID: "dns", Name: "dns", Network: "tcp", Listen: "127.0.0.1", Port: port, TargetHost: "slow.test", TargetPort: 443, Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	if time.Since(start) > time.Second {
		t.Fatal("starting the listener waited for DNS")
	}
	eventually(t, "background DNS lookup started", func() bool { return lookups.Load() > 0 })
	start = time.Now()
	service.Close()
	if time.Since(start) > time.Second {
		t.Fatal("stopping the listener waited for the DNS timeout")
	}
}

func TestIdleTCPConnectionIsClosedAndABusyOneIsNot(t *testing.T) {
	defer func(old time.Duration) { tcpIdleTimeout = old }(tcpIdleTimeout)
	tcpIdleTimeout = 250 * time.Millisecond
	port := freePort(t, "tcp")
	service, err := Start([]shared.ForwardRule{{ID: "r", Name: "r", Network: "tcp", Listen: "127.0.0.1", Port: port, TargetHost: "127.0.0.1", TargetPort: tcpBackend(t, "127.0.0.1:0", "A"), Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	idle, _ := greet(t, port)
	busy, _ := greet(t, port)
	if idle == nil || busy == nil {
		t.Fatal("connect")
	}
	defer idle.Close()
	defer busy.Close()
	// A trickle far below any chunk size still counts as activity.
	for end := time.Now().Add(700 * time.Millisecond); time.Now().Before(end); time.Sleep(60 * time.Millisecond) {
		if !echoes(busy) {
			t.Fatal("a connection that keeps exchanging data was closed as idle")
		}
	}
	_ = idle.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := idle.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("idle connection not closed by the forwarder: %v", err)
	}
	eventually(t, "idle slot released", func() bool { return service.tcpTotal.Load() == 1 })
}

func TestHostNameTargetFollowsDNS(t *testing.T) {
	// Two backends on the same port, one per address family, stand in for a
	// name whose record changes.
	v4 := tcpBackend(t, "127.0.0.1:0", "4")
	v6 := tcpBackend(t, net.JoinHostPort("::1", strconv.Itoa(v4)), "6")
	if v6 != v4 {
		t.Skip("could not bind both families on one port")
	}
	udp4, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(v4)))
	if err != nil {
		t.Skip(err)
	}
	defer udp4.Close()
	udp6, err := net.ListenPacket("udp", net.JoinHostPort("::1", strconv.Itoa(v4)))
	if err != nil {
		t.Skip(err)
	}
	defer udp6.Close()
	for name, backend := range map[string]net.PacketConn{"4": udp4, "6": udp6} {
		go func() {
			buf := make([]byte, 64)
			for {
				_, from, err := backend.ReadFrom(buf)
				if err != nil {
					return
				}
				_, _ = backend.WriteTo([]byte(name), from)
			}
		}()
	}
	var answer atomic.Value
	answer.Store(netip.MustParseAddr("127.0.0.1"))
	lookups := atomic.Int64{}
	defer func(old func(context.Context, string, string) ([]netip.Addr, error)) { lookupNetIP = old }(lookupNetIP)
	lookupNetIP = func(_ context.Context, _, host string) ([]netip.Addr, error) {
		if host != "target.test" {
			t.Errorf("looked up %q", host)
		}
		lookups.Add(1)
		return []netip.Addr{answer.Load().(netip.Addr)}, nil
	}
	tcpPort, udpPort := freePort(t, "tcp"), freePort(t, "udp")
	service, err := Start([]shared.ForwardRule{
		{ID: "t", Name: "t", Network: "tcp", Listen: "127.0.0.1", Port: tcpPort, TargetHost: "target.test", TargetPort: v4, Enabled: true},
		{ID: "u", Name: "u", Network: "udp", Listen: "127.0.0.1", Port: udpPort, TargetHost: "target.test", TargetPort: v4, Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	old, name := greet(t, tcpPort)
	if name != "4" {
		t.Fatalf("TCP reached %q before the change", name)
	}
	defer old.Close()
	client, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(udpPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ask := func() string {
		_ = client.SetDeadline(time.Now().Add(300 * time.Millisecond))
		if _, err := client.Write([]byte("?")); err != nil {
			return ""
		}
		reply := make([]byte, 8)
		n, err := client.Read(reply)
		if err != nil {
			return ""
		}
		return string(reply[:n])
	}
	eventually(t, "initial UDP DNS answer is used", func() bool { return ask() == "4" })
	before := lookups.Load()
	for i := 0; i < 20; i++ {
		ask()
	}
	if lookups.Load() > before+3 {
		t.Fatalf("datagrams triggered %d lookups; resolution must stay in the background", lookups.Load()-before)
	}

	answer.Store(netip.MustParseAddr("::1"))
	eventually(t, "new TCP connections follow the name", func() bool {
		conn, name := greet(t, tcpPort)
		if conn != nil {
			conn.Close()
		}
		return name == "6"
	})
	// The same UDP client, without doing anything, ends up at the new address.
	eventually(t, "the UDP session moves to the new address", func() bool { return ask() == "6" })
	// An established TCP connection is not cut by a DNS change.
	if !echoes(old) {
		t.Fatal("an established TCP connection was closed when the name moved")
	}
}

func TestUDPSessionGrowsForLargeDatagrams(t *testing.T) {
	backend, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	large := bytes.Repeat([]byte("x"), 9000)
	go func() {
		buf := make([]byte, 64)
		for {
			_, from, err := backend.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = backend.WriteTo(large, from)
		}
	}()
	port := freePort(t, "udp")
	service, err := Start([]shared.ForwardRule{{ID: "u", Name: "u", Network: "udp", Listen: "127.0.0.1", Port: port, TargetHost: "127.0.0.1", TargetPort: backend.LocalAddr().(*net.UDPAddr).Port, Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	client, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	reply := make([]byte, 16000)
	// The first oversized reply is lost while the session's buffer grows; after
	// that they arrive whole, never cut short.
	eventually(t, "large datagrams delivered intact", func() bool {
		_ = client.SetDeadline(time.Now().Add(200 * time.Millisecond))
		if _, err := client.Write([]byte("?")); err != nil {
			return false
		}
		n, err := client.Read(reply)
		if err == nil && n != len(large) {
			t.Fatalf("a truncated datagram of %d bytes was forwarded", n)
		}
		return err == nil
	})
}

func TestTargetAddressPolicy(t *testing.T) {
	for addr, refused := range map[string]bool{
		"127.0.0.1": true, "::1": true, "0.0.0.0": true, "169.254.169.254": true, "fe80::1": true,
		"224.0.0.1": true, "100.100.100.200": true, "fd00:ec2::254": true, "::ffff:127.0.0.1": true,
		// Relaying into a private network or to CGNAT and other public space is normal.
		"10.0.0.5": false, "192.168.1.10": false, "172.16.3.4": false, "fd12:3456::1": false,
		"100.64.1.1": false, "100.100.1.1": false, "8.8.8.8": false, "2001:4860::8888": false,
	} {
		if got := rejectPrivateAddr(netip.MustParseAddr(addr)); got != refused {
			t.Errorf("%s: refused=%v, want %v", addr, got, refused)
		}
	}
}
