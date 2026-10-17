package forward

import (
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"mui/internal/shared"
)

func fastHealth(t *testing.T) {
	t.Helper()
	oldInterval, oldTimeout := healthInterval, healthTimeout
	healthInterval, healthTimeout = 30*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() { healthInterval, healthTimeout = oldInterval, oldTimeout })
}

func balancedRule(network string, port int, balance string, targets ...int) shared.ForwardRule {
	rule := shared.ForwardRule{ID: "lb", Name: "lb", Network: network, Listen: "127.0.0.1", Port: port, Balance: balance, Enabled: true}
	for _, target := range targets {
		rule.Targets = append(rule.Targets, shared.ForwardTarget{Host: "127.0.0.1", Port: target})
	}
	return rule
}

func TestFailoverSkipsDeadTargetAndReturnsWhenItRecovers(t *testing.T) {
	fastHealth(t)
	primary := freePort(t, "tcp") // nothing listens here yet
	backup := tcpBackend(t, "127.0.0.1:0", "B")
	port := freePort(t, "tcp")
	service, err := Start([]shared.ForwardRule{balancedRule("tcp", port, "failover", primary, backup)})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	conn, name := greet(t, port)
	if conn == nil || name != "B" {
		t.Fatalf("with the primary down the backup must answer, got %q", name)
	}
	conn.Close()
	tcpBackend(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(primary)), "A")
	eventually(t, "new connections return to the recovered primary", func() bool {
		conn, name := greet(t, port)
		if conn != nil {
			conn.Close()
		}
		return name == "A"
	})
}

func TestRoundRobinSpreadsConnections(t *testing.T) {
	fastHealth(t)
	a, b := tcpBackend(t, "127.0.0.1:0", "A"), tcpBackend(t, "127.0.0.1:0", "B")
	port := freePort(t, "tcp")
	service, err := Start([]shared.ForwardRule{balancedRule("tcp", port, "round-robin", a, b)})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	seen := map[string]int{}
	for range 6 {
		conn, name := greet(t, port)
		if conn == nil {
			t.Fatal("connect")
		}
		conn.Close()
		seen[name]++
	}
	if seen["A"] != 3 || seen["B"] != 3 {
		t.Fatalf("round-robin should alternate: %v", seen)
	}
}

// udpBackend answers every datagram with its name. A TCP listener on the same
// port stands for the health check, as a forwarder or SS node has both.
func udpBackend(t *testing.T, name string) (port int, stopTCP func()) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 64)
		for {
			_, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteTo([]byte(name), from)
		}
	}()
	port = conn.LocalAddr().(*net.UDPAddr).Port
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Skipf("cannot pair a TCP listener with UDP port %d: %v", port, err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return port, func() { listener.Close() }
}

func TestUDPSessionMovesOffATargetThatGoesDown(t *testing.T) {
	fastHealth(t)
	primary, stopPrimary := udpBackend(t, "A")
	backup, _ := udpBackend(t, "B")
	port := freePort(t, "udp")
	spec := balancedRule("udp", port, "failover", primary, backup)
	spec.HealthCheck = "tcp" // This target explicitly provides paired TCP health.
	service, err := Start([]shared.ForwardRule{spec})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	client, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	answer := func() string {
		_ = client.SetDeadline(time.Now().Add(200 * time.Millisecond))
		if _, err := client.Write([]byte("?")); err != nil {
			return ""
		}
		buf := make([]byte, 8)
		n, err := client.Read(buf)
		if err != nil {
			return ""
		}
		return string(buf[:n])
	}
	eventually(t, "primary answers", func() bool { return answer() == "A" })
	stopPrimary()
	eventually(t, "the same client is moved to the backup", func() bool { return answer() == "B" })
}

// A route's TCP and UDP forwards to the same destinations share one probe.
func TestRulesShareHealthProbes(t *testing.T) {
	fastHealth(t)
	var accepted atomic.Int64
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			c.Close()
		}
	}()
	target := listener.Addr().(*net.TCPAddr).Port
	other := tcpBackend(t, "127.0.0.1:0", "B")
	tcpRule := balancedRule("tcp", freePort(t, "tcp"), "failover", target, other)
	udpRule := balancedRule("udp", freePort(t, "udp"), "failover", target, other)
	tcpRule.ID, udpRule.ID = "t", "u"
	udpRule.HealthCheck = "tcp"
	service, err := Start([]shared.ForwardRule{tcpRule, udpRule})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * healthInterval)
	service.Close()
	// Two rules probing separately would connect about 40 times.
	if n := accepted.Load(); n == 0 || n > 25 {
		t.Fatalf("expected one shared probe per interval, got %d connections in 20 intervals", n)
	}
}
