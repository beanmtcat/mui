package forward

import (
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"mui/internal/shared"
)

func udpOnlyBackend(t *testing.T, address, name string) (int, func()) {
	t.Helper()
	conn, err := net.ListenPacket("udp", address)
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
			conn.WriteTo([]byte(name), from)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).Port, func() { conn.Close() }
}

func udpAnswer(client net.Conn) string {
	client.SetDeadline(time.Now().Add(40 * time.Millisecond))
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

func TestUDPOnlyTargetsRoundRobinWithoutTCPHealth(t *testing.T) {
	fastHealth(t)
	a, _ := udpOnlyBackend(t, "127.0.0.1:0", "A")
	b, _ := udpOnlyBackend(t, "127.0.0.1:0", "B")
	port := freePort(t, "udp")
	svc, err := Start([]shared.ForwardRule{balancedRule("udp", port, "round-robin", a, b)})
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	time.Sleep(4 * healthInterval) // Previously both healthy UDP targets became down.
	seen := map[string]int{}
	for range 6 {
		c, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			t.Fatal(err)
		}
		name := udpAnswer(c)
		c.Close()
		seen[name]++
	}
	if seen["A"] != 3 || seen["B"] != 3 {
		t.Fatalf("UDP-only round robin: %v", seen)
	}
}

func TestUDPOnlySessionFailsOverAndRetriesRecoveredPrimary(t *testing.T) {
	fastHealth(t)
	healthInterval = 100 * time.Millisecond
	a, stopA := udpOnlyBackend(t, "127.0.0.1:0", "A")
	b, _ := udpOnlyBackend(t, "127.0.0.1:0", "B")
	port := freePort(t, "udp")
	svc, err := Start([]shared.ForwardRule{balancedRule("udp", port, "failover", a, b)})
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	c, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	eventually(t, "primary UDP answer", func() bool { return udpAnswer(c) == "A" })
	stopA()
	eventually(t, "same client moves to backup after UDP socket error", func() bool { return udpAnswer(c) == "B" })
	udpOnlyBackend(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(a)), "A")
	eventually(t, "same client retries recovered primary", func() bool { return udpAnswer(c) == "A" })
}

func TestRoundRobinFallbackRotatesWhenAllTargetsAreDown(t *testing.T) {
	r := &rule{spec: shared.ForwardRule{Balance: "round-robin"}, targets: []*target{newTarget("192.0.2.1", 53), newTarget("192.0.2.2", 53)}}
	for _, target := range r.targets {
		target.markDown()
	}
	seen := map[*target]int{}
	for range 6 {
		seen[r.candidates()[0]]++
	}
	if seen[r.targets[0]] != 3 || seen[r.targets[1]] != 3 {
		t.Fatalf("fallback remains pinned: %v", seen)
	}
}

func TestDualStackForwardAcceptsIPv4AndIPv6(t *testing.T) {
	// A skip here means the test host has no IPv6 support; IPv4 tests still run.
	probe, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 unavailable: %v", err)
	}
	probe.Close()
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			var backend int
			if network == "tcp" {
				backend = tcpBackend(t, "[::1]:0", "A")
			} else {
				backend, _ = udpOnlyBackend(t, "[::1]:0", "A")
			}
			port := freePort(t, network)
			spec := shared.ForwardRule{ID: "dual", Name: "dual", Network: network, Listen: "::", Port: port, Targets: []shared.ForwardTarget{{Host: "::1", Port: backend}}, Enabled: true}
			svc, err := Start([]shared.ForwardRule{spec})
			if err != nil {
				t.Fatal(err)
			}
			defer svc.Close()
			for _, host := range []string{"127.0.0.1", "::1"} {
				c, err := net.DialTimeout(network, net.JoinHostPort(host, strconv.Itoa(port)), time.Second)
				if err != nil {
					t.Fatalf("%s: %v", host, err)
				}
				if network == "udp" {
					answer := udpAnswer(c)
					c.Close()
					if answer != "A" {
						t.Fatalf("%s: UDP answer %q", host, answer)
					}
				} else {
					c.SetDeadline(time.Now().Add(time.Second))
					reply := make([]byte, 1)
					_, err := io.ReadFull(c, reply)
					c.Close()
					if err != nil || string(reply) != "A" {
						t.Fatalf("%s: TCP %q %v", host, reply, err)
					}
				}
			}
		})
	}
}
