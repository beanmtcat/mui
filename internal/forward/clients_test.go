package forward

import (
	"fmt"
	"io"
	"mui/internal/shared"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestEntryClientSourcesTCPAndUDP(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			var port int
			if network == "tcp" {
				l, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer l.Close()
				port = l.Addr().(*net.TCPAddr).Port
				go func() {
					for {
						c, e := l.Accept()
						if e != nil {
							return
						}
						go func() { defer c.Close(); io.Copy(c, c) }()
					}
				}()
			} else {
				l, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer l.Close()
				port = l.LocalAddr().(*net.UDPAddr).Port
				go func() {
					buf := make([]byte, 2048)
					for {
						n, a, e := l.ReadFrom(buf)
						if e != nil {
							return
						}
						l.WriteTo(buf[:n], a)
					}
				}()
			}
			rule := shared.ForwardRule{ID: "entry", Name: "entry", Network: network, Listen: "127.0.0.1", Port: freePort(t, network), Targets: []shared.ForwardTarget{{Host: "127.0.0.1", Port: port}}, Enabled: true, ObserveClients: true, RouteID: "route", ClientNodeID: "node"}
			s, err := Start([]shared.ForwardRule{rule})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			c, err := net.Dial(network, net.JoinHostPort("127.0.0.1", strconv.Itoa(rule.Port)))
			if err != nil {
				t.Fatal(err)
			}
			c.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err = c.Write([]byte("hello")); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 5)
			if _, err = io.ReadFull(c, buf); err != nil {
				t.Fatal(err)
			}
			c.Close()
			eventually(t, "entry captures short connections", func() bool {
				p := s.ConnectionSnapshot()
				return len(p) == 1 && p[0].IP == "127.0.0.1" && p[0].RouteID == "route" && p[0].NodeID == "node"
			})
			// Intermediate hops must not create observations presented as clients.
			rule.ObserveClients = false
			if err = s.Reload([]shared.ForwardRule{rule}); err != nil {
				t.Fatal(err)
			}
			count := len(s.ConnectionSnapshot())
			if count != 1 {
				t.Fatal(count)
			}
		})
	}
}

func TestClientObservationLimitsAndExpiry(t *testing.T) {
	s := &Service{rules: map[string]*rule{}}
	spec := shared.ForwardRule{ID: "f", RouteID: "r", ClientNodeID: "n", ObserveClients: true}
	for i := 0; i < maxClientObservations+100; i++ {
		s.clients.record(spec, sourceOf(&net.TCPAddr{IP: net.ParseIP(fmt.Sprintf("203.0.%d.%d", i/250, i%250+1))}), time.Now())
	}
	if got := len(s.ConnectionSnapshot()); got != maxClientObservations {
		t.Fatal(got)
	}
	s2 := &Service{rules: map[string]*rule{}}
	s2.clients.record(spec, sourceOf(&net.TCPAddr{IP: net.ParseIP("203.0.113.1")}), time.Now().Add(-3*time.Minute))
	if len(s2.ConnectionSnapshot()) != 0 {
		t.Fatal("expired observations retained")
	}
	spec.ObserveClients = false
	s2.clients.record(spec, sourceOf(&net.TCPAddr{IP: net.ParseIP("203.0.113.2")}), time.Now())
	if len(s2.ConnectionSnapshot()) != 0 {
		t.Fatal("intermediate source presented as client")
	}
}
