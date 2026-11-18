package forward

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"mui/internal/shared"
)

type qualityClock struct {
	g *relayQualityGroup
	t time.Time
}

func newQualityClock() qualityClock {
	t := time.Unix(1_800_000_000, 0)
	return qualityClock{g: newRelayQualityGroup(2, t), t: t}
}

func (c *qualityClock) tick(a, b time.Duration) {
	c.t = c.t.Add(5 * time.Second)
	c.g.observeProbes([]probeResult{{c.t, a, a >= 0}, {c.t, b, b >= 0}}, c.t)
}

func (c *qualityClock) repeat(n int, a, b time.Duration) {
	for range n {
		c.tick(a, b)
	}
}

func (c *qualityClock) expect(t *testing.T, state, reason string) {
	t.Helper()
	got, why, _, _ := (qualityRef{c.g, 0}).status()
	if got != state || reason != "" && why != reason {
		t.Fatalf("%v: state %s (%s), want %s (%s)", c.t, got, why, state, reason)
	}
}

func TestRelayQualitySlowHandshakeRequiresLocalAndPeerContrast(t *testing.T) {
	for _, bothSlow := range []bool{false, true} {
		t.Run(fmt.Sprintf("bothSlow=%t", bothSlow), func(t *testing.T) {
			c := newQualityClock()
			c.repeat(12*10, 20*time.Millisecond, 25*time.Millisecond)
			peer := 25 * time.Millisecond
			if bothSlow {
				peer = 280 * time.Millisecond
			}
			c.repeat(12, 300*time.Millisecond, peer)
			c.expect(t, shared.RelayNormal, "")
			c.repeat(14, 300*time.Millisecond, peer)
			if bothSlow {
				c.expect(t, shared.RelayNormal, "")
			} else {
				c.expect(t, shared.RelayDegraded, "slow_handshake")
			}
		})
	}
}

func TestRelayQualityProbeLossHardFailureAndProbationRecovery(t *testing.T) {
	c := newQualityClock()
	ok := 20 * time.Millisecond
	c.repeat(12, ok, ok)
	for range 9 {
		c.tick(-1, ok)
		c.repeat(3, ok, ok)
	}
	c.expect(t, shared.RelayDegraded, "probe_loss")
	c.tick(-1, ok)
	c.tick(-1, ok)
	c.expect(t, shared.RelayDown, "probe_failed")
	c.tick(ok, ok)
	c.expect(t, shared.RelayDown, "probe_failed")
	c.tick(ok, ok)
	c.expect(t, shared.RelayDegraded, "probe_failed")
	c.repeat(40, ok, ok)
	c.expect(t, shared.RelayProbation, "recovering")

	ref := qualityRef{c.g, 0}
	for i := 1; i <= 9; i++ {
		ref.observeConnection(netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}), qualityGood, c.t, c.t)
	}
	ref.observeConnection(netip.MustParseAddr("192.0.2.10"), qualityBad, c.t, c.t)
	c.repeat(25, ok, ok)
	c.expect(t, shared.RelayProbation, "recovering")
	ref.observeConnection(netip.MustParseAddr("192.0.2.10"), qualityGood, c.t, c.t)
	c.repeat(23, ok, ok)
	c.expect(t, shared.RelayProbation, "recovering")
	c.tick(ok, ok)
	c.expect(t, shared.RelayNormal, "healthy")
}

func TestRelayQualityBackoffDoublesCapsAndResets(t *testing.T) {
	c := newQualityClock()
	q := &c.g.targets[0]
	for _, want := range []time.Duration{4 * time.Minute, 8 * time.Minute, 16 * time.Minute, 30 * time.Minute, 30 * time.Minute} {
		q.transition(shared.RelayProbation, "recovering", c.t)
		q.evaluate(c.t, "blackhole", false)
		if q.state != shared.RelayDegraded || q.recovery != want {
			t.Fatalf("backoff %s in state %s, want %s", q.recovery, q.state, want)
		}
		q.evaluate(c.t, "", false)
		q.evaluate(c.t.Add(want-time.Second), "", false)
		if q.state != shared.RelayDegraded {
			t.Fatal("probation started before extended observation")
		}
		q.evaluate(c.t.Add(want), "", false)
		if q.state != shared.RelayProbation {
			t.Fatal("did not enter probation after observation")
		}
	}
	q.transition(shared.RelayNormal, "healthy", c.t)
	q.evaluate(c.t, "", true)
	q.evaluate(c.t.Add(time.Hour), "", true)
	if q.recovery != 2*time.Minute {
		t.Fatalf("normal for an hour kept the backoff at %s", q.recovery)
	}
}

func TestRelayQualityPassiveRatioThreshold(t *testing.T) {
	peer := relayQualitySignals{good: 12, bad: 8}
	if hit := (relayQualitySignals{good: 6, bad: 14}).passivelyWorseThan(peer); !hit {
		t.Fatal("exactly 30 percentage points should qualify")
	}
	if hit := (relayQualitySignals{good: 7, bad: 13}).passivelyWorseThan(peer); hit {
		t.Fatal("less than 30 percentage points should not qualify")
	}
}

func TestRelayQualityPassiveSignalRequiresDistinctSourcesAndPeer(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		badSources           int
		peerSamples, peerBad bool
		wantState            string
	}{
		{"same source", 1, true, false, shared.RelayNormal},
		{"19 sources", 19, true, false, shared.RelayNormal},
		{"missing comparator", 20, false, false, shared.RelayNormal},
		{"peer also bad", 20, true, true, shared.RelayNormal},
		{"blackhole", 20, true, false, shared.RelayDegraded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newQualityClock()
			good := qualityRef{c.g, 1}
			bad := qualityRef{c.g, 0}
			for tick := range 27 {
				if tick%6 == 0 {
					for range 100 {
						bad.observeConnection(netip.MustParseAddr("192.0.2.1"), qualityBad, c.t, c.t)
					}
					for i := range tc.badSources {
						bad.observeConnection(netip.AddrFrom4([4]byte{192, 0, 2, byte(1 + i)}), qualityBad, c.t, c.t)
					}
					if tc.peerSamples {
						result := qualityGood
						if tc.peerBad {
							result = qualityBad
						}
						for i := range 20 {
							good.observeConnection(netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)}), result, c.t, c.t)
						}
					}
				}
				c.tick(20*time.Millisecond, 20*time.Millisecond)
			}
			c.expect(t, tc.wantState, "")
			if tc.wantState == shared.RelayDegraded {
				c.expect(t, tc.wantState, "blackhole")
			}
		})
	}
}

func TestRelayQualityProbationAllocationAndOverrides(t *testing.T) {
	for _, balance := range []string{"round-robin", "failover"} {
		t.Run(balance, func(t *testing.T) {
			c := newQualityClock()
			r := &rule{spec: shared.ForwardRule{RouteID: "route", Balance: balance}, quality: c.g}
			for i := range 2 {
				target := newTarget("127.0.0.1", 10000+i)
				target.quality = qualityRef{c.g, i}
				r.targets = append(r.targets, target)
			}
			first, second := r.targets[0], r.targets[1]
			c.g.targets[0].transition(shared.RelayProbation, "recovering", c.t)
			selected := 0
			for range 100 {
				if r.candidates()[0] == first {
					selected++
				}
			}
			if selected != 10 {
				t.Fatalf("trial share %d/100", selected)
			}
			c.g.targets[0].transition(shared.RelayDegraded, "blackhole", c.t)
			if r.candidates()[0] != second {
				t.Fatal("degraded chosen ahead of normal")
			}
			first.updateRelay(shared.ForwardTarget{ServerID: "first", Override: shared.RelayNormal}, c.t)
			reported, _ := first.relaySnapshot("f", c.t)
			if reported.State != shared.RelayNormal || reported.AutoState != shared.RelayDegraded || reported.AutoReason != "blackhole" {
				t.Fatalf("unexpected overridden report %+v", reported)
			}
			first.markDown()
			if r.candidates()[0] != second {
				t.Fatal("manual normal hid hard failure")
			}
			first.updateRelay(shared.ForwardTarget{ServerID: "first"}, c.t)
			c.g.targets[0].transition(shared.RelayDegraded, "blackhole", c.t)
			c.g.targets[1].transition(shared.RelayDegraded, "probe_loss", c.t)
			got := r.candidates()
			if len(got) != 2 || balance == "failover" && got[0] != first {
				t.Fatalf("all degraded severed the route: %v", got)
			}
			if balance == "round-robin" && got[0] == r.candidates()[0] {
				t.Fatal("round-robin did not treat all automatically degraded targets as normal")
			}
			first.updateRelay(shared.ForwardTarget{Override: shared.RelayDown}, c.t)
			got = r.candidates()
			if len(got) != 1 || got[0] != second {
				t.Fatal("manual down escaped isolation")
			}
		})
	}
}

func TestRelayQualityRealTCPBlackholeAndClientAbort(t *testing.T) {
	for _, mode := range []string{"upstream EOF", "upstream RST", "client first", "no first byte"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "no first byte" {
				before := tcpInitialTimeout
				tcpInitialTimeout = 100 * time.Millisecond
				t.Cleanup(func() { tcpInitialTimeout = before })
			}
			backend, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer backend.Close()
			backendDone := make(chan struct{})
			go func() {
				defer close(backendDone)
				c, err := backend.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(time.Second))
				if mode == "upstream RST" {
					_ = c.(*net.TCPConn).SetLinger(0)
				}
				_, _ = io.ReadFull(c, make([]byte, 4))
				if mode == "client first" || mode == "no first byte" {
					_, _ = io.Copy(io.Discard, c)
				}
			}()
			backup := tcpBackend(t, "127.0.0.1:0", "B")
			port := freePort(t, "tcp")
			spec := balancedRule("tcp+udp", port, "failover", backend.Addr().(*net.TCPAddr).Port, backup)
			spec.RouteID, spec.HealthCheck = "route", "tcp"
			s, err := Start([]shared.ForwardRule{spec})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			tcp := s.rules[spec.ID+"\x00tcp"]
			if udp := s.rules[spec.ID+"\x00udp"]; tcp.quality == nil || udp.quality != tcp.quality {
				t.Fatal("TCP and UDP do not share their target quality group")
			}
			client, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			_ = client.SetDeadline(time.Now().Add(time.Second))
			if _, err := client.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			if mode == "client first" {
				_ = client.(*net.TCPConn).CloseWrite()
			}
			if mode != "no first byte" {
				_, _ = io.Copy(io.Discard, client)
				<-backendDone
			}
			n := func() int {
				tcp.quality.mu.Lock()
				defer tcp.quality.mu.Unlock()
				return len(tcp.quality.targets[0].passive)
			}
			if mode == "client first" {
				if got := n(); got != 0 {
					t.Fatalf("client abort counted as upstream failure: %d", got)
				}
			} else {
				eventually(t, "upstream failure counted", func() bool { return n() == 1 })
			}
		})
	}
}

func TestRelayProbationTenMinuteShortcutRequiresCleanObservations(t *testing.T) {
	for _, mode := range []string{"clean", "passive failure", "failed probe", "slow probe"} {
		t.Run(mode, func(t *testing.T) {
			c := newQualityClock()
			ok := 20 * time.Millisecond
			c.repeat(12*10, ok, ok)
			c.g.targets[0].transition(shared.RelayProbation, "recovering", c.t)
			c.repeat(12, ok, ok)
			switch mode {
			case "passive failure":
				(qualityRef{c.g, 0}).observeConnection(netip.MustParseAddr("192.0.2.1"), qualityBad, c.t, c.t)
				c.tick(ok, ok)
			case "failed probe":
				c.tick(-1, ok)
			case "slow probe":
				c.tick(400*time.Millisecond, ok)
			default:
				c.tick(ok, ok)
			}
			c.repeat(106, ok, ok)
			c.expect(t, shared.RelayProbation, "recovering")
			c.tick(ok, ok)
			if mode == "clean" {
				c.expect(t, shared.RelayNormal, "healthy")
			} else {
				c.expect(t, shared.RelayProbation, "recovering")
			}
		})
	}
}
