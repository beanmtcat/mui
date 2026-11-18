package forward

import (
	"net"
	"slices"
	"strconv"
	"testing"
	"time"

	"mui/internal/shared"
)

func TestRelayManualCandidatesAndLocalExpiry(t *testing.T) {
	now := time.Now()
	expired := now.Add(-2 * time.Minute)
	soon := now.Add(-30 * time.Second)
	spec := []shared.ForwardTarget{
		{ServerID: "A", Override: shared.RelayDegraded},
		{ServerID: "B", Override: shared.RelayDown},
		{ServerID: "C", Override: shared.RelayNormal},
		{ServerID: "D"},
		{ServerID: "E", Override: shared.RelayDown, OverrideUntil: &expired},
		{ServerID: "F", Override: shared.RelayDown, OverrideUntil: &soon},
	}
	rule := &rule{spec: shared.ForwardRule{RouteID: "route", Balance: "round-robin"}}
	for i, spec := range spec {
		tr := newTarget("127.0.0.1", 12300+i)
		tr.updateRelay(spec, now)
		rule.targets = append(rule.targets, tr)
	}
	rule.targets[2].markDown()
	rule.targets[3].markDown()
	snapshot, _ := rule.targets[2].relaySnapshot("rule", now)
	if snapshot.State != shared.RelayDown || snapshot.Source != "auto" || snapshot.AutoState != shared.RelayDown {
		t.Fatalf("normal override suppressed automatic failure: %+v", snapshot)
	}
	for _, want := range [][]string{{"E", "A", "C", "D"}, {"E", "A", "C", "D"}} {
		var got []string
		for _, tr := range rule.candidates() {
			got = append(got, tr.relay.serverID)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("candidates %v, want %v", got, want)
		}
	}
}

func TestRelayNormalOverrideStillFailsOverOnDialFailure(t *testing.T) {
	primary := freePort(t, "tcp")
	backup := tcpBackend(t, "127.0.0.1:0", "B")
	port := freePort(t, "tcp")
	rule := balancedRule("tcp", port, "failover", primary, backup)
	rule.RouteID = "route"
	rule.Targets[0].ServerID, rule.Targets[0].Override = "primary", shared.RelayNormal
	service, err := Start([]shared.ForwardRule{rule})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	conn, seen := greet(t, port)
	if seen != "B" {
		t.Fatalf("client reached %q", seen)
	}
	conn.Close()
	points := service.RelaySnapshot()
	if len(points) != 1 || points[0].AutoState != shared.RelayDown || points[0].State != shared.RelayDown {
		t.Fatalf("did not observe a failed dial under a normal override: %+v", points)
	}
}

func TestRelayOverrideReloadKeepsListenerAndEstablishedTCP(t *testing.T) {
	a, b := tcpBackend(t, "127.0.0.1:0", "A"), tcpBackend(t, "127.0.0.1:0", "B")
	port := freePort(t, "tcp")
	spec := balancedRule("tcp", port, "failover", a, b)
	spec.RouteID = "route"
	spec.Targets[0].ServerID, spec.Targets[1].ServerID = "A", "B"
	service, err := Start([]shared.ForwardRule{spec})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	conn, seen := greet(t, port)
	if seen != "A" {
		t.Fatalf("before reload reached %q", seen)
	}
	defer conn.Close()
	live := service.rules[spec.ID+"\x00tcp"]
	spec.Targets = slices.Clone(spec.Targets)
	spec.Targets[0].Override = shared.RelayDown
	if err = service.Reload([]shared.ForwardRule{spec}); err != nil {
		t.Fatal(err)
	}
	if service.rules[spec.ID+"\x00tcp"] != live || !echoes(conn) {
		t.Fatal("TCP rule was replaced or its existing connection no longer works")
	}
	fresh, seen := greet(t, port)
	if seen != "B" {
		t.Fatalf("new connection after manual down reached %q", seen)
	}
	fresh.Close()
}

func TestRelayOverrideUDPDegradedKeepsSessionAndDownMovesIt(t *testing.T) {
	a, _ := udpBackend(t, "A")
	b, _ := udpBackend(t, "B")
	port := freePort(t, "udp")
	spec := balancedRule("udp", port, "failover", a, b)
	spec.RouteID = "route"
	service, err := Start([]shared.ForwardRule{spec})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	client := func() net.Conn {
		c, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	assertAnswer := func(c net.Conn, want string) {
		t.Helper()
		_ = c.SetDeadline(time.Now().Add(time.Second))
		if _, err := c.Write([]byte("?")); err != nil {
			t.Fatal(err)
		}
		var buf [8]byte
		n, err := c.Read(buf[:])
		if err != nil || string(buf[:n]) != want {
			t.Fatalf("UDP answer %q, want %q: %v", buf[:n], want, err)
		}
	}
	c := client()
	assertAnswer(c, "A")
	spec.Targets = slices.Clone(spec.Targets)
	spec.Targets[0].Override = shared.RelayDegraded
	if err = service.Reload([]shared.ForwardRule{spec}); err != nil {
		t.Fatal(err)
	}
	assertAnswer(c, "A")
	assertAnswer(client(), "B")
	spec.Targets[0].Override = shared.RelayDown
	if err = service.Reload([]shared.ForwardRule{spec}); err != nil {
		t.Fatal(err)
	}
	assertAnswer(c, "B")
}

func TestRelayNormalOverrideSkipsFailedPrimaryUntilRecovery(t *testing.T) {
	primary := freePort(t, "tcp")
	backup := tcpBackend(t, "127.0.0.1:0", "B")
	port := freePort(t, "tcp")
	spec := balancedRule("tcp", port, "failover", primary, backup)
	spec.RouteID, spec.HealthCheck = "route", "none"
	spec.Targets[0].Override = shared.RelayNormal
	service, err := Start([]shared.ForwardRule{spec})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	expect := func(want string) {
		t.Helper()
		conn, seen := greet(t, port)
		if conn != nil {
			conn.Close()
		}
		if seen != want {
			t.Fatalf("connection reached %q, want %q", seen, want)
		}
	}
	expect("B") // The failed first dial marks the primary down.
	tcpBackend(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(primary)), "A")
	expect("B") // A first attempt to the primary would succeed now.
	target := service.rules[spec.ID+"\x00tcp"].targets[0]
	target.observe(true)
	expect("B")
	target.observe(true)
	expect("A")
}

func TestRelayDownstreamReloadKeepsTCPAndRestoresPriority(t *testing.T) {
	a, b := tcpBackend(t, "127.0.0.1:0", "A"), tcpBackend(t, "127.0.0.1:0", "B")
	port := freePort(t, "tcp")
	spec := balancedRule("tcp", port, "failover", a, b)
	spec.RouteID = "route"
	spec.Targets[0].ServerID, spec.Targets[0].Override = "A", shared.RelayNormal
	s, err := Start([]shared.ForwardRule{spec})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	oldRule := s.rules[spec.ID+"\x00tcp"]
	assertBackend := func(want string) net.Conn {
		t.Helper()
		conn, seen := greet(t, port)
		if seen != want {
			t.Fatalf("reached %q, want %q", seen, want)
		}
		return conn
	}
	original := assertBackend("A")
	defer original.Close()
	spec.Targets = slices.Clone(spec.Targets)
	spec.Targets[0].Downstream = shared.RelayDown
	if err := s.Reload([]shared.ForwardRule{spec}); err != nil {
		t.Fatal(err)
	}
	if s.rules[spec.ID+"\x00tcp"] != oldRule || !echoes(original) {
		t.Fatal("downstream-only reload replaced the rule or lost its TCP connection")
	}
	assertBackend("B").Close()
	r := s.RelaySnapshot()[0]
	if r.State != shared.RelayDown || r.Source != "auto" || r.Reason != "downstream_down" {
		t.Fatalf("manual normal hid downstream failure: %+v", r)
	}
	current := oldRule.candidates()
	if len(current) != 2 || current[1] != oldRule.targets[0] {
		t.Fatal("downstream failure must keep the target last as fallback")
	}
	spec.Targets[0].Downstream = ""
	if err := s.Reload([]shared.ForwardRule{spec}); err != nil {
		t.Fatal(err)
	}
	assertBackend("A").Close()
	if !echoes(original) {
		t.Fatal("clearing the downstream hint interrupted the established connection")
	}
}
