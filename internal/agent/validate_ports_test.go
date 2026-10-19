package agent

import (
	"mui/internal/shared"
	"testing"
)

func TestDesiredSnellInnerPortConflicts(t *testing.T) {
	n := shared.ManagedNode{Node: shared.Node{ID: "12345678901234567890123456789012", Name: "Snell", Protocol: "snell", Port: 54321, SnellPort: 23456, ShadowTLSHost: "example.com", Enabled: true}, Password: "snell-secret", ShadowTLSPassword: "outer-secret"}
	state := shared.DesiredState{Revision: 1, Nodes: []shared.ManagedNode{n}}
	if err := ValidateDesired(state); err != nil {
		t.Fatal(err)
	}
	state.Forwards = []shared.ForwardRule{{ID: "22345678901234567890123456789012", Name: "forward", Listen: "0.0.0.0", Port: 23456, Network: "tcp", Targets: []shared.ForwardTarget{{Host: "example.com", Port: 443}}, Enabled: true, FirewallPolicy: "all"}}
	if err := ValidateDesired(state); err == nil {
		t.Fatal("forward can occupy Snell inner listener")
	}
	state.Forwards[0].Network = "udp"
	if err := ValidateDesired(state); err != nil {
		t.Fatalf("UDP can share a TCP-only inner port: %v", err)
	}
	other := n
	other.Node.ID = "32345678901234567890123456789012"
	other.Node.Port++
	state.Nodes = append(state.Nodes, other)
	if err := ValidateDesired(state); err == nil {
		t.Fatal("duplicate inner port accepted")
	}
}

func TestDesiredTCPUDPOwnsBothPorts(t *testing.T) {
	f := shared.ForwardRule{ID: "12345678901234567890123456789012", Name: "both", Network: shared.ForwardTCPUDP, Listen: "0.0.0.0", Port: 51000, Targets: []shared.ForwardTarget{{Host: "198.51.100.5", Port: 51000}}, Enabled: true, FirewallPolicy: "all"}
	for _, network := range []string{"tcp", "udp"} {
		state := shared.DesiredState{Revision: 1, Forwards: []shared.ForwardRule{f}}
		if err := ValidateDesired(state); err != nil {
			t.Fatal(err)
		}
		other := f
		other.ID = "22345678901234567890123456789012"
		other.Network = network
		state.Forwards = append(state.Forwards, other)
		if ValidateDesired(state) == nil {
			t.Fatalf("combined rule failed to reserve %s", network)
		}
	}
}
