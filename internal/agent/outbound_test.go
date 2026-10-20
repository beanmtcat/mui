package agent

import (
	"mui/internal/shared"
	"net"
	"testing"
)

func TestOutboundInterfacePreflight(t *testing.T) {
	all, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	name := ""
	for _, iface := range all {
		if iface.Flags&net.FlagUp != 0 {
			name = iface.Name
			break
		}
	}
	if name == "" {
		t.Skip("no enabled network interface")
	}
	state := shared.DesiredState{OutboundInterface: name}
	if err := checkOutboundInterfaces(state); err != nil {
		t.Fatal(err)
	}
	state.OutboundInterface = "mui-absent0"
	if err := checkOutboundInterfaces(state); err == nil {
		t.Fatal("accepted nonexistent default interface")
	}
	state.OutboundInterface = ""
	state.Nodes = []shared.ManagedNode{{Node: shared.Node{Enabled: true, OutboundMode: "interface", OutboundInterface: "mui-absent0"}}}
	if err := checkOutboundInterfaces(state); err == nil {
		t.Fatal("accepted nonexistent node interface")
	}
	state.Nodes[0].Node.Enabled = false
	if err := checkOutboundInterfaces(state); err != nil {
		t.Fatalf("disabled override prevented apply: %v", err)
	}
	state.OutboundInterface = "../bad"
	if err := ValidateDesired(state); err == nil {
		t.Fatal("invalid server interface accepted by validator")
	}
}
