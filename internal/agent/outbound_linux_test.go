//go:build linux

package agent

import (
	"mui/internal/shared"
	"strings"
	"testing"
)

func TestOutboundCoreCapabilities(t *testing.T) {
	if strings.Contains(coreUnitForState(shared.DesiredState{}), "CAP_NET_RAW") {
		t.Fatal("unbound core gained RAW capability")
	}
	for _, state := range []shared.DesiredState{{OutboundInterface: "ppp0"}, {Nodes: []shared.ManagedNode{{Node: shared.Node{Enabled: true, OutboundMode: "interface", OutboundInterface: "eth0"}}}}} {
		unit := coreUnitForState(state)
		if !strings.Contains(unit, "User=mui-core") || !strings.Contains(unit, "AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW") || !strings.Contains(unit, "CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW") {
			t.Fatal(unit)
		}
	}
}
