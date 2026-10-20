//go:build linux

package agent

import (
	"mui/internal/shared"
	"testing"
)

func TestRuntimeForwardsKeepsClientMetadata(t *testing.T) {
	f := shared.ForwardRule{ID: "f", RouteID: "r", ObserveClients: true, ClientNodeID: "n", Enabled: true}
	out := runtimeForwards(shared.DesiredState{Forwards: []shared.ForwardRule{f}})
	if len(out) != 1 || !out[0].ObserveClients || out[0].RouteID != "r" || out[0].ClientNodeID != "n" {
		t.Fatal(out)
	}
}
