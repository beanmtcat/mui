package agent

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"mui/internal/shared"
)

func TestOnlyRelayForwardChanges(t *testing.T) {
	old := []shared.ForwardRule{{ID: "r", RouteID: "route", Port: 50000, Targets: []shared.ForwardTarget{{Host: "192.0.2.1", Port: 443}}}}
	raw, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	if onlyRelayForwardChanges(raw, old) {
		t.Fatal("unchanged rules were treated as a relay update")
	}
	next := slices.Clone(old)
	next[0].Targets = slices.Clone(old[0].Targets)
	next[0].Targets[0].Downstream = shared.RelayDown
	if !onlyRelayForwardChanges(raw, next) {
		t.Fatal("downstream-only update was missed")
	}
	next[0].Targets[0].Downstream = ""
	until := time.Now().UTC().Add(time.Hour)
	next[0].Targets[0].ServerID = "relay"
	next[0].Targets[0].Override, next[0].Targets[0].OverrideUntil = shared.RelayDown, &until
	if !onlyRelayForwardChanges(raw, next) {
		t.Fatal("relay-only update was missed")
	}
	next[0].Targets[0].Port++
	if onlyRelayForwardChanges(raw, next) {
		t.Fatal("endpoint change was incorrectly classified as in-place")
	}
	next[0].Targets[0].Port--
	next[0].FirewallSources = "192.0.2.2"
	if onlyRelayForwardChanges(raw, next) {
		t.Fatal("firewall change was incorrectly classified as in-place")
	}
}

func TestApplyForwardServiceActiveReloadDoesNotRestartOnFailure(t *testing.T) {
	for _, reloadErr := range []error{nil, errors.New("test reload failed")} {
		var calls []string
		cmd := func(args ...string) (string, error) {
			calls = append(calls, args[0])
			if args[0] == "reload" {
				return "", reloadErr
			}
			return "", nil
		}
		wait := func([]byte) error {
			calls = append(calls, "wait")
			return nil
		}
		want := []string{"enable", "reload"}
		if reloadErr == nil {
			want = append(want, "wait")
		}
		if err := applyForwardService(cmd, wait, nil, true, false); err != reloadErr || !slices.Equal(calls, want) {
			t.Fatalf("reload calls %v, error %v", calls, err)
		}
	}
}
