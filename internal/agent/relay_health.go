package agent

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"syscall"
	"time"

	"mui/internal/shared"
)

const relaySnapshotPath = "/run/mui-forward/relay-states.json"

type relaySnapshot struct {
	At     time.Time           `json:"at"`
	States []shared.RelayState `json:"states"`
}

func writeRelaySnapshot(states []shared.RelayState) error {
	raw, err := json.Marshal(relaySnapshot{At: time.Now(), States: states})
	if err != nil {
		return err
	}
	return writeFileAtomic(relaySnapshotPath, raw, 0600)
}

func readRelaySnapshot() []shared.RelayState {
	f, err := os.OpenFile(relaySnapshotPath, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil
	}
	defer f.Close()
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
		return nil
	}
	var snapshot relaySnapshot
	if json.NewDecoder(io.LimitReader(f, 8<<20)).Decode(&snapshot) != nil || time.Since(snapshot.At) > time.Minute || time.Until(snapshot.At) > time.Minute {
		return nil
	}
	return snapshot.States
}

func relayReportBatch(points []shared.RelayState, offset *int) []shared.RelayState {
	if len(points) <= shared.MaxRelayReport {
		*offset = 0
		return points
	}
	start := *offset % len(points)
	end := min(start+shared.MaxRelayReport, len(points))
	*offset = end
	return points[start:end]
}

// Relay-only updates must never fall back to restarting an active forwarder.
func onlyRelayForwardChanges(previous []byte, next []shared.ForwardRule) bool {
	var old []shared.ForwardRule
	if json.Unmarshal(previous, &old) != nil || len(old) != len(next) {
		return false
	}
	clearMetadata := func(rules []shared.ForwardRule) []byte {
		clean := make([]shared.ForwardRule, len(rules))
		for i, rule := range rules {
			clean[i] = rule
			clean[i].Targets = make([]shared.ForwardTarget, len(rule.Targets))
			for j, target := range rule.Targets {
				clean[i].Targets[j] = shared.ForwardTarget{Host: target.Host, Port: target.Port}
			}
		}
		out, _ := json.Marshal(clean)
		return out
	}
	oldRaw, _ := json.Marshal(old)
	nextRaw, _ := json.Marshal(next)
	return !bytes.Equal(oldRaw, nextRaw) && bytes.Equal(clearMetadata(old), clearMetadata(next))
}

// A running forwarder without a service-unit change keeps its sockets on reload.
func applyForwardService(command func(...string) (string, error), wait func([]byte) error, raw []byte, running, unitChanged bool) error {
	if _, err := command("enable", "mui-forward.service"); err != nil {
		return err
	}
	action := "restart"
	if running && !unitChanged {
		action = "reload"
	}
	if _, err := command(action, "mui-forward.service"); err != nil {
		return err
	}
	return wait(raw)
}
