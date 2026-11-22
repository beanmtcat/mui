package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"mui/internal/forward"
	"mui/internal/shared"
)

// evaluateEntryTrafficProtection evaluates local entry-server total traffic
// protection against the host's NIC counters. It runs on the entry server so
// protection triggers and recovers on cycle rollover even if the panel is
// unreachable.
func evaluateEntryTrafficProtection(state *trafficState, policy *shared.EntryTrafficProtectionPolicy, now time.Time) (*shared.EntryTrafficProtectionState, int64, bool) {
	if policy == nil || !policy.Enabled || policy.LimitBytes <= 0 {
		changed := state.EntryProtectionActive
		state.EntryProtectionActive = false
		state.EntryProtectionTriggeredAt = nil
		state.EntryProtectionTriggeredUsed = 0
		return nil, 0, changed
	}
	loc := shared.ResolveTrafficLocation(policy.Timezone, policy.TZOffset, time.Local)
	start, end := shared.MonthlyCycleBounds(now, policy.ResetDay, loc)
	startMs := start.UTC().UnixMilli()
	endMs := end.UTC().UnixMilli()

	changed := false
	if state.EntryCycleStartMs != startMs {
		// New cycle (or reset day changed): reset local counters and auto-clear protection.
		state.EntryCycleStartMs = startMs
		state.EntryCycleRx = 0
		state.EntryCycleTx = 0
		if state.EntryProtectionActive {
			changed = true
		}
		state.EntryProtectionActive = false
		state.EntryProtectionTriggeredAt = nil
		state.EntryProtectionTriggeredUsed = 0
	}
	if policy.CycleStartMs == startMs {
		if policy.BaselineRx > state.EntryCycleRx {
			state.EntryCycleRx = policy.BaselineRx
		}
		if policy.BaselineTx > state.EntryCycleTx {
			state.EntryCycleTx = policy.BaselineTx
		}
	}
	used := shared.ComputeServerTrafficUsed(state.EntryCycleRx, state.EntryCycleTx, policy.LimitType)
	thresholdBytes := shared.EntryProtectionThresholdBytes(policy.LimitBytes, policy.ThresholdPercent)
	shouldBlock := thresholdBytes > 0 && used >= thresholdBytes
	if shouldBlock && !state.EntryProtectionActive {
		t := now.UTC()
		state.EntryProtectionActive = true
		state.EntryProtectionTriggeredAt = &t
		state.EntryProtectionTriggeredUsed = used
		changed = true
	} else if !shouldBlock && state.EntryProtectionActive {
		state.EntryProtectionActive = false
		state.EntryProtectionTriggeredAt = nil
		state.EntryProtectionTriggeredUsed = 0
		changed = true
	}
	return &shared.EntryTrafficProtectionState{
		Active:         state.EntryProtectionActive,
		CycleStartMs:   startMs,
		TriggeredAt:    state.EntryProtectionTriggeredAt,
		TriggeredUsed:  state.EntryProtectionTriggeredUsed,
		ThresholdBytes: thresholdBytes,
		LimitBytes:     policy.LimitBytes,
		Source:         "agent",
	}, endMs, changed
}

func syncEntryTrafficProtection(state *trafficState, host HostStatus, lastSynced *int, now time.Time) *shared.EntryTrafficProtectionState {
	current := ReadCurrent()
	protState, cycleEndMs, changed := evaluateEntryTrafficProtection(state, current.EntryTrafficProtection, now)
	active := protState != nil && protState.Active
	want := 0
	if active {
		want = 1
	}
	fileDrift := host.Supported && ((active && (!host.EntryProtectionFileExists || !host.EntryProtectionFileActive)) || (!active && host.EntryProtectionFileActive))
	if changed || *lastSynced != want || fileDrift {
		var cycleStart int64
		if protState != nil {
			cycleStart = protState.CycleStartMs
		}
		if err := CallHelper("entry.protection", shared.DesiredState{
			EntryTrafficProtection: &shared.EntryTrafficProtectionPolicy{
				Enabled:      active,
				CycleStartMs: cycleStart,
				CycleEndMs:   cycleEndMs,
			},
		}); err != nil {
			fmt.Fprintln(os.Stderr, "entry protection sync:", err)
		} else {
			*lastSynced = want
		}
	}
	if changed {
		_ = saveTraffic(*state)
	}
	return protState
}

func writeEntryProtectionSignal(path string, active bool, cycleStartMs, cycleEndMs int64, group string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	sig := forward.EntryProtectionSignal{
		Active:       active,
		CycleStartMs: cycleStartMs,
		CycleEndMs:   cycleEndMs,
		UpdatedAt:    time.Now().UTC(),
	}
	data, err := json.Marshal(sig)
	if err != nil {
		return err
	}
	if group != "" {
		return writeOwnedSignal(path, data, group)
	}
	return writeFileAtomic(path, data, 0640)
}

func readEntryProtectionPolicy(path string) *shared.EntryTrafficProtectionPolicy {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var policy shared.EntryTrafficProtectionPolicy
	if err := json.Unmarshal(raw, &policy); err != nil || !policy.Enabled || policy.LimitBytes <= 0 {
		return nil
	}
	return &policy
}

func loadTrafficAt(path string) trafficState {
	var s trafficState
	s.Last = map[string][2]int64{}
	s.LastUsers = map[string][2]int64{}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	return s
}

func saveTrafficAt(path string, s trafficState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, b, 0600)
}

// runOfflineEntryProtectionLoop runs inside standalone mui-agent forward when
// an offline-exported entry-protection-policy.json is present, sampling host
// NIC counters directly and toggling service entry-hop blocking locally.
func runOfflineEntryProtectionLoop(ctx context.Context, policyPath, nicStatePath string, svc *forward.Service, interval time.Duration) {
	state := loadTrafficAt(nicStatePath)
	step := func() {
		policy := readEntryProtectionPolicy(policyPath)
		if policy == nil {
			// Policy removed or disabled: clear offline protection only (never
			// interferes with online signal-file protection).
			if state.EntryProtectionActive {
				state.EntryProtectionActive = false
				state.EntryProtectionTriggeredAt = nil
				state.EntryProtectionTriggeredUsed = 0
				_ = saveTrafficAt(nicStatePath, state)
			}
			svc.SetEntryProtectionBlocked(false)
			return
		}
		if err := sampleServerTrafficAt(&state, nicStatePath); err != nil {
			fmt.Fprintln(os.Stderr, "offline entry nic sample:", err)
		}
		protState, _, changed := evaluateEntryTrafficProtection(&state, policy, time.Now())
		if changed {
			_ = saveTrafficAt(nicStatePath, state)
		}
		svc.SetEntryProtectionBlocked(protState != nil && protState.Active)
	}
	step()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			step()
		}
	}
}
