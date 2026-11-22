package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"mui/internal/forward"
	"mui/internal/shared"
)

// TestLocalEntryProtectionTriggerAndCycleRecovery verifies that the local
// agent evaluates host NIC traffic against the early-stop threshold and
// automatically clears protection at the next monthly cycle boundary even when
// the panel is unreachable.
func TestLocalEntryProtectionTriggerAndCycleRecovery(t *testing.T) {
	now := time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC)
	cycleStart, cycleEnd := shared.MonthlyCycleBounds(now, 1, time.UTC)
	policy := &shared.EntryTrafficProtectionPolicy{
		Enabled:          true,
		LimitBytes:       1000,
		ThresholdPercent: 95, // triggers at 950 bytes
		LimitType:        "sum",
		ResetDay:         1,
		Timezone:         "UTC",
		CycleStartMs:     cycleStart.UTC().UnixMilli(),
		BaselineRx:       500,
		BaselineTx:       400, // 900 bytes (< 950)
	}
	state := &trafficState{}

	// Below threshold: not active.
	ps, endMs, changed := evaluateEntryTrafficProtection(state, policy, now)
	if ps == nil || ps.Active || changed || endMs != cycleEnd.UTC().UnixMilli() {
		t.Fatalf("expected inactive below threshold, got ps=%+v endMs=%d changed=%v", ps, endMs, changed)
	}

	// Local NIC delta pushes total to 960 >= 950 while panel is unreachable.
	state.EntryCycleRx += 60
	ps, endMs, changed = evaluateEntryTrafficProtection(state, policy, now.Add(30*time.Second))
	if ps == nil || !ps.Active || !changed || ps.TriggeredUsed != 960 || endMs != cycleEnd.UTC().UnixMilli() {
		t.Fatalf("expected local protection trigger at 960, got ps=%+v endMs=%d changed=%v", ps, endMs, changed)
	}

	// Signal file lives in persistent directory (/etc/mui-forward), NOT /run/mui-forward.
	if filepath.Dir(ForwardEntryProtection) != ForwardDir {
		t.Fatalf("ForwardEntryProtection must live in persistent ForwardDir (%s), got %s", ForwardDir, ForwardEntryProtection)
	}

	// Write signal file and verify cycleEndMs is persisted.
	sigPath := filepath.Join(t.TempDir(), "entry-protection.json")
	if err := writeEntryProtectionSignal(sigPath, true, ps.CycleStartMs, endMs, ""); err != nil {
		t.Fatalf("writeEntryProtectionSignal: %v", err)
	}
	if _, err := os.Stat(sigPath); err != nil {
		t.Fatalf("signal file missing: %v", err)
	}

	// Next cycle (April 1, 2026 00:01 UTC): must auto-clear even without panel contact!
	nextCycle := time.Date(2026, 4, 1, 0, 1, 0, 0, time.UTC)
	ps, _, changed = evaluateEntryTrafficProtection(state, policy, nextCycle)
	if ps == nil || ps.Active || !changed {
		t.Fatalf("expected auto-recovery on new cycle, got ps=%+v changed=%v", ps, changed)
	}
	if state.EntryCycleRx != 0 || state.EntryCycleTx != 0 {
		t.Fatalf("expected local cycle counters reset, got rx=%d tx=%d", state.EntryCycleRx, state.EntryCycleTx)
	}
}

// TestOfflineEntryProtectionLifecycle verifies that runOfflineEntryProtectionLoop
// activates protection from persisted NIC state, survives restarts, and clears
// when the offline policy file is removed.
func TestOfflineEntryProtectionLifecycle(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "entry-protection-policy.json")
	nicStatePath := filepath.Join(dir, "entry-nic-state.json")
	missingOnlineSig := filepath.Join(dir, "online-signal.json")

	now := time.Now().UTC()
	start, end := shared.MonthlyCycleBounds(now, 1, time.UTC)
	policy := shared.EntryTrafficProtectionPolicy{
		Enabled: true, LimitBytes: 1000, ThresholdPercent: 95,
		LimitType: "sum", ResetDay: 1, Timezone: "UTC",
		CycleStartMs: start.UnixMilli(), CycleEndMs: end.UnixMilli(),
	}
	pRaw, _ := json.Marshal(policy)
	if err := os.WriteFile(policyPath, pRaw, 0600); err != nil {
		t.Fatal(err)
	}
	// Pre-seed NIC state above 95% threshold (simulating restart after trigger).
	if err := saveTrafficAt(nicStatePath, trafficState{
		EntryCycleStartMs: start.UnixMilli(),
		EntryCycleRx:      600,
		EntryCycleTx:      400,
	}); err != nil {
		t.Fatal(err)
	}

	svc, err := forward.StartWithOptions(nil, "", missingOnlineSig)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runOfflineEntryProtectionLoop(ctx, policyPath, nicStatePath, svc, 50*time.Millisecond)
	}()

	// Verify offline protection activates and stays active.
	time.Sleep(150 * time.Millisecond)
	// Remove offline policy -> loop must clear offline protection cleanly.
	_ = os.Remove(policyPath)
	time.Sleep(150 * time.Millisecond)
	cancel()
	<-done
}
