package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"mui/internal/shared"
)

type trafficState struct {
	InstanceID        string                      `json:"instanceId"`
	Sequence          int64                       `json:"sequence"`
	Last              map[string][2]int64         `json:"last"`
	Pending           []shared.TrafficPoint       `json:"pending"`
	LastUsers         map[string][2]int64         `json:"lastUsers"`
	UserPending       []shared.UserTrafficPoint   `json:"userPending"`
	NetworkBoot       string                      `json:"networkBoot"`
	NetworkKernelBoot string                      `json:"networkKernelBoot"`
	NetworkIface      string                      `json:"networkIface"`
	NetworkSequence   int64                       `json:"networkSequence"`
	NetworkLast       [2]int64                    `json:"networkLast"`
	NetworkPending    []shared.ServerTrafficPoint `json:"networkPending"`
}

const pendingJobPath = DataDir + "/pending-job.json"

// Samples wait here while the panel is unreachable. Thirty-second samples of a
// busy host fill this in about a week; beyond that the oldest are dropped.
const maxPendingPoints = 20000

// copySlice returns a fresh backing array holding the same elements, so a
// truncated pending slice does not keep the old, larger array alive.
func copySlice[T any](s []T) []T {
	out := make([]T, len(s))
	copy(out, s)
	return out
}

// truncatePending keeps at most max newest elements, copied into a new slice.
func truncatePending[T any](s []T, max int) []T {
	if len(s) <= max {
		return s
	}
	return copySlice(s[len(s)-max:])
}

// writeFileAtomic writes data to path via a temp file in the same directory,
// fsyncs the file, renames it over path, and fsyncs the directory.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".mui-tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return fsyncDir(dir)
}

func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// claimedJob is the on-disk form of pending-job.json. Claimed marks a job
// that was accepted but not yet executed; Report holds the executed result
// awaiting acknowledgement. Job carries the full claimed job (including the
// DesiredState) so a restart can re-execute a claim that never ran.
type claimedJob struct {
	Claimed bool               `json:"claimed"`
	Report  shared.AgentReport `json:"report"`
	Job     shared.Job         `json:"job,omitempty"`
}

func loadPendingJob() claimedJob {
	data, err := os.ReadFile(pendingJobPath)
	if err != nil {
		return claimedJob{}
	}
	var claimed claimedJob
	if err := json.Unmarshal(data, &claimed); err == nil && (claimed.Claimed || claimed.Report.JobID != "" || claimed.Job.ID != "") {
		return claimed
	}
	// Old format: a bare AgentReport holding an executed result.
	var report shared.AgentReport
	if err := json.Unmarshal(data, &report); err == nil && report.JobID != "" {
		return claimedJob{Claimed: true, Report: report}
	}
	return claimedJob{}
}

func writePendingJob(claimed claimedJob) error {
	data, err := json.Marshal(claimed)
	if err != nil {
		return err
	}
	tmp := pendingJobPath + ".tmp"
	if err = os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, pendingJobPath)
}

// savePendingJob persists an executed job's result. It keeps the original
// signature: callers pass the result report.
func savePendingJob(report shared.AgentReport) error {
	return writePendingJob(claimedJob{Claimed: true, Report: report})
}

// saveClaimedJob persists a job claim before it is executed.
func saveClaimedJob(job shared.Job) error {
	return writePendingJob(claimedJob{Claimed: true, Job: job, Report: shared.AgentReport{JobID: job.ID, JobKind: job.Kind, FencingToken: job.FencingToken}})
}

func loadTraffic() trafficState {
	var s trafficState
	s.Last = map[string][2]int64{}
	s.LastUsers = map[string][2]int64{}
	b, err := os.ReadFile(DataDir + "/traffic.json")
	if err == nil {
		_ = json.Unmarshal(b, &s)
	}
	if s.Last == nil {
		s.Last = map[string][2]int64{}
	}
	if s.LastUsers == nil {
		s.LastUsers = map[string][2]int64{}
	}
	return s
}

func saveTraffic(s trafficState) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	// Skip the write when nothing changed, so an idle agent does not rewrite
	// traffic.json on every successful report.
	// Still write if the file went missing, so a deleted traffic.json is recreated.
	if lastTrafficBytes != nil && bytes.Equal(b, lastTrafficBytes) {
		if _, err := os.Stat(DataDir + "/traffic.json"); err == nil {
			return nil
		}
	}
	tmp := DataDir + "/traffic.json.tmp"
	if err = os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	if err = os.Rename(tmp, DataDir+"/traffic.json"); err != nil {
		return err
	}
	lastTrafficBytes = b
	return nil
}

var lastTrafficBytes []byte

func sampleTraffic(ctx context.Context, state *trafficState) error {
	current := ReadCurrent()
	if len(current.Nodes) == 0 {
		return nil
	}
	stats, err := ReadStats(ctx)
	if err != nil {
		return err
	}
	instance := coreInstanceID()
	if instance == "" {
		return errors.New("sing-box process not running")
	}
	if state.InstanceID != instance {
		state.InstanceID = instance
		state.Last = map[string][2]int64{}
		state.LastUsers = map[string][2]int64{}
	}
	for _, item := range current.Nodes {
		n := item.Node
		if !n.Enabled {
			continue
		}
		pair := stats.Nodes[n.ID]
		last := state.Last[n.ID]
		up := pair[0] - last[0]
		down := pair[1] - last[1]
		if up < 0 {
			up = pair[0]
		}
		if down < 0 {
			down = pair[1]
		}
		state.Last[n.ID] = pair
		if up == 0 && down == 0 {
			continue
		}
		state.Sequence++
		state.Pending = append(state.Pending, shared.TrafficPoint{NodeID: n.ID, InstanceID: instance, Sequence: state.Sequence, Uplink: up, Downlink: down, At: time.Now()})
	}
	for _, item := range current.Nodes {
		if !item.Node.Enabled {
			continue
		}
		for _, user := range item.Users {
			pair, ok := stats.Users[user.Name]
			if !ok {
				continue
			}
			last := state.LastUsers[user.Name]
			up, down := pair[0]-last[0], pair[1]-last[1]
			if up < 0 {
				up = pair[0]
			}
			if down < 0 {
				down = pair[1]
			}
			state.LastUsers[user.Name] = pair
			if up == 0 && down == 0 {
				continue
			}
			state.Sequence++
			state.UserPending = append(state.UserPending, shared.UserTrafficPoint{NodeID: item.Node.ID, SubscriptionID: user.SubscriptionID, InstanceID: instance, Sequence: state.Sequence, Uplink: up, Downlink: down, At: time.Now()})
		}
	}
	return saveTraffic(*state)
}

func coreInstanceID() string {
	pid := coreMainPID()
	if pid == "" || pid == "0" {
		return ""
	}
	stat, err := os.ReadFile("/proc/" + pid + "/stat")
	if err != nil {
		return pid
	}
	parts := strings.Fields(string(stat))
	if len(parts) > 21 {
		return pid + "-" + parts[21]
	}
	return pid
}
