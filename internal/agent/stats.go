package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protowire"
	"mui/internal/shared"
)

type statsRequest struct{}
type statsResponse struct{ Counters map[string]int64 }
type wireCodec struct{}

func (wireCodec) Name() string { return "proto" }
func (wireCodec) Marshal(v any) ([]byte, error) {
	if _, ok := v.(*statsRequest); ok {
		return []byte{}, nil
	}
	return nil, fmt.Errorf("unsupported protobuf request %T", v)
}
func (wireCodec) Unmarshal(raw []byte, v any) error {
	resp, ok := v.(*statsResponse)
	if !ok {
		return fmt.Errorf("unsupported protobuf response %T", v)
	}
	resp.Counters = map[string]int64{}
	for len(raw) > 0 {
		field, kind, n := protowire.ConsumeTag(raw)
		if n < 0 {
			return errors.New("invalid stats tag")
		}
		raw = raw[n:]
		if field == 1 && kind == protowire.BytesType {
			value, m := protowire.ConsumeBytes(raw)
			if m < 0 {
				return errors.New("invalid stat")
			}
			raw = raw[m:]
			name, count, err := decodeStat(value)
			if err != nil {
				return err
			}
			if name != "" {
				resp.Counters[name] = count
			}
			continue
		}
		m := protowire.ConsumeFieldValue(field, kind, raw)
		if m < 0 {
			return errors.New("invalid stats field")
		}
		raw = raw[m:]
	}
	return nil
}
func decodeStat(raw []byte) (string, int64, error) {
	var name string
	var value int64
	for len(raw) > 0 {
		field, kind, n := protowire.ConsumeTag(raw)
		if n < 0 {
			return "", 0, errors.New("invalid stat tag")
		}
		raw = raw[n:]
		switch {
		case field == 1 && kind == protowire.BytesType:
			b, m := protowire.ConsumeBytes(raw)
			if m < 0 {
				return "", 0, errors.New("invalid stat name")
			}
			name = string(b)
			raw = raw[m:]
		case field == 2 && kind == protowire.VarintType:
			v, m := protowire.ConsumeVarint(raw)
			if m < 0 {
				return "", 0, errors.New("invalid stat value")
			}
			value = int64(v)
			raw = raw[m:]
		default:
			m := protowire.ConsumeFieldValue(field, kind, raw)
			if m < 0 {
				return "", 0, errors.New("invalid stat field")
			}
			raw = raw[m:]
		}
	}
	return name, value, nil
}

type StatsSnapshot struct {
	Nodes map[string][2]int64
	Users map[string][2]int64
}

// statsConnMu guards the shared stats client. The connection is reused
// across samples; a failed call closes it so the next sample dials fresh.
var statsConnMu sync.Mutex
var statsConn *grpc.ClientConn

func statsClient() (*grpc.ClientConn, error) {
	statsConnMu.Lock()
	defer statsConnMu.Unlock()
	if statsConn != nil {
		return statsConn, nil
	}
	conn, err := grpc.NewClient("127.0.0.1:"+strconv.Itoa(shared.StatsAPIPort), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithDefaultCallOptions(grpc.ForceCodec(wireCodec{})))
	if err != nil {
		return nil, err
	}
	statsConn = conn
	return conn, nil
}

func dropStatsClient() {
	statsConnMu.Lock()
	defer statsConnMu.Unlock()
	if statsConn != nil {
		_ = statsConn.Close()
		statsConn = nil
	}
}

func ReadStats(ctx context.Context) (StatsSnapshot, error) {
	if err := checkStatsListenerOwner(); err != nil {
		return StatsSnapshot{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	conn, err := statsClient()
	if err != nil {
		return StatsSnapshot{}, err
	}
	var response statsResponse
	if err = conn.Invoke(ctx, "/v2ray.core.app.stats.command.StatsService/QueryStats", &statsRequest{}, &response); err != nil {
		dropStatsClient()
		return StatsSnapshot{}, err
	}
	return parseStatsCounters(response.Counters), nil
}

// checkStatsListenerOwner verifies the process listening on the stats port
// is sing-box before the agent talks to it. Another process could otherwise
// squat the port and feed the agent forged counters.
func checkStatsListenerOwner() error {
	inodes, uids, err := statsListenerInodes()
	if err != nil {
		return err
	}
	if len(inodes) == 0 {
		return fmt.Errorf("no process is listening on the stats port %d", shared.StatsAPIPort)
	}
	// Primary path: bind the socket inode to its owning process through
	// /proc/[pid]/fd, then check that process is sing-box.
	if pid, ok := findSocketOwner(inodes); ok {
		pidDir := filepath.Join("/proc", pid)
		exe, _ := os.Readlink(filepath.Join(pidDir, "exe"))
		if strings.Contains(exe, "sing-box") {
			return nil
		}
		cmdline, _ := os.ReadFile(filepath.Join(pidDir, "cmdline"))
		if strings.Contains(string(cmdline), "sing-box") {
			return nil
		}
		return fmt.Errorf("stats port %d is owned by pid %s, not sing-box", shared.StatsAPIPort, pid)
	}
	// Fallback: the agent runs unprivileged, so other users' /proc/[pid]/fd
	// directories are unreadable and the scan above finds nothing. In that
	// case fall back to the socket's owner UID (it must be the core
	// account sing-box runs as) plus the presence of a sing-box process.
	// A squatter would have to run as the core account to fake the UID,
	// which is already a compromise of the core itself.
	return checkStatsListenerFallback(uids)
}

// findSocketOwner returns the pid whose fd directory holds one of the given
// socket inodes, or false when no fd directory is readable (for example
// when the caller is unprivileged and the owner is another user).
func findSocketOwner(inodes map[string]bool) (string, bool) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return "", false
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		pidDir := filepath.Join("/proc", entry.Name())
		fds, err := os.ReadDir(filepath.Join(pidDir, "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(pidDir, "fd", fd.Name()))
			if err != nil {
				continue
			}
			for inode := range inodes {
				if target == "socket:["+inode+"]" {
					return entry.Name(), true
				}
			}
		}
	}
	return "", false
}

func checkStatsListenerFallback(uids map[string]bool) error {
	coreUID, err := lookupUserID(coreUser)
	if err != nil {
		return err
	}
	if !uids[coreUID] {
		return fmt.Errorf("stats port %d socket is not owned by %s", shared.StatsAPIPort, coreUser)
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil {
			continue
		}
		if strings.Contains(string(cmdline), "sing-box") {
			return nil
		}
	}
	return fmt.Errorf("stats port %d is owned by %s but no sing-box process is running", shared.StatsAPIPort, coreUser)
}

// lookupUserID resolves a user name to its UID from /etc/passwd without
// spawning a process.
func lookupUserID(name string) (string, error) {
	raw, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 3 && fields[0] == name {
			return fields[2], nil
		}
	}
	return "", fmt.Errorf("user %s not found in /etc/passwd", name)
}

// statsListenerInodes returns the socket inodes and owner UIDs of listening
// sockets on the stats port, from /proc/net/tcp and /proc/net/tcp6.
// Columns: sl, local_address, rem_address, st, tx_queue:rx_queue,
// tr:tm->when, retrnsmt, uid at field 7, timeout, inode at field 9;
// st 0A is LISTEN.
func statsListenerInodes() (map[string]bool, map[string]bool, error) {
	inodes := map[string]bool{}
	uids := map[string]bool{}
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, nil, err
		}
		for _, line := range strings.Split(string(raw), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 10 || fields[3] != "0A" {
				continue
			}
			addr := fields[1]
			colon := strings.LastIndex(addr, ":")
			if colon < 0 {
				continue
			}
			port, err := strconv.ParseUint(addr[colon+1:], 16, 32)
			if err != nil || int(port) != shared.StatsAPIPort {
				continue
			}
			inodes[fields[9]] = true
			uids[fields[7]] = true
		}
	}
	return inodes, uids, nil
}

func parseStatsCounters(counters map[string]int64) StatsSnapshot {
	out := StatsSnapshot{Nodes: map[string][2]int64{}, Users: map[string][2]int64{}}
	for name, value := range counters {
		parts := strings.Split(name, ">>>")
		if len(parts) != 4 || parts[2] != "traffic" || (parts[3] != "uplink" && parts[3] != "downlink") {
			continue
		}
		var counters map[string][2]int64
		var id string
		switch {
		case parts[0] == "inbound" && strings.HasPrefix(parts[1], "node-"):
			counters, id = out.Nodes, strings.TrimPrefix(parts[1], "node-")
		case parts[0] == "user" && strings.HasPrefix(parts[1], "mui-"):
			counters, id = out.Users, parts[1]
		default:
			continue
		}
		if id == "" {
			continue
		}
		pair := counters[id]
		if parts[3] == "uplink" {
			pair[0] = value
		}
		if parts[3] == "downlink" {
			pair[1] = value
		}
		counters[id] = pair
	}
	return out
}
