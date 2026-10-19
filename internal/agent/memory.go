package agent

import (
	"os"
	"runtime/debug"
	"strconv"
	"strings"
)

const mebibyte int64 = 1 << 20

// The memory limit is a GC target, not an RSS cap or a connection limit. Use
// the smaller of host and container memory; never reserve the entire machine
// independently for each of the three processes.
func availableMemory() int64 {
	var total int64
	if raw, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == "MemTotal:" {
				n, _ := strconv.ParseInt(fields[1], 10, 64)
				total = n * 1024
			}
		}
	}
	for _, path := range []string{"/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"} {
		if raw, err := os.ReadFile(path); err == nil {
			if n, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64); err == nil && n > 0 && (total == 0 || n < total) {
				total = n
			}
		}
	}
	if total <= 0 {
		return 1024 * mebibyte
	}
	return total
}

func memoryBudget(role string, total int64) int64 {
	divisor, minimum, maximum := int64(16), int64(16), int64(64)
	switch role {
	case "helper":
		divisor, minimum, maximum = 32, 12, 32
	case "forward":
		divisor, minimum, maximum = 6, 32, 256
	case "core":
		divisor, minimum, maximum = 4, 48, 512
	}
	return min(max(total/divisor, minimum*mebibyte), maximum*mebibyte)
}

// ConfigureMemory applies defaults without requiring shell environment
// variables. Explicit Go runtime settings in a service override the defaults.
func ConfigureMemory(role string) {
	if role != "run" && role != "helper" && role != "forward" {
		return
	}
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(memoryBudget(role, availableMemory()))
	}
	if os.Getenv("GOGC") == "" {
		debug.SetGCPercent(75)
	}
}
