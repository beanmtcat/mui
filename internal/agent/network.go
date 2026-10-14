package agent

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"mui/internal/shared"
)

func sampleServerTraffic(state *trafficState) error {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return err
	}
	route, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return err
	}
	iface := defaultInterface(string(route))
	if iface == "" {
		if v6, e := os.ReadFile("/proc/net/ipv6_route"); e == nil {
			iface = defaultIPv6Interface(string(v6))
		}
	}
	if iface == "" {
		return errors.New("default network interface unavailable")
	}
	raw, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return err
	}
	rx, tx, err := parseInterfaceBytes(string(raw), iface)
	if err != nil {
		return err
	}
	bootID := strings.TrimSpace(string(boot))
	if state.NetworkKernelBoot != bootID || state.NetworkIface != iface {
		var suffix [8]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return err
		}
		state.NetworkKernelBoot = bootID
		state.NetworkBoot = bootID + "-" + hex.EncodeToString(suffix[:])
		state.NetworkIface = iface
		// A new boot or interface starts a new sequence space, and pending
		// points belong to the previous boot: drop them so the panel
		// never stitches counters from two boots into one series.
		state.NetworkSequence = 0
		state.NetworkPending = nil
		state.NetworkLast = [2]int64{rx, tx}
		return saveTraffic(*state)
	}
	deltaRx, deltaTx := rx-state.NetworkLast[0], tx-state.NetworkLast[1]
	// A counter that moved backwards is a reset (interface flap, driver
	// reload), not traffic: count it as zero and say so, instead of
	// crediting the whole counter value as one sample's delta.
	if deltaRx < 0 {
		fmt.Fprintf(os.Stderr, "network: %s rx counter rolled back %d -> %d; counting 0\n", iface, state.NetworkLast[0], rx)
		deltaRx = 0
	}
	if deltaTx < 0 {
		fmt.Fprintf(os.Stderr, "network: %s tx counter rolled back %d -> %d; counting 0\n", iface, state.NetworkLast[1], tx)
		deltaTx = 0
	}
	state.NetworkLast = [2]int64{rx, tx}
	if deltaRx == 0 && deltaTx == 0 {
		// Nothing moved: keep the new baseline in memory and skip the
		// disk write. An idle host sampled every 30s must not rewrite
		// traffic.json every cycle.
		return nil
	}
	state.NetworkSequence++
	state.NetworkPending = append(state.NetworkPending, shared.ServerTrafficPoint{BootID: state.NetworkBoot, Interface: iface, Sequence: state.NetworkSequence, Rx: deltaRx, Tx: deltaTx, At: time.Now()})
	return saveTraffic(*state)
}
func defaultInterface(route string) string {
	// /proc/net/route columns: Iface, Destination, Gateway, Flags, RefCnt,
	// Use, Metric, Mask. A usable default route is up and goes through a
	// gateway (Flags RTF_UP|RTF_GATEWAY); among candidates the smallest
	// metric wins.
	best := ""
	var bestMetric int64 = -1
	for _, line := range strings.Split(route, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 8 || fields[1] != "00000000" || fields[0] == "lo" {
			continue
		}
		flags, err := strconv.ParseUint(fields[3], 16, 32)
		if err != nil || flags&0x3 != 0x3 {
			continue
		}
		metric, err := strconv.ParseInt(fields[6], 10, 64)
		if err != nil {
			continue
		}
		if best == "" || metric < bestMetric {
			best, bestMetric = fields[0], metric
		}
	}
	return best
}
func defaultIPv6Interface(route string) string {
	zero := strings.Repeat("0", 32)
	for _, line := range strings.Split(route, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 10 && fields[0] == zero && fields[1] == "00" && fields[len(fields)-1] != "lo" {
			return fields[len(fields)-1]
		}
	}
	return ""
}
func parseInterfaceBytes(data, iface string) (int64, int64, error) {
	for _, line := range strings.Split(data, "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) != iface {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 16 {
			return 0, 0, errors.New("invalid /proc/net/dev counters")
		}
		rx, e := strconv.ParseInt(fields[0], 10, 64)
		if e != nil {
			return 0, 0, e
		}
		tx, e := strconv.ParseInt(fields[8], 10, 64)
		return rx, tx, e
	}
	return 0, 0, fmt.Errorf("interface %s missing from /proc/net/dev", iface)
}
