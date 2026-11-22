package shared

import (
	"math"
	"strings"
	"time"
)

const (
	// DefaultEntryProtectionThreshold is the default early stop percentage for
	// entry server total traffic protection, leaving headroom for sampling lag
	// and host vs provider billing differences.
	DefaultEntryProtectionThreshold = 95
	MinEntryProtectionThreshold     = 50
	MaxEntryProtectionThreshold     = 100

	// MaxRouteTrafficLimitBytes matches the server traffic limit cap (2^53).
	MaxRouteTrafficLimitBytes int64 = 1 << 53
	// MaxRouteSpeedLimitMbps caps per-route speed limit to 100 Gbps (100,000 Mbps).
	MaxRouteSpeedLimitMbps float64 = 100_000
	// BytesPerMbps converts decimal Mbps (megabits/sec) to bytes/sec: 1 Mbps = 125,000 B/s.
	BytesPerMbps float64 = 125_000
)

// ResolveTrafficLocation resolves an IANA timezone name with a fixed-offset
// fallback (in seconds east of UTC) so hosts without tzdata still compute
// identical cycle boundaries to the panel.
func ResolveTrafficLocation(tzName string, offsetSeconds int, fallback *time.Location) *time.Location {
	tzName = strings.TrimSpace(tzName)
	if tzName != "" && tzName != "Local" {
		if loc, err := time.LoadLocation(tzName); err == nil && loc != nil {
			return loc
		}
		return time.FixedZone(tzName, offsetSeconds)
	}
	if offsetSeconds != 0 {
		return time.FixedZone("PANEL", offsetSeconds)
	}
	if fallback != nil {
		return fallback
	}
	return time.Local
}

// ResetBoundaryInMonth returns 00:00:00 of the effective reset day in (year, month)
// in loc, clamping days 29–31 to the last day of shorter months.
func ResetBoundaryInMonth(year int, month time.Month, resetDay int, loc *time.Location) time.Time {
	if loc == nil {
		loc = time.Local
	}
	if resetDay < 1 {
		resetDay = 1
	}
	if resetDay > 31 {
		resetDay = 31
	}
	lastDay := time.Date(year, month+1, 0, 0, 0, 0, 0, loc).Day()
	day := resetDay
	if day > lastDay {
		day = lastDay
	}
	return time.Date(year, month, day, 0, 0, 0, 0, loc)
}

// MonthlyCycleBounds returns [start, end) for the monthly traffic cycle
// containing now using resetDay (1–31, <=0 defaults to 1) in loc.
func MonthlyCycleBounds(now time.Time, resetDay int, loc *time.Location) (time.Time, time.Time) {
	if loc == nil {
		loc = time.Local
	}
	if resetDay <= 0 || resetDay > 31 {
		resetDay = 1
	}
	local := now.In(loc)
	y, m, _ := local.Date()
	cur := ResetBoundaryInMonth(y, m, resetDay, loc)
	if !local.Before(cur) {
		nextMonth := time.Date(y, m+1, 1, 0, 0, 0, 0, loc)
		ny, nm, _ := nextMonth.Date()
		return cur, ResetBoundaryInMonth(ny, nm, resetDay, loc)
	}
	prevMonth := time.Date(y, m-1, 1, 0, 0, 0, 0, loc)
	py, pm, _ := prevMonth.Date()
	return ResetBoundaryInMonth(py, pm, resetDay, loc), cur
}

// ComputeRouteTrafficUsed computes route cycle usage from entry-hop uplink
// (client -> upstream) and downlink (upstream -> client) bytes.
func ComputeRouteTrafficUsed(uplink, downlink int64, limitType string) int64 {
	if uplink < 0 {
		uplink = 0
	}
	if downlink < 0 {
		downlink = 0
	}
	switch strings.TrimSpace(limitType) {
	case "up":
		return uplink
	case "down":
		return downlink
	default:
		return uplink + downlink
	}
}

// ComputeServerTrafficUsed computes server host NIC cycle usage from rx
// (download / inbound) and tx (upload / outbound) bytes.
func ComputeServerTrafficUsed(rx, tx int64, limitType string) int64 {
	if rx < 0 {
		rx = 0
	}
	if tx < 0 {
		tx = 0
	}
	switch strings.TrimSpace(limitType) {
	case "up":
		return tx
	case "down":
		return rx
	case "max":
		if tx > rx {
			return tx
		}
		return rx
	case "min":
		if tx < rx {
			return tx
		}
		return rx
	default:
		return rx + tx
	}
}

// MbpsToBytesPerSec converts a Mbps limit to bytes per second (0 = unlimited).
func MbpsToBytesPerSec(mbps float64) int64 {
	if math.IsNaN(mbps) || math.IsInf(mbps, 0) || mbps <= 0 {
		return 0
	}
	bps := int64(math.Round(mbps * BytesPerMbps))
	if bps < 1024 {
		bps = 1024
	}
	return bps
}

// EntryProtectionThresholdBytes returns the byte threshold at which entry total
// traffic protection triggers for a server traffic limit and percentage.
func EntryProtectionThresholdBytes(limitBytes int64, thresholdPercent int) int64 {
	if limitBytes <= 0 {
		return 0
	}
	if thresholdPercent < MinEntryProtectionThreshold || thresholdPercent > MaxEntryProtectionThreshold {
		thresholdPercent = DefaultEntryProtectionThreshold
	}
	if thresholdPercent >= 100 {
		return limitBytes
	}
	return int64(math.Floor(float64(limitBytes) * float64(thresholdPercent) / 100.0))
}

// ValidRouteTrafficLimitType reports whether v is a valid route quota direction.
func ValidRouteTrafficLimitType(v string) bool {
	switch strings.TrimSpace(v) {
	case "", "sum", "up", "down":
		return true
	default:
		return false
	}
}

// RouteHasTrafficLimit reports whether a route configures a quota or speed cap.
func RouteHasTrafficLimit(rt Route) bool {
	return rt.TrafficLimit > 0 || rt.UpSpeedLimitMbps > 0 || rt.DownSpeedLimitMbps > 0
}
