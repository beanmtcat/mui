package forward

import (
	"strconv"
	"strings"
	"time"

	"mui/internal/shared"
)

func relayQualityKey(spec shared.ForwardRule) string {
	if spec.RouteID == "" || len(spec.Targets) < 2 || !tcpHealth(spec) {
		return ""
	}
	var b strings.Builder
	b.WriteString(spec.RouteID)
	b.WriteByte(0)
	b.WriteString(strconv.Itoa(spec.Port))
	for _, target := range spec.Targets {
		b.WriteByte(0)
		b.WriteString(target.Host)
		b.WriteByte(0)
		b.WriteString(strconv.Itoa(target.Port))
	}
	return b.String()
}

// A chain's TCP and UDP rules with the same endpoint group share the quality
// judgment. Manual settings and the actual socket sessions stay rule-local.
// Called only during Reload, with the service lock held.
func (s *Service) relayQualityFor(spec shared.ForwardRule) *relayQualityGroup {
	key := relayQualityKey(spec)
	if key == "" {
		return nil
	}
	if s.qualityGroups == nil {
		s.qualityGroups = make(map[string]*relayQualityGroup)
	}
	group := s.qualityGroups[key]
	if group == nil {
		group = newRelayQualityGroup(len(spec.Targets), time.Now())
		s.qualityGroups[key] = group
	}
	return group
}

func (s *Service) pruneRelayQualityGroups() {
	active := make(map[string]bool)
	for _, r := range s.rules {
		if r.quality != nil {
			active[relayQualityKey(r.spec)] = true
		}
	}
	for key := range s.qualityGroups {
		if !active[key] {
			delete(s.qualityGroups, key)
		}
	}
}
