package shared

import "time"

const (
	RelayHealthVersion = "0.6.32"
	MaxRelayReport     = 200
	RelayNormal        = "normal"
	RelayDegraded      = "degraded"
	RelayDown          = "down"
	RelayProbation     = "probation"
)

func ValidRelayState(state string) bool {
	return state == RelayNormal || state == RelayDegraded || state == RelayDown
}

type RelayOverride struct {
	FromServerID string     `json:"fromServerId"`
	ToServerID   string     `json:"toServerId"`
	State        string     `json:"state"`
	Until        *time.Time `json:"until,omitempty"`
	Note         string     `json:"note"`
}

type RelayStats struct {
	ProbeSuccesses    int   `json:"probeSuccesses"`
	MedianMS          int64 `json:"medianMs"`
	BaselineMS        int64 `json:"baselineMs"`
	PassiveBadPercent int   `json:"passiveBadPercent"`
	PassiveSamples    int   `json:"passiveSamples"`
}

type RelayState struct {
	ForwardID  string      `json:"forwardId"`
	ServerID   string      `json:"serverId"`
	Host       string      `json:"host"`
	Port       int         `json:"port"`
	State      string      `json:"state"`
	Source     string      `json:"source"`
	AutoState  string      `json:"autoState"`
	Reason     string      `json:"reason"`
	Since      time.Time   `json:"since"`
	AutoSince  *time.Time  `json:"autoSince,omitempty"`
	AutoReason string      `json:"autoReason,omitempty"`
	Stats      *RelayStats `json:"stats,omitempty"`
}

// ReportedAt is assigned by the panel. Since can predate the last heartbeat.
type RelayStateSample struct {
	RelayState
	ReportedAt time.Time `json:"reportedAt"`
}

type RelayEdge struct {
	FromServerID       string         `json:"fromServerId"`
	ToServerID         string         `json:"toServerId"`
	Reported           *RelayState    `json:"reported,omitempty"`
	Override           *RelayOverride `json:"override,omitempty"`
	Availability       string         `json:"availability,omitempty"`
	DownstreamFlapping bool           `json:"downstreamFlapping,omitempty"`
}

// RelayDownstreamStatus is panel bookkeeping for one live routed listener.
// The masks describe fresh observations of the listener's ordered targets.
type RelayDownstreamStatus struct {
	Down          bool              `json:"down,omitempty"`
	DownSeen      uint32            `json:"downSeen,omitempty"`
	DownRoundAt   *time.Time        `json:"downRoundAt,omitempty"`
	LastAllDownAt *time.Time        `json:"lastAllDownAt,omitempty"`
	HealthyAt     map[int]time.Time `json:"healthyAt,omitempty"`
	EvidenceAt    time.Time         `json:"evidenceAt"`
	Changes       []time.Time       `json:"changes,omitempty"`
	FlappingUntil *time.Time        `json:"flappingUntil,omitempty"`
	Previous      []string          `json:"previous,omitempty"`
}
