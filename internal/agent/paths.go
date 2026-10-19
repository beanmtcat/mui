package agent

import (
	"regexp"

	"mui/internal/shared"
)

const (
	ConfigDir     = "/etc/mui-agent"
	DataDir       = "/var/lib/mui-agent"
	SocketPath    = "/run/mui-agent/helper.sock"
	ForwardDir    = "/etc/mui-forward"
	ForwardConfig = ForwardDir + "/forwards.json"
	ForwardReady  = "/run/mui-forward/ready"
	ForwardStats  = "/run/mui-forward/stats.json"
	// The core runs under its own account so that a compromised proxy process
	// can reach neither the agent token nor the privileged helper socket.
	CoreDir    = "/etc/mui-core"
	CoreConfig = CoreDir + "/sing-box.json"
	CertDir    = CoreDir + "/certs"
	// The applied state is written by the root helper and read by the agent. It
	// lives in the root-owned config directory: a root process must not create
	// files in a directory the unprivileged agent account can rearrange.
	CurrentState       = ConfigDir + "/current.json"
	legacyCurrentState = DataDir + "/current.json"
	// ReleaseKeyPath holds the Ed25519 public key pinned at install time. When
	// present, upgrades need a manifest signed by its private half, so a
	// compromised panel cannot hand out binaries of its own.
	ReleaseKeyPath = ConfigDir + "/release.pub"
	// PanelPublicKeyPath holds the panel's Ed25519 public key. When present,
	// signed desired states are verified against it.
	PanelPublicKeyPath = ConfigDir + "/panel.pub"
	// UpgradeConfirmedPath records the agent build the panel has seen
	// reporting successfully after a self-update.
	UpgradeConfirmedPath = ConfigDir + "/upgrade-confirmed"
	agentUser            = "mui-agent"
	coreUser             = "mui-core"
	forwardUser          = "mui-forward"
)

// HostStatus is what the privileged helper can see and the unprivileged agent cannot.
type HostStatus struct {
	UFW            string                       `json:"ufw"`
	SSHPorts       []int                        `json:"sshPorts,omitempty"`
	Conflict       string                       `json:"conflict,omitempty"`
	Rules          []string                     `json:"rules,omitempty"`
	ForwardTraffic []shared.ForwardTrafficPoint `json:"forwardTraffic,omitempty"`
	// Supported reports whether this helper implements the current
	// panel protocol. The capability bits below describe what this
	// build can do; the panel gates features on them.
	Supported             bool `json:"supported"`
	ManualFirewallSupport bool `json:"manualFirewallSupport"`
	AgentSelfUpdate       bool `json:"agentSelfUpdate"`
	ForwardTCPUDP         bool `json:"forwardTcpUdp"`
	ForwardSupport        bool `json:"forwardSupport"`
	ShadowTLSAuth         bool `json:"shadowTlsAuth"`
	SnellFixedPort        bool `json:"snellFixedPort"`
	AgentProxySupport     bool `json:"agentProxySupport"`
	SnellV6               bool `json:"snellV6"`
	MultiUserStats        bool `json:"multiUserStats"`
	NodeFirewallPolicies  bool `json:"nodeFirewallPolicies"`
	CoreSelfUpdate        bool `json:"coreSelfUpdate"`
	ReleaseKeyPinned      bool `json:"releaseKeyPinned"`
}

// IDs the panel issues; anything else in a desired state or a stats name is rejected.
var safeNodeID = regexp.MustCompile(`^[0-9a-f]{32,36}$`)
var safeRuleID = regexp.MustCompile(`^[0-9a-f]{32,36}$`)
