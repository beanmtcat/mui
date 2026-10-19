package shared

import (
	"encoding/json"
	"time"
)

type Server struct {
	ManagementMode          string     `json:"managementMode"`
	OfflineExportedRevision int64      `json:"offlineExportedRevision"`
	OfflineExportedAt       *time.Time `json:"offlineExportedAt,omitempty"`
	ID                      string     `json:"id"`
	Name                    string     `json:"name"`
	// Roles is any combination of entry, line, transit and exit. Only an exit
	// server runs sing-box and carries nodes; the others run forwards.
	Roles    []string `json:"roles"`
	Country  string   `json:"country"`
	Region   string   `json:"region"`
	City     string   `json:"city"`
	Provider string   `json:"provider"`
	Tags     string   `json:"tags"`
	Notes    string   `json:"notes"`
	IPv4     string   `json:"ipv4"`
	IPv6     string   `json:"ipv6"`
	Domain   string   `json:"domain"`
	// InternalAddress is how other servers on the same private network or
	// dedicated line (IPLC/IEPL) reach this one; a route hop can use it.
	InternalAddress            string     `json:"internalAddress"`
	AgentProxySwitchPending    bool       `json:"agentProxySwitchPending,omitempty"`
	AgentProxyPreviousInternal bool       `json:"agentProxyPreviousInternal,omitempty"`
	AgentProxyPreviousNodeID   string     `json:"agentProxyPreviousNodeId,omitempty"`
	AgentProxyNodeID           string     `json:"agentProxyNodeId,omitempty"`
	AgentProxyInternal         bool       `json:"agentProxyInternal,omitempty"`
	AgentProxySupport          bool       `json:"agentProxySupport,omitempty"`
	FirewallMode               string     `json:"firewallMode"`
	ManualFirewallSupport      bool       `json:"manualFirewallSupport"`
	Status                     string     `json:"status"`
	OS                         string     `json:"os"`
	Arch                       string     `json:"arch"`
	AgentVersion               string     `json:"agentVersion"`
	AgentBuild                 string     `json:"agentBuild"`
	AgentSelfUpdate            bool       `json:"agentSelfUpdate"`
	NodeFirewallPolicies       bool       `json:"nodeFirewallPolicies"`
	MultiUserStats             bool       `json:"multiUserStats"`
	ForwardTCPUDP              bool       `json:"forwardTcpUdp"`
	ForwardSupport             bool       `json:"forwardSupport"`
	ShadowTLSAuth              bool       `json:"shadowTlsAuth"`
	SnellFixedPort             bool       `json:"snellFixedPort"`
	SnellV6                    bool       `json:"snellV6"`
	ReleaseKeyPinned           bool       `json:"releaseKeyPinned"`
	AppliedRevision            int64      `json:"appliedRevision"`
	CoreVersion                string     `json:"coreVersion"`
	CoreBuild                  string     `json:"coreBuild"`
	CoreSelfUpdate             bool       `json:"coreSelfUpdate"`
	UFWStatus                  string     `json:"ufwStatus"`
	StatsStatus                string     `json:"statsStatus"`
	NetworkRx                  int64      `json:"networkRx"`
	NetworkTx                  int64      `json:"networkTx"`
	LastSeen                   *time.Time `json:"lastSeen"`
	Revision                   int64      `json:"revision"`
	// Reported by the agent; never edited by the administrator.
	DetectedIPv4     string   `json:"detectedIpv4"`
	DetectedIPv6     string   `json:"detectedIpv6"`
	ClockSkewSeconds int64    `json:"clockSkewSeconds"`
	SSHPorts         []int    `json:"sshPorts"`
	FirewallConflict string   `json:"firewallConflict"`
	UFWRules         []string `json:"ufwRules"`
}

type Node struct {
	ID             string `json:"id"`
	ServerID       string `json:"serverId"`
	Name           string `json:"name"`
	Protocol       string `json:"protocol"`
	Username       string `json:"username,omitempty"`
	Port           int    `json:"port"`
	Listen         string `json:"listen"`
	PublishAddress string `json:"publishAddress"`
	Method         string `json:"method"`
	SnellVersion   int    `json:"snellVersion"`
	// omitempty: a node without an inner Snell port encodes exactly as it
	// did before the field existed.
	SnellPort       int    `json:"snellPort,omitempty"`
	Obfs            string `json:"obfs"`
	ShadowTLSHost   string `json:"shadowTlsHost"`
	TLSName         string `json:"tlsName"`
	CertificateID   string `json:"certificateId"`
	FirewallPolicy  string `json:"firewallPolicy"`
	FirewallSources string `json:"firewallSources"`
	// Direct allows clients to connect to the node itself, so it can be put
	// into a subscription as is. Without it the node is reachable only through
	// routes: its port admits nothing but their last hops (RouteSources).
	Direct bool `json:"direct"`
	// RouteSources is computed by the panel from the routes ending at this
	// node: the addresses their last hops connect from.
	RouteSources string    `json:"routeSources"`
	Enabled      bool      `json:"enabled"`
	Deleting     bool      `json:"deleting"`
	Status       string    `json:"status"`
	Error        string    `json:"error"`
	Uplink       int64     `json:"uplink"`
	Downlink     int64     `json:"downlink"`
	CreatedAt    time.Time `json:"createdAt"`
}

// NodeTemplate stores reusable node settings without a server-specific address
// or certificate. Its optional password is stored separately and encrypted.
type NodeTemplate struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Protocol      string `json:"protocol"`
	Username      string `json:"username,omitempty"`
	Port          int    `json:"port"`
	Listen        string `json:"listen"`
	Method        string `json:"method"`
	SnellVersion  int    `json:"snellVersion"`
	SnellPort     int    `json:"snellPort"`
	Obfs          string `json:"obfs"`
	ShadowTLSHost string `json:"shadowTlsHost"`
	TLSName       string `json:"tlsName"`
}

type Certificate struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Domain    string    `json:"domain"`
	PEM       string    `json:"pem,omitempty"`
	Key       string    `json:"key,omitempty"`
	ExpiresAt time.Time `json:"expiresAt"`
	// Derived by the server from ExpiresAt via CertExpiryStatus; never
	// stored, so list/create responses always agree on expiry state.
	DaysUntilExpiry int  `json:"daysUntilExpiry"`
	ExpiringSoon    bool `json:"expiringSoon"`
}

type FirewallRule struct {
	ID       string `json:"id"`
	ServerID string `json:"serverId"`
	PortFrom int    `json:"portFrom"`
	PortTo   int    `json:"portTo"`
	Network  string `json:"network"`
	Source   string `json:"source"`
	// Family limits a rule to "ipv4" or "ipv6"; empty means both. With a
	// source, the source decides. omitempty keeps older agents verifying.
	Family   string `json:"family,omitempty"`
	Action   string `json:"action"`
	Comment  string `json:"comment"`
	Owner    string `json:"owner"`
	Deleting bool   `json:"deleting"`
	Status   string `json:"status"`
}

// ForwardTarget is one destination of a forward.
type ForwardTarget struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// ForwardRule terminates an inbound TCP connection or UDP association on the
// managed server and opens a new connection to one of its destinations. With
// several destinations, Balance picks among the healthy ones: "failover" uses
// the first healthy one in order, "round-robin" spreads new connections.
type ForwardRule struct {
	ID       string          `json:"id"`
	ServerID string          `json:"serverId"`
	Name     string          `json:"name"`
	Network  string          `json:"network"`
	Listen   string          `json:"listen"`
	Port     int             `json:"port"`
	Targets  []ForwardTarget `json:"targets"`
	Balance  string          `json:"balance"`
	// Empty uses protocol defaults for each socket: TCP probing for TCP,
	// passive errors for UDP, including tcp+udp rules.
	HealthCheck string `json:"healthCheck,omitempty"`
	// RouteID marks a forward the panel generated for a route; it is edited
	// through the route, never directly.
	RouteID         string `json:"routeId,omitempty"`
	FirewallPolicy  string `json:"firewallPolicy"`
	FirewallSources string `json:"firewallSources"`
	Enabled         bool   `json:"enabled"`
	Deleting        bool   `json:"deleting"`
	Status          string `json:"status"`
	Error           string `json:"error"`
	Uplink          int64  `json:"uplink"`
	Downlink        int64  `json:"downlink"`
}

type Subscription struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	CustomerID string     `json:"customerId"`
	Format     string     `json:"format"`
	NodeIDs    []string   `json:"nodeIds"`
	RouteIDs   []string   `json:"routeIds"`
	Enabled    bool       `json:"enabled"`
	ExpiresAt  *time.Time `json:"expiresAt"`
	URL        string     `json:"url,omitempty"`
	Uplink     int64      `json:"uplink"`
	Downlink   int64      `json:"downlink"`
	// Filled in for the list view only: nodes this subscription names whose
	// configuration is not live on their server yet, and whether the link can
	// be shown again.
	PendingNodeIDs  []string `json:"pendingNodeIds,omitempty"`
	PendingRouteIDs []string `json:"pendingRouteIds,omitempty"`
	LinkAvailable   bool     `json:"linkAvailable,omitempty"`
}

// Server roles. A server may hold several.
const (
	RoleEntry   = "entry"   // first hop of a route; subscribable
	RoleLine    = "line"    // first or middle hop of a route; subscribable
	RoleTransit = "transit" // middle hop of a route
	RoleExit    = "exit"    // runs sing-box; its nodes end routes
)

func HasRole(s Server, role string) bool {
	for _, r := range s.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// Route carries clients from a first-hop server through zero or more middle
// hops to a node on an exit server. Every hop listens on the same Port; the
// panel generates the forwards.
type Route struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	EntryServerID string     `json:"entryServerId"`
	Hops          []RouteHop `json:"hops"`
	NodeID        string     `json:"nodeId"`
	// NodeInternal makes the last hop reach the exit server by its internal
	// address instead of its public one.
	NodeInternal bool `json:"nodeInternal"`
	// NodeSourceMode selects the last hop's address used by the exit UFW
	// allowlist, independently of the destination address selection.
	NodeSourceMode string `json:"nodeSourceMode,omitempty"`
	Port           int    `json:"port"`
	Enabled        bool   `json:"enabled"`
	Notes          string `json:"notes"`
	// Filled in for the list view: whether every hop has applied its forward.
	Status string `json:"status,omitempty"`
}

// RouteHop is one middle hop. With several servers it is a load-balanced
// group: the previous hop sends to the healthy ones as Balance says.
type RouteHop struct {
	ServerIDs []string `json:"serverIds"`
	Balance   string   `json:"balance"`
	// Internal makes the previous hop reach these servers by their internal
	// addresses.
	Internal bool `json:"internal"`
	// SourceMode selects the previous hop's UFW source: auto, public or
	// internal. It does not bind the outgoing connection to an interface.
	SourceMode string `json:"sourceMode,omitempty"`
}

type Customer struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Notes     string    `json:"notes"`
	CreatedAt time.Time `json:"createdAt"`
}

type SubscriptionAccess struct {
	ID             string    `json:"id"`
	SubscriptionID string    `json:"subscriptionId"`
	CustomerID     string    `json:"customerId"`
	IP             string    `json:"ip"`
	At             time.Time `json:"at"`
}

type ConnectionIP struct {
	ServerID string    `json:"serverId"`
	NodeID   string    `json:"nodeId"`
	IP       string    `json:"ip"`
	LastSeen time.Time `json:"lastSeen"`
	Cursor   string    `json:"cursor,omitempty"`
}

type ConnectionPoint struct {
	NodeID string `json:"nodeId"`
	IP     string `json:"ip"`
}

type Operation struct {
	ID          string `json:"id"`
	ServerID    string `json:"serverId"`
	Kind        string `json:"kind"`
	Status      string `json:"status"`
	Error       string `json:"error"`
	Revision    int64  `json:"revision"`
	TargetBuild string `json:"targetBuild,omitempty"`
	// FencingToken is issued at claim time; a report for this operation is
	// accepted only when it carries the same token, so a stale claim cannot
	// overwrite the result of a newer one.
	FencingToken string    `json:"fencingToken"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
	// Deployed summarises the node configuration this job carries, so that a
	// success report tells the panel exactly what is live on the server.
	Deployed map[string]NodeDeployment `json:"deployed,omitempty"`
}

// NodeDeployment records what one node looks like on its server: a fingerprint
// of everything a client depends on, the subscriptions with a login on it,
// and the firewall sources the server successfully applied.
type NodeDeployment struct {
	Fingerprint     string   `json:"fingerprint"`
	Subscriptions   []string `json:"subscriptions"`
	FirewallPolicy  string   `json:"firewallPolicy"`
	FirewallSources string   `json:"firewallSources"`
}

type ManagedNode struct {
	Node              Node       `json:"node"`
	Password          string     `json:"password"`
	ShadowTLSPassword string     `json:"shadowTlsPassword,omitempty"`
	Users             []NodeUser `json:"users,omitempty"`
	CertificatePEM    string     `json:"certificatePem,omitempty"`
	CertificateKey    string     `json:"certificateKey,omitempty"`
}

// NodeUser is one subscription's login on a managed node. Name is unique
// across all inbounds so sing-box's user counters can be attributed exactly.
type NodeUser struct {
	SubscriptionID    string `json:"subscriptionId"`
	Name              string `json:"name"`
	Password          string `json:"password"`
	ShadowTLSPassword string `json:"shadowTlsPassword,omitempty"`
}

type SOCKS5Proxy struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type DesiredState struct {
	AgentProxy        *SOCKS5Proxy   `json:"agentProxy,omitempty"`
	FirewallMode      string         `json:"firewallMode,omitempty"`
	Revision          int64          `json:"revision"`
	ProtocolVersion   int            `json:"protocolVersion"`
	Signature         string         `json:"signature"`
	UpgradeSHA256     string         `json:"upgradeSha256,omitempty"`
	CoreUpgradeSHA256 string         `json:"coreUpgradeSha256,omitempty"`
	Nodes             []ManagedNode  `json:"nodes"`
	Rules             []FirewallRule `json:"rules"`
	Forwards          []ForwardRule  `json:"forwards"`
	// HostRules are the rule lines (as `ufw status numbered` prints them,
	// without the number) a "ufw.delete" job removes, each on its own.
	HostRules []string `json:"hostRules,omitempty"`
}

type Job struct {
	ID           string       `json:"id"`
	ServerID     string       `json:"serverId"`
	Kind         string       `json:"kind"`
	FencingToken string       `json:"fencingToken"`
	State        DesiredState `json:"state"`
	// StateRaw is State exactly as the panel sent it, kept by the agent when
	// it decodes a job; the panel's signature covers these bytes. It is
	// written out only by the agent, so a saved job keeps them.
	StateRaw json.RawMessage `json:"stateRaw,omitempty"`
}

// UnmarshalJSON keeps the state's bytes as received next to the decoded
// state. A job the agent saved itself carries them as stateRaw.
func (j *Job) UnmarshalJSON(data []byte) error {
	type plain Job
	var aux struct {
		plain
		State json.RawMessage `json:"state"`
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	*j = Job(aux.plain)
	raw := aux.StateRaw
	if len(raw) == 0 {
		raw = aux.State
	}
	if len(raw) == 0 || string(raw) == "null" {
		j.StateRaw = nil
		return nil
	}
	j.StateRaw = append(json.RawMessage(nil), raw...)
	return json.Unmarshal(raw, &j.State)
}

type TrafficPoint struct {
	NodeID     string    `json:"nodeId"`
	InstanceID string    `json:"instanceId"`
	Sequence   int64     `json:"sequence"`
	Uplink     int64     `json:"uplink"`
	Downlink   int64     `json:"downlink"`
	At         time.Time `json:"at"`
}

type UserTrafficPoint struct {
	NodeID         string    `json:"nodeId"`
	SubscriptionID string    `json:"subscriptionId"`
	InstanceID     string    `json:"instanceId"`
	Sequence       int64     `json:"sequence"`
	Uplink         int64     `json:"uplink"`
	Downlink       int64     `json:"downlink"`
	At             time.Time `json:"at"`
}

type ForwardTrafficPoint struct {
	ForwardID  string    `json:"forwardId"`
	InstanceID string    `json:"instanceId"`
	Uplink     int64     `json:"uplink"`
	Downlink   int64     `json:"downlink"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

type ServerTrafficPoint struct {
	BootID    string    `json:"bootId"`
	Interface string    `json:"interface"`
	Sequence  int64     `json:"sequence"`
	Rx        int64     `json:"rx"`
	Tx        int64     `json:"tx"`
	At        time.Time `json:"at"`
}

type AgentReport struct {
	ManualFirewallSupport bool                  `json:"manualFirewallSupport,omitempty"`
	JobID                 string                `json:"jobId,omitempty"`
	JobKind               string                `json:"jobKind,omitempty"`
	JobStatus             string                `json:"jobStatus,omitempty"`
	JobError              string                `json:"jobError,omitempty"`
	FencingToken          string                `json:"fencingToken,omitempty"`
	OS                    string                `json:"os,omitempty"`
	Arch                  string                `json:"arch,omitempty"`
	AgentVersion          string                `json:"agentVersion,omitempty"`
	AgentBuild            string                `json:"agentBuild,omitempty"`
	AgentSelfUpdate       bool                  `json:"agentSelfUpdate,omitempty"`
	NodeFirewallPolicies  bool                  `json:"nodeFirewallPolicies,omitempty"`
	MultiUserStats        bool                  `json:"multiUserStats,omitempty"`
	ForwardSupport        bool                  `json:"forwardSupport,omitempty"`
	ForwardTCPUDP         bool                  `json:"forwardTcpUdp,omitempty"`
	ShadowTLSAuth         bool                  `json:"shadowTlsAuth,omitempty"`
	SnellFixedPort        bool                  `json:"snellFixedPort,omitempty"`
	SnellV6               bool                  `json:"snellV6,omitempty"`
	AgentProxySupport     bool                  `json:"agentProxySupport,omitempty"`
	ReleaseKeyPinned      bool                  `json:"releaseKeyPinned,omitempty"`
	CoreVersion           string                `json:"coreVersion,omitempty"`
	CoreBuild             string                `json:"coreBuild,omitempty"`
	BuildDigest           string                `json:"buildDigest,omitempty"`
	CoreDigest            string                `json:"coreDigest,omitempty"`
	CoreSelfUpdate        bool                  `json:"coreSelfUpdate,omitempty"`
	UFWStatus             string                `json:"ufwStatus,omitempty"`
	StatsStatus           string                `json:"statsStatus,omitempty"`
	IPv4                  string                `json:"ipv4,omitempty"`
	IPv6                  string                `json:"ipv6,omitempty"`
	Traffic               []TrafficPoint        `json:"traffic,omitempty"`
	UserTraffic           []UserTrafficPoint    `json:"userTraffic,omitempty"`
	ForwardTraffic        []ForwardTrafficPoint `json:"forwardTraffic,omitempty"`
	ServerTraffic         []ServerTrafficPoint  `json:"serverTraffic,omitempty"`
	Connections           []ConnectionPoint     `json:"connections,omitempty"`
	// HostReported marks a report that carries the host firewall fields below,
	// so that empty values mean "none" rather than "not sampled".
	HostReported     bool       `json:"hostReported,omitempty"`
	SSHPorts         []int      `json:"sshPorts,omitempty"`
	FirewallConflict string     `json:"firewallConflict,omitempty"`
	UFWRules         []string   `json:"ufwRules,omitempty"`
	AgentTime        *time.Time `json:"agentTime,omitempty"`
}
