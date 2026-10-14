package shared

import "time"

type Server struct {
	ID                   string     `json:"id"`
	Name                 string     `json:"name"`
	Purpose              string     `json:"purpose"`
	Country              string     `json:"country"`
	Region               string     `json:"region"`
	City                 string     `json:"city"`
	Provider             string     `json:"provider"`
	Tags                 string     `json:"tags"`
	Notes                string     `json:"notes"`
	IPv4                 string     `json:"ipv4"`
	IPv6                 string     `json:"ipv6"`
	Domain               string     `json:"domain"`
	Status               string     `json:"status"`
	OS                   string     `json:"os"`
	Arch                 string     `json:"arch"`
	AgentVersion         string     `json:"agentVersion"`
	AgentBuild           string     `json:"agentBuild"`
	AgentSelfUpdate      bool       `json:"agentSelfUpdate"`
	NodeFirewallPolicies bool       `json:"nodeFirewallPolicies"`
	MultiUserStats       bool       `json:"multiUserStats"`
	ForwardSupport       bool       `json:"forwardSupport"`
	ShadowTLSAuth        bool       `json:"shadowTlsAuth"`
	ReleaseKeyPinned     bool       `json:"releaseKeyPinned"`
	AppliedRevision      int64      `json:"appliedRevision"`
	CoreVersion          string     `json:"coreVersion"`
	CoreBuild            string     `json:"coreBuild"`
	CoreSelfUpdate       bool       `json:"coreSelfUpdate"`
	UFWStatus            string     `json:"ufwStatus"`
	StatsStatus          string     `json:"statsStatus"`
	NetworkRx            int64      `json:"networkRx"`
	NetworkTx            int64      `json:"networkTx"`
	LastSeen             *time.Time `json:"lastSeen"`
	Revision             int64      `json:"revision"`
	// Reported by the agent; never edited by the administrator.
	DetectedIPv4     string   `json:"detectedIpv4"`
	DetectedIPv6     string   `json:"detectedIpv6"`
	ClockSkewSeconds int64    `json:"clockSkewSeconds"`
	SSHPorts         []int    `json:"sshPorts"`
	FirewallConflict string   `json:"firewallConflict"`
	UFWRules         []string `json:"ufwRules"`
}

type Node struct {
	ID              string    `json:"id"`
	ServerID        string    `json:"serverId"`
	Name            string    `json:"name"`
	Protocol        string    `json:"protocol"`
	Port            int       `json:"port"`
	Listen          string    `json:"listen"`
	PublishAddress  string    `json:"publishAddress"`
	Method          string    `json:"method"`
	SnellVersion    int       `json:"snellVersion"`
	Obfs            string    `json:"obfs"`
	ShadowTLSHost   string    `json:"shadowTlsHost"`
	TLSName         string    `json:"tlsName"`
	CertificateID   string    `json:"certificateId"`
	FirewallPolicy  string    `json:"firewallPolicy"`
	FirewallSources string    `json:"firewallSources"`
	Enabled         bool      `json:"enabled"`
	Deleting        bool      `json:"deleting"`
	Status          string    `json:"status"`
	Error           string    `json:"error"`
	Uplink          int64     `json:"uplink"`
	Downlink        int64     `json:"downlink"`
	CreatedAt       time.Time `json:"createdAt"`
}

// NodeTemplate stores reusable node settings without a server-specific address
// or certificate. Its optional password is stored separately and encrypted.
type NodeTemplate struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Protocol      string `json:"protocol"`
	Port          int    `json:"port"`
	Listen        string `json:"listen"`
	Method        string `json:"method"`
	SnellVersion  int    `json:"snellVersion"`
	Obfs          string `json:"obfs"`
	ShadowTLSHost string `json:"shadowTlsHost"`
	TLSName       string `json:"tlsName"`
}

type Certificate struct {
	ID        string    `json:"id"`
	ServerID  string    `json:"serverId"`
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
	Action   string `json:"action"`
	Comment  string `json:"comment"`
	Owner    string `json:"owner"`
	Deleting bool   `json:"deleting"`
	Status   string `json:"status"`
}

// ForwardRule terminates an inbound TCP connection or UDP association on the
// managed server and opens a new connection to the configured destination.
type ForwardRule struct {
	ID              string `json:"id"`
	ServerID        string `json:"serverId"`
	Name            string `json:"name"`
	Network         string `json:"network"`
	Listen          string `json:"listen"`
	Port            int    `json:"port"`
	TargetHost      string `json:"targetHost"`
	TargetPort      int    `json:"targetPort"`
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
	Enabled    bool       `json:"enabled"`
	ExpiresAt  *time.Time `json:"expiresAt"`
	URL        string     `json:"url,omitempty"`
	Uplink     int64      `json:"uplink"`
	Downlink   int64      `json:"downlink"`
	// Filled in for the list view only: nodes this subscription names whose
	// configuration is not live on their server yet, and whether the link can
	// be shown again.
	PendingNodeIDs []string `json:"pendingNodeIds,omitempty"`
	LinkAvailable  bool     `json:"linkAvailable,omitempty"`
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
// of everything a client depends on, and the subscriptions with a login on it.
type NodeDeployment struct {
	Fingerprint   string   `json:"fingerprint"`
	Subscriptions []string `json:"subscriptions"`
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

type DesiredState struct {
	Revision          int64          `json:"revision"`
	ProtocolVersion   int            `json:"protocolVersion"`
	Signature         string         `json:"signature"`
	UpgradeSHA256     string         `json:"upgradeSha256,omitempty"`
	CoreUpgradeSHA256 string         `json:"coreUpgradeSha256,omitempty"`
	Nodes             []ManagedNode  `json:"nodes"`
	Rules             []FirewallRule `json:"rules"`
	Forwards          []ForwardRule  `json:"forwards"`
}

type Job struct {
	ID           string       `json:"id"`
	ServerID     string       `json:"serverId"`
	Kind         string       `json:"kind"`
	FencingToken string       `json:"fencingToken"`
	State        DesiredState `json:"state"`
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
	JobID                string                `json:"jobId,omitempty"`
	JobKind              string                `json:"jobKind,omitempty"`
	JobStatus            string                `json:"jobStatus,omitempty"`
	JobError             string                `json:"jobError,omitempty"`
	FencingToken         string                `json:"fencingToken,omitempty"`
	OS                   string                `json:"os,omitempty"`
	Arch                 string                `json:"arch,omitempty"`
	AgentVersion         string                `json:"agentVersion,omitempty"`
	AgentBuild           string                `json:"agentBuild,omitempty"`
	AgentSelfUpdate      bool                  `json:"agentSelfUpdate,omitempty"`
	NodeFirewallPolicies bool                  `json:"nodeFirewallPolicies,omitempty"`
	MultiUserStats       bool                  `json:"multiUserStats,omitempty"`
	ForwardSupport       bool                  `json:"forwardSupport,omitempty"`
	ShadowTLSAuth        bool                  `json:"shadowTlsAuth,omitempty"`
	ReleaseKeyPinned     bool                  `json:"releaseKeyPinned,omitempty"`
	CoreVersion          string                `json:"coreVersion,omitempty"`
	CoreBuild            string                `json:"coreBuild,omitempty"`
	BuildDigest          string                `json:"buildDigest,omitempty"`
	CoreDigest           string                `json:"coreDigest,omitempty"`
	CoreSelfUpdate       bool                  `json:"coreSelfUpdate,omitempty"`
	UFWStatus            string                `json:"ufwStatus,omitempty"`
	StatsStatus          string                `json:"statsStatus,omitempty"`
	IPv4                 string                `json:"ipv4,omitempty"`
	IPv6                 string                `json:"ipv6,omitempty"`
	Traffic              []TrafficPoint        `json:"traffic,omitempty"`
	UserTraffic          []UserTrafficPoint    `json:"userTraffic,omitempty"`
	ForwardTraffic       []ForwardTrafficPoint `json:"forwardTraffic,omitempty"`
	ServerTraffic        []ServerTrafficPoint  `json:"serverTraffic,omitempty"`
	Connections          []ConnectionPoint     `json:"connections,omitempty"`
	// HostReported marks a report that carries the host firewall fields below,
	// so that empty values mean "none" rather than "not sampled".
	HostReported     bool       `json:"hostReported,omitempty"`
	SSHPorts         []int      `json:"sshPorts,omitempty"`
	FirewallConflict string     `json:"firewallConflict,omitempty"`
	UFWRules         []string   `json:"ufwRules,omitempty"`
	AgentTime        *time.Time `json:"agentTime,omitempty"`
}
