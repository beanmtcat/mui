package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"mui/internal/shared"
)

// signDesiredState attaches the panel's Ed25519 signature to a DesiredState.
func (a *App) signDesiredState(state shared.DesiredState) (shared.DesiredState, error) {
	private, err := a.Store.PanelSigningPrivateKey()
	if err != nil {
		return state, err
	}
	state.Signature = shared.SignDesiredState(private, state)
	return state, nil
}

// verifyAgentSignature checks the HMAC request signature on agent traffic.
// The message is method + "\n" + path + "\n" + timestamp + "\n" + nonce +
// "\n" + sha256hex(body); the key is the raw SHA-256 of the agent token,
// which the server stores as its hex encoding. Timestamps must be within 5
// minutes and a nonce may be used once within 10 minutes.
func (a *App) verifyAgentSignature(r *http.Request, body []byte, tokenHashHexes []string) error {
	timestamp := r.Header.Get("X-Agent-Timestamp")
	nonce := r.Header.Get("X-Agent-Nonce")
	signature := r.Header.Get("X-Agent-Signature")
	if timestamp == "" || nonce == "" || signature == "" {
		return errors.New("agent signature required")
	}
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || abs64(time.Now().Unix()-ts) > 300 {
		return errors.New("agent timestamp out of range")
	}
	if len(nonce) != 32 {
		return errors.New("agent nonce must be 32 hex characters")
	}
	if _, err := hex.DecodeString(nonce); err != nil {
		return errors.New("agent nonce must be hex")
	}
	got, err := hex.DecodeString(signature)
	if err != nil {
		return errors.New("agent signature must be hex")
	}
	sum := sha256.Sum256(body)
	msg := r.Method + "\n" + r.URL.Path + "\n" + timestamp + "\n" + nonce + "\n" + hex.EncodeToString(sum[:])
	matched := false
	for _, tokenHashHex := range tokenHashHexes {
		key, err := hex.DecodeString(tokenHashHex)
		if err != nil {
			return errors.New("agent token hash is invalid")
		}
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(msg))
		if hmac.Equal(got, mac.Sum(nil)) {
			matched = true
			break
		}
	}
	if !matched {
		return errors.New("agent signature mismatch")
	}
	return a.rememberNonce(r.Header.Get("X-Server-ID"), nonce, time.Now())
}

// A nonce must be remembered as long as its timestamp is accepted (five
// minutes either way). An Agent sends a few requests a minute, so a server
// at its quota is replaying or flooding; only that server is refused.
const (
	nonceTTL       = 10 * time.Minute
	noncesPerAgent = 2048
)

func (a *App) rememberNonce(serverID, nonce string, now time.Time) error {
	a.nonceMu.Lock()
	defer a.nonceMu.Unlock()
	expire := func(seen map[string]time.Time) {
		for k, t := range seen {
			if now.Sub(t) > nonceTTL {
				delete(seen, k)
			}
		}
	}
	// Sweeping everything on every request would cost a full scan under the
	// lock; once a minute keeps the table to about one TTL of traffic.
	if now.Sub(a.noncePurge) > time.Minute {
		a.noncePurge = now
		for id, seen := range a.nonces {
			if expire(seen); len(seen) == 0 {
				delete(a.nonces, id)
			}
		}
	}
	seen := a.nonces[serverID]
	if seen == nil {
		seen = map[string]time.Time{}
		a.nonces[serverID] = seen
	}
	if t, used := seen[nonce]; used && now.Sub(t) <= nonceTTL {
		return errors.New("agent nonce replayed")
	}
	if len(seen) >= noncesPerAgent {
		expire(seen)
		if len(seen) >= noncesPerAgent {
			return errors.New("agent nonce quota exceeded")
		}
	}
	seen[nonce] = now
	return nil
}

// maxAgentBody matches readJSON's limit, which the Agent handlers use next.
const maxAgentBody = 2 << 20

func (a *App) agentAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Server-ID")
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		var hash string
		var signs int64
		if id == "" || token == "" || a.Store.DB.QueryRow(`SELECT agent_hash,agent_signs FROM mui_servers WHERE id=$1`, id).Scan(&hash, &signs) != nil {
			errorJSON(w, 401, "agent authentication failed")
			return
		}
		if hash == "" {
			if srv, err := a.Store.Server(id); err == nil && srv.Status == "revoked" {
				errorJSON(w, http.StatusGone, "agent credential revoked; stop contacting this panel")
			} else {
				errorJSON(w, 401, "agent authentication failed")
			}
			return
		}
		if !hmac.Equal([]byte(hash), []byte(Hash(token))) {
			errorJSON(w, 401, "agent authentication failed")
			return
		}
		if srv, err := a.Store.Server(id); err != nil || shared.NoAgentManaged(srv) {
			errorJSON(w, 403, "该服务器不接收在线 Agent 请求")
			return
		}
		// A signed request is always verified. An unsigned one is accepted
		// only from an agent that has never signed: one that predates
		// signatures keeps reporting (and can fetch the upgrade that teaches
		// it to sign) instead of looking offline. After its first signed
		// request, unsigned ones are refused, so a stripped signature cannot
		// downgrade it.
		// The signature covers the body, so it is read whole before the
		// handler's own JSON limit applies; bound it here as well.
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxAgentBody))
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				errorJSON(w, http.StatusRequestEntityTooLarge, "request body too large")
				return
			}
			errorJSON(w, 400, "cannot read request body")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		signed := r.Header.Get("X-Agent-Signature") != ""
		if !signed && signs != 0 {
			errorJSON(w, 401, "agent signature required")
			return
		}
		if signed {
			if err := a.verifyAgentSignature(r, body, []string{hash}); err != nil {
				errorJSON(w, 401, "agent signature verification failed")
				return
			}
			if signs == 0 {
				_, _ = a.Store.DB.Exec(`UPDATE mui_servers SET agent_signs=1 WHERE id=$1`, id)
			}
		}
		next(w, r)
	}
}

// agentObservedIPv4 is called over an IPv4-only connection by an Agent whose
// local IPv4 is hidden by NAT. A SOCKS5 exit must not be mistaken for the
// Agent host; clientIP only trusts headers from configured reverse proxies.
func (a *App) agentObservedIPv4(w http.ResponseWriter, r *http.Request) {
	server, err := a.Store.Server(r.Header.Get("X-Server-ID"))
	if err != nil {
		errorJSON(w, 404, "服务器不存在")
		return
	}
	if !server.AutoSyncPublicIP || server.AgentProxyNodeID != "" || server.AgentProxyPreviousNodeID != "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	ip := net.ParseIP(a.clientIP(r))
	if ip == nil || ip.To4() == nil || !publicUnicast(ip) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, 200, map[string]string{"ipv4": ip.String()})
}

func (a *App) revokeAgent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validServerID(id) || !a.serverExists(id) {
		errorJSON(w, 404, "服务器不存在")
		return
	}
	unlock := a.lockServer(id)
	defer unlock()
	server, err := a.Store.Server(id)
	if err != nil {
		errorJSON(w, 404, "服务器不存在")
		return
	}
	server.Status = "revoked"
	server.LastSeen = nil
	tx, err := a.Store.DB.Begin()
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE mui_servers SET data=$1,agent_hash='',agent_signs=0,enroll_hash='',enroll_expires=0 WHERE id=$2`, Marshal(server), id)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if n, _ := result.RowsAffected(); n == 0 {
		errorJSON(w, 404, "服务器不存在")
		return
	}
	rows, err := tx.Query(`SELECT id,data FROM mui_operations WHERE server_id=$1 AND (claimed_at>=0 OR state<>'')`, id)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	type unfinished struct {
		id string
		op shared.Operation
	}
	var pending []unfinished
	for rows.Next() {
		var item unfinished
		var raw string
		if err = rows.Scan(&item.id, &raw); err == nil {
			err = json.Unmarshal([]byte(raw), &item.op)
		}
		if err != nil {
			break
		}
		if item.op.Status == "queued" || item.op.Status == "running" || item.op.Status == "activating" {
			pending = append(pending, item)
		}
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	for _, item := range pending {
		item.op.Status, item.op.Error, item.op.UpdatedAt = "superseded", "Agent 凭据已吊销", time.Now()
		if _, err = tx.Exec(`UPDATE mui_operations SET data=$1,state='',claimed_at=-1 WHERE id=$2`, Marshal(item.op), item.id); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
	}
	if err = tx.Commit(); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.auditRequest(r, "agent.revoke", id, "")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) enrollment(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	server, err := a.Store.Server(id)
	if err != nil {
		errorJSON(w, 404, "服务器不存在")
		return
	}
	if shared.NoAgentManaged(server) {
		errorJSON(w, 409, "该服务器不安装在线 Agent，不使用接入令牌")
		return
	}
	token := Token()
	_, err = a.Store.DB.Exec(`UPDATE mui_servers SET enroll_hash=$1,enroll_expires=$2 WHERE id=$3`, Hash(token), time.Now().Add(10*time.Minute).Unix(), id)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	publicURL := a.publicURLForRequest(r)
	writeJSON(w, 200, map[string]any{"enrollToken": token, "installCommand": a.installCommandAt(publicURL, id, token, server), "offlineInstall": a.offlineInstallAt(publicURL, id, token, server), "standaloneInstall": a.standaloneInstallAt(publicURL)})
}

func (a *App) agentEnroll(w http.ResponseWriter, r *http.Request) {
	if a.rateCount(r, "enroll", 1) > 30 {
		errorJSON(w, 429, "请求过于频繁")
		return
	}
	var in struct {
		ServerID string `json:"serverId"`
		Token    string `json:"token"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if !validServerID(in.ServerID) || !a.serverExists(in.ServerID) {
		errorJSON(w, 401, "接入令牌无效或已过期")
		return
	}
	unlock := a.lockServer(in.ServerID)
	defer unlock()
	server, serverErr := a.Store.Server(in.ServerID)
	if serverErr == nil && shared.NoAgentManaged(server) {
		errorJSON(w, 403, "该服务器不支持在线接入")
		return
	}
	var expected string
	var expires int64
	err := a.Store.DB.QueryRow(`SELECT enroll_hash,enroll_expires FROM mui_servers WHERE id=$1`, in.ServerID).Scan(&expected, &expires)
	if err != nil || expected == "" || expires < time.Now().Unix() || !hmac.Equal([]byte(expected), []byte(Hash(in.Token))) {
		errorJSON(w, 401, "接入令牌无效或已过期")
		return
	}
	if srv, err := a.Store.Server(in.ServerID); err == nil && srv.AgentProxyNodeID != "" {
		ready, err := a.agentProxyAccessLive(srv)
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		if !ready {
			errorJSON(w, 409, "SOCKS5 服务器尚未确认 Agent 来源放行规则，请等待该服务器的配置任务成功后重试；接入令牌尚未使用")
			return
		}
	}
	token := Token()
	server.Status, server.LastSeen = "pending", nil
	result, err := a.Store.DB.Exec(`UPDATE mui_servers SET data=$1,agent_hash=$2,agent_signs=0,enroll_hash='',enroll_expires=0 WHERE id=$3 AND enroll_hash=$4 AND enroll_expires>=$5`, Marshal(server), Hash(token), in.ServerID, expected, time.Now().Unix())
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		errorJSON(w, 401, "接入令牌已使用")
		return
	}
	publicKey, err := a.Store.EnsurePanelSigningKey()
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.auditRequest(r, "agent.enroll", in.ServerID, "")
	writeJSON(w, 200, map[string]string{"agentToken": token, "panelPublicKey": base64.StdEncoding.EncodeToString(publicKey)})
}

func (a *App) agentJob(w http.ResponseWriter, r *http.Request) {
	id := r.Header.Get("X-Server-ID")
	server, err := a.Store.Server(id)
	if err != nil {
		errorJSON(w, 404, "服务器不存在")
		return
	}
	if err = a.syncExpiredSubscriptionsThrottled(); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	nodes, err := a.Store.Nodes(id)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	// An agent that cannot apply firewall policies must not receive *.apply
	// jobs, but upgrade and init jobs behind them still flow: ClaimJob skips
	// the apply jobs instead of this handler failing the whole poll.
	allowApply := server.NodeFirewallPolicies
	if !allowApply {
		allowApply = true
		for _, node := range nodes {
			if !node.Deleting && node.FirewallPolicy != "" && node.FirewallPolicy != "all" {
				allowApply = false
				break
			}
		}
	}
	// An older Agent ignores the SOCKS5 egress and would send the traffic out
	// of this server's own address instead.
	if allowApply && !server.NodeSOCKSOutbound {
		for _, node := range nodes {
			if node.Enabled && !node.Deleting && node.OutboundMode == "socks5" {
				allowApply = false
				break
			}
		}
	}
	if allowApply && !server.NodeDomainBlock {
		for _, node := range nodes {
			if node.Enabled && !node.Deleting && len(node.BlockedDomains) > 0 {
				allowApply = false
				break
			}
		}
	}
	if !server.AgentProxySupport {
		if server.AgentProxyNodeID != "" {
			allowApply = false
		}
		for _, n := range nodes {
			if !n.Deleting && n.Protocol == "socks5" {
				allowApply = false
			}
		}
	}
	if allowApply && (!server.OutboundBindingSupport || !shared.VersionAtLeast(server.AgentVersion, "0.6.12")) {
		if outboundBindingRequired(server, nodes) {
			allowApply = false
		}
	}
	if allowApply && !server.SnellFixedPort {
		for _, node := range nodes {
			if node.Enabled && !node.Deleting && node.Protocol == "snell" && node.ShadowTLSHost != "" && node.SnellPort != 0 {
				// An older helper silently ignores this field. Keep the apply
				// queued, while still allowing its agent.upgrade job through.
				allowApply = false
				break
			}
		}
	}
	if allowApply && (!server.SnellV6 || !shared.VersionAtLeast(server.AgentVersion, "0.6.11")) {
		for _, node := range nodes {
			// Older helpers validate disabled nodes too, so even an inactive
			// v6 node must not be included in a state they cannot understand.
			if !node.Deleting && node.Protocol == "snell" && shared.SnellVersion(node) == 6 {
				allowApply = false
				break
			}
		}
	}
	if allowApply && !server.ForwardTCPUDP {
		forwards, err := a.Store.Forwards(id)
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		for _, f := range forwards {
			if !f.Deleting && f.Network == shared.ForwardTCPUDP {
				allowApply = false
				break
			}
		}
	}
	if shared.ManualFirewall(server.FirewallMode) && !server.ManualFirewallSupport {
		allowApply = false
	}
	// Only a pending proxy switch must wait for the proxy host's source rule.
	// An unchanged proxy must not stall unrelated node or forward applies.
	if allowApply && server.AgentProxySwitchPending && server.AgentProxyNodeID != "" {
		ready, err := a.agentProxyAccessLive(server)
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		allowApply = ready
	}
	job, err := a.Store.ClaimJob(id, allowApply)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if job == nil {
		w.WriteHeader(204)
		return
	}
	writeJSON(w, 200, job)
}

func (a *App) agentReport(w http.ResponseWriter, r *http.Request) {
	id := r.Header.Get("X-Server-ID")
	unlock := a.lockServer(id)
	defer unlock()
	var in shared.AgentReport
	if !readJSON(w, r, &in) {
		return
	}
	server, err := a.Store.Server(id)
	if err != nil {
		errorJSON(w, 404, "服务器不存在")
		return
	}
	// Authentication happens before this handler takes the per-server lock.
	// A report already in flight when credentials are revoked must not restore
	// the server to "online" after the revocation write.
	if server.Status == "revoked" {
		errorJSON(w, http.StatusGone, "agent credential revoked; stop contacting this panel")
		return
	}
	if shared.NoAgentManaged(server) {
		errorJSON(w, 403, "该服务器不接收在线上报")
		return
	}
	var currentHash string
	if err := a.Store.DB.QueryRow(`SELECT agent_hash FROM mui_servers WHERE id=$1`, id).Scan(&currentHash); err != nil || !hmac.Equal([]byte(currentHash), []byte(Hash(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")))) {
		errorJSON(w, 401, "agent authentication failed")
		return
	}
	// Validate the job report before any write takes effect: an invalid
	// JobStatus, a job that belongs to another server, or a fencing token
	// that does not match the claim must not leave traffic or server state
	// behind.
	var op shared.Operation
	if in.JobID != "" {
		if in.JobStatus != "success" && in.JobStatus != "failed" {
			errorJSON(w, 400, "invalid job status")
			return
		}
		var e error
		op, e = a.Store.Operation(in.JobID)
		if e != nil || op.ServerID != id {
			errorJSON(w, 404, "job not found")
			return
		}
		if op.FencingToken != "" && in.FencingToken != op.FencingToken {
			// An agent that predates fencing never echoes a token. Refusing its
			// result would leave it resending forever, and an agent of that age
			// stops polling for new jobs while a result is outstanding, so it
			// could never even receive its upgrade. Such an agent is recognised
			// by never having signed a request.
			var signs int64
			_ = a.Store.DB.QueryRow(`SELECT agent_signs FROM mui_servers WHERE id=$1`, id).Scan(&signs)
			if in.FencingToken != "" || signs != 0 {
				errorJSON(w, 409, "fencing token mismatch")
				return
			}
		}
		if op.Status == "success" || op.Status == "failed" {
			writeJSON(w, 200, map[string]bool{"ok": true})
			return
		}
	}
	// Report arrays are bounded before any write: without this a 2 MiB body
	// could carry tens of thousands of points into one transaction.
	if len(in.Traffic) > 2000 || len(in.UserTraffic) > 2000 || len(in.ForwardTraffic) > 2000 || len(in.ServerTraffic) > 2000 {
		errorJSON(w, 400, "report arrays must have at most 2000 entries each")
		return
	}
	if len(in.ForwardConnections) > 500 {
		errorJSON(w, 400, "too many forward connection points")
		return
	}
	if len(in.RouteLatencies) > 200 {
		errorJSON(w, 400, "too many route latency points")
		return
	}
	becameClientIPs := in.AgentVersion != "" && shared.VersionAtLeast(in.AgentVersion, "0.6.13") && !shared.VersionAtLeast(server.AgentVersion, "0.6.13")
	becameRouteUFW := !shared.ManualFirewall(server.FirewallMode) && in.AgentVersion != "" && shared.VersionAtLeast(in.AgentVersion, "0.6.15") && !shared.VersionAtLeast(server.AgentVersion, "0.6.15")
	becameShadowTLSDial := in.AgentVersion != "" && shared.VersionAtLeast(in.AgentVersion, "0.6.16") && !shared.VersionAtLeast(server.AgentVersion, "0.6.16")
	becameIdleCoreStop := in.AgentVersion != "" && shared.VersionAtLeast(in.AgentVersion, "0.6.22") && !shared.VersionAtLeast(server.AgentVersion, "0.6.22") && server.CoreBuild != ""
	server.Status = "online"
	becameMultiUser := !server.MultiUserStats && in.MultiUserStats
	becameOutboundBinding := in.AgentVersion != "" && !server.OutboundBindingSupport && in.OutboundBindingSupport && shared.VersionAtLeast(in.AgentVersion, "0.6.12")
	becameForward := !server.ForwardSupport && in.ForwardSupport
	becameForwardTCPUDP := in.AgentVersion != "" && !server.ForwardTCPUDP && in.ForwardTCPUDP
	becameManualFirewall := in.AgentVersion != "" && !server.ManualFirewallSupport && in.ManualFirewallSupport && shared.ManualFirewall(server.FirewallMode)
	// Agent-supplied text ends up in the server document and on the admin's
	// screen; keep each piece to a sane size.
	in.OS, in.Arch, in.AgentVersion, in.AgentBuild = clip(in.OS, 120), clip(in.Arch, 32), clip(in.AgentVersion, 64), clip(in.AgentBuild, 64)
	in.CoreVersion, in.CoreBuild, in.FirewallConflict, in.JobError = clip(in.CoreVersion, 120), clip(in.CoreBuild, 64), clip(in.FirewallConflict, 64), clip(in.JobError, 2000)
	in.UFWStatus, in.StatsStatus, in.IPv4, in.IPv6, in.ObservedIPv4 = clip(in.UFWStatus, 32), clip(in.StatsStatus, 32), clip(in.IPv4, 64), clip(in.IPv6, 64), clip(in.ObservedIPv4, 64)
	if len(in.SSHPorts) > 16 {
		in.SSHPorts = in.SSHPorts[:16]
	}
	for i := range in.UFWRules {
		in.UFWRules[i] = clip(in.UFWRules[i], 300)
	}
	// A change in how Snell logins are checked changes every such node's
	// configuration, so it needs an apply like any other change.
	schemeChanged := in.AgentVersion != "" && server.ShadowTLSAuth != in.ShadowTLSAuth
	now := time.Now()
	server.LastSeen = &now
	if in.OS != "" {
		server.OS = in.OS
	}
	if in.Arch != "" {
		server.Arch = in.Arch
	}
	if in.AgentVersion != "" {
		server.ManagementMigrationFrom = ""
		server.AgentVersion = in.AgentVersion
		server.NodeFirewallPolicies = in.NodeFirewallPolicies
		server.NodeDomainBlock = in.NodeDomainBlock
		server.NodeSOCKSOutbound = in.NodeSOCKSOutbound
		server.ManualFirewallSupport = in.ManualFirewallSupport
		server.MultiUserStats = in.MultiUserStats
		server.ForwardSupport = in.ForwardSupport
		server.ForwardTCPUDP = in.ForwardTCPUDP
		server.ShadowTLSAuth = in.ShadowTLSAuth
		server.SnellFixedPort = in.SnellFixedPort
		server.SnellV6 = in.SnellV6 && shared.VersionAtLeast(in.AgentVersion, "0.6.11")
		server.HostMonitor = in.HostMonitor
		server.OutboundBindingSupport = in.OutboundBindingSupport && shared.VersionAtLeast(in.AgentVersion, "0.6.12")
		server.AgentProxySupport = in.AgentProxySupport
		server.ReleaseKeyPinned = in.ReleaseKeyPinned
		server.AgentSelfUpdate = in.AgentSelfUpdate
		server.AgentBuild = in.AgentBuild
	}
	if in.CoreVersion != "" {
		server.CoreVersion = in.CoreVersion
	}
	if in.CoreBuild != "" {
		server.CoreBuild = in.CoreBuild
	}
	if in.AgentVersion != "" {
		server.CoreSelfUpdate = in.CoreSelfUpdate
	}
	if in.UFWStatus != "" {
		server.UFWStatus = in.UFWStatus
	}
	if in.StatsStatus != "" {
		server.StatsStatus = in.StatsStatus
	}
	// Only a local public interface IPv4 may fill an empty configured IPv4.
	// A panel-observed NAT egress is a firewall source candidate, and may
	// follow an existing configured IPv4 only if it matched the last detected
	// value. Empty reports must not erase previously detected addresses.
	if in.HostReported {
		localIPv4 := net.ParseIP(in.IPv4)
		validLocalIPv4 := localIPv4 != nil && localIPv4.To4() != nil && publicUnicast(localIPv4)
		observedIPv4 := net.ParseIP(in.ObservedIPv4)
		validObservedIPv4 := observedIPv4 != nil && observedIPv4.To4() != nil && publicUnicast(observedIPv4)
		previousDetectedIPv4 := server.DetectedIPv4
		detectedIPv4 := ""
		observedAddress := ""
		noProxy := server.AgentProxyNodeID == "" && server.AgentProxyPreviousNodeID == ""
		if validLocalIPv4 {
			detectedIPv4 = localIPv4.String()
		} else if noProxy {
			if validObservedIPv4 {
				observedAddress = observedIPv4.String()
			} else if server.AutoSyncPublicIP && !shared.VersionAtLeast(server.AgentVersion, "0.6.23") {
				// Agents before 0.6.23 did not send observedIpv4. Their direct
				// report source can still reveal the NAT egress address. A newer
				// Agent's empty observation means its probe has not succeeded yet.
				observed := net.ParseIP(a.clientIP(r))
				if observed != nil && observed.To4() != nil && publicUnicast(observed) {
					observedAddress = observed.String()
				}
			}
			if observedAddress != "" {
				detectedIPv4 = observedAddress
			} else if server.AutoSyncPublicIP {
				// A restart or failed probe can omit the observation. Keep the
				// last source so route firewalls do not remove its allow rule.
				detectedIPv4 = previousDetectedIPv4
			}
		}
		ipv6 := net.ParseIP(in.IPv6)
		validIPv6 := ipv6 != nil && ipv6.To4() == nil && publicUnicast(ipv6)
		detectedIPv6 := server.DetectedIPv6
		if validIPv6 {
			detectedIPv6 = ipv6.String()
		}
		updateIPv4 := validLocalIPv4 && (server.IPv4 == "" || server.AutoSyncPublicIP && server.IPv4 != localIPv4.String())
		updateIPv4 = updateIPv4 || server.AutoSyncPublicIP && observedAddress != "" && server.IPv4 != "" && server.IPv4 == previousDetectedIPv4 && server.IPv4 != observedAddress
		updateIPv6 := validIPv6 && (server.IPv6 == "" || server.AutoSyncPublicIP && server.IPv6 != in.IPv6)
		if server.DetectedIPv4 != detectedIPv4 || server.DetectedIPv6 != detectedIPv6 || updateIPv4 || updateIPv6 {
			// Route firewalls admit hops by these addresses. The sync takes
			// the server locks itself, so it runs after this report is done.
			defer func() { go a.syncRoutesInBackground() }()
		}
		server.DetectedIPv4, server.DetectedIPv6 = detectedIPv4, detectedIPv6
		if updateIPv4 {
			if validLocalIPv4 {
				server.IPv4 = localIPv4.String()
			} else {
				server.IPv4 = observedAddress
			}
		}
		if updateIPv6 {
			server.IPv6 = in.IPv6
		}
	}
	if in.AgentTime != nil {
		server.ClockSkewSeconds = int64(in.AgentTime.Sub(now).Seconds())
	}
	if in.HostReported {
		server.SSHPorts, server.FirewallConflict, server.UFWRules = in.SSHPorts, in.FirewallConflict, in.UFWRules
		if len(server.UFWRules) > 300 {
			server.UFWRules = server.UFWRules[:300]
		}
		if len(in.RouteLatencies) > 0 {
			forwards, e := a.Store.Forwards(id)
			if e != nil {
				errorJSON(w, 500, e.Error())
				return
			}
			server.RouteLatencies = validRouteLatencies(in.RouteLatencies, forwards, now)
		}
	}
	if err = a.Store.PutServer(server); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	minTrafficAt, maxTrafficAt := trafficTimeWindow(now, server.ClockSkewSeconds)
	if len(in.Traffic) > 0 {
		filtered := in.Traffic[:0]
		for _, p := range in.Traffic {
			if len(p.InstanceID) <= 128 && !p.At.IsZero() && !p.At.Before(minTrafficAt) && !p.At.After(maxTrafficAt) {
				filtered = append(filtered, p)
			}
		}
		if len(filtered) > 0 {
			if err = a.Store.SaveTraffic(id, filtered); err != nil {
				errorJSON(w, 500, err.Error())
				return
			}
		}
	}
	if len(in.UserTraffic) > 0 {
		filtered := in.UserTraffic[:0]
		for _, p := range in.UserTraffic {
			if len(p.InstanceID) <= 128 && !p.At.IsZero() && !p.At.Before(minTrafficAt) && !p.At.After(maxTrafficAt) {
				filtered = append(filtered, p)
			}
		}
		if len(filtered) > 0 {
			if err = a.Store.SaveUserTraffic(id, filtered); err != nil {
				errorJSON(w, 500, err.Error())
				return
			}
		}
	}
	if len(in.ForwardTraffic) > 0 {
		filtered := in.ForwardTraffic[:0]
		for _, p := range in.ForwardTraffic {
			if len(p.InstanceID) <= 128 {
				filtered = append(filtered, p)
			}
		}
		if len(filtered) > 0 {
			if err = a.Store.SaveForwardTraffic(id, filtered); err != nil {
				errorJSON(w, 500, err.Error())
				return
			}
		}
	}
	if len(in.ServerTraffic) > 0 {
		filtered := in.ServerTraffic[:0]
		for _, p := range in.ServerTraffic {
			if len(p.BootID) <= 128 && len(p.Interface) <= 128 && !p.At.IsZero() && !p.At.Before(minTrafficAt) && !p.At.After(maxTrafficAt) {
				filtered = append(filtered, p)
			}
		}
		if len(filtered) > 0 {
			if err = a.Store.SaveServerTraffic(id, filtered); err != nil {
				errorJSON(w, 500, err.Error())
				return
			}
		}
	}
	if len(in.ForwardConnections) > 0 {
		if err = a.saveForwardConnectionIPs(id, in.ForwardConnections); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
	}
	if len(in.Connections) > 0 {
		if err = a.Store.SaveConnectionIPs(id, in.Connections); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
	}
	if in.JobID != "" {
		// op was loaded and validated before any write above.
		if op.Kind == "agent.upgrade" && in.JobStatus == "success" {
			err = a.Store.MarkUpgradeActivating(in.JobID)
		} else {
			if op.Kind == "core.upgrade" && in.JobStatus == "success" && (in.CoreBuild != op.TargetBuild || in.CoreDigest != "" && in.CoreDigest != op.TargetBuild) {
				in.JobStatus = "failed"
				in.JobError = "Agent 未确认新版 sing-box 构建哈希"
			}
			err = a.Store.FinishJob(in.JobID, in.JobStatus, in.JobError)
		}
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		if in.JobStatus == "failed" {
			failedOp := op
			failedOp.Status = in.JobStatus
			failedOp.Error = in.JobError
			a.notifyApplyFailed(server, failedOp)
		}
		if op.Kind == "core.upgrade" && in.JobStatus == "success" && !shared.CanHostNodes(server) {
			// Transit already supports nodes. Other roles become an exit when
			// sing-box is explicitly installed.
			server.Roles, _ = validRoles(append(server.Roles, shared.RoleExit))
			if err = a.Store.PutServer(server); err != nil {
				errorJSON(w, 500, err.Error())
				return
			}
		}
		if op.Kind == "ufw.init" && in.JobStatus == "success" && op.Revision == server.Revision {
			nodes, _ := a.Store.Nodes(id)
			rules, _ := a.Store.Rules(id)
			forwards, _ := a.Store.Forwards(id)
			if len(nodes) > 0 || len(rules) > 0 || len(forwards) > 0 {
				if err := a.queueApplyLocked(id, "nodes.apply"); err != nil {
					log.Printf("ufw.init follow-up apply for %s: %v", id, err)
				}
			}
		}
		if strings.HasSuffix(op.Kind, ".apply") && in.JobStatus == "success" && op.Revision == server.Revision {
			proxyChanged := server.AgentProxyPreviousNodeID != "" || server.AgentProxySwitchPending
			server.AgentProxyPreviousNodeID = ""
			server.AgentProxyPreviousInternal = false
			server.AgentProxyPreviousSourceMode = ""
			server.AgentProxySwitchPending = false
			if err = a.Store.PutServer(server); err != nil {
				errorJSON(w, 500, err.Error())
				return
			}
			if proxyChanged {
				defer func() { go a.syncRoutesInBackground() }()
			}
		}
		if strings.HasSuffix(op.Kind, ".apply") && in.JobStatus == "success" && op.Deployed != nil {
			// Whatever revision this job was, it is what the server runs now.
			if err = a.Store.SetAppliedDeployment(id, op.Deployed); err != nil {
				errorJSON(w, 500, err.Error())
				return
			}
		}
		// Only configuration applies touch node/rule/forward status. An upgrade
		// failure must not mark unrelated pending nodes as errored: upgrade
		// operations are queued with the server's current revision.
		if strings.HasSuffix(op.Kind, ".apply") && op.Revision == server.Revision {
			if in.JobStatus == "success" && server.MultiUserStats {
				server.AppliedRevision = op.Revision
				if err = a.Store.PutServer(server); err != nil {
					errorJSON(w, 500, err.Error())
					return
				}
			}
			nodes, _ := a.Store.Nodes(id)
			if in.JobStatus == "success" {
				deleted := []string{}
				for _, n := range nodes {
					if n.Deleting {
						_, _ = a.Store.DB.Exec(`DELETE FROM mui_nodes WHERE id=$1`, n.ID)
						deleted = append(deleted, n.ID)
						continue
					}
					n.Status = "active"
					if !n.Enabled {
						n.Status = "disabled"
					}
					n.Error = ""
					password, _ := a.Store.NodeSecret(n.ID)
					_ = a.Store.PutNode(n, password)
				}
				if err := a.dropFromSubscriptions(deleted); err != nil {
					log.Printf("drop deleted nodes from subscriptions: %v", err)
				}
				rules, _ := a.Store.Rules(id)
				if shared.ManualFirewall(server.FirewallMode) {
					rules = nil // A manual apply did not change these host rules.
				}
				for _, rule := range rules {
					if rule.Deleting {
						_, _ = a.Store.DB.Exec(`DELETE FROM mui_firewall_rules WHERE id=$1`, rule.ID)
						continue
					}
					rule.Status = "active"
					_, _ = a.Store.DB.Exec(`UPDATE mui_firewall_rules SET data=$1 WHERE id=$2`, Marshal(rule), rule.ID)
				}
				forwards, _ := a.Store.Forwards(id)
				if !server.ForwardSupport {
					forwards = nil // This agent ignored them; they stay pending.
				}
				for _, forward := range forwards {
					if forward.Deleting {
						_, _ = a.Store.DB.Exec(`DELETE FROM mui_forward_counters WHERE forward_id=$1`, forward.ID)
						_, _ = a.Store.DB.Exec(`DELETE FROM mui_forward_totals WHERE forward_id=$1`, forward.ID)
						_, _ = a.Store.DB.Exec(`DELETE FROM mui_forwards WHERE id=$1`, forward.ID)
						continue
					}
					forward.Status = "active"
					if !forward.Enabled {
						forward.Status = "disabled"
					}
					forward.Error = ""
					_ = a.Store.PutForward(forward)
				}
			} else {
				for _, n := range nodes {
					if n.Status == "pending" || n.Deleting {
						if !n.Deleting {
							n.Status = "error"
						}
						n.Error = in.JobError
						password, _ := a.Store.NodeSecret(n.ID)
						_ = a.Store.PutNode(n, password)
					}
				}
				rules, _ := a.Store.Rules(id)
				if shared.ManualFirewall(server.FirewallMode) {
					rules = nil
				}
				for _, rule := range rules {
					if rule.Status == "pending" || rule.Deleting {
						rule.Status = "error"
						_, _ = a.Store.DB.Exec(`UPDATE mui_firewall_rules SET data=$1 WHERE id=$2`, Marshal(rule), rule.ID)
					}
				}
				forwards, _ := a.Store.Forwards(id)
				for _, forward := range forwards {
					if forward.Status == "pending" || forward.Deleting {
						forward.Status = "error"
						forward.Error = in.JobError
						_ = a.Store.PutForward(forward)
					}
				}
			}
		}
	}
	if server.AgentBuild != "" {
		if err = a.Store.CompleteUpgradeByBuild(id, server.AgentBuild, in.BuildDigest); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
	}
	if becameOutboundBinding {
		nodes, err := a.Store.Nodes(id)
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		if outboundBindingRequired(server, nodes) {
			if err = a.queueApplyLocked(id, "nodes.apply"); err != nil {
				errorJSON(w, 500, err.Error())
				return
			}
		}
	}
	if becameMultiUser || schemeChanged || becameShadowTLSDial {
		nodes, e := a.Store.Nodes(id)
		if e != nil {
			errorJSON(w, 500, e.Error())
			return
		}
		needsApply := becameMultiUser || schemeChanged
		if becameShadowTLSDial {
			for _, node := range nodes {
				if node.Enabled && !node.Deleting && node.Protocol == "snell" && node.ShadowTLSHost != "" && shared.EffectiveOutboundInterface(node, server.OutboundInterface) != "" {
					needsApply = true
					break
				}
			}
		}
		if len(nodes) > 0 && needsApply {
			if err = a.queueApplyLocked(id, "subscriptions.apply"); err != nil {
				errorJSON(w, 500, err.Error())
				return
			}
		}
	}
	if becameForward || becameForwardTCPUDP || becameClientIPs || becameRouteUFW {
		forwards, e := a.Store.Forwards(id)
		if e != nil {
			errorJSON(w, 500, e.Error())
			return
		}
		if len(forwards) > 0 {
			if err = a.queueApplyLocked(id, "forwards.apply"); err != nil {
				errorJSON(w, 500, err.Error())
				return
			}
		} else if becameRouteUFW {
			nodes, e := a.Store.Nodes(id)
			if e != nil {
				errorJSON(w, 500, e.Error())
				return
			}
			if len(nodes) > 0 {
				if err = a.queueApplyLocked(id, "nodes.apply"); err != nil {
					errorJSON(w, 500, err.Error())
					return
				}
			}
		}
	}
	if becameIdleCoreStop {
		// Older Agents kept sing-box running with an empty configuration. A
		// server already changed to entry-only may have no pending apply job,
		// so queue one when the fixed Agent first reports its new version.
		nodes, e := a.Store.Nodes(id)
		if e != nil {
			errorJSON(w, 500, e.Error())
			return
		}
		if !slices.ContainsFunc(nodes, func(n shared.Node) bool { return n.Enabled && !n.Deleting }) {
			if err = a.queueApplyLocked(id, "nodes.apply"); err != nil {
				errorJSON(w, 500, err.Error())
				return
			}
		}
	}
	if becameManualFirewall {
		// Even an empty manual server needs a signed local state so the
		// helper knows which firewall mode applies before any nodes exist.
		if err = a.queueApplyLocked(id, "nodes.apply"); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
	}
	writeJSON(w, 200, map[string]bool{"ok": true, "autoSyncPublicIp": server.AutoSyncPublicIP})
}

func trafficRetentionDays() int {
	days := 90
	if v := strings.TrimSpace(os.Getenv("MUI_TRAFFIC_RETENTION_DAYS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			days = n
		}
	}
	if days == 0 {
		return 365
	}
	if days < 32 {
		return 32
	}
	return days
}

// trafficTimeWindow returns the acceptable [minAt, maxAt] range for reported
// traffic samples. Signed agents are already within 5 minutes of panel time,
// while unsigned legacy agents or hosts with drifted clocks/timezones report
// ClockSkewSeconds; clamping that skew to ±24h avoids dropping legitimate
// samples while still bounding future rows so PruneTraffic will remove them.
func trafficTimeWindow(now time.Time, clockSkewSeconds int64) (time.Time, time.Time) {
	const maxSkew = int64(24 * 3600)
	skew := clockSkewSeconds
	if skew > maxSkew {
		skew = maxSkew
	} else if skew < -maxSkew {
		skew = -maxSkew
	}
	minAt := now.AddDate(0, 0, -trafficRetentionDays())
	maxAt := now.Add(10 * time.Minute)
	if skew < 0 {
		minAt = minAt.Add(time.Duration(skew) * time.Second)
	} else if skew > 0 {
		maxAt = maxAt.Add(time.Duration(skew) * time.Second)
	}
	return minAt, maxAt
}
