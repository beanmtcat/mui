package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	_ "embed"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"mui/internal/shared"

	"golang.org/x/crypto/bcrypt"
)

type rateBucket struct {
	Count int
	Reset time.Time
}
type App struct {
	Store       *Store
	PublicURL   string
	agentBinDir string
	// mu serialises mutating admin requests. Agent traffic uses per-server
	// locks instead (see lockServer), so one slow agent report no longer
	// blocks every admin write and every other agent.
	mu     sync.Mutex
	rateMu sync.Mutex
	rates  map[string]rateBucket
	// serverLocks serialises server edits, agent reports and queueApply for one
	// server. Admin writes also keep the global mu.
	serverLocksMu sync.Mutex
	serverLocks   map[string]*sync.Mutex
	// nonces remembers agent request nonces for replay detection.
	nonceMu sync.Mutex
	nonces  map[string]time.Time
	trusted []*net.IPNet
	// downloads bounds how many release binaries are being sent at once.
	downloads chan struct{}
	// downloadsByIP bounds concurrent downloads per client address.
	dlMu          sync.Mutex
	downloadsByIP map[string]int
	// releaseKey, when set, is pinned by agents at install time; upgrades must
	// then carry a manifest signed by its private half.
	releaseKey    ed25519.PublicKey
	releaseKeyB64 string
}

//go:embed install-agent.sh
var installAgentScript []byte

func NewApp(s *Store, publicURL string) (*App, error) {
	password := os.Getenv("MUI_ADMIN_PASSWORD")
	var count int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM mui_admin`).Scan(&count); err != nil {
		return nil, err
	}
	// MUI_ADMIN_RESET is the way back in after a lost password or authenticator.
	reset := count > 0 && os.Getenv("MUI_ADMIN_RESET") == "1"
	if count == 0 || reset {
		if len(password) < 12 {
			return nil, errors.New("MUI_ADMIN_PASSWORD must be at least 12 characters for first start or reset")
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}
		if reset {
			if _, err = s.DB.Exec(`UPDATE mui_admin SET password_hash=$1,totp_secret='' WHERE id=1`, string(hash)); err != nil {
				return nil, err
			}
			if _, err = s.DB.Exec(`DELETE FROM mui_sessions`); err != nil {
				return nil, err
			}
			s.Audit("admin.reset", "admin", "MUI_ADMIN_RESET")
		} else if _, err = s.DB.Exec(`INSERT INTO mui_admin(id,password_hash,totp_secret) VALUES(1,$1,'')`, string(hash)); err != nil {
			return nil, err
		}
	}
	binDir := os.Getenv("MUI_AGENT_BIN_DIR")
	if binDir == "" {
		binDir = "bin"
	}
	app := &App{Store: s, PublicURL: strings.TrimRight(publicURL, "/"), agentBinDir: binDir, rates: map[string]rateBucket{}, downloads: make(chan struct{}, 4), serverLocks: map[string]*sync.Mutex{}, nonces: map[string]time.Time{}, downloadsByIP: map[string]int{}}
	if _, err := s.EnsurePanelSigningKey(); err != nil {
		return nil, fmt.Errorf("panel signing key: %w", err)
	}
	if encoded := strings.TrimSpace(os.Getenv("MUI_RELEASE_PUBLIC_KEY")); encoded != "" {
		key, err := shared.ParseReleaseKey(encoded)
		if err != nil {
			return nil, fmt.Errorf("MUI_RELEASE_PUBLIC_KEY: %w", err)
		}
		app.releaseKey, app.releaseKeyB64 = key, encoded
	}
	for _, item := range strings.Split(os.Getenv("MUI_TRUSTED_PROXIES"), ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if ip := net.ParseIP(item); ip != nil {
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			item = fmt.Sprintf("%s/%d", item, bits)
		}
		_, network, err := net.ParseCIDR(item)
		if err != nil {
			return nil, fmt.Errorf("MUI_TRUSTED_PROXIES: %w", err)
		}
		app.trusted = append(app.trusted, network)
	}
	return app, nil
}

func (a *App) trustedProxy(ip net.IP) bool {
	for _, network := range a.trusted {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// clientIP is the address rate limits are keyed on. X-Forwarded-For is only
// believed when the connection comes from a configured proxy, and then the
// right-most address that is not itself a proxy is used: anything further
// left is supplied by the client.
func (a *App) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip == nil || !a.trustedProxy(ip) {
		return host
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.TrimSpace(hops[i]))
		if ip == nil {
			break
		}
		if !a.trustedProxy(ip) {
			return ip.String()
		}
	}
	return host
}

// lockServer returns the unlock function for one server's mutex, creating the
// mutex on first use. Callers must not hold two server locks at once.
func (a *App) lockServer(id string) func() {
	a.serverLocksMu.Lock()
	mu, ok := a.serverLocks[id]
	if !ok {
		mu = &sync.Mutex{}
		a.serverLocks[id] = mu
	}
	a.serverLocksMu.Unlock()
	mu.Lock()
	return mu.Unlock
}

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
	a.nonceMu.Lock()
	defer a.nonceMu.Unlock()
	now := time.Now()
	for k, t := range a.nonces {
		if now.Sub(t) > 10*time.Minute {
			delete(a.nonces, k)
		}
	}
	if _, used := a.nonces[nonce]; used {
		return errors.New("agent nonce replayed")
	}
	if len(a.nonces) > 100000 {
		return errors.New("agent nonce table full")
	}
	a.nonces[nonce] = now
	return nil
}

func abs64(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

// rateCount adds `add` events to the client's one-minute bucket for this scope
// and returns the total. Pass 0 to read without counting.
func (a *App) rateCount(r *http.Request, scope string, add int) int {
	key := scope + ":" + a.clientIP(r)
	a.rateMu.Lock()
	defer a.rateMu.Unlock()
	now := time.Now()
	bucket := a.rates[key]
	if now.After(bucket.Reset) {
		bucket = rateBucket{Reset: now.Add(time.Minute)}
	}
	bucket.Count += add
	if add > 0 {
		a.rates[key] = bucket
	}
	if len(a.rates) > 10000 {
		for k, v := range a.rates {
			if now.After(v.Reset) {
				delete(a.rates, k)
			}
		}
	}
	return bucket.Count
}

func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /download/install.sh", a.downloadInstallScript)
	mux.HandleFunc("GET /download/{arch}/{file}", a.downloadAgentFile)
	mux.HandleFunc("POST /api/login", a.login)
	mux.HandleFunc("POST /api/logout", a.require(a.logout))
	mux.HandleFunc("GET /api/me", a.require(a.me))
	mux.HandleFunc("POST /api/totp/setup", a.require(a.totpSetup))
	mux.HandleFunc("POST /api/totp/enable", a.require(a.totpEnable))
	mux.HandleFunc("POST /api/totp/disable", a.require(a.totpDisable))
	mux.HandleFunc("POST /api/password", a.require(a.changePassword))
	mux.HandleFunc("GET /api/servers", a.require(a.servers))
	mux.HandleFunc("POST /api/servers", a.require(a.servers))
	mux.HandleFunc("PATCH /api/servers/{id}", a.require(a.serverByID))
	mux.HandleFunc("DELETE /api/servers/{id}", a.require(a.serverByID))
	mux.HandleFunc("POST /api/servers/{id}/enrollment", a.require(a.enrollment))
	mux.HandleFunc("POST /api/servers/{id}/agent/upgrade", a.require(a.agentUpgrade))
	mux.HandleFunc("POST /api/servers/{id}/core/upgrade", a.require(a.coreUpgrade))
	mux.HandleFunc("GET /api/agent/release", a.require(a.agentRelease))
	mux.HandleFunc("GET /api/core/release", a.require(a.coreRelease))
	mux.HandleFunc("POST /api/servers/{id}/revoke", a.require(a.revokeAgent))
	mux.HandleFunc("POST /api/servers/{id}/ufw/init", a.require(a.ufwInit))
	mux.HandleFunc("GET /api/servers/{id}/traffic", a.require(a.serverTraffic))
	mux.HandleFunc("GET /api/nodes", a.require(a.nodes))
	mux.HandleFunc("POST /api/nodes", a.require(a.nodes))
	mux.HandleFunc("GET /api/node-templates", a.require(a.nodeTemplates))
	mux.HandleFunc("POST /api/node-templates", a.require(a.nodeTemplates))
	mux.HandleFunc("GET /api/node-templates/{id}", a.require(a.nodeTemplateByID))
	mux.HandleFunc("PATCH /api/node-templates/{id}", a.require(a.nodeTemplateByID))
	mux.HandleFunc("DELETE /api/node-templates/{id}", a.require(a.nodeTemplateByID))
	mux.HandleFunc("PATCH /api/nodes/{id}", a.require(a.nodeByID))
	mux.HandleFunc("DELETE /api/nodes/{id}", a.require(a.nodeByID))
	mux.HandleFunc("GET /api/nodes/{id}/secret", a.require(a.nodeSecret))
	mux.HandleFunc("GET /api/nodes/{id}/share", a.require(a.share))
	mux.HandleFunc("GET /api/certificates", a.require(a.certificates))
	mux.HandleFunc("POST /api/certificates", a.require(a.certificates))
	mux.HandleFunc("DELETE /api/certificates/{id}", a.require(a.certificateByID))
	mux.HandleFunc("GET /api/firewall", a.require(a.firewall))
	mux.HandleFunc("POST /api/firewall", a.require(a.firewall))
	mux.HandleFunc("DELETE /api/firewall/{id}", a.require(a.firewallByID))
	mux.HandleFunc("GET /api/forwards", a.require(a.forwards))
	mux.HandleFunc("POST /api/forwards", a.require(a.forwards))
	mux.HandleFunc("PATCH /api/forwards/{id}", a.require(a.forwardByID))
	mux.HandleFunc("DELETE /api/forwards/{id}", a.require(a.forwardByID))
	mux.HandleFunc("GET /api/subscriptions", a.require(a.subscriptions))
	mux.HandleFunc("GET /api/customers", a.require(a.customers))
	mux.HandleFunc("POST /api/customers", a.require(a.customers))
	mux.HandleFunc("PATCH /api/customers/{id}", a.require(a.customerByID))
	mux.HandleFunc("DELETE /api/customers/{id}", a.require(a.customerByID))
	mux.HandleFunc("GET /api/clients/activity", a.require(a.clientActivity))
	mux.HandleFunc("GET /api/clients/accesses", a.require(a.clientAccesses))
	mux.HandleFunc("GET /api/clients/connections", a.require(a.clientConnections))
	mux.HandleFunc("POST /api/subscriptions", a.require(a.subscriptions))
	mux.HandleFunc("PATCH /api/subscriptions/{id}", a.require(a.subscriptionByID))
	mux.HandleFunc("DELETE /api/subscriptions/{id}", a.require(a.subscriptionByID))
	mux.HandleFunc("GET /api/subscriptions/{id}/preview", a.require(a.previewSubscription))
	mux.HandleFunc("GET /api/subscriptions/{id}/traffic/series", a.require(a.subscriptionTrafficSeries))
	mux.HandleFunc("POST /api/subscriptions/{id}/rotate", a.require(a.rotateSubscription))
	mux.HandleFunc("GET /api/subscriptions/{id}/link", a.require(a.subscriptionLink))
	mux.HandleFunc("GET /api/operations", a.require(a.operations))
	mux.HandleFunc("POST /api/operations/{id}/retry", a.require(a.retryOperation))
	mux.HandleFunc("GET /api/traffic", a.require(a.traffic))
	mux.HandleFunc("GET /api/traffic/series", a.require(a.trafficSeries))
	mux.HandleFunc("GET /api/traffic/summary", a.require(a.trafficSummary))
	mux.HandleFunc("GET /api/traffic/ranking", a.require(a.trafficRanking))
	mux.HandleFunc("GET /api/audit", a.require(a.audit))
	mux.HandleFunc("GET /s/{token}", a.subscriptionDownload)
	mux.HandleFunc("POST /agent/enroll", a.agentEnroll)
	mux.HandleFunc("GET /agent/job", a.agentAuth(a.agentJob))
	mux.HandleFunc("POST /agent/report", a.agentAuth(a.agentReport))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	return a.SecurityHeaders(mux)
}

func (a *App) downloadInstallScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(installAgentScript)
}

// timeoutWriter aborts a download whose total time exceeds the deadline.
// ServeContent stops on the first write error, so a stalled transfer cannot
// hold a download slot forever.
func (a *App) downloadAgentFile(w http.ResponseWriter, r *http.Request) {
	arch, name := r.PathValue("arch"), r.PathValue("file")
	if arch != "amd64" && arch != "arm64" || name != "mui-agent" && name != "sing-box" && name != "SHA256SUMS" && name != "SHA256SUMS.sig" {
		http.NotFound(w, r)
		return
	}
	// These files are public and large. An install fetches four of them; allow
	// a few installs per address and a handful of transfers in total.
	if a.rateCount(r, "download", 1) > 20 {
		errorJSON(w, 429, "下载过于频繁，请稍后再试")
		return
	}
	if name == "mui-agent" || name == "sing-box" {
		select {
		case a.downloads <- struct{}{}:
			defer func() { <-a.downloads }()
		default:
			w.Header().Set("Retry-After", "30")
			errorJSON(w, 503, "同时下载的请求过多，请稍后再试")
			return
		}
		// One concurrent binary download per address: a single slow client
		// must not occupy every global slot.
		ip := a.clientIP(r)
		a.dlMu.Lock()
		if a.downloadsByIP[ip] >= 1 {
			a.dlMu.Unlock()
			w.Header().Set("Retry-After", "30")
			errorJSON(w, 503, "该地址已有下载在进行，请稍后再试")
			return
		}
		a.downloadsByIP[ip]++
		a.dlMu.Unlock()
		defer func() {
			a.dlMu.Lock()
			a.downloadsByIP[ip]--
			if a.downloadsByIP[ip] <= 0 {
				delete(a.downloadsByIP, ip)
			}
			a.dlMu.Unlock()
		}()
	}
	archDir := filepath.Join(a.agentBinDir, arch)
	if info, err := os.Lstat(archDir); err != nil || !info.IsDir() {
		http.NotFound(w, r)
		return
	}
	path := filepath.Join(archDir, name)
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if strings.HasPrefix(name, "SHA256SUMS") {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	// A real write deadline: a client that stops reading is cut off instead of
	// holding a download slot forever.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(30 * time.Minute))
	http.ServeContent(w, r, name, info.ModTime(), f)
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func (a *App) installCommand(serverID, token, purpose string) string {
	if purpose != "relay" {
		purpose = "node"
	}
	pipeline := "curl -fsSL " + shellQuote(a.PublicURL+"/download/install.sh") +
		" | sudo sh -s -- " + shellQuote(a.PublicURL) +
		" " + shellQuote(serverID) +
		" " + shellQuote(token) +
		" " + shellQuote(purpose)
	if a.releaseKeyB64 != "" {
		pipeline += " " + shellQuote(a.releaseKeyB64)
	}
	return "bash -o pipefail -c " + shellQuote(pipeline)
}

func (a *App) SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		// The panel serves only its own scripts, styles and (for TOTP QR
		// codes) data: images. No plugins, no framing, no third-party origins.
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
		if r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS" {
			if origin := r.Header.Get("Origin"); origin != "" {
				u, err := url.Parse(origin)
				// A reverse proxy may rewrite Host, so the public URL's
				// host is an equally valid origin.
				publicHost := ""
				if pub, perr := url.Parse(a.PublicURL); perr == nil {
					publicHost = pub.Host
				}
				if err != nil || (!strings.EqualFold(u.Host, r.Host) && !strings.EqualFold(u.Host, publicHost)) {
					errorJSON(w, 403, "origin mismatch")
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// pageLimit reads ?limit=, between 1 and 500. Without it a caller gets the
// 200 most recent rows, as every list did before paging existed.
func pageLimit(r *http.Request) int {
	n, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || n < 1 {
		return 200
	}
	return min(n, 500)
}

// logQuery assembles the optional filters of a log listing with numbered
// placeholders. Column names come from the handlers, never from the request.
type logQuery struct {
	base    string
	clauses []string
	args    []any
}

func newLogQuery(base string) (*logQuery, *[]any) {
	q := &logQuery{base: base}
	return q, &q.args
}
func (q *logQuery) arg(value any) string {
	q.args = append(q.args, value)
	return "$" + strconv.Itoa(len(q.args))
}
func (q *logQuery) where(clause string) { q.clauses = append(q.clauses, clause) }
func (q *logQuery) equal(column, value string) {
	if value != "" {
		q.where(column + "=" + q.arg(value))
	}
}
func (q *logQuery) before(column, value string) {
	if value != "" {
		q.where(column + "<" + q.arg(value))
	}
}
func (q *logQuery) filtered() string {
	if len(q.clauses) == 0 {
		return q.base
	}
	return q.base + " WHERE " + strings.Join(q.clauses, " AND ")
}
func (q *logQuery) sql(order string, limit, offset int) string {
	s := q.filtered() + " ORDER BY " + order + " LIMIT " + strconv.Itoa(limit)
	if offset > 0 {
		s += " OFFSET " + strconv.Itoa(offset)
	}
	return s
}

// likeEscape makes user text match literally inside a LIKE pattern.
func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// clip shortens untrusted text to at most max bytes without splitting a rune.
func clip(s string, max int) string {
	if len(s) <= max {
		return s
	}
	for max > 0 && s[max]&0xC0 == 0x80 {
		max--
	}
	return s[:max]
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func errorJSON(w http.ResponseWriter, status int, msg string) {
	if status == 500 {
		// Internal details (database errors, driver messages) must not reach
		// the client; they go to the server log instead. Other 5xx codes
		// (503, ...) carry client-meaningful reasons and keep them.
		log.Printf("internal error (%d): %s", status, msg)
		msg = "内部错误"
	}
	writeJSON(w, status, map[string]string{"error": msg})
}

// paginateList serves a list endpoint with optional cursor paging. Without
// ?limit= the legacy behaviour is kept: the full bare array. With ?limit= the
// response is an envelope {items, nextCursor, total}; cursor is the ID of the
// last item already seen (IDs sort chronologically). limit is clamped to 500.
func paginateList[T any](w http.ResponseWriter, r *http.Request, list []T, getID func(T) string) {
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		writeJSON(w, 200, list)
		return
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit < 1 {
		limit = 100
	}
	limit = min(limit, 500)
	cursor := r.URL.Query().Get("cursor")
	page := make([]T, 0, limit)
	nextCursor := ""
	for _, item := range list {
		id := getID(item)
		if cursor != "" && id <= cursor {
			continue
		}
		if len(page) >= limit {
			break
		}
		page = append(page, item)
	}
	// nextCursor is the last returned ID, set only when more items remain.
	if len(page) == limit {
		for _, item := range list {
			if getID(item) > getID(page[len(page)-1]) {
				nextCursor = getID(page[len(page)-1])
				break
			}
		}
	}
	writeJSON(w, 200, map[string]any{"items": page, "nextCursor": nextCursor, "total": len(list)})
}
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		errorJSON(w, 400, err.Error())
		return false
	}
	return true
}
func (a *App) require(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("mui_session")
		if err != nil {
			errorJSON(w, 401, "请先登录")
			return
		}
		var expiry, lastSeen int64
		err = a.Store.DB.QueryRow(`SELECT expires_at,last_seen_at FROM mui_sessions WHERE token_hash=$1`, Hash(c.Value)).Scan(&expiry, &lastSeen)
		if err != nil || expiry < time.Now().Unix() {
			errorJSON(w, 401, "会话已过期")
			return
		}
		now := time.Now().Unix()
		// Sessions also expire after 24 hours without any activity. Rows
		// written before last_seen_at existed carry 0 and are treated as
		// freshly used once.
		if lastSeen > 0 && now-lastSeen > 24*3600 {
			_, _ = a.Store.DB.Exec(`DELETE FROM mui_sessions WHERE token_hash=$1`, Hash(c.Value))
			errorJSON(w, 401, "会话已过期")
			return
		}
		_, _ = a.Store.DB.Exec(`UPDATE mui_sessions SET last_seen_at=$1 WHERE token_hash=$2`, now, Hash(c.Value))
		if r.Method != "GET" && r.Method != "HEAD" {
			a.mu.Lock()
			defer a.mu.Unlock()
		}
		next(w, r)
	}
}
func (a *App) agentAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Server-ID")
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		var hash string
		var signs int64
		if id == "" || token == "" || a.Store.DB.QueryRow(`SELECT agent_hash,agent_signs FROM mui_servers WHERE id=$1`, id).Scan(&hash, &signs) != nil || hash == "" {
			errorJSON(w, 401, "agent authentication failed")
			return
		}
		if !hmac.Equal([]byte(hash), []byte(Hash(token))) {
			errorJSON(w, 401, "agent authentication failed")
			return
		}
		// A signed request is always verified. An unsigned one is accepted
		// only from an agent that has never signed: one that predates
		// signatures keeps reporting (and can fetch the upgrade that teaches
		// it to sign) instead of looking offline. After its first signed
		// request, unsigned ones are refused, so a stripped signature cannot
		// downgrade it.
		body, err := io.ReadAll(r.Body)
		if err != nil {
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

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	// Only failures count, and only against the address they came from, so a
	// stranger guessing passwords cannot lock the administrator out.
	if a.rateCount(r, "login", 0) >= 10 {
		errorJSON(w, 429, "登录尝试过于频繁，请稍后再试")
		return
	}
	var in struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	hash, totp, err := a.adminCredentials()
	if err != nil {
		errorJSON(w, 500, "admin unavailable")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(in.Password)) != nil {
		a.rateCount(r, "login", 1)
		errorJSON(w, 401, "密码或验证码错误")
		return
	}
	if totp != "" && !a.checkTOTP(totp, in.Code) {
		a.rateCount(r, "login", 1)
		errorJSON(w, 401, "密码或验证码错误")
		return
	}
	token := Token()
	expiry := time.Now().Add(7 * 24 * time.Hour)
	_, _ = a.Store.DB.Exec(`DELETE FROM mui_sessions WHERE expires_at<$1`, time.Now().Unix())
	_, err = a.Store.DB.Exec(`INSERT INTO mui_sessions(token_hash,expires_at) VALUES($1,$2)`, Hash(token), expiry.Unix())
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "mui_session", Value: token, Path: "/", HttpOnly: true, Secure: r.TLS != nil || strings.HasPrefix(a.PublicURL, "https://"), SameSite: http.SameSiteStrictMode, Expires: expiry})
	writeJSON(w, 200, map[string]any{"ok": true, "totpEnabled": totp != ""})
}
func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie("mui_session")
	if c != nil {
		_, _ = a.Store.DB.Exec(`DELETE FROM mui_sessions WHERE token_hash=$1`, Hash(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: "mui_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (a *App) me(w http.ResponseWriter, r *http.Request) {
	_, secret, _ := a.adminCredentials()
	writeJSON(w, 200, map[string]any{"authenticated": true, "totpEnabled": secret != ""})
}

// adminCredentials returns the password hash and the TOTP secret ("" when
// two-factor is off). The secret is stored encrypted; a value written before
// that was introduced is still read as is.
func (a *App) adminCredentials() (hash, totp string, err error) {
	if err = a.Store.DB.QueryRow(`SELECT password_hash,totp_secret FROM mui_admin WHERE id=1`).Scan(&hash, &totp); err != nil {
		return "", "", err
	}
	if sealed, ok := strings.CutPrefix(totp, "enc:"); ok {
		totp, err = a.Store.Decrypt(sealed)
	}
	return hash, totp, err
}
func (a *App) changePassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	hash, _, err := a.adminCredentials()
	if err != nil || bcrypt.CompareHashAndPassword([]byte(hash), []byte(in.Current)) != nil {
		errorJSON(w, 403, "当前密码错误")
		return
	}
	if len(in.New) < 12 || len(in.New) > 72 {
		errorJSON(w, 400, "新密码需为 12-72 个字符")
		return
	}
	next, err := bcrypt.GenerateFromPassword([]byte(in.New), bcrypt.DefaultCost)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if _, err = a.Store.DB.Exec(`UPDATE mui_admin SET password_hash=$1 WHERE id=1`, string(next)); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	// Every other session was opened with the old password.
	c, _ := r.Cookie("mui_session")
	_, _ = a.Store.DB.Exec(`DELETE FROM mui_sessions WHERE token_hash<>$1`, Hash(c.Value))
	a.Store.Audit("admin.password", "admin", "")
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (a *App) totpDisable(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	hash, totp, err := a.adminCredentials()
	if err != nil || bcrypt.CompareHashAndPassword([]byte(hash), []byte(in.Password)) != nil || (totp != "" && !verifyTOTP(totp, in.Code)) {
		errorJSON(w, 403, "密码或验证码错误")
		return
	}
	if _, err = a.Store.DB.Exec(`UPDATE mui_admin SET totp_secret='' WHERE id=1`); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.Store.Audit("admin.totp.disable", "admin", "")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// checkTOTP verifies a login code for a caller who has already proven the
// password. Five wrong codes in a row lock the second factor for five minutes
// whatever address they come from, and a code is accepted only once. The
// replay state lives in the database, so a restart does not make a used code
// valid again.
func (a *App) checkTOTP(secret, code string) bool {
	a.rateMu.Lock()
	defer a.rateMu.Unlock()
	lastStep, failures, lockedUntil, err := a.Store.TOTPState()
	if err != nil {
		log.Printf("totp state: %v", err)
		return false
	}
	if time.Now().Before(lockedUntil) {
		return false
	}
	step, ok := totpStep(secret, code)
	if ok && step > lastStep {
		if err := a.Store.SetTOTPState(step, 0, time.Time{}); err != nil {
			log.Printf("totp state: %v", err)
			return false
		}
		return true
	}
	failures++
	locked := time.Time{}
	if failures >= 5 {
		failures, locked = 0, time.Now().Add(5*time.Minute)
		a.Store.Audit("admin.totp.lock", "admin", "5 consecutive wrong codes")
	}
	if err := a.Store.SetTOTPState(lastStep, failures, locked); err != nil {
		log.Printf("totp state: %v", err)
		return false
	}
	return false
}

func verifyTOTP(secret, code string) bool {
	_, ok := totpStep(secret, code)
	return ok
}

// totpStep returns the 30-second step the code belongs to, within one step of now.
func totpStep(secret, code string) (uint64, bool) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return 0, false
	}
	for offset := -1; offset <= 1; offset++ {
		step := uint64(time.Now().Unix()/30 + int64(offset))
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, step)
		mac := hmac.New(sha1.New, key)
		mac.Write(buf)
		sum := mac.Sum(nil)
		i := int(sum[len(sum)-1] & 0xf)
		value := binary.BigEndian.Uint32(sum[i:i+4]) & 0x7fffffff
		if subtle.ConstantTimeCompare([]byte(fmt.Sprintf("%06d", value%1000000)), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}
func (a *App) totpSetup(w http.ResponseWriter, r *http.Request) {
	_, secret, _ := a.adminCredentials()
	if secret != "" {
		errorJSON(w, 409, "已启用 TOTP")
		return
	}
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	secret = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
	// Pending enrollment is tied to the current session and expires with it.
	// The pending secret is encrypted like the enabled one.
	c, _ := r.Cookie("mui_session")
	sealed, err := a.Store.Encrypt(secret)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	_, _ = a.Store.DB.Exec(`INSERT INTO mui_totp_pending(session_hash,secret) VALUES($1,$2) ON CONFLICT(session_hash) DO UPDATE SET secret=excluded.secret`, Hash(c.Value), "enc:"+sealed)
	writeJSON(w, 200, map[string]string{"secret": secret, "uri": "otpauth://totp/MUI:admin?secret=" + secret + "&issuer=MUI"})
}
func (a *App) totpEnable(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Code string `json:"code"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	c, _ := r.Cookie("mui_session")
	var secret string
	if a.Store.DB.QueryRow(`SELECT secret FROM mui_totp_pending WHERE session_hash=$1`, Hash(c.Value)).Scan(&secret) != nil {
		errorJSON(w, 400, "验证码错误")
		return
	}
	// Pending secrets written before encryption was introduced are plain.
	if sealed, ok := strings.CutPrefix(secret, "enc:"); ok {
		clear, err := a.Store.Decrypt(sealed)
		if err != nil {
			errorJSON(w, 400, "验证码错误")
			return
		}
		secret = clear
	}
	if !verifyTOTP(secret, in.Code) {
		errorJSON(w, 400, "验证码错误")
		return
	}
	sealed, err := a.Store.Encrypt(secret)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if _, err = a.Store.DB.Exec(`UPDATE mui_admin SET totp_secret=$1 WHERE id=1`, "enc:"+sealed); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	// Only this session's pending enrollment is consumed; other sessions'
	// pending enrollments stay untouched.
	_, _ = a.Store.DB.Exec(`DELETE FROM mui_totp_pending WHERE session_hash=$1`, Hash(c.Value))
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) servers(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		list, err := a.Store.Servers()
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		for i := range list {
			list[i].Status = serverStatus(list[i])
		}
		paginateList(w, r, list, func(s shared.Server) string { return s.ID })
		return
	}
	var in shared.Server
	if !readJSON(w, r, &in) {
		return
	}
	// Only administrator-supplied fields are copied. Agent-reported fields
	// (AppliedRevision, AgentBuild, LastSeen, DetectedIPv4/IPv6, UFWRules,
	// SSHPorts, ...) are never writable at creation.
	purpose := in.Purpose
	if purpose == "" {
		purpose = "node"
	}
	if purpose != "node" && purpose != "relay" {
		errorJSON(w, 400, "服务器用途无效")
		return
	}
	srv := shared.Server{
		ID: ID(), Name: in.Name, Purpose: purpose,
		Country: strings.ToUpper(in.Country), Region: in.Region, City: in.City,
		Provider: in.Provider, Tags: in.Tags, Notes: in.Notes,
		IPv4: in.IPv4, IPv6: in.IPv6, Domain: in.Domain,
		Status: "pending", UFWStatus: "unknown",
	}
	if strings.TrimSpace(srv.Name) == "" || len(srv.Country) != 2 || (srv.IPv4 == "" && srv.IPv6 == "" && srv.Domain == "") {
		errorJSON(w, 400, "需填写名称、国家代码和公网地址或域名")
		return
	}
	if srv.IPv4 != "" && net.ParseIP(srv.IPv4).To4() == nil || srv.IPv6 != "" && (net.ParseIP(srv.IPv6) == nil || net.ParseIP(srv.IPv6).To4() != nil) {
		errorJSON(w, 400, "IP 格式无效")
		return
	}
	token := Token()
	_, err := a.Store.DB.Exec(`INSERT INTO mui_servers(id,data,enroll_hash,enroll_expires) VALUES($1,$2,$3,$4)`, srv.ID, Marshal(srv), Hash(token), time.Now().Add(10*time.Minute).Unix())
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.Store.Audit("server.create", srv.ID, srv.Name)
	writeJSON(w, 201, map[string]any{"server": srv, "enrollToken": token, "installCommand": a.installCommand(srv.ID, token, srv.Purpose)})
}

// serverStatus derives what the stored status cannot express: a server that
// stopped reporting is offline, whatever its last report said.
func serverStatus(s shared.Server) string {
	if s.LastSeen == nil {
		return "pending"
	}
	// Agents report every 30 seconds; two missed reports mean offline.
	if time.Since(*s.LastSeen) > 90*time.Second {
		return "offline"
	}
	return "online"
}

// purgeServer removes a server together with everything that belongs to it.
// It is the only way to get rid of a server whose agent will never confirm a
// deletion again.
func (a *App) purgeServer(id string) error {
	nodes, err := a.Store.Nodes(id)
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(nodes))
	for _, n := range nodes {
		ids = append(ids, n.ID)
	}
	tx, err := a.Store.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, nodeID := range ids {
		for _, stmt := range []string{`DELETE FROM mui_traffic WHERE node_id=$1`, `DELETE FROM mui_node_totals WHERE node_id=$1`, `DELETE FROM mui_user_traffic WHERE node_id=$1`, `DELETE FROM mui_user_totals WHERE node_id=$1`} {
			if _, err = tx.Exec(stmt, nodeID); err != nil {
				return err
			}
		}
	}
	for _, stmt := range []string{
		`DELETE FROM mui_forward_counters WHERE forward_id IN (SELECT id FROM mui_forwards WHERE server_id=$1)`,
		`DELETE FROM mui_forward_totals WHERE forward_id IN (SELECT id FROM mui_forwards WHERE server_id=$1)`,
	} {
		if _, err = tx.Exec(stmt, id); err != nil {
			return err
		}
	}
	for _, stmt := range []string{
		`DELETE FROM mui_nodes WHERE server_id=$1`, `DELETE FROM mui_firewall_rules WHERE server_id=$1`, `DELETE FROM mui_forwards WHERE server_id=$1`, `DELETE FROM mui_certificates WHERE server_id=$1`,
		`DELETE FROM mui_operations WHERE server_id=$1`, `DELETE FROM mui_server_traffic WHERE server_id=$1`, `DELETE FROM mui_server_totals WHERE server_id=$1`, `DELETE FROM mui_server_applied WHERE server_id=$1`,
		`DELETE FROM mui_connection_ips WHERE server_id=$1`,
		`DELETE FROM mui_servers WHERE id=$1`,
	} {
		if _, err = tx.Exec(stmt, id); err != nil {
			return err
		}
	}
	if err = a.dropFromSubscriptionsTx(tx, ids); err != nil {
		return err
	}
	return tx.Commit()
}

// dropFromSubscriptionsTx is dropFromSubscriptions inside an existing
// transaction, so a purge either removes the nodes and their subscription
// references together or removes nothing.
func (a *App) dropFromSubscriptionsTx(tx *sql.Tx, nodeIDs []string) error {
	if len(nodeIDs) == 0 {
		return nil
	}
	gone := map[string]bool{}
	for _, id := range nodeIDs {
		gone[id] = true
	}
	rows, err := tx.Query(`SELECT id,data FROM mui_subscriptions`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type subRow struct {
		id  string
		sub shared.Subscription
	}
	updates := []subRow{}
	for rows.Next() {
		var row subRow
		var raw string
		if err := rows.Scan(&row.id, &raw); err != nil {
			return err
		}
		if err := json.Unmarshal([]byte(raw), &row.sub); err != nil {
			return err
		}
		kept := make([]string, 0, len(row.sub.NodeIDs))
		for _, id := range row.sub.NodeIDs {
			if !gone[id] {
				kept = append(kept, id)
			}
		}
		if len(kept) != len(row.sub.NodeIDs) {
			row.sub.NodeIDs = kept
			updates = append(updates, row)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	for _, row := range updates {
		if _, err := tx.Exec(`UPDATE mui_subscriptions SET data=$1 WHERE id=$2`, Marshal(row.sub), row.id); err != nil {
			return err
		}
	}
	return nil
}

// dropFromSubscriptions removes deleted nodes from every subscription that lists them.
func (a *App) dropFromSubscriptions(nodeIDs []string) error {
	if len(nodeIDs) == 0 {
		return nil
	}
	gone := map[string]bool{}
	for _, id := range nodeIDs {
		gone[id] = true
	}
	subs, err := a.Store.Subscriptions()
	if err != nil {
		return err
	}
	for _, sub := range subs {
		kept := make([]string, 0, len(sub.NodeIDs))
		for _, id := range sub.NodeIDs {
			if !gone[id] {
				kept = append(kept, id)
			}
		}
		if len(kept) == len(sub.NodeIDs) {
			continue
		}
		sub.NodeIDs = kept
		if _, err = a.Store.DB.Exec(`UPDATE mui_subscriptions SET data=$1 WHERE id=$2`, Marshal(sub), sub.ID); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) revokeAgent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	result, err := a.Store.DB.Exec(`UPDATE mui_servers SET agent_hash='',enroll_hash='',enroll_expires=0 WHERE id=$1`, id)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if n, _ := result.RowsAffected(); n == 0 {
		errorJSON(w, 404, "服务器不存在")
		return
	}
	a.Store.Audit("agent.revoke", id, "")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) serverByID(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	// PATCH writes the whole server document, including fields supplied by
	// heartbeats. Share their lock so neither writer restores an older snapshot.
	unlock := a.lockServer(id)
	defer unlock()
	old, err := a.Store.Server(id)
	if err != nil {
		errorJSON(w, 404, "服务器不存在")
		return
	}
	if r.Method == "DELETE" {
		if serverStatus(old) == "online" {
			errorJSON(w, 409, "服务器仍在线；请先删除其节点与规则并停用 Agent，或吊销 Agent 凭据后再删除")
			return
		}
		nodes, _ := a.Store.Nodes(id)
		rules, _ := a.Store.Rules(id)
		forwards, _ := a.Store.Forwards(id)
		certs, _ := a.Store.Certificates(id)
		if (len(nodes) > 0 || len(rules) > 0 || len(forwards) > 0 || len(certs) > 0) && r.URL.Query().Get("force") != "1" {
			errorJSON(w, 409, "该服务器仍有节点、转发、规则或证书；离线服务器可强制删除")
			return
		}
		if err = a.purgeServer(id); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		a.Store.Audit("server.delete", id, old.Name)
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}
	var in shared.Server
	if !readJSON(w, r, &in) {
		return
	}
	old.Name = in.Name
	if in.Purpose == "" {
		in.Purpose = "node"
	}
	if in.Purpose != "node" && in.Purpose != "relay" {
		errorJSON(w, 400, "服务器用途无效")
		return
	}
	if old.Purpose == "" {
		old.Purpose = "node"
	}
	if old.AgentVersion != "" && in.Purpose != old.Purpose {
		errorJSON(w, 409, "已接入的服务器请通过 sing-box 安装操作转换用途")
		return
	}
	if in.Purpose == "relay" && old.Purpose != "relay" {
		nodes, err := a.Store.Nodes(id)
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		if len(nodes) > 0 {
			errorJSON(w, 409, "该服务器仍有节点，请先删除节点再切换为仅转发")
			return
		}
	}
	old.Purpose = in.Purpose
	old.Country = strings.ToUpper(in.Country)
	old.Region = in.Region
	old.City = in.City
	old.Provider = in.Provider
	old.Tags = in.Tags
	old.Notes = in.Notes
	old.IPv4 = in.IPv4
	old.IPv6 = in.IPv6
	old.Domain = in.Domain
	if old.Name == "" || len(old.Country) != 2 || (old.IPv4 == "" && old.IPv6 == "" && old.Domain == "") {
		errorJSON(w, 400, "名称、国家代码及地址必填")
		return
	}
	if old.IPv4 != "" && net.ParseIP(old.IPv4).To4() == nil || old.IPv6 != "" && (net.ParseIP(old.IPv6) == nil || net.ParseIP(old.IPv6).To4() != nil) {
		errorJSON(w, 400, "IP 格式无效")
		return
	}
	if err = a.Store.PutServer(old); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.Store.Audit("server.update", id, old.Name)
	writeJSON(w, 200, old)
}
func (a *App) enrollment(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	server, err := a.Store.Server(id)
	if err != nil {
		errorJSON(w, 404, "服务器不存在")
		return
	}
	token := Token()
	_, err = a.Store.DB.Exec(`UPDATE mui_servers SET enroll_hash=$1,enroll_expires=$2 WHERE id=$3`, Hash(token), time.Now().Add(10*time.Minute).Unix(), id)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"enrollToken": token, "installCommand": a.installCommand(id, token, server.Purpose)})
}

func normalizeNodeTemplate(t *shared.NodeTemplate) {
	t.Name = strings.TrimSpace(t.Name)
	t.Listen = strings.TrimSpace(t.Listen)
	t.ShadowTLSHost = strings.TrimSpace(t.ShadowTLSHost)
	if t.Listen == "" {
		t.Listen = "0.0.0.0"
	}
	switch t.Protocol {
	case "ss":
		if t.Method == "" {
			t.Method = "2022-blake3-aes-128-gcm"
		}
		t.SnellVersion, t.Obfs, t.ShadowTLSHost, t.TLSName = 0, "", "", ""
	case "snell":
		if t.SnellVersion == 0 {
			t.SnellVersion = 5
		}
		if t.Obfs == "" {
			t.Obfs = "none"
		}
		t.Method, t.TLSName = "", ""
	case "anytls":
		t.TLSName = strings.TrimSpace(t.TLSName)
		t.Method, t.SnellVersion, t.Obfs, t.ShadowTLSHost = "", 0, "", ""
	}
}

func (a *App) nodeTemplates(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		list, err := a.Store.NodeTemplates()
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		paginateList(w, r, list, func(t shared.NodeTemplate) string { return t.ID })
		return
	}
	var in struct {
		shared.NodeTemplate
		Password          string `json:"password"`
		ShadowTLSPassword string `json:"shadowTlsPassword"`
		// Older clients may still send these template fields; they are ignored.
		FirewallPolicy  string `json:"firewallPolicy"`
		FirewallSources string `json:"firewallSources"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	t := in.NodeTemplate
	t.ID = ID()
	normalizeNodeTemplate(&t)
	if t.Protocol == "snell" && t.ShadowTLSHost == "" {
		errorJSON(w, 400, "Snell 模板需要 ShadowTLS SNI / 握手域名")
		return
	}
	if err := shared.ValidateNodeTemplate(t); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if in.Password != "" {
		if err := validatePassword(shared.Node{Protocol: t.Protocol, Method: t.Method}, in.Password); err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
	}
	if err := validateShadowTLSPassword(t.Protocol, in.ShadowTLSPassword); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if err := a.Store.PutNodeTemplate(t, in.Password, in.ShadowTLSPassword); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.Store.Audit("node_template.create", t.ID, t.Name)
	writeJSON(w, 201, t)
}

func (a *App) nodeTemplateByID(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	old, err := a.Store.NodeTemplate(id)
	if err != nil {
		errorJSON(w, 404, "节点模板不存在")
		return
	}
	if r.Method == "GET" {
		password, err := a.Store.NodeTemplateSecret(id)
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		shadowPassword, err := a.Store.NodeTemplateShadowTLSSecret(id)
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, struct {
			shared.NodeTemplate
			Password          string `json:"password"`
			ShadowTLSPassword string `json:"shadowTlsPassword"`
		}{old, password, shadowPassword})
		return
	}
	if r.Method == "DELETE" {
		if err := a.Store.DeleteNodeTemplate(id); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		a.Store.Audit("node_template.delete", id, "")
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}
	var in struct {
		shared.NodeTemplate
		Password          *string `json:"password"`
		ShadowTLSPassword *string `json:"shadowTlsPassword"`
		FirewallPolicy    string  `json:"firewallPolicy"`
		FirewallSources   string  `json:"firewallSources"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	t := in.NodeTemplate
	t.ID = id
	normalizeNodeTemplate(&t)
	if t.Protocol == "snell" && t.ShadowTLSHost == "" {
		errorJSON(w, 400, "Snell 模板需要 ShadowTLS SNI / 握手域名")
		return
	}
	if err := shared.ValidateNodeTemplate(t); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	password, err := a.Store.NodeTemplateSecret(id)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if in.Password != nil {
		password = *in.Password
	}
	shadowPassword, err := a.Store.NodeTemplateShadowTLSSecret(id)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if in.ShadowTLSPassword != nil {
		shadowPassword = *in.ShadowTLSPassword
	}
	if t.Protocol != "snell" {
		shadowPassword = ""
	}
	if password != "" {
		if err := validatePassword(shared.Node{Protocol: t.Protocol, Method: t.Method}, password); err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
	}
	if err := validateShadowTLSPassword(t.Protocol, shadowPassword); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if err := a.Store.PutNodeTemplate(t, password, shadowPassword); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.Store.Audit("node_template.update", id, t.Name)
	writeJSON(w, 200, t)
}

func (a *App) nodes(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		list, err := a.Store.Nodes(r.URL.Query().Get("serverId"))
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		totals, err := a.Store.NodeTotals()
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		for i := range list {
			list[i].Uplink, list[i].Downlink = totals[list[i].ID][0], totals[list[i].ID][1]
		}
		paginateList(w, r, list, func(n shared.Node) string { return n.ID })
		return
	}
	var in struct {
		shared.Node
		Password          string `json:"password"`
		ShadowTLSPassword string `json:"shadowTlsPassword"`
		TemplateID        string `json:"templateId"`
		// Enabled is a pointer so creation can tell "omitted" (default true)
		// from an explicit false.
		Enabled *bool `json:"enabled"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	n := in.Node
	n.ShadowTLSHost = strings.TrimSpace(n.ShadowTLSHost)
	n.ID = ID()
	n.CreatedAt = time.Now()
	n.Status = "pending"
	n.Deleting = false
	n.Enabled = true
	if in.Enabled != nil {
		n.Enabled = *in.Enabled
	}
	if n.Listen == "" {
		n.Listen = "0.0.0.0"
	}
	if n.Method == "" {
		n.Method = "2022-blake3-aes-128-gcm"
	}
	policy, sources, accessErr := shared.NormalizeFirewallAccess(n.FirewallPolicy, n.FirewallSources)
	if accessErr != nil {
		errorJSON(w, 400, accessErr.Error())
		return
	}
	n.FirewallPolicy, n.FirewallSources = policy, sources
	if n.Protocol == "snell" {
		n.SnellVersion = 5
		if n.ShadowTLSHost == "" {
			errorJSON(w, 400, "Snell 节点需要 ShadowTLS SNI / 握手域名")
			return
		}
	}
	server, err := a.Store.Server(n.ServerID)
	if err != nil {
		errorJSON(w, 404, "服务器不存在")
		return
	}
	if server.Purpose == "relay" {
		errorJSON(w, 409, "该服务器为仅转发模式；请先在服务器列表安装 sing-box")
		return
	}
	var cert *shared.Certificate
	if n.CertificateID != "" {
		v, err := a.Store.Certificate(n.CertificateID)
		if err == nil && v.ServerID == n.ServerID {
			cert = &v
		}
	}
	if err := shared.ValidateNode(n, cert, false); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if err := sshPortError(server, n.Port, n.Port); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	others, _ := a.Store.Nodes(n.ServerID)
	for _, other := range others {
		if shared.PortConflict(n, other) {
			errorJSON(w, 409, "端口已被其他节点占用")
			return
		}
	}
	if err := a.checkNodeForwardPort(n); err != nil {
		errorJSON(w, 409, err.Error())
		return
	}
	password := in.Password
	shadowPassword := in.ShadowTLSPassword
	if in.TemplateID != "" {
		template, err := a.Store.NodeTemplate(in.TemplateID)
		if err != nil {
			errorJSON(w, 404, "节点模板不存在")
			return
		}
		if template.Protocol != n.Protocol || (n.Protocol == "ss" && template.Method != n.Method) || (n.Protocol == "snell" && template.ShadowTLSHost != n.ShadowTLSHost) {
			errorJSON(w, 400, "节点协议、加密方式或 ShadowTLS 域名与模板不一致")
			return
		}
		if password == "" {
			password, err = a.Store.NodeTemplateSecret(in.TemplateID)
			if err != nil {
				errorJSON(w, 500, err.Error())
				return
			}
		}
		if n.Protocol == "snell" && shadowPassword == "" {
			shadowPassword, err = a.Store.NodeTemplateShadowTLSSecret(in.TemplateID)
			if err != nil {
				errorJSON(w, 500, err.Error())
				return
			}
		}
	}
	if password == "" {
		password = Token()
		if n.Protocol == "ss" && strings.HasPrefix(n.Method, "2022-") {
			password = base64Key(n.Method)
		}
	}
	if err := validatePassword(n, password); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if n.Protocol == "snell" && shadowPassword == "" {
		shadowPassword = Token()
	}
	if err := validateShadowTLSPassword(n.Protocol, shadowPassword); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if err := a.Store.PutNodeWithShadowTLS(n, password, shadowPassword); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if err := a.queueApply(n.ServerID, "nodes.apply"); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.Store.Audit("node.create", n.ID, n.Name)
	writeJSON(w, 201, n)
}

// sshPortError refuses a port range that covers a port sshd listens on, as last
// reported by the agent. The agent enforces the same on the host; this only
// gives the answer before a job is queued.
func sshPortError(server shared.Server, from, to int) error {
	for _, port := range server.SSHPorts {
		if port >= from && port <= to {
			return fmt.Errorf("端口 %d 是该服务器的 SSH 端口", port)
		}
	}
	return nil
}
func base64Key(method string) string {
	length := 16
	if !strings.Contains(method, "128") {
		length = 32
	}
	b := make([]byte, length)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}
func validatePassword(n shared.Node, password string) error {
	if len(password) < 8 {
		return errors.New("密码 / PSK 至少 8 字符")
	}
	if n.Protocol == "ss" && strings.HasPrefix(n.Method, "2022-") {
		raw, err := base64.StdEncoding.DecodeString(password)
		length := 16
		if !strings.Contains(n.Method, "128") {
			length = 32
		}
		if err != nil || len(raw) != length {
			return fmt.Errorf("%s 密钥必须是 %d 字节的 Base64", n.Method, length)
		}
	}
	return nil
}
func validateShadowTLSPassword(protocol, password string) error {
	if protocol != "snell" {
		if password != "" {
			return errors.New("只有 Snell 节点可以设置 ShadowTLS 密码")
		}
		return nil
	}
	if password != "" && (len(password) < 8 || strings.ContainsAny(password, ",\r\n")) {
		return errors.New("ShadowTLS 密码至少 8 字符，且不能包含逗号或换行")
	}
	return nil
}

func (a *App) nodeSecret(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := a.Store.Node(id); err != nil {
		errorJSON(w, 404, "节点不存在")
		return
	}
	password, err := a.Store.NodeSecret(id)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	shadowPassword, err := a.Store.NodeShadowTLSSecret(id)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]string{"password": password, "shadowTlsPassword": shadowPassword})
}

func (a *App) nodeByID(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	old, err := a.Store.Node(id)
	if err != nil {
		errorJSON(w, 404, "节点不存在")
		return
	}
	if r.Method == "DELETE" {
		old.Deleting = true
		old.Error = ""
		password, _ := a.Store.NodeSecret(id)
		if err = a.Store.PutNode(old, password); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		if err = a.queueApply(old.ServerID, "nodes.apply"); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		a.Store.Audit("node.delete", id, old.Name)
		writeJSON(w, 202, map[string]bool{"queued": true})
		return
	}
	if old.Deleting {
		errorJSON(w, 409, "节点正在删除，无法编辑")
		return
	}
	var in struct {
		shared.Node
		Password          string `json:"password"`
		ShadowTLSPassword string `json:"shadowTlsPassword"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	n := in.Node
	n.ShadowTLSHost = strings.TrimSpace(n.ShadowTLSHost)
	n.ID = old.ID
	n.ServerID = old.ServerID
	n.CreatedAt = old.CreatedAt
	n.Status = "pending"
	n.Deleting = false
	if n.Listen == "" {
		n.Listen = "0.0.0.0"
	}
	if n.Method == "" {
		n.Method = old.Method
	}
	if n.SnellVersion == 0 && n.Protocol == "snell" {
		n.SnellVersion = 5
	}
	policy, sources, accessErr := shared.NormalizeFirewallAccess(n.FirewallPolicy, n.FirewallSources)
	if accessErr != nil {
		errorJSON(w, 400, accessErr.Error())
		return
	}
	n.FirewallPolicy, n.FirewallSources = policy, sources
	if n.Protocol == "snell" && n.ShadowTLSHost == "" {
		errorJSON(w, 400, "Snell 节点需要 ShadowTLS SNI / 握手域名")
		return
	}
	var cert *shared.Certificate
	if n.CertificateID != "" {
		v, e := a.Store.Certificate(n.CertificateID)
		if e == nil && v.ServerID == n.ServerID {
			cert = &v
		}
	}
	// A node may be switched off with an expired certificate, not kept running with one.
	if err = shared.ValidateNode(n, cert, !n.Enabled); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	subs, err := a.Store.Subscriptions()
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	for _, sub := range subs {
		for _, nodeID := range sub.NodeIDs {
			if nodeID == n.ID {
				if err := validateSubscriptionNode(sub.Format, n); err != nil {
					errorJSON(w, 400, "节点被订阅“"+sub.Name+"”使用："+err.Error())
					return
				}
			}
		}
	}
	server, err := a.Store.Server(n.ServerID)
	if err != nil {
		errorJSON(w, 404, "服务器不存在")
		return
	}
	if n.Port != old.Port {
		if err = sshPortError(server, n.Port, n.Port); err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
	}
	others, _ := a.Store.Nodes(n.ServerID)
	for _, other := range others {
		if shared.PortConflict(n, other) {
			errorJSON(w, 409, "端口已被其他节点占用")
			return
		}
	}
	if err := a.checkNodeForwardPort(n); err != nil {
		errorJSON(w, 409, err.Error())
		return
	}
	password := in.Password
	if password == "" {
		password, _ = a.Store.NodeSecret(id)
		if n.Protocol == "ss" && strings.HasPrefix(n.Method, "2022-") && (old.Protocol != "ss" || old.Method != n.Method) {
			password = base64Key(n.Method)
		}
	}
	if err := validatePassword(n, password); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	shadowPassword := in.ShadowTLSPassword
	if n.Protocol == "snell" && shadowPassword == "" {
		if old.Protocol == "snell" {
			shadowPassword, err = a.Store.NodeShadowTLSSecret(id)
			if err != nil {
				errorJSON(w, 500, err.Error())
				return
			}
		}
		if shadowPassword == "" {
			shadowPassword = Token()
		}
	}
	if n.Protocol != "snell" {
		shadowPassword = ""
	}
	if err := validateShadowTLSPassword(n.Protocol, shadowPassword); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if err = a.Store.PutNodeWithShadowTLS(n, password, shadowPassword); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if err = a.queueApply(n.ServerID, "nodes.apply"); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.Store.Audit("node.update", id, n.Name)
	writeJSON(w, 200, n)
}
func (a *App) share(w http.ResponseWriter, r *http.Request) {
	n, err := a.Store.Node(r.PathValue("id"))
	if err != nil {
		errorJSON(w, 404, "节点不存在")
		return
	}
	server, _ := a.Store.Server(n.ServerID)
	password, _ := a.Store.NodeSecret(n.ID)
	if n.Protocol == "ss" && shared.SSMultiUser(n.Method) {
		if live, err := a.nodeLive(n, server, "direct"); err != nil || !live {
			errorJSON(w, 503, "该节点的配置尚未在服务器上生效")
			return
		}
		password += ":" + a.Store.SubscriptionUser(n, "direct").Password
	}
	uri, err := shared.ShareURI(shared.SubscriptionItem{Node: n, Server: server, Password: password})
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"uri": uri})
}

func (a *App) certificates(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		list, err := a.Store.Certificates(r.URL.Query().Get("serverId"))
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		for i := range list {
			list[i].PEM = ""
			list[i].DaysUntilExpiry, list[i].ExpiringSoon = shared.CertExpiryStatus(list[i].ExpiresAt)
		}
		paginateList(w, r, list, func(c shared.Certificate) string { return c.ID })
		return
	}
	var in shared.Certificate
	if !readJSON(w, r, &in) {
		return
	}
	if _, err := a.Store.Server(in.ServerID); err != nil {
		errorJSON(w, 404, "服务器不存在")
		return
	}
	expires, _, err := shared.ParseCertificate(in.PEM, in.Key)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if err := shared.CheckCertificateServerAuth(in.PEM, in.Key); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if !shared.CertificateCovers(in.PEM, in.Domain) {
		errorJSON(w, 400, "证书域名不匹配")
		return
	}
	in.ID = ID()
	in.ExpiresAt = expires
	in.DaysUntilExpiry, in.ExpiringSoon = shared.CertExpiryStatus(expires)
	if err = a.Store.PutCertificate(in); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	in.Key = ""
	a.Store.Audit("certificate.create", in.ID, in.Domain)
	writeJSON(w, 201, in)
}
func (a *App) certificateByID(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c, err := a.Store.Certificate(id)
	if err != nil {
		errorJSON(w, 404, "证书不存在")
		return
	}
	nodes, _ := a.Store.Nodes(c.ServerID)
	for _, n := range nodes {
		if n.CertificateID == id {
			errorJSON(w, 409, "证书仍被节点使用")
			return
		}
	}
	_, err = a.Store.DB.Exec(`DELETE FROM mui_certificates WHERE id=$1`, id)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.Store.Audit("certificate.delete", id, c.Domain)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// CheckExpiringCertificates logs and audits certificates expiring within 30
// days. It runs on the pruning schedule, so one entry appears per check
// cycle per certificate, not per request.
func (a *App) CheckExpiringCertificates() {
	list, err := a.Store.Certificates("")
	if err != nil {
		log.Printf("certificate expiry check: %v", err)
		return
	}
	for _, c := range list {
		days, soon := shared.CertExpiryStatus(c.ExpiresAt)
		if !soon {
			continue
		}
		msg := fmt.Sprintf("证书 %s（服务器 %s）%d 天后过期", c.Domain, c.ServerID, days)
		log.Printf("certificate expiring: %s", msg)
		a.Store.Audit("certificate.expiring", c.ID, msg)
	}
}

func (a *App) firewall(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		list, err := a.Store.Rules(r.URL.Query().Get("serverId"))
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		paginateList(w, r, list, func(rule shared.FirewallRule) string { return rule.ID })
		return
	}
	var in shared.FirewallRule
	if !readJSON(w, r, &in) {
		return
	}
	server, err := a.Store.Server(in.ServerID)
	if err != nil {
		errorJSON(w, 404, "服务器不存在")
		return
	}
	if strings.TrimSpace(in.Source) != "" {
		_, source, err := shared.NormalizeFirewallAccess("restricted", in.Source)
		if err != nil || strings.Contains(source, ",") {
			errorJSON(w, 400, "单条规则的来源必须是一个 IP 或 CIDR")
			return
		}
		in.Source = source
	}
	if err := validateRule(in); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if in.Action == "deny" && in.Network == "tcp" {
		if err := sshPortError(server, in.PortFrom, in.PortTo); err != nil {
			errorJSON(w, 400, "拒绝规则不能覆盖 SSH 端口："+err.Error())
			return
		}
	}
	in.ID = ID()
	in.Owner = "custom"
	in.Status = "pending"
	in.Deleting = false
	_, err = a.Store.DB.Exec(`INSERT INTO mui_firewall_rules(id,server_id,data) VALUES($1,$2,$3)`, in.ID, in.ServerID, Marshal(in))
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if err = a.queueApply(in.ServerID, "firewall.apply"); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.Store.Audit("firewall.create", in.ID, in.Comment)
	writeJSON(w, 201, in)
}
func validateRule(r shared.FirewallRule) error {
	if r.PortFrom < 1 || r.PortFrom > 65535 || r.PortTo < r.PortFrom || r.PortTo > 65535 {
		return errors.New("端口范围无效")
	}
	if r.Network != "tcp" && r.Network != "udp" {
		return errors.New("协议只能是 tcp 或 udp")
	}
	if r.Action != "allow" && r.Action != "deny" {
		return errors.New("动作只能是 allow 或 deny")
	}
	if r.Source != "" {
		if _, _, err := net.ParseCIDR(r.Source); err != nil {
			return errors.New("来源必须是 CIDR")
		}
	}
	return nil
}
func (a *App) firewallByID(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rules, _ := a.Store.Rules("")
	var target *shared.FirewallRule
	for i := range rules {
		if rules[i].ID == id {
			target = &rules[i]
			break
		}
	}
	if target == nil {
		errorJSON(w, 404, "规则不存在")
		return
	}
	target.Deleting = true
	_, err := a.Store.DB.Exec(`UPDATE mui_firewall_rules SET data=$1 WHERE id=$2`, Marshal(target), id)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if err = a.queueApply(target.ServerID, "firewall.apply"); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.Store.Audit("firewall.delete", id, target.Comment)
	writeJSON(w, 202, map[string]bool{"queued": true})
}
func (a *App) ufwInit(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	server, err := a.Store.Server(id)
	if err != nil {
		errorJSON(w, 404, "服务器不存在")
		return
	}
	if server.UFWStatus == "active" && serverStatus(server) == "online" {
		errorJSON(w, 409, "该服务器的 UFW 已启用，无需初始化")
		return
	}
	if err := a.queueApply(id, "ufw.init"); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.Store.Audit("ufw.init", id, "")
	writeJSON(w, 202, map[string]bool{"queued": true})
}

func (a *App) subscriptions(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		list, err := a.Store.Subscriptions()
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		rows, err := a.Store.DB.Query(`SELECT subscription_id,SUM(uplink),SUM(downlink) FROM mui_user_totals GROUP BY subscription_id`)
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		totals := map[string][2]int64{}
		for rows.Next() {
			var id string
			var up, down int64
			if err = rows.Scan(&id, &up, &down); err != nil {
				break
			}
			totals[id] = [2]int64{up, down}
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		linkRows, err := a.Store.DB.Query(`SELECT id FROM mui_subscriptions WHERE token_enc<>''`)
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		hasLink := map[string]bool{}
		for linkRows.Next() {
			var id string
			if linkRows.Scan(&id) == nil {
				hasLink[id] = true
			}
		}
		linkRows.Close()
		for i := range list {
			list[i].Uplink, list[i].Downlink = totals[list[i].ID][0], totals[list[i].ID][1]
			list[i].LinkAvailable = hasLink[list[i].ID]
			if list[i].Enabled && (list[i].ExpiresAt == nil || time.Now().Before(*list[i].ExpiresAt)) {
				if _, _, pending, err := a.subscriptionItems(list[i]); err == nil {
					list[i].PendingNodeIDs = pending
				}
			}
		}
		paginateList(w, r, list, func(s shared.Subscription) string { return s.ID })
		return
	}
	var raw struct {
		shared.Subscription
		// Enabled is a pointer so creation can tell "omitted" (default true)
		// from an explicit false.
		Enabled *bool `json:"enabled"`
	}
	if !readJSON(w, r, &raw) {
		return
	}
	in := raw.Subscription
	if in.Name == "" || (in.Format != "sing-box" && in.Format != "surge") {
		errorJSON(w, 400, "名称或格式无效")
		return
	}
	if !a.validCustomer(in.CustomerID) {
		errorJSON(w, 400, "客户不存在")
		return
	}
	for _, id := range in.NodeIDs {
		n, err := a.Store.Node(id)
		if err != nil {
			errorJSON(w, 400, "节点不存在: "+id)
			return
		}
		if err := validateSubscriptionNode(in.Format, n); err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
	}
	in.ID = ID()
	in.Enabled = true
	if raw.Enabled != nil {
		in.Enabled = *raw.Enabled
	}
	token := Token()
	sealed, err := a.Store.Encrypt(token)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	in.Uplink, in.Downlink, in.URL, in.PendingNodeIDs, in.LinkAvailable = 0, 0, "", nil, false
	_, err = a.Store.DB.Exec(`INSERT INTO mui_subscriptions(id,data,token_hash,token_enc) VALUES($1,$2,$3,$4)`, in.ID, Marshal(in), Hash(token), sealed)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if err = a.queueSubscriptionApply(in.NodeIDs); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	in.URL = a.PublicURL + "/s/" + token
	a.Store.Audit("subscription.create", in.ID, in.Name)
	writeJSON(w, 201, in)
}

func (a *App) subscriptionTrafficSeries(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	list, err := a.Store.Subscriptions()
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	found := false
	for _, sub := range list {
		if sub.ID == id {
			found = true
			break
		}
	}
	if !found {
		errorJSON(w, 404, "订阅不存在")
		return
	}
	hours, _ := strconv.Atoi(r.URL.Query().Get("hours"))
	if hours < 1 || hours > 31*24 {
		hours = 24
	}
	const hour = int64(3600000)
	last := time.Now().UnixMilli() / hour
	first := last - int64(hours) + 1
	rows, err := a.Store.DB.Query(`SELECT at_ms/3600000 AS bucket,SUM(uplink),SUM(downlink) FROM mui_user_traffic WHERE subscription_id=$1 AND at_ms>=$2 GROUP BY at_ms/3600000`, id, first*hour)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	defer rows.Close()
	sums := map[int64][2]int64{}
	for rows.Next() {
		var bucket, up, down int64
		if err = rows.Scan(&bucket, &up, &down); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		sums[bucket] = [2]int64{up, down}
	}
	if err = rows.Err(); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	out := make([]map[string]any, 0, hours)
	for bucket := first; bucket <= last; bucket++ {
		out = append(out, map[string]any{"at": time.UnixMilli(bucket * hour), "uplink": sums[bucket][0], "downlink": sums[bucket][1]})
	}
	writeJSON(w, 200, out)
}
func (a *App) subscriptionByID(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	list, _ := a.Store.Subscriptions()
	var old *shared.Subscription
	for i := range list {
		if list[i].ID == id {
			old = &list[i]
			break
		}
	}
	if old == nil {
		errorJSON(w, 404, "订阅不存在")
		return
	}
	if r.Method == "DELETE" {
		_, err := a.Store.DB.Exec(`DELETE FROM mui_subscriptions WHERE id=$1`, id)
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		_, _ = a.Store.DB.Exec(`DELETE FROM mui_subscription_expiry_applied WHERE subscription_id=$1`, id)
		if err = a.queueSubscriptionApply(old.NodeIDs); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		a.Store.Audit("subscription.delete", id, old.Name)
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}
	var in shared.Subscription
	if !readJSON(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.Name) == "" || (in.Format != "sing-box" && in.Format != "surge") {
		errorJSON(w, 400, "名称或格式无效")
		return
	}
	if !a.validCustomer(in.CustomerID) {
		errorJSON(w, 400, "客户不存在")
		return
	}
	for _, nodeID := range in.NodeIDs {
		n, err := a.Store.Node(nodeID)
		if err != nil {
			errorJSON(w, 400, "节点不存在: "+nodeID)
			return
		}
		if err := validateSubscriptionNode(in.Format, n); err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
	}
	previousNodeIDs := append([]string(nil), old.NodeIDs...)
	old.Name = in.Name
	old.CustomerID = in.CustomerID
	old.Format = in.Format
	old.NodeIDs = in.NodeIDs
	old.Enabled = in.Enabled
	old.ExpiresAt = in.ExpiresAt
	_, err := a.Store.DB.Exec(`UPDATE mui_subscriptions SET data=$1 WHERE id=$2`, Marshal(old), id)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	_, _ = a.Store.DB.Exec(`DELETE FROM mui_subscription_expiry_applied WHERE subscription_id=$1`, id)
	if err = a.queueSubscriptionApply(append(previousNodeIDs, old.NodeIDs...)); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.Store.Audit("subscription.update", id, old.Name)
	writeJSON(w, 200, old)
}

func validateSubscriptionNode(format string, n shared.Node) error {
	if n.Protocol == "ss" && !shared.SSMultiUser(n.Method) {
		return errors.New("订阅多用户统计要求 SS 节点使用 2022 加密方式")
	}
	if format == "surge" {
		switch {
		case n.Protocol == "ss" && n.Method == "2022-blake3-chacha20-poly1305":
			return errors.New("Surge 订阅不支持 2022-blake3-chacha20-poly1305")
		case n.Protocol == "snell" && n.ShadowTLSHost == "":
			return errors.New("Surge 订阅中的 Snell 节点需启用 ShadowTLS")
		case n.Protocol == "anytls":
			return errors.New("Surge 订阅暂不支持 AnyTLS 节点")
		}
	}
	return nil
}

func (a *App) queueSubscriptionApply(nodeIDs []string) error {
	servers := map[string]bool{}
	for _, id := range nodeIDs {
		n, err := a.Store.Node(id)
		if err == nil {
			servers[n.ServerID] = true
		}
	}
	for id := range servers {
		server, err := a.Store.Server(id)
		if err != nil {
			return err
		}
		if !server.MultiUserStats {
			continue
		} // The upgraded Agent queues the first apply when it reports support.
		if err := a.queueApply(id, "subscriptions.apply"); err != nil {
			return err
		}
	}
	return nil
}

// A subscription expiry must remove its credentials even if no administrator
// is using the panel. Agents poll this path, so one of them schedules the apply.
func (a *App) syncExpiredSubscriptions() error {
	subs, err := a.Store.Subscriptions()
	if err != nil {
		return err
	}
	now := time.Now()
	for _, sub := range subs {
		if !sub.Enabled || sub.ExpiresAt == nil || now.Before(*sub.ExpiresAt) {
			continue
		}
		at := sub.ExpiresAt.UnixMilli()
		var done int64
		err = a.Store.DB.QueryRow(`SELECT expires_at FROM mui_subscription_expiry_applied WHERE subscription_id=$1`, sub.ID).Scan(&done)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if done == at {
			continue
		}
		if err = a.queueSubscriptionApply(sub.NodeIDs); err != nil {
			return err
		}
		if _, err = a.Store.DB.Exec(`INSERT INTO mui_subscription_expiry_applied(subscription_id,expires_at) VALUES($1,$2) ON CONFLICT(subscription_id) DO UPDATE SET expires_at=excluded.expires_at`, sub.ID, at); err != nil {
			return err
		}
	}
	return nil
}
func (a *App) rotateSubscription(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	token := Token()
	sealed, err := a.Store.Encrypt(token)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	result, err := a.Store.DB.Exec(`UPDATE mui_subscriptions SET token_hash=$1,token_enc=$2 WHERE id=$3`, Hash(token), sealed, id)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		errorJSON(w, 404, "订阅不存在")
		return
	}
	a.Store.Audit("subscription.rotate", id, "")
	writeJSON(w, 200, map[string]string{"url": a.PublicURL + "/s/" + token})
}

// subscriptionLink shows an existing link again. Links created before tokens
// were kept (encrypted) cannot be recovered and have to be rotated once.
func (a *App) subscriptionLink(w http.ResponseWriter, r *http.Request) {
	var sealed string
	err := a.Store.DB.QueryRow(`SELECT token_enc FROM mui_subscriptions WHERE id=$1`, r.PathValue("id")).Scan(&sealed)
	if errors.Is(err, sql.ErrNoRows) {
		errorJSON(w, 404, "订阅不存在")
		return
	}
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if sealed == "" {
		errorJSON(w, 409, "该订阅创建于旧版本，链接未保存；轮换一次后即可随时查看")
		return
	}
	token, err := a.Store.Decrypt(sealed)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]string{"url": a.PublicURL + "/s/" + token})
}

func (a *App) subscriptionDownload(w http.ResponseWriter, r *http.Request) {
	if a.rateCount(r, "subscription", 1) > 120 {
		errorJSON(w, 429, "请求过于频繁")
		return
	}
	sub, err := a.Store.SubscriptionByToken(r.PathValue("token"))
	if err != nil || !sub.Enabled || (sub.ExpiresAt != nil && time.Now().After(*sub.ExpiresAt)) {
		errorJSON(w, 404, "订阅无效")
		return
	}
	items, skipped, pending, err := a.subscriptionItems(sub)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	// Some nodes waiting is fine: the rest are served. All of them waiting is
	// usually a few seconds after a change, and an empty answer would make the
	// client drop nodes that are about to work.
	if len(items) == 0 && len(pending) > 0 {
		w.Header().Set("Retry-After", "30")
		errorJSON(w, 503, "订阅中的节点配置正在生效，请稍后重试")
		return
	}
	// Every node skipped for a permanent reason (disabled, incompatible)
	// must not become a silent empty configuration: the client would drop
	// nodes without knowing why.
	if len(items) == 0 && len(pending) == 0 {
		errorJSON(w, 503, "订阅中没有可用节点："+strings.Join(skipped, "; "))
		return
	}
	body, _, err := shared.RenderSubscription(sub.Format, items)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if _, err := a.Store.DB.Exec(`INSERT INTO mui_subscription_access(id,subscription_id,customer_id,ip,at_ms) VALUES($1,$2,$3,$4,$5)`, ID(), sub.ID, sub.CustomerID, a.clientIP(r), time.Now().UnixMilli()); err != nil {
		errorJSON(w, 500, "无法记录订阅访问")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if sub.Format == "sing-box" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	_, _ = w.Write(body)
}

func (a *App) previewSubscription(w http.ResponseWriter, r *http.Request) {
	list, err := a.Store.Subscriptions()
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	var selected *shared.Subscription
	for i := range list {
		if list[i].ID == r.PathValue("id") {
			selected = &list[i]
			break
		}
	}
	if selected == nil {
		errorJSON(w, 404, "订阅不存在")
		return
	}
	items, skipped, _, err := a.subscriptionItems(*selected)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	body, excluded, err := shared.RenderSubscription(selected.Format, items)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	excluded = append(skipped, excluded...)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"content": string(body), "excluded": excluded})
}

func (a *App) operations(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	if err := a.Store.ExpireUpgrades(); err != nil {
		a.mu.Unlock()
		errorJSON(w, 500, err.Error())
		return
	}
	a.mu.Unlock()
	// IDs start with their creation time, so "before an ID" means "older than".
	query, args := newLogQuery(`SELECT data FROM mui_operations`)
	query.equal("server_id", r.URL.Query().Get("serverId"))
	query.before("id", r.URL.Query().Get("before"))
	rows, err := a.Store.DB.Query(query.sql("id DESC", pageLimit(r), 0), *args...)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := []shared.Operation{}
	for rows.Next() {
		var raw string
		_ = rows.Scan(&raw)
		var op shared.Operation
		_ = json.Unmarshal([]byte(raw), &op)
		op.Deployed = nil
		out = append(out, op)
	}
	writeJSON(w, 200, out)
}
func (a *App) retryOperation(w http.ResponseWriter, r *http.Request) {
	op, err := a.Store.Operation(r.PathValue("id"))
	if err != nil {
		errorJSON(w, 404, "操作不存在")
		return
	}
	if op.Status != "failed" {
		errorJSON(w, 409, "仅失败操作可重试")
		return
	}
	if op.Kind == "agent.upgrade" {
		_, err = a.queueAgentUpgrade(op.ServerID)
	} else if op.Kind == "core.upgrade" {
		_, err = a.queueCoreUpgrade(op.ServerID)
	} else {
		err = a.queueApply(op.ServerID, op.Kind)
	}
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.Store.Audit("operation.retry", op.ID, op.Kind)
	writeJSON(w, 202, map[string]bool{"queued": true})
}
func (a *App) traffic(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("nodeId")
	if id == "" {
		errorJSON(w, 400, "nodeId required")
		return
	}
	rows, err := a.Store.DB.Query(`SELECT at_ms,uplink,downlink FROM mui_traffic WHERE node_id=$1 ORDER BY at_ms DESC LIMIT 1000`, id)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var at, up, down int64
		if rows.Scan(&at, &up, &down) == nil {
			out = append(out, map[string]any{"at": time.UnixMilli(at), "uplink": up, "downlink": down})
		}
	}
	writeJSON(w, 200, out)
}

// trafficSeries returns traffic per hour for the last `hours` hours (24 by
// default, at most 31 days), oldest first, with empty hours filled in: one
// node's when nodeId is given, otherwise all nodes together.
func (a *App) trafficSeries(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("nodeId")
	hours, _ := strconv.Atoi(r.URL.Query().Get("hours"))
	if hours < 1 || hours > 31*24 {
		hours = 24
	}
	const hour = int64(3600000)
	last := time.Now().UnixMilli() / hour
	first := last - int64(hours) + 1
	query, args := newLogQuery(`SELECT at_ms/3600000 AS bucket,SUM(uplink),SUM(downlink) FROM mui_traffic`)
	query.equal("node_id", id)
	query.where("at_ms>=" + query.arg(first*hour))
	rows, err := a.Store.DB.Query(query.filtered()+" GROUP BY at_ms/3600000", *args...)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	defer rows.Close()
	sums := map[int64][2]int64{}
	for rows.Next() {
		var bucket, up, down int64
		if rows.Scan(&bucket, &up, &down) == nil {
			sums[bucket] = [2]int64{up, down}
		}
	}
	out := make([]map[string]any, 0, hours)
	for bucket := first; bucket <= last; bucket++ {
		out = append(out, map[string]any{"at": time.UnixMilli(bucket * hour), "uplink": sums[bucket][0], "downlink": sums[bucket][1]})
	}
	writeJSON(w, 200, out)
}

// trafficRanking sums traffic since ?since= (Unix milliseconds, the browser's
// local midnight; by default the server's) per node and per subscription.
func (a *App) trafficRanking(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	since := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).UnixMilli()
	if n, err := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64); err == nil && n >= now.AddDate(0, 0, -31).UnixMilli() && n <= now.UnixMilli() {
		since = n
	}
	type usage struct {
		ID       string `json:"id"`
		Uplink   int64  `json:"uplink"`
		Downlink int64  `json:"downlink"`
	}
	sum := func(table, column string) ([]usage, error) {
		rows, err := a.Store.DB.Query(`SELECT `+column+`,SUM(uplink),SUM(downlink) FROM `+table+` WHERE at_ms>=$1 GROUP BY `+column, since)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := []usage{}
		for rows.Next() {
			var item usage
			if err = rows.Scan(&item.ID, &item.Uplink, &item.Downlink); err != nil {
				return nil, err
			}
			out = append(out, item)
		}
		return out, rows.Err()
	}
	nodes, err := sum("mui_traffic", "node_id")
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	subscriptions, err := sum("mui_user_traffic", "subscription_id")
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"nodes": nodes, "subscriptions": subscriptions})
}
func (a *App) serverTraffic(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := a.Store.Server(id); err != nil {
		errorJSON(w, 404, "服务器不存在")
		return
	}
	rows, err := a.Store.DB.Query(`SELECT at_ms,interface,rx,tx FROM mui_server_traffic WHERE server_id=$1 ORDER BY at_ms DESC LIMIT 1000`, id)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var at, rx, tx int64
		var iface string
		if rows.Scan(&at, &iface, &rx, &tx) == nil {
			out = append(out, map[string]any{"at": time.UnixMilli(at), "interface": iface, "rx": rx, "tx": tx})
		}
	}
	writeJSON(w, 200, out)
}
func (a *App) trafficSummary(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	month := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	parse := func(key string, fallback time.Time) int64 {
		v := r.URL.Query().Get(key)
		if v == "" {
			return fallback.UnixMilli()
		}
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < now.AddDate(-2, 0, 0).UnixMilli() || n > now.UnixMilli() {
			return fallback.UnixMilli()
		}
		return n
	}
	sum := func(start int64) (map[string]int64, error) {
		var up, down sql.NullInt64
		err := a.Store.DB.QueryRow(`SELECT SUM(uplink),SUM(downlink) FROM mui_traffic WHERE at_ms>=$1`, start).Scan(&up, &down)
		return map[string]int64{"uplink": up.Int64, "downlink": down.Int64}, err
	}
	d, err := sum(parse("dayStart", today))
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	m, err := sum(parse("monthStart", month))
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"today": d, "month": m})
}
func (a *App) audit(w http.ResponseWriter, r *http.Request) {
	query, args := newLogQuery(`SELECT id,at_ms,action,target,detail FROM mui_audit`)
	query.before("id", r.URL.Query().Get("before"))
	if q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q"))); q != "" {
		query.where("LOWER(action || ' ' || detail) LIKE " + query.arg("%"+likeEscape(q)+"%") + ` ESCAPE '\'`)
	}
	rows, err := a.Store.DB.Query(query.sql("id DESC", pageLimit(r), 0), *args...)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var at int64
		var id, action, target, detail string
		if rows.Scan(&id, &at, &action, &target, &detail) == nil {
			out = append(out, map[string]any{"id": id, "at": time.UnixMilli(at), "action": action, "target": target, "detail": detail})
		}
	}
	writeJSON(w, 200, out)
}

func (a *App) desired(serverID string) (shared.DesiredState, error) {
	server, err := a.Store.Server(serverID)
	if err != nil {
		return shared.DesiredState{}, err
	}
	nodes, err := a.Store.Nodes(serverID)
	if err != nil {
		return shared.DesiredState{}, err
	}
	state := shared.DesiredState{Revision: server.Revision, ProtocolVersion: 1, Nodes: []shared.ManagedNode{}, Rules: []shared.FirewallRule{}, Forwards: []shared.ForwardRule{}}
	subscriptions, err := a.Store.Subscriptions()
	if err != nil {
		return state, err
	}
	for _, n := range nodes {
		if n.Deleting {
			continue
		}
		password, err := a.Store.NodeSecret(n.ID)
		if err != nil {
			return state, err
		}
		shadowPassword, err := a.Store.NodeShadowTLSSecret(n.ID)
		if err != nil {
			return state, err
		}
		item := shared.ManagedNode{Node: n, Password: password, ShadowTLSPassword: shadowPassword}
		if n.Protocol == "ss" && shared.SSMultiUser(n.Method) {
			item.Users = append(item.Users, a.Store.SubscriptionUser(n, "direct"))
		}
		for _, sub := range subscriptions {
			if !sub.Enabled || sub.ExpiresAt != nil && time.Now().After(*sub.ExpiresAt) || n.Protocol == "ss" && !shared.SSMultiUser(n.Method) {
				continue
			}
			for _, id := range sub.NodeIDs {
				if id == n.ID {
					item.Users = append(item.Users, a.Store.SubscriptionUser(n, sub.ID))
					break
				}
			}
		}
		if n.CertificateID != "" {
			c, e := a.Store.Certificate(n.CertificateID)
			if e != nil {
				return state, e
			}
			key, e := a.Store.CertificateKey(c.ID)
			if e != nil {
				return state, e
			}
			item.CertificatePEM = c.PEM
			item.CertificateKey = key
		}
		state.Nodes = append(state.Nodes, item)
	}
	rules, err := a.Store.Rules(serverID)
	if err != nil {
		return state, err
	}
	for _, rule := range rules {
		if !rule.Deleting {
			state.Rules = append(state.Rules, rule)
		}
	}
	forwards, err := a.Store.Forwards(serverID)
	if err != nil {
		return state, err
	}
	for _, forward := range forwards {
		if !forward.Deleting {
			state.Forwards = append(state.Forwards, forward)
		}
	}
	// Every queued configuration carries the panel's signature so the agent
	// can verify it came from the panel. Signing failure fails the queueing.
	return a.signDesiredState(state)
}

func (a *App) subscriptionItem(sub shared.Subscription, n shared.Node, server shared.Server) (shared.SubscriptionItem, error) {
	password, err := a.Store.NodeSecret(n.ID)
	if err != nil {
		return shared.SubscriptionItem{}, err
	}
	shadowPassword, err := a.Store.NodeShadowTLSSecret(n.ID)
	if err != nil {
		return shared.SubscriptionItem{}, err
	}
	item := shared.SubscriptionItem{Node: n, Server: server, Password: password, ShadowTLSPassword: shadowPassword}
	if n.Protocol == "ss" && !shared.SSMultiUser(n.Method) {
		return item, errors.New("订阅不支持非 2022 的 SS 节点")
	}
	user := a.Store.SubscriptionUser(n, sub.ID)
	switch n.Protocol {
	case "ss":
		item.Password = password + ":" + user.Password
	case "snell":
		// See SingBoxConfig: behind ShadowTLS the per-subscription secret is the
		// ShadowTLS password. An agent that predates this still expects a Snell
		// user key as well.
		if n.ShadowTLSHost != "" {
			item.ShadowTLSPassword = user.ShadowTLSPassword
		}
		if n.ShadowTLSHost == "" || !server.ShadowTLSAuth {
			item.UserKey = user.Password
		}
	case "anytls":
		item.Password = user.Password
	}
	return item, nil
}

// queueApply snapshots the desired state of a server into a job for its agent.
// Only configuration jobs advance the revision: it identifies a configuration,
// and "ufw.init" does not change one. It takes the server's lock;
// queueApplyLocked is the same logic for callers that already hold it
// (agentReport), since Go mutexes are not reentrant. agentJob never holds
// the server lock: ClaimJob is atomic via compare-and-swap.
func (a *App) queueApply(serverID, kind string) error {
	unlock := a.lockServer(serverID)
	defer unlock()
	return a.queueApplyLocked(serverID, kind)
}

func (a *App) queueApplyLocked(serverID, kind string) error {
	server, err := a.Store.Server(serverID)
	if err != nil {
		return err
	}
	apply := strings.HasSuffix(kind, ".apply")
	if kind == "forwards.apply" && !server.ForwardSupport {
		// This agent cannot act on forwards, and nothing else changed. The rule
		// stays pending; the first report from a capable agent queues a full
		// apply. Everything else on the server keeps flowing as usual.
		return nil
	}
	if apply {
		if err := a.Store.SupersedeQueuedApply(serverID); err != nil {
			return err
		}
		server.Revision++
		if err = a.Store.PutServer(server); err != nil {
			return err
		}
	}
	state, err := a.desired(serverID)
	if err != nil {
		return err
	}
	now := time.Now()
	op := shared.Operation{ID: ID(), ServerID: serverID, Kind: kind, Status: "queued", Revision: server.Revision, CreatedAt: now, UpdatedAt: now}
	if apply {
		op.Deployed = a.deployment(server, state)
	}
	return a.Store.PutOperation(op, state)
}

// nodeFingerprint covers everything a client configuration depends on. Two
// equal fingerprints mean a client built from the panel's current data can
// connect to what the server is running.
func (a *App) nodeFingerprint(server shared.Server, n shared.Node, password, shadowPassword string) string {
	scheme := "users"
	if n.Protocol == "snell" && n.ShadowTLSHost != "" && server.ShadowTLSAuth {
		scheme = "shadowtls"
	}
	return a.Store.Fingerprint(n.Protocol, strconv.Itoa(n.Port), n.Method, n.Obfs, n.ShadowTLSHost, n.TLSName, password, shadowPassword, scheme)
}

func (a *App) deployment(server shared.Server, state shared.DesiredState) map[string]shared.NodeDeployment {
	out := map[string]shared.NodeDeployment{}
	for _, item := range state.Nodes {
		if !item.Node.Enabled {
			continue
		}
		subs := make([]string, 0, len(item.Users))
		for _, user := range item.Users {
			subs = append(subs, user.SubscriptionID)
		}
		out[item.Node.ID] = shared.NodeDeployment{Fingerprint: a.nodeFingerprint(server, item.Node, item.Password, item.ShadowTLSPassword), Subscriptions: subs}
	}
	return out
}

// nodeLive reports whether a node, as the panel currently describes it, is what
// its server is running, with a login for the given subscription ("" for none).
// It looks at this node only: an unapplied change elsewhere on the server, or a
// server that is offline, does not make a working node unavailable.
func (a *App) nodeLive(n shared.Node, server shared.Server, subscriptionID string) (bool, error) {
	if !n.Enabled || n.Deleting {
		return false, nil
	}
	if subscriptionID != "" && !server.MultiUserStats {
		return false, nil
	}
	applied, known, err := a.Store.AppliedDeployment(server.ID)
	if err != nil {
		return false, err
	}
	if !known {
		// No apply has completed since deployments were first recorded; fall
		// back to the server-wide revision check used before.
		return n.Status == "active" && server.MultiUserStats && server.AppliedRevision >= server.Revision, nil
	}
	deployed, ok := applied[n.ID]
	if !ok {
		return false, nil
	}
	password, err := a.Store.NodeSecret(n.ID)
	if err != nil {
		return false, err
	}
	shadowPassword, err := a.Store.NodeShadowTLSSecret(n.ID)
	if err != nil {
		return false, err
	}
	if deployed.Fingerprint != a.nodeFingerprint(server, n, password, shadowPassword) {
		return false, nil
	}
	if subscriptionID == "" {
		return true, nil
	}
	for _, id := range deployed.Subscriptions {
		if id == subscriptionID {
			return true, nil
		}
	}
	return false, nil
}

// subscriptionItems resolves a subscription to the nodes that can be handed
// out right now. Nodes that cannot are named in skipped, with the reason, and
// pending lists those that are merely waiting for their server to apply.
func (a *App) subscriptionItems(sub shared.Subscription) (items []shared.SubscriptionItem, skipped []string, pending []string, err error) {
	items, skipped, pending = []shared.SubscriptionItem{}, []string{}, []string{}
	for _, id := range sub.NodeIDs {
		n, e := a.Store.Node(id)
		if e != nil {
			continue
		}
		server, e := a.Store.Server(n.ServerID)
		if e != nil {
			continue
		}
		if !n.Enabled || n.Deleting {
			skipped = append(skipped, n.Name+": 节点已停用或正在删除")
			continue
		}
		if e := validateSubscriptionNode(sub.Format, n); e != nil {
			skipped = append(skipped, n.Name+": "+e.Error())
			continue
		}
		live, e := a.nodeLive(n, server, sub.ID)
		if e != nil {
			return nil, nil, nil, e
		}
		if !live {
			skipped = append(skipped, n.Name+": 配置尚未在服务器 "+server.Name+" 上生效")
			pending = append(pending, n.ID)
			continue
		}
		item, e := a.subscriptionItem(sub, n, server)
		if e != nil {
			skipped = append(skipped, n.Name+": "+e.Error())
			continue
		}
		// Liveness was just established from what the server runs; the stored
		// status only says whether the latest edit has been confirmed.
		item.Node.Status = "active"
		items = append(items, item)
	}
	return items, skipped, pending, nil
}

func (a *App) agentEnroll(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ServerID string `json:"serverId"`
		Token    string `json:"token"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	var expected string
	var expires int64
	err := a.Store.DB.QueryRow(`SELECT enroll_hash,enroll_expires FROM mui_servers WHERE id=$1`, in.ServerID).Scan(&expected, &expires)
	if err != nil || expected == "" || expires < time.Now().Unix() || !hmac.Equal([]byte(expected), []byte(Hash(in.Token))) {
		errorJSON(w, 401, "接入令牌无效或已过期")
		return
	}
	token := Token()
	result, err := a.Store.DB.Exec(`UPDATE mui_servers SET agent_hash=$1,agent_signs=0,enroll_hash='',enroll_expires=0 WHERE id=$2 AND enroll_hash=$3 AND enroll_expires>=$4`, Hash(token), in.ServerID, expected, time.Now().Unix())
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
	a.Store.Audit("agent.enroll", in.ServerID, "")
	writeJSON(w, 200, map[string]string{"agentToken": token, "panelPublicKey": base64.StdEncoding.EncodeToString(publicKey)})
}
func (a *App) agentJob(w http.ResponseWriter, r *http.Request) {
	id := r.Header.Get("X-Server-ID")
	server, err := a.Store.Server(id)
	if err != nil {
		errorJSON(w, 404, "服务器不存在")
		return
	}
	if err = a.syncExpiredSubscriptions(); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	// An agent that cannot apply firewall policies must not receive *.apply
	// jobs, but upgrade and init jobs behind them still flow: ClaimJob skips
	// the apply jobs instead of this handler failing the whole poll.
	allowApply := server.NodeFirewallPolicies
	if !allowApply {
		allowApply = true
		nodes, err := a.Store.Nodes(id)
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		for _, node := range nodes {
			if !node.Deleting && node.FirewallPolicy != "" && node.FirewallPolicy != "all" {
				allowApply = false
				break
			}
		}
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
	server.Status = "online"
	becameMultiUser := !server.MultiUserStats && in.MultiUserStats
	becameForward := !server.ForwardSupport && in.ForwardSupport
	// Agent-supplied text ends up in the server document and on the admin's
	// screen; keep each piece to a sane size.
	in.OS, in.Arch, in.AgentVersion, in.AgentBuild = clip(in.OS, 120), clip(in.Arch, 32), clip(in.AgentVersion, 64), clip(in.AgentBuild, 64)
	in.CoreVersion, in.CoreBuild, in.FirewallConflict, in.JobError = clip(in.CoreVersion, 120), clip(in.CoreBuild, 64), clip(in.FirewallConflict, 64), clip(in.JobError, 2000)
	in.UFWStatus, in.StatsStatus, in.IPv4, in.IPv6 = clip(in.UFWStatus, 32), clip(in.StatsStatus, 32), clip(in.IPv4, 64), clip(in.IPv6, 64)
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
		server.AgentVersion = in.AgentVersion
		server.NodeFirewallPolicies = in.NodeFirewallPolicies
		server.MultiUserStats = in.MultiUserStats
		server.ForwardSupport = in.ForwardSupport
		server.ShadowTLSAuth = in.ShadowTLSAuth
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
	// Detected addresses are kept next to the ones the administrator entered and
	// only fill them in when nothing was entered; they never overwrite them.
	server.DetectedIPv4, server.DetectedIPv6 = in.IPv4, in.IPv6
	if in.IPv4 != "" && server.IPv4 == "" {
		server.IPv4 = in.IPv4
	}
	if in.IPv6 != "" && server.IPv6 == "" {
		server.IPv6 = in.IPv6
	}
	if in.AgentTime != nil {
		server.ClockSkewSeconds = int64(in.AgentTime.Sub(now).Seconds())
	}
	if in.HostReported {
		server.SSHPorts, server.FirewallConflict, server.UFWRules = in.SSHPorts, in.FirewallConflict, in.UFWRules
		if len(server.UFWRules) > 300 {
			server.UFWRules = server.UFWRules[:300]
		}
	}
	if err = a.Store.PutServer(server); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if len(in.Traffic) > 0 {
		if err = a.Store.SaveTraffic(id, in.Traffic); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
	}
	if len(in.UserTraffic) > 0 {
		if err = a.Store.SaveUserTraffic(id, in.UserTraffic); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
	}
	if len(in.ForwardTraffic) > 0 {
		if err = a.Store.SaveForwardTraffic(id, in.ForwardTraffic); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
	}
	if len(in.ServerTraffic) > 0 {
		if err = a.Store.SaveServerTraffic(id, in.ServerTraffic); err != nil {
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
		if op.Kind == "core.upgrade" && in.JobStatus == "success" && server.Purpose == "relay" {
			server.Purpose = "node"
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
	if becameMultiUser || schemeChanged {
		nodes, e := a.Store.Nodes(id)
		if e != nil {
			errorJSON(w, 500, e.Error())
			return
		}
		if len(nodes) > 0 {
			if err = a.queueApplyLocked(id, "subscriptions.apply"); err != nil {
				errorJSON(w, 500, err.Error())
				return
			}
		}
	}
	if becameForward {
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
		}
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
