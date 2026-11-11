package server

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"mui/internal/shared"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sync/singleflight"
)

type App struct {
	Store               *Store
	PublicURL           string
	publicURLs          []*url.URL
	agentBinDir         string
	releaseVersion      string
	releaseMu           sync.Mutex
	releaseCache        map[string]githubReleaseCacheEntry
	releaseFlights      singleflight.Group
	releaseClient       *http.Client
	releaseTimeout      time.Duration
	releaseFetchTimeout time.Duration
	releaseFailureTTL   time.Duration
	// mu serialises mutating admin requests. Agent traffic uses per-server
	// locks instead (see lockServer), so one slow agent report no longer
	// blocks every admin write and every other agent.
	mu        sync.Mutex
	rateMu    sync.Mutex
	rates     map[string]rateBucket
	ratePurge time.Time
	// logins bounds concurrent password checks: bcrypt is deliberately slow,
	// and a flood of attempts must not take every CPU.
	logins chan struct{}
	// serverLocks serialises server edits, agent reports and queueApply for one
	// server. Admin writes also keep the global mu.
	serverLocksMu sync.Mutex
	serverLocks   map[string]*sync.Mutex
	// nonces remembers agent request nonces for replay detection, per
	// server, so one compromised Agent cannot fill the table for the others.
	nonceMu    sync.Mutex
	nonces     map[string]map[string]time.Time
	noncePurge time.Time
	trusted    []*net.IPNet
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

func NewApp(s *Store, publicURL string) (*App, error) {
	publicURLs, err := parsePublicURLs(publicURL)
	if err != nil {
		return nil, err
	}
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
	app := &App{Store: s, PublicURL: publicURLs[0].String(), publicURLs: publicURLs, agentBinDir: binDir, rates: map[string]rateBucket{}, logins: make(chan struct{}, 4), downloads: make(chan struct{}, 4), serverLocks: map[string]*sync.Mutex{}, nonces: map[string]map[string]time.Time{}, downloadsByIP: map[string]int{}}
	if version := strings.TrimSpace(os.Getenv("MUI_AGENT_RELEASE_VERSION")); version != "" {
		if _, err := shared.GitHubReleaseArchive(version, "amd64"); err != nil {
			return nil, fmt.Errorf("MUI_AGENT_RELEASE_VERSION: %w", err)
		}
		if !supportsGitHubRelease(version) {
			return nil, errors.New("MUI_AGENT_RELEASE_VERSION requires Agent 0.6.19 or newer")
		}
		app.releaseVersion = version
	}
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
	if app.releaseVersion != "" && app.releaseKey == nil {
		return nil, errors.New("MUI_AGENT_RELEASE_VERSION requires MUI_RELEASE_PUBLIC_KEY so GitHub downloads are verified")
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
	// Reconcile stored forwards on startup as well as after edits. A release
	// may change how route targets are selected even when no server is edited.
	// A failure here must not keep the panel from starting; the next edit or
	// agent report retries the sync.
	if err := app.syncRoutes(); err != nil {
		log.Printf("reconcile routes: %v", err)
	}
	if app.releaseVersion != "" {
		app.prefetchGitHubReleases()
	}
	return app, nil
}

func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /download/install.sh", a.downloadInstallScript)
	mux.HandleFunc("GET /download/uninstall.sh", a.downloadUninstallScript)
	mux.HandleFunc("GET /download/{arch}/{file}", a.downloadAgentFile)
	mux.HandleFunc("POST /api/login", a.login)
	mux.HandleFunc("POST /api/logout", a.require(a.logout))
	mux.HandleFunc("GET /api/me", a.require(a.me))
	mux.HandleFunc("POST /api/totp/setup", a.require(a.totpSetup))
	mux.HandleFunc("POST /api/totp/enable", a.require(a.totpEnable))
	mux.HandleFunc("POST /api/totp/disable", a.require(a.totpDisable))
	mux.HandleFunc("POST /api/password", a.require(a.changePassword))
	mux.HandleFunc("GET /api/settings/komari", a.require(a.komariSetting))
	mux.HandleFunc("PUT /api/settings/komari", a.require(a.komariSetting))
	mux.HandleFunc("GET /api/settings/surge-profile", a.require(a.surgeProfileSetting))
	mux.HandleFunc("PUT /api/settings/surge-profile", a.require(a.surgeProfileSetting))
	mux.HandleFunc("GET /api/surge-templates", a.require(a.surgeTemplates))
	mux.HandleFunc("POST /api/surge-templates", a.require(a.surgeTemplates))
	mux.HandleFunc("PATCH /api/surge-templates/{id}", a.require(a.surgeTemplateByID))
	mux.HandleFunc("DELETE /api/surge-templates/{id}", a.require(a.surgeTemplateByID))
	mux.HandleFunc("GET /api/help", a.require(a.helpArticles))
	mux.HandleFunc("POST /api/help", a.require(a.helpArticles))
	mux.HandleFunc("PATCH /api/help/{id}", a.require(a.helpArticleByID))
	mux.HandleFunc("DELETE /api/help/{id}", a.require(a.helpArticleByID))
	mux.HandleFunc("GET /api/servers", a.require(a.servers))
	mux.HandleFunc("POST /api/servers", a.require(a.servers))
	mux.HandleFunc("PATCH /api/servers/{id}", a.require(a.serverByID))
	mux.HandleFunc("DELETE /api/servers/{id}", a.require(a.serverByID))
	mux.HandleFunc("POST /api/servers/{id}/offline/export", a.require(a.offlineExport))
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
	mux.HandleFunc("PATCH /api/certificates/{id}", a.require(a.certificateByID))
	mux.HandleFunc("DELETE /api/certificates/{id}", a.require(a.certificateByID))
	mux.HandleFunc("GET /api/firewall", a.require(a.firewall))
	mux.HandleFunc("POST /api/firewall", a.require(a.firewall))
	mux.HandleFunc("PATCH /api/firewall/{id}", a.require(a.firewallByID))
	mux.HandleFunc("DELETE /api/firewall/{id}", a.require(a.firewallByID))
	mux.HandleFunc("POST /api/servers/{id}/ufw/delete", a.require(a.hostRuleDelete))
	mux.HandleFunc("POST /api/servers/{id}/ufw/adopt", a.require(a.hostRuleAdopt))
	mux.HandleFunc("GET /api/forwards", a.require(a.forwards))
	mux.HandleFunc("POST /api/forwards", a.require(a.forwards))
	mux.HandleFunc("PATCH /api/forwards/{id}", a.require(a.forwardByID))
	mux.HandleFunc("DELETE /api/forwards/{id}", a.require(a.forwardByID))
	mux.HandleFunc("GET /api/routes", a.require(a.routes))
	mux.HandleFunc("POST /api/routes", a.require(a.routes))
	mux.HandleFunc("PATCH /api/routes/{id}", a.require(a.routeByID))
	mux.HandleFunc("DELETE /api/routes/{id}", a.require(a.routeByID))
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
	mux.HandleFunc("GET /agent/komari", a.agentAuth(a.agentKomari))
	mux.HandleFunc("GET /agent/observed-ipv4", a.agentAuth(a.agentObservedIPv4))
	mux.HandleFunc("GET /agent/job", a.agentAuth(a.agentJob))
	mux.HandleFunc("POST /agent/report", a.agentAuth(a.agentReport))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	return a.SecurityHeaders(mux)
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
				if !a.originAllowed(r, origin) {
					errorJSON(w, 403, "origin mismatch")
					return
				}
			}
			if strings.HasPrefix(r.URL.Path, "/api/") {
				// The panel's own page sends this custom header, which a form
				// on another site cannot set. Sec-Fetch-Site also catches a
				// sibling subdomain, which counts as same-site and therefore
				// still receives the SameSite=Strict session cookie.
				if r.Header.Get("X-Requested-With") != "XMLHttpRequest" {
					errorJSON(w, 403, "missing X-Requested-With header")
					return
				}
				if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
					errorJSON(w, 403, "cross-site request refused")
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}
