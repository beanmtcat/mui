package agent

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"mui/internal/shared"
)

type Config struct {
	URL        string              `json:"url"`
	ServerID   string              `json:"serverId"`
	Token      string              `json:"token"`
	AgentProxy *shared.SOCKS5Proxy `json:"agentProxy,omitempty"`
}

// ReadConfig distinguishes a malformed file from a file that parses but is
// missing fields, so a corrupt config is not misreported as merely empty.
func ReadConfig() (Config, error) {
	b, err := os.ReadFile(ConfigDir + "/config.json")
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return Config{}, fmt.Errorf("parse agent config: %w", err)
	}
	var missing []string
	if c.URL == "" {
		missing = append(missing, "url")
	}
	if c.ServerID == "" {
		missing = append(missing, "serverId")
	}
	if c.Token == "" {
		missing = append(missing, "token")
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("agent config incomplete: missing %s", strings.Join(missing, ", "))
	}
	if err := shared.ValidateAgentProxy(c.AgentProxy); err != nil {
		return Config{}, err
	}
	return c, nil
}

// serverStatusError carries the HTTP status of a failed panel call so callers
// can tell "not implemented" (404/501) apart from a transient failure.
type serverStatusError struct {
	Status int
	Body   string
}

func (e *serverStatusError) Error() string {
	return fmt.Sprintf("server %d: %s", e.Status, e.Body)
}

// signHeaders builds the per-request authentication headers for one /agent/*
// call. The signature covers method, path, timestamp, nonce and the SHA-256 of
// the body, keyed by SHA-256(keyMaterial), so a captured request cannot be
// replayed against another path or body.
func signHeaders(method, rawURL string, body []byte, keyMaterial string) (map[string]string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("sign request URL: %w", err)
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	var nonceBytes [16]byte
	if _, err := rand.Read(nonceBytes[:]); err != nil {
		return nil, fmt.Errorf("sign request nonce: %w", err)
	}
	nonce := hex.EncodeToString(nonceBytes[:])
	bodyHash := sha256.Sum256(body)
	key := sha256.Sum256([]byte(keyMaterial))
	mac := hmac.New(sha256.New, key[:])
	fmt.Fprintf(mac, "%s\n%s\n%s\n%s\n%s", method, path, timestamp, nonce, hex.EncodeToString(bodyHash[:]))
	return map[string]string{
		"X-Agent-Timestamp": timestamp,
		"X-Agent-Nonce":     nonce,
		"X-Agent-Signature": hex.EncodeToString(mac.Sum(nil)),
	}, nil
}

// Enroll exchanges an enrollment token for an agent token. It uses its own
// client with a 30s timeout rather than http.DefaultClient, and signs the
// request with the enrollment token as key material. The panel may also
// return its public key, which the installer pins for upgrade verification.
func Enroll(url, serverID, token string, proxies ...*shared.SOCKS5Proxy) (agentToken, panelPublicKey string, err error) {
	var out struct {
		AgentToken     string `json:"agentToken"`
		PanelPublicKey string `json:"panelPublicKey"`
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var p *shared.SOCKS5Proxy
	if len(proxies) > 0 {
		p = proxies[0]
	}
	client, err := panelHTTPClient(p, 30*time.Second)
	if err != nil {
		return "", "", err
	}
	if err := sendJSON(ctx, client, "POST", strings.TrimRight(url, "/")+"/agent/enroll", map[string]string{"serverId": serverID, "token": token}, nil, &out, token); err != nil {
		return "", "", err
	}
	if out.AgentToken == "" {
		return "", "", errors.New("enroll: panel returned an empty agent token")
	}
	return out.AgentToken, out.PanelPublicKey, nil
}

// sendJSON performs one panel call. When signKey is non-empty the request is
// signed with signHeaders using signKey as key material; pass "" only for
// calls that carry no /agent/* authentication.
func sendJSON(ctx context.Context, client *http.Client, method, rawURL string, in any, headers map[string]string, out any, signKey string) error {
	var body []byte
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = raw
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if signKey != "" {
		signed, err := signHeaders(method, rawURL, body, signKey)
		if err != nil {
			return err
		}
		for k, v := range signed {
			req.Header.Set(k, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 204 {
		return nil
	}
	if resp.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &serverStatusError{Status: resp.StatusCode, Body: string(message)}
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out)
	}
	return nil
}

// osRelease is computed once: the distribution does not change under a
// running agent.
var osReleaseCached = sync.OnceValue(func() string {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return runtime.GOOS
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
		}
	}
	return runtime.GOOS
})

func osRelease() string { return osReleaseCached() }

// checkPanelURL is the strict panel URL check shared in spirit with
// validatePanelURL in upgrade_linux.go: no userinfo, query or fragment; only
// https, or http on loopback.
func checkPanelURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.User != nil {
		return nil, errors.New("panel URL must not contain userinfo")
	}
	if u.RawQuery != "" || u.ForceQuery {
		return nil, errors.New("panel URL must not contain a query")
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return nil, errors.New("panel URL must not contain a fragment")
	}
	if u.Scheme == "https" {
		// ok
	} else if u.Scheme == "http" && u.Hostname() == "127.0.0.1" {
		// ok
	} else {
		return nil, errors.New("agent requires HTTPS panel URL")
	}
	if u.Host == "" {
		return nil, errors.New("panel URL must contain a host")
	}
	return u, nil
}

// CheckConfigURL validates the saved URL without contacting the panel.
func CheckConfigURL(raw string) error {
	_, err := checkPanelURL(raw)
	return err
}
