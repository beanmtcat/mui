package shared

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
)

// OfflineBundleVersion is the file format. Version 2 signs the JSON value
// itself (see canonicalJSON), so a file stays valid however it is formatted
// and however many fields an older agent does not know.
const OfflineBundleVersion = 2

// OfflineBundleMinAgent is the oldest agent that understands every field the
// panel writes into an offline file. Raise it whenever a new field changes
// what an agent must do; older agents then refuse the file instead of
// ignoring the field.
const OfflineBundleMinAgent = "0.6.7"

// OfflineBundle is a signed complete replacement of one server's forwards.
type OfflineBundle struct {
	Version         int           `json:"version"`
	MinAgentVersion string        `json:"minAgentVersion"`
	ExportID        string        `json:"exportId"`
	ServerID        string        `json:"serverId"`
	Revision        int64         `json:"revision"`
	PanelPublicKey  string        `json:"panelPublicKey"`
	Forwards        []ForwardRule `json:"forwards"`
	Signature       string        `json:"signature"`

	// raw is the document as received; empty for a bundle built here.
	raw []byte
}

// ParseOfflineBundle reads a file exported by the panel. Fields this program
// does not know are kept in the signed document and otherwise ignored; the
// file's minAgentVersion says whether ignoring them is safe.
func ParseOfflineBundle(raw []byte) (OfflineBundle, error) {
	var b OfflineBundle
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&b); err != nil {
		return b, fmt.Errorf("离线配置格式无效: %w", err)
	}
	if err := offlineJSONEnd(dec); err != nil {
		return b, err
	}
	b.raw = append([]byte(nil), raw...)
	return b, b.Verify()
}

// Raw is the document to store: the bytes as received, or this program's
// encoding of a bundle it built.
func (b OfflineBundle) Raw() []byte {
	if b.raw != nil {
		return b.raw
	}
	raw, _ := json.Marshal(b)
	return raw
}

// canonicalJSON re-encodes a JSON value with sorted keys, no insignificant
// whitespace and no HTML escaping, optionally without one top-level key. Two
// encodings of the same value, whether by Go or by a browser, agree.
func canonicalJSON(raw []byte, drop string) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	if err := offlineJSONEnd(dec); err != nil {
		return nil, err
	}
	if object, ok := value.(map[string]any); ok && drop != "" {
		delete(object, drop)
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), nil
}

// CanonicalForwards is the signed forwards value, for comparing two files
// including fields this program does not know.
func (b OfflineBundle) CanonicalForwards() ([]byte, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(b.Raw(), &doc); err != nil {
		return nil, err
	}
	return canonicalJSON(doc["forwards"], "")
}

func offlineJSONEnd(dec *json.Decoder) error {
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("离线配置末尾存在多余内容")
	}
	return nil
}

// signingBytes covers the whole document except the signature, as a JSON
// value: what the panel wrote, including fields this program does not know.
func (b OfflineBundle) signingBytes() ([]byte, error) {
	canonical, err := canonicalJSON(b.Raw(), "signature")
	if err != nil {
		return nil, err
	}
	return append([]byte("mui-offline-config-v2\n"), canonical...), nil
}

func (b *OfflineBundle) Sign(key ed25519.PrivateKey) {
	b.Version, b.MinAgentVersion = OfflineBundleVersion, OfflineBundleMinAgent
	b.PanelPublicKey = base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	b.Signature, b.raw = "", nil
	message, _ := b.signingBytes()
	b.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, message))
}

func (b OfflineBundle) Verify() error {
	key, err := base64.StdEncoding.DecodeString(b.PanelPublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return errors.New("离线配置的面板公钥无效")
	}
	message, err := b.signingBytes()
	if err != nil {
		return errors.New("离线配置格式无效")
	}
	sig, err := base64.StdEncoding.DecodeString(b.Signature)
	if err != nil || !ed25519.Verify(key, message, sig) {
		return errors.New("离线配置签名校验失败，请重新从面板导出")
	}
	if b.Version != OfflineBundleVersion || b.ExportID == "" || b.ServerID == "" || b.Revision < 1 || b.Forwards == nil {
		return errors.New("离线配置版本或身份无效")
	}
	for _, f := range b.Forwards {
		if f.ServerID != b.ServerID || f.FirewallPolicy != "manual" || f.FirewallSources != "" || f.Deleting {
			return errors.New("离线配置只能包含本机的手动防火墙转发规则")
		}
	}
	return nil
}

// Digest identifies the exact signed document, formatting aside.
func (b OfflineBundle) Digest() string {
	canonical, err := canonicalJSON(b.Raw(), "")
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

// CheckAgentVersion refuses a file this agent is too old to apply exactly.
func (b OfflineBundle) CheckAgentVersion(agent string) error {
	if !VersionAtLeast(agent, b.MinAgentVersion) {
		return fmt.Errorf("该离线配置需要 Agent %s 或更高版本（本机 %s），请先升级离线 Agent", b.MinAgentVersion, agent)
	}
	return nil
}

var versionPattern = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)

// VersionAtLeast compares the first X.Y.Z in each string; pre-release
// suffixes are ignored, so "0.6.7-dev" satisfies "0.6.7". An empty minimum
// is always met; an unreadable version never meets a minimum.
func VersionAtLeast(have, need string) bool {
	if need == "" {
		return true
	}
	h, n := versionPattern.FindStringSubmatch(have), versionPattern.FindStringSubmatch(need)
	if h == nil || n == nil {
		return false
	}
	for i := 1; i <= 3; i++ {
		a, _ := strconv.Atoi(h[i])
		b, _ := strconv.Atoi(n[i])
		if a != b {
			return a > b
		}
	}
	return true
}

func OfflineManaged(s Server) bool { return s.ManagementMode == "offline" }
