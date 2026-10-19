package shared

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// ParseReleaseKey decodes the base64 Ed25519 public key that release
// manifests are signed with.
func ParseReleaseKey(encoded string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("release public key must be a base64 Ed25519 key")
	}
	return ed25519.PublicKey(raw), nil
}

// VerifyManifest checks a SHA256SUMS file against its detached signature
// (base64, as written by cmd/release-sign).
func VerifyManifest(key ed25519.PublicKey, manifest, signature []byte) error {
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(signature)))
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(key, manifest, sig) {
		return errors.New("release manifest signature is invalid")
	}
	return nil
}

// CanonicalDesiredState is the exact byte sequence a panel signature covers:
// the DesiredState with its Signature field cleared, marshalled with the
// struct's field order. The agent verifies by clearing Signature the same way.
func CanonicalDesiredState(state DesiredState) []byte {
	state.Signature = ""
	b, _ := json.Marshal(state)
	return b
}

// SignDesiredState returns a base64 Ed25519 signature over
// CanonicalDesiredState. The panel signs every DesiredState it queues so the
// agent's helper can tell a panel-issued configuration from a forged one.
func SignDesiredState(private ed25519.PrivateKey, state DesiredState) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(private, CanonicalDesiredState(state)))
}

// VerifyDesiredState checks state.Signature against the panel public key.
func VerifyDesiredState(public ed25519.PublicKey, state DesiredState) error {
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(state.Signature))
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(public, CanonicalDesiredState(state), sig) {
		return errors.New("desired state signature is invalid")
	}
	return nil
}

// VerifyDesiredStateRaw checks the signature over the state exactly as the
// panel sent it: the received JSON with the signature value emptied, which is
// what CanonicalDesiredState produced on the panel. Unlike re-encoding with
// this program's own types, it does not depend on knowing every field, so a
// panel may add fields without breaking older agents.
func VerifyDesiredStateRaw(public ed25519.PublicKey, raw []byte) error {
	var head struct {
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(raw, &head); err != nil || head.Signature == "" {
		return errors.New("desired state signature is invalid")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(head.Signature))
	field := []byte(`"signature":"` + head.Signature + `"`)
	if err != nil || len(sig) != ed25519.SignatureSize || bytes.Count(raw, field) != 1 {
		return errors.New("desired state signature is invalid")
	}
	canonical := bytes.Replace(raw, field, []byte(`"signature":""`), 1)
	if !ed25519.Verify(public, canonical, sig) {
		return errors.New("desired state signature is invalid")
	}
	return nil
}

// ManifestHash returns the SHA-256 a SHA256SUMS file lists for a file name.
func ManifestHash(manifest []byte, name string) (string, bool) {
	for _, line := range strings.Split(string(manifest), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == name {
			return strings.ToLower(fields[0]), true
		}
	}
	return "", false
}
