//go:build linux

package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"mui/internal/shared"
)

func TestPinnedPanelKeyRefusesUnsignedState(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	state := shared.DesiredState{Revision: 1, ProtocolVersion: 1, FirewallMode: "manual"}
	if err := verifyDesiredSignatureWith(pub, state, nil); err == nil {
		t.Fatal("a stripped signature was accepted with a pinned panel key")
	}
	if err := verifyDesiredSignatureWith(nil, state, nil); err != nil {
		t.Fatal("a host without a pinned key must keep accepting unsigned states", err)
	}
	signed := state
	signed.Signature = shared.SignDesiredState(priv, state)
	if err := verifyDesiredSignatureWith(pub, signed, nil); err != nil {
		t.Fatal(err)
	}
	signed.FirewallMode = "ufw"
	if err := verifyDesiredSignatureWith(pub, signed, nil); err == nil {
		t.Fatal("a modified state passed verification")
	}
}
