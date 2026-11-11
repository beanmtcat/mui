//go:build linux

package agent

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"

	"mui/internal/shared"
)

// verifyDesiredSignature checks a panel signature over the desired state. The
// signature covers the state with the Signature field cleared, so the panel
// signs exactly what the helper verifies. The signature itself is base64,
// the same encoding the release manifest signatures use. Unsigned states
// are accepted only on hosts with no pinned panel key (installed before
// key pinning existed), and a signature without a pinned key is accepted
// with a warning so the gap is visible instead of silent.
func verifyDesiredSignature(state shared.DesiredState, raw []byte) error {
	panelKey, err := panelPublicKey()
	if err != nil {
		return err
	}
	return verifyDesiredSignatureWith(panelKey, state, raw)
}

func verifyDesiredSignatureWith(panelKey ed25519.PublicKey, state shared.DesiredState, raw []byte) error {
	if state.Signature == "" {
		// Once a panel key is pinned, an unsigned state is a stripped or forged
		// one: the panel signs every state it sends. Refuse it, or anything
		// that can reach the helper socket could rewrite the firewall as root.
		if panelKey != nil {
			return errors.New("desired state is not signed, but a panel public key is pinned; refusing it")
		}
		return nil
	}
	if panelKey == nil {
		fmt.Fprintln(os.Stderr, "warning: desired state carries a signature, but no panel public key is pinned; accepting without verification")
		return nil
	}
	// The bytes as received are what the panel signed. Re-encoding with
	// this agent's own types would drop fields it does not know yet.
	if len(raw) > 0 {
		return shared.VerifyDesiredStateRaw(panelKey, raw)
	}
	return shared.VerifyDesiredState(panelKey, state)
}

func panelPublicKey() (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(PanelPublicKeyPath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return shared.ParseReleaseKey(string(raw))
}

// pinnedReleaseKey returns the release key fixed at install time, if any.
func pinnedReleaseKey() (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(ReleaseKeyPath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return shared.ParseReleaseKey(string(raw))
}
