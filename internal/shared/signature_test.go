package shared

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func signedJob(t *testing.T) (ed25519.PublicKey, []byte) {
	t.Helper()
	private := ed25519.NewKeyFromSeed(make([]byte, 32))
	state := DesiredState{Revision: 3, ProtocolVersion: 1, Nodes: []ManagedNode{{Node: Node{ID: "n", Name: "<ss>&", Protocol: "ss", Port: 443, Enabled: true}, Password: "secret+/="}}}
	state.Signature = SignDesiredState(private, state)
	// The panel answers with json.Encoder, which escapes HTML like Marshal.
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(Job{ID: "j", Kind: "nodes.apply", State: state}); err != nil {
		t.Fatal(err)
	}
	return private.Public().(ed25519.PublicKey), body.Bytes()
}

func TestRawSignatureSurvivesUnknownFields(t *testing.T) {
	public, body := signedJob(t)
	var job Job
	if err := json.Unmarshal(body, &job); err != nil {
		t.Fatal(err)
	}
	if err := VerifyDesiredStateRaw(public, job.StateRaw); err != nil {
		t.Fatalf("as sent: %v", err)
	}
	// A newer panel signs fields this build does not know. Decoding drops
	// them, so re-encoding cannot verify; the raw bytes still do.
	private := ed25519.NewKeyFromSeed(make([]byte, 32))
	newer := []byte(`{"revision":3,"protocolVersion":1,"signature":"","futureField":{"x":[1,2]},"nodes":[]}`)
	sig := ed25519.Sign(private, newer)
	signed := bytes.Replace(newer, []byte(`"signature":""`), []byte(`"signature":"`+b64(sig)+`"`), 1)
	var decoded DesiredState
	_ = json.Unmarshal(signed, &decoded)
	if VerifyDesiredState(public, decoded) == nil {
		t.Fatal("re-encoding was expected to lose the unknown field")
	}
	if err := VerifyDesiredStateRaw(public, signed); err != nil {
		t.Fatalf("raw bytes with an unknown field: %v", err)
	}
	tampered := bytes.Replace(signed, []byte(`"revision":3`), []byte(`"revision":4`), 1)
	if VerifyDesiredStateRaw(public, tampered) == nil {
		t.Fatal("a changed state verified")
	}
}

// The agent saves a claimed job and runs it after a restart; the saved copy
// must keep the bytes the panel signed.
func TestSavedJobKeepsSignedBytes(t *testing.T) {
	public, body := signedJob(t)
	var job Job
	if err := json.Unmarshal(body, &job); err != nil {
		t.Fatal(err)
	}
	saved, err := json.Marshal(job)
	if err != nil {
		t.Fatal(err)
	}
	var restored Job
	if err := json.Unmarshal(saved, &restored); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored.StateRaw, job.StateRaw) || restored.State.Revision != 3 || restored.State.Nodes[0].Password != "secret+/=" {
		t.Fatalf("restored job: %+v", restored)
	}
	if err := VerifyDesiredStateRaw(public, restored.StateRaw); err != nil {
		t.Fatalf("restored job: %v", err)
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
