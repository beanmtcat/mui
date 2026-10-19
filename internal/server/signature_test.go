package server

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"mui/internal/shared"
)

// The job an agent downloads verifies over the bytes it received, including
// nodes with and without a Snell inner port.
func TestServedJobVerifiesOverReceivedBytes(t *testing.T) {
	p := newTestMui(t)
	id, agent := p.enroll("signed")
	p.newAgent(agent)
	if code, out, _ := p.do("POST", "/api/nodes", map[string]any{"direct": true, "serverId": id, "name": "<s>&", "protocol": "ss", "port": 50001, "method": "2022-blake3-aes-128-gcm"}, nil); code != 201 {
		t.Fatalf("ss node: %d %v", code, out)
	}
	if code, out, _ := p.do("POST", "/api/nodes", map[string]any{"direct": true, "serverId": id, "name": "snell", "protocol": "snell", "port": 50002, "shadowTlsHost": "www.example.com"}, nil); code != 201 {
		t.Fatalf("snell node: %d %v", code, out)
	}
	req := httptest.NewRequest("GET", "/agent/job", nil)
	for k, v := range agent {
		req.Header.Set(k, v)
	}
	signAgentRequest(t, req, agent["Authorization"][len("Bearer "):], nil)
	rec := httptest.NewRecorder()
	p.handler.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("job: %d %s", rec.Code, rec.Body.String())
	}
	var job shared.Job
	if err := json.Unmarshal(rec.Body.Bytes(), &job); err != nil {
		t.Fatal(err)
	}
	private, err := p.store.PanelSigningPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	public := private.Public().(ed25519.PublicKey)
	if err := shared.VerifyDesiredStateRaw(public, job.StateRaw); err != nil {
		t.Fatalf("received bytes: %v", err)
	}
	if err := shared.VerifyDesiredState(public, job.State); err != nil {
		t.Fatalf("re-encoded by the same version: %v", err)
	}
}
