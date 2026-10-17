package server

import (
	"io"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Hold PATCH at body decoding, after it has read the old server document.
type gatedServerBody struct {
	reader           io.Reader
	entered, release chan struct{}
	once             sync.Once
}

func (b *gatedServerBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return b.reader.Read(p)
}

func TestServerPatchPreservesConcurrentAgentReport(t *testing.T) {
	p := newTestMui(t)
	id, agent := p.enroll("concurrent")
	body := &gatedServerBody{
		reader:  strings.NewReader(`{"name":"edited","roles":["exit"],"country":"SG","ipv4":"203.0.113.10"}`),
		entered: make(chan struct{}), release: make(chan struct{}),
	}
	req := httptest.NewRequest("PATCH", "/api/servers/"+id, body)
	req.AddCookie(p.cookie)
	rec := httptest.NewRecorder()
	patchDone := make(chan struct{})
	go func() { defer close(patchDone); p.handler.ServeHTTP(rec, req) }()
	<-body.entered
	reportDone := make(chan struct{})
	var code int
	go func() {
		defer close(reportDone)
		code, _, _ = p.do("POST", "/agent/report", map[string]any{"agentVersion": "0.6.0", "agentBuild": "reported-build"}, agent)
	}()
	// Without the shared lock the report finishes here and PATCH overwrites it.
	select {
	case <-reportDone:
	case <-time.After(100 * time.Millisecond):
	}
	close(body.release)
	<-patchDone
	<-reportDone
	if rec.Code != 200 || code != 200 {
		t.Fatalf("PATCH=%d report=%d", rec.Code, code)
	}
	server, err := p.store.Server(id)
	if err != nil {
		t.Fatal(err)
	}
	if server.Name != "edited" || server.AgentBuild != "reported-build" || server.LastSeen == nil {
		t.Fatalf("concurrent write lost server data: %+v", server)
	}
}
