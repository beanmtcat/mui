package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func statusServe(h http.Handler, method, target string, headers map[string]string, remoteAddr string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func assertOnlyAllowedKeys(t *testing.T, path string, obj map[string]any, allowed ...string) {
	t.Helper()
	allowSet := make(map[string]bool, len(allowed))
	for _, k := range allowed {
		allowSet[k] = true
	}
	for k := range obj {
		if !allowSet[k] {
			t.Fatalf("%s exposed unexpected JSON field %q (value=%v)", path, k, obj[k])
		}
	}
}
