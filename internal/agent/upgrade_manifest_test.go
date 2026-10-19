package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

type manifestTransport func(*http.Request) (*http.Response, error)

func (f manifestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestUpgradeManifestSignaturePolicy(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte("agent build")))
	manifest := []byte(digest + "  mui-agent\n")
	wrongManifest := []byte(strings.Repeat("0", 64) + "  mui-agent\n")
	for _, tc := range []struct {
		name          string
		key           ed25519.PublicKey
		manifest      []byte
		signatureCode int
		invalidSig    bool
		wantError     string
	}{
		{name: "unsigned release without signature", manifest: manifest, signatureCode: 404},
		{name: "unsigned hash mismatch", manifest: wrongManifest, signatureCode: 404, wantError: "expected hash"},
		{name: "signed release", key: public, manifest: manifest, signatureCode: 200},
		{name: "pinned key requires signature", key: public, manifest: manifest, signatureCode: 404, wantError: "HTTP 404"},
		{name: "pinned key rejects invalid signature", key: public, manifest: manifest, signatureCode: 200, invalidSig: true, wantError: "signature is invalid"},
		{name: "signed hash mismatch", key: public, manifest: wrongManifest, signatureCode: 200, wantError: "expected hash"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signatureRequests := 0
			client := &http.Client{Transport: manifestTransport(func(r *http.Request) (*http.Response, error) {
				code, body := http.StatusOK, tc.manifest
				switch r.URL.Path {
				case "/download/amd64/SHA256SUMS":
				case "/download/amd64/SHA256SUMS.sig":
					signatureRequests++
					code = tc.signatureCode
					body = []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private, tc.manifest)))
					if tc.invalidSig {
						body = []byte(base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)))
					}
				default:
					t.Fatalf("unexpected request: %s", r.URL.Path)
				}
				return &http.Response{StatusCode: code, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body))}, nil
			})}
			got, err := fetchUpgradeManifest(context.Background(), client, "https://panel.example/download/amd64/", tc.key, "mui-agent", digest)
			if tc.wantError == "" {
				if err != nil || !bytes.Equal(got, tc.manifest) {
					t.Fatalf("manifest = %q, error = %v", got, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("error = %v, want %q", err, tc.wantError)
			}
			wantRequests := 0
			if tc.key != nil {
				wantRequests = 1
			}
			if signatureRequests != wantRequests {
				t.Fatalf("signature requests = %d, want %d", signatureRequests, wantRequests)
			}
		})
	}
}
