package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func signedTestManifest(t *testing.T) (ed25519.PublicKey, string, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := fmt.Sprintf("%064x  mui-agent\n%064x  sing-box\n", 1, 2)
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(private, []byte(manifest))) + "\n"
	return public, manifest, signature
}

func testReleaseResponse(body string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}

func TestGitHubReleaseTimeoutSingleflightAndFailureCache(t *testing.T) {
	public, _, _ := signedTestManifest(t)
	var downloads atomic.Int32
	app := &App{
		releaseVersion:      "0.6.21",
		releaseKey:          public,
		releaseTimeout:      100 * time.Millisecond,
		releaseFetchTimeout: 40 * time.Millisecond,
		releaseFailureTTL:   time.Minute,
		releaseClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			downloads.Add(1)
			<-req.Context().Done()
			return nil, req.Context().Err()
		})},
	}
	const callers = 12
	start := make(chan struct{})
	var group sync.WaitGroup
	for i := 0; i < callers; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			_, err := app.githubRelease(context.Background(), "amd64")
			if err == nil || !strings.Contains(err.Error(), "暂时无法读取 GitHub Release") {
				t.Errorf("timeout error: %v", err)
			}
		}()
	}
	close(start)
	group.Wait()
	if got := downloads.Load(); got != 1 {
		t.Fatalf("concurrent requests downloaded %d times", got)
	}
	if _, err := app.githubRelease(context.Background(), "amd64"); err == nil || downloads.Load() != 1 {
		t.Fatalf("failure cache missed: %v, downloads=%d", err, downloads.Load())
	}
}

func TestGitHubReleaseSlowFetchOutlivesPageAndCachesSignedHashes(t *testing.T) {
	public, manifest, signature := signedTestManifest(t)
	started := make(chan struct{})
	continueFetch := make(chan struct{})
	var downloads atomic.Int32
	app := &App{
		releaseVersion:      "0.6.21",
		releaseKey:          public,
		releaseTimeout:      20 * time.Millisecond, // scaled-down 20-second page limit
		releaseFetchTimeout: time.Second,           // independent background limit
		releaseClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			downloads.Add(1)
			if strings.HasSuffix(req.URL.Path, ".SHA256SUMS") {
				close(started)
				select {
				case <-continueFetch:
				case <-req.Context().Done():
					return nil, req.Context().Err()
				}
				return testReleaseResponse(manifest), nil
			}
			if strings.HasSuffix(req.URL.Path, ".SHA256SUMS.sig") {
				return testReleaseResponse(signature), nil
			}
			t.Errorf("panel downloaded an unexpected asset: %s", req.URL)
			return nil, fmt.Errorf("unexpected release asset")
		})},
	}
	result := make(chan error, 1)
	go func() {
		_, err := app.githubRelease(context.Background(), "amd64")
		result <- err
	}()
	<-started
	if err := <-result; err == nil || !strings.Contains(err.Error(), "暂时无法读取 GitHub Release") {
		t.Fatalf("page should time out first: %v", err)
	}
	close(continueFetch)
	deadline := time.Now().Add(time.Second)
	for {
		if _, _, ok := app.cachedGitHubRelease("0.6.21/amd64"); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("background fetch did not fill the cache")
		}
		time.Sleep(time.Millisecond)
	}
	before := time.Now()
	info, err := app.githubRelease(context.Background(), "amd64")
	if err != nil || info.AgentHash != fmt.Sprintf("%064x", 1) || info.CoreHash != fmt.Sprintf("%064x", 2) {
		t.Fatalf("cached signed hashes: %+v %v", info, err)
	}
	if elapsed := time.Since(before); elapsed >= app.releaseTimeout {
		t.Fatalf("cached lookup took %s", elapsed)
	}
	if got := downloads.Load(); got != 2 {
		t.Fatalf("panel made %d requests; expected only manifest and signature", got)
	}
}

func TestGitHubReleaseRejectsInvalidSignature(t *testing.T) {
	public, manifest, _ := signedTestManifest(t)
	app := &App{
		releaseVersion: "0.6.21",
		releaseKey:     public,
		releaseClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if strings.HasSuffix(req.URL.Path, ".SHA256SUMS") {
				return testReleaseResponse(manifest), nil
			}
			return testReleaseResponse("bad signature"), nil
		})},
	}
	if _, err := app.githubRelease(context.Background(), "arm64"); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("invalid signature accepted: %v", err)
	}
}
