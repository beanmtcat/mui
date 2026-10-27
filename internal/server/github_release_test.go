package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestGitHubReleaseTimeoutSingleflightAndFailureCache(t *testing.T) {
	var downloads atomic.Int32
	app := &App{
		releaseVersion:    "0.6.21",
		releaseTimeout:    80 * time.Millisecond,
		releaseFailureTTL: time.Minute,
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
	deadline := time.Now().Add(time.Second)
	for {
		if _, _, ok := app.cachedGitHubRelease("0.6.21/amd64"); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed-out fetch was not cached")
		}
		time.Sleep(time.Millisecond)
	}
	if got := downloads.Load(); got != 1 {
		t.Fatalf("concurrent requests downloaded %d times", got)
	}
	if _, err := app.githubRelease(context.Background(), "amd64"); err == nil || downloads.Load() != 1 {
		t.Fatalf("failure cache missed: %v, downloads=%d", err, downloads.Load())
	}
}

func TestReadGitHubReleaseArchive(t *testing.T) {
	agent, core := []byte("agent build"), []byte("core build")
	manifest := []byte(fmt.Sprintf("%x  mui-agent\n%x  sing-box\n", sha256.Sum256(agent), sha256.Sum256(core)))
	archive := func(corrupt bool) []byte {
		var out bytes.Buffer
		gz := gzip.NewWriter(&out)
		tw := tar.NewWriter(gz)
		for _, item := range []struct {
			name string
			data []byte
		}{
			{"amd64/mui-agent", agent}, {"amd64/sing-box", core}, {"amd64/SHA256SUMS", manifest}, {"amd64/SHA256SUMS.sig", []byte("signature")},
		} {
			if corrupt && item.name == "amd64/sing-box" {
				item.data = []byte("modified core")
			}
			if err := tw.WriteHeader(&tar.Header{Name: item.name, Mode: 0644, Size: int64(len(item.data)), Typeflag: tar.TypeReg}); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write(item.data); err != nil {
				t.Fatal(err)
			}
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
		return out.Bytes()
	}
	for _, bad := range []bool{false, true} {
		info, sums, sig, err := readGitHubReleaseArchive(bytes.NewReader(archive(bad)), "amd64")
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(sums, manifest) || string(sig) != "signature" || info.AgentHash != fmt.Sprintf("%x", sha256.Sum256(agent)) {
			t.Fatalf("unexpected archive contents: %+v %q %q", info, sums, sig)
		}
		if (info.CoreHash == fmt.Sprintf("%x", sha256.Sum256(core))) == bad {
			t.Fatalf("core hash did not reflect archive contents: %+v", info)
		}
	}
}
