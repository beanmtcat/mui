package server

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"mui/internal/shared"
)

type githubReleaseInfo struct {
	AgentHash string
	CoreHash  string
}

type githubReleaseCacheEntry struct {
	Info      githubReleaseInfo
	Err       error
	ExpiresAt time.Time // zero means a successful result for this immutable version
}

const githubReleaseRequestTimeout = 20 * time.Second
const githubReleaseErrorTTL = 5 * time.Minute

func (a *App) githubReleaseLimits() (time.Duration, time.Duration) {
	timeout, ttl := a.releaseTimeout, a.releaseFailureTTL
	if timeout <= 0 {
		timeout = githubReleaseRequestTimeout
	}
	if ttl <= 0 {
		ttl = githubReleaseErrorTTL
	}
	return timeout, ttl
}

func (a *App) cachedGitHubRelease(key string) (githubReleaseInfo, error, bool) {
	a.releaseMu.Lock()
	defer a.releaseMu.Unlock()
	entry, ok := a.releaseCache[key]
	if !ok || entry.Err != nil && !time.Now().Before(entry.ExpiresAt) {
		return githubReleaseInfo{}, nil, false
	}
	return entry.Info, entry.Err, true
}

func (a *App) prefetchGitHubReleases() {
	for _, arch := range []string{"amd64", "arm64"} {
		go func(arch string) {
			if _, err := a.githubRelease(context.Background(), arch); err != nil {
				// The error is cached; opening the page will show it without waiting.
				// Startup itself does not depend on GitHub being reachable.
				return
			}
		}(arch)
	}
}

// The panel reads a GitHub archive to learn the hashes used for upgrade
// decisions. It never serves the archive or extracted binaries to Agents.
func (a *App) githubRelease(ctx context.Context, arch string) (githubReleaseInfo, error) {
	url, err := shared.GitHubReleaseArchive(a.releaseVersion, arch)
	if err != nil {
		return githubReleaseInfo{}, err
	}
	key := a.releaseVersion + "/" + arch
	if info, err, ok := a.cachedGitHubRelease(key); ok {
		return info, err
	}
	timeout, failureTTL := a.githubReleaseLimits()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	result := a.releaseFlights.DoChan(key, func() (any, error) {
		// A caller may have filled the cache between the first check and joining
		// this flight. Network work and archive verification never hold releaseMu.
		if info, err, ok := a.cachedGitHubRelease(key); ok {
			return info, err
		}
		fetchCtx, stop := context.WithTimeout(context.Background(), timeout)
		defer stop()
		info, err := a.fetchGitHubRelease(fetchCtx, url, arch)
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			err = errors.New("暂时无法读取 GitHub Release")
		}
		entry := githubReleaseCacheEntry{Info: info, Err: err}
		if err != nil {
			entry.ExpiresAt = time.Now().Add(failureTTL)
		}
		a.releaseMu.Lock()
		if a.releaseCache == nil {
			a.releaseCache = make(map[string]githubReleaseCacheEntry)
		}
		a.releaseCache[key] = entry
		a.releaseMu.Unlock()
		return info, err
	})
	select {
	case got := <-result:
		if got.Err != nil {
			return githubReleaseInfo{}, got.Err
		}
		return got.Val.(githubReleaseInfo), nil
	case <-ctx.Done():
		return githubReleaseInfo{}, errors.New("暂时无法读取 GitHub Release")
	}
}

func (a *App) fetchGitHubRelease(ctx context.Context, url, arch string) (githubReleaseInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return githubReleaseInfo{}, err
	}
	client := a.releaseClient
	if client == nil {
		client = &http.Client{Timeout: githubReleaseRequestTimeout, CheckRedirect: githubReleaseRedirect}
	}
	resp, err := client.Do(req)
	if err != nil {
		return githubReleaseInfo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return githubReleaseInfo{}, fmt.Errorf("GitHub Agent release %s: HTTP %d", arch, resp.StatusCode)
	}
	info, manifest, signature, err := readGitHubReleaseArchive(io.LimitReader(resp.Body, 512<<20), arch)
	if err != nil {
		return githubReleaseInfo{}, err
	}
	if a.releaseKey != nil {
		if err := shared.VerifyManifest(a.releaseKey, manifest, signature); err != nil {
			return githubReleaseInfo{}, fmt.Errorf("GitHub Agent release signature: %w", err)
		}
	}
	if want, ok := shared.ManifestHash(manifest, "mui-agent"); !ok || want != info.AgentHash {
		return githubReleaseInfo{}, errors.New("GitHub Agent release binary does not match SHA256SUMS")
	}
	if want, ok := shared.ManifestHash(manifest, "sing-box"); !ok || want != info.CoreHash {
		return githubReleaseInfo{}, errors.New("GitHub sing-box release binary does not match SHA256SUMS")
	}
	return info, nil
}

func githubReleaseRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > 5 || req.URL.Scheme != "https" || req.URL.User != nil {
		return errors.New("unsafe GitHub release redirect")
	}
	host := strings.ToLower(req.URL.Hostname())
	if host != "github.com" && host != "release-assets.githubusercontent.com" && host != "objects.githubusercontent.com" {
		return errors.New("unexpected GitHub release redirect host")
	}
	return nil
}

func readGitHubReleaseArchive(source io.Reader, arch string) (githubReleaseInfo, []byte, []byte, error) {
	zr, err := gzip.NewReader(source)
	if err != nil {
		return githubReleaseInfo{}, nil, nil, err
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	var info githubReleaseInfo
	var manifest, signature []byte
	seen := map[string]bool{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return info, nil, nil, err
		}
		if hdr.Name == arch || hdr.Name == arch+"/" {
			if hdr.Typeflag != tar.TypeDir {
				return info, nil, nil, errors.New("invalid GitHub release directory")
			}
			continue
		}
		name := strings.TrimPrefix(hdr.Name, arch+"/")
		if !strings.HasPrefix(hdr.Name, arch+"/") || seen[name] || hdr.Typeflag != tar.TypeReg {
			return info, nil, nil, errors.New("unexpected GitHub release archive member")
		}
		seen[name] = true
		switch name {
		case "mui-agent", "sing-box":
			max := int64(128 << 20)
			if name == "sing-box" {
				max = 256 << 20
			}
			if hdr.Size <= 0 || hdr.Size > max {
				return info, nil, nil, errors.New("GitHub release binary size is invalid")
			}
			h := sha256.New()
			if _, err = io.Copy(h, tr); err != nil {
				return info, nil, nil, err
			}
			if name == "mui-agent" {
				info.AgentHash = hex.EncodeToString(h.Sum(nil))
			} else {
				info.CoreHash = hex.EncodeToString(h.Sum(nil))
			}
		case "SHA256SUMS", "SHA256SUMS.sig":
			if hdr.Size <= 0 || hdr.Size > 8192 {
				return info, nil, nil, errors.New("GitHub release manifest size is invalid")
			}
			value, err := io.ReadAll(tr)
			if err != nil {
				return info, nil, nil, err
			}
			if name == "SHA256SUMS" {
				manifest = value
			} else {
				signature = value
			}
		default:
			return info, nil, nil, fmt.Errorf("unexpected GitHub release file %q", name)
		}
	}
	if info.AgentHash == "" || info.CoreHash == "" || len(manifest) == 0 {
		return info, nil, nil, errors.New("GitHub release archive is incomplete")
	}
	return info, manifest, signature, nil
}
