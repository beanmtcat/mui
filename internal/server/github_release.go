package server

import (
	"context"
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
const githubReleaseFetchTimeout = 5 * time.Minute
const githubReleaseErrorTTL = 5 * time.Minute

func (a *App) githubReleaseLimits() (time.Duration, time.Duration, time.Duration) {
	requestTimeout, fetchTimeout, ttl := a.releaseTimeout, a.releaseFetchTimeout, a.releaseFailureTTL
	if requestTimeout <= 0 {
		requestTimeout = githubReleaseRequestTimeout
	}
	if fetchTimeout <= 0 {
		fetchTimeout = githubReleaseFetchTimeout
	}
	if ttl <= 0 {
		ttl = githubReleaseErrorTTL
	}
	return requestTimeout, fetchTimeout, ttl
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

// The panel reads only a signed manifest to learn the hashes used for upgrade
// decisions. The archive is downloaded by Agents, not by the panel.
func (a *App) githubRelease(ctx context.Context, arch string) (githubReleaseInfo, error) {
	url, err := shared.GitHubReleaseManifest(a.releaseVersion, arch, false)
	if err != nil {
		return githubReleaseInfo{}, err
	}
	signatureURL, err := shared.GitHubReleaseManifest(a.releaseVersion, arch, true)
	if err != nil {
		return githubReleaseInfo{}, err
	}
	key := a.releaseVersion + "/" + arch
	if info, err, ok := a.cachedGitHubRelease(key); ok {
		return info, err
	}
	requestTimeout, fetchTimeout, failureTTL := a.githubReleaseLimits()
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	result := a.releaseFlights.DoChan(key, func() (any, error) {
		// A caller may have filled the cache between the first check and joining
		// this flight. Network work and signature verification never hold releaseMu.
		if info, err, ok := a.cachedGitHubRelease(key); ok {
			return info, err
		}
		// The shared fetch outlives a page request but has its own firm limit.
		fetchCtx, stop := context.WithTimeout(context.Background(), fetchTimeout)
		defer stop()
		info, err := a.fetchGitHubRelease(fetchCtx, url, signatureURL)
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

func (a *App) fetchGitHubRelease(ctx context.Context, manifestURL, signatureURL string) (githubReleaseInfo, error) {
	if a.releaseKey == nil {
		return githubReleaseInfo{}, errors.New("GitHub Release requires a release public key")
	}
	manifest, err := a.getGitHubReleaseFile(ctx, manifestURL, 8192)
	if err != nil {
		return githubReleaseInfo{}, err
	}
	signature, err := a.getGitHubReleaseFile(ctx, signatureURL, 8192)
	if err != nil {
		return githubReleaseInfo{}, err
	}
	if err := shared.VerifyManifest(a.releaseKey, manifest, signature); err != nil {
		return githubReleaseInfo{}, fmt.Errorf("GitHub Agent release signature: %w", err)
	}
	agentHash, agentOK := shared.ManifestHash(manifest, "mui-agent")
	coreHash, coreOK := shared.ManifestHash(manifest, "sing-box")
	if !agentOK || !coreOK || !validReleaseHash(agentHash) || !validReleaseHash(coreHash) {
		return githubReleaseInfo{}, errors.New("GitHub Agent release manifest is incomplete")
	}
	return githubReleaseInfo{AgentHash: agentHash, CoreHash: coreHash}, nil
}

func validReleaseHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func (a *App) getGitHubReleaseFile(ctx context.Context, url string, maxSize int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	client := a.releaseClient
	if client == nil {
		client = &http.Client{CheckRedirect: githubReleaseRedirect}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub Agent release %s: HTTP %d", url, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || int64(len(data)) > maxSize {
		return nil, errors.New("GitHub Agent release manifest or signature has invalid size")
	}
	return data, nil
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
