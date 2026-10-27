//go:build linux

package agent

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"mui/internal/shared"
)

// Download the archive on the target server, not via the MUI panel. The
// release URL can only name this repository and a validated version, even
// though the unprivileged worker forwards the version in its helper request.
func downloadGitHubUpgradeArtifact(proxy *shared.SOCKS5Proxy, name, expected string, maxSize int64, version string, key ed25519.PublicKey) (string, error) {
	endpoint, err := shared.GitHubReleaseArchive(version, runtime.GOARCH)
	if err != nil {
		return "", err
	}
	client, err := panelHTTPClient(proxy, 3*time.Minute)
	if err != nil {
		return "", err
	}
	client.CheckRedirect = gitHubReleaseRedirect
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub release HTTP %d", resp.StatusCode)
	}
	zr, err := gzip.NewReader(io.LimitReader(resp.Body, 512<<20))
	if err != nil {
		return "", err
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	tmp, err := os.CreateTemp("/usr/local/bin", "."+name+"-upgrade-*")
	if err != nil {
		return "", err
	}
	valid := false
	defer func() {
		_ = tmp.Close()
		if !valid {
			_ = os.Remove(tmp.Name())
		}
	}()
	var manifest, signature []byte
	var got string
	seen := map[string]bool{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if hdr.Name == runtime.GOARCH || hdr.Name == runtime.GOARCH+"/" {
			if hdr.Typeflag != tar.TypeDir {
				return "", errors.New("invalid GitHub release directory")
			}
			continue
		}
		file := strings.TrimPrefix(hdr.Name, runtime.GOARCH+"/")
		if !strings.HasPrefix(hdr.Name, runtime.GOARCH+"/") || seen[file] || hdr.Typeflag != tar.TypeReg {
			return "", errors.New("unexpected GitHub release archive member")
		}
		seen[file] = true
		switch file {
		case "mui-agent", "sing-box":
			limit := int64(maxAgentBinarySize)
			if file == "sing-box" {
				limit = maxCoreBinarySize
			}
			if hdr.Size <= 0 || hdr.Size > limit {
				return "", errors.New("invalid GitHub release binary size")
			}
			if file == name {
				h := sha256.New()
				if _, err := io.Copy(io.MultiWriter(tmp, h), tr); err != nil {
					return "", err
				}
				got = hex.EncodeToString(h.Sum(nil))
			}
		case "SHA256SUMS", "SHA256SUMS.sig":
			if hdr.Size <= 0 || hdr.Size > 8192 {
				return "", errors.New("invalid GitHub release manifest size")
			}
			value, err := io.ReadAll(tr)
			if err != nil {
				return "", err
			}
			if file == "SHA256SUMS" {
				manifest = value
			} else {
				signature = value
			}
		default:
			return "", fmt.Errorf("unexpected GitHub release file %q", file)
		}
	}
	if got == "" || got != expected || tmpSize(tmp) <= 0 || tmpSize(tmp) > maxSize {
		return "", errors.New("GitHub release binary failed SHA-256 or size verification")
	}
	if key != nil {
		if err := shared.VerifyManifest(key, manifest, signature); err != nil {
			return "", err
		}
	}
	if listed, ok := shared.ManifestHash(manifest, name); !ok || listed != expected {
		return "", fmt.Errorf("%s is not listed with the expected hash in the GitHub release manifest", name)
	}
	if minVer, ok, err := manifestMinVersion(manifest); err != nil {
		return "", err
	} else if ok {
		current, err := parseSemver(Version)
		if err != nil {
			return "", err
		}
		if current.compare(minVer) < 0 {
			return "", fmt.Errorf("release requires a newer Agent than %s", Version)
		}
	}
	if err := tmp.Chmod(0755); err != nil {
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	valid = true
	return tmp.Name(), nil
}

func tmpSize(file *os.File) int64 {
	info, err := file.Stat()
	if err != nil {
		return -1
	}
	return info.Size()
}

func gitHubReleaseRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > 5 || req.URL.Scheme != "https" || req.URL.User != nil {
		return errors.New("unsafe GitHub release redirect")
	}
	host := strings.ToLower(req.URL.Hostname())
	if host != "github.com" && host != "release-assets.githubusercontent.com" && host != "objects.githubusercontent.com" {
		return errors.New("unexpected GitHub release redirect host")
	}
	return nil
}
