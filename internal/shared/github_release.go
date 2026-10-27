package shared

import (
	"fmt"
	"regexp"
	"strings"
)

var githubReleaseVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

// GitHubReleaseArchive is the immutable-version download URL used by the
// installer, panel release checks and Agent upgrade helper. Never construct a
// download host or path from a job supplied by an unprivileged Agent worker.
func GitHubReleaseArchive(version, arch string) (string, error) {
	if !githubReleaseVersion.MatchString(version) {
		return "", fmt.Errorf("invalid Agent release version %q", version)
	}
	if arch != "amd64" && arch != "arm64" {
		return "", fmt.Errorf("unsupported Agent release architecture %q", arch)
	}
	return fmt.Sprintf("https://github.com/beanmtcat/mui/releases/download/v%s/mui-agent-%s-linux-%s.tar.gz", version, version, arch), nil
}

// GitHubReleaseManifest returns the small, per-architecture signed manifest
// uploaded alongside the archive. The archive retains identical copies for
// Agent installs and upgrades.
func GitHubReleaseManifest(version, arch string, signature bool) (string, error) {
	archive, err := GitHubReleaseArchive(version, arch)
	if err != nil {
		return "", err
	}
	suffix := ".SHA256SUMS"
	if signature {
		suffix += ".sig"
	}
	return strings.TrimSuffix(archive, ".tar.gz") + suffix, nil
}
