package shared

import "testing"

func TestGitHubReleaseArchive(t *testing.T) {
	got, err := GitHubReleaseArchive("0.6.19", "amd64")
	if err != nil || got != "https://github.com/beanmtcat/mui/releases/download/v0.6.19/mui-agent-0.6.19-linux-amd64.tar.gz" {
		t.Fatalf("archive URL: %q %v", got, err)
	}
	for _, version := range []string{"", "v0.6.19", "0.6.19/../x", "0.6.19?x=1"} {
		if _, err := GitHubReleaseArchive(version, "amd64"); err == nil {
			t.Fatalf("accepted %q", version)
		}
	}
	if _, err := GitHubReleaseArchive("0.6.19", "other"); err == nil {
		t.Fatal("accepted unsupported architecture")
	}
	for _, item := range []struct {
		signature bool
		want      string
	}{
		{false, "https://github.com/beanmtcat/mui/releases/download/v0.6.21/mui-agent-0.6.21-linux-arm64.SHA256SUMS"},
		{true, "https://github.com/beanmtcat/mui/releases/download/v0.6.21/mui-agent-0.6.21-linux-arm64.SHA256SUMS.sig"},
	} {
		got, err := GitHubReleaseManifest("0.6.21", "arm64", item.signature)
		if err != nil || got != item.want {
			t.Fatalf("manifest URL: %q %v", got, err)
		}
	}
}
