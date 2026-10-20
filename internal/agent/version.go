package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

// Version is the agent version string. It defaults to a -dev build and is
// replaced at release time via: go build -ldflags "-X mui/internal/agent.Version=<tag>"
var Version = "0.6.14-dev"

// CoreBinaryPath is the managed sing-box binary whose hash CoreBuild reports.
const CoreBinaryPath = "/usr/local/bin/sing-box"

func CoreBuild() string {
	sum, err := CoreBuildE()
	if err != nil {
		return ""
	}
	return sum
}

func CoreBuildE() (string, error) { return fileSHA256(CoreBinaryPath) }

func BinarySHA256() string {
	sum, err := BinarySHA256E()
	if err != nil {
		return ""
	}
	return sum
}

func BinarySHA256E() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	return fileSHA256(path)
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
