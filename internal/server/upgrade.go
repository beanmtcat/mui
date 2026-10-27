package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"mui/internal/shared"
)

func (a *App) releaseHash(arch string) (string, error) {
	return a.artifactHash(arch, "mui-agent")
}

func (a *App) artifactHash(arch, name string) (string, error) {
	return a.artifactHashContext(context.Background(), arch, name)
}

func (a *App) artifactHashContext(ctx context.Context, arch, name string) (string, error) {
	if arch != "amd64" && arch != "arm64" {
		return "", errors.New("unsupported architecture")
	}
	if name != "mui-agent" && name != "sing-box" {
		return "", errors.New("unsupported release artifact")
	}
	if a.releaseVersion != "" {
		info, err := a.githubRelease(ctx, arch)
		if err != nil {
			return "", err
		}
		if name == "mui-agent" {
			return info.AgentHash, nil
		}
		return info.CoreHash, nil
	}
	dir := filepath.Join(a.agentBinDir, arch)
	if info, err := os.Lstat(dir); err != nil || !info.IsDir() {
		return "", errors.New("Agent release directory is missing")
	}
	path := filepath.Join(dir, name)
	maxSize := int64(128 << 20)
	if name == "sing-box" {
		maxSize = 256 << 20
	}
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxSize {
		return "", fmt.Errorf("%s release binary is missing or invalid", name)
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, err = io.Copy(h, f)
	f.Close()
	if err != nil {
		return "", err
	}
	got := hex.EncodeToString(h.Sum(nil))
	manifest, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil || len(manifest) > 4096 {
		return "", errors.New("Agent release checksum file is missing or invalid")
	}
	if a.releaseKey != nil {
		// Agents that pinned the key will refuse an unsigned build; say so here
		// rather than after the job has been sent.
		signature, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS.sig"))
		if err != nil || shared.VerifyManifest(a.releaseKey, manifest, signature) != nil {
			return "", errors.New("发布清单缺少有效签名；请用发布私钥重新运行 deploy/build-agent.sh")
		}
	}
	for _, line := range strings.Split(string(manifest), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == name {
			if fields[0] != got {
				return "", fmt.Errorf("%s does not match SHA256SUMS", name)
			}
			return got, nil
		}
	}
	return "", fmt.Errorf("SHA256SUMS has no %s entry", name)
}

func (a *App) agentRelease(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, a.releaseBuilds(r.Context(), "mui-agent"))
}

func (a *App) coreRelease(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, a.releaseBuilds(r.Context(), "sing-box"))
}

// Both architectures are checked in parallel under one request deadline. A
// stalled GitHub connection cannot make the second architecture wait another
// full timeout, and requests sharing an architecture join one fetch.
func (a *App) releaseBuilds(parent context.Context, artifact string) map[string]string {
	builds := map[string]string{}
	if artifact == "mui-agent" && a.releaseVersion != "" {
		builds["releaseVersion"] = a.releaseVersion
	}
	ctx, cancel := context.WithTimeout(parent, githubReleaseRequestTimeout)
	defer cancel()
	var mu sync.Mutex
	var group sync.WaitGroup
	for _, arch := range []string{"amd64", "arm64"} {
		group.Add(1)
		go func(arch string) {
			defer group.Done()
			hash, err := a.artifactHashContext(ctx, arch, artifact)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				builds[arch] = hash
			} else if a.releaseVersion != "" {
				builds[arch+"Error"] = err.Error()
			}
		}(arch)
	}
	group.Wait()
	return builds
}

func supportsGitHubRelease(version string) bool {
	var major, minor, patch int
	if n, _ := fmt.Sscanf(version, "%d.%d.%d", &major, &minor, &patch); n != 3 {
		return false
	}
	return major > 0 || minor > 6 || minor == 6 && patch >= 19
}

func (a *App) queueAgentUpgrade(serverID, ip string) (shared.Operation, error) {
	return a.queueBinaryUpgrade(serverID, "agent.upgrade", ip)
}

func (a *App) queueCoreUpgrade(serverID, ip string) (shared.Operation, error) {
	return a.queueBinaryUpgrade(serverID, "core.upgrade", ip)
}

func (a *App) queueBinaryUpgrade(serverID, kind, ip string) (shared.Operation, error) {
	if err := a.Store.ExpireUpgrades(); err != nil {
		return shared.Operation{}, err
	}
	server, err := a.Store.Server(serverID)
	if err != nil {
		return shared.Operation{}, err
	}
	if shared.OfflineManaged(server) {
		return shared.Operation{}, errors.New("离线服务器请下载新版 Agent 和对应摘要、签名文件，上传后由本机已安装的 /usr/local/bin/mui-agent offline upgrade --binary ./mui-agent 执行升级")
	}
	if a.releaseVersion != "" && !supportsGitHubRelease(server.AgentVersion) {
		return shared.Operation{}, errors.New("当前 Agent 尚不支持从 GitHub Release 升级；请先用新版接入命令重装一次")
	}
	var artifact, current string
	var state shared.DesiredState
	switch kind {
	case "agent.upgrade":
		if !server.AgentSelfUpdate {
			return shared.Operation{}, errors.New("当前 Agent 不支持自更新，需要先人工安装支持自更新的版本一次")
		}
		artifact, current = "mui-agent", server.AgentBuild
	case "core.upgrade":
		if !server.CoreSelfUpdate {
			return shared.Operation{}, errors.New("当前 Agent 不支持 sing-box 自更新，请先升级 Agent")
		}
		artifact, current = "sing-box", server.CoreBuild
	default:
		return shared.Operation{}, errors.New("unsupported upgrade kind")
	}
	hash, err := a.artifactHash(server.Arch, artifact)
	if err != nil {
		return shared.Operation{}, err
	}
	if current == hash {
		return shared.Operation{}, fmt.Errorf("%s 已是面板提供的当前构建", artifact)
	}
	rows, err := a.Store.DB.Query(`SELECT data FROM mui_operations WHERE server_id=$1 AND state<>'' ORDER BY id DESC`, serverID)
	if err != nil {
		return shared.Operation{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if err = rows.Scan(&raw); err != nil {
			return shared.Operation{}, err
		}
		var op shared.Operation
		if json.Unmarshal([]byte(raw), &op) == nil && (op.Kind == "agent.upgrade" || op.Kind == "core.upgrade") && (op.Status == "queued" || op.Status == "running" || op.Status == "activating") {
			return shared.Operation{}, errors.New("该服务器已有进行中的程序升级")
		}
	}
	if err = rows.Err(); err != nil {
		return shared.Operation{}, err
	}
	now := time.Now()
	op := shared.Operation{ID: ID(), ServerID: serverID, Kind: kind, Status: "queued", TargetBuild: hash, Revision: server.Revision, CreatedAt: now, UpdatedAt: now}
	if kind == "agent.upgrade" {
		state.UpgradeSHA256 = hash
	} else {
		state.CoreUpgradeSHA256 = hash
	}
	state.UpgradeRelease = a.releaseVersion
	if err = a.Store.PutOperation(op, state); err != nil {
		return shared.Operation{}, err
	}
	a.Store.AuditWithIP(kind, serverID, fmt.Sprintf("queued %s", hash[:12]), ip)
	return op, nil
}

func (a *App) agentUpgrade(w http.ResponseWriter, r *http.Request) {
	if _, err := a.Store.Server(r.PathValue("id")); err != nil {
		errorJSON(w, 404, "服务器不存在")
		return
	}
	op, err := a.queueAgentUpgrade(r.PathValue("id"), a.clientIP(r))
	if err != nil {
		errorJSON(w, 409, err.Error())
		return
	}
	writeJSON(w, 202, op)
}

func (a *App) coreUpgrade(w http.ResponseWriter, r *http.Request) {
	if _, err := a.Store.Server(r.PathValue("id")); err != nil {
		errorJSON(w, 404, "服务器不存在")
		return
	}
	op, err := a.queueCoreUpgrade(r.PathValue("id"), a.clientIP(r))
	if err != nil {
		errorJSON(w, 409, err.Error())
		return
	}
	writeJSON(w, 202, op)
}
