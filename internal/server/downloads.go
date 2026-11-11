package server

import (
	_ "embed"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"mui/internal/shared"
)

//go:embed install-agent.sh
var installAgentScript []byte

//go:embed uninstall-agent.sh
var uninstallAgentScript []byte

func (a *App) downloadInstallScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(installAgentScript)
}

func (a *App) downloadUninstallScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(uninstallAgentScript)
}

// timeoutWriter aborts a download whose total time exceeds the deadline.
// ServeContent stops on the first write error, so a stalled transfer cannot
// hold a download slot forever.
func (a *App) downloadAgentFile(w http.ResponseWriter, r *http.Request) {
	if a.releaseVersion != "" {
		http.NotFound(w, r)
		return
	}
	arch, name := r.PathValue("arch"), r.PathValue("file")
	if arch != "amd64" && arch != "arm64" || name != "mui-agent" && name != "sing-box" && name != "SHA256SUMS" && name != "SHA256SUMS.sig" {
		http.NotFound(w, r)
		return
	}
	// These files are public and large. An install fetches four of them; allow
	// a few installs per address and a handful of transfers in total.
	if a.rateCount(r, "download", 1) > 20 {
		errorJSON(w, 429, "下载过于频繁，请稍后再试")
		return
	}
	if name == "mui-agent" || name == "sing-box" {
		select {
		case a.downloads <- struct{}{}:
			defer func() { <-a.downloads }()
		default:
			w.Header().Set("Retry-After", "30")
			errorJSON(w, 503, "同时下载的请求过多，请稍后再试")
			return
		}
		// One concurrent binary download per address: a single slow client
		// must not occupy every global slot.
		ip := a.clientIP(r)
		a.dlMu.Lock()
		if a.downloadsByIP[ip] >= 1 {
			a.dlMu.Unlock()
			w.Header().Set("Retry-After", "30")
			errorJSON(w, 503, "该地址已有下载在进行，请稍后再试")
			return
		}
		a.downloadsByIP[ip]++
		a.dlMu.Unlock()
		defer func() {
			a.dlMu.Lock()
			a.downloadsByIP[ip]--
			if a.downloadsByIP[ip] <= 0 {
				delete(a.downloadsByIP, ip)
			}
			a.dlMu.Unlock()
		}()
	}
	archDir := filepath.Join(a.agentBinDir, arch)
	if info, err := os.Lstat(archDir); err != nil || !info.IsDir() {
		http.NotFound(w, r)
		return
	}
	path := filepath.Join(archDir, name)
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	// Preserve extensionless release filenames. Serving a manifest as plain
	// text lets browsers append .txt, which breaks the target install command.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+name+"\"")
	// A real write deadline: a client that stops reading is cut off instead of
	// holding a download slot forever.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(30 * time.Minute))
	http.ServeContent(w, r, name, info.ModTime(), f)
}

// installCommand installs sing-box ("node") only on an exit server; the
// others run forwards alone ("relay").
func (a *App) installCommand(serverID, token string, server shared.Server) string {
	return a.installCommandAt(a.PublicURL, serverID, token, server)
}

func (a *App) installCommandAt(publicURL, serverID, token string, server shared.Server) string {
	purpose := "relay"
	if shared.InstallsCore(server) {
		purpose = "node"
	}
	// Keep the token out of every child process's arguments, including the
	// outer shell. Download the script first so its stdin can carry the token.
	proxyPrelude, _, proxyErr := a.installProxyPrelude(server, true)
	if proxyErr != nil {
		return "printf '%s\\n' " + shellQuote(proxyErr.Error()) + " >&2; exit 1"
	}
	curlProxy := ""
	if proxyPrelude != "" {
		curlProxy = " --config \"$mui_proxy_dir/curl.conf\""
	}
	installerURL := publicURL + "/download/install.sh"
	command := "(\nset -eu\numask 077\n" +
		"if [ \"$(id -u)\" -eq 0 ]; then\n  set -- sh\n" +
		"elif command -v sudo >/dev/null 2>&1; then\n  set -- sudo sh\n" +
		"else\n  printf '%s\\n' '当前用户不是 root，且未安装 sudo；请切换到 root 后重新执行接入命令。' >&2\n  exit 1\nfi\n" +
		"mui_installer=$(mktemp)\n" +
		"trap 'rm -f \"$mui_installer\"' EXIT HUP INT TERM\n" + proxyPrelude +
		"curl -fsSL" + curlProxy + " " + shellQuote(installerURL) + " -o \"$mui_installer\"\n" +
		"\"$@\" \"$mui_installer\" " + shellQuote(publicURL) +
		" " + shellQuote(serverID) + " - " + shellQuote(purpose)
	if a.releaseVersion != "" {
		command += " " + shellQuote(a.releaseKeyB64)
		if proxyPrelude != "" {
			command += " \"$mui_proxy_dir\""
		} else {
			command += " ''"
		}
		command += " " + shellQuote(a.releaseVersion)
		return command + " <<'MUI_ENROLLMENT_TOKEN'\n" + token + "\nMUI_ENROLLMENT_TOKEN\n)"
	}
	if a.releaseKeyB64 != "" || proxyPrelude != "" {
		command += " " + shellQuote(a.releaseKeyB64)
	}
	if proxyPrelude != "" {
		command += " \"$mui_proxy_dir\""
	}
	return command + " <<'MUI_ENROLLMENT_TOKEN'\n" + token + "\nMUI_ENROLLMENT_TOKEN\n)"
}
