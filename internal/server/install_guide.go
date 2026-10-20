package server

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"mui/internal/shared"
)

type installFile struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type installDownload struct {
	Arch    string        `json:"arch"`
	Files   []installFile `json:"files"`
	Command string        `json:"command"`
}

type offlineInstallGuide struct {
	MigrationCommand string            `json:"migrationCommand,omitempty"`
	ProxyNotice      string            `json:"proxyNotice,omitempty"`
	Command          string            `json:"command"`
	Downloads        []installDownload `json:"downloads"`
	Signed           bool              `json:"signed"`
	ExampleConfig    string            `json:"exampleConfig,omitempty"`
}

const manualInstallDirectory = "mui-install"

// The same release files serve online and manual installs. Only the latter's
// small enrollment request needs to run over the target machine's connection.
func (a *App) offlineInstall(serverID, token string, server shared.Server) offlineInstallGuide {
	return a.offlineInstallAt(a.PublicURL, serverID, token, server)
}

func (a *App) offlineInstallAt(publicURL, serverID, token string, server shared.Server) offlineInstallGuide {
	binaries := []string{"mui-agent"}
	core := "-"
	if shared.InstallsCore(server) {
		binaries = append(binaries, "sing-box")
		core = "./sing-box"
	}
	files := append(append([]string{}, binaries...), "SHA256SUMS")
	if a.releaseKeyB64 != "" {
		files = append(files, "SHA256SUMS.sig")
	}
	guide := offlineInstallGuide{Downloads: []installDownload{}, Signed: a.releaseKeyB64 != "", MigrationCommand: managementMigrationCommand(server)}
	if server.AgentProxyNodeID != "" {
		guide.ProxyNotice = "已按入口所选的公网 / 内网来源生成 SOCKS5 放行规则，不要求节点开启客户端直连。请先在操作记录中确认代理服务器的配置任务成功，再执行接入命令。来源类型可独立于 SOCKS5 连接地址设置；经过 NAT 时请在服务器档案填写实际出口 IP。"
	}
	guide.Downloads = installDownloads(publicURL, files)
	proxyPrelude, proxyFlag, proxyErr := a.installProxyPrelude(server, false)
	if proxyErr != nil {
		guide.Command = "printf '%s\\n' " + shellQuote(proxyErr.Error()) + " >&2; exit 1"
		return guide
	}
	guide.Command = localInstallPrelude(files, binaries) + proxyPrelude +
		"\"$@\" ./mui-agent install " + shellQuote(publicURL) + " " + shellQuote(serverID) + " - " + shellQuote(core) + " " + shellQuote(a.releaseKeyB64) + proxyFlag + " --token-stdin <<'MUI_ENROLLMENT_TOKEN'\n" + token + "\nMUI_ENROLLMENT_TOKEN\n" +
		"printf '%s\\n' 'MUI Agent 安装完成。'\n)"
	return guide
}

func (a *App) standaloneInstallAt(publicURL string) offlineInstallGuide {
	files := []string{"mui-agent", "SHA256SUMS"}
	if a.releaseKeyB64 != "" {
		files = append(files, "SHA256SUMS.sig")
	}
	guide := offlineInstallGuide{Downloads: installDownloads(publicURL, files), Signed: a.releaseKeyB64 != "", ExampleConfig: shared.OfflineForwardExample}
	// An upgrade goes through the installed agent, which checks the new
	// binary against the release key it pinned before running it; the new
	// binary checking itself would prove nothing.
	install := "\"$@\" ./mui-agent offline install --config ./forwards.json"
	if a.releaseKeyB64 != "" {
		install += " --release-key " + shellQuote(a.releaseKeyB64)
	}
	guide.Command = localInstallPrelude(files, []string{"mui-agent"}) +
		"if \"$@\" test -f /etc/mui-forward/offline.json && \"$@\" test -x /usr/local/bin/mui-agent; then\n" +
		"  \"$@\" /usr/local/bin/mui-agent offline upgrade --binary ./mui-agent --config ./forwards.json\n" +
		"else\n  " + install + "\nfi\n" +
		"printf '%s\\n' 'MUI 离线转发安装完成，防火墙端口请自行放行。'\n)"
	return guide
}

func installDownloads(publicURL string, files []string) []installDownload {
	downloads := []installDownload{}
	for _, arch := range []string{"amd64", "arm64"} {
		download := installDownload{Arch: arch, Files: []installFile{}}
		var cmd strings.Builder
		cmd.WriteString("(\nset -eu\nmkdir -p \"$HOME/" + manualInstallDirectory + "\"\n")
		for _, name := range files {
			url := publicURL + "/download/" + arch + "/" + name
			download.Files = append(download.Files, installFile{Name: name, URL: url})
			cmd.WriteString("curl -fL --retry 3 --connect-timeout 15 " + shellQuote(url) + " -o \"$HOME/" + manualInstallDirectory + "/" + name + "\"\n")
		}
		cmd.WriteString(")")
		download.Command = cmd.String()
		downloads = append(downloads, download)
	}
	return downloads
}

func localInstallPrelude(files, binaries []string) string {
	var cmd strings.Builder
	cmd.WriteString("(\nset -eu\numask 077\ncd \"$HOME/" + manualInstallDirectory + "\"\n")
	// Some browsers save text downloads with an extra .txt suffix. Normalize
	// only when the canonical filename is absent; never replace an existing
	// manifest or skip its checksum/signature checks.
	for _, name := range []string{"SHA256SUMS", "SHA256SUMS.sig"} {
		cmd.WriteString("if [ ! -e " + shellQuote(name) + " ] && [ -f " + shellQuote(name+".txt") + " ]; then\n  mv -- " + shellQuote(name+".txt") + " " + shellQuote(name) + "\nfi\n")
	}
	// Verify the executable before running it. Never use --ignore-missing:
	// missing binaries or missing/duplicate manifest entries must fail closed.
	for _, name := range files {
		cmd.WriteString("test -f " + shellQuote(name) + " || { printf '%s\\n' " + shellQuote("缺少 "+name+"，请将同一发布版本的全部文件上传到 ~/"+manualInstallDirectory+"/。") + " >&2; exit 1; }\n")
	}
	for _, name := range binaries {
		cmd.WriteString("test \"$(grep -Ec " + shellQuote(" \\*?"+name+"$") + " SHA256SUMS)\" -eq 1 || { printf '%s\\n' " + shellQuote("SHA256SUMS 中的 "+name+" 条目缺失或重复，请重新下载同一版本文件。") + " >&2; exit 1; }\n")
	}
	cmd.WriteString("grep -E " + shellQuote(" \\*?("+strings.Join(binaries, "|")+")$") + " SHA256SUMS | sha256sum -c >/dev/null || { printf '%s\\n' '文件摘要校验失败，请重新上传同一发布版本的文件。' >&2; exit 1; }\n")
	cmd.WriteString("chmod 755 " + strings.Join(binaries, " ") + "\n")
	// "$@" is the privilege prefix: nothing for root, sudo otherwise.
	cmd.WriteString("if [ \"$(id -u)\" -eq 0 ]; then\n  set --\n")
	cmd.WriteString("elif command -v sudo >/dev/null 2>&1; then\n  set -- sudo\n")
	cmd.WriteString("else\n  printf '%s\\n' '当前用户不是 root，且未安装 sudo；请切换到 root 后重新执行安装命令。' >&2\n  exit 1\nfi\n")
	return cmd.String()
}

// installProxyPrelude returns a shell fragment and the Agent install flag.
// The Agent reads the proxy from a protected file, and so does curl when the
// command downloads the installer itself (withCurl); secrets never appear in
// child process arguments. Commands that run files the administrator uploaded
// download nothing, so they get no curl configuration.
func (a *App) installProxyPrelude(server shared.Server, withCurl bool) (string, string, error) {
	if server.AgentProxyNodeID == "" {
		return "", "", nil
	}
	proxy, err := a.agentProxy(server)
	if err != nil {
		return "", "", err
	}
	prelude := "mui_proxy_dir=$(mktemp -d)\ntrap 'rm -rf \"$mui_proxy_dir\"; rm -f \"${mui_installer:-}\"' EXIT HUP INT TERM\n" +
		"printf '%s' " + shellQuote(Marshal(proxy)) + " > \"$mui_proxy_dir/proxy.json\"\n"
	if withCurl {
		curlConfig := fmt.Sprintf("proxy = %s\nproxy-user = %s\n", strconv.Quote("socks5h://"+net.JoinHostPort(proxy.Host, strconv.Itoa(proxy.Port))), strconv.Quote(proxy.Username+":"+proxy.Password))
		prelude += "printf '%s' " + shellQuote(curlConfig) + " > \"$mui_proxy_dir/curl.conf\"\n"
	}
	return prelude, " --proxy-file \"$mui_proxy_dir/proxy.json\"", nil
}
