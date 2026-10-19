package agent

import (
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"
)

var sshListenerProcess = regexp.MustCompile(`\("sshd(?:-session)?",pid=[0-9]+,fd=[0-9]+\)`)

// detectSSHPorts protects the actual TCP listeners as well as configured future
// ports. sshd -T alone is insufficient: a running daemon may still use an old
// port, and socket activation may bind a different port on sshd's behalf.
func detectSSHPorts(run func(string, ...string) (string, error)) (map[int]bool, error) {
	ports, tcpListeners := map[int]bool{}, map[int]bool{}
	out, err := run("ss", "-H", "-lntp")
	if err != nil {
		return nil, errors.New("无法读取实际 SSH 监听端口，已拒绝修改 SSH 防护；请检查 ss -lntp")
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] != "LISTEN" {
			continue
		}
		port := listeningPort(fields[3])
		if port == 0 {
			continue
		}
		tcpListeners[port] = true
		if sshListenerProcess.MatchString(strings.Join(fields[5:], " ")) {
			ports[port] = true
		}
	}
	// Active SSH sockets can be owned by PID 1 until the first SSH connection.
	// Cross-check their port against ss so an unbound configuration is never
	// accepted as evidence of a working SSH listener.
	if sockets, err := run("systemctl", "list-sockets", "--no-legend", "--no-pager", "--plain"); err == nil {
		for _, line := range strings.Split(sockets, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 || (fields[1] != "ssh.socket" && fields[1] != "sshd.socket") {
				continue
			}
			if port := listeningPort(fields[0]); port != 0 && tcpListeners[port] {
				ports[port] = true
			}
		}
	}
	if len(ports) == 0 {
		return nil, errors.New("无法确认 SSH 实际监听端口，已拒绝修改 SSH 防护；请检查 ssh/sshd 服务或 socket")
	}
	// Preserve configured ports too, so a later intentional SSH restart does
	// not require removing the currently working port's protection first.
	if config, err := run("sshd", "-T"); err == nil {
		for _, line := range strings.Split(config, "\n") {
			fields := strings.Fields(line)
			if len(fields) == 2 && fields[0] == "port" {
				if port, err := strconv.Atoi(fields[1]); err == nil && validPort(port) {
					ports[port] = true
				}
			}
		}
	}
	return ports, nil
}

func listeningPort(address string) int {
	if index := strings.LastIndexByte(address, ':'); index >= 0 {
		host := strings.Trim(address[:index], "[]")
		if zone := strings.LastIndexByte(host, '%'); zone >= 0 {
			host = host[:zone]
		}
		if host != "*" && net.ParseIP(host) == nil {
			return 0
		}
		address = address[index+1:]
	}
	port, err := strconv.Atoi(address)
	if err != nil || !validPort(port) {
		return 0
	}
	return port
}
