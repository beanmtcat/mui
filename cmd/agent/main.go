package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"mui/internal/agent"
	"mui/internal/shared"
)

const usage = `usage: mui-agent <command> [args]
  mui-agent install PANEL_URL SERVER_ID ENROLL_TOKEN [SING_BOX_BINARY|-] [RELEASE_PUBLIC_KEY] [--token-stdin | --token-file <path> | --token-file=<path>] [--proxy-file <path>]
  mui-agent run
  mui-agent forward
  mui-agent offline <init|check|install|apply|upgrade> [args]   (offline --help for details)
  mui-agent helper
  mui-agent version
  mui-agent rollback-if-unconfirmed EXPECTED_SHA256
  mui-agent --help | -h`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "--help", "-h", "help":
		fmt.Println(usage)
		return
	}
	var err error
	agent.ConfigureMemory(os.Args[1])
	switch os.Args[1] {
	case "offline":
		err = runOfflineCommand(os.Args[2:])
	case "version":
		fmt.Println("mui-agent " + agent.Version)
	case "rollback-if-unconfirmed":
		if runtime.GOOS != "linux" {
			err = fmt.Errorf("rollback-if-unconfirmed is only supported on Linux")
		} else if len(os.Args) != 3 {
			err = fmt.Errorf("usage: mui-agent rollback-if-unconfirmed EXPECTED_SHA256")
		} else {
			err = agent.RollbackIfUnconfirmed(os.Args[2])
		}
	case "install":
		if runtime.GOOS != "linux" {
			err = fmt.Errorf("install is only supported on Linux")
			break
		}
		var panel, serverID, token, core, releaseKey string
		args := os.Args[2:]
		var proxyFile string
		args, proxyFile, err = parseProxyFlag(args)
		var p *shared.SOCKS5Proxy
		if err == nil && proxyFile != "" {
			p, err = agent.ReadProxyFile(proxyFile)
		}
		if err != nil {
			break
		}
		panel, serverID, token, core, releaseKey, err = parseInstallArgs(args)
		if err == nil {
			err = agent.Install(panel, serverID, token, core, releaseKey, p)
		}
	case "helper":
		if runtime.GOOS != "linux" {
			err = fmt.Errorf("helper is only supported on Linux")
		} else {
			err = agent.ServeHelper()
		}
	case "check-config":
		var config agent.Config
		config, err = agent.ReadConfig()
		if err == nil {
			err = agent.CheckConfigURL(config.URL)
		}
	case "run":
		if runtime.GOOS != "linux" {
			err = fmt.Errorf("run is only supported on Linux")
		} else {
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			err = agent.Run(ctx)
		}
	case "forward":
		if runtime.GOOS != "linux" {
			err = fmt.Errorf("forward is only supported on Linux")
		} else {
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			err = agent.RunForward(ctx)
		}
	default:
		err = fmt.Errorf("unknown command %q\n%s", os.Args[1], usage)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// parseInstallArgs parses install arguments:
// install PANEL SERVER TOKEN [SING_BOX|-] [RELEASE_KEY]
// [--token-stdin | --token-file <path> | --token-file=<path>]
//
// With --token-stdin the token is read from stdin; with --token-file it is
// read from a file that is deleted after reading. In both cases the TOKEN
// positional must be the "-" placeholder. A real token passed on the command
// line is accepted for compatibility but warns: it is visible to `ps`.
func parseInstallArgs(args []string) (panel, serverID, token, core, releaseKey string, err error) {
	var positionals []string
	tokenStdin := false
	tokenFile := ""
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--token-stdin":
			tokenStdin = true
		case arg == "--token-file":
			if i+1 >= len(args) {
				return "", "", "", "", "", fmt.Errorf("usage: mui-agent install PANEL_URL SERVER_ID ENROLL_TOKEN [SING_BOX_BINARY|-] [RELEASE_PUBLIC_KEY] [--token-stdin | --token-file <path>]")
			}
			i++
			tokenFile = args[i]
		case strings.HasPrefix(arg, "--token-file="):
			tokenFile = strings.TrimPrefix(arg, "--token-file=")
			if tokenFile == "" {
				return "", "", "", "", "", fmt.Errorf("--token-file requires a path")
			}
		case strings.HasPrefix(arg, "--"):
			return "", "", "", "", "", fmt.Errorf("unknown install flag %q", arg)
		default:
			positionals = append(positionals, arg)
		}
	}
	if tokenStdin && tokenFile != "" {
		return "", "", "", "", "", fmt.Errorf("--token-stdin and --token-file are mutually exclusive")
	}
	if len(positionals) < 3 || len(positionals) > 5 {
		return "", "", "", "", "", fmt.Errorf("usage: mui-agent install PANEL_URL SERVER_ID ENROLL_TOKEN [SING_BOX_BINARY|-] [RELEASE_PUBLIC_KEY] [--token-stdin | --token-file <path>]")
	}
	panel, serverID = positionals[0], positionals[1]
	tokenArg := positionals[2]
	if len(positionals) >= 4 && positionals[3] != "-" {
		core = positionals[3]
	}
	if len(positionals) == 5 {
		releaseKey = positionals[4]
	}
	switch {
	case tokenStdin:
		if tokenArg != "-" {
			return "", "", "", "", "", fmt.Errorf("--token-stdin requires the TOKEN positional to be \"-\"")
		}
		raw, readErr := io.ReadAll(os.Stdin)
		if readErr != nil {
			return "", "", "", "", "", fmt.Errorf("read token from stdin: %w", readErr)
		}
		token = strings.TrimSpace(string(raw))
		if token == "" {
			return "", "", "", "", "", fmt.Errorf("no token read from stdin")
		}
	case tokenFile != "":
		if tokenArg != "-" {
			return "", "", "", "", "", fmt.Errorf("--token-file requires the TOKEN positional to be \"-\"")
		}
		raw, readErr := os.ReadFile(tokenFile)
		if readErr != nil {
			return "", "", "", "", "", fmt.Errorf("read token file: %w", readErr)
		}
		// Delete the file right after reading: it holds a live credential.
		if removeErr := os.Remove(tokenFile); removeErr != nil {
			fmt.Fprintf(os.Stderr, "warning: could not delete token file %s: %v; delete it manually\n", tokenFile, removeErr)
		}
		token = strings.TrimSpace(string(raw))
		if token == "" {
			return "", "", "", "", "", fmt.Errorf("no token read from %s", tokenFile)
		}
	case tokenArg == "-":
		return "", "", "", "", "", fmt.Errorf("TOKEN \"-\" requires --token-stdin or --token-file")
	default:
		fmt.Fprintln(os.Stderr, "warning: token 经命令行传递会被 ps 看到，建议 --token-stdin")
		token = tokenArg
	}
	return panel, serverID, token, core, releaseKey, nil
}

// Proxy credentials are supplied in a protected JSON file, never argv.
func parseProxyFlag(args []string) ([]string, string, error) {
	var out []string
	path := ""
	for i := 0; i < len(args); i++ {
		if args[i] == "--proxy-file" {
			if path != "" || i+1 >= len(args) || args[i+1] == "" {
				return nil, "", fmt.Errorf("--proxy-file requires exactly one path")
			}
			i++
			path = args[i]
		} else {
			out = append(out, args[i])
		}
	}
	return out, path, nil
}
