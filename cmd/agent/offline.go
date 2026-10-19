package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"mui/internal/agent"
)

const offlineUsage = `usage:
  mui-agent offline init [FILE]                         create example (default: forwards.json)
  mui-agent offline check [FILE]                        validate (default: /etc/mui-forward/forwards.json)
  mui-agent offline install --config FILE [--release-key KEY | --release-key-file FILE]
  mui-agent offline upgrade --binary NEW_MUI_AGENT [--config FILE]
                                                        run with the installed agent: verify the new
                                                        binary with the pinned release key, then install
  mui-agent offline apply FILE                          validate, reload and confirm; rollback on failure

Offline mode runs only mui-forward.service, without panel enrollment, sing-box or UFW.
Use root for install/apply. Configure host firewall rules separately.`

func runOfflineCommand(args []string) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		fmt.Println(offlineUsage)
		return nil
	}
	switch args[0] {
	case "init", "check":
		if len(args) > 2 {
			return errors.New(offlineUsage)
		}
		path := agent.ForwardConfig
		if args[0] == "init" {
			path = "forwards.json"
		}
		if len(args) == 2 {
			path = args[1]
		}
		if args[0] == "init" {
			if err := agent.InitOfflineForwards(path); err != nil {
				return err
			}
			fmt.Println("示例已写入 " + path + "；请先修改目标地址和端口。")
			return nil
		}
		rules, _, err := agent.ReadOfflineForwards(path)
		if err != nil {
			return err
		}
		fmt.Printf("配置校验通过：%d 条规则（未检查目标连通性或实际端口占用）。\n", len(rules))
		return nil
	case "install":
		flags := flag.NewFlagSet("offline install", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		config := flags.String("config", "", "forward rules JSON")
		key := flags.String("release-key", "", "base64 release public key")
		keyFile := flags.String("release-key-file", "", "release public key file")
		if err := flags.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				fmt.Println(offlineUsage)
				return nil
			}
			return err
		}
		if *config == "" || flags.NArg() != 0 || *key != "" && *keyFile != "" {
			return errors.New(offlineUsage)
		}
		if *keyFile != "" {
			raw, err := os.ReadFile(*keyFile)
			if err != nil {
				return err
			}
			*key = string(raw)
			if strings.TrimSpace(*key) == "" {
				return errors.New("发布公钥文件为空")
			}
		}
		var emptyKey bool
		flags.Visit(func(f *flag.Flag) {
			if f.Name == "release-key" && strings.TrimSpace(*key) == "" {
				emptyKey = true
			}
		})
		if emptyKey {
			return errors.New("发布公钥不能为空")
		}
		if err := agent.InstallOffline(*config, *key); err != nil {
			return err
		}
		fmt.Println("离线转发服务安装完成，已启用开机启动。防火墙端口需自行放行。")
		return nil
	case "upgrade":
		flags := flag.NewFlagSet("offline upgrade", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		binary := flags.String("binary", "", "new mui-agent, next to its SHA256SUMS")
		config := flags.String("config", "", "configuration to apply (default: the one in use)")
		if err := flags.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				fmt.Println(offlineUsage)
				return nil
			}
			return err
		}
		if *binary == "" || flags.NArg() != 0 {
			return errors.New(offlineUsage)
		}
		if err := agent.UpgradeOffline(*binary, *config); err != nil {
			return err
		}
		fmt.Println("离线 Agent 已升级并应用配置。")
		return nil
	case "apply":
		if len(args) != 2 {
			return errors.New(offlineUsage)
		}
		if err := agent.ApplyOfflineForwards(args[1]); err != nil {
			return err
		}
		fmt.Println("转发配置已应用，转发进程已确认加载。")
		return nil
	default:
		return errors.New(offlineUsage)
	}
}
