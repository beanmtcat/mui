//go:build !linux

package agent

import "errors"

func InstallOffline(string, string) error { return errors.New("离线安装仅支持 Linux") }
func ApplyOfflineForwards(string) error   { return errors.New("离线应用仅支持 Linux") }
func UpgradeOffline(string, string) error { return errors.New("离线升级仅支持 Linux") }
