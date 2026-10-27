#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  printf '%s\n' '请以 root 执行 MUI Agent 卸载脚本。' >&2
  exit 1
fi

units='mui-agent mui-agent-helper mui-forward mui-sing-box panel-agent panel-agent-helper panel-sing-box'
mui_core_owned=0
if [ -f /etc/systemd/system/mui-sing-box.service ] || [ -f /etc/systemd/system/panel-sing-box.service ] || [ -f /etc/init.d/mui-sing-box ] || [ -f /etc/init.d/panel-sing-box ] || [ -d /etc/mui-core ]; then
  mui_core_owned=1
fi
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  for unit in $units; do
    if [ -f "/etc/systemd/system/$unit.service" ]; then
      systemctl disable --now "$unit.service"
    fi
  done
  for unit in $units; do
    rm -f "/etc/systemd/system/$unit.service"
  done
  systemctl daemon-reload
elif command -v rc-service >/dev/null 2>&1 && command -v rc-update >/dev/null 2>&1; then
  for unit in $units; do
    if [ -f "/etc/init.d/$unit" ]; then
      if rc-service "$unit" status >/dev/null 2>&1; then
        rc-service "$unit" stop
      fi
      if [ -e "/etc/runlevels/default/$unit" ]; then
        rc-update del "$unit" default
      fi
      rm -f "/etc/init.d/$unit"
    fi
  done
else
  printf '%s\n' '未检测到正在运行的 systemd 或 OpenRC，未卸载任何文件。' >&2
  exit 1
fi

rm -f /usr/local/bin/mui-agent
if [ "$mui_core_owned" -eq 1 ]; then rm -f /usr/local/bin/sing-box; fi
rm -rf /etc/mui-agent /etc/mui-forward /etc/mui-core /var/lib/mui-agent
printf '%s\n' 'MUI Agent、转发与 sing-box 服务已卸载。UFW 规则和系统账户未改动，请按需检查。'
