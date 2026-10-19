package shared

// OfflineForwardExample is used by the local CLI and the panel download guide.
const OfflineForwardExample = `[
  {
    "id": "entry",
    "name": "入口 TCP + UDP",
    "network": "tcp+udp",
    "listen": "0.0.0.0",
    "port": 50001,
    "targets": [{"host": "10.0.0.2", "port": 50001}],
    "balance": "failover",
    "firewallPolicy": "manual",
    "enabled": true
  }
]
`
