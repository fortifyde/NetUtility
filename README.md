# NetUtility

<div align="center">

<a href="https://github.com/fortifyde/NetUtility/actions/workflows/ci.yml"><img src="https://github.com/fortifyde/NetUtility/actions/workflows/ci.yml/badge.svg" alt="Build"></a> <img src="https://img.shields.io/github/go-mod/go-version/fortifyde/NetUtility" alt="Go"> <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
</div>

Terminal-based network assessment toolkit for Linux — traffic capture, VLAN discovery, host categorization, port/service enumeration, and vulnerability scanning through an interactive TUI and CLI.

<div align="center">
<img src="assets/demo.gif" alt="NetUtility TUI demo" width="800">
</div>

## TUI Features

- **Category-driven menus** — browse scripts by category and run them with a single keypress
- **Dashboard** (`Ctrl+D`) — real-time host stats, category breakdowns, ASCII bar charts, and recent activity
- **Host Inventory** (`Ctrl+N`) — sortable/filterable host table with per-host detail view and manual categorization
- **Job Manager** (`Ctrl+J`) — concurrent job execution (default: 3 slots), progress tracking, cancellation, and output replay
- **Streaming output viewer** — live script output with ANSI color support, interactive input handling, search, and background mode
- **Global search** (`/`) — fuzzy search across all scripts by name, description, or keyword
- **Assessment checklist** — workflow progress tracking: capture, system config, discovery, categorization, port/vuln scanning, device config extraction
- **Topology visualization** — interactive D3.js network topology viewer with VLAN grouping, connection inference, and risk overlay
- **Compliance checking** — automated security compliance assessment against network device configurations
- **File server** — share scan results across VLANs via an authenticated HTTP(S) server

## Script Categories

| Category | Scripts |
|---|---|
| **Network Setup** | Interface management, VLAN configuration, IP address setup, route configuration, DNS configuration |
| **System Utilities** | Workspace selection, OUI database, log management, team IP exclusion, config backup/restore, file server |
| **Network Discovery** | Auto discovery, multi-phase discovery, packet capture, ARP table ingestion, LLDP/CDP neighbor discovery, VLAN extraction |
| **Capture Analysis** | Packet capture analysis, MAC address analysis, passive OS fingerprinting |
| **Port Scanning** | Full TCP port/service enumeration, vulnerability assessment |
| **Reconnaissance** | Web screenshot capture, exploit search, SNMP device interrogation |
| **Config Gathering** | Network device config extraction (Cisco IOS/Nexus, HP Comware/ProVision/Aruba) |

## Installation

**Requirements:** Linux, Go 1.26+, `nmap`, `tshark`, `jq`

**Recommended:** `fping`, `arp-scan`, `sshpass`

**Optional:** `masscan`, `nikto`, `sslscan`, `gowitness`, `expect`, `python3` with `netmiko`

```bash
git clone https://github.com/fortifyde/NetUtility.git
cd NetUtility
go build -o netutil ./cmd/netutil
```

## Usage

**TUI mode** (default):
```bash
sudo ./netutil
```

**CLI mode** — run scripts directly by shortcut:
```bash
sudo ./netutil auto-discover       # Automated discovery workflow
sudo ./netutil multi-discovery     # Multi-phase discovery
sudo ./netutil capture             # Packet capture
sudo ./netutil packet-analysis     # Analyze pcap files
sudo ./netutil fingerprint         # Passive OS fingerprinting
sudo ./netutil port-scan           # Port & service scan
sudo ./netutil vuln                # Vulnerability assessment
sudo ./netutil lldp                # LLDP/CDP neighbor discovery
sudo ./netutil snmp                # SNMP device interrogation
sudo ./netutil exploits            # Exploit search
sudo ./netutil screenshot          # Web screenshot capture
sudo ./netutil interfaces          # Manage network interfaces
sudo ./netutil config-ip           # Configure IP addresses
sudo ./netutil gather-configs      # Extract device configs via SSH
sudo ./netutil setup-fileserver    # Set up authenticated file server
```

Use `sudo ./netutil --help` to list all commands. Shortcuts support fuzzy matching — e.g. `netutil cap` resolves to `capture`.

## Legal Notice

This toolkit performs active network scanning. Misconfiguration of scanned hosts may cause unexpected behavior. Use only on networks you own or have explicit authorization to test. The author accepts no liability for misuse.

## License

MIT — see [LICENSE](LICENSE) for details.
