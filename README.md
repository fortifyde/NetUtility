# NetUtility

<div align="center">

<a href="https://github.com/fortifyde/NetUtility/actions/workflows/ci.yml"><img src="https://github.com/fortifyde/NetUtility/actions/workflows/ci.yml/badge.svg" alt="Build"></a>
<img src="https://img.shields.io/github/go-mod/go-version/fortifyde/NetUtility" alt="Go">
<a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>

</div>

Terminal-based network assessment toolkit for Linux. Handles traffic capture, VLAN discovery, host categorization, port/service enumeration, and vulnerability scanning with an interactive TUI and CLI interface.

## TUI Features

- **Category-driven menus** — browse scripts by category and run them with a single keypress
- **Dashboard** (`Ctrl+D`) — real-time host stats, category breakdowns, ASCII bar charts, and recent activity
- **Host Inventory** (`Ctrl+N`) — sortable/filterable host table with per-host detail view and manual categorization
- **Job Manager** (`Ctrl+J`) — concurrent job execution (default: 3 slots), progress tracking, cancellation, and output replay
- **Streaming output viewer** — live script output with ANSI color support, interactive input handling, search, and background mode
- **Global search** (`/`) — fuzzy search across all scripts by name, description, or keyword
- **Assessment checklist** — workflow progress tracking: capture, system config, discovery, categorization, port/vuln scanning, device config extraction
- **File server** — share scan results across VLANs via an authenticated HTTP(S) server

## Script Categories

| Category | Description |
|---|---|
| **Host Configuration** | Interface, VLAN, IP, route, and DNS configuration |
| **System Utilities** | Workspace setup, OUI database, log management, team IP exclusion, config backup/restore |
| **Advanced Tools** | All-in-one automated discovery, web screenshot capture, device config extraction (Cisco, HP, Aruba) |
| **Network Discovery** | Multi-phase discovery, packet capture, VLAN extraction, MAC vendor analysis, packet analysis |
| **Port Scanning** | Full TCP port enumeration with service detection, vulnerability assessment |

## Installation

**Requirements:** Linux, Go 1.26+, `nmap`, `tshark`, `jq`

**Recommended:** `fping`, `arp-scan`, `sshpass`

**Optional:** `masscan`, `nikto`, `sslscan`, `gowitness`, `expect`

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
sudo ./netutil capture             # Packet capture
sudo ./netutil port-scan           # Port & service scan
sudo ./netutil vuln                # Vulnerability assessment
sudo ./netutil interfaces          # Manage network interfaces
sudo ./netutil config-ip           # Configure IP addresses
sudo ./netutil setup-fileserver    # Set up authenticated file server
sudo ./netutil gather-configs      # Extract device configs via SSH
```

Use `sudo ./netutil --help` to list all commands. Shortcuts support fuzzy matching — e.g. `netutil cap` resolves to `capture`.

## Legal Notice

This toolkit performs active network scanning. Misconfiguration of scanned hosts may cause unexpected behavior. Use only on networks you own or have explicit authorization to test. The author accepts no liability for misuse.

## License

MIT — see [LICENSE](LICENSE) for details.
