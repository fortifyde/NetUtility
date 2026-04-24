# NetUtility

[![Build](https://github.com/fortifyde/NetUtility/actions/workflows/ci.yml/badge.svg)](https://github.com/fortifyde/NetUtility/actions/workflows/ci.yml) ![Go](https://img.shields.io/github/go-mod/go-version/fortifyde/NetUtility)

Terminal-based network assessment toolkit. Automates VLAN discovery, host categorization, and service enumeration with an interactive TUI and CLI interface.

## TUI Features

- **Category-driven menus** — browse scripts by category (host config, discovery, scanning, etc.) and run them with a single keypress
- **Dashboard** (`Ctrl+D`) — real-time host stats, category breakdowns, ASCII bar charts, and recent activity
- **Host Inventory** (`Ctrl+N`) — sortable/filterable host table with per-host detail view, and manual categorization
- **Job Manager** (`Ctrl+J`) — concurrent job execution (up to 9 slots), progress tracking, cancellation, and output replay
- **Streaming output viewer** — live script output with ANSI color support, interactive input handling, search, and background mode
- **Global search** (`/`) — fuzzy search across all scripts by name, description, or keyword
- **File server** — share scan results across VLANs via an authenticated HTTP(s) server (`sudo ./netutil setup-fileserver`)

## Script Categories

| Category | Description |
|---|---|
| **Host Configuration** | Interface/VLAN management, IP/route/DNS config |
| **Network Discovery** | Multi-phase discovery, Packet capture, VLAN extraction, MAC vendor analysis |
| **Port Scanning** | Safe nmap enumeration, nmap vulnerability scanning, full port scans with service detection |
| **Advanced Tools** | All-in-one automated discovery, device config gathering (Cisco, HP, Aruba) |
| **Utilities** | Working directory selection, OUI database updates, log management, team IP exclusion, config backup/restore |

## Installation

**Requirements:** Linux, Go 1.24+, `arp-scan`, `nmap`, `tshark`/`tcpdump`, `fping`, `masscan` (optional), `jq`, `sshpass`

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
sudo ./netutil auto-discover    # Automated discovery workflow
sudo ./netutil capture          # Packet capture
sudo ./netutil port-scan        # Port & service scan
sudo ./netutil vuln             # Vulnerability assessment
sudo ./netutil interfaces       # Manage network interfaces
sudo ./netutil config-ip        # Configure IP addresses
sudo ./netutil setup-fileserver # Set up authenticated file server
```

Use `sudo ./netutil --help` to list all commands. Shortcuts support fuzzy matching — e.g. `netutil cap` resolves to `capture`.

## Legal Notice

This toolkit performs active network scanning. Use only on networks you own or have explicit authorization to test. The author accepts no liability for misuse.

## License

MIT — see [LICENSE](LICENSE) for details.
