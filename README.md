# NetUtility

A comprehensive terminal-based network security and analysis toolkit designed for security professionals and network administrators. NetUtility combines advanced network discovery, packet analysis, and security assessment capabilities into a unified, easy-to-use platform.

## What does it do?

NetUtility provides a sophisticated suite of network analysis tools accessible through both an interactive TUI and direct CLI commands. It automates complex network analysis workflows, from promiscuous packet capture and VLAN discovery to comprehensive security assessment and infrastructure configuration.

## Main Features

**System Configuration**
- Manage network interfaces (bring them up/down, configure IPs)
- Create and manage VLAN interfaces
- Configure routing and DNS settings
- Backup and restore your network configuration

**Network Reconnaissance**
- Run packet captures with tshark
- Extract VLAN information from traffic
- Detect unsafe protocols in network traffic
- Enumerate hosts and categorize them by OS

**Vulnerability Assessment**
- Deep port scanning with service detection
- Run safe Nmap NSE scripts (no brute forcing)
- Analyze results offline with vulnerability mapping
- Get actionable remediation advice

**Device Configuration**
- SSH into network devices (routers, switches, etc.)
- Automatically detect vendor (Cisco, Juniper, HP, Aruba, Fortinet)
- Pull configuration files with vendor-specific commands
- Organize everything in a structured way

## Getting Started

You'll need Linux with networking tools (tshark, nmap, fping, ssh). Depending on your Distribution, most of what you need may already be there.

```bash
git clone https://github.com/fortifyde/NetUtility.git
cd NetUtility
go build -o netutil ./cmd/netutil
chmod +x scripts/*/*.sh
sudo ./netutil
```

### Enhanced CLI Usage

NetUtility now supports direct command execution without the TUI:

```bash
# Run commands directly
./netutil scan                    # Network enumeration
./netutil capture                 # Packet capture
./netutil vuln                    # Vulnerability scan

# Use numeric shortcuts
./netutil 1                       # Most common task (eg: network enum)
./netutil 2                       # Second most common (eg: capture)

# Fuzzy matching works too
./netutil cap                     # Matches "capture"
./netutil enum                    # Matches "enumeration"

# Get help and info
./netutil --help                  # Show help
./netutil --list                  # List all commands
./netutil --recent                # Show recent commands
```

### Bash Completion

Enable bash completion for better productivity:

```bash
# Install completion (add to ~/.bashrc)
source scripts/completion/netutil_completion.bash

# Or install system-wide
sudo cp scripts/completion/netutil_completion.bash /etc/bash_completion.d/netutil
```

With completion enabled, you can press Tab to autocomplete commands and options.

The interface is pretty straightforward - use arrow keys to navigate, tab to switch between panels, enter to select things, and escape to exit.

## How it works

Everything is organized into scripts that live in the `scripts/` directory. When you select a task, it runs the appropriate script and shows you the output in real-time. Results get saved to organized directories in your home folder.

The tool automatically handles privilege escalation when needed and has reasonable timeouts built in. If something goes wrong, it won't hang forever.

## Safety first

This tool is designed for legitimate security testing and network administration. All the vulnerability scanning uses safe, non-intrusive techniques - no brute force attacks or anything that might cause problems.

Always make sure you have permission before running these tools against any network or system that isn't yours.

## File structure

```
NetUtility/
├── cmd/netutil/           # Main application
├── internal/              # Go application logic
├── scripts/               # All the bash scripts organized by category
│   ├── system/           # Network configuration
│   ├── network/          # Reconnaissance tools
│   ├── vulnerability/    # Security assessment
│   └── config/           # Device configuration
└── README.md
```

## Contributing

Found a bug? Want to add a new script? Pull requests are welcome. The code is straightforward Go with a clean structure, and adding new scripts is pretty simple.

## License

MIT License - use it however you want, just don't blame me if something breaks.

---

**Important**: This is a tool for authorized security professionals. Don't use it on networks you don't own or don't have explicit permission to test. Be responsible.
