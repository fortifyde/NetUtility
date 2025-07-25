# NetUtility

A terminal-based network discovery and analysis toolkit for security professionals and network administrators. NetUtility helps you understand what's on your network through intelligent scanning, traffic analysis, and automated reconnaissance workflows.

## What it does

NetUtility makes network discovery easy by automating the tedious parts while giving you control over the important decisions. Point it at a network interface, and it will:

- Capture traffic to understand network layout and VLANs
- Intelligently configure interfaces based on what it finds
- Discover live hosts using multiple scanning techniques
- Categorize devices as Windows, Linux, or network appliances
- Generate organized reports with actionable information

The tool is designed around real-world workflows - whether you're assessing a new network, troubleshooting connectivity, or conducting security analysis.

## Core Features

**Intelligent Auto-Discovery**
- VLAN-aware network discovery that adapts to your environment
- Smart IP configuration based on captured traffic patterns
- Multi-phase scanning (ARP → ping → port discovery → categorization)
- Automatic interface configuration with user confirmation

**Network Analysis**
- Traffic capture with tshark/tcpdump integration
- VLAN extraction and analysis from packet captures
- Host categorization (Windows, Linux, network devices/appliances)
- Protocol analysis and security assessment

**System Management**
- Network interface configuration (IP addresses, VLANs, routing)
- DNS configuration and network backup/restore
- Working directory management for organized results
- Comprehensive logging and audit trails

**Security Assessment** 
- Safe vulnerability scanning with Nmap NSE scripts
- Deep port analysis with service detection
- Network device configuration backup and analysis
- Risk assessment with remediation recommendations

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

The interface is straightforward - use arrow keys to navigate, tab to switch between panels, enter to select tasks, and escape to exit.

## How it works

NetUtility is built around the concept of workflows rather than individual tools. When you run auto-discovery, for example, it:

1. **Captures traffic** to understand the network environment
2. **Analyzes VLANs** and determines network topology  
3. **Configures interfaces** intelligently based on findings
4. **Discovers hosts** using multiple scanning techniques
5. **Categorizes devices** into meaningful groups
6. **Generates reports** with actionable insights

Each workflow is implemented as shell scripts in the `scripts/` directory, organized by function (network, system, vulnerability, etc.). The Go-based TUI provides the interface, job management, and real-time output display.

Results are automatically organized in timestamped directories, and the tool handles privilege escalation when needed. If something goes wrong, it won't hang forever thanks to built-in timeouts.

## Safety first

This tool is designed for legitimate security testing and network administration. All the vulnerability scanning uses safe, non-intrusive techniques - no brute force attacks or anything that might cause problems.

Always make sure you have permission before running these tools against any network or system that isn't yours.

## Project Structure

```
NetUtility/
├── cmd/netutil/           # Main application entry point
├── internal/              # Core Go application logic
│   ├── app/              # Application framework and utilities
│   ├── config/           # Configuration management
│   ├── jobs/             # Background job execution
│   ├── metadata/         # Script metadata and registry
│   └── ui/               # Terminal user interface
├── scripts/               # Organized shell scripts by function
│   ├── advanced/         # Automated workflows (auto-discovery)
│   ├── network/          # Discovery and analysis tools
│   ├── system/           # Interface and network configuration
│   ├── vulnerability/    # Security assessment scripts
│   └── config/           # Device configuration management
└── README.md
```

## Contributing

Found a bug? Want to add a new script? Pull requests are welcome. The code is straightforward Go with a clean structure, and adding new scripts is pretty simple.

## License

MIT License - use it however you want, just don't blame me if something breaks.

---

**Important**: This is a tool for authorized security professionals. Don't use it on networks you don't own or don't have explicit permission to test. Be responsible.
