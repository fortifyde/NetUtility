# NetUtility

A terminal-based toolkit for network security assessments. NetUtility automates discovery, host categorization, and initial scanning to establish a foundation for deeper analysis. It handles the mechanical work of network enumeration while organizing results for follow-on investigation.

## Purpose

Security assessments start with understanding what exists on the network. NetUtility addresses the complexity of VLAN discovery, interface configuration, and host classification through automated workflows. From initial packet capture through categorized findings, it provides structured output that feeds into manual analysis and specialized tooling.

This is a stepping stone, not a complete solution. It gets you from network connection to organized intelligence quickly, then hands off to your analysis workflow.

## Key Features

**Terminal Interface (TUI)**
Interactive menu system with background job execution. Run long-duration scans without blocking the interface. Monitor multiple concurrent operations with real-time output streaming. Navigate with keyboard shortcuts and manage jobs through a dedicated panel.

**Modular Script System**
Scripts are loaded dynamically through YAML metadata files. Each script defines its parameters, dependencies, and output patterns. Add new capabilities by dropping script files into the appropriate category directory. The TUI rebuilds its menus automatically.

**VLAN Discovery and Configuration**
Captures traffic to identify VLANs, then configures virtual interfaces for scanning. Suggests IP addresses based on observed network patterns. Runs discovery independently per VLAN, handling network segmentation without manual intervention.

**Host Categorization**
Analyzes open ports, service banners, and OS fingerprints to classify hosts as Windows, Linux, or network devices. Groups findings by category for targeted follow-up. Uses weighted scoring across multiple indicators rather than single-point identification.

**Session-Based Organization**
All scan results land in timestamped session directories. Maintains separation between different assessment runs. Generates reports automatically and preserves evidence with audit trails. The `latest/` symlink always points to the most recent session.

**Multi-Phase Discovery**
Eight-phase workflow progresses from topology mapping through service enumeration. Adapts scanning based on what previous phases found. Balances thoroughness against time by using progressive techniques (ICMP first, then TCP, finally comprehensive port scans for responsive hosts).

## How It Works

The toolkit contains six script categories: discovery, scanning, configuration, advanced workflows, utilities, and host-config. Each script has a companion `.meta.yaml` file describing its parameters and behavior.

The TUI reads these metadata files on startup and builds menus dynamically. When you select a script, the interface validates parameters, checks dependencies, and streams output to a viewer with scrollback. The job manager handles concurrent execution (default limit: 3 jobs) and allows backgrounding long-running operations.

Results go into structured directories under your working directory: `discovery/`, `captures/`, `port_and_security_scans/`, and others. Each session creates a timestamped subdirectory. Categorized host lists (Windows, Linux, network devices) feed into targeted scanning scripts.

## Architecture

- **Go-based TUI**: Built with tview/tcell for terminal rendering. Channel-based concurrency for job management and output streaming.
- **POSIX Shell Scripts**: Approximately 12,000 lines across 21 scripts. Work with bash, dash, zsh, and fish.
- **Metadata System**: YAML files define script parameters, validation rules, CLI shortcuts, and output patterns.
- **Correlation Engine**: Cross-references findings from different scan types and builds relationship maps.
- **OUI Database**: Vendor identification from MAC addresses for device fingerprinting.

## Getting Started

**Requirements:**
Linux system with Go 1.24+, nmap, tshark/tcpdump, fping, masscan (optional), and standard networking tools.

**Build:**
```bash
git clone https://github.com/fortifyde/NetUtility.git
cd NetUtility
go build -o netutil ./cmd/netutil
./netutil
```

**CLI Usage:**
Run scripts directly without the TUI using shortcuts defined in metadata files:
```bash
./netutil auto-discover    # Launch automated workflow
./netutil safe-scan        # Safe NSE enumeration
./netutil port-scan        # Full port discovery
```

Use `./netutil --help` to list all available commands and shortcuts.

## Sharing Scan Results

NetUtility includes an HTTP file server for sharing scan results with your team across VLANs. Run `sudo ./netutil setup-fileserver` to configure the service with authentication. The setup wizard creates user accounts, installs a systemd service, and displays access URLs (default port: 8080).

## Safety and Legal Notice

This toolkit generates network traffic and performs active scanning. Use only on networks you own or have explicit authorization to test. Unauthorized network scanning may violate computer fraud and abuse laws. The authors accept no liability for misuse.

## License

MIT License - See LICENSE file for details.
