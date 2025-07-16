# NetUtility

A terminal-based network security toolkit that puts all your favorite pentesting and system administration tools in one convenient place. If you're tired of remembering dozens of command-line switches and constantly switching between different tools, this is for you.

## What does it do?

NetUtility gives you a clean, organized menu system to run common network security tasks without having to remember all the syntax. It's designed for Kali Linux and focuses on the tools you actually use day-to-day.

Think of it as your network toolkit dashboard - select what you want to do, and it handles the heavy lifting while showing you real-time output.

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

You'll need Kali Linux with the standard tools (tshark, nmap, fping, ssh). Most of what you need is already there.

```bash
git clone https://github.com/fortifyde/NetUtility.git
cd NetUtility
go build -o netutil ./cmd/netutil
chmod +x scripts/*/*.sh
sudo ./netutil
```

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