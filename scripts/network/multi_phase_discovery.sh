#!/bin/sh

# Multi-phase Network Discovery Workflow
# Comprehensive network discovery using multiple techniques in sequence
# Phase 1: ARP scan → Phase 2: Ping sweep → Phase 3: DNS lookup → Phase 4: Port scan → Phase 5: Categorization

. "$(dirname "$0")/../common/utils.sh"
. "$(dirname "$0")/../common/logging.sh"

echo "=== Multi-Phase Network Discovery ==="
echo

# Log script start
log_script_start "multi_phase_discovery.sh" "$@"

DISCOVERY_DIR="${NETUTIL_WORKDIR:-$HOME}/discovery"
TEMP_DIR=$(mktemp -d)

# Cleanup on exit
trap 'rm -rf "$TEMP_DIR"' EXIT

# Create discovery directory
mkdir -p "$DISCOVERY_DIR"

# Get current interface and network
echo "Available network interfaces:"
selected_interface=$(select_interface)

if [ -z "$selected_interface" ]; then
    echo "No interface selected"
    exit 1
fi

echo "Selected interface: $selected_interface"
log_info "Selected interface: $selected_interface"

# Check for VLAN interfaces and offer VLAN-aware discovery
echo
echo "Discovery mode options:"
echo "1. Standard discovery (single network)"
echo "2. VLAN-aware discovery (scan multiple VLANs)"
echo
read -p "Select discovery mode (1-2): " discovery_mode

case "$discovery_mode" in
    1)
        discovery_type="standard"
        # Get network range for standard discovery
        network_range=$(get_network_range "$selected_interface")
        if [ -z "$network_range" ]; then
            echo "Could not determine network range for $selected_interface"
            log_error "Could not determine network range for $selected_interface"
            # Prompt user for manual input instead of failing
            network_range=$(prompt_network_range)
            if [ -z "$network_range" ]; then
                echo "No network range provided. Exiting."
                exit 1
            fi
        fi
        echo "Network range: $network_range"
        log_info "Network range: $network_range"
        ;;
    2)
        discovery_type="vlan_aware"
        echo "VLAN-aware discovery selected"
        log_info "VLAN-aware discovery mode selected"
        
        # Check for existing VLAN interfaces
        vlan_interfaces=$(ip link show | grep "@$selected_interface:" | cut -d':' -f2 | tr -d ' ')
        if [ -n "$vlan_interfaces" ]; then
            echo "Found existing VLAN interfaces:"
            echo "$vlan_interfaces" | sed 's/^/  /'
            log_info "Found existing VLAN interfaces: $(echo "$vlan_interfaces" | tr '\n' ' ')"
        else
            echo "No existing VLAN interfaces found on $selected_interface"
            echo "You may need to create VLAN interfaces first using the vlans command"
            log_warn "No VLAN interfaces found for VLAN-aware discovery"
        fi
        
        # Get network ranges for all interfaces (including VLANs)
        network_ranges=""
        for interface in $selected_interface $vlan_interfaces; do
            range=$(get_network_range "$interface")
            if [ -n "$range" ]; then
                network_ranges="$network_ranges $range"
                echo "  $interface: $range"
            fi
        done
        
        if [ -z "$network_ranges" ]; then
            echo "No network ranges could be determined. Falling back to standard discovery."
            discovery_type="standard"
            network_range=$(get_network_range "$selected_interface")
            if [ -z "$network_range" ]; then
                echo "Could not determine network range for standard fallback either."
                # Prompt user for manual input
                network_range=$(prompt_network_range)
                if [ -z "$network_range" ]; then
                    echo "No network range provided. Exiting."
                    exit 1
                fi
            fi
        else
            echo "Will scan networks: $network_ranges"
            log_info "VLAN-aware discovery networks: $network_ranges"
        fi
        ;;
    *)
        echo "Invalid selection. Using standard discovery."
        discovery_type="standard"
        network_range=$(get_network_range "$selected_interface")
        if [ -z "$network_range" ]; then
            echo "Could not determine network range for $selected_interface"
            # Prompt user for manual input
            network_range=$(prompt_network_range)
            if [ -z "$network_range" ]; then
                echo "No network range provided. Exiting."
                exit 1
            fi
        fi
        ;;
esac

echo

# Create timestamped discovery session
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SESSION_DIR="$DISCOVERY_DIR/discovery_${TIMESTAMP}"
mkdir -p "$SESSION_DIR"

# Discovery report
REPORT_FILE="$SESSION_DIR/discovery_report.txt"

echo "=== Multi-Phase Network Discovery Report ===" > "$REPORT_FILE"
echo "Interface: $selected_interface" >> "$REPORT_FILE"
echo "Discovery type: $discovery_type" >> "$REPORT_FILE"
if [ "$discovery_type" = "standard" ]; then
    echo "Network: $network_range" >> "$REPORT_FILE"
else
    echo "Networks: $network_ranges" >> "$REPORT_FILE"
fi
echo "Discovery started: $(date)" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

if [ "$discovery_type" = "standard" ]; then
    echo "Starting multi-phase discovery on $network_range..."
    log_info "Starting multi-phase discovery on $network_range"
    target_networks="$network_range"
else
    echo "Starting VLAN-aware multi-phase discovery on multiple networks..."
    log_info "Starting VLAN-aware multi-phase discovery on networks: $network_ranges"
    target_networks="$network_ranges"
fi

# Phase 1: ARP Scan
echo "--- PHASE 1: ARP SCAN ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Phase 1: ARP Scan - Discovering active hosts on local network..."
> "$TEMP_DIR/arp_hosts.txt"

if [ "$discovery_type" = "vlan_aware" ]; then
    echo "Performing VLAN-aware ARP discovery..." >> "$REPORT_FILE"
    # Scan each VLAN interface separately
    for interface in $selected_interface $vlan_interfaces; do
        if [ -n "$interface" ]; then
            echo "  Scanning interface: $interface" >> "$REPORT_FILE"
            if command -v arp-scan >/dev/null 2>&1; then
                arp-scan --local --interface="$interface" 2>/dev/null | grep -E "([0-9]+\.){3}[0-9]+" | \
                    awk -v iface="$interface" '{print $1 "\t" $2 "\t" $3 "\t" iface}' >> "$REPORT_FILE"
                arp-scan --local --interface="$interface" 2>/dev/null | grep -E "([0-9]+\.){3}[0-9]+" | \
                    awk '{print $1}' >> "$TEMP_DIR/arp_hosts.txt"
            else
                ip neighbor show dev "$interface" | grep -E "([0-9]+\.){3}[0-9]+" | \
                    awk -v iface="$interface" '{print $1 "\t" $2 "\t" $3 "\t" iface}' >> "$REPORT_FILE"
                ip neighbor show dev "$interface" | grep -E "([0-9]+\.){3}[0-9]+" | \
                    awk '{print $1}' >> "$TEMP_DIR/arp_hosts.txt"
            fi
        fi
    done
else
    if command -v arp-scan >/dev/null 2>&1; then
        echo "Using arp-scan for Layer 2 discovery..." >> "$REPORT_FILE"
        arp-scan --local --interface="$selected_interface" | grep -E "([0-9]+\.){3}[0-9]+" | \
            awk '{print $1}' > "$TEMP_DIR/arp_hosts.txt"
        arp-scan --local --interface="$selected_interface" | grep -E "([0-9]+\.){3}[0-9]+" | \
            awk '{print $1 "\t" $2 "\t" $3}' >> "$REPORT_FILE"
    else
        echo "arp-scan not available, using IP neighbor discovery..." >> "$REPORT_FILE"
        ip neighbor show dev "$selected_interface" | grep -E "([0-9]+\.){3}[0-9]+" | \
            awk '{print $1}' > "$TEMP_DIR/arp_hosts.txt"
        ip neighbor show dev "$selected_interface" | grep -E "([0-9]+\.){3}[0-9]+" >> "$REPORT_FILE"
    fi
fi

arp_count=$(wc -l < "$TEMP_DIR/arp_hosts.txt")
echo >> "$REPORT_FILE"
echo "ARP scan complete. Found $arp_count hosts via ARP." >> "$REPORT_FILE"
log_network_operation "ARP scan" "$network_range" "Found $arp_count hosts"
echo >> "$REPORT_FILE"

# Phase 2: Ping Sweep
echo "--- PHASE 2: PING SWEEP ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Phase 2: Ping Sweep - Testing connectivity and OS fingerprinting..."
> "$TEMP_DIR/ping_hosts.txt"

if [ "$discovery_type" = "vlan_aware" ]; then
    echo "Performing VLAN-aware ping sweep..." >> "$REPORT_FILE"
    for network in $target_networks; do
        if [ -n "$network" ]; then
            echo "  Ping sweep on network: $network" >> "$REPORT_FILE"
            if command -v fping >/dev/null 2>&1; then
                fping -a -g "$network" 2>/dev/null >> "$TEMP_DIR/ping_hosts.txt"
            else
                # Extract network portion for ping sweep
                network_base=$(echo "$network" | cut -d'/' -f1 | cut -d'.' -f1-3)
                for i in $(seq 1 254); do
                    if ping -c 1 -W 1 "${network_base}.$i" >/dev/null 2>&1; then
                        echo "${network_base}.$i" >> "$TEMP_DIR/ping_hosts.txt"
                    fi
                done
            fi
        fi
    done
else
    if command -v fping >/dev/null 2>&1; then
        echo "Using fping for fast ping sweep..." >> "$REPORT_FILE"
        fping -a -g "$network_range" 2>/dev/null > "$TEMP_DIR/ping_hosts.txt"
    else
        echo "fping not available, using basic ping..." >> "$REPORT_FILE"
        # Extract network portion for ping sweep
        network_base=$(echo "$network_range" | cut -d'/' -f1 | cut -d'.' -f1-3)
        for i in $(seq 1 254); do
            if ping -c 1 -W 1 "${network_base}.$i" >/dev/null 2>&1; then
                echo "${network_base}.$i" >> "$TEMP_DIR/ping_hosts.txt"
            fi
        done
    fi
fi

# TTL-based OS fingerprinting
echo "TTL-based OS fingerprinting:" >> "$REPORT_FILE"
while read -r host; do
    if [ -n "$host" ]; then
        ttl=$(ping -c 1 -W 1 "$host" 2>/dev/null | grep "ttl=" | head -1 | sed 's/.*ttl=\([0-9]*\).*/\1/')
        if [ -n "$ttl" ]; then
            if [ "$ttl" -ge 240 ]; then
                os_guess="Windows (TTL ~255)"
            elif [ "$ttl" -ge 120 ]; then
                os_guess="Windows (TTL ~128)"
            elif [ "$ttl" -ge 60 ]; then
                os_guess="Linux/Unix (TTL ~64)"
            else
                os_guess="Unknown (TTL $ttl)"
            fi
            echo "$host\t$ttl\t$os_guess" >> "$REPORT_FILE"
        fi
    fi
done < "$TEMP_DIR/ping_hosts.txt"

ping_count=$(wc -l < "$TEMP_DIR/ping_hosts.txt")
echo >> "$REPORT_FILE"
echo "Ping sweep complete. Found $ping_count responsive hosts." >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Combine ARP and ping results
cat "$TEMP_DIR/arp_hosts.txt" "$TEMP_DIR/ping_hosts.txt" | sort -u > "$TEMP_DIR/all_hosts.txt"
all_hosts_count=$(wc -l < "$TEMP_DIR/all_hosts.txt")

echo "Combined discovery results: $all_hosts_count unique hosts" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Phase 3: DNS Reverse Lookup
echo "--- PHASE 3: DNS REVERSE LOOKUP ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Phase 3: DNS Reverse Lookup - Resolving hostnames..."
echo "IP Address\tHostname" >> "$REPORT_FILE"
echo "----------------------------" >> "$REPORT_FILE"

while read -r host; do
    if [ -n "$host" ]; then
        # Try reverse DNS lookup
        hostname=$(dig +short -x "$host" 2>/dev/null | sed 's/\.$//g')
        if [ -z "$hostname" ]; then
            hostname=$(nslookup "$host" 2>/dev/null | grep "name =" | head -1 | awk '{print $4}' | sed 's/\.$//g')
        fi
        if [ -z "$hostname" ]; then
            hostname="<no hostname>"
        fi
        echo "$host\t$hostname" >> "$REPORT_FILE"
        echo "$host\t$hostname" >> "$TEMP_DIR/dns_results.txt"
    fi
done < "$TEMP_DIR/all_hosts.txt"

echo >> "$REPORT_FILE"

# Phase 4: Windows-Specific Discovery
echo "--- PHASE 4: WINDOWS-SPECIFIC DISCOVERY ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Phase 4: Windows-Specific Discovery - SMB and NetBIOS enumeration..."

# SMB/NetBIOS discovery
echo "SMB/NetBIOS enumeration:" >> "$REPORT_FILE"
> "$TEMP_DIR/smb_hosts.txt"
> "$TEMP_DIR/netbios_names.txt"

while read -r host; do
    if [ -n "$host" ]; then
        # Test for SMB (port 445)
        if nc -z -w 2 "$host" 445 2>/dev/null; then
            echo "$host" >> "$TEMP_DIR/smb_hosts.txt"
            echo "  $host - SMB port 445 open" >> "$REPORT_FILE"
            
            # Try to get NetBIOS name using nmblookup
            if command -v nmblookup >/dev/null 2>&1; then
                netbios_name=$(nmblookup -A "$host" 2>/dev/null | grep "<00>" | head -1 | awk '{print $1}')
                if [ -n "$netbios_name" ]; then
                    echo "$host\t$netbios_name" >> "$TEMP_DIR/netbios_names.txt"
                    echo "    NetBIOS name: $netbios_name" >> "$REPORT_FILE"
                fi
            fi
            
            # Try to get SMB information using smbclient
            if command -v smbclient >/dev/null 2>&1; then
                smb_info=$(smbclient -L "$host" -N 2>/dev/null | grep "Workgroup\|Domain" | head -1)
                if [ -n "$smb_info" ]; then
                    echo "    $smb_info" >> "$REPORT_FILE"
                fi
            fi
        fi
        
        # Test for NetBIOS (port 139)
        if nc -z -w 2 "$host" 139 2>/dev/null; then
            echo "  $host - NetBIOS port 139 open" >> "$REPORT_FILE"
        fi
        
        # Test for WinRM (port 5985)
        if nc -z -w 2 "$host" 5985 2>/dev/null; then
            echo "  $host - WinRM port 5985 open" >> "$REPORT_FILE"
        fi
        
        # Test for RDP (port 3389)
        if nc -z -w 2 "$host" 3389 2>/dev/null; then
            echo "  $host - RDP port 3389 open" >> "$REPORT_FILE"
        fi
    fi
done < "$TEMP_DIR/all_hosts.txt"

smb_count=$(wc -l < "$TEMP_DIR/smb_hosts.txt")
echo >> "$REPORT_FILE"
echo "Found $smb_count hosts with SMB services" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Phase 5: Port Scan (Top ports only for speed)
echo "--- PHASE 5: PORT SCAN ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Phase 5: Port Scan - Identifying services on discovered hosts..."
if command -v nmap >/dev/null 2>&1; then
    echo "Using nmap for service detection..." >> "$REPORT_FILE"
    
    # Create nmap targets file
    tr '\n' ' ' < "$TEMP_DIR/all_hosts.txt" > "$TEMP_DIR/nmap_targets.txt"
    
    # Quick port scan of top 1000 ports
    nmap -n -sS --top-ports 1000 -T4 --open --reason -oN "$SESSION_DIR/nmap_results.txt" \
        -iL "$TEMP_DIR/all_hosts.txt" 2>/dev/null | \
        grep -E "Nmap scan report|open" >> "$REPORT_FILE"
    
    # Service detection on open ports
    echo >> "$REPORT_FILE"
    echo "Service detection results:" >> "$REPORT_FILE"
    nmap -n -sV --version-intensity 3 -T4 --open -oN "$SESSION_DIR/nmap_services.txt" \
        -iL "$TEMP_DIR/all_hosts.txt" 2>/dev/null | \
        grep -E "Nmap scan report|open" >> "$REPORT_FILE"
else
    echo "nmap not available, skipping detailed port scan" >> "$REPORT_FILE"
fi

echo >> "$REPORT_FILE"

# Phase 6: Host Categorization
echo "--- PHASE 6: HOST CATEGORIZATION ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Phase 6: Host Categorization - Analyzing discovered hosts..."

# Create categorized host lists
mkdir -p "$SESSION_DIR/categorized"

# Initialize category files
> "$SESSION_DIR/categorized/windows_hosts.txt"
> "$SESSION_DIR/categorized/linux_hosts.txt"
> "$SESSION_DIR/categorized/network_devices.txt"
> "$SESSION_DIR/categorized/web_servers.txt"
> "$SESSION_DIR/categorized/database_servers.txt"
> "$SESSION_DIR/categorized/unknown_hosts.txt"

# Categorize based on available information
while read -r host; do
    if [ -n "$host" ]; then
        category="unknown"
        
        # Check TTL-based OS detection
        ttl=$(ping -c 1 -W 1 "$host" 2>/dev/null | grep "ttl=" | head -1 | sed 's/.*ttl=\([0-9]*\).*/\1/')
        
        # Priority 1: Check Windows-specific discovery results
        if grep -q "^$host$" "$TEMP_DIR/smb_hosts.txt" 2>/dev/null; then
            category="windows"
            echo "$host" >> "$SESSION_DIR/categorized/windows_hosts.txt"
        # Priority 2: Check for common services (if nmap results exist)
        elif [ -f "$SESSION_DIR/nmap_services.txt" ]; then
            # Check for Windows-specific services
            if grep -A 50 "$host" "$SESSION_DIR/nmap_services.txt" | grep -qE "(microsoft|smb|netbios|rdp|3389|445|139)"; then
                category="windows"
                echo "$host" >> "$SESSION_DIR/categorized/windows_hosts.txt"
            # Check for web servers
            elif grep -A 50 "$host" "$SESSION_DIR/nmap_services.txt" | grep -qE "(http|80|443|8080|8443)"; then
                category="web_server"
                echo "$host" >> "$SESSION_DIR/categorized/web_servers.txt"
            # Check for database servers
            elif grep -A 50 "$host" "$SESSION_DIR/nmap_services.txt" | grep -qE "(mysql|postgresql|mssql|oracle|1433|3306|5432)"; then
                category="database"
                echo "$host" >> "$SESSION_DIR/categorized/database_servers.txt"
            # Check for network devices
            elif grep -A 50 "$host" "$SESSION_DIR/nmap_services.txt" | grep -qE "(snmp|ssh|telnet|161|22|23)"; then
                category="network_device"
                echo "$host" >> "$SESSION_DIR/categorized/network_devices.txt"
            # TTL-based categorization
            elif [ -n "$ttl" ] && [ "$ttl" -ge 120 ]; then
                category="windows"
                echo "$host" >> "$SESSION_DIR/categorized/windows_hosts.txt"
            elif [ -n "$ttl" ] && [ "$ttl" -ge 60 ] && [ "$ttl" -lt 120 ]; then
                category="linux"
                echo "$host" >> "$SESSION_DIR/categorized/linux_hosts.txt"
            else
                category="unknown"
                echo "$host" >> "$SESSION_DIR/categorized/unknown_hosts.txt"
            fi
        else
            # Fallback to TTL-based categorization only
            if [ -n "$ttl" ] && [ "$ttl" -ge 120 ]; then
                category="windows"
                echo "$host" >> "$SESSION_DIR/categorized/windows_hosts.txt"
            elif [ -n "$ttl" ] && [ "$ttl" -ge 60 ] && [ "$ttl" -lt 120 ]; then
                category="linux"
                echo "$host" >> "$SESSION_DIR/categorized/linux_hosts.txt"
            else
                category="unknown"
                echo "$host" >> "$SESSION_DIR/categorized/unknown_hosts.txt"
            fi
        fi
        
        # Get hostname for display
        hostname=$(grep "^$host" "$TEMP_DIR/dns_results.txt" | cut -f2)
        if [ -z "$hostname" ]; then
            hostname="<no hostname>"
        fi
        
        echo "$host\t$hostname\t$category" >> "$REPORT_FILE"
    fi
done < "$TEMP_DIR/all_hosts.txt"

echo >> "$REPORT_FILE"

# Summary statistics
echo "--- DISCOVERY SUMMARY ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

windows_count=$(wc -l < "$SESSION_DIR/categorized/windows_hosts.txt")
linux_count=$(wc -l < "$SESSION_DIR/categorized/linux_hosts.txt")
network_count=$(wc -l < "$SESSION_DIR/categorized/network_devices.txt")
web_count=$(wc -l < "$SESSION_DIR/categorized/web_servers.txt")
database_count=$(wc -l < "$SESSION_DIR/categorized/database_servers.txt")
unknown_count=$(wc -l < "$SESSION_DIR/categorized/unknown_hosts.txt")

echo "Discovery Statistics:" >> "$REPORT_FILE"
echo "  Total hosts discovered: $all_hosts_count" >> "$REPORT_FILE"
echo "  Windows hosts: $windows_count" >> "$REPORT_FILE"
echo "  Linux/Unix hosts: $linux_count" >> "$REPORT_FILE"
echo "  Network devices: $network_count" >> "$REPORT_FILE"
echo "  Web servers: $web_count" >> "$REPORT_FILE"
echo "  Database servers: $database_count" >> "$REPORT_FILE"
echo "  Unknown hosts: $unknown_count" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Discovery phases completed:" >> "$REPORT_FILE"
echo "  ✓ Phase 1: ARP Scan ($arp_count hosts)" >> "$REPORT_FILE"
echo "  ✓ Phase 2: Ping Sweep ($ping_count hosts)" >> "$REPORT_FILE"
echo "  ✓ Phase 3: DNS Lookup (completed)" >> "$REPORT_FILE"
echo "  ✓ Phase 4: Windows-Specific Discovery ($smb_count SMB hosts)" >> "$REPORT_FILE"
echo "  ✓ Phase 5: Port Scan (completed)" >> "$REPORT_FILE"
echo "  ✓ Phase 6: Categorization (completed)" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Discovery completed at $(date)" >> "$REPORT_FILE"

# Create summary files
echo "Creating summary files..."
cp "$TEMP_DIR/all_hosts.txt" "$SESSION_DIR/all_discovered_hosts.txt"
cp "$TEMP_DIR/dns_results.txt" "$SESSION_DIR/dns_results.txt"

# Copy Windows-specific discovery results
if [ -s "$TEMP_DIR/smb_hosts.txt" ]; then
    cp "$TEMP_DIR/smb_hosts.txt" "$SESSION_DIR/smb_hosts.txt"
fi
if [ -s "$TEMP_DIR/netbios_names.txt" ]; then
    cp "$TEMP_DIR/netbios_names.txt" "$SESSION_DIR/netbios_names.txt"
fi

echo
echo "Multi-phase discovery complete!"
echo "Results saved to: $SESSION_DIR"
log_info "Multi-phase discovery completed successfully"
log_info "Results saved to: $SESSION_DIR"
log_info "Discovery summary: $all_hosts_count total hosts, $windows_count Windows, $linux_count Linux/Unix, $network_count network devices"
echo
echo "Discovery Summary:"
if [ "$discovery_type" = "vlan_aware" ]; then
    echo "  Discovery mode: VLAN-aware (multiple networks)"
    echo "  Networks scanned: $target_networks"
else
    echo "  Discovery mode: Standard (single network)"
    echo "  Network scanned: $network_range"
fi
echo "  Total hosts discovered: $all_hosts_count"
echo "  SMB/Windows hosts found: $smb_count"
echo "  Windows hosts: $windows_count"
echo "  Linux/Unix hosts: $linux_count"
echo "  Network devices: $network_count"
echo "  Web servers: $web_count"
echo "  Database servers: $database_count"
echo "  Unknown hosts: $unknown_count"
echo
echo "Files created:"
echo "  - discovery_report.txt (detailed report)"
echo "  - all_discovered_hosts.txt (host list)"
echo "  - dns_results.txt (hostname resolutions)"
echo "  - categorized/ (categorized host lists)"
if [ -f "$SESSION_DIR/smb_hosts.txt" ]; then
    echo "  - smb_hosts.txt (SMB/Windows hosts)"
fi
if [ -f "$SESSION_DIR/netbios_names.txt" ]; then
    echo "  - netbios_names.txt (NetBIOS computer names)"
fi
if [ -f "$SESSION_DIR/nmap_results.txt" ]; then
    echo "  - nmap_results.txt (port scan results)"
    echo "  - nmap_services.txt (service detection)"
fi
echo
echo "Opening detailed report..."
echo
cat "$REPORT_FILE"

# Log script completion
log_script_end "multi_phase_discovery.sh" 0