#!/bin/sh

# Enhanced Multi-phase Network Discovery Workflow
# Comprehensive network discovery integrating ActiveRecon methodology
# Phase 1: ARP scan → Phase 2: Ping sweep → Phase 3: DNS lookup → Phase 4: Windows Discovery 
# Phase 5: Progressive Port Scan → Phase 6: Service Enumeration → Phase 7: Vulnerability Assessment 
# Phase 8: Host Categorization → Phase 9: Evidence Processing

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

# Parse command line arguments for non-interactive mode
# Usage: multi_phase_discovery.sh [interface] [discovery_mode]
# discovery_mode: 1=standard, 2=vlan_aware
provided_interface="$1"
provided_discovery_mode="$2"

# Get current interface and network
if [ -n "$provided_interface" ]; then
    selected_interface="$provided_interface"
    echo "Using provided interface: $selected_interface"
else
    echo "Available network interfaces:"
    selected_interface=$(select_interface)
    
    if [ -z "$selected_interface" ]; then
        echo "No interface selected"
        exit 1
    fi
fi

echo "Selected interface: $selected_interface"
log_info "Selected interface: $selected_interface"

# Check for VLAN interfaces and offer VLAN-aware discovery
echo
if [ -n "$provided_discovery_mode" ]; then
    discovery_mode="$provided_discovery_mode"
    echo "Using provided discovery mode: $discovery_mode"
else
    echo "Discovery mode options:"
    echo "1. Standard discovery (single network)"
    echo "2. VLAN-aware discovery (scan multiple VLANs)"
    echo
    echo "Select discovery mode (1-2): " >&2
    read discovery_mode
fi

case "$discovery_mode" in
    1)
        discovery_type="standard"
        # Check for manually specified network range first
        if [ -n "$MANUAL_NETWORK_RANGE" ]; then
            network_range="$MANUAL_NETWORK_RANGE"
            echo "Using manually specified network range: $network_range"
            log_info "Using manually specified network range: $network_range"
        else
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
        fi
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

# Enhanced fping function with better reliability and error handling
enhanced_fping_sweep() {
    local network="$1"
    local output_file="$2"
    local temp_output="$TEMP_DIR/fping_temp_$$"
    local temp_errors="$TEMP_DIR/fping_errors_$$"
    
    # Configuration for improved reliability
    local timeout=1000    # Timeout per ping in ms (1 second)
    local retries=2       # Number of retries per host
    local interval=10     # Interval between pings in ms
    local max_hosts=100   # Maximum concurrent hosts (reduce network load)
    
    echo "  Enhanced fping configuration:" >> "$REPORT_FILE"
    echo "    Network: $network" >> "$REPORT_FILE"
    echo "    Timeout: ${timeout}ms, Retries: $retries, Interval: ${interval}ms" >> "$REPORT_FILE"
    
    # Attempt 1: Standard enhanced fping with optimal settings
    echo "  Attempting fping sweep (standard mode)..." >> "$REPORT_FILE"
    if fping -a -g -t "$timeout" -r "$retries" -i "$interval" -q "$network" 2>"$temp_errors" >"$temp_output"; then
        # fping succeeded
        cat "$temp_output" >> "$output_file"
        hosts_found=$(wc -l < "$temp_output")
        echo "    Standard mode: Found $hosts_found hosts" >> "$REPORT_FILE"
        
        # Log any warnings (but not errors since we succeeded)
        if [ -s "$temp_errors" ] && ! grep -q "ICMP.*unreachable\|Permission denied" "$temp_errors"; then
            echo "    Warnings: $(head -3 "$temp_errors" | tr '\n' '; ')" >> "$REPORT_FILE"
        fi
        
        rm -f "$temp_output" "$temp_errors"
        return 0
    fi
    
    # Attempt 2: Fallback with relaxed settings for difficult networks
    echo "  Standard mode failed, trying compatibility mode..." >> "$REPORT_FILE"
    > "$temp_output"
    > "$temp_errors"
    
    # More conservative settings for difficult networks
    if fping -a -g -t 2000 -r 3 -i 50 -q "$network" 2>"$temp_errors" >"$temp_output"; then
        cat "$temp_output" >> "$output_file"
        hosts_found=$(wc -l < "$temp_output")
        echo "    Compatibility mode: Found $hosts_found hosts" >> "$REPORT_FILE"
        
        rm -f "$temp_output" "$temp_errors"
        return 0
    fi
    
    # Attempt 3: Check for common permission/network issues and provide guidance
    echo "  Compatibility mode failed, diagnosing issues..." >> "$REPORT_FILE"
    
    if grep -q "Operation not permitted\|Permission denied" "$temp_errors"; then
        echo "    Issue: Insufficient privileges for raw socket operations" >> "$REPORT_FILE"
        echo "    Recommendation: Run with elevated privileges or use unprivileged mode" >> "$REPORT_FILE"
        
        # Try unprivileged mode (uses UDP instead of ICMP)
        if command -v fping >/dev/null 2>&1 && fping -h 2>&1 | grep -q "\-S"; then
            echo "  Attempting unprivileged mode..." >> "$REPORT_FILE"
            if fping -a -g -S 0 -t 2000 -r 2 -q "$network" 2>/dev/null >"$temp_output"; then
                cat "$temp_output" >> "$output_file"
                hosts_found=$(wc -l < "$temp_output")
                echo "    Unprivileged mode: Found $hosts_found hosts" >> "$REPORT_FILE"
                
                rm -f "$temp_output" "$temp_errors"
                return 0
            fi
        fi
    elif grep -q "Network is unreachable\|No route to host" "$temp_errors"; then
        echo "    Issue: Network routing problem" >> "$REPORT_FILE"
        echo "    Recommendation: Check network configuration and routing table" >> "$REPORT_FILE"
    elif grep -q "Invalid argument\|Address family not supported" "$temp_errors"; then
        echo "    Issue: Network configuration or IPv6/IPv4 mismatch" >> "$REPORT_FILE"
        echo "    Recommendation: Verify network range format and system configuration" >> "$REPORT_FILE"
    else
        echo "    Issue: Unknown fping error" >> "$REPORT_FILE"
        echo "    Error details: $(head -2 "$temp_errors" | tr '\n' '; ')" >> "$REPORT_FILE"
    fi
    
    # Attempt 4: Final fallback with basic settings
    echo "  Final attempt with minimal options..." >> "$REPORT_FILE"
    > "$temp_output"
    if timeout 30 fping -a -g "$network" 2>/dev/null >"$temp_output"; then
        cat "$temp_output" >> "$output_file"
        hosts_found=$(wc -l < "$temp_output")
        echo "    Basic mode: Found $hosts_found hosts" >> "$REPORT_FILE"
        
        rm -f "$temp_output" "$temp_errors"
        return 0
    fi
    
    # Complete failure - log and return error
    echo "    All fping attempts failed - network may be unreachable or misconfigured" >> "$REPORT_FILE"
    rm -f "$temp_output" "$temp_errors"
    return 1
}

# Enhanced service categorization function
categorize_services_enhanced() {
    cd "$SESSION_DIR"
    
    # Create service category files
    > "$TEMP_DIR/ftp_targets.txt"
    > "$TEMP_DIR/ssh_targets.txt"
    > "$TEMP_DIR/telnet_targets.txt"
    > "$TEMP_DIR/smtp_targets.txt"
    > "$TEMP_DIR/dns_targets.txt"
    > "$TEMP_DIR/web_targets.txt"
    > "$TEMP_DIR/pop3_targets.txt"
    > "$TEMP_DIR/imap_targets.txt"
    > "$TEMP_DIR/smb_targets.txt"
    > "$TEMP_DIR/database_targets.txt"
    > "$TEMP_DIR/rdp_targets.txt"
    > "$TEMP_DIR/vnc_targets.txt"
    > "$TEMP_DIR/snmp_targets.txt"
    
    # Process all scan results
    for scan_file in "$SESSION_DIR"/nmap_*.txt; do
        if [ -f "$scan_file" ]; then
            # Extract services by port patterns
            grep "21/tcp.*open" "$scan_file" 2>/dev/null | grep "Nmap scan report" | awk '{print $5}' >> "$TEMP_DIR/ftp_targets.txt" || true
            grep "22/tcp.*open" "$scan_file" 2>/dev/null | grep "Nmap scan report" | awk '{print $5}' >> "$TEMP_DIR/ssh_targets.txt" || true
            grep "23/tcp.*open" "$scan_file" 2>/dev/null | grep "Nmap scan report" | awk '{print $5}' >> "$TEMP_DIR/telnet_targets.txt" || true
            grep -E "25/tcp.*open|587/tcp.*open|465/tcp.*open" "$scan_file" 2>/dev/null | grep "Nmap scan report" | awk '{print $5}' >> "$TEMP_DIR/smtp_targets.txt" || true
            grep -E "53/tcp.*open|53/udp.*open" "$scan_file" 2>/dev/null | grep "Nmap scan report" | awk '{print $5}' >> "$TEMP_DIR/dns_targets.txt" || true
            grep -E "80/tcp.*open|443/tcp.*open|8080/tcp.*open|8443/tcp.*open" "$scan_file" 2>/dev/null | grep "Nmap scan report" | awk '{print $5}' >> "$TEMP_DIR/web_targets.txt" || true
            grep -E "110/tcp.*open|995/tcp.*open" "$scan_file" 2>/dev/null | grep "Nmap scan report" | awk '{print $5}' >> "$TEMP_DIR/pop3_targets.txt" || true
            grep -E "143/tcp.*open|993/tcp.*open" "$scan_file" 2>/dev/null | grep "Nmap scan report" | awk '{print $5}' >> "$TEMP_DIR/imap_targets.txt" || true
            grep -E "135/tcp.*open|139/tcp.*open|445/tcp.*open" "$scan_file" 2>/dev/null | grep "Nmap scan report" | awk '{print $5}' >> "$TEMP_DIR/smb_targets.txt" || true
            grep -E "1433/tcp.*open|3306/tcp.*open|5432/tcp.*open|1521/tcp.*open|27017/tcp.*open" "$scan_file" 2>/dev/null | grep "Nmap scan report" | awk '{print $5}' >> "$TEMP_DIR/database_targets.txt" || true
            grep -E "3389/tcp.*open" "$scan_file" 2>/dev/null | grep "Nmap scan report" | awk '{print $5}' >> "$TEMP_DIR/rdp_targets.txt" || true
            grep -E "5900/tcp.*open" "$scan_file" 2>/dev/null | grep "Nmap scan report" | awk '{print $5}' >> "$TEMP_DIR/vnc_targets.txt" || true
            grep -E "161/udp.*open" "$scan_file" 2>/dev/null | grep "Nmap scan report" | awk '{print $5}' >> "$TEMP_DIR/snmp_targets.txt" || true
        fi
    done
    
    # Remove duplicates from each target file
    for target_file in "$TEMP_DIR"/*_targets.txt; do
        if [ -f "$target_file" ]; then
            sort -u "$target_file" -o "$target_file"
        fi
    done
    
    # Generate service distribution summary
    {
        echo "=== Enhanced Service Distribution Summary ==="
        echo "FTP Services: $(wc -l < "$TEMP_DIR/ftp_targets.txt")"
        echo "SSH Services: $(wc -l < "$TEMP_DIR/ssh_targets.txt")"
        echo "Telnet Services: $(wc -l < "$TEMP_DIR/telnet_targets.txt")"
        echo "SMTP Services: $(wc -l < "$TEMP_DIR/smtp_targets.txt")"
        echo "DNS Services: $(wc -l < "$TEMP_DIR/dns_targets.txt")"
        echo "Web Services: $(wc -l < "$TEMP_DIR/web_targets.txt")"
        echo "POP3 Services: $(wc -l < "$TEMP_DIR/pop3_targets.txt")"
        echo "IMAP Services: $(wc -l < "$TEMP_DIR/imap_targets.txt")"
        echo "SMB Services: $(wc -l < "$TEMP_DIR/smb_targets.txt")"
        echo "Database Services: $(wc -l < "$TEMP_DIR/database_targets.txt")"
        echo "RDP Services: $(wc -l < "$TEMP_DIR/rdp_targets.txt")"
        echo "VNC Services: $(wc -l < "$TEMP_DIR/vnc_targets.txt")"
        echo "SNMP Services: $(wc -l < "$TEMP_DIR/snmp_targets.txt")"
    } > service_summary_enhanced.txt
    
    echo "Enhanced service categorization completed" >> "$REPORT_FILE"
    cat service_summary_enhanced.txt >> "$REPORT_FILE"
}

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
                arp-scan --local --interface="$interface" 2>/dev/null | grep -v "Interface:" | grep -E "^([0-9]+\.){3}[0-9]+" | \
                    awk -v iface="$interface" '{print $1 "\t" $2 "\t" $3 "\t" iface}' >> "$REPORT_FILE"
                arp-scan --local --interface="$interface" 2>/dev/null | grep -v "Interface:" | grep -E "^([0-9]+\.){3}[0-9]+" | \
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
        arp-scan --local --interface="$selected_interface" | grep -v "Interface:" | grep -E "^([0-9]+\.){3}[0-9]+" | \
            awk '{print $1}' > "$TEMP_DIR/arp_hosts.txt"
        arp-scan --local --interface="$selected_interface" | grep -v "Interface:" | grep -E "^([0-9]+\.){3}[0-9]+" | \
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
                enhanced_fping_sweep "$network" "$TEMP_DIR/ping_hosts.txt"
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
        enhanced_fping_sweep "$network_range" "$TEMP_DIR/ping_hosts.txt"
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

# Phase 5: Progressive Port Scan
echo "--- PHASE 5: PROGRESSIVE PORT SCAN ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Phase 5: Progressive Port Scan - Multi-layered port discovery..."
if command -v nmap >/dev/null 2>&1; then
    echo "Using progressive scanning methodology..." >> "$REPORT_FILE"
    
    # Create nmap targets file
    tr '\n' ' ' < "$TEMP_DIR/all_hosts.txt" > "$TEMP_DIR/nmap_targets.txt"
    
    # Stage 1: Fast common port scan
    echo "  Stage 1: Fast common port scan..." >> "$REPORT_FILE"
    COMMON_PORTS="1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416,417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5987-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,8180-8181,8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8873,8888,8899,8994,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,13456,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389"
    
    nmap -n -sS -p "$COMMON_PORTS" -T4 --open --reason -oN "$SESSION_DIR/nmap_fast_scan.txt" \
        -iL "$TEMP_DIR/all_hosts.txt" 2>/dev/null | \
        grep -E "Nmap scan report|open" >> "$REPORT_FILE"
    
    # Extract high-value targets for comprehensive scanning
    echo "  Identifying high-value targets..." >> "$REPORT_FILE"
    grep -E "22/open|80/open|443/open|445/open|3389/open|21/open|23/open|25/open|53/open|135/open|139/open|1433/open|3306/open|5432/open" \
        "$SESSION_DIR/nmap_fast_scan.txt" 2>/dev/null | grep "Nmap scan report" | awk '{print $5}' | sort -u > "$TEMP_DIR/high_value_targets.txt" || true
    
    hv_count=$(wc -l < "$TEMP_DIR/high_value_targets.txt")
    echo "    High-value targets identified: $hv_count" >> "$REPORT_FILE"
    
    # Stage 2: Comprehensive scan on high-value targets
    if [ "$hv_count" -gt 0 ]; then
        echo "  Stage 2: Comprehensive scan on high-value targets..." >> "$REPORT_FILE"
        nmap -n -sS -p- --min-rate 5000 -T4 --open \
            -iL "$TEMP_DIR/high_value_targets.txt" -oN "$SESSION_DIR/nmap_comprehensive_scan.txt" 2>/dev/null || true
    fi
    
    # Stage 3: UDP scan on common ports
    echo "  Stage 3: UDP scan on common ports..." >> "$REPORT_FILE"
    nmap -n -sU --top-ports 100 -T4 --open \
        -iL "$TEMP_DIR/all_hosts.txt" -oN "$SESSION_DIR/nmap_udp_scan.txt" 2>/dev/null || true
    
    # Service categorization
    echo "  Categorizing discovered services..." >> "$REPORT_FILE"
    categorize_services_enhanced
    
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

# Update latest symlinks
update_latest_links "discovery" "$SESSION_DIR"

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