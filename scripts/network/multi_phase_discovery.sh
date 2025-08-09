#!/bin/sh

# Enhanced Multi-phase Network Discovery Workflow
# Comprehensive network discovery
# Phase 1: Enhanced Network Discovery (topology, infrastructure, DNS, segmentation, ARP)
# Phase 2: Comprehensive Host Discovery (ICMP, TCP bypass, UDP probes, masscan, early classification)
# Phase 3: DNS lookup → Phase 4: Windows Discovery → Phase 5: Progressive Port Scan
# Phase 6: Service Enumeration → Phase 7: Vulnerability Assessment → Phase 8: Host Categorization
# Phase 9: Evidence Processing

. "$(dirname "$0")/../common/utils.sh"
. "$(dirname "$0")/../common/logging.sh"

echo "=== Multi-Phase Network Discovery ==="
echo

# Log script start
log_script_start "multi_phase_discovery.sh" "$@"

DISCOVERY_DIR="${NETUTIL_WORKDIR:-$HOME}/discovery"

# Note: No temporary directory - all data stored in permanent evidence structure

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

# Create professional evidence directory structure
EVIDENCE_DIR="$SESSION_DIR/evidence"
mkdir -p "$EVIDENCE_DIR"/{phase1_network_discovery,phase2_host_discovery,phase3_dns_analysis,phase4_windows_discovery,phase5_port_scanning,phase6_service_enumeration,phase7_vulnerability_assessment,phase8_host_categorization,phase9_evidence_processing}
mkdir -p "$EVIDENCE_DIR"/{phase1_network_discovery,phase2_host_discovery,phase3_dns_analysis,phase4_windows_discovery,phase5_port_scanning,phase6_service_enumeration,phase7_vulnerability_assessment}/raw_scans
mkdir -p "$SESSION_DIR"/{service_targets,consolidated,reports}

# Define evidence directories for easy reference
PHASE1_DIR="$EVIDENCE_DIR/phase1_network_discovery"
PHASE2_DIR="$EVIDENCE_DIR/phase2_host_discovery"
PHASE3_DIR="$EVIDENCE_DIR/phase3_dns_analysis"
PHASE4_DIR="$EVIDENCE_DIR/phase4_windows_discovery"
PHASE5_DIR="$EVIDENCE_DIR/phase5_port_scanning"
PHASE6_DIR="$EVIDENCE_DIR/phase6_service_enumeration"
PHASE7_DIR="$EVIDENCE_DIR/phase7_vulnerability_assessment"
PHASE8_DIR="$EVIDENCE_DIR/phase8_host_categorization"
PHASE9_DIR="$EVIDENCE_DIR/phase9_evidence_processing"
SERVICE_TARGETS_DIR="$SESSION_DIR/service_targets"
CONSOLIDATED_DIR="$SESSION_DIR/consolidated"
REPORTS_DIR="$SESSION_DIR/reports"

# Discovery report
REPORT_FILE="$REPORTS_DIR/discovery_report.txt"

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

# Network topology discovery functions
discover_network_topology() {
    local target_networks="$1"
    local output_file="$2"
    
    echo "  Performing network topology discovery..." >> "$REPORT_FILE"
    
    # Gateway discovery for each network
    for network in $target_networks; do
        if [ -n "$network" ]; then
            echo "    Analyzing network: $network" >> "$REPORT_FILE"
            
            # Extract gateway IP (usually .1 or .254)
            network_base=$(echo "$network" | cut -d'/' -f1 | cut -d'.' -f1-3)
            
            # Test common gateway addresses
            for gateway_last in 1 254; do
                gateway_ip="${network_base}.${gateway_last}"
                if ping -c 1 -W 1 "$gateway_ip" >/dev/null 2>&1; then
                    echo "      Gateway detected: $gateway_ip" >> "$REPORT_FILE"
                    echo "$gateway_ip" >> "$output_file"
                    
                    # Try to get gateway MAC and vendor info
                    if command -v arp-scan >/dev/null 2>&1; then
                        gateway_mac=$(arp-scan -l 2>/dev/null | grep "$gateway_ip" | awk '{print $2}' | head -1)
                        if [ -n "$gateway_mac" ]; then
                            echo "        MAC: $gateway_mac" >> "$REPORT_FILE"
                        fi
                    fi
                fi
            done
            
            # Network boundary detection via traceroute
            if command -v traceroute >/dev/null 2>&1; then
                echo "      Tracing network boundaries..." >> "$REPORT_FILE"
                sample_ip="${network_base}.10"
                if traceroute -m 5 -w 2 "$sample_ip" 2>/dev/null | head -5 | tail -n +2 | \
                   grep -E "^[[:space:]]*[0-9]+" >/dev/null 2>&1; then
                    echo "        Network routing detected for $network" >> "$REPORT_FILE"
                fi
            fi
        fi
    done
}

# Reverse DNS enumeration
perform_reverse_dns_enumeration() {
    local network="$1"
    local output_file="$2"
    
    echo "  Performing reverse DNS enumeration..." >> "$REPORT_FILE"
    
    network_base=$(echo "$network" | cut -d'/' -f1 | cut -d'.' -f1-3)
    reverse_dns_found=0
    
    # Sample reverse DNS lookups to identify naming patterns
    for i in 1 10 50 100 254; do
        test_ip="${network_base}.$i"
        if command -v dig >/dev/null 2>&1; then
            reverse_result=$(dig -x "$test_ip" +short 2>/dev/null | head -1)
        elif command -v nslookup >/dev/null 2>&1; then
            reverse_result=$(nslookup "$test_ip" 2>/dev/null | grep "name =" | cut -d'=' -f2 | tr -d ' ' | head -1)
        else
            continue
        fi
        
        if [ -n "$reverse_result" ] && [ "$reverse_result" != "$test_ip" ]; then
            echo "      Reverse DNS: $test_ip -> $reverse_result" >> "$REPORT_FILE"
            echo "$test_ip" >> "$output_file"
            reverse_dns_found=$((reverse_dns_found + 1))
        fi
    done
    
    if [ $reverse_dns_found -gt 0 ]; then
        echo "    Found $reverse_dns_found hosts with reverse DNS entries" >> "$REPORT_FILE"
    else
        echo "    No reverse DNS entries detected in sample" >> "$REPORT_FILE"
    fi
}

# Network device identification via SNMP
identify_network_devices() {
    local target_networks="$1"
    local output_file="$2"
    
    echo "  Identifying network infrastructure devices..." >> "$REPORT_FILE"
    
    if ! command -v nmap >/dev/null 2>&1; then
        echo "    nmap not available, skipping SNMP device discovery" >> "$REPORT_FILE"
        return
    fi
    
    # Quick SNMP scan for network devices
    for network in $target_networks; do
        if [ -n "$network" ]; then
            echo "    SNMP scan on $network..." >> "$REPORT_FILE"
            
            # Use nmap to find SNMP services quickly
            snmp_output="$PHASE1_DIR/raw_scans/snmp_scan_${network//\//_}_$$.txt"
            if nmap -sU -p161 --open --host-timeout 10s --min-rate 1000 "$network" \
                  -oG "$snmp_output" >/dev/null 2>&1; then
                
                # Extract hosts with SNMP
                snmp_hosts=$(grep "161/open" "$snmp_output" 2>/dev/null | awk '{print $2}' | sort -u)
                
                if [ -n "$snmp_hosts" ]; then
                    echo "      Found SNMP services on:" >> "$REPORT_FILE"
                    echo "$snmp_hosts" | while read -r snmp_host; do
                        echo "        $snmp_host" >> "$REPORT_FILE"
                        echo "$snmp_host" >> "$output_file"
                        
                        # Try to get system description if possible
                        if command -v snmpwalk >/dev/null 2>&1; then
                            sys_desc=$(timeout 5 snmpwalk -c public -v1 "$snmp_host" 1.3.6.1.2.1.1.1.0 2>/dev/null | \
                                      cut -d':' -f2- | tr -d '"' | head -1)
                            if [ -n "$sys_desc" ]; then
                                echo "          System: $sys_desc" >> "$REPORT_FILE"
                            fi
                        fi
                    done
                else
                    echo "      No SNMP services detected" >> "$REPORT_FILE"
                fi
                
                rm -f "$snmp_output"
            fi
        fi
    done
}

# TCP discovery with firewall bypass techniques
perform_tcp_discovery() {
    local target_networks="$1"
    local output_file="$2"
    
    echo "  Performing TCP discovery with firewall bypass..." >> "$REPORT_FILE"
    
    if ! command -v nmap >/dev/null 2>&1; then
        echo "    nmap not available, skipping TCP discovery" >> "$REPORT_FILE"
        return
    fi
    
    # Common ports that often pass through firewalls
    tcp_ports="21,22,25,53,80,135,139,443,445,993,995,3389,5900"
    
    for network in $target_networks; do
        if [ -n "$network" ]; then
            echo "    TCP SYN discovery on $network..." >> "$REPORT_FILE"
            
            tcp_output="$PHASE2_DIR/raw_scans/tcp_discovery_${network//\//_}_$$.txt"
            
            # Use TCP SYN ping to bypass ICMP filtering
            if nmap -sn -PS"$tcp_ports" --min-rate 1000 --host-timeout 30s \
                  "$network" -oG "$tcp_output" >/dev/null 2>&1; then
                
                # Extract responding hosts
                tcp_hosts=$(grep "Up" "$tcp_output" 2>/dev/null | awk '{print $2}' | sort -u)
                
                if [ -n "$tcp_hosts" ]; then
                    echo "      TCP-responsive hosts:" >> "$REPORT_FILE"
                    echo "$tcp_hosts" | while read -r tcp_host; do
                        echo "        $tcp_host" >> "$REPORT_FILE"
                        echo "$tcp_host" >> "$output_file"
                    done
                    
                    tcp_count=$(echo "$tcp_hosts" | wc -l)
                    echo "      Found $tcp_count hosts via TCP discovery" >> "$REPORT_FILE"
                else
                    echo "      No TCP-responsive hosts found" >> "$REPORT_FILE"
                fi
                
                rm -f "$tcp_output"
            else
                echo "      TCP discovery failed on $network" >> "$REPORT_FILE"
            fi
        fi
    done
}

# UDP discovery for common services
perform_udp_discovery() {
    local target_networks="$1"
    local output_file="$2"
    
    echo "  Performing UDP service discovery..." >> "$REPORT_FILE"
    
    if ! command -v nmap >/dev/null 2>&1; then
        echo "    nmap not available, skipping UDP discovery" >> "$REPORT_FILE"
        return
    fi
    
    # Common UDP services that respond to probes
    udp_ports="53,67,68,137,161,500,514,1434"
    
    for network in $target_networks; do
        if [ -n "$network" ]; then
            echo "    UDP service probe on $network..." >> "$REPORT_FILE"
            
            udp_output="$PHASE2_DIR/raw_scans/udp_discovery_${network//\//_}_$$.txt"
            
            # Use UDP ping for service discovery
            if nmap -sn -PU"$udp_ports" --min-rate 500 --host-timeout 45s \
                  "$network" -oG "$udp_output" >/dev/null 2>&1; then
                
                # Extract responding hosts
                udp_hosts=$(grep "Up" "$udp_output" 2>/dev/null | awk '{print $2}' | sort -u)
                
                if [ -n "$udp_hosts" ]; then
                    echo "      UDP-responsive hosts:" >> "$REPORT_FILE"
                    echo "$udp_hosts" | while read -r udp_host; do
                        echo "        $udp_host" >> "$REPORT_FILE"
                        echo "$udp_host" >> "$output_file"
                    done
                    
                    udp_count=$(echo "$udp_hosts" | wc -l)
                    echo "      Found $udp_count hosts via UDP discovery" >> "$REPORT_FILE"
                else
                    echo "      No UDP-responsive hosts found" >> "$REPORT_FILE"
                fi
                
                rm -f "$udp_output"
            else
                echo "      UDP discovery failed on $network" >> "$REPORT_FILE"
            fi
        fi
    done
}

# High-speed discovery using masscan (if available)
perform_masscan_discovery() {
    local target_networks="$1"
    local output_file="$2"
    
    echo "  Attempting high-speed discovery with masscan..." >> "$REPORT_FILE"
    
    if ! command -v masscan >/dev/null 2>&1; then
        echo "    masscan not available, skipping high-speed discovery" >> "$REPORT_FILE"
        return
    fi
    
    for network in $target_networks; do
        if [ -n "$network" ]; then
            echo "    Masscan sweep on $network..." >> "$REPORT_FILE"
            
            masscan_output="$PHASE2_DIR/raw_scans/masscan_discovery_${network//\//_}_$$.txt"
            
            # High-speed scan of top ports
            if masscan -p80,443,22,21,25,53,135,139,445 "$network" \
                  --rate=1000 --open -oG "$masscan_output" >/dev/null 2>&1; then
                
                # Extract hosts with open ports
                masscan_hosts=$(grep "open" "$masscan_output" 2>/dev/null | awk '{print $2}' | sort -u)
                
                if [ -n "$masscan_hosts" ]; then
                    echo "      Masscan discovered hosts:" >> "$REPORT_FILE"
                    echo "$masscan_hosts" | while read -r masscan_host; do
                        echo "        $masscan_host" >> "$REPORT_FILE"
                        echo "$masscan_host" >> "$output_file"
                    done
                    
                    masscan_count=$(echo "$masscan_hosts" | wc -l)
                    echo "      Found $masscan_count hosts via masscan" >> "$REPORT_FILE"
                else
                    echo "      No hosts found via masscan" >> "$REPORT_FILE"
                fi
                
                rm -f "$masscan_output"
            else
                echo "      Masscan failed on $network" >> "$REPORT_FILE"
            fi
        fi
    done
}

# IPv6 Network Discovery - Integration with refactored IPv6 script
perform_ipv6_discovery() {
    local interface="$1"
    local output_file="$2"
    
    echo "  Performing IPv6 network discovery..." >> "$REPORT_FILE"
    
    # Check if IPv6 is available on the interface
    if ! ip -6 addr show "$interface" | grep -q "inet6"; then
        echo "    No IPv6 addresses found on $interface, skipping IPv6 discovery" >> "$REPORT_FILE"
        return 0
    fi
    
    # Source the IPv6 discovery script to load the function
    . "$(dirname "$0")/ipv6_discovery.sh"
    
    # Call the IPv6 discovery function with our evidence directory
    perform_ipv6_discovery_main "$interface" "$EVIDENCE_DIR"
    
    # Extract discovered IPv6 hosts for integration into our workflow
    IPV6_HOSTS_FILE="$EVIDENCE_DIR/ipv6_discovery/discovered_ipv6_hosts.txt"
    if [ -f "$IPV6_HOSTS_FILE" ] && [ -s "$IPV6_HOSTS_FILE" ]; then
        cat "$IPV6_HOSTS_FILE" >> "$output_file"
        ipv6_count=$(wc -l < "$IPV6_HOSTS_FILE")
        echo "    Found $ipv6_count unique IPv6 addresses" >> "$REPORT_FILE"
        
        if [ "$ipv6_count" -gt 0 ]; then
            echo "    Sample IPv6 discoveries:" >> "$REPORT_FILE"
            head -3 "$IPV6_HOSTS_FILE" | sed 's/^/      /' >> "$REPORT_FILE"
        fi
        
        echo "    IPv6 evidence saved to: evidence/ipv6_discovery/" >> "$REPORT_FILE"
    else
        echo "    No IPv6 hosts discovered" >> "$REPORT_FILE"
    fi
    
    # Remove duplicates from output
    if [ -s "$output_file" ]; then
        sort -u "$output_file" -o "$output_file"
    fi
}

# Early OS detection and device classification
perform_early_os_detection() {
    local host_file="$1"
    local output_file="$2"
    
    echo "  Performing early OS detection and device classification..." >> "$REPORT_FILE"
    
    if ! command -v nmap >/dev/null 2>&1; then
        echo "    nmap not available, skipping OS detection" >> "$REPORT_FILE"
        return
    fi
    
    if [ ! -f "$host_file" ] || [ ! -s "$host_file" ]; then
        echo "    No hosts available for OS detection" >> "$REPORT_FILE"
        return
    fi
    
    # Sample a subset of hosts for OS detection to avoid overwhelming the scan
    sample_hosts="$PHASE2_DIR/os_sample_hosts.txt"
    head -10 "$host_file" > "$sample_hosts"
    
    if [ -s "$sample_hosts" ]; then
        echo "    OS fingerprinting sample hosts..." >> "$REPORT_FILE"
        
        os_output="$PHASE2_DIR/raw_scans/os_detection_$$.txt"
        
        # Quick OS detection with reasonable timeouts
        if nmap -O --osscan-guess --host-timeout 45s --max-retries 2 \
              -iL "$sample_hosts" -oN "$os_output" >/dev/null 2>&1; then
            
            # Process OS detection results
            while IFS= read -r line; do
                if echo "$line" | grep -q "Nmap scan report for"; then
                    current_host=$(echo "$line" | awk '{print $5}')
                elif echo "$line" | grep -q "Running:"; then
                    os_info=$(echo "$line" | sed 's/Running: //')
                    if [ -n "$current_host" ] && [ -n "$os_info" ]; then
                        echo "      $current_host: $os_info" >> "$REPORT_FILE"
                        echo "$current_host	$os_info" >> "$output_file"
                    fi
                fi
            done < "$os_output"
            
            rm -f "$os_output"
        else
            echo "    OS detection scan failed or incomplete" >> "$REPORT_FILE"
        fi
        
        rm -f "$sample_hosts"
    fi
}

# Early device classification via quick service probes
perform_early_device_classification() {
    local host_file="$1" 
    local output_file="$2"
    
    echo "  Performing early device classification..." >> "$REPORT_FILE"
    
    if ! command -v nmap >/dev/null 2>&1; then
        echo "    nmap not available, skipping device classification" >> "$REPORT_FILE"
        return
    fi
    
    if [ ! -f "$host_file" ] || [ ! -s "$host_file" ]; then
        echo "    No hosts available for device classification" >> "$REPORT_FILE"
        return
    fi
    
    # Quick classification scan focusing on identifying key device types
    device_output="$PHASE2_DIR/raw_scans/device_classification_$$.txt"
    
    # Scan for key ports that indicate device types
    classification_ports="22,23,80,135,139,161,443,445,623,5900"
    
    echo "    Quick service classification scan..." >> "$REPORT_FILE"
    
    if nmap -sS -p"$classification_ports" --open --host-timeout 30s \
          -iL "$host_file" -oG "$device_output" >/dev/null 2>&1; then
        
        # Analyze results for device classification
        while IFS= read -r line; do
            if echo "$line" | grep -q "Host:.*Ports:"; then
                host=$(echo "$line" | awk '{print $2}')
                ports=$(echo "$line" | cut -d':' -f3-)
                
                device_type="unknown"
                confidence="low"
                indicators=""
                
                # Windows indicators
                if echo "$ports" | grep -q "135/open\|139/open\|445/open"; then
                    device_type="windows_host"
                    confidence="medium"
                    indicators="SMB/RPC services"
                # Linux/Unix indicators  
                elif echo "$ports" | grep -q "22/open" && ! echo "$ports" | grep -q "135/open\|139/open"; then
                    device_type="linux_host"
                    confidence="medium"
                    indicators="SSH service"
                # Network device indicators
                elif echo "$ports" | grep -q "23/open\|161/open"; then
                    device_type="network_device"
                    confidence="medium"  
                    indicators="Telnet/SNMP management"
                # Server management indicators
                elif echo "$ports" | grep -q "623/open\|5900/open"; then
                    device_type="server_management"
                    confidence="medium"
                    indicators="IPMI/VNC management"
                # Web-based device
                elif echo "$ports" | grep -q "80/open\|443/open"; then
                    device_type="web_device"
                    confidence="low"
                    indicators="Web interface"
                fi
                
                if [ "$device_type" != "unknown" ]; then
                    echo "      $host: $device_type ($confidence confidence) - $indicators" >> "$REPORT_FILE"
                    echo "$host	$device_type	$confidence	$indicators" >> "$output_file"
                fi
            fi
        done < "$device_output"
        
        rm -f "$device_output"
    else
        echo "    Device classification scan failed" >> "$REPORT_FILE"
    fi
}

# Network segmentation analysis
analyze_network_segmentation() {
    local target_networks="$1"
    local output_file="$2"
    
    echo "  Analyzing network segmentation and reachability..." >> "$REPORT_FILE"
    
    # Analyze subnet reachability
    echo "    Testing subnet reachability patterns..." >> "$REPORT_FILE"
    
    # Test common private network ranges for reachability
    test_ranges="10.0.0.0/24 10.1.0.0/24 172.16.0.0/24 172.16.1.0/24 192.168.0.0/24 192.168.1.0/24 192.168.10.0/24 192.168.100.0/24"
    reachable_subnets=0
    
    for test_range in $test_ranges; do
        # Extract the first IP of the range for testing
        test_ip=$(echo "$test_range" | cut -d'/' -f1 | cut -d'.' -f1-3).1
        
        # Quick connectivity test
        if ping -c 1 -W 1 "$test_ip" >/dev/null 2>&1; then
            echo "      Reachable subnet detected: $test_range (via $test_ip)" >> "$REPORT_FILE"
            echo "$test_range" >> "$output_file"
            reachable_subnets=$((reachable_subnets + 1))
        fi
    done
    
    if [ $reachable_subnets -eq 0 ]; then
        echo "      No additional subnets detected in common ranges" >> "$REPORT_FILE"
    else
        echo "      Found $reachable_subnets potentially reachable subnets" >> "$REPORT_FILE"
    fi
    
    # VLAN discovery enhancement (if VLAN-aware mode)
    if [ "$discovery_type" = "vlan_aware" ]; then
        echo "    Enhanced VLAN analysis..." >> "$REPORT_FILE"
        
        # Check for additional VLAN interfaces that might have been created
        current_vlans=$(ip link show | grep "@$selected_interface:" | wc -l)
        echo "      Active VLAN interfaces: $current_vlans" >> "$REPORT_FILE"
        
        # Look for CDP/LLDP information if tools are available
        if command -v lldpctl >/dev/null 2>&1; then
            echo "      Gathering LLDP neighbor information..." >> "$REPORT_FILE"
            lldp_neighbors=$(lldpctl 2>/dev/null | grep -c "Interface:" || echo 0)
            if [ "$lldp_neighbors" -gt 0 ]; then
                echo "        LLDP neighbors detected: $lldp_neighbors" >> "$REPORT_FILE"
                lldpctl 2>/dev/null | grep -A5 "Interface:" | head -20 >> "$REPORT_FILE" || true
            else
                echo "        No LLDP neighbors detected" >> "$REPORT_FILE"
            fi
        fi
    fi
    
    # Routing analysis
    echo "    Analyzing routing information..." >> "$REPORT_FILE"
    
    # Check routing table for insights into network segmentation
    if command -v ip >/dev/null 2>&1; then
        routes_count=$(ip route show | grep -v "linkdown" | wc -l)
        echo "      Active routes: $routes_count" >> "$REPORT_FILE"
        
        # Show key routing information
        ip route show | grep -E "default via|192\.168\.|10\.|172\." | head -5 | while read -r route; do
            echo "        $route" >> "$REPORT_FILE"
        done
    fi
    
    # Network boundary detection via traceroute sampling
    if command -v traceroute >/dev/null 2>&1 && [ -n "$target_networks" ]; then
        echo "    Sampling network boundaries..." >> "$REPORT_FILE"
        
        # Pick a sample network for boundary testing
        sample_network=$(echo "$target_networks" | awk '{print $1}')
        if [ -n "$sample_network" ]; then
            sample_ip=$(echo "$sample_network" | cut -d'/' -f1 | cut -d'.' -f1-3).10
            
            echo "      Tracing path to $sample_ip..." >> "$REPORT_FILE"
            traceroute_output=$(traceroute -m 5 -w 2 "$sample_ip" 2>/dev/null | head -5)
            
            if [ -n "$traceroute_output" ]; then
                hops=$(echo "$traceroute_output" | grep -c "^[[:space:]]*[0-9]")
                echo "        Network hops to target: $hops" >> "$REPORT_FILE"
                
                # Look for potential network boundaries (different subnets in path)
                echo "$traceroute_output" | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | \
                head -3 | while read -r hop_ip; do
                    echo "          Hop: $hop_ip" >> "$REPORT_FILE"
                done
            fi
        fi
    fi
}

# Enhanced fping function with better reliability and error handling
enhanced_fping_sweep() {
    local network="$1"
    local output_file="$2"
    local temp_output="$PHASE2_DIR/raw_scans/fping_temp_$$"
    local temp_errors="$PHASE2_DIR/raw_scans/fping_errors_$$"
    
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
    > "$SERVICE_TARGETS_DIR/ftp_targets.txt"
    > "$SERVICE_TARGETS_DIR/ssh_targets.txt"
    > "$SERVICE_TARGETS_DIR/telnet_targets.txt"
    > "$SERVICE_TARGETS_DIR/smtp_targets.txt"
    > "$SERVICE_TARGETS_DIR/dns_targets.txt"
    > "$SERVICE_TARGETS_DIR/web_targets.txt"
    > "$SERVICE_TARGETS_DIR/pop3_targets.txt"
    > "$SERVICE_TARGETS_DIR/imap_targets.txt"
    > "$SERVICE_TARGETS_DIR/smb_targets.txt"
    > "$SERVICE_TARGETS_DIR/database_targets.txt"
    > "$SERVICE_TARGETS_DIR/rdp_targets.txt"
    > "$SERVICE_TARGETS_DIR/vnc_targets.txt"
    > "$SERVICE_TARGETS_DIR/snmp_targets.txt"
    
    # Process all scan results
    for scan_file in "$SESSION_DIR"/nmap_*.txt; do
        if [ -f "$scan_file" ]; then
            # Extract services by port patterns
            grep "21/tcp.*open" "$scan_file" 2>/dev/null | grep "Nmap scan report" | awk '{print $5}' >> "$SERVICE_TARGETS_DIR/ftp_targets.txt" || true
            grep "22/tcp.*open" "$scan_file" 2>/dev/null | grep "Nmap scan report" | awk '{print $5}' >> "$SERVICE_TARGETS_DIR/ssh_targets.txt" || true
            grep "23/tcp.*open" "$scan_file" 2>/dev/null | grep "Nmap scan report" | awk '{print $5}' >> "$SERVICE_TARGETS_DIR/telnet_targets.txt" || true
            grep -E "25/tcp.*open|587/tcp.*open|465/tcp.*open" "$scan_file" 2>/dev/null | grep "Nmap scan report" | awk '{print $5}' >> "$SERVICE_TARGETS_DIR/smtp_targets.txt" || true
            grep -E "53/tcp.*open|53/udp.*open" "$scan_file" 2>/dev/null | grep "Nmap scan report" | awk '{print $5}' >> "$SERVICE_TARGETS_DIR/dns_targets.txt" || true
            grep -E "80/tcp.*open|443/tcp.*open|8080/tcp.*open|8443/tcp.*open" "$scan_file" 2>/dev/null | grep "Nmap scan report" | awk '{print $5}' >> "$SERVICE_TARGETS_DIR/web_targets.txt" || true
            grep -E "110/tcp.*open|995/tcp.*open" "$scan_file" 2>/dev/null | grep "Nmap scan report" | awk '{print $5}' >> "$SERVICE_TARGETS_DIR/pop3_targets.txt" || true
            grep -E "143/tcp.*open|993/tcp.*open" "$scan_file" 2>/dev/null | grep "Nmap scan report" | awk '{print $5}' >> "$SERVICE_TARGETS_DIR/imap_targets.txt" || true
            grep -E "135/tcp.*open|139/tcp.*open|445/tcp.*open" "$scan_file" 2>/dev/null | grep "Nmap scan report" | awk '{print $5}' >> "$SERVICE_TARGETS_DIR/smb_targets.txt" || true
            grep -E "1433/tcp.*open|3306/tcp.*open|5432/tcp.*open|1521/tcp.*open|27017/tcp.*open" "$scan_file" 2>/dev/null | grep "Nmap scan report" | awk '{print $5}' >> "$SERVICE_TARGETS_DIR/database_targets.txt" || true
            grep -E "3389/tcp.*open" "$scan_file" 2>/dev/null | grep "Nmap scan report" | awk '{print $5}' >> "$SERVICE_TARGETS_DIR/rdp_targets.txt" || true
            grep -E "5900/tcp.*open" "$scan_file" 2>/dev/null | grep "Nmap scan report" | awk '{print $5}' >> "$SERVICE_TARGETS_DIR/vnc_targets.txt" || true
            grep -E "161/udp.*open" "$scan_file" 2>/dev/null | grep "Nmap scan report" | awk '{print $5}' >> "$SERVICE_TARGETS_DIR/snmp_targets.txt" || true
        fi
    done
    
    # Remove duplicates from each target file
    for target_file in "$SERVICE_TARGETS_DIR"/*_targets.txt; do
        if [ -f "$target_file" ]; then
            sort -u "$target_file" -o "$target_file"
        fi
    done
    
    # Generate service distribution summary
    {
        echo "=== Enhanced Service Distribution Summary ==="
        echo "FTP Services: $(wc -l < "$SERVICE_TARGETS_DIR/ftp_targets.txt")"
        echo "SSH Services: $(wc -l < "$SERVICE_TARGETS_DIR/ssh_targets.txt")"
        echo "Telnet Services: $(wc -l < "$SERVICE_TARGETS_DIR/telnet_targets.txt")"
        echo "SMTP Services: $(wc -l < "$SERVICE_TARGETS_DIR/smtp_targets.txt")"
        echo "DNS Services: $(wc -l < "$SERVICE_TARGETS_DIR/dns_targets.txt")"
        echo "Web Services: $(wc -l < "$SERVICE_TARGETS_DIR/web_targets.txt")"
        echo "POP3 Services: $(wc -l < "$SERVICE_TARGETS_DIR/pop3_targets.txt")"
        echo "IMAP Services: $(wc -l < "$SERVICE_TARGETS_DIR/imap_targets.txt")"
        echo "SMB Services: $(wc -l < "$SERVICE_TARGETS_DIR/smb_targets.txt")"
        echo "Database Services: $(wc -l < "$SERVICE_TARGETS_DIR/database_targets.txt")"
        echo "RDP Services: $(wc -l < "$SERVICE_TARGETS_DIR/rdp_targets.txt")"
        echo "VNC Services: $(wc -l < "$SERVICE_TARGETS_DIR/vnc_targets.txt")"
        echo "SNMP Services: $(wc -l < "$SERVICE_TARGETS_DIR/snmp_targets.txt")"
    } > service_summary_enhanced.txt
    
    echo "Enhanced service categorization completed" >> "$REPORT_FILE"
    cat service_summary_enhanced.txt >> "$REPORT_FILE"
}

# Safe service enumeration functions (defensive-only, no brute forcing)
enumerate_ftp_services() {
    if [ ! -s "$SERVICE_TARGETS_DIR/ftp_targets.txt" ]; then
        return 0
    fi
    
    echo "  FTP service enumeration (safe)..." >> "$REPORT_FILE"
    
    # Safe FTP enumeration - only anonymous access check and banner grabbing
    nmap -n -p21 --script ftp-anon -T4 \
        -iL "$SERVICE_TARGETS_DIR/ftp_targets.txt" -oA "$PHASE6_DIR/raw_scans/nmap_ftp_enum" 2>/dev/null || true
    
    # Manual FTP banner grabbing
    echo "    FTP banners:" >> "$REPORT_FILE"
    while read -r target; do
        if [ -n "$target" ]; then
            echo "      $target:" >> "$REPORT_FILE"
            timeout 10 nc "$target" 21 2>/dev/null | head -3 | sed 's/^/        /' >> "$REPORT_FILE" || true
        fi
    done < "$SERVICE_TARGETS_DIR/ftp_targets.txt"
}

enumerate_ssh_services() {
    if [ ! -s "$SERVICE_TARGETS_DIR/ssh_targets.txt" ]; then
        return 0
    fi
    
    echo "  SSH service enumeration (safe)..." >> "$REPORT_FILE"
    
    # Enhanced SSH enumeration with comprehensive analysis
    nmap -n -p22 --script ssh-hostkey,ssh2-enum-algos,ssh-auth-methods,banner -T4 \
        -iL "$SERVICE_TARGETS_DIR/ssh_targets.txt" -oA "$PHASE6_DIR/raw_scans/nmap_ssh_enum" 2>/dev/null || true
    
    # Enhanced SSH fingerprinting and banner analysis
    echo "    SSH service fingerprinting:" >> "$REPORT_FILE"
    > "$PHASE6_DIR/ssh_service_details.txt"
    
    while read -r target; do
        if [ -n "$target" ]; then
            echo "      $target:" >> "$REPORT_FILE"
            
            # Enhanced banner grab
            ssh_banner=$(timeout 5 nc "$target" 22 2>/dev/null | head -1)
            if [ -n "$ssh_banner" ]; then
                echo "        Banner: $ssh_banner" >> "$REPORT_FILE"
                echo "$target: $ssh_banner" >> "$PHASE6_DIR/ssh_service_details.txt"
                
                # Extract and analyze version information
                if echo "$ssh_banner" | grep -q "OpenSSH"; then
                    version=$(echo "$ssh_banner" | grep -o "OpenSSH_[0-9.]*[a-zA-Z0-9_-]*")
                    echo "        Version: $version" >> "$REPORT_FILE"
                    
                    # Version analysis for vulnerability assessment
                    case "$version" in
                        *"OpenSSH_1."*|*"OpenSSH_2."*|*"OpenSSH_3."*|*"OpenSSH_4."*|*"OpenSSH_5."*)
                            echo "        Risk: Very old SSH version" >> "$REPORT_FILE"
                            ;;
                        *"OpenSSH_6."*|*"OpenSSH_7.0"*|*"OpenSSH_7.1"*|*"OpenSSH_7.2"*)
                            echo "        Risk: Older SSH version" >> "$REPORT_FILE"
                            ;;
                    esac
                fi
                
                # OS fingerprinting from SSH banner
                if echo "$ssh_banner" | grep -qi "ubuntu"; then
                    echo "        OS: Ubuntu Linux" >> "$REPORT_FILE"
                elif echo "$ssh_banner" | grep -qi "debian"; then
                    echo "        OS: Debian Linux" >> "$REPORT_FILE"
                elif echo "$ssh_banner" | grep -qi "centos\|rhel"; then
                    echo "        OS: RedHat/CentOS" >> "$REPORT_FILE"
                elif echo "$ssh_banner" | grep -qi "freebsd"; then
                    echo "        OS: FreeBSD" >> "$REPORT_FILE"
                fi
            else
                echo "        Banner: [No response]" >> "$REPORT_FILE"
            fi
        fi
    done < "$SERVICE_TARGETS_DIR/ssh_targets.txt"
}

enumerate_web_services() {
    if [ ! -s "$SERVICE_TARGETS_DIR/web_targets.txt" ]; then
        return 0
    fi
    
    echo "  Web service enumeration (safe)..." >> "$REPORT_FILE"
    
    # Enhanced HTTP enumeration with comprehensive fingerprinting
    nmap -n -p80,443,8080,8443 --script http-methods,http-headers,http-title,http-server-header,http-robots.txt,http-security-headers -T4 \
        -iL "$SERVICE_TARGETS_DIR/web_targets.txt" -oA "$PHASE6_DIR/raw_scans/nmap_web_enum" 2>/dev/null || true
    
    # SSL certificate and security analysis
    nmap -n -p443 --script ssl-cert,ssl-enum-ciphers,ssl-date -T4 \
        -iL "$SERVICE_TARGETS_DIR/web_targets.txt" -oA "$PHASE6_DIR/raw_scans/nmap_ssl_info" 2>/dev/null || true
    
    # Enhanced web service fingerprinting
    echo "    Web service fingerprinting:" >> "$REPORT_FILE"
    > "$PHASE6_DIR/web_service_details.txt"
    
    while read -r target; do
        if [ -n "$target" ]; then
            echo "      $target:" >> "$REPORT_FILE"
            
            # HTTP banner grabbing and analysis
            for port in 80 8080; do
                if nc -z -w 2 "$target" "$port" 2>/dev/null; then
                    echo "        HTTP Port $port:" >> "$REPORT_FILE"
                    
                    # Get HTTP headers and server information
                    http_response=$(timeout 10 curl -s -I "http://$target:$port/" 2>/dev/null)
                    if [ -n "$http_response" ]; then
                        # Extract server information
                        server_header=$(echo "$http_response" | grep -i "^server:" | cut -d' ' -f2-)
                        if [ -n "$server_header" ]; then
                            echo "          Server: $server_header" >> "$REPORT_FILE"
                            echo "$target:$port Server: $server_header" >> "$PHASE6_DIR/web_service_details.txt"
                            
                            # Analyze server type and version
                            case "$server_header" in
                                *"Apache"*)
                                    echo "          Technology: Apache HTTP Server" >> "$REPORT_FILE"
                                    if echo "$server_header" | grep -qE "Apache/[0-2]\.[0-4]"; then
                                        echo "          Risk: Very old Apache version" >> "$REPORT_FILE"
                                    fi
                                    ;;
                                *"nginx"*)
                                    echo "          Technology: Nginx" >> "$REPORT_FILE"
                                    ;;
                                *"IIS"*)
                                    echo "          Technology: Microsoft IIS" >> "$REPORT_FILE"
                                    echo "          OS: Windows Server" >> "$REPORT_FILE"
                                    ;;
                                *"lighttpd"*)
                                    echo "          Technology: Lighttpd" >> "$REPORT_FILE"
                                    ;;
                            esac
                        fi
                        
                        # Check for additional headers that reveal technology
                        if echo "$http_response" | grep -qi "x-powered-by:"; then
                            powered_by=$(echo "$http_response" | grep -i "x-powered-by:" | cut -d' ' -f2-)
                            echo "          X-Powered-By: $powered_by" >> "$REPORT_FILE"
                            
                            case "$powered_by" in
                                *"PHP"*)
                                    echo "          Framework: PHP" >> "$REPORT_FILE"
                                    ;;
                                *"ASP.NET"*)
                                    echo "          Framework: ASP.NET" >> "$REPORT_FILE"
                                    echo "          OS: Windows" >> "$REPORT_FILE"
                                    ;;
                            esac
                        fi
                        
                        # Check security headers
                        if ! echo "$http_response" | grep -qi "x-frame-options:"; then
                            echo "          Security: Missing X-Frame-Options header" >> "$REPORT_FILE"
                        fi
                        if ! echo "$http_response" | grep -qi "x-content-type-options:"; then
                            echo "          Security: Missing X-Content-Type-Options header" >> "$REPORT_FILE"
                        fi
                    fi
                fi
            done
            
            # HTTPS analysis
            for port in 443 8443; do
                if nc -z -w 2 "$target" "$port" 2>/dev/null; then
                    echo "        HTTPS Port $port:" >> "$REPORT_FILE"
                    
                    # Get HTTPS headers
                    https_response=$(timeout 10 curl -s -I -k "https://$target:$port/" 2>/dev/null)
                    if [ -n "$https_response" ]; then
                        server_header=$(echo "$https_response" | grep -i "^server:" | cut -d' ' -f2-)
                        if [ -n "$server_header" ]; then
                            echo "          Server: $server_header" >> "$REPORT_FILE"
                        fi
                    fi
                    
                    # SSL certificate basic info (if openssl is available)
                    if command -v openssl >/dev/null 2>&1; then
                        cert_info=$(timeout 10 openssl s_client -connect "$target:$port" -servername "$target" 2>/dev/null < /dev/null)
                        if [ -n "$cert_info" ]; then
                            # Extract certificate subject
                            cert_subject=$(echo "$cert_info" | grep "subject=" | head -1)
                            if [ -n "$cert_subject" ]; then
                                echo "          Certificate: $cert_subject" >> "$REPORT_FILE"
                            fi
                            
                            # Check for certificate expiry warnings
                            if echo "$cert_info" | grep -q "Verify return code: [^0]"; then
                                echo "          SSL Warning: Certificate verification failed" >> "$REPORT_FILE"
                            fi
                        fi
                    fi
                fi
            done
        fi
    done < "$SERVICE_TARGETS_DIR/web_targets.txt"
}

enumerate_database_services() {
    if [ ! -s "$SERVICE_TARGETS_DIR/database_targets.txt" ]; then
        return 0
    fi
    
    echo "  Database service enumeration (safe)..." >> "$REPORT_FILE"
    
    # Enhanced database enumeration with comprehensive fingerprinting
    nmap -n -p3306 --script mysql-info,mysql-variables,banner -T4 \
        -iL "$SERVICE_TARGETS_DIR/database_targets.txt" -oA "$PHASE6_DIR/raw_scans/nmap_mysql_info" 2>/dev/null || true
    
    nmap -n -p1433 --script ms-sql-info,ms-sql-config,banner -T4 \
        -iL "$SERVICE_TARGETS_DIR/database_targets.txt" -oA "$PHASE6_DIR/raw_scans/nmap_mssql_info" 2>/dev/null || true
    
    nmap -n -p27017 --script mongodb-info,mongodb-databases,banner -T4 \
        -iL "$SERVICE_TARGETS_DIR/database_targets.txt" -oA "$PHASE6_DIR/raw_scans/nmap_mongodb_info" 2>/dev/null || true
    
    nmap -n -p5432 --script pgsql-databases,banner -T4 \
        -iL "$SERVICE_TARGETS_DIR/database_targets.txt" -oA "$PHASE6_DIR/raw_scans/nmap_postgresql_info" 2>/dev/null || true
    
    nmap -n -p1521 --script oracle-sid-brute,oracle-enum-users,banner -T4 \
        -iL "$SERVICE_TARGETS_DIR/database_targets.txt" -oA "$PHASE6_DIR/raw_scans/nmap_oracle_info" 2>/dev/null || true
    
    # Enhanced database service fingerprinting
    echo "    Database service fingerprinting:" >> "$REPORT_FILE"
    > "$PHASE6_DIR/database_service_details.txt"
    
    while read -r target; do
        if [ -n "$target" ]; then
            echo "      $target:" >> "$REPORT_FILE"
            
            # MySQL/MariaDB detection (port 3306)
            if nc -z -w 2 "$target" 3306 2>/dev/null; then
                echo "        MySQL/MariaDB Port 3306:" >> "$REPORT_FILE"
                # Try to get MySQL version banner
                mysql_banner=$(timeout 5 nc "$target" 3306 2>/dev/null | strings | head -5 | grep -i mysql)
                if [ -n "$mysql_banner" ]; then
                    echo "          Banner: $mysql_banner" >> "$REPORT_FILE"
                    echo "$target:3306 MySQL: $mysql_banner" >> "$PHASE6_DIR/database_service_details.txt"
                    
                    # Version analysis
                    if echo "$mysql_banner" | grep -qi "5\.0\|5\.1\|5\.5"; then
                        echo "          Risk: Older MySQL version" >> "$REPORT_FILE"
                    elif echo "$mysql_banner" | grep -qi "mariadb"; then
                        echo "          Technology: MariaDB" >> "$REPORT_FILE"
                    fi
                else
                    echo "          Service: MySQL/MariaDB detected" >> "$REPORT_FILE"
                fi
            fi
            
            # Microsoft SQL Server detection (port 1433)
            if nc -z -w 2 "$target" 1433 2>/dev/null; then
                echo "        Microsoft SQL Server Port 1433:" >> "$REPORT_FILE"
                echo "          Service: MSSQL Server detected" >> "$REPORT_FILE"
                echo "          OS: Windows Server" >> "$REPORT_FILE"
                echo "$target:1433 MSSQL: Active" >> "$PHASE6_DIR/database_service_details.txt"
            fi
            
            # PostgreSQL detection (port 5432)
            if nc -z -w 2 "$target" 5432 2>/dev/null; then
                echo "        PostgreSQL Port 5432:" >> "$REPORT_FILE"
                echo "          Service: PostgreSQL detected" >> "$REPORT_FILE"
                echo "$target:5432 PostgreSQL: Active" >> "$PHASE6_DIR/database_service_details.txt"
            fi
            
            # MongoDB detection (port 27017)
            if nc -z -w 2 "$target" 27017 2>/dev/null; then
                echo "        MongoDB Port 27017:" >> "$REPORT_FILE"
                echo "          Service: MongoDB detected" >> "$REPORT_FILE"
                echo "$target:27017 MongoDB: Active" >> "$PHASE6_DIR/database_service_details.txt"
            fi
            
            # Oracle detection (port 1521)
            if nc -z -w 2 "$target" 1521 2>/dev/null; then
                echo "        Oracle Database Port 1521:" >> "$REPORT_FILE"
                echo "          Service: Oracle Database detected" >> "$REPORT_FILE"
                echo "$target:1521 Oracle: Active" >> "$PHASE6_DIR/database_service_details.txt"
            fi
            
            # Redis detection (port 6379)
            if nc -z -w 2 "$target" 6379 2>/dev/null; then
                echo "        Redis Port 6379:" >> "$REPORT_FILE"
                # Try to get Redis info
                redis_info=$(timeout 3 echo "INFO server" | nc "$target" 6379 2>/dev/null | head -10)
                if echo "$redis_info" | grep -q "redis_version"; then
                    version=$(echo "$redis_info" | grep "redis_version" | cut -d: -f2)
                    echo "          Service: Redis $version" >> "$REPORT_FILE"
                    echo "$target:6379 Redis: $version" >> "$PHASE6_DIR/database_service_details.txt"
                else
                    echo "          Service: Redis detected" >> "$REPORT_FILE"
                fi
            fi
        fi
    done < "$SERVICE_TARGETS_DIR/database_targets.txt"
}

enumerate_smb_services() {
    if [ ! -s "$SERVICE_TARGETS_DIR/smb_targets.txt" ]; then
        return 0
    fi
    
    echo "  SMB service enumeration (safe)..." >> "$REPORT_FILE"
    
    # Enhanced SMB enumeration with comprehensive fingerprinting
    nmap -n -p445,139 --script smb-protocols,smb-security-mode,smb-os-discovery,smb2-capabilities -T4 \
        -iL "$SERVICE_TARGETS_DIR/smb_targets.txt" -oA "$PHASE6_DIR/raw_scans/nmap_smb_info" 2>/dev/null || true
    
    # Detailed SMB banner grabbing and version detection
    echo "    SMB server analysis:" >> "$REPORT_FILE"
    while read -r target; do
        if [ -n "$target" ]; then
            echo "      SMB Analysis for $target:" >> "$REPORT_FILE"
            
            # SMB port 445 banner analysis
            if nc -z -w 2 "$target" 445 2>/dev/null; then
                echo "        SMB Port 445:" >> "$REPORT_FILE"
                
                # Try to get SMB dialect information
                smb_info=$(timeout 5 nmap -n -p445 --script smb-protocols "$target" 2>/dev/null | grep -A 10 "smb-protocols")
                if [ -n "$smb_info" ]; then
                    # Extract SMB version information
                    if echo "$smb_info" | grep -q "SMBv1"; then
                        echo "          Protocol: SMBv1 (legacy)" >> "$REPORT_FILE"
                        echo "          Risk: SMBv1 protocol enabled" >> "$REPORT_FILE"
                    fi
                    if echo "$smb_info" | grep -q "SMBv2"; then
                        echo "          Protocol: SMBv2" >> "$REPORT_FILE"
                    fi
                    if echo "$smb_info" | grep -q "SMBv3"; then
                        echo "          Protocol: SMBv3" >> "$REPORT_FILE"
                    fi
                fi
                
                # OS and architecture detection from SMB
                os_info=$(timeout 5 nmap -n -p445 --script smb-os-discovery "$target" 2>/dev/null | grep -A 5 "OS:")
                if [ -n "$os_info" ]; then
                    os_name=$(echo "$os_info" | grep "OS:" | sed 's/.*OS: //' | cut -d'(' -f1)
                    if [ -n "$os_name" ]; then
                        echo "          OS: $os_name" >> "$REPORT_FILE"
                        case "$os_name" in
                            *"Windows Server 2003"*|*"Windows XP"*)
                                echo "          Risk: End-of-life Windows version" >> "$REPORT_FILE"
                                ;;
                            *"Windows Server 2008"*)
                                echo "          Risk: Extended support ended" >> "$REPORT_FILE"
                                ;;
                        esac
                    fi
                fi
                
                echo "$target:445 SMB: Active" >> "$PHASE6_DIR/smb_service_details.txt"
            fi
            
            # NetBIOS port 139 analysis  
            if nc -z -w 2 "$target" 139 2>/dev/null; then
                echo "        NetBIOS Port 139:" >> "$REPORT_FILE"
                echo "          Service: NetBIOS Session Service" >> "$REPORT_FILE"
                echo "          Protocol: NetBIOS over TCP" >> "$REPORT_FILE"
                echo "$target:139 NetBIOS: Active" >> "$PHASE6_DIR/smb_service_details.txt"
                
                # NetBIOS name resolution
                if command -v nmblookup >/dev/null 2>&1; then
                    nb_name=$(timeout 5 nmblookup -A "$target" 2>/dev/null | grep "<00>" | head -1 | awk '{print $1}')
                    if [ -n "$nb_name" ]; then
                        echo "          NetBIOS Name: $nb_name" >> "$REPORT_FILE"
                    fi
                fi
            fi
            
            # Safe share enumeration (no authentication)
            if command -v smbclient >/dev/null 2>&1; then
                echo "        Share Information:" >> "$REPORT_FILE"
                share_info=$(timeout 10 smbclient -L "//$target" -N 2>/dev/null | grep -E "Disk|IPC|Printer" | head -5)
                if [ -n "$share_info" ]; then
                    echo "$share_info" | sed 's/^/          /' >> "$REPORT_FILE"
                    # Check for potentially sensitive shares
                    if echo "$share_info" | grep -qi "admin\|c\$\|ipc\$"; then
                        echo "          Note: Administrative shares detected" >> "$REPORT_FILE"
                    fi
                else
                    echo "          Access: Anonymous access denied" >> "$REPORT_FILE"
                fi
            fi
        fi
    done < "$SERVICE_TARGETS_DIR/smb_targets.txt"
}

enumerate_dns_services() {
    if [ ! -s "$SERVICE_TARGETS_DIR/dns_targets.txt" ]; then
        return 0
    fi
    
    echo "  DNS service enumeration (safe)..." >> "$REPORT_FILE"
    
    # Enhanced DNS server enumeration and fingerprinting
    nmap -n -p53 --script dns-nsid,dns-service-discovery,dns-recursion -T4 \
        -iL "$SERVICE_TARGETS_DIR/dns_targets.txt" -oA "$PHASE6_DIR/raw_scans/nmap_dns_info" 2>/dev/null || true
    
    # Detailed DNS server analysis
    echo "    DNS server analysis:" >> "$REPORT_FILE"
    while read -r target; do
        if [ -n "$target" ]; then
            echo "      DNS Analysis for $target:" >> "$REPORT_FILE"
            
            # TCP DNS port 53 analysis
            if nc -z -w 2 "$target" 53 2>/dev/null; then
                echo "        DNS TCP Port 53:" >> "$REPORT_FILE"
                echo "          Service: DNS Server (TCP)" >> "$REPORT_FILE"
                
                # Try to get DNS version information
                if command -v dig >/dev/null 2>&1; then
                    # Query for version (BIND servers often respond)
                    version_info=$(timeout 5 dig @"$target" version.bind chaos txt +short 2>/dev/null | tr -d '"')
                    if [ -n "$version_info" ]; then
                        echo "          Version: $version_info" >> "$REPORT_FILE"
                        # Check for known vulnerable versions
                        case "$version_info" in
                            *"BIND 9.8"*|*"BIND 9.9.0"*|*"BIND 9.9.1"*)
                                echo "          Risk: Potentially outdated BIND version" >> "$REPORT_FILE"
                                ;;
                        esac
                    fi
                    
                    # Test DNS recursion
                    recursion_test=$(timeout 5 dig @"$target" google.com +short 2>/dev/null)
                    if [ -n "$recursion_test" ]; then
                        echo "          Configuration: Recursion enabled" >> "$REPORT_FILE"
                        echo "          Risk: Open DNS resolver detected" >> "$REPORT_FILE"
                    else
                        echo "          Configuration: Recursion disabled/restricted" >> "$REPORT_FILE"
                    fi
                    
                    # Check for zone transfer (safe test)
                    zone_test=$(timeout 5 dig @"$target" . axfr 2>/dev/null | head -5)
                    if echo "$zone_test" | grep -q "XFR size"; then
                        echo "          Risk: Zone transfer may be allowed" >> "$REPORT_FILE"
                    fi
                fi
                
                echo "$target:53 DNS: Active (TCP)" >> "$PHASE6_DIR/dns_service_details.txt"
            fi
            
            # UDP DNS port 53 analysis
            if timeout 3 nc -u -z -w 1 "$target" 53 2>/dev/null; then
                echo "        DNS UDP Port 53:" >> "$REPORT_FILE"
                echo "          Service: DNS Server (UDP)" >> "$REPORT_FILE"
                
                # DNS server identification via UDP
                if command -v dig >/dev/null 2>&1; then
                    # Test basic DNS functionality
                    dns_response=$(timeout 3 dig @"$target" . NS +short 2>/dev/null | head -1)
                    if [ -n "$dns_response" ]; then
                        echo "          Root NS Query: Successful" >> "$REPORT_FILE"
                    fi
                    
                    # Check response rate (amplification risk)
                    response_size=$(timeout 3 dig @"$target" . ANY +short 2>/dev/null | wc -c)
                    if [ "$response_size" -gt 512 ]; then
                        echo "          Risk: Large UDP responses (amplification risk)" >> "$REPORT_FILE"
                    fi
                fi
                
                echo "$target:53 DNS: Active (UDP)" >> "$PHASE6_DIR/dns_service_details.txt"
            fi
            
            # DNS over HTTPS/TLS detection (ports 853, 443)
            if nc -z -w 2 "$target" 853 2>/dev/null; then
                echo "        DNS over TLS Port 853:" >> "$REPORT_FILE"
                echo "          Service: DNS over TLS (DoT)" >> "$REPORT_FILE"
                echo "$target:853 DoT: Active" >> "$PHASE6_DIR/dns_service_details.txt"
            fi
        fi
    done < "$SERVICE_TARGETS_DIR/dns_targets.txt"
}

enumerate_snmp_services() {
    if [ ! -s "$SERVICE_TARGETS_DIR/snmp_targets.txt" ]; then
        return 0
    fi
    
    echo "  SNMP service enumeration (safe)..." >> "$REPORT_FILE"
    
    # Enhanced SNMP enumeration with comprehensive system information
    nmap -n -sU -p161 --script snmp-sysdescr,snmp-info,snmp-interfaces -T4 \
        -iL "$SERVICE_TARGETS_DIR/snmp_targets.txt" -oA "$PHASE6_DIR/raw_scans/nmap_snmp_info" 2>/dev/null || true
    
    # Detailed SNMP server analysis
    echo "    SNMP server analysis:" >> "$REPORT_FILE"
    while read -r target; do
        if [ -n "$target" ]; then
            echo "      SNMP Analysis for $target:" >> "$REPORT_FILE"
            
            # SNMP UDP port 161 analysis
            if timeout 3 nc -u -z -w 1 "$target" 161 2>/dev/null; then
                echo "        SNMP UDP Port 161:" >> "$REPORT_FILE"
                echo "          Service: SNMP Agent" >> "$REPORT_FILE"
                
                # SNMP community string testing (safe defaults only)
                if command -v snmpget >/dev/null 2>&1; then
                    # Test with common read-only community strings (safe)
                    for community in "public" "private" "community"; do
                        snmp_test=$(timeout 5 snmpget -v2c -c "$community" "$target" 1.3.6.1.2.1.1.1.0 2>/dev/null)
                        if [ -n "$snmp_test" ] && ! echo "$snmp_test" | grep -q "Timeout"; then
                            echo "          Community: $community (accessible)" >> "$REPORT_FILE"
                            
                            # Get system description
                            sys_desc=$(echo "$snmp_test" | grep "STRING:" | cut -d'"' -f2)
                            if [ -n "$sys_desc" ]; then
                                echo "          System: $sys_desc" >> "$REPORT_FILE"
                                
                                # Identify device type from system description
                                case "$sys_desc" in
                                    *"Cisco"*|*"cisco"*)
                                        echo "          Device Type: Cisco Network Device" >> "$REPORT_FILE"
                                        ;;
                                    *"HP"*|*"Hewlett"*)
                                        echo "          Device Type: HP Network Device" >> "$REPORT_FILE"
                                        ;;
                                    *"Juniper"*|*"JUNOS"*)
                                        echo "          Device Type: Juniper Network Device" >> "$REPORT_FILE"
                                        ;;
                                    *"Linux"*|*"Ubuntu"*|*"CentOS"*|*"RedHat"*)
                                        echo "          Device Type: Linux Server" >> "$REPORT_FILE"
                                        ;;
                                    *"Windows"*)
                                        echo "          Device Type: Windows Server" >> "$REPORT_FILE"
                                        ;;
                                    *"VMware"*)
                                        echo "          Device Type: VMware ESXi Host" >> "$REPORT_FILE"
                                        ;;
                                    *)
                                        echo "          Device Type: Unknown SNMP Device" >> "$REPORT_FILE"
                                        ;;
                                esac
                            fi
                            
                            # Get system uptime
                            uptime_info=$(timeout 5 snmpget -v2c -c "$community" "$target" 1.3.6.1.2.1.1.3.0 2>/dev/null | grep "Timeticks")
                            if [ -n "$uptime_info" ]; then
                                uptime_val=$(echo "$uptime_info" | grep -o '([^)]*)')
                                if [ -n "$uptime_val" ]; then
                                    echo "          Uptime: $uptime_val" >> "$REPORT_FILE"
                                fi
                            fi
                            
                            # Get system contact and location (if available)
                            contact_info=$(timeout 5 snmpget -v2c -c "$community" "$target" 1.3.6.1.2.1.1.4.0 2>/dev/null | grep "STRING:" | cut -d'"' -f2)
                            if [ -n "$contact_info" ] && [ "$contact_info" != "NULL" ]; then
                                echo "          Contact: $contact_info" >> "$REPORT_FILE"
                            fi
                            
                            location_info=$(timeout 5 snmpget -v2c -c "$community" "$target" 1.3.6.1.2.1.1.6.0 2>/dev/null | grep "STRING:" | cut -d'"' -f2)
                            if [ -n "$location_info" ] && [ "$location_info" != "NULL" ]; then
                                echo "          Location: $location_info" >> "$REPORT_FILE"
                            fi
                            
                            # Security assessment
                            if [ "$community" = "public" ]; then
                                echo "          Risk: Default 'public' community string active" >> "$REPORT_FILE"
                            elif [ "$community" = "private" ]; then
                                echo "          Risk: Default 'private' community string active" >> "$REPORT_FILE"
                            fi
                            
                            break # Stop testing other communities once we find one that works
                        fi
                    done
                    
                    # If no community strings worked
                    if ! echo "$snmp_test" | grep -q "STRING:"; then
                        echo "          Access: Default community strings not accessible" >> "$REPORT_FILE"
                    fi
                elif command -v snmpwalk >/dev/null 2>&1; then
                    # Fallback to snmpwalk if snmpget not available
                    snmp_test=$(timeout 5 snmpwalk -v2c -c public "$target" 1.3.6.1.2.1.1.1.0 2>/dev/null | head -1)
                    if [ -n "$snmp_test" ]; then
                        echo "          Community: public (accessible)" >> "$REPORT_FILE"
                        sys_desc=$(echo "$snmp_test" | cut -d'=' -f2 | sed 's/STRING: //' | tr -d '"')
                        if [ -n "$sys_desc" ]; then
                            echo "          System: $sys_desc" >> "$REPORT_FILE"
                        fi
                    fi
                else
                    echo "          Tool: snmp utilities not available" >> "$REPORT_FILE"
                fi
                
                echo "$target:161 SNMP: Active" >> "$PHASE6_DIR/snmp_service_details.txt"
            fi
            
            # SNMP Trap port 162 detection
            if timeout 3 nc -u -z -w 1 "$target" 162 2>/dev/null; then
                echo "        SNMP Trap Port 162:" >> "$REPORT_FILE"
                echo "          Service: SNMP Trap Receiver" >> "$REPORT_FILE"
                echo "$target:162 SNMP-Trap: Active" >> "$PHASE6_DIR/snmp_service_details.txt"
            fi
        fi
    done < "$SERVICE_TARGETS_DIR/snmp_targets.txt"
}

# Safe vulnerability assessment functions (detection only, no exploitation)
vulnerability_scan_web_services() {
    if [ ! -s "$SERVICE_TARGETS_DIR/web_targets.txt" ]; then
        return 0
    fi
    
    echo "    Web service vulnerability detection (safe)..." >> "$REPORT_FILE"
    
    # Safe web vulnerability detection - no exploitation attempts
    nmap -n -p443 --script ssl-heartbleed,ssl-poodle -T4 \
        -iL "$SERVICE_TARGETS_DIR/web_targets.txt" -oA "$PHASE7_DIR/raw_scans/nmap_web_vulns" 2>/dev/null || true
}

vulnerability_scan_smb_services() {
    if [ ! -s "$SERVICE_TARGETS_DIR/smb_targets.txt" ]; then
        return 0
    fi
    
    echo "    SMB service vulnerability detection (safe)..." >> "$REPORT_FILE"
    
    # Safe SMB vulnerability detection - no exploitation
    nmap -n -p445 --script smb-vuln-ms17-010,smb-vuln-ms08-067 -T4 \
        -iL "$SERVICE_TARGETS_DIR/smb_targets.txt" -oA "$PHASE7_DIR/raw_scans/nmap_smb_vulns" 2>/dev/null || true
}

vulnerability_scan_ssh_services() {
    if [ ! -s "$SERVICE_TARGETS_DIR/ssh_targets.txt" ]; then
        return 0
    fi
    
    echo "    SSH service vulnerability detection (safe)..." >> "$REPORT_FILE"
    
    # Safe SSH vulnerability detection
    nmap -n -p22 --script ssh2-enum-algos -T4 \
        -iL "$SERVICE_TARGETS_DIR/ssh_targets.txt" -oA "$PHASE7_DIR/raw_scans/nmap_ssh_crypto" 2>/dev/null || true
}

vulnerability_scan_database_services() {
    if [ ! -s "$SERVICE_TARGETS_DIR/database_targets.txt" ]; then
        return 0
    fi
    
    echo "    Database service vulnerability detection (safe)..." >> "$REPORT_FILE"
    
    # Only check for empty passwords, no brute forcing
    nmap -n -p3306 --script mysql-empty-password -T4 \
        -iL "$SERVICE_TARGETS_DIR/database_targets.txt" -oA "$PHASE7_DIR/raw_scans/nmap_mysql_emptypass" 2>/dev/null || true
    
    nmap -n -p1433 --script ms-sql-empty-password -T4 \
        -iL "$SERVICE_TARGETS_DIR/database_targets.txt" -oA "$PHASE7_DIR/raw_scans/nmap_mssql_emptypass" 2>/dev/null || true
}

process_vulnerability_results() {
    echo "  Processing vulnerability assessment results..." >> "$REPORT_FILE"
    
    # Extract vulnerability information from scan results
    > "$PHASE7_DIR/vulnerabilities_found.txt"
    
    # Check for critical vulnerabilities in all scan results
    for vuln_file in "$SESSION_DIR"/nmap_*_vulns.nmap "$SESSION_DIR"/nmap_*_emptypass.nmap; do
        if [ -f "$vuln_file" ]; then
            # Look for VULNERABLE entries
            grep -i "VULNERABLE\|STATE.*vulnerable" "$vuln_file" 2>/dev/null >> "$PHASE7_DIR/vulnerabilities_found.txt" || true
        fi
    done
    
    vuln_count=$(wc -l < "$PHASE7_DIR/vulnerabilities_found.txt")
    echo "    Potential vulnerabilities detected: $vuln_count" >> "$REPORT_FILE"
    
    if [ "$vuln_count" -gt 0 ]; then
        echo "    Vulnerability findings:" >> "$REPORT_FILE"
        head -10 "$PHASE7_DIR/vulnerabilities_found.txt" | sed 's/^/      /' >> "$REPORT_FILE"
    fi
}

# Phase 1: Enhanced Network Discovery
echo "--- PHASE 1: ENHANCED NETWORK DISCOVERY ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Phase 1: Enhanced Network Discovery - Layer 2 discovery, topology analysis, and infrastructure identification..."

# Initialize host discovery files
> "$PHASE1_DIR/arp_hosts.txt"
> "$PHASE1_DIR/topology_hosts.txt"
> "$PHASE1_DIR/infrastructure_hosts.txt"

# Sub-phase 1.1: Network Topology Discovery
echo "  Sub-phase 1.1: Network topology and boundary analysis..." >> "$REPORT_FILE"
discover_network_topology "$target_networks" "$PHASE1_DIR/topology_hosts.txt"

# Sub-phase 1.2: Infrastructure Device Identification  
echo "  Sub-phase 1.2: Network infrastructure identification..." >> "$REPORT_FILE"
identify_network_devices "$target_networks" "$PHASE1_DIR/infrastructure_hosts.txt"

# Sub-phase 1.3: Reverse DNS Pattern Analysis
echo "  Sub-phase 1.3: Reverse DNS enumeration..." >> "$REPORT_FILE"
if [ "$discovery_type" = "vlan_aware" ]; then
    for network in $target_networks; do
        if [ -n "$network" ]; then
            perform_reverse_dns_enumeration "$network" "$PHASE1_DIR/topology_hosts.txt"
        fi
    done
else
    perform_reverse_dns_enumeration "$network_range" "$PHASE1_DIR/topology_hosts.txt"
fi

# Sub-phase 1.4: Network Segmentation Analysis
echo "  Sub-phase 1.4: Network segmentation analysis..." >> "$REPORT_FILE"
> "$PHASE1_DIR/segmentation_analysis.txt"
analyze_network_segmentation "$target_networks" "$PHASE1_DIR/segmentation_analysis.txt"
segmentation_findings=$(wc -l < "$PHASE1_DIR/segmentation_analysis.txt")
echo "  Sub-phase 1.4 complete: $segmentation_findings segmentation findings" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Sub-phase 1.5: Layer 2 ARP Discovery
echo "  Sub-phase 1.5: Layer 2 ARP discovery..." >> "$REPORT_FILE"

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
                    awk '{print $1}' >> "$PHASE1_DIR/arp_hosts.txt"
            else
                ip neighbor show dev "$interface" | grep -E "([0-9]+\.){3}[0-9]+" | \
                    awk -v iface="$interface" '{print $1 "\t" $2 "\t" $3 "\t" iface}' >> "$REPORT_FILE"
                ip neighbor show dev "$interface" | grep -E "([0-9]+\.){3}[0-9]+" | \
                    awk '{print $1}' >> "$PHASE1_DIR/arp_hosts.txt"
            fi
        fi
    done
else
    if command -v arp-scan >/dev/null 2>&1; then
        echo "Using arp-scan for Layer 2 discovery..." >> "$REPORT_FILE"
        arp-scan --local --interface="$selected_interface" | grep -v "Interface:" | grep -E "^([0-9]+\.){3}[0-9]+" | \
            awk '{print $1}' > "$PHASE1_DIR/arp_hosts.txt"
        arp-scan --local --interface="$selected_interface" | grep -v "Interface:" | grep -E "^([0-9]+\.){3}[0-9]+" | \
            awk '{print $1 "\t" $2 "\t" $3}' >> "$REPORT_FILE"
    else
        echo "arp-scan not available, using IP neighbor discovery..." >> "$REPORT_FILE"
        ip neighbor show dev "$selected_interface" | grep -E "([0-9]+\.){3}[0-9]+" | \
            awk '{print $1}' > "$PHASE1_DIR/arp_hosts.txt"
        ip neighbor show dev "$selected_interface" | grep -E "([0-9]+\.){3}[0-9]+" >> "$REPORT_FILE"
    fi
fi

# Consolidate all Phase 1 discoveries
cat "$PHASE1_DIR/arp_hosts.txt" "$PHASE1_DIR/topology_hosts.txt" "$PHASE1_DIR/infrastructure_hosts.txt" | \
    sort -u > "$PHASE1_DIR/phase1_all_hosts.txt"

arp_count=$(wc -l < "$PHASE1_DIR/arp_hosts.txt")
topology_count=$(wc -l < "$PHASE1_DIR/topology_hosts.txt")
infrastructure_count=$(wc -l < "$PHASE1_DIR/infrastructure_hosts.txt")
phase1_total=$(wc -l < "$PHASE1_DIR/phase1_all_hosts.txt")

echo >> "$REPORT_FILE"
echo "Phase 1 Enhanced Network Discovery Summary:" >> "$REPORT_FILE"
echo "  Layer 2 ARP hosts: $arp_count" >> "$REPORT_FILE"
echo "  Topology/DNS hosts: $topology_count" >> "$REPORT_FILE"
echo "  Infrastructure devices: $infrastructure_count" >> "$REPORT_FILE"
echo "  Segmentation findings: $segmentation_findings" >> "$REPORT_FILE"
echo "  Total unique hosts: $phase1_total" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"
echo "  Sub-phases completed:" >> "$REPORT_FILE"
echo "    ✓ Network topology and boundary analysis" >> "$REPORT_FILE"
echo "    ✓ Infrastructure device identification" >> "$REPORT_FILE"
echo "    ✓ Reverse DNS pattern analysis" >> "$REPORT_FILE"
echo "    ✓ Network segmentation analysis" >> "$REPORT_FILE"
echo "    ✓ Layer 2 ARP discovery" >> "$REPORT_FILE"

log_network_operation "Enhanced Phase 1 discovery" "$network_range" "Found $phase1_total hosts ($arp_count ARP, $topology_count topology, $infrastructure_count infrastructure, $segmentation_findings segmentation)"
echo >> "$REPORT_FILE"

# Phase 2: Comprehensive Host Discovery
echo "--- PHASE 2: COMPREHENSIVE HOST DISCOVERY ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Phase 2: Comprehensive Host Discovery - Multi-protocol discovery with firewall bypass techniques..."

# Initialize discovery files
> "$PHASE2_DIR/ping_hosts.txt"
> "$PHASE2_DIR/tcp_hosts.txt"
> "$PHASE2_DIR/udp_hosts.txt"
> "$PHASE2_DIR/masscan_hosts.txt"

# Sub-phase 2.1: ICMP Discovery (Traditional Ping Sweep)
echo "  Sub-phase 2.1: ICMP connectivity testing..." >> "$REPORT_FILE"

if [ "$discovery_type" = "vlan_aware" ]; then
    echo "Performing VLAN-aware ping sweep..." >> "$REPORT_FILE"
    for network in $target_networks; do
        if [ -n "$network" ]; then
            echo "  Ping sweep on network: $network" >> "$REPORT_FILE"
            if command -v fping >/dev/null 2>&1; then
                enhanced_fping_sweep "$network" "$PHASE2_DIR/ping_hosts.txt"
            else
                # Extract network portion for ping sweep
                network_base=$(echo "$network" | cut -d'/' -f1 | cut -d'.' -f1-3)
                for i in $(seq 1 254); do
                    if ping -c 1 -W 1 "${network_base}.$i" >/dev/null 2>&1; then
                        echo "${network_base}.$i" >> "$PHASE2_DIR/ping_hosts.txt"
                    fi
                done
            fi
        fi
    done
else
    if command -v fping >/dev/null 2>&1; then
        echo "Using fping for fast ping sweep..." >> "$REPORT_FILE"
        enhanced_fping_sweep "$network_range" "$PHASE2_DIR/ping_hosts.txt"
    else
        echo "fping not available, using basic ping..." >> "$REPORT_FILE"
        # Extract network portion for ping sweep
        network_base=$(echo "$network_range" | cut -d'/' -f1 | cut -d'.' -f1-3)
        for i in $(seq 1 254); do
            if ping -c 1 -W 1 "${network_base}.$i" >/dev/null 2>&1; then
                echo "${network_base}.$i" >> "$PHASE2_DIR/ping_hosts.txt"
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
done < "$PHASE2_DIR/ping_hosts.txt"

ping_count=$(wc -l < "$PHASE2_DIR/ping_hosts.txt")
echo >> "$REPORT_FILE"
echo "  Sub-phase 2.1 complete: Found $ping_count ICMP-responsive hosts." >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Sub-phase 2.2: TCP Discovery with Firewall Bypass
echo "  Sub-phase 2.2: TCP discovery with firewall bypass..." >> "$REPORT_FILE"
perform_tcp_discovery "$target_networks" "$PHASE2_DIR/tcp_hosts.txt"
tcp_count=$(wc -l < "$PHASE2_DIR/tcp_hosts.txt")
echo "  Sub-phase 2.2 complete: Found $tcp_count TCP-responsive hosts." >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Sub-phase 2.3: UDP Service Discovery  
echo "  Sub-phase 2.3: UDP service discovery..." >> "$REPORT_FILE"
perform_udp_discovery "$target_networks" "$PHASE2_DIR/udp_hosts.txt"
udp_count=$(wc -l < "$PHASE2_DIR/udp_hosts.txt")
echo "  Sub-phase 2.3 complete: Found $udp_count UDP-responsive hosts." >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Sub-phase 2.4: High-Speed Discovery (if masscan available)
echo "  Sub-phase 2.4: High-speed discovery (masscan)..." >> "$REPORT_FILE"
perform_masscan_discovery "$target_networks" "$PHASE2_DIR/masscan_hosts.txt"
masscan_count=$(wc -l < "$PHASE2_DIR/masscan_hosts.txt")
echo "  Sub-phase 2.4 complete: Found $masscan_count hosts via masscan." >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Sub-phase 2.5: IPv6 Network Discovery
echo "  Sub-phase 2.5: IPv6 network discovery..." >> "$REPORT_FILE"
> "$PHASE2_DIR/ipv6_hosts.txt"
perform_ipv6_discovery "$selected_interface" "$PHASE2_DIR/ipv6_hosts.txt"
ipv6_count=$(wc -l < "$PHASE2_DIR/ipv6_hosts.txt")
echo "  Sub-phase 2.5 complete: Found $ipv6_count IPv6 hosts." >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Combine all Phase 1 and Phase 2 results
cat "$PHASE1_DIR/phase1_all_hosts.txt" "$PHASE2_DIR/ping_hosts.txt" "$PHASE2_DIR/tcp_hosts.txt" \
    "$PHASE2_DIR/udp_hosts.txt" "$PHASE2_DIR/masscan_hosts.txt" "$PHASE2_DIR/ipv6_hosts.txt" | sort -u > "$CONSOLIDATED_DIR/all_hosts.txt"
all_hosts_count=$(wc -l < "$CONSOLIDATED_DIR/all_hosts.txt")

echo "Phase 2 Comprehensive Host Discovery Summary:" >> "$REPORT_FILE"
echo "  ICMP-responsive hosts: $ping_count" >> "$REPORT_FILE"
echo "  TCP-responsive hosts: $tcp_count" >> "$REPORT_FILE"
echo "  UDP-responsive hosts: $udp_count" >> "$REPORT_FILE"
echo "  Masscan-discovered hosts: $masscan_count" >> "$REPORT_FILE"
echo "  IPv6-discovered hosts: $ipv6_count" >> "$REPORT_FILE"
echo "  Combined unique hosts (Phases 1+2): $all_hosts_count" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

log_network_operation "Enhanced Phase 2 discovery" "$network_range" "Found $all_hosts_count total hosts (ICMP:$ping_count, TCP:$tcp_count, UDP:$udp_count, Masscan:$masscan_count, IPv6:$ipv6_count)"

# Sub-phase 2.6: Early OS Detection and Device Classification
echo "  Sub-phase 2.6: Early OS detection and device classification..." >> "$REPORT_FILE"

# Initialize classification files
> "$PHASE2_DIR/early_os_detection.txt"
> "$PHASE2_DIR/early_device_classification.txt"

# Perform early OS detection on discovered hosts
perform_early_os_detection "$CONSOLIDATED_DIR/all_hosts.txt" "$PHASE2_DIR/early_os_detection.txt"

# Perform early device classification
perform_early_device_classification "$CONSOLIDATED_DIR/all_hosts.txt" "$PHASE2_DIR/early_device_classification.txt"

# Count classification results
os_classified_count=$(wc -l < "$PHASE2_DIR/early_os_detection.txt")
device_classified_count=$(wc -l < "$PHASE2_DIR/early_device_classification.txt")

echo "  Sub-phase 2.5 complete: OS classified: $os_classified_count, Device types: $device_classified_count" >> "$REPORT_FILE"
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
        echo "$host\t$hostname" >> "$PHASE3_DIR/dns_results.txt"
    fi
done < "$PHASE2_DIR/all_hosts.txt"

echo >> "$REPORT_FILE"

# Phase 4: Windows-Specific Discovery
echo "--- PHASE 4: WINDOWS-SPECIFIC DISCOVERY ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Phase 4: Windows-Specific Discovery - SMB and NetBIOS enumeration..."

# SMB/NetBIOS discovery
echo "SMB/NetBIOS enumeration:" >> "$REPORT_FILE"
> "$PHASE4_DIR/smb_hosts.txt"
> "$PHASE4_DIR/netbios_names.txt"

while read -r host; do
    if [ -n "$host" ]; then
        # Test for SMB (port 445)
        if nc -z -w 2 "$host" 445 2>/dev/null; then
            echo "$host" >> "$PHASE4_DIR/smb_hosts.txt"
            echo "  $host - SMB port 445 open" >> "$REPORT_FILE"
            
            # Try to get NetBIOS name using nmblookup
            if command -v nmblookup >/dev/null 2>&1; then
                netbios_name=$(nmblookup -A "$host" 2>/dev/null | grep "<00>" | head -1 | awk '{print $1}')
                if [ -n "$netbios_name" ]; then
                    echo "$host\t$netbios_name" >> "$PHASE4_DIR/netbios_names.txt"
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
done < "$PHASE2_DIR/all_hosts.txt"

smb_count=$(wc -l < "$PHASE4_DIR/smb_hosts.txt")
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
    tr '\n' ' ' < "$CONSOLIDATED_DIR/all_hosts.txt" > "$PHASE5_DIR/nmap_targets.txt"
    
    # Stage 1: Fast common port scan
    echo "  Stage 1: Fast common port scan..." >> "$REPORT_FILE"
    COMMON_PORTS="1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416,417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5987-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,8180-8181,8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8873,8888,8899,8994,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,13456,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389"
    
    nmap -n -sS -p "$COMMON_PORTS" -T4 --open --reason -oN "$SESSION_DIR/nmap_fast_scan.txt" \
        -iL "$PHASE2_DIR/all_hosts.txt" 2>/dev/null | \
        grep -E "Nmap scan report|open" >> "$REPORT_FILE"
    
    # Extract high-value targets for comprehensive scanning
    echo "  Identifying high-value targets..." >> "$REPORT_FILE"
    grep -E "22/open|80/open|443/open|445/open|3389/open|21/open|23/open|25/open|53/open|135/open|139/open|1433/open|3306/open|5432/open" \
        "$PHASE5_DIR/raw_scans/nmap_fast_scan.txt" 2>/dev/null | grep "Nmap scan report" | awk '{print $5}' | sort -u > "$PHASE5_DIR/high_value_targets.txt" || true
    
    hv_count=$(wc -l < "$PHASE5_DIR/high_value_targets.txt")
    echo "    High-value targets identified: $hv_count" >> "$REPORT_FILE"
    
    # Stage 2: Comprehensive scan on high-value targets
    if [ "$hv_count" -gt 0 ]; then
        echo "  Stage 2: Comprehensive scan on high-value targets..." >> "$REPORT_FILE"
        nmap -n -sS -p- --min-rate 5000 -T4 --open \
            -iL "$PHASE5_DIR/high_value_targets.txt" -oN "$PHASE5_DIR/raw_scans/nmap_comprehensive_scan.txt" 2>/dev/null || true
    fi
    
    # Stage 3: UDP scan on common ports
    echo "  Stage 3: UDP scan on common ports..." >> "$REPORT_FILE"
    nmap -n -sU --top-ports 100 -T4 --open \
        -iL "$PHASE2_DIR/all_hosts.txt" -oN "$PHASE5_DIR/raw_scans/nmap_udp_scan.txt" 2>/dev/null || true
    
    # Service categorization
    echo "  Categorizing discovered services..." >> "$REPORT_FILE"
    categorize_services_enhanced
    
else
    echo "nmap not available, skipping detailed port scan" >> "$REPORT_FILE"
fi

echo >> "$REPORT_FILE"

# Phase 6: Service Enumeration
echo "--- PHASE 6: SERVICE ENUMERATION ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Phase 6: Service Enumeration - Detailed service analysis..."
if command -v nmap >/dev/null 2>&1; then
    echo "Performing comprehensive service enumeration..." >> "$REPORT_FILE"
    
    # Version detection on all discovered services
    echo "  Stage 1: Version detection and banner grabbing..." >> "$REPORT_FILE"
    nmap -n -sV --version-intensity 5 -T4 \
        -iL "$PHASE2_DIR/all_hosts.txt" -oA "$PHASE6_DIR/raw_scans/nmap_version_detection" 2>/dev/null || true
    
    # Default script scan for additional service information
    echo "  Stage 2: Default NSE scripts..." >> "$REPORT_FILE"
    nmap -n -sC -T4 \
        -iL "$PHASE2_DIR/all_hosts.txt" -oA "$PHASE6_DIR/raw_scans/nmap_default_scripts" 2>/dev/null || true
    
    # Service-specific enumeration
    enumerate_ftp_services
    enumerate_ssh_services
    enumerate_web_services
    enumerate_database_services
    enumerate_smb_services
    enumerate_dns_services
    enumerate_snmp_services
    
else
    echo "nmap not available, skipping service enumeration" >> "$REPORT_FILE"
fi

echo >> "$REPORT_FILE"

# Phase 7: Vulnerability Assessment (Defensive)
echo "--- PHASE 7: VULNERABILITY ASSESSMENT ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Phase 7: Vulnerability Assessment - Security analysis (defensive only)..."
if command -v nmap >/dev/null 2>&1; then
    echo "Performing defensive vulnerability assessment..." >> "$REPORT_FILE"
    
    # Configuration security assessment
    echo "  Stage 1: Configuration security assessment..." >> "$REPORT_FILE"
    nmap -n --script auth -T4 \
        -iL "$PHASE2_DIR/all_hosts.txt" -oA "$PHASE7_DIR/raw_scans/nmap_default_creds" 2>/dev/null || true
    
    # Weak cryptography detection
    echo "  Stage 2: Cryptographic security assessment..." >> "$REPORT_FILE"
    nmap -n --script ssl-enum-ciphers,ssh2-enum-algos -T4 \
        -iL "$PHASE2_DIR/all_hosts.txt" -oA "$PHASE7_DIR/raw_scans/nmap_crypto_analysis" 2>/dev/null || true
    
    # Service-specific vulnerability scans (safe)
    vulnerability_scan_web_services
    vulnerability_scan_smb_services
    vulnerability_scan_ssh_services
    vulnerability_scan_database_services
    
    # Process vulnerability results
    process_vulnerability_results
    
else
    echo "nmap not available, skipping vulnerability assessment" >> "$REPORT_FILE"
fi

echo >> "$REPORT_FILE"

# Phase 8: Host Categorization
echo "--- PHASE 8: HOST CATEGORIZATION ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Phase 8: Host Categorization - Analyzing discovered hosts..."

# Create categorized host lists
mkdir -p "$SESSION_DIR/categorized"
mkdir -p "$PHASE8_DIR"

# Initialize detailed category files
> "$SESSION_DIR/categorized/windows_hosts.txt"
> "$SESSION_DIR/categorized/linux_hosts.txt"
> "$SESSION_DIR/categorized/network_devices.txt"
> "$SESSION_DIR/categorized/web_servers.txt"
> "$SESSION_DIR/categorized/database_servers.txt"
> "$SESSION_DIR/categorized/unknown_hosts.txt"

# Initialize simplified team assignment files 
> "$PHASE8_DIR/team_windows.txt"
> "$PHASE8_DIR/team_linux.txt" 
> "$PHASE8_DIR/team_network.txt"

# Categorize based on available information
while read -r host; do
    if [ -n "$host" ]; then
        category="unknown"
        
        # Check TTL-based OS detection
        ttl=$(ping -c 1 -W 1 "$host" 2>/dev/null | grep "ttl=" | head -1 | sed 's/.*ttl=\([0-9]*\).*/\1/')
        
        # Priority 1: Check Windows-specific discovery results
        if grep -q "^$host$" "$PHASE4_DIR/smb_hosts.txt" 2>/dev/null; then
            category="windows"
            echo "$host" >> "$SESSION_DIR/categorized/windows_hosts.txt"
            echo "$host" >> "$PHASE8_DIR/team_windows.txt"
        # Priority 2: Check for common services (if nmap results exist)
        elif [ -f "$SESSION_DIR/nmap_services.txt" ]; then
            # Check for Windows-specific services
            if grep -A 50 "$host" "$SESSION_DIR/nmap_services.txt" | grep -qE "(microsoft|smb|netbios|rdp|3389|445|139)"; then
                category="windows"
                echo "$host" >> "$SESSION_DIR/categorized/windows_hosts.txt"
                echo "$host" >> "$PHASE8_DIR/team_windows.txt"
            # Check for web servers
            elif grep -A 50 "$host" "$SESSION_DIR/nmap_services.txt" | grep -qE "(http|80|443|8080|8443)"; then
                category="web_server"
                echo "$host" >> "$SESSION_DIR/categorized/web_servers.txt"
                echo "$host" >> "$PHASE8_DIR/team_linux.txt"  # Web servers typically Linux
            # Check for database servers
            elif grep -A 50 "$host" "$SESSION_DIR/nmap_services.txt" | grep -qE "(mysql|postgresql|mssql|oracle|1433|3306|5432)"; then
                category="database"
                echo "$host" >> "$SESSION_DIR/categorized/database_servers.txt"
                # Database assignment: MSSQL->Windows, others->Linux
                if grep -A 50 "$host" "$SESSION_DIR/nmap_services.txt" | grep -qE "(mssql|1433)"; then
                    echo "$host" >> "$PHASE8_DIR/team_windows.txt"
                else
                    echo "$host" >> "$PHASE8_DIR/team_linux.txt"
                fi
            # Check for network devices
            elif grep -A 50 "$host" "$SESSION_DIR/nmap_services.txt" | grep -qE "(snmp|ssh|telnet|161|22|23)"; then
                category="network_device"
                echo "$host" >> "$SESSION_DIR/categorized/network_devices.txt"
                echo "$host" >> "$PHASE8_DIR/team_network.txt"
            # TTL-based categorization
            elif [ -n "$ttl" ] && [ "$ttl" -ge 120 ]; then
                category="windows"
                echo "$host" >> "$SESSION_DIR/categorized/windows_hosts.txt"
                echo "$host" >> "$PHASE8_DIR/team_windows.txt"
            elif [ -n "$ttl" ] && [ "$ttl" -ge 60 ] && [ "$ttl" -lt 120 ]; then
                category="linux"
                echo "$host" >> "$SESSION_DIR/categorized/linux_hosts.txt"
                echo "$host" >> "$PHASE8_DIR/team_linux.txt"
            else
                category="unknown"
                echo "$host" >> "$SESSION_DIR/categorized/unknown_hosts.txt"
                echo "$host" >> "$PHASE8_DIR/team_network.txt"  # Unknown hosts go to network team
            fi
        else
            # Fallback to TTL-based categorization only
            if [ -n "$ttl" ] && [ "$ttl" -ge 120 ]; then
                category="windows"
                echo "$host" >> "$SESSION_DIR/categorized/windows_hosts.txt"
                echo "$host" >> "$PHASE8_DIR/team_windows.txt"
            elif [ -n "$ttl" ] && [ "$ttl" -ge 60 ] && [ "$ttl" -lt 120 ]; then
                category="linux"
                echo "$host" >> "$SESSION_DIR/categorized/linux_hosts.txt"
                echo "$host" >> "$PHASE8_DIR/team_linux.txt"
            else
                category="unknown"
                echo "$host" >> "$SESSION_DIR/categorized/unknown_hosts.txt"
                echo "$host" >> "$PHASE8_DIR/team_network.txt"  # Unknown hosts go to network team
            fi
        fi
        
        # Get hostname for display
        hostname=$(grep "^$host" "$PHASE3_DIR/dns_results.txt" | cut -f2)
        if [ -z "$hostname" ]; then
            hostname="<no hostname>"
        fi
        
        echo "$host\t$hostname\t$category" >> "$REPORT_FILE"
    fi
done < "$PHASE2_DIR/all_hosts.txt"

echo >> "$REPORT_FILE"

# Phase 9: Evidence Processing and Manifest Creation
echo "--- PHASE 9: EVIDENCE PROCESSING ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Phase 9: Evidence Processing - Consolidating scan data and generating comprehensive service inventory..."

# Create evidence manifest
echo "  Creating evidence manifest..." >> "$REPORT_FILE"
{
    echo "=== NetUtility Evidence Manifest ==="
    echo "Generated: $(date)"
    echo "Session: $SESSION_DIR"
    echo ""
    echo "=== Directory Structure ==="
    echo "evidence/"
    echo "├── phase1_network_discovery/"
    echo "│   └── raw_scans/ (ARP, topology, infrastructure scans)"
    echo "├── phase2_host_discovery/"
    echo "│   └── raw_scans/ (ICMP, TCP, UDP, masscan results)"
    echo "├── phase3_dns_analysis/"
    echo "│   └── dns_results.txt"
    echo "├── phase4_windows_discovery/"
    echo "│   ├── smb_hosts.txt"
    echo "│   └── netbios_names.txt"
    echo "├── phase5_port_scanning/"
    echo "│   └── raw_scans/ (Port scan results)"
    echo "├── phase6_service_enumeration/"
    echo "│   └── raw_scans/ (Service detection scans)"
    echo "├── phase7_vulnerability_assessment/"
    echo "│   ├── vulnerabilities_found.txt"
    echo "│   └── raw_scans/ (Vulnerability scans)"
    echo "└── phase8_host_categorization/"
    echo "    ├── categorized/ (Detailed host type classifications)"
    echo "    ├── team_windows.txt (Windows hosts for Windows team)"
    echo "    ├── team_linux.txt (Linux/Unix hosts for Linux team)"  
    echo "    └── team_network.txt (Network devices/unknown for Network team)"
    echo ""
    echo "service_targets/ (Service-specific target lists)"
    echo "consolidated/ (Summary files and reports)"
    echo "reports/ (Final analysis and summaries)"
    echo ""
    echo "=== File Checksums ==="
    find "$EVIDENCE_DIR" -type f -exec sha256sum {} \; 2>/dev/null | sort
    echo ""
    echo "=== Service Targets Checksums ==="
    find "$SERVICE_TARGETS_DIR" -type f -exec sha256sum {} \; 2>/dev/null | sort
} > "$SESSION_DIR/EVIDENCE_MANIFEST.txt"

# Create comprehensive service inventory
echo "  Consolidating scan data..." >> "$REPORT_FILE"
{
    echo "IP_Address,Port,Protocol,State,Service,Version,Banner"
    
    # Process all nmap scan results from evidence directories
    for scan_file in "$EVIDENCE_DIR"/*/raw_scans/nmap_*.txt; do
        if [ -f "$scan_file" ]; then
            # Extract service information from nmap results
            grep -E "Nmap scan report|open" "$scan_file" 2>/dev/null | while read -r line; do
                if echo "$line" | grep -q "Nmap scan report"; then
                    current_host=$(echo "$line" | awk '{print $5}')
                elif echo "$line" | grep -q "open"; then
                    port_info=$(echo "$line" | awk '{print $1}')
                    service=$(echo "$line" | awk '{print $3}')
                    version=$(echo "$line" | cut -d' ' -f4- | tr ',' ';')
                    echo "$current_host,$port_info,open,$service,$version,Unknown"
                fi
            done 2>/dev/null || true
        fi
    done | sort -t',' -k1,1V -k2,2n
} > "$SESSION_DIR/comprehensive_service_inventory.csv"

# Create attack surface summary
echo "  Generating attack surface summary..." >> "$REPORT_FILE"
{
    echo "=== Attack Surface Analysis ==="
    echo "Assessment Date: $(date)"
    echo "Target Networks: $(echo "$target_networks" | tr ' ' ', ')"
    echo ""
    echo "=== Infrastructure Summary ==="
    echo "Total Hosts Discovered: $all_hosts_count"
    
    # Service statistics from enhanced categorization
    if [ -f "service_summary_enhanced.txt" ]; then
        echo ""
        cat service_summary_enhanced.txt
    fi
    
    echo ""
    echo "=== Security Findings ==="
    if [ -f "$PHASE7_DIR/vulnerabilities_found.txt" ] && [ -s "$PHASE7_DIR/vulnerabilities_found.txt" ]; then
        vuln_count=$(wc -l < "$PHASE7_DIR/vulnerabilities_found.txt")
        echo "Potential Vulnerabilities: $vuln_count"
        echo "Top findings:"
        head -5 "$PHASE7_DIR/vulnerabilities_found.txt" | sed 's/^/  - /'
    else
        echo "No critical vulnerabilities detected in defensive scans"
    fi
    
    echo ""
    echo "=== Key Files Generated ==="
    echo "Service Inventory: comprehensive_service_inventory.csv"
    echo "Discovery Report: discovery_report.txt"
    echo "Categorized Hosts: categorized/ directory"
    if [ -f "$SESSION_DIR/smb_hosts.txt" ]; then
        echo "SMB Hosts: smb_hosts.txt"
    fi
    if [ -f "$SESSION_DIR/netbios_names.txt" ]; then
        echo "NetBIOS Names: netbios_names.txt"
    fi
} > "$SESSION_DIR/attack_surface_summary.txt"

echo "  Evidence processing completed - $(wc -l < "$SESSION_DIR/comprehensive_service_inventory.csv") services cataloged" >> "$REPORT_FILE"

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

# Team assignment counts
team_windows_count=$(wc -l < "$PHASE8_DIR/team_windows.txt")
team_linux_count=$(wc -l < "$PHASE8_DIR/team_linux.txt")
team_network_count=$(wc -l < "$PHASE8_DIR/team_network.txt")

echo "Discovery Statistics:" >> "$REPORT_FILE"
echo "  Total hosts discovered: $all_hosts_count" >> "$REPORT_FILE"
echo "  Windows hosts: $windows_count" >> "$REPORT_FILE"
echo "  Linux/Unix hosts: $linux_count" >> "$REPORT_FILE"
echo "  Network devices: $network_count" >> "$REPORT_FILE"
echo "  Web servers: $web_count" >> "$REPORT_FILE"
echo "  Database servers: $database_count" >> "$REPORT_FILE"
echo "  Unknown hosts: $unknown_count" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"
echo "Team Assignment Summary:" >> "$REPORT_FILE"
echo "  Windows Team: $team_windows_count hosts" >> "$REPORT_FILE"
echo "  Linux Team: $team_linux_count hosts" >> "$REPORT_FILE"
echo "  Network Team: $team_network_count hosts" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Enhanced discovery phases completed:" >> "$REPORT_FILE"
echo "  ✓ Phase 1: Enhanced Network Discovery" >> "$REPORT_FILE"
echo "      - Topology analysis, infrastructure ID, DNS patterns, segmentation analysis, ARP scan" >> "$REPORT_FILE"
echo "      - Total hosts: $phase1_total (ARP:$arp_count, topology:$topology_count, infrastructure:$infrastructure_count)" >> "$REPORT_FILE"
echo "  ✓ Phase 2: Comprehensive Host Discovery" >> "$REPORT_FILE"
echo "      - ICMP, TCP bypass, UDP probes, masscan, early OS/device classification" >> "$REPORT_FILE"
echo "      - Total hosts: $all_hosts_count (ICMP:$ping_count, TCP:$tcp_count, UDP:$udp_count, masscan:$masscan_count)" >> "$REPORT_FILE"
echo "      - Classifications: $os_classified_count OS detected, $device_classified_count device types" >> "$REPORT_FILE"
echo "  ✓ Phase 3: DNS Lookup (completed)" >> "$REPORT_FILE"
echo "  ✓ Phase 4: Windows-Specific Discovery ($smb_count SMB hosts)" >> "$REPORT_FILE"
echo "  ✓ Phase 5: Progressive Port Scan (multi-stage)" >> "$REPORT_FILE"
echo "  ✓ Phase 6: Service Enumeration (defensive)" >> "$REPORT_FILE"
echo "  ✓ Phase 7: Vulnerability Assessment (safe detection)" >> "$REPORT_FILE"
echo "  ✓ Phase 8: Host Categorization (completed)" >> "$REPORT_FILE"
echo "  ✓ Phase 9: Evidence Processing (inventory generated)" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Discovery completed at $(date)" >> "$REPORT_FILE"

# Create summary files
echo "Creating summary files..."
cp "$PHASE2_DIR/all_hosts.txt" "$SESSION_DIR/all_discovered_hosts.txt"
cp "$PHASE3_DIR/dns_results.txt" "$SESSION_DIR/dns_results.txt"

# Copy Windows-specific discovery results
if [ -s "$PHASE4_DIR/smb_hosts.txt" ]; then
    cp "$PHASE4_DIR/smb_hosts.txt" "$SESSION_DIR/smb_hosts.txt"
fi
if [ -s "$PHASE4_DIR/netbios_names.txt" ]; then
    cp "$PHASE4_DIR/netbios_names.txt" "$SESSION_DIR/netbios_names.txt"
fi

# Phase 9: Service Organization and Team Handoff File Generation
echo "--- PHASE 9: SERVICE ORGANIZATION & TEAM HANDOFF ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Phase 9: Generating service organization and team handoff files..."

# Create team handoff directory
TEAM_HANDOFF_DIR="$SESSION_DIR/team_handoff"
mkdir -p "$TEAM_HANDOFF_DIR"/{windows,linux,network,manual_assignment}

# Generate comprehensive service inventory for team coordination
generate_service_inventory() {
    local inventory_file="$TEAM_HANDOFF_DIR/service_inventory.csv"
    
    echo "Host,Service,Port,Protocol,Version,Risk_Level,Team_Assignment,Notes" > "$inventory_file"
    
    # Process each service type
    for service_dir in "$PHASE6_DIR"/*_service_details.txt; do
        if [ -f "$service_dir" ]; then
            service_type=$(basename "$service_dir" | sed 's/_service_details.txt//')
            
            while IFS=':' read -r host port_service rest; do
                if [ -n "$host" ] && [ -n "$port_service" ]; then
                    # Extract port and service info
                    port=$(echo "$port_service" | cut -d' ' -f1)
                    service=$(echo "$port_service" | cut -d' ' -f2-)
                    
                    # Determine team assignment and risk level
                    case "$service_type" in
                        "ssh"|"ftp"|"telnet"|"smtp"|"imap"|"pop3")
                            team="Linux"
                            risk="Medium"
                            ;;
                        "smb"|"rdp")
                            team="Windows"
                            risk="High"
                            ;;
                        "database"|"mysql"|"mssql"|"postgresql"|"mongodb"|"oracle"|"redis")
                            team="Manual_Assignment"
                            risk="Critical"
                            ;;
                        "web"|"http"|"https")
                            team="Manual_Assignment"
                            risk="Medium"
                            ;;
                        "dns"|"snmp")
                            team="Network"
                            risk="Low"
                            ;;
                        *)
                            team="Manual_Assignment"
                            risk="Low"
                            ;;
                    esac
                    
                    echo "$host,$service_type,$port,TCP,$service,$risk,$team," >> "$inventory_file"
                fi
            done < "$service_dir"
        fi
    done
    
    echo "  Service inventory created: $(wc -l < "$inventory_file") services catalogued" >> "$REPORT_FILE"
}

# Generate team-specific target lists with context
generate_team_handoff_files() {
    echo "  Creating team-specific handoff files..." >> "$REPORT_FILE"
    
    # Windows Team Handoff
    {
        echo "=== WINDOWS TEAM HANDOFF ==="
        echo "Generated: $(date)"
        echo "Assessment Phase: Initial Discovery"
        echo ""
        echo "== SMB/NetBIOS TARGETS =="
        if [ -s "$SERVICE_TARGETS_DIR/smb_targets.txt" ]; then
            echo "SMB Service Hosts ($(wc -l < "$SERVICE_TARGETS_DIR/smb_targets.txt")):"
            cat "$SERVICE_TARGETS_DIR/smb_targets.txt" | sed 's/^/  /'
            echo ""
            echo "Key SMB Information:"
            if [ -f "$PHASE6_DIR/smb_service_details.txt" ]; then
                head -10 "$PHASE6_DIR/smb_service_details.txt" | sed 's/^/  /'
            fi
        else
            echo "No SMB targets identified"
        fi
        echo ""
        
        echo "== RDP TARGETS =="
        if [ -s "$SERVICE_TARGETS_DIR/rdp_targets.txt" ]; then
            echo "RDP Service Hosts ($(wc -l < "$SERVICE_TARGETS_DIR/rdp_targets.txt")):"
            cat "$SERVICE_TARGETS_DIR/rdp_targets.txt" | sed 's/^/  /'
        else
            echo "No RDP targets identified"
        fi
        echo ""
        
        echo "== WINDOWS HOST IDENTIFICATION =="
        if [ -f "$PHASE8_DIR/team_windows.txt" ]; then
            echo "Windows Hosts Identified ($(wc -l < "$PHASE8_DIR/team_windows.txt")):"
            cat "$PHASE8_DIR/team_windows.txt" | sed 's/^/  /'
        fi
        echo ""
        
        echo "== NETBIOS NAMES =="
        if [ -f "$SESSION_DIR/netbios_names.txt" ]; then
            echo "NetBIOS Computer Names:"
            head -20 "$SESSION_DIR/netbios_names.txt" | sed 's/^/  /'
        fi
        echo ""
        
        echo "== ASSESSMENT PRIORITIES =="
        echo "1. SMB Protocol Analysis (versions, signing, shares)"
        echo "2. Windows Version Identification"
        echo "3. NetBIOS Name Enumeration"
        echo "4. RDP Configuration Assessment"
        echo "5. Windows-specific Vulnerability Assessment"
        echo ""
        echo "== RAW SCAN DATA =="
        echo "SMB Nmap Scans: $PHASE6_DIR/raw_scans/nmap_smb_*"
        echo "RDP Detection: $SERVICE_TARGETS_DIR/rdp_targets.txt"
        echo "Team Assignment: $PHASE8_DIR/team_windows.txt"
        
    } > "$TEAM_HANDOFF_DIR/windows/WINDOWS_TEAM_HANDOFF.txt"
    
    # Linux Team Handoff
    {
        echo "=== LINUX TEAM HANDOFF ==="
        echo "Generated: $(date)"
        echo "Assessment Phase: Initial Discovery"
        echo ""
        echo "== SSH TARGETS =="
        if [ -s "$SERVICE_TARGETS_DIR/ssh_targets.txt" ]; then
            echo "SSH Service Hosts ($(wc -l < "$SERVICE_TARGETS_DIR/ssh_targets.txt")):"
            cat "$SERVICE_TARGETS_DIR/ssh_targets.txt" | sed 's/^/  /'
            echo ""
            echo "Key SSH Information:"
            if [ -f "$PHASE6_DIR/ssh_service_details.txt" ]; then
                head -10 "$PHASE6_DIR/ssh_service_details.txt" | sed 's/^/  /'
            fi
        else
            echo "No SSH targets identified"
        fi
        echo ""
        
        echo "== LINUX HOST IDENTIFICATION =="
        if [ -f "$PHASE8_DIR/team_linux.txt" ]; then
            echo "Linux/Unix Hosts Identified ($(wc -l < "$PHASE8_DIR/team_linux.txt")):"
            cat "$PHASE8_DIR/team_linux.txt" | sed 's/^/  /'
        fi
        echo ""
        
        echo "== OTHER LINUX SERVICES =="
        for service in ftp telnet smtp imap pop3; do
            if [ -s "$SERVICE_TARGETS_DIR/${service}_targets.txt" ]; then
                echo "${service^^} Targets ($(wc -l < "$SERVICE_TARGETS_DIR/${service}_targets.txt")):"
                cat "$SERVICE_TARGETS_DIR/${service}_targets.txt" | sed 's/^/  /'
                echo ""
            fi
        done
        
        echo "== ASSESSMENT PRIORITIES =="
        echo "1. SSH Configuration Analysis (versions, key algorithms)"
        echo "2. Operating System Identification"
        echo "3. Service Version Enumeration"
        echo "4. Linux-specific Vulnerability Assessment"
        echo "5. Configuration Security Review"
        echo ""
        echo "== RAW SCAN DATA =="
        echo "SSH Nmap Scans: $PHASE6_DIR/raw_scans/nmap_ssh_*"
        echo "Service Scans: $PHASE6_DIR/raw_scans/nmap_*_enum.nmap"
        echo "Team Assignment: $PHASE8_DIR/team_linux.txt"
        
    } > "$TEAM_HANDOFF_DIR/linux/LINUX_TEAM_HANDOFF.txt"
    
    # Network Team Handoff
    {
        echo "=== NETWORK TEAM HANDOFF ==="
        echo "Generated: $(date)"
        echo "Assessment Phase: Initial Discovery"
        echo ""
        echo "== NETWORK INFRASTRUCTURE =="
        if [ -f "$PHASE8_DIR/team_network.txt" ]; then
            echo "Network Devices Identified ($(wc -l < "$PHASE8_DIR/team_network.txt")):"
            cat "$PHASE8_DIR/team_network.txt" | sed 's/^/  /'
        fi
        echo ""
        
        echo "== DNS SERVERS =="
        if [ -s "$SERVICE_TARGETS_DIR/dns_targets.txt" ]; then
            echo "DNS Service Hosts ($(wc -l < "$SERVICE_TARGETS_DIR/dns_targets.txt")):"
            cat "$SERVICE_TARGETS_DIR/dns_targets.txt" | sed 's/^/  /'
        fi
        echo ""
        
        echo "== SNMP DEVICES =="
        if [ -s "$SERVICE_TARGETS_DIR/snmp_targets.txt" ]; then
            echo "SNMP Service Hosts ($(wc -l < "$SERVICE_TARGETS_DIR/snmp_targets.txt")):"
            cat "$SERVICE_TARGETS_DIR/snmp_targets.txt" | sed 's/^/  /'
            echo ""
            if [ -f "$PHASE6_DIR/snmp_service_details.txt" ]; then
                echo "SNMP Device Information:"
                head -15 "$PHASE6_DIR/snmp_service_details.txt" | sed 's/^/  /'
            fi
        fi
        echo ""
        
        echo "== NETWORK TOPOLOGY =="
        if [ -f "$PHASE1_DIR/topology_hosts.txt" ]; then
            echo "Network Topology Findings:"
            head -10 "$PHASE1_DIR/topology_hosts.txt" | sed 's/^/  /'
        fi
        echo ""
        
        echo "== ASSESSMENT PRIORITIES =="
        echo "1. Network Device Configuration Review"
        echo "2. SNMP Community String Assessment"
        echo "3. DNS Configuration Analysis"
        echo "4. Network Segmentation Validation"
        echo "5. Infrastructure Security Assessment"
        echo ""
        echo "== RAW SCAN DATA =="
        echo "DNS Scans: $PHASE6_DIR/raw_scans/nmap_dns_*"
        echo "SNMP Scans: $PHASE6_DIR/raw_scans/nmap_snmp_*"
        echo "Network Discovery: $PHASE1_DIR/"
        
    } > "$TEAM_HANDOFF_DIR/network/NETWORK_TEAM_HANDOFF.txt"
    
    # Manual Assignment Handoff (Web and Database services)
    {
        echo "=== MANUAL ASSIGNMENT HANDOFF ==="
        echo "Generated: $(date)"
        echo "Assessment Phase: Initial Discovery"
        echo "Note: These services require manual team assignment based on availability"
        echo ""
        
        echo "== WEB SERVICES (Manual Assignment Required) =="
        if [ -s "$SERVICE_TARGETS_DIR/web_targets.txt" ]; then
            echo "Web Service Hosts ($(wc -l < "$SERVICE_TARGETS_DIR/web_targets.txt")):"
            cat "$SERVICE_TARGETS_DIR/web_targets.txt" | sed 's/^/  /'
            echo ""
            if [ -f "$PHASE6_DIR/web_service_details.txt" ]; then
                echo "Web Service Details:"
                head -15 "$PHASE6_DIR/web_service_details.txt" | sed 's/^/  /'
            fi
        else
            echo "No web services identified"
        fi
        echo ""
        
        echo "== DATABASE SERVICES (Manual Assignment Required) =="
        if [ -s "$SERVICE_TARGETS_DIR/database_targets.txt" ]; then
            echo "Database Service Hosts ($(wc -l < "$SERVICE_TARGETS_DIR/database_targets.txt")):"
            cat "$SERVICE_TARGETS_DIR/database_targets.txt" | sed 's/^/  /'
            echo ""
            if [ -f "$PHASE6_DIR/database_service_details.txt" ]; then
                echo "Database Service Details:"
                cat "$PHASE6_DIR/database_service_details.txt" | sed 's/^/  /'
            fi
        else
            echo "No database services identified"
        fi
        echo ""
        
        echo "== VNC SERVICES (Manual Assignment Required) =="
        if [ -s "$SERVICE_TARGETS_DIR/vnc_targets.txt" ]; then
            echo "VNC Service Hosts ($(wc -l < "$SERVICE_TARGETS_DIR/vnc_targets.txt")):"
            cat "$SERVICE_TARGETS_DIR/vnc_targets.txt" | sed 's/^/  /'
        fi
        echo ""
        
        echo "== ASSIGNMENT RECOMMENDATIONS =="
        echo "Web Services:"
        echo "  • Can be assigned to any team with web application experience"
        echo "  • Consider workload balance when assigning"
        echo ""
        echo "Database Services:"
        echo "  • High priority - assign to team with database expertise"
        echo "  • Consider criticality of database systems"
        echo ""
        echo "VNC Services:"
        echo "  • Typically Linux/Unix systems - consider Linux team first"
        echo "  • Can be assigned based on current team capacity"
        echo ""
        echo "== RAW SCAN DATA =="
        echo "Web Scans: $PHASE6_DIR/raw_scans/nmap_web_*"
        echo "Database Scans: $PHASE6_DIR/raw_scans/nmap_*_emptypass.nmap"
        echo "Service Details: $PHASE6_DIR/web_service_details.txt, $PHASE6_DIR/database_service_details.txt"
        
    } > "$TEAM_HANDOFF_DIR/manual_assignment/MANUAL_ASSIGNMENT_HANDOFF.txt"
    
    echo "  Team handoff files generated successfully" >> "$REPORT_FILE"
}

# Generate priority assessment matrix
generate_priority_matrix() {
    local matrix_file="$TEAM_HANDOFF_DIR/PRIORITY_ASSESSMENT_MATRIX.txt"
    
    {
        echo "=== PRIORITY ASSESSMENT MATRIX ==="
        echo "Generated: $(date)"
        echo "Assessment Context: Air-gapped Vulnerability Assessment"
        echo "Team Structure: Windows, Linux, Network + Manual Assignment"
        echo ""
        echo "== CRITICAL PRIORITIES (Immediate Action Required) =="
        
        # Check for critical findings
        critical_count=0
        if [ -s "$SERVICE_TARGETS_DIR/database_targets.txt" ]; then
            db_count=$(wc -l < "$SERVICE_TARGETS_DIR/database_targets.txt")
            echo "🔴 Database Services: $db_count hosts identified (MANUAL ASSIGNMENT)"
            echo "   Action: Immediate authentication and configuration review"
            echo "   Assignment: Assign to team with database expertise and current availability"
            critical_count=$((critical_count + db_count))
        fi
        
        if [ -s "$SERVICE_TARGETS_DIR/smb_targets.txt" ]; then
            smb_count=$(wc -l < "$SERVICE_TARGETS_DIR/smb_targets.txt")
            echo "🔴 SMB Services: $smb_count hosts identified (WINDOWS TEAM)"
            echo "   Action: Protocol version and share security assessment"
            critical_count=$((critical_count + smb_count))
        fi
        
        if [ "$critical_count" -eq 0 ]; then
            echo "✅ No critical services requiring immediate attention identified"
        fi
        
        echo ""
        echo "== HIGH PRIORITIES (Next 48 Hours) =="
        
        high_count=0
        if [ -s "$SERVICE_TARGETS_DIR/web_targets.txt" ]; then
            web_count=$(wc -l < "$SERVICE_TARGETS_DIR/web_targets.txt")
            echo "🟡 Web Services: $web_count hosts identified (MANUAL ASSIGNMENT)"
            echo "   Action: Web application security assessment"
            echo "   Assignment: Assign based on team availability and web app experience"
            high_count=$((high_count + web_count))
        fi
        
        if [ -s "$SERVICE_TARGETS_DIR/rdp_targets.txt" ]; then
            rdp_count=$(wc -l < "$SERVICE_TARGETS_DIR/rdp_targets.txt")
            echo "🟡 RDP Services: $rdp_count hosts identified (WINDOWS TEAM)" 
            echo "   Action: Remote access configuration review"
            high_count=$((high_count + rdp_count))
        fi
        
        if [ "$high_count" -eq 0 ]; then
            echo "✅ No high-priority services identified"
        fi
        
        echo ""
        echo "== MEDIUM PRIORITIES (Next Week) =="
        
        medium_count=0
        if [ -s "$SERVICE_TARGETS_DIR/ssh_targets.txt" ]; then
            ssh_count=$(wc -l < "$SERVICE_TARGETS_DIR/ssh_targets.txt")
            echo "🟢 SSH Services: $ssh_count hosts identified (LINUX TEAM)"
            echo "   Action: SSH hardening and key management review"
            medium_count=$((medium_count + ssh_count))
        fi
        
        if [ -s "$SERVICE_TARGETS_DIR/snmp_targets.txt" ]; then
            snmp_count=$(wc -l < "$SERVICE_TARGETS_DIR/snmp_targets.txt")
            echo "🟢 SNMP Services: $snmp_count hosts identified (NETWORK TEAM)"
            echo "   Action: SNMP community and access control review"
            medium_count=$((medium_count + snmp_count))
        fi
        
        if [ "$medium_count" -eq 0 ]; then
            echo "✅ No medium-priority services identified"
        fi
        
        echo ""
        echo "== TEAM WORKLOAD DISTRIBUTION =="
        windows_total=$(($([ -s "$SERVICE_TARGETS_DIR/smb_targets.txt" ] && wc -l < "$SERVICE_TARGETS_DIR/smb_targets.txt" || echo 0) + $([ -s "$SERVICE_TARGETS_DIR/rdp_targets.txt" ] && wc -l < "$SERVICE_TARGETS_DIR/rdp_targets.txt" || echo 0)))
        linux_total=$(($([ -s "$SERVICE_TARGETS_DIR/ssh_targets.txt" ] && wc -l < "$SERVICE_TARGETS_DIR/ssh_targets.txt" || echo 0) + $([ -s "$SERVICE_TARGETS_DIR/ftp_targets.txt" ] && wc -l < "$SERVICE_TARGETS_DIR/ftp_targets.txt" || echo 0)))
        network_total=$(($([ -s "$SERVICE_TARGETS_DIR/dns_targets.txt" ] && wc -l < "$SERVICE_TARGETS_DIR/dns_targets.txt" || echo 0) + $([ -s "$SERVICE_TARGETS_DIR/snmp_targets.txt" ] && wc -l < "$SERVICE_TARGETS_DIR/snmp_targets.txt" || echo 0)))
        manual_total=$(($([ -s "$SERVICE_TARGETS_DIR/web_targets.txt" ] && wc -l < "$SERVICE_TARGETS_DIR/web_targets.txt" || echo 0) + $([ -s "$SERVICE_TARGETS_DIR/database_targets.txt" ] && wc -l < "$SERVICE_TARGETS_DIR/database_targets.txt" || echo 0)))
        
        echo "Windows Team: $windows_total assigned services"
        echo "Linux Team: $linux_total assigned services"
        echo "Network Team: $network_total assigned services"
        echo "Manual Assignment Required: $manual_total services"
        echo ""
        echo "Recommended approach for manual assignments:"
        if [ "$manual_total" -gt 0 ]; then
            echo "• Prioritize database services for immediate assignment"
            echo "• Consider team current workload when assigning web services"
            echo "• Database services should go to most experienced database team"
        fi
        
    } > "$matrix_file"
    
    echo "  Priority assessment matrix created" >> "$REPORT_FILE"
}

# Execute service organization functions
echo "  Generating comprehensive service inventory..." >> "$REPORT_FILE"
generate_service_inventory

echo "  Creating team-specific handoff files..." >> "$REPORT_FILE"
generate_team_handoff_files

echo "  Building priority assessment matrix..." >> "$REPORT_FILE"
generate_priority_matrix

echo "Phase 9 complete: Service organization and team handoff files generated" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo
echo "Multi-phase discovery complete!"
echo "Results saved to: $SESSION_DIR"

# Update latest symlinks
update_latest_links "discovery" "$SESSION_DIR"

log_info "Multi-phase discovery completed successfully"
log_info "Results saved to: $SESSION_DIR"
log_info "Discovery summary: $all_hosts_count total hosts, $windows_count Windows, $linux_count Linux/Unix, $network_count network devices"
echo
echo "Enhanced Discovery Summary:"
if [ "$discovery_type" = "vlan_aware" ]; then
    echo "  Discovery mode: VLAN-aware (multiple networks)"
    echo "  Networks scanned: $target_networks"
else
    echo "  Discovery mode: Standard (single network)"
    echo "  Network scanned: $network_range"
fi
echo "  Total hosts discovered: $all_hosts_count"
echo "  Windows hosts: $windows_count"
echo "  Linux/Unix hosts: $linux_count"
echo "  Network devices: $network_count"
echo "  Web servers: $web_count"
echo "  Database servers: $database_count"
echo "  Unknown hosts: $unknown_count"
echo
echo "Team Assignment Summary:"
echo "  🪟 Windows Team: $team_windows_count hosts"
echo "  🐧 Linux Team: $team_linux_count hosts"
echo "  🌐 Network Team: $team_network_count hosts"

# Show vulnerability count if available
if [ -f "$PHASE7_DIR/vulnerabilities_found.txt" ]; then
    vuln_count=$(wc -l < "$PHASE7_DIR/vulnerabilities_found.txt")
    echo "  Potential vulnerabilities: $vuln_count"
fi

echo
echo "Key Files Created:"
echo "  📊 comprehensive_service_inventory.csv (complete service catalog)"
echo "  📋 attack_surface_summary.txt (executive summary)"
echo "  📝 discovery_report.txt (detailed technical report)"
echo "  📁 categorized/ (hosts organized by type)"
echo "  📍 all_discovered_hosts.txt (master host list)"
echo "  🔍 dns_results.txt (hostname resolutions)"

# Enhanced scan results
echo "  🛡️  Evidence preservation:"
echo "     - EVIDENCE_MANIFEST.txt (complete file inventory with checksums)"
echo "     - evidence/ directory (organized by reconnaissance phase)"
echo "     - service_targets/ directory (service-specific target lists)"
echo
echo "  👥 Team Assignment Files:"
echo "     - evidence/phase8_host_categorization/team_windows.txt"
echo "     - evidence/phase8_host_categorization/team_linux.txt" 
echo "     - evidence/phase8_host_categorization/team_network.txt"

if [ -f "$SESSION_DIR/smb_hosts.txt" ]; then
    echo "  🪟 smb_hosts.txt (SMB/Windows hosts)"
fi
if [ -f "$SESSION_DIR/netbios_names.txt" ]; then
    echo "  🏷️  netbios_names.txt (NetBIOS computer names)"
fi
echo
echo "Opening detailed report..."
echo
cat "$REPORT_FILE"

# Log script completion
log_script_end "multi_phase_discovery.sh" 0
