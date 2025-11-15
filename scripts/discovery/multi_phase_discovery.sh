#!/bin/sh

# Enhanced Multi-phase Network Discovery Workflow
# Comprehensive network discovery
# Phase 1: Enhanced Network Discovery (topology, infrastructure, DNS, segmentation, ARP)
# Phase 2: Comprehensive Host Discovery (ICMP, TCP bypass, UDP probes, masscan, early classification)
# Phase 3: DNS lookup → Phase 4: Windows Discovery → Phase 5: Progressive Port Scan
# Phase 6: Service Enumeration → Phase 7: Host Categorization → Phase 8: Evidence Processing

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
# Usage: multi_phase_discovery.sh [interface]
provided_interface="$1"

# Get current interface and network
if [ -n "$provided_interface" ]; then
    selected_interface="$provided_interface"
    echo "Using provided interface: $selected_interface"
else
    echo "Available network interfaces (including VLANs):"
    selected_interface=$(select_interface "Select interface or VLAN to scan" "" "false")

    if [ -z "$selected_interface" ]; then
        echo "No interface selected"
        exit 1
    fi
fi

echo "Selected interface: $selected_interface"
log_info "Selected interface: $selected_interface"

# Function to detect VLAN interface and extract VLAN ID
detect_vlan_interface() {
    interface="$1"
    # Check if interface name contains dot (e.g., eth0.100)
    if echo "$interface" | grep -q '\.'; then
        vlan_id=$(echo "$interface" | cut -d'.' -f2)
        # Validate VLAN ID is numeric
        if echo "$vlan_id" | grep -qE '^[0-9]+$'; then
            echo "$vlan_id"
            return 0
        fi
    fi
    return 1
}

# Detect if selected interface is a VLAN interface
if detected_vlan_id=$(detect_vlan_interface "$selected_interface"); then
    IS_VLAN_INTERFACE="true"
    DETECTED_VLAN_ID="$detected_vlan_id"
    echo "VLAN interface detected: $selected_interface (VLAN $DETECTED_VLAN_ID)"
    log_info "VLAN interface detected: $selected_interface (VLAN $DETECTED_VLAN_ID)"
else
    IS_VLAN_INTERFACE="false"
    DETECTED_VLAN_ID=""
fi

# Network range detection and confirmation
echo
# Check for manually specified network range first
if [ -n "$MANUAL_NETWORK_RANGE" ]; then
    network_range="$MANUAL_NETWORK_RANGE"
    echo "Using manually specified network range: $network_range"
    log_info "Using manually specified network range: $network_range"
else
    # Get network range for selected interface
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
    else
        # Network detected - prompt user for confirmation
        echo "Detected network: $network_range"
        echo "Scan this network? (Y/n/custom): " >&2
        read -r confirm
        case "$confirm" in
            n|N|no|NO)
                echo "Scan cancelled by user."
                exit 0
                ;;
            c|C|custom|CUSTOM)
                echo "Enter custom network range:"
                network_range=$(prompt_network_range)
                if [ -z "$network_range" ]; then
                    echo "No network range provided. Exiting."
                    exit 1
                fi
                ;;
            *)
                echo "Using detected network: $network_range"
                ;;
        esac
    fi
    log_info "Network range: $network_range"
fi

echo

# Create discovery session - check for auto-discovery context
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Detect auto-discovery context and use appropriate directories
if [ "$AUTO_DISCOVERY_SESSION" = "true" ]; then
    # Running within auto-discovery workflow - use provided directories
    if [ "$AUTO_DISCOVERY_MAIN_NETWORK" = "true" ]; then
        # Main network discovery in auto-discovery
        SESSION_ROOT_DIR="$AUTO_DISCOVERY_SESSION_DIR"
        SESSION_DIR="$AUTO_DISCOVERY_MAIN_DIR"
        echo "Auto-discovery context detected: Main network mode"
        log_info "Multiphase discovery running in auto-discovery main network context"
    elif [ -n "$AUTO_DISCOVERY_VLAN_ID" ]; then
        # VLAN-specific discovery in auto-discovery
        SESSION_ROOT_DIR="$AUTO_DISCOVERY_SESSION_DIR"
        # shellcheck disable=SC2153
        SESSION_DIR="$AUTO_DISCOVERY_VLAN_DIR"
        echo "Auto-discovery context detected: VLAN $AUTO_DISCOVERY_VLAN_ID"
        log_info "Multiphase discovery running in auto-discovery VLAN context: $AUTO_DISCOVERY_VLAN_ID"
    else
        # Fallback to standard behavior
        SESSION_ROOT_DIR="$DISCOVERY_DIR/discovery_${TIMESTAMP}"
        SESSION_DIR="$SESSION_ROOT_DIR"
        mkdir -p "$SESSION_DIR"
    fi
else
    # Standalone multiphase discovery - create VLAN-aware structure
    SESSION_ROOT_DIR="$DISCOVERY_DIR/discovery_${TIMESTAMP}"
    mkdir -p "$SESSION_ROOT_DIR"

    # Determine subfolder based on VLAN detection
    if [ "$IS_VLAN_INTERFACE" = "true" ]; then
        # VLAN interface detected - create VLAN-specific subfolder
        SESSION_DIR="$SESSION_ROOT_DIR/vlan_$DETECTED_VLAN_ID"
        mkdir -p "$SESSION_DIR"
        echo "Standalone discovery mode: VLAN $DETECTED_VLAN_ID"
        echo "Results will be organized in: $SESSION_DIR"
        log_info "Multiphase discovery running in standalone VLAN mode: VLAN $DETECTED_VLAN_ID"
    else
        # Non-VLAN interface - create main_network subfolder
        SESSION_DIR="$SESSION_ROOT_DIR/main_network"
        mkdir -p "$SESSION_DIR"
        echo "Standalone discovery mode: Main network"
        echo "Results will be organized in: $SESSION_DIR"
        log_info "Multiphase discovery running in standalone main network mode"
    fi
fi

# Ensure session directory exists
mkdir -p "$SESSION_DIR"

# Create session metadata file (only for standalone mode, not auto-discovery)
if [ "$AUTO_DISCOVERY_SESSION" != "true" ]; then
    SESSION_METADATA="$SESSION_ROOT_DIR/session_metadata.txt"
    {
        echo "=== Multi-Phase Discovery Session Metadata ==="
        echo "Session ID: discovery_${TIMESTAMP}"
        echo "Started: $(date)"
        echo "Interface: $selected_interface"
        if [ "$IS_VLAN_INTERFACE" = "true" ]; then
            echo "VLAN ID: $DETECTED_VLAN_ID"
            echo "Discovery Mode: Standalone VLAN Discovery"
        else
            echo "Discovery Mode: Standalone Main Network Discovery"
        fi
        echo "Network: $network_range"
        echo "Session directory: $SESSION_ROOT_DIR"
        echo "Results directory: $SESSION_DIR"
        echo ""
    } > "$SESSION_METADATA"
fi

# Create professional evidence directory structure
EVIDENCE_DIR="$SESSION_DIR/evidence"
mkdir -p "$EVIDENCE_DIR/phase1_network_discovery" \
         "$EVIDENCE_DIR/phase2_host_discovery" \
         "$EVIDENCE_DIR/phase3_dns_analysis" \
         "$EVIDENCE_DIR/phase4_windows_discovery" \
         "$EVIDENCE_DIR/phase5_port_scanning" \
         "$EVIDENCE_DIR/phase6_service_enumeration" \
         "$EVIDENCE_DIR/phase7_host_categorization"
mkdir -p "$EVIDENCE_DIR/phase1_network_discovery/raw_scans" \
         "$EVIDENCE_DIR/phase2_host_discovery/raw_scans" \
         "$EVIDENCE_DIR/phase3_dns_analysis/raw_scans" \
         "$EVIDENCE_DIR/phase4_windows_discovery/raw_scans" \
         "$EVIDENCE_DIR/phase5_port_scanning/raw_scans" \
         "$EVIDENCE_DIR/phase6_service_enumeration/raw_scans"
mkdir -p "$SESSION_DIR/service_targets" \
         "$SESSION_DIR/reports"

# Define evidence directories for easy reference
PHASE1_DIR="$EVIDENCE_DIR/phase1_network_discovery"
PHASE2_DIR="$EVIDENCE_DIR/phase2_host_discovery"
PHASE3_DIR="$EVIDENCE_DIR/phase3_dns_analysis"
PHASE4_DIR="$EVIDENCE_DIR/phase4_windows_discovery"
PHASE5_DIR="$EVIDENCE_DIR/phase5_port_scanning"
PHASE6_DIR="$EVIDENCE_DIR/phase6_service_enumeration"
PHASE7_DIR="$EVIDENCE_DIR/phase7_host_categorization"
# Phase 7 (formerly Phase 9) removed - no longer generating separate team handoff files
SERVICE_TARGETS_DIR="$SESSION_DIR/service_targets"
REPORTS_DIR="$SESSION_DIR/reports"

# Discovery report
REPORT_FILE="$REPORTS_DIR/discovery_report.txt"

echo "=== Multi-Phase Network Discovery Report ===" > "$REPORT_FILE"
echo "Interface: $selected_interface" >> "$REPORT_FILE"
echo "Network: $network_range" >> "$REPORT_FILE"
echo "Discovery started: $(date)" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Starting multi-phase discovery on $network_range..."
log_info "Starting multi-phase discovery on $network_range"
target_networks="$network_range"

# Helper functions for enriched file generation
extract_version_from_nmap() {
    ip="$1"
    service="$2"

    # Search nmap XML/gnmap files for version info
    version="Unknown"
    for scan_file in "$EVIDENCE_DIR"/raw_scans/nmap_*.gnmap "$EVIDENCE_DIR"/raw_scans/nmap_*.txt; do
        if [ -f "$scan_file" ]; then
            # Extract version from nmap output for this IP and service
            version_line=$(grep "$ip" "$scan_file" 2>/dev/null | grep -i "$service" | grep -oP 'Version: \K[^,)]+' | head -1)
            if [ -n "$version_line" ]; then
                version="$version_line"
                break
            fi
        fi
    done
    echo "$version"
}

extract_os_from_nmap() {
    ip="$1"

    # Try to extract OS from nmap scan results
    os="Unknown"
    for scan_file in "$EVIDENCE_DIR"/raw_scans/nmap_*.gnmap "$EVIDENCE_DIR"/raw_scans/nmap_*.txt; do
        if [ -f "$scan_file" ]; then
            os_line=$(grep -A5 "$ip" "$scan_file" 2>/dev/null | grep -i "OS:" | head -1 | sed 's/.*OS: //' | cut -d',' -f1)
            if [ -n "$os_line" ]; then
                os="$os_line"
                break
            fi
        fi
    done
    echo "$os"
}

detect_vulnerability_flags() {
    ip="$1"
    service="$2"
    version="$3"

    flags=""

    case "$service" in
        smb)
            # Check for SMBv1
            if grep -q "$ip.*SMBv1" "$EVIDENCE_DIR"/raw_scans/nmap_*.txt 2>/dev/null; then
                flags="${flags}[SMBv1_ENABLED]"
            fi
            # Check for signing disabled
            if grep -q "$ip.*signing.*disabled" "$EVIDENCE_DIR"/raw_scans/nmap_*.txt 2>/dev/null; then
                flags="${flags}[SIGNING_OFF]"
            fi
            ;;
        ssh)
            # Check for old OpenSSH versions
            if echo "$version" | grep -qE "OpenSSH_[0-5]\.|OpenSSH_6\.[0-6]"; then
                flags="${flags}[VULNERABLE_VERSION]"
            fi
            ;;
        web|http|https)
            # Check for outdated web servers
            if echo "$version" | grep -qiE "Apache/[0-1]\.|Apache/2\.[0-2]"; then
                flags="${flags}[OUTDATED]"
            fi
            ;;
    esac

    echo "$flags"
}

get_host_services() {
    ip="$1"

    services=""
    [ -f "$SERVICE_TARGETS_DIR/ssh_targets.txt" ] && grep -q "^$ip$" "$SERVICE_TARGETS_DIR/ssh_targets.txt" && services="$services SSH:22,"
    [ -f "$SERVICE_TARGETS_DIR/smb_targets.txt" ] && grep -q "^$ip$" "$SERVICE_TARGETS_DIR/smb_targets.txt" && services="$services SMB:445,"
    [ -f "$SERVICE_TARGETS_DIR/web_targets.txt" ] && grep -q "^$ip$" "$SERVICE_TARGETS_DIR/web_targets.txt" && services="$services HTTP:80/443,"
    [ -f "$SERVICE_TARGETS_DIR/rdp_targets.txt" ] && grep -q "^$ip$" "$SERVICE_TARGETS_DIR/rdp_targets.txt" && services="$services RDP:3389,"
    [ -f "$SERVICE_TARGETS_DIR/database_targets.txt" ] && grep -q "^$ip$" "$SERVICE_TARGETS_DIR/database_targets.txt" && services="$services DB,"

    # Remove trailing comma
    services=$(echo "$services" | sed 's/,$//')
    echo "$services"
}

create_enriched_service_target() {
    service_name="$1"
    base_file="$2"

    enriched_file="${base_file%.txt}_enriched.txt"

    # Header
    echo "# Enriched $service_name targets - IP:PORT HOSTNAME VERSION OS [FLAGS]" > "$enriched_file"
    echo "# Format: IP:PORT HOSTNAME VERSION OS [FLAGS]" >> "$enriched_file"
    echo "#" >> "$enriched_file"

    # Process each IP in the base file
    if [ -f "$base_file" ] && [ -s "$base_file" ]; then
        while read -r ip; do
            if [ -z "$ip" ]; then
                continue
            fi

            # Get hostname from dns_results.txt
            hostname="-"
            if [ -f "$SESSION_DIR/dns_results.txt" ]; then
                hostname=$(grep "^${ip}[[:space:]]" "$SESSION_DIR/dns_results.txt" 2>/dev/null | awk '{print $2}' | head -1)
                [ -z "$hostname" ] && hostname="-"
            fi

            # Get version and OS info
            version=$(extract_version_from_nmap "$ip" "$service_name")
            os=$(extract_os_from_nmap "$ip")
            flags=$(detect_vulnerability_flags "$ip" "$service_name" "$version")

            # Determine default port based on service
            case "$service_name" in
                ssh) port="22" ;;
                smb) port="445" ;;
                rdp) port="3389" ;;
                web|http) port="80" ;;
                https) port="443" ;;
                database) port="3306" ;;
                dns) port="53" ;;
                ftp) port="21" ;;
                *) port="?" ;;
            esac

            # Write enriched line
            echo "$ip:$port $hostname $version $os $flags" >> "$enriched_file"
        done < "$base_file"
    fi

    log_info "Created enriched file: $enriched_file"
}

create_enriched_categorized_hosts() {
    category="$1"
    base_file="$2"

    enriched_file="${base_file%.txt}_enriched.txt"

    # Header
    echo "# Enriched $category hosts - IP HOSTNAME OS [SERVICES]" > "$enriched_file"
    echo "# Format: IP HOSTNAME OS [SERVICES]" >> "$enriched_file"
    echo "#" >> "$enriched_file"

    # Process each IP
    if [ -f "$base_file" ] && [ -s "$base_file" ]; then
        while read -r ip; do
            if [ -z "$ip" ]; then
                continue
            fi

            # Get hostname
            hostname="-"
            if [ -f "$SESSION_DIR/dns_results.txt" ]; then
                hostname=$(grep "^${ip}[[:space:]]" "$SESSION_DIR/dns_results.txt" 2>/dev/null | awk '{print $2}' | head -1)
                [ -z "$hostname" ] && hostname="-"
            fi

            # Get OS and services
            os=$(extract_os_from_nmap "$ip")
            services=$(get_host_services "$ip")
            [ -z "$services" ] && services="None"

            # Write enriched line
            echo "$ip $hostname $os [$services]" >> "$enriched_file"
        done < "$base_file"
    fi

    log_info "Created enriched categorized file: $enriched_file"
}

# Network topology discovery functions
discover_network_topology() {
    target_networks="$1"
    output_file="$2"

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
    network="$1"
    output_file="$2"

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
            # Verify host is reachable before adding
            if ping -c 1 -W 1 "$test_ip" >/dev/null 2>&1; then
                echo "      Reverse DNS: $test_ip -> $reverse_result (verified alive)" >> "$REPORT_FILE"
                echo "$test_ip" >> "$output_file"
                reverse_dns_found=$((reverse_dns_found + 1))
            else
                echo "      Reverse DNS: $test_ip -> $reverse_result (not reachable, skipped)" >> "$REPORT_FILE"
            fi
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
    target_networks="$1"
    output_file="$2"

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
            network_sanitized=$(echo "$network" | tr '/' '_')
            snmp_output="$PHASE1_DIR/raw_scans/snmp_scan_${network_sanitized}_$$.txt"
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

                # Keep raw scan for evidence
            fi
        fi
    done
}

# TCP discovery with firewall bypass techniques
perform_tcp_discovery() {
    target_networks="$1"
    output_file="$2"

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

            network_sanitized=$(echo "$network" | tr '/' '_')
            tcp_output="$PHASE2_DIR/raw_scans/tcp_discovery_${network_sanitized}_$$.txt"
            
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

                # Keep raw scan for evidence
            else
                echo "      TCP discovery failed on $network" >> "$REPORT_FILE"
            fi
        fi
    done
}

# UDP discovery for common services
perform_udp_discovery() {
    target_networks="$1"
    output_file="$2"

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

            network_sanitized=$(echo "$network" | tr '/' '_')
            udp_output="$PHASE2_DIR/raw_scans/udp_discovery_${network_sanitized}_$$.txt"
            
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

                # Keep raw scan for evidence
            else
                echo "      UDP discovery failed on $network" >> "$REPORT_FILE"
            fi
        fi
    done
}

# High-speed discovery using masscan (if available)
perform_masscan_discovery() {
    target_networks="$1"
    output_file="$2"

    echo "  Attempting high-speed discovery with masscan..." >> "$REPORT_FILE"
    
    if ! command -v masscan >/dev/null 2>&1; then
        echo "    masscan not available, skipping high-speed discovery" >> "$REPORT_FILE"
        return
    fi
    
    for network in $target_networks; do
        if [ -n "$network" ]; then
            echo "    Masscan sweep on $network..." >> "$REPORT_FILE"

            network_sanitized=$(echo "$network" | tr '/' '_')
            masscan_output="$PHASE2_DIR/raw_scans/masscan_discovery_${network_sanitized}_$$.txt"
            
            # High-speed scan of top ports
            if masscan -p80,443,22,21,25,53,135,139,445 "$network" \
                  --rate=1000 --open -oG "$masscan_output" >/dev/null 2>&1; then

                # Extract hosts with open ports (IP is in 4th column of grepable output)
                masscan_hosts=$(grep "open" "$masscan_output" 2>/dev/null | awk '{print $4}' | sort -u)
                
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

                # Keep raw scan for evidence
            else
                echo "      Masscan failed on $network" >> "$REPORT_FILE"
            fi
        fi
    done
}

# IPv6 Network Discovery - Integration with refactored IPv6 script
perform_ipv6_discovery() {
    interface="$1"
    output_file="$2"

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
    host_file="$1"
    output_file="$2"

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
    host_file="$1"
    output_file="$2"

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
    target_networks="$1"
    output_file="$2"

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
    network="$1"
    output_file="$2"

    # Create descriptive temp file names (sanitize network for safe filenames)
    network_sanitized=$(echo "$network" | tr '/' '_' | tr ':' '_')
    temp_output="$PHASE2_DIR/raw_scans/fping_sweep_${network_sanitized}_$$.txt"
    temp_errors="$PHASE2_DIR/raw_scans/fping_errors_${network_sanitized}_$$.txt"

    # Configuration for improved reliability
    timeout=1000    # Timeout per ping in ms (1 second)
    retries=2       # Number of retries per host
    interval=10     # Interval between pings in ms
    # max_hosts=100   # Maximum concurrent hosts (reduce network load) - unused
    
    echo "  Enhanced fping configuration:" >> "$REPORT_FILE"
    echo "    Network: $network" >> "$REPORT_FILE"
    echo "    Timeout: ${timeout}ms, Retries: $retries, Interval: ${interval}ms" >> "$REPORT_FILE"
    
    # Attempt 1: Standard enhanced fping with optimal settings
    echo "  Attempting fping sweep (standard mode)..." >> "$REPORT_FILE"
    fping -a -g -t "$timeout" -r "$retries" -i "$interval" -q "$network" 2>"$temp_errors" >"$temp_output"
    if [ -s "$temp_output" ]; then
        # fping found hosts (exit code 1 is normal when some hosts are unreachable)
        cat "$temp_output" >> "$output_file"
        hosts_found=$(wc -l < "$temp_output")
        echo "    Standard mode: Found $hosts_found hosts" >> "$REPORT_FILE"

        # Log any warnings (but not errors since we succeeded)
        if [ -s "$temp_errors" ] && ! grep -q "ICMP.*unreachable\|Permission denied" "$temp_errors"; then
            echo "    Warnings: $(head -3 "$temp_errors" | tr '\n' '; ')" >> "$REPORT_FILE"
        fi

        # Keep raw scan for evidence
        return 0
    fi
    
    # Attempt 2: Fallback with relaxed settings for difficult networks
    echo "  Standard mode failed, trying compatibility mode..." >> "$REPORT_FILE"
    : > "$temp_output"
    : > "$temp_errors"

    # More conservative settings for difficult networks
    fping -a -g -t 2000 -r 3 -i 50 -q "$network" 2>"$temp_errors" >"$temp_output"
    if [ -s "$temp_output" ]; then
        cat "$temp_output" >> "$output_file"
        hosts_found=$(wc -l < "$temp_output")
        echo "    Compatibility mode: Found $hosts_found hosts" >> "$REPORT_FILE"

        # Keep raw scan for evidence
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
            fping -a -g -S 0 -t 2000 -r 2 -q "$network" 2>/dev/null >"$temp_output"
            if [ -s "$temp_output" ]; then
                cat "$temp_output" >> "$output_file"
                hosts_found=$(wc -l < "$temp_output")
                echo "    Unprivileged mode: Found $hosts_found hosts" >> "$REPORT_FILE"

                # Keep raw scan for evidence
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
    : > "$temp_output"
    timeout 30 fping -a -g "$network" 2>/dev/null >"$temp_output"
    if [ -s "$temp_output" ]; then
        cat "$temp_output" >> "$output_file"
        hosts_found=$(wc -l < "$temp_output")
        echo "    Basic mode: Found $hosts_found hosts" >> "$REPORT_FILE"

        # Keep raw scan for evidence
        return 0
    fi
    
    # Complete failure - log and return error
    echo "    All fping attempts failed - network may be unreachable or misconfigured" >> "$REPORT_FILE"
    rm -f "$temp_output" "$temp_errors"
    return 1
}

# Enhanced service categorization function
categorize_services_enhanced() {
    cd "$SESSION_DIR" || return

    # Create service category files
    : > "$SERVICE_TARGETS_DIR/ftp_targets.txt"
    : > "$SERVICE_TARGETS_DIR/ssh_targets.txt"
    : > "$SERVICE_TARGETS_DIR/telnet_targets.txt"
    : > "$SERVICE_TARGETS_DIR/smtp_targets.txt"
    : > "$SERVICE_TARGETS_DIR/dns_targets.txt"
    : > "$SERVICE_TARGETS_DIR/web_targets.txt"
    : > "$SERVICE_TARGETS_DIR/pop3_targets.txt"
    : > "$SERVICE_TARGETS_DIR/imap_targets.txt"
    : > "$SERVICE_TARGETS_DIR/smb_targets.txt"
    : > "$SERVICE_TARGETS_DIR/database_targets.txt"
    : > "$SERVICE_TARGETS_DIR/rdp_targets.txt"
    : > "$SERVICE_TARGETS_DIR/vnc_targets.txt"
    : > "$SERVICE_TARGETS_DIR/snmp_targets.txt"
    
    # Process all scan results
    for scan_file in "$SESSION_DIR"/nmap_*.txt "$PHASE5_DIR"/raw_scans/nmap_*.txt; do
        if [ -f "$scan_file" ]; then
            # Extract services by port patterns using awk
            awk '/Nmap scan report for/{host=$5} /21\/tcp.*open/{print host}' "$scan_file" 2>/dev/null >> "$SERVICE_TARGETS_DIR/ftp_targets.txt" || true
            awk '/Nmap scan report for/{host=$5} /22\/tcp.*open/{print host}' "$scan_file" 2>/dev/null >> "$SERVICE_TARGETS_DIR/ssh_targets.txt" || true
            awk '/Nmap scan report for/{host=$5} /23\/tcp.*open/{print host}' "$scan_file" 2>/dev/null >> "$SERVICE_TARGETS_DIR/telnet_targets.txt" || true
            awk '/Nmap scan report for/{host=$5} /(25|587|465)\/tcp.*open/{print host}' "$scan_file" 2>/dev/null >> "$SERVICE_TARGETS_DIR/smtp_targets.txt" || true
            awk '/Nmap scan report for/{host=$5} /53\/(tcp|udp).*open/{print host}' "$scan_file" 2>/dev/null >> "$SERVICE_TARGETS_DIR/dns_targets.txt" || true
            awk '/Nmap scan report for/{host=$5} /(80|443|8080|8443)\/tcp.*open/{print host}' "$scan_file" 2>/dev/null >> "$SERVICE_TARGETS_DIR/web_targets.txt" || true
            awk '/Nmap scan report for/{host=$5} /(110|995)\/tcp.*open/{print host}' "$scan_file" 2>/dev/null >> "$SERVICE_TARGETS_DIR/pop3_targets.txt" || true
            awk '/Nmap scan report for/{host=$5} /(143|993)\/tcp.*open/{print host}' "$scan_file" 2>/dev/null >> "$SERVICE_TARGETS_DIR/imap_targets.txt" || true
            awk '/Nmap scan report for/{host=$5} /(135|139|445)\/tcp.*open/{print host}' "$scan_file" 2>/dev/null >> "$SERVICE_TARGETS_DIR/smb_targets.txt" || true
            awk '/Nmap scan report for/{host=$5} /(1433|3306|5432|1521|27017)\/tcp.*open/{print host}' "$scan_file" 2>/dev/null >> "$SERVICE_TARGETS_DIR/database_targets.txt" || true
            awk '/Nmap scan report for/{host=$5} /3389\/tcp.*open/{print host}' "$scan_file" 2>/dev/null >> "$SERVICE_TARGETS_DIR/rdp_targets.txt" || true
            awk '/Nmap scan report for/{host=$5} /5900\/tcp.*open/{print host}' "$scan_file" 2>/dev/null >> "$SERVICE_TARGETS_DIR/vnc_targets.txt" || true
            awk '/Nmap scan report for/{host=$5} /161\/udp.*open/{print host}' "$scan_file" 2>/dev/null >> "$SERVICE_TARGETS_DIR/snmp_targets.txt" || true
        fi
    done
    
    # Remove duplicates from each target file
    for target_file in "$SERVICE_TARGETS_DIR"/*_targets.txt; do
        if [ -f "$target_file" ]; then
            sort -u "$target_file" -o "$target_file"
        fi
    done

    # Generate enriched service target files
    echo "Creating enriched service target files..." >> "$REPORT_FILE"
    create_enriched_service_target "ftp" "$SERVICE_TARGETS_DIR/ftp_targets.txt"
    create_enriched_service_target "ssh" "$SERVICE_TARGETS_DIR/ssh_targets.txt"
    create_enriched_service_target "telnet" "$SERVICE_TARGETS_DIR/telnet_targets.txt"
    create_enriched_service_target "smtp" "$SERVICE_TARGETS_DIR/smtp_targets.txt"
    create_enriched_service_target "dns" "$SERVICE_TARGETS_DIR/dns_targets.txt"
    create_enriched_service_target "web" "$SERVICE_TARGETS_DIR/web_targets.txt"
    create_enriched_service_target "pop3" "$SERVICE_TARGETS_DIR/pop3_targets.txt"
    create_enriched_service_target "imap" "$SERVICE_TARGETS_DIR/imap_targets.txt"
    create_enriched_service_target "smb" "$SERVICE_TARGETS_DIR/smb_targets.txt"
    create_enriched_service_target "database" "$SERVICE_TARGETS_DIR/database_targets.txt"
    create_enriched_service_target "rdp" "$SERVICE_TARGETS_DIR/rdp_targets.txt"
    create_enriched_service_target "vnc" "$SERVICE_TARGETS_DIR/vnc_targets.txt"
    create_enriched_service_target "snmp" "$SERVICE_TARGETS_DIR/snmp_targets.txt"
    echo "Enriched service target files created" >> "$REPORT_FILE"

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
    : > "$PHASE6_DIR/ssh_service_details.txt"
    
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
    : > "$PHASE6_DIR/web_service_details.txt"
    
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
    : > "$PHASE6_DIR/database_service_details.txt"
    
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

# Phase 7 vulnerability scanning functions removed - moved to separate workflow
# These functions are no longer part of auto discovery to improve efficiency
# Use the dedicated vulnerability scanning workflow instead

# Phase 1: Enhanced Network Discovery
echo "--- PHASE 1: ENHANCED NETWORK DISCOVERY ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Phase 1: Enhanced Network Discovery - Layer 2 discovery, topology analysis, and infrastructure identification..."

# Initialize host discovery files
: > "$PHASE1_DIR/arp_hosts.txt"
: > "$PHASE1_DIR/topology_hosts.txt"
: > "$PHASE1_DIR/infrastructure_hosts.txt"

# Sub-phase 1.1: Network Topology Discovery
echo "  Sub-phase 1.1: Network topology and boundary analysis..." >> "$REPORT_FILE"
discover_network_topology "$target_networks" "$PHASE1_DIR/topology_hosts.txt"

# Sub-phase 1.2: Infrastructure Device Identification  
echo "  Sub-phase 1.2: Network infrastructure identification..." >> "$REPORT_FILE"
identify_network_devices "$target_networks" "$PHASE1_DIR/infrastructure_hosts.txt"

# Sub-phase 1.3: Reverse DNS Pattern Analysis
echo "  Sub-phase 1.3: Reverse DNS enumeration..." >> "$REPORT_FILE"
perform_reverse_dns_enumeration "$network_range" "$PHASE1_DIR/topology_hosts.txt"

# Sub-phase 1.4: Network Segmentation Analysis
echo "  Sub-phase 1.4: Network segmentation analysis..." >> "$REPORT_FILE"
: > "$PHASE1_DIR/segmentation_analysis.txt"
analyze_network_segmentation "$target_networks" "$PHASE1_DIR/segmentation_analysis.txt"
segmentation_findings=$(wc -l < "$PHASE1_DIR/segmentation_analysis.txt")
echo "  Sub-phase 1.4 complete: $segmentation_findings segmentation findings" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Sub-phase 1.5: Layer 2 ARP Discovery
echo "  Sub-phase 1.5: Layer 2 ARP discovery..." >> "$REPORT_FILE"

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
: > "$PHASE2_DIR/ping_hosts.txt"
: > "$PHASE2_DIR/tcp_hosts.txt"
: > "$PHASE2_DIR/udp_hosts.txt"
: > "$PHASE2_DIR/masscan_hosts.txt"

# Sub-phase 2.1: ICMP Discovery (Traditional Ping Sweep)
echo "  Sub-phase 2.1: ICMP connectivity testing..." >> "$REPORT_FILE"

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
: > "$PHASE2_DIR/ipv6_hosts.txt"
perform_ipv6_discovery "$selected_interface" "$PHASE2_DIR/ipv6_hosts.txt"
ipv6_count=$(wc -l < "$PHASE2_DIR/ipv6_hosts.txt")
echo "  Sub-phase 2.5 complete: Found $ipv6_count IPv6 hosts." >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Combine all Phase 1 and Phase 2 results
cat "$PHASE1_DIR/phase1_all_hosts.txt" "$PHASE2_DIR/ping_hosts.txt" "$PHASE2_DIR/tcp_hosts.txt" \
    "$PHASE2_DIR/udp_hosts.txt" "$PHASE2_DIR/masscan_hosts.txt" "$PHASE2_DIR/ipv6_hosts.txt" | sort -u > "$PHASE2_DIR/all_hosts.txt"
all_hosts_count=$(wc -l < "$PHASE2_DIR/all_hosts.txt")

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
: > "$PHASE2_DIR/early_os_detection.txt"
: > "$PHASE2_DIR/early_device_classification.txt"

# Perform early OS detection on discovered hosts
perform_early_os_detection "$PHASE2_DIR/all_hosts.txt" "$PHASE2_DIR/early_os_detection.txt"

# Perform early device classification
perform_early_device_classification "$PHASE2_DIR/all_hosts.txt" "$PHASE2_DIR/early_device_classification.txt"

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
: > "$PHASE4_DIR/smb_hosts.txt"
: > "$PHASE4_DIR/netbios_names.txt"

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
    tr '\n' ' ' < "$PHASE2_DIR/all_hosts.txt" > "$PHASE5_DIR/nmap_targets.txt"
    
    # Stage 1: Fast common port scan
    # Using top 1000 ports for comprehensive coverage while maintaining reasonable speed
    echo "  Stage 1: Fast common port scan (top 1000 ports)..." >> "$REPORT_FILE"

    nmap -n -sS --top-ports 1000 -T4 --min-rate 2000 --open --reason -oN "$SESSION_DIR/nmap_fast_scan.txt" \
        -iL "$PHASE2_DIR/all_hosts.txt" 2>/dev/null | \
        grep -E "Nmap scan report|open" >> "$REPORT_FILE"
    
    # Extract high-value targets for comprehensive scanning
    echo "  Identifying high-value targets..." >> "$REPORT_FILE"
    awk '/Nmap scan report for/{host=$5} /(22|80|443|445|3389|21|23|25|53|135|139|1433|3306|5432)\/(tcp|udp).*open/{print host}' \
        "$SESSION_DIR/nmap_fast_scan.txt" 2>/dev/null | sort -u > "$PHASE5_DIR/high_value_targets.txt" || true
    
    hv_count=$(wc -l < "$PHASE5_DIR/high_value_targets.txt")
    echo "    High-value targets identified: $hv_count" >> "$REPORT_FILE"

    # Stage 2: UDP scan on critical ports
    # Reduced from 100 to top 20 UDP ports for efficiency
    # Covers DNS, SNMP, NTP, DHCP, and other critical UDP services
    echo "  Stage 2: UDP scan on critical ports (top 20)..." >> "$REPORT_FILE"
    nmap -n -sU --top-ports 20 -T4 --open \
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

    # Extract open ports from Phase 5 TCP scan for targeted enumeration
    echo "  Extracting open ports from Phase 5 results..." >> "$REPORT_FILE"
    if [ -f "$SESSION_DIR/nmap_fast_scan.txt" ]; then
        # Extract unique open TCP ports across all hosts (excluding open|filtered)
        grep -oP '\d+/tcp\s+open\s' "$SESSION_DIR/nmap_fast_scan.txt" 2>/dev/null | \
            cut -d'/' -f1 | sort -nu | tr '\n' ',' | sed 's/,$//' > "$PHASE6_DIR/open_ports.txt" || true

        # Also extract UDP ports if available (excluding open|filtered)
        if [ -f "$PHASE5_DIR/raw_scans/nmap_udp_scan.txt" ]; then
            grep -oP '\d+/udp\s+open\s' "$PHASE5_DIR/raw_scans/nmap_udp_scan.txt" 2>/dev/null | \
                cut -d'/' -f1 | sort -nu | tr '\n' ',' | sed 's/,$//' > "$PHASE6_DIR/open_udp_ports.txt" || true
        fi

        OPEN_TCP_PORTS=$(cat "$PHASE6_DIR/open_ports.txt" 2>/dev/null)
        OPEN_UDP_PORTS=$(cat "$PHASE6_DIR/open_udp_ports.txt" 2>/dev/null)

        if [ -n "$OPEN_TCP_PORTS" ]; then
            echo "    Open TCP ports found: $OPEN_TCP_PORTS" >> "$REPORT_FILE"
            PORT_ARGS="-p $OPEN_TCP_PORTS"
        else
            echo "    No open TCP ports found, using top 1000 ports" >> "$REPORT_FILE"
            PORT_ARGS="--top-ports 1000"
        fi

        if [ -n "$OPEN_UDP_PORTS" ]; then
            echo "    Open UDP ports found: $OPEN_UDP_PORTS" >> "$REPORT_FILE"
        fi
    else
        echo "    Phase 5 results not found, using top 1000 ports" >> "$REPORT_FILE"
        PORT_ARGS="--top-ports 1000"
        OPEN_UDP_PORTS=""
    fi

    # Version detection on discovered open ports only
    # Using -Pn since hosts are already confirmed up from Phase 2
    echo "  Stage 1: Version detection and banner grabbing (TCP)..." >> "$REPORT_FILE"
    nmap -Pn -n -sV --version-intensity 5 -T4 $PORT_ARGS \
        -iL "$PHASE2_DIR/all_hosts.txt" -oA "$PHASE6_DIR/raw_scans/nmap_version_detection" 2>/dev/null || true

    # Default script scan on discovered open ports only
    # Using -Pn since hosts are already confirmed up from Phase 2
    echo "  Stage 2: Default NSE scripts (TCP)..." >> "$REPORT_FILE"
    nmap -Pn -n -sC -T4 $PORT_ARGS \
        -iL "$PHASE2_DIR/all_hosts.txt" -oA "$PHASE6_DIR/raw_scans/nmap_default_scripts" 2>/dev/null || true

    # UDP service enumeration on discovered open UDP ports
    if [ -n "$OPEN_UDP_PORTS" ]; then
        echo "  Stage 3: UDP service version detection..." >> "$REPORT_FILE"
        nmap -Pn -n -sU -sV --version-intensity 5 -T4 -p "$OPEN_UDP_PORTS" \
            -iL "$PHASE2_DIR/all_hosts.txt" -oA "$PHASE6_DIR/raw_scans/nmap_udp_services" 2>/dev/null || true

        echo "  Stage 4: UDP default NSE scripts..." >> "$REPORT_FILE"
        nmap -Pn -n -sU -sC -T4 -p "$OPEN_UDP_PORTS" \
            -iL "$PHASE2_DIR/all_hosts.txt" -oA "$PHASE6_DIR/raw_scans/nmap_udp_scripts" 2>/dev/null || true
    fi
    
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

# Phase 7: Host Categorization
echo "--- PHASE 7: HOST CATEGORIZATION ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Phase 7: Host Categorization - Analyzing discovered hosts..."

# Create categorized host lists
mkdir -p "$SESSION_DIR/categorized"
mkdir -p "$PHASE7_DIR"

# Initialize detailed category files
: > "$SESSION_DIR/categorized/windows_hosts.txt"
: > "$SESSION_DIR/categorized/linux_hosts.txt"
: > "$SESSION_DIR/categorized/network_devices.txt"
: > "$SESSION_DIR/categorized/web_servers.txt"
: > "$SESSION_DIR/categorized/database_servers.txt"
: > "$SESSION_DIR/categorized/unknown_hosts.txt"

# Initialize simplified team assignment files 
: > "$PHASE7_DIR/team_windows.txt"
: > "$PHASE7_DIR/team_linux.txt" 
: > "$PHASE7_DIR/team_network.txt"

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
            echo "$host" >> "$PHASE7_DIR/team_windows.txt"
        # Priority 2: Check for common services (if nmap results exist)
        elif [ -f "$SESSION_DIR/nmap_services.txt" ]; then
            # Check for Windows-specific services
            if grep -A 50 "$host" "$SESSION_DIR/nmap_services.txt" | grep -qE "(microsoft|smb|netbios|rdp|3389|445|139)"; then
                category="windows"
                echo "$host" >> "$SESSION_DIR/categorized/windows_hosts.txt"
                echo "$host" >> "$PHASE7_DIR/team_windows.txt"
            # Check for web servers
            elif grep -A 50 "$host" "$SESSION_DIR/nmap_services.txt" | grep -qE "(http|80|443|8080|8443)"; then
                category="web_server"
                echo "$host" >> "$SESSION_DIR/categorized/web_servers.txt"
                echo "$host" >> "$PHASE7_DIR/team_linux.txt"  # Web servers typically Linux
            # Check for database servers
            elif grep -A 50 "$host" "$SESSION_DIR/nmap_services.txt" | grep -qE "(mysql|postgresql|mssql|oracle|1433|3306|5432)"; then
                category="database"
                echo "$host" >> "$SESSION_DIR/categorized/database_servers.txt"
                # Database assignment: MSSQL->Windows, others->Linux
                if grep -A 50 "$host" "$SESSION_DIR/nmap_services.txt" | grep -qE "(mssql|1433)"; then
                    echo "$host" >> "$PHASE7_DIR/team_windows.txt"
                else
                    echo "$host" >> "$PHASE7_DIR/team_linux.txt"
                fi
            # Check for network devices
            elif grep -A 50 "$host" "$SESSION_DIR/nmap_services.txt" | grep -qE "(snmp|ssh|telnet|161|22|23)"; then
                category="network_device"
                echo "$host" >> "$SESSION_DIR/categorized/network_devices.txt"
                echo "$host" >> "$PHASE7_DIR/team_network.txt"
            # TTL-based categorization
            elif [ -n "$ttl" ] && [ "$ttl" -ge 120 ]; then
                category="windows"
                echo "$host" >> "$SESSION_DIR/categorized/windows_hosts.txt"
                echo "$host" >> "$PHASE7_DIR/team_windows.txt"
            elif [ -n "$ttl" ] && [ "$ttl" -ge 60 ] && [ "$ttl" -lt 120 ]; then
                category="linux"
                echo "$host" >> "$SESSION_DIR/categorized/linux_hosts.txt"
                echo "$host" >> "$PHASE7_DIR/team_linux.txt"
            else
                category="unknown"
                echo "$host" >> "$SESSION_DIR/categorized/unknown_hosts.txt"
                echo "$host" >> "$PHASE7_DIR/team_network.txt"  # Unknown hosts go to network team
            fi
        else
            # Fallback to TTL-based categorization only
            if [ -n "$ttl" ] && [ "$ttl" -ge 120 ]; then
                category="windows"
                echo "$host" >> "$SESSION_DIR/categorized/windows_hosts.txt"
                echo "$host" >> "$PHASE7_DIR/team_windows.txt"
            elif [ -n "$ttl" ] && [ "$ttl" -ge 60 ] && [ "$ttl" -lt 120 ]; then
                category="linux"
                echo "$host" >> "$SESSION_DIR/categorized/linux_hosts.txt"
                echo "$host" >> "$PHASE7_DIR/team_linux.txt"
            else
                category="unknown"
                echo "$host" >> "$SESSION_DIR/categorized/unknown_hosts.txt"
                echo "$host" >> "$PHASE7_DIR/team_network.txt"  # Unknown hosts go to network team
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

# Generate enriched categorized host files
echo "  Creating enriched categorized host files..." >> "$REPORT_FILE"
create_enriched_categorized_hosts "windows" "$SESSION_DIR/categorized/windows_hosts.txt"
create_enriched_categorized_hosts "linux" "$SESSION_DIR/categorized/linux_hosts.txt"
create_enriched_categorized_hosts "network_devices" "$SESSION_DIR/categorized/network_devices.txt"
create_enriched_categorized_hosts "web_servers" "$SESSION_DIR/categorized/web_servers.txt"
create_enriched_categorized_hosts "database_servers" "$SESSION_DIR/categorized/database_servers.txt"
create_enriched_categorized_hosts "unknown" "$SESSION_DIR/categorized/unknown_hosts.txt"
echo "  Enriched categorized host files created" >> "$REPORT_FILE"

echo >> "$REPORT_FILE"

# Phase 8: Evidence Processing and Manifest Creation
echo "--- PHASE 8: EVIDENCE PROCESSING ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Phase 8: Evidence Processing - Consolidating scan data and generating comprehensive service inventory..."

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
    echo "└── phase7_host_categorization/"
    echo "    ├── categorized/ (Detailed host type classifications)"
    echo "    ├── team_windows.txt (Windows hosts for Windows team)"
    echo "    ├── team_linux.txt (Linux/Unix hosts for Linux team)"  
    echo "    └── team_network.txt (Network devices/unknown for Network team)"
    echo ""
    echo "service_targets/ (Service-specific target lists and enriched files)"
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
    echo "IP_Address,Port,Protocol,State,Service,Version,Flags"

    # Process all nmap scan results from evidence directories
    for scan_file in "$EVIDENCE_DIR"/*/raw_scans/nmap_*.txt; do
        if [ -f "$scan_file" ]; then
            # Extract service information from nmap results with improved parsing
            current_host=""
            while IFS= read -r line; do
                # Check for host header
                if echo "$line" | grep -q "Nmap scan report for"; then
                    current_host=$(echo "$line" | awk '{print $5}' | tr -d '()')
                # Check for open ports
                elif echo "$line" | grep -qE "^[0-9]+/(tcp|udp).*(open|filtered)"; then
                    if [ -n "$current_host" ]; then
                        # Parse port line more carefully
                        port=$(echo "$line" | awk '{print $1}' | cut -d'/' -f1)
                        protocol=$(echo "$line" | awk '{print $1}' | cut -d'/' -f2)
                        state=$(echo "$line" | awk '{print $2}')
                        service=$(echo "$line" | awk '{print $3}')

                        # Extract version info (everything after service name)
                        version=$(echo "$line" | cut -d' ' -f4- | sed 's/,/;/g' | sed 's/  */ /g')
                        [ -z "$version" ] && version="Unknown"

                        # Detect vulnerability flags
                        flags=""
                        case "$service" in
                            microsoft-ds|netbios-ssn|smb)
                                if echo "$version" | grep -qi "SMBv1"; then
                                    flags="SMBv1_ENABLED"
                                fi
                                ;;
                            ssh)
                                if echo "$version" | grep -qE "OpenSSH [0-5]\.|OpenSSH 6\.[0-6]"; then
                                    flags="VULNERABLE_VERSION"
                                fi
                                ;;
                            ftp)
                                if echo "$version" | grep -qi "vsftpd 2\.[0-2]"; then
                                    flags="VULNERABLE_VERSION"
                                fi
                                ;;
                        esac

                        echo "$current_host,$port,$protocol,$state,$service,$version,$flags"
                    fi
                fi
            done < "$scan_file" 2>/dev/null || true
        fi
    done | sort -t',' -k1,1V -k2,2n -u
} > "$SESSION_DIR/comprehensive_service_inventory.csv"

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
team_windows_count=$(wc -l < "$PHASE7_DIR/team_windows.txt")
team_linux_count=$(wc -l < "$PHASE7_DIR/team_linux.txt")
team_network_count=$(wc -l < "$PHASE7_DIR/team_network.txt")

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
echo "  ✓ Phase 6: Service Enumeration (TCP/UDP version detection + NSE scripts)" >> "$REPORT_FILE"
echo "  ✓ Phase 7: Host Categorization (completed)" >> "$REPORT_FILE"
echo "  ✓ Phase 8: Evidence Processing (inventory generated)" >> "$REPORT_FILE"
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

echo "Final reporting complete" >> "$REPORT_FILE"
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
echo "  Network scanned: $network_range"
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
echo "     - evidence/phase7_host_categorization/team_windows.txt"
echo "     - evidence/phase7_host_categorization/team_linux.txt" 
echo "     - evidence/phase7_host_categorization/team_network.txt"

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
