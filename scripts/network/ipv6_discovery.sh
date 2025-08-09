#!/bin/sh

# IPv6 Network Discovery Script
# Implements IPv6 multicast discovery and neighbor solicitation scanning
# Can be called standalone or integrated into multiphase discovery workflow

. "$(dirname "$0")/../common/utils.sh"

# IPv6 Discovery Function - supports both standalone and integrated modes
perform_ipv6_discovery_main() {
    local interface="$1"
    local evidence_base_dir="$2"  # Base evidence directory (e.g., session/evidence)
    
    # Determine if we're running standalone or integrated
    if [ -z "$interface" ]; then
        # Standalone mode - interactive interface selection
        echo "=== IPv6 Network Discovery ==="
        echo
        
        echo "Available network interfaces:"
        interface=$(select_interface)
        
        if [ -z "$interface" ]; then
            echo "No interface selected"
            exit 1
        fi
        
        echo "Selected interface: $interface"
        
        # Set up standalone evidence structure
        DISCOVERY_DIR="${NETUTIL_WORKDIR:-$HOME}/discovery"
        TIMESTAMP=$(date +%Y%m%d_%H%M%S)
        SESSION_DIR="$DISCOVERY_DIR/ipv6_discovery_${TIMESTAMP}"
        evidence_base_dir="$SESSION_DIR/evidence"
    fi
    
    # Create IPv6 evidence directory structure
    IPV6_EVIDENCE_DIR="$evidence_base_dir/ipv6_discovery"
    mkdir -p "$IPV6_EVIDENCE_DIR"/{multicast_discovery,neighbor_analysis,router_discovery,address_scanning,service_discovery,security_analysis}
    mkdir -p "$IPV6_EVIDENCE_DIR"/{multicast_discovery,service_discovery}/raw_scans
    
    # Set up output files
    IPV6_HOSTS_FILE="$IPV6_EVIDENCE_DIR/discovered_ipv6_hosts.txt"
    IPV6_REPORT_FILE="$IPV6_EVIDENCE_DIR/ipv6_discovery_report.txt"
    
    # Initialize report
    echo "=== IPv6 Network Discovery Report ===" > "$IPV6_REPORT_FILE"
    echo "Interface: $interface" >> "$IPV6_REPORT_FILE"
    echo "Discovery started: $(date)" >> "$IPV6_REPORT_FILE"
    echo "Evidence directory: $IPV6_EVIDENCE_DIR" >> "$IPV6_REPORT_FILE"
    echo >> "$IPV6_REPORT_FILE"
    
    # Create working directory
    TEMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TEMP_DIR"' EXIT
    
    # Initialize output files
    > "$IPV6_HOSTS_FILE"
    
    # Check if interface has IPv6 enabled
    ipv6_addresses=$(ip -6 addr show "$interface" | grep -c "inet6")
    if [ "$ipv6_addresses" -eq 0 ]; then
        echo "Warning: No IPv6 addresses found on $interface" >> "$IPV6_REPORT_FILE"
        echo "IPv6 may not be enabled on this interface" >> "$IPV6_REPORT_FILE"
        if [ -z "$evidence_base_dir" ]; then
            echo "Warning: No IPv6 addresses found on $interface"
            echo "IPv6 may not be enabled on this interface"
        fi
        return 0
    fi
    
    # Display current IPv6 configuration
    echo "--- CURRENT IPv6 CONFIGURATION ---" >> "$IPV6_REPORT_FILE"
    echo >> "$IPV6_REPORT_FILE"
    
    echo "IPv6 addresses on $interface:" >> "$IPV6_REPORT_FILE"
    ip -6 addr show "$interface" | grep "inet6" | \
        sed 's/^[[:space:]]*/ /' >> "$IPV6_REPORT_FILE"
    echo >> "$IPV6_REPORT_FILE"
    
    echo "IPv6 routing table:" >> "$IPV6_REPORT_FILE"
    ip -6 route show dev "$interface" | sed 's/^/ /' >> "$IPV6_REPORT_FILE"
    echo >> "$IPV6_REPORT_FILE"

    # Phase 1: IPv6 Multicast Discovery
    echo "--- PHASE 1: IPv6 MULTICAST DISCOVERY ---" >> "$IPV6_REPORT_FILE"
    echo >> "$IPV6_REPORT_FILE"
    
    # Define IPv6 multicast addresses
    IPV6_ALL_NODES="ff02::1"
    IPV6_ALL_ROUTERS="ff02::2"
    IPV6_ALL_DHCP="ff02::1:2"
    
    # Ping all nodes multicast address
    echo "Pinging all-nodes multicast address ($IPV6_ALL_NODES):" >> "$IPV6_REPORT_FILE"
    ping6 -c 3 -I "$interface" "$IPV6_ALL_NODES" 2>/dev/null | \
        grep "bytes from" | awk '{print $4}' | cut -d':' -f1 | sort -u > "$TEMP_DIR/all_nodes.txt"

    if [ -s "$TEMP_DIR/all_nodes.txt" ]; then
        echo "Responses from all-nodes multicast:" >> "$IPV6_REPORT_FILE"
        cat "$TEMP_DIR/all_nodes.txt" | sed 's/^/ /' >> "$IPV6_REPORT_FILE"
        cat "$TEMP_DIR/all_nodes.txt" >> "$IPV6_HOSTS_FILE"
        cp "$TEMP_DIR/all_nodes.txt" "$IPV6_EVIDENCE_DIR/multicast_discovery/all_nodes_responses.txt"
    else
        echo "No responses to all-nodes multicast" >> "$IPV6_REPORT_FILE"
    fi
    echo >> "$IPV6_REPORT_FILE"

    # Ping all routers multicast address
    echo "Pinging all-routers multicast address ($IPV6_ALL_ROUTERS):" >> "$IPV6_REPORT_FILE"
    ping6 -c 3 -I "$interface" "$IPV6_ALL_ROUTERS" 2>/dev/null | \
        grep "bytes from" | awk '{print $4}' | cut -d':' -f1 | sort -u > "$TEMP_DIR/all_routers.txt"

    if [ -s "$TEMP_DIR/all_routers.txt" ]; then
        echo "Responses from all-routers multicast:" >> "$IPV6_REPORT_FILE"
        cat "$TEMP_DIR/all_routers.txt" | sed 's/^/ /' >> "$IPV6_REPORT_FILE"
        cat "$TEMP_DIR/all_routers.txt" >> "$IPV6_HOSTS_FILE"
        cp "$TEMP_DIR/all_routers.txt" "$IPV6_EVIDENCE_DIR/multicast_discovery/all_routers_responses.txt"
    else
        echo "No responses to all-routers multicast" >> "$IPV6_REPORT_FILE"
    fi
    echo >> "$IPV6_REPORT_FILE"

    # Ping DHCPv6 multicast address
    echo "Pinging DHCPv6 multicast address ($IPV6_ALL_DHCP):" >> "$IPV6_REPORT_FILE"
    ping6 -c 3 -I "$interface" "$IPV6_ALL_DHCP" 2>/dev/null | \
        grep "bytes from" | awk '{print $4}' | cut -d':' -f1 | sort -u > "$TEMP_DIR/dhcpv6.txt"

    if [ -s "$TEMP_DIR/dhcpv6.txt" ]; then
        echo "Responses from DHCPv6 multicast:" >> "$IPV6_REPORT_FILE"
        cat "$TEMP_DIR/dhcpv6.txt" | sed 's/^/ /' >> "$IPV6_REPORT_FILE"
        cat "$TEMP_DIR/dhcpv6.txt" >> "$IPV6_HOSTS_FILE"
        cp "$TEMP_DIR/dhcpv6.txt" "$IPV6_EVIDENCE_DIR/multicast_discovery/dhcpv6_responses.txt"
    else
        echo "No responses to DHCPv6 multicast" >> "$IPV6_REPORT_FILE"
    fi
    echo >> "$IPV6_REPORT_FILE"

    # Phase 2: Neighbor Discovery Table
    echo "--- PHASE 2: NEIGHBOR DISCOVERY TABLE ---" >> "$IPV6_REPORT_FILE"
    echo >> "$IPV6_REPORT_FILE"

    echo "Current IPv6 neighbor cache:" >> "$IPV6_REPORT_FILE"
    ip -6 neighbor show dev "$interface" | \
        grep -v "FAILED" | sed 's/^/ /' >> "$IPV6_REPORT_FILE"
    echo >> "$IPV6_REPORT_FILE"

    # Extract IPv6 addresses from neighbor cache
    ip -6 neighbor show dev "$interface" | \
        grep -v "FAILED" | awk '{print $1}' > "$TEMP_DIR/neighbors.txt"
    
    if [ -s "$TEMP_DIR/neighbors.txt" ]; then
        cat "$TEMP_DIR/neighbors.txt" >> "$IPV6_HOSTS_FILE"
        cp "$TEMP_DIR/neighbors.txt" "$IPV6_EVIDENCE_DIR/neighbor_analysis/neighbor_cache.txt"
    fi

    # Phase 3: Router Solicitation
    echo "--- PHASE 3: ROUTER SOLICITATION ---" >> "$IPV6_REPORT_FILE"
    echo >> "$IPV6_REPORT_FILE"

    if command -v rdisc6 >/dev/null 2>&1; then
        echo "Using rdisc6 for router discovery..." >> "$IPV6_REPORT_FILE"
        timeout 10 rdisc6 "$interface" 2>/dev/null | \
            grep -E "Soliciting|Advertisement from" >> "$IPV6_REPORT_FILE"
        
        # Extract router addresses if any were discovered
        timeout 10 rdisc6 "$interface" 2>/dev/null | \
            grep "Advertisement from" | awk '{print $3}' | sort -u > "$TEMP_DIR/routers.txt"
        
        if [ -s "$TEMP_DIR/routers.txt" ]; then
            cat "$TEMP_DIR/routers.txt" >> "$IPV6_HOSTS_FILE"
            cp "$TEMP_DIR/routers.txt" "$IPV6_EVIDENCE_DIR/router_discovery/discovered_routers.txt"
        fi
    else
        echo "rdisc6 not available, using manual router discovery..." >> "$IPV6_REPORT_FILE"
        # Manual router solicitation using ping to all-routers
        ping6 -c 2 -I "$interface" "$IPV6_ALL_ROUTERS" >/dev/null 2>&1
        sleep 2
        echo "Router advertisements received (check neighbor cache):" >> "$IPV6_REPORT_FILE"
        ip -6 neighbor show dev "$interface" | \
            grep "router" | sed 's/^/ /' >> "$IPV6_REPORT_FILE"
        
        # Extract router addresses from neighbor cache
        ip -6 neighbor show dev "$interface" | \
            grep "router" | awk '{print $1}' > "$TEMP_DIR/routers.txt"
        
        if [ -s "$TEMP_DIR/routers.txt" ]; then
            cat "$TEMP_DIR/routers.txt" >> "$IPV6_HOSTS_FILE"
            cp "$TEMP_DIR/routers.txt" "$IPV6_EVIDENCE_DIR/router_discovery/neighbor_routers.txt"
        fi
    fi
    echo >> "$IPV6_REPORT_FILE"

    # Phase 4: Address Scanning
    # Link-local address probing
    link_local_prefix=$(ip -6 addr show "$interface" | grep "fe80" | \
        head -1 | awk '{print $2}' | cut -d'/' -f1 | cut -d':' -f1-4)
    
    if [ -n "$link_local_prefix" ] && command -v ping6 >/dev/null 2>&1; then
        echo "--- PHASE 4: ADDRESS SCANNING ---" >> "$IPV6_REPORT_FILE"
        echo "Scanning link-local addresses with prefix $link_local_prefix:" >> "$IPV6_REPORT_FILE"
        
        for suffix in "::1" "::2" "::10" "::254"; do
            test_addr="${link_local_prefix}${suffix}"
            if ping6 -c 1 -W 1 "$test_addr%$interface" >/dev/null 2>&1; then
                echo " $test_addr - ALIVE" >> "$IPV6_REPORT_FILE"
                echo "$test_addr" >> "$IPV6_HOSTS_FILE"
                echo "$test_addr" >> "$TEMP_DIR/scanned_addresses.txt"
            fi
        done
        
        if [ -s "$TEMP_DIR/scanned_addresses.txt" ]; then
            cp "$TEMP_DIR/scanned_addresses.txt" "$IPV6_EVIDENCE_DIR/address_scanning/link_local_scan.txt"
        fi
        echo >> "$IPV6_REPORT_FILE"
    fi
    
    # Combine all discovered addresses and remove duplicates
    cat "$TEMP_DIR"/*.txt 2>/dev/null | sort -u > "$IPV6_HOSTS_FILE"
    
    # Phase 5: Service Discovery (if nmap available and hosts found)
    if [ -s "$IPV6_HOSTS_FILE" ] && command -v nmap >/dev/null 2>&1; then
        echo "--- PHASE 5: IPv6 SERVICE DISCOVERY ---" >> "$IPV6_REPORT_FILE"
        echo "Performing IPv6 port scan on discovered hosts..." >> "$IPV6_REPORT_FILE"
        
        nmap_output="$IPV6_EVIDENCE_DIR/service_discovery/raw_scans/ipv6_services.txt"
        nmap -6 -n -sS --top-ports 20 -T4 --open -oN "$nmap_output" \
              -iL "$IPV6_HOSTS_FILE" 2>/dev/null | \
              grep -E "Nmap scan report|open" >> "$IPV6_REPORT_FILE"
        echo >> "$IPV6_REPORT_FILE"
    fi
    
    # Final summary
    total_discovered=$(wc -l < "$IPV6_HOSTS_FILE" 2>/dev/null || echo 0)
    
    echo "--- DISCOVERY SUMMARY ---" >> "$IPV6_REPORT_FILE"
    echo "Total unique IPv6 addresses: $total_discovered" >> "$IPV6_REPORT_FILE"
    echo "Discovery completed at $(date)" >> "$IPV6_REPORT_FILE"
    echo >> "$IPV6_REPORT_FILE"
    
    # For standalone mode, provide user feedback
    if [ -z "$evidence_base_dir" ]; then
        echo
        echo "IPv6 discovery complete!"
        echo "Results saved to: $IPV6_EVIDENCE_DIR"
        echo "Total IPv6 addresses discovered: $total_discovered"
        if [ -f "$nmap_output" ]; then
            echo "IPv6 service scan results: $nmap_output"
        fi
    fi
}

# Main execution - determine if running standalone or as integration
if [ "$0" = "${BASH_SOURCE[0]}" ] || [ "${0##*/}" = "ipv6_discovery.sh" ]; then
    # Running standalone
    perform_ipv6_discovery_main
else
    # Running as integration - function is available for calling
    true
fi