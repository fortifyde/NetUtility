#!/bin/sh

# IPv6 Network Discovery Script
# Implements IPv6 multicast discovery and neighbor solicitation scanning

. "$(dirname "$0")/../common/utils.sh"

echo "=== IPv6 Network Discovery ==="
echo

DISCOVERY_DIR="${NETUTIL_WORKDIR:-$HOME}/discovery"
TEMP_DIR=$(mktemp -d)

# Cleanup on exit
trap 'rm -rf "$TEMP_DIR"' EXIT

# Create discovery directory
mkdir -p "$DISCOVERY_DIR"

# IPv6 multicast addresses for discovery
IPV6_ALL_NODES="ff02::1"
IPV6_ALL_ROUTERS="ff02::2"
IPV6_ALL_DHCP="ff02::1:2"
IPV6_SOLICITED_NODE="ff02::1:ff00:0/104"

# Get current interface
echo "Available network interfaces:"
selected_interface=$(select_interface)

if [ -z "$selected_interface" ]; then
    echo "No interface selected"
    exit 1
fi

echo "Selected interface: $selected_interface"

# Check if interface has IPv6 enabled
ipv6_addresses=$(ip -6 addr show "$selected_interface" | grep -c "inet6")
if [ "$ipv6_addresses" -eq 0 ]; then
    echo "Warning: No IPv6 addresses found on $selected_interface"
    echo "IPv6 may not be enabled on this interface"
    echo
fi

# Create timestamped discovery session
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SESSION_DIR="$DISCOVERY_DIR/ipv6_discovery_${TIMESTAMP}"
mkdir -p "$SESSION_DIR"

# Discovery report
REPORT_FILE="$SESSION_DIR/ipv6_discovery_report.txt"

echo "=== IPv6 Network Discovery Report ===" > "$REPORT_FILE"
echo "Interface: $selected_interface" >> "$REPORT_FILE"
echo "Discovery started: $(date)" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Display current IPv6 configuration
echo "--- CURRENT IPv6 CONFIGURATION ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "IPv6 addresses on $selected_interface:" >> "$REPORT_FILE"
ip -6 addr show "$selected_interface" | grep "inet6" | \
    sed 's/^[[:space:]]*/  /' >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "IPv6 routing table:" >> "$REPORT_FILE"
ip -6 route show dev "$selected_interface" | sed 's/^/  /' >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Phase 1: IPv6 Multicast Discovery
echo "--- PHASE 1: IPv6 MULTICAST DISCOVERY ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Phase 1: IPv6 Multicast Discovery - Pinging multicast addresses..."

# Ping all nodes multicast address
echo "Pinging all-nodes multicast address ($IPV6_ALL_NODES):" >> "$REPORT_FILE"
ping6 -c 3 -I "$selected_interface" "$IPV6_ALL_NODES" 2>/dev/null | \
    grep "bytes from" | awk '{print $4}' | cut -d':' -f1 | sort -u > "$TEMP_DIR/all_nodes.txt"

if [ -s "$TEMP_DIR/all_nodes.txt" ]; then
    echo "Responses from all-nodes multicast:" >> "$REPORT_FILE"
    cat "$TEMP_DIR/all_nodes.txt" | sed 's/^/  /' >> "$REPORT_FILE"
else
    echo "No responses to all-nodes multicast" >> "$REPORT_FILE"
fi
echo >> "$REPORT_FILE"

# Ping all routers multicast address
echo "Pinging all-routers multicast address ($IPV6_ALL_ROUTERS):" >> "$REPORT_FILE"
ping6 -c 3 -I "$selected_interface" "$IPV6_ALL_ROUTERS" 2>/dev/null | \
    grep "bytes from" | awk '{print $4}' | cut -d':' -f1 | sort -u > "$TEMP_DIR/all_routers.txt"

if [ -s "$TEMP_DIR/all_routers.txt" ]; then
    echo "Responses from all-routers multicast:" >> "$REPORT_FILE"
    cat "$TEMP_DIR/all_routers.txt" | sed 's/^/  /' >> "$REPORT_FILE"
else
    echo "No responses to all-routers multicast" >> "$REPORT_FILE"
fi
echo >> "$REPORT_FILE"

# Ping DHCPv6 multicast address
echo "Pinging DHCPv6 multicast address ($IPV6_ALL_DHCP):" >> "$REPORT_FILE"
ping6 -c 3 -I "$selected_interface" "$IPV6_ALL_DHCP" 2>/dev/null | \
    grep "bytes from" | awk '{print $4}' | cut -d':' -f1 | sort -u > "$TEMP_DIR/dhcpv6.txt"

if [ -s "$TEMP_DIR/dhcpv6.txt" ]; then
    echo "Responses from DHCPv6 multicast:" >> "$REPORT_FILE"
    cat "$TEMP_DIR/dhcpv6.txt" | sed 's/^/  /' >> "$REPORT_FILE"
else
    echo "No responses to DHCPv6 multicast" >> "$REPORT_FILE"
fi
echo >> "$REPORT_FILE"

# Phase 2: Neighbor Discovery Table
echo "--- PHASE 2: NEIGHBOR DISCOVERY TABLE ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Phase 2: Neighbor Discovery - Checking neighbor cache..."
echo "Current IPv6 neighbor cache:" >> "$REPORT_FILE"
ip -6 neighbor show dev "$selected_interface" | \
    grep -v "FAILED" | sed 's/^/  /' >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Extract IPv6 addresses from neighbor cache
ip -6 neighbor show dev "$selected_interface" | \
    grep -v "FAILED" | awk '{print $1}' > "$TEMP_DIR/neighbors.txt"

# Phase 3: Router Solicitation
echo "--- PHASE 3: ROUTER SOLICITATION ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Phase 3: Router Solicitation - Discovering routers..."
if command -v rdisc6 >/dev/null 2>&1; then
    echo "Using rdisc6 for router discovery..." >> "$REPORT_FILE"
    timeout 10 rdisc6 "$selected_interface" 2>/dev/null | \
        grep -E "Soliciting|Advertisement from" >> "$REPORT_FILE"
else
    echo "rdisc6 not available, using manual router discovery..." >> "$REPORT_FILE"
    # Manual router solicitation using ping to all-routers
    ping6 -c 2 -I "$selected_interface" "$IPV6_ALL_ROUTERS" >/dev/null 2>&1
    sleep 2
    echo "Router advertisements received (check neighbor cache):" >> "$REPORT_FILE"
    ip -6 neighbor show dev "$selected_interface" | \
        grep "router" | sed 's/^/  /' >> "$REPORT_FILE"
fi
echo >> "$REPORT_FILE"

# Phase 4: Address Scanning
echo "--- PHASE 4: IPv6 ADDRESS SCANNING ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Phase 4: IPv6 Address Scanning - Testing common IPv6 addresses..."

# Get link-local prefix from interface
link_local_prefix=$(ip -6 addr show "$selected_interface" | grep "fe80" | \
    head -1 | awk '{print $2}' | cut -d'/' -f1 | cut -d':' -f1-4)

if [ -n "$link_local_prefix" ]; then
    echo "Scanning link-local addresses with prefix $link_local_prefix:" >> "$REPORT_FILE"
    
    # Test common link-local addresses
    for suffix in "::1" "::2" "::10" "::100" "::254" "::fffe" "::ffff"; do
        test_addr="${link_local_prefix}${suffix}"
        if ping6 -c 1 -W 1 "$test_addr%$selected_interface" >/dev/null 2>&1; then
            echo "  $test_addr - ALIVE" >> "$REPORT_FILE"
            echo "$test_addr" >> "$TEMP_DIR/scanned_addresses.txt"
        fi
    done
else
    echo "No link-local prefix found for scanning" >> "$REPORT_FILE"
fi
echo >> "$REPORT_FILE"

# Phase 5: Service Discovery
echo "--- PHASE 5: IPv6 SERVICE DISCOVERY ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Phase 5: IPv6 Service Discovery - Checking for IPv6 services..."

# Combine all discovered addresses
cat "$TEMP_DIR/all_nodes.txt" "$TEMP_DIR/all_routers.txt" "$TEMP_DIR/dhcpv6.txt" \
    "$TEMP_DIR/neighbors.txt" "$TEMP_DIR/scanned_addresses.txt" 2>/dev/null | \
    sort -u > "$TEMP_DIR/all_ipv6_hosts.txt"

if [ -s "$TEMP_DIR/all_ipv6_hosts.txt" ]; then
    echo "Discovered IPv6 addresses:" >> "$REPORT_FILE"
    cat "$TEMP_DIR/all_ipv6_hosts.txt" | sed 's/^/  /' >> "$REPORT_FILE"
    echo >> "$REPORT_FILE"
    
    # Port scanning on discovered hosts (if nmap supports IPv6)
    if command -v nmap >/dev/null 2>&1; then
        echo "Performing IPv6 port scan on discovered hosts..." >> "$REPORT_FILE"
        # Quick scan of common ports
        nmap -6 -n -sS --top-ports 100 -T4 --open -oN "$SESSION_DIR/ipv6_nmap_results.txt" \
            -iL "$TEMP_DIR/all_ipv6_hosts.txt" 2>/dev/null | \
            grep -E "Nmap scan report|open" >> "$REPORT_FILE"
    else
        echo "nmap not available for IPv6 port scanning" >> "$REPORT_FILE"
    fi
else
    echo "No IPv6 addresses discovered" >> "$REPORT_FILE"
fi
echo >> "$REPORT_FILE"

# Phase 6: IPv6 Security Analysis
echo "--- PHASE 6: IPv6 SECURITY ANALYSIS ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Phase 6: IPv6 Security Analysis - Checking for security issues..."

# Check for privacy extensions
echo "Privacy extensions status:" >> "$REPORT_FILE"
if [ -f "/proc/sys/net/ipv6/conf/$selected_interface/use_tempaddr" ]; then
    privacy_status=$(cat "/proc/sys/net/ipv6/conf/$selected_interface/use_tempaddr")
    case "$privacy_status" in
        0) echo "  Privacy extensions: DISABLED" >> "$REPORT_FILE" ;;
        1) echo "  Privacy extensions: ENABLED (prefer public)" >> "$REPORT_FILE" ;;
        2) echo "  Privacy extensions: ENABLED (prefer temporary)" >> "$REPORT_FILE" ;;
        *) echo "  Privacy extensions: UNKNOWN ($privacy_status)" >> "$REPORT_FILE" ;;
    esac
else
    echo "  Privacy extensions: Status unknown" >> "$REPORT_FILE"
fi

# Check for IPv6 forwarding
echo "IPv6 forwarding status:" >> "$REPORT_FILE"
if [ -f "/proc/sys/net/ipv6/conf/all/forwarding" ]; then
    forwarding_status=$(cat "/proc/sys/net/ipv6/conf/all/forwarding")
    if [ "$forwarding_status" = "1" ]; then
        echo "  IPv6 forwarding: ENABLED (this host may be routing IPv6)" >> "$REPORT_FILE"
    else
        echo "  IPv6 forwarding: DISABLED" >> "$REPORT_FILE"
    fi
else
    echo "  IPv6 forwarding: Status unknown" >> "$REPORT_FILE"
fi

# Check for duplicate addresses
echo "Duplicate address detection:" >> "$REPORT_FILE"
if ip -6 addr show "$selected_interface" | grep -q "dadfailed"; then
    echo "  ⚠️  Duplicate addresses detected!" >> "$REPORT_FILE"
else
    echo "  No duplicate addresses detected" >> "$REPORT_FILE"
fi

echo >> "$REPORT_FILE"

# Summary
echo "--- DISCOVERY SUMMARY ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

all_nodes_count=$(wc -l < "$TEMP_DIR/all_nodes.txt" 2>/dev/null || echo 0)
all_routers_count=$(wc -l < "$TEMP_DIR/all_routers.txt" 2>/dev/null || echo 0)
dhcpv6_count=$(wc -l < "$TEMP_DIR/dhcpv6.txt" 2>/dev/null || echo 0)
neighbors_count=$(wc -l < "$TEMP_DIR/neighbors.txt" 2>/dev/null || echo 0)
total_discovered=$(wc -l < "$TEMP_DIR/all_ipv6_hosts.txt" 2>/dev/null || echo 0)

echo "IPv6 Discovery Statistics:" >> "$REPORT_FILE"
echo "  Responses to all-nodes multicast: $all_nodes_count" >> "$REPORT_FILE"
echo "  Responses to all-routers multicast: $all_routers_count" >> "$REPORT_FILE"
echo "  Responses to DHCPv6 multicast: $dhcpv6_count" >> "$REPORT_FILE"
echo "  Neighbor cache entries: $neighbors_count" >> "$REPORT_FILE"
echo "  Total unique IPv6 addresses: $total_discovered" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Discovery phases completed:" >> "$REPORT_FILE"
echo "  ✓ Phase 1: Multicast Discovery" >> "$REPORT_FILE"
echo "  ✓ Phase 2: Neighbor Discovery" >> "$REPORT_FILE"
echo "  ✓ Phase 3: Router Solicitation" >> "$REPORT_FILE"
echo "  ✓ Phase 4: Address Scanning" >> "$REPORT_FILE"
echo "  ✓ Phase 5: Service Discovery" >> "$REPORT_FILE"
echo "  ✓ Phase 6: Security Analysis" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Discovery completed at $(date)" >> "$REPORT_FILE"

# Create summary files
if [ -s "$TEMP_DIR/all_ipv6_hosts.txt" ]; then
    cp "$TEMP_DIR/all_ipv6_hosts.txt" "$SESSION_DIR/discovered_ipv6_hosts.txt"
fi

echo
echo "IPv6 discovery complete!"
echo "Results saved to: $SESSION_DIR"
echo
echo "Discovery Summary:"
echo "  Total IPv6 addresses discovered: $total_discovered"
echo "  All-nodes multicast responses: $all_nodes_count"
echo "  All-routers multicast responses: $all_routers_count"
echo "  DHCPv6 multicast responses: $dhcpv6_count"
echo "  Neighbor cache entries: $neighbors_count"
echo
echo "Files created:"
echo "  - ipv6_discovery_report.txt (detailed report)"
if [ -s "$TEMP_DIR/all_ipv6_hosts.txt" ]; then
    echo "  - discovered_ipv6_hosts.txt (IPv6 host list)"
fi
if [ -f "$SESSION_DIR/ipv6_nmap_results.txt" ]; then
    echo "  - ipv6_nmap_results.txt (IPv6 port scan results)"
fi
echo
echo "Opening detailed report..."
echo
cat "$REPORT_FILE"