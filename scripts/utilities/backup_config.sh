#!/bin/sh
#
# Network Configuration Backup Script
# Creates comprehensive backup of network interfaces, IPs, routes, and DNS
# Generates executable restoration script with proper ordering
#

set -e

# Configuration
BACKUP_DIR="${NETUTIL_WORKDIR:-$HOME}/netutil_backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="network_config_$TIMESTAMP"
BACKUP_FILE="$BACKUP_DIR/$BACKUP_NAME.tar.gz"
HOSTNAME=$(hostname)

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Create temporary working directory
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

echo "=== Network Configuration Backup ==="
echo
echo "Timestamp: $TIMESTAMP"
echo "Hostname: $HOSTNAME"
echo "Backup location: $BACKUP_FILE"
echo

# ============================================================================
# Phase 1: Enumerate Interfaces
# ============================================================================

echo "Phase 1: Enumerating network interfaces..."

PARENT_INTERFACES=""
VLAN_INTERFACES=""
INTERFACE_COUNT=0
VLAN_COUNT=0

# Parse interface information
ip link show | while read -r line; do
    case "$line" in
        [0-9]*:\ *@*:*)
            # VLAN interface (format: N: vlan.ID@parent: <...> state STATE)
            iface=$(echo "$line" | sed 's/^[0-9]*: *\([^@]*\)@.*/\1/')
            parent=$(echo "$line" | sed 's/.*@\([^:]*\):.*/\1/')
            state=$(echo "$line" | sed 's/.*state \([A-Z]*\).*/\1/')

            # Extract VLAN ID from interface name (e.g., eth0.100 -> 100)
            vlan_id=$(echo "$iface" | sed 's/.*\.\([0-9]*\)$/\1/')

            # Skip if this is loopback
            if [ "$iface" != "lo" ]; then
                echo "$iface:$parent:$vlan_id:$state" >> "$TEMP_DIR/vlan_list.tmp"
            fi
            ;;
        [0-9]*:\ *:*)
            # Parent/physical interface (format: N: iface: <...> state STATE)
            iface=$(echo "$line" | sed 's/^[0-9]*: *\([^:]*\):.*/\1/')
            state=$(echo "$line" | sed 's/.*state \([A-Z]*\).*/\1/')

            # Skip loopback
            if [ "$iface" != "lo" ]; then
                echo "$iface:$state" >> "$TEMP_DIR/parent_list.tmp"
            fi
            ;;
    esac
done

# Count interfaces
if [ -f "$TEMP_DIR/parent_list.tmp" ]; then
    INTERFACE_COUNT=$(wc -l < "$TEMP_DIR/parent_list.tmp")
fi

if [ -f "$TEMP_DIR/vlan_list.tmp" ]; then
    VLAN_COUNT=$(wc -l < "$TEMP_DIR/vlan_list.tmp")
    INTERFACE_COUNT=$((INTERFACE_COUNT + VLAN_COUNT))
fi

echo "  Found $INTERFACE_COUNT interfaces ($VLAN_COUNT VLANs)"

# ============================================================================
# Phase 2: Capture IP Addresses (excluding link-local IPv6)
# ============================================================================

echo "Phase 2: Capturing IP addresses..."

> "$TEMP_DIR/ip_addresses.conf"
IP_COUNT=0

ip addr show | awk '
BEGIN {
    iface = ""
}
/^[0-9]+:/ {
    # Extract interface name
    iface = $2
    gsub(/:/, "", iface)
    gsub(/@.*/, "", iface)
}
/inet / {
    # IPv4 address
    ip = $2
    # Skip loopback
    if (iface != "lo" && ip !~ /^127\./) {
        print iface ":" ip
    }
}
/inet6/ {
    # IPv6 address - only if NOT link-local (scope link)
    if ($4 != "link") {
        ip = $2
        if (iface != "lo") {
            print iface ":" ip
        }
    }
}
' > "$TEMP_DIR/ip_addresses.conf"

if [ -f "$TEMP_DIR/ip_addresses.conf" ]; then
    IP_COUNT=$(wc -l < "$TEMP_DIR/ip_addresses.conf")
fi

echo "  Captured $IP_COUNT IP addresses (link-local IPv6 excluded)"

# ============================================================================
# Phase 3: Capture Routes (excluding kernel routes)
# ============================================================================

echo "Phase 3: Capturing routes..."

> "$TEMP_DIR/routes.conf"
ROUTE_COUNT=0

# Capture routes, exclude kernel-generated routes
ip route show | grep -v "proto kernel" | while read -r route_line; do
    # Parse route: destination via gateway dev interface
    # Can be: "default via X.X.X.X dev ethX" or "X.X.X.X/YY via X.X.X.X dev ethX"
    echo "$route_line" >> "$TEMP_DIR/routes.conf"
    ROUTE_COUNT=$((ROUTE_COUNT + 1))
done

if [ -f "$TEMP_DIR/routes.conf" ]; then
    ROUTE_COUNT=$(wc -l < "$TEMP_DIR/routes.conf")
fi

echo "  Captured $ROUTE_COUNT routes (kernel routes excluded)"

# ============================================================================
# Phase 4: Capture DNS Configuration
# ============================================================================

echo "Phase 4: Capturing DNS configuration..."

> "$TEMP_DIR/dns.conf"

if [ -f /etc/resolv.conf ]; then
    # Extract nameservers
    grep "^nameserver" /etc/resolv.conf > "$TEMP_DIR/dns_nameservers.tmp" 2>/dev/null || true

    # Extract search domains
    grep "^search" /etc/resolv.conf > "$TEMP_DIR/dns_search.tmp" 2>/dev/null || true

    # Copy full resolv.conf for reference
    cp /etc/resolv.conf "$TEMP_DIR/resolv.conf.backup"
fi

echo "  DNS configuration captured"

# ============================================================================
# Phase 5: Save Debug Information
# ============================================================================

echo "Phase 5: Saving debug information..."

mkdir -p "$TEMP_DIR/debug"

# Raw command outputs for debugging
ip addr show > "$TEMP_DIR/debug/ip_addr_raw.txt"
ip link show > "$TEMP_DIR/debug/ip_link_raw.txt"
ip route show > "$TEMP_DIR/debug/ip_route_raw.txt"
ip route show table all > "$TEMP_DIR/debug/ip_route_all_raw.txt"

echo "  Debug information saved"

# ============================================================================
# Phase 6: Generate Metadata
# ============================================================================

echo "Phase 6: Generating metadata..."

cat > "$TEMP_DIR/metadata.txt" << METADATA_EOF
Backup Timestamp: $TIMESTAMP
Hostname: $HOSTNAME
Kernel: $(uname -r)
Interface Count: $INTERFACE_COUNT
VLAN Count: $VLAN_COUNT
IP Address Count: $IP_COUNT
Route Count: $ROUTE_COUNT
METADATA_EOF

echo "  Metadata generated"

# ============================================================================
# Phase 7: Generate Restoration Script
# ============================================================================

echo "Phase 7: Generating restoration script..."

cat > "$TEMP_DIR/restore.sh" << 'RESTORE_SCRIPT_EOF'
#!/bin/sh
#
# Network Configuration Restoration Script
# Auto-generated by backup_config.sh
#
# Usage: ./restore.sh [--execute]
#   Without --execute: Preview mode (shows what would be done)
#   With --execute: Executes the restoration
#

set -e

RESTORE_SCRIPT_EOF

# Add metadata to restoration script
cat >> "$TEMP_DIR/restore.sh" << RESTORE_META_EOF

# Backup Metadata
BACKUP_TIMESTAMP="$TIMESTAMP"
BACKUP_HOSTNAME="$HOSTNAME"
INTERFACE_COUNT=$INTERFACE_COUNT
VLAN_COUNT=$VLAN_COUNT
IP_COUNT=$IP_COUNT
ROUTE_COUNT=$ROUTE_COUNT

RESTORE_META_EOF

# Add parent interfaces data
cat >> "$TEMP_DIR/restore.sh" << 'RESTORE_PARENT_HEADER_EOF'

# Parent Interfaces (interface:state)
PARENT_INTERFACES="
RESTORE_PARENT_HEADER_EOF

if [ -f "$TEMP_DIR/parent_list.tmp" ]; then
    cat "$TEMP_DIR/parent_list.tmp" >> "$TEMP_DIR/restore.sh"
fi

cat >> "$TEMP_DIR/restore.sh" << 'RESTORE_PARENT_FOOTER_EOF'
"

RESTORE_PARENT_FOOTER_EOF

# Add VLAN interfaces data
cat >> "$TEMP_DIR/restore.sh" << 'RESTORE_VLAN_HEADER_EOF'

# VLAN Interfaces (vlan:parent:vlan_id:state)
VLAN_INTERFACES="
RESTORE_VLAN_HEADER_EOF

if [ -f "$TEMP_DIR/vlan_list.tmp" ]; then
    cat "$TEMP_DIR/vlan_list.tmp" >> "$TEMP_DIR/restore.sh"
fi

cat >> "$TEMP_DIR/restore.sh" << 'RESTORE_VLAN_FOOTER_EOF'
"

RESTORE_VLAN_FOOTER_EOF

# Add IP addresses data
cat >> "$TEMP_DIR/restore.sh" << 'RESTORE_IP_HEADER_EOF'

# IP Addresses (interface:ip/cidr)
IP_ADDRESSES="
RESTORE_IP_HEADER_EOF

if [ -f "$TEMP_DIR/ip_addresses.conf" ]; then
    cat "$TEMP_DIR/ip_addresses.conf" >> "$TEMP_DIR/restore.sh"
fi

cat >> "$TEMP_DIR/restore.sh" << 'RESTORE_IP_FOOTER_EOF'
"

RESTORE_IP_FOOTER_EOF

# Add routes data
cat >> "$TEMP_DIR/restore.sh" << 'RESTORE_ROUTE_HEADER_EOF'

# Routes (raw route commands)
ROUTES="
RESTORE_ROUTE_HEADER_EOF

if [ -f "$TEMP_DIR/routes.conf" ]; then
    cat "$TEMP_DIR/routes.conf" >> "$TEMP_DIR/restore.sh"
fi

cat >> "$TEMP_DIR/restore.sh" << 'RESTORE_ROUTE_FOOTER_EOF'
"

RESTORE_ROUTE_FOOTER_EOF

# Add DNS data
cat >> "$TEMP_DIR/restore.sh" << 'RESTORE_DNS_HEADER_EOF'

# DNS Configuration
DNS_NAMESERVERS="
RESTORE_DNS_HEADER_EOF

if [ -f "$TEMP_DIR/dns_nameservers.tmp" ]; then
    cat "$TEMP_DIR/dns_nameservers.tmp" >> "$TEMP_DIR/restore.sh"
fi

cat >> "$TEMP_DIR/restore.sh" << 'RESTORE_DNS_NS_FOOTER_EOF'
"

DNS_SEARCH="
RESTORE_DNS_NS_FOOTER_EOF

if [ -f "$TEMP_DIR/dns_search.tmp" ]; then
    cat "$TEMP_DIR/dns_search.tmp" >> "$TEMP_DIR/restore.sh"
fi

cat >> "$TEMP_DIR/restore.sh" << 'RESTORE_DNS_FOOTER_EOF'
"

RESTORE_DNS_FOOTER_EOF

# Add restoration functions
cat >> "$TEMP_DIR/restore.sh" << 'RESTORE_FUNCTIONS_EOF'

# ============================================================================
# Restoration Functions
# ============================================================================

log_info() {
    echo "[INFO] $1"
}

log_success() {
    echo "[SUCCESS] $1"
}

log_error() {
    echo "[ERROR] $1" >&2
}

log_warning() {
    echo "[WARNING] $1" >&2
}

# Phase 1: Shutdown interfaces (VLANs first, then parents)
shutdown_interfaces() {
    log_info "Phase 1: Shutting down interfaces..."

    # Shutdown VLANs first
    echo "$VLAN_INTERFACES" | while IFS=: read -r vlan parent vlan_id state; do
        if [ -n "$vlan" ]; then
            if [ "$DRY_RUN" = "true" ]; then
                log_info "  [DRY-RUN] Would bring down VLAN: $vlan"
            else
                log_info "  Bringing down VLAN: $vlan"
                ip link set "$vlan" down 2>/dev/null || log_warning "    Failed to bring down $vlan"
            fi
        fi
    done

    # Shutdown parent interfaces
    echo "$PARENT_INTERFACES" | while IFS=: read -r iface state; do
        if [ -n "$iface" ]; then
            if [ "$DRY_RUN" = "true" ]; then
                log_info "  [DRY-RUN] Would bring down interface: $iface"
            else
                log_info "  Bringing down interface: $iface"
                ip link set "$iface" down 2>/dev/null || log_warning "    Failed to bring down $iface"
            fi
        fi
    done

    log_success "Phase 1 complete"
}

# Phase 2: Restore parent interfaces
restore_parent_interfaces() {
    log_info "Phase 2: Restoring parent interfaces..."

    echo "$PARENT_INTERFACES" | while IFS=: read -r iface state; do
        if [ -n "$iface" ]; then
            if [ "$DRY_RUN" = "true" ]; then
                log_info "  [DRY-RUN] Would configure interface: $iface (state: $state)"
                log_info "    Would flush link-local IPv6 addresses"
            else
                log_info "  Configuring interface: $iface (state: $state)"

                # Bring interface up
                if ip link set "$iface" up 2>/dev/null; then
                    log_success "    Interface $iface brought UP"

                    # Flush link-local IPv6 addresses
                    ip -6 addr flush dev "$iface" scope link 2>/dev/null || true
                    log_info "    Link-local IPv6 addresses flushed"
                else
                    log_error "    Failed to bring up interface $iface"
                fi
            fi
        fi
    done

    log_success "Phase 2 complete"
}

# Phase 3: Restore VLAN interfaces
restore_vlan_interfaces() {
    log_info "Phase 3: Restoring VLAN interfaces..."

    echo "$VLAN_INTERFACES" | while IFS=: read -r vlan parent vlan_id state; do
        if [ -n "$vlan" ] && [ -n "$parent" ] && [ -n "$vlan_id" ]; then
            if [ "$DRY_RUN" = "true" ]; then
                log_info "  [DRY-RUN] Would create VLAN: $vlan (parent: $parent, ID: $vlan_id, state: $state)"
                log_info "    Would flush link-local IPv6 addresses"
            else
                log_info "  Creating VLAN: $vlan (parent: $parent, ID: $vlan_id)"

                # Check if VLAN already exists
                if ip link show "$vlan" >/dev/null 2>&1; then
                    log_warning "    VLAN $vlan already exists, skipping creation"
                else
                    # Create VLAN
                    if ip link add link "$parent" name "$vlan" type vlan id "$vlan_id" 2>/dev/null; then
                        log_success "    VLAN $vlan created"
                    else
                        log_error "    Failed to create VLAN $vlan"
                        continue
                    fi
                fi

                # Bring VLAN up
                if ip link set "$vlan" up 2>/dev/null; then
                    log_success "    VLAN $vlan brought UP"

                    # Flush link-local IPv6 addresses
                    ip -6 addr flush dev "$vlan" scope link 2>/dev/null || true
                    log_info "    Link-local IPv6 addresses flushed"
                else
                    log_error "    Failed to bring up VLAN $vlan"
                fi
            fi
        fi
    done

    log_success "Phase 3 complete"
}

# Phase 4: Restore IP addresses
restore_ip_addresses() {
    log_info "Phase 4: Restoring IP addresses..."

    echo "$IP_ADDRESSES" | while IFS=: read -r iface ip; do
        if [ -n "$iface" ] && [ -n "$ip" ]; then
            if [ "$DRY_RUN" = "true" ]; then
                log_info "  [DRY-RUN] Would add IP: $ip to $iface"
            else
                log_info "  Adding IP: $ip to $iface"

                # Check if IP already exists
                if ip addr show dev "$iface" | grep -q "$ip"; then
                    log_warning "    IP $ip already exists on $iface"
                else
                    if ip addr add "$ip" dev "$iface" 2>/dev/null; then
                        log_success "    IP $ip added to $iface"
                    else
                        log_error "    Failed to add IP $ip to $iface"
                    fi
                fi
            fi
        fi
    done

    log_success "Phase 4 complete"
}

# Phase 5: Restore routes
restore_routes() {
    log_info "Phase 5: Restoring routes..."

    echo "$ROUTES" | while read -r route_line; do
        if [ -n "$route_line" ]; then
            if [ "$DRY_RUN" = "true" ]; then
                log_info "  [DRY-RUN] Would add route: $route_line"
            else
                log_info "  Adding route: $route_line"

                # Execute route command
                if ip route add $route_line 2>/dev/null; then
                    log_success "    Route added: $route_line"
                else
                    log_warning "    Failed to add route (may already exist): $route_line"
                fi
            fi
        fi
    done

    log_success "Phase 5 complete"
}

# Phase 6: Restore DNS configuration
restore_dns() {
    log_info "Phase 6: Restoring DNS configuration..."

    if [ "$DRY_RUN" = "true" ]; then
        log_info "  [DRY-RUN] Would update /etc/resolv.conf"
        echo "$DNS_NAMESERVERS" | while read -r line; do
            if [ -n "$line" ]; then
                log_info "    Would add: $line"
            fi
        done
        echo "$DNS_SEARCH" | while read -r line; do
            if [ -n "$line" ]; then
                log_info "    Would add: $line"
            fi
        done
    else
        log_info "  Updating /etc/resolv.conf"

        # Backup current resolv.conf
        if [ -f /etc/resolv.conf ]; then
            cp /etc/resolv.conf /etc/resolv.conf.backup.$(date +%Y%m%d_%H%M%S)
        fi

        # Write new resolv.conf
        {
            echo "# Restored by network configuration backup"
            echo "# Restoration timestamp: $(date)"
            echo ""
            echo "$DNS_NAMESERVERS"
            echo "$DNS_SEARCH"
        } > /etc/resolv.conf

        log_success "  DNS configuration restored"
    fi

    log_success "Phase 6 complete"
}

# ============================================================================
# Main Restoration Logic
# ============================================================================

show_info() {
    echo "========================================"
    echo "Network Configuration Restoration"
    echo "========================================"
    echo ""
    echo "Backup Information:"
    echo "  Timestamp: $BACKUP_TIMESTAMP"
    echo "  Hostname: $BACKUP_HOSTNAME"
    echo "  Interfaces: $INTERFACE_COUNT ($VLAN_COUNT VLANs)"
    echo "  IP Addresses: $IP_COUNT"
    echo "  Routes: $ROUTE_COUNT"
    echo ""
}

show_preview() {
    echo "Restoration Preview:"
    echo ""
    echo "Phase 1: Shutdown interfaces"
    echo "  VLANs: $VLAN_COUNT"
    echo "  Parents: $(echo "$PARENT_INTERFACES" | grep -v "^$" | wc -l)"
    echo ""
    echo "Phase 2: Restore parent interfaces"
    echo "$PARENT_INTERFACES" | while IFS=: read -r iface state; do
        if [ -n "$iface" ]; then
            echo "  - $iface (state: $state)"
        fi
    done
    echo ""
    echo "Phase 3: Restore VLAN interfaces"
    echo "$VLAN_INTERFACES" | while IFS=: read -r vlan parent vlan_id state; do
        if [ -n "$vlan" ]; then
            echo "  - $vlan (parent: $parent, ID: $vlan_id, state: $state)"
        fi
    done
    echo ""
    echo "Phase 4: Restore IP addresses ($IP_COUNT total)"
    echo "$IP_ADDRESSES" | head -10 | while IFS=: read -r iface ip; do
        if [ -n "$iface" ] && [ -n "$ip" ]; then
            echo "  - $iface: $ip"
        fi
    done
    if [ "$IP_COUNT" -gt 10 ]; then
        echo "  ... and $((IP_COUNT - 10)) more"
    fi
    echo ""
    echo "Phase 5: Restore routes ($ROUTE_COUNT total)"
    echo "$ROUTES" | head -5 | while read -r route; do
        if [ -n "$route" ]; then
            echo "  - $route"
        fi
    done
    if [ "$ROUTE_COUNT" -gt 5 ]; then
        echo "  ... and $((ROUTE_COUNT - 5)) more"
    fi
    echo ""
    echo "Phase 6: Restore DNS configuration"
    echo "$DNS_NAMESERVERS" | while read -r ns; do
        if [ -n "$ns" ]; then
            echo "  - $ns"
        fi
    done
    echo ""
}

main() {
    show_info

    if [ "$1" = "--execute" ]; then
        echo "WARNING: This will modify your network configuration!"
        echo "Press Ctrl+C within 5 seconds to cancel..."
        sleep 5
        echo ""

        DRY_RUN=false

        shutdown_interfaces
        restore_parent_interfaces
        restore_vlan_interfaces
        restore_ip_addresses
        restore_routes
        restore_dns

        echo ""
        echo "========================================"
        echo "Network Restoration Complete!"
        echo "========================================"
        echo ""
        echo "Verification commands:"
        echo "  ip addr show     # Check IP addresses"
        echo "  ip link show     # Check interfaces"
        echo "  ip route show    # Check routes"
        echo "  cat /etc/resolv.conf  # Check DNS"
        echo ""

    else
        DRY_RUN=true
        show_preview
        echo ""
        echo "========================================"
        echo "This was a preview. No changes were made."
        echo "========================================"
        echo ""
        echo "To execute the restoration, run:"
        echo "  $0 --execute"
        echo ""
    fi
}

# Execute main function
main "$@"
RESTORE_FUNCTIONS_EOF

chmod +x "$TEMP_DIR/restore.sh"

echo "  Restoration script generated"

# ============================================================================
# Phase 8: Create Tarball
# ============================================================================

echo "Phase 8: Creating backup archive..."

# Create tarball
cd "$TEMP_DIR"
tar czf "$BACKUP_FILE" ./*

echo "  Archive created: $BACKUP_FILE"

# ============================================================================
# Summary
# ============================================================================

echo
echo "=== Backup Complete ==="
echo
echo "Backup file: $BACKUP_FILE"
echo "Size: $(du -h "$BACKUP_FILE" | cut -f1)"
echo
echo "Summary:"
echo "  Interfaces: $INTERFACE_COUNT ($VLAN_COUNT VLANs)"
echo "  IP Addresses: $IP_COUNT (link-local IPv6 excluded)"
echo "  Routes: $ROUTE_COUNT (kernel routes excluded)"
echo
echo "To restore this backup, use: restore_config.sh"
echo
