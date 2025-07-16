#!/bin/bash

echo "=== Network Configuration Backup ==="
echo

BACKUP_DIR="${NETUTIL_WORKDIR:-$HOME}/netutil_backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/network_config_$TIMESTAMP.tar.gz"

echo "Creating backup directory: $BACKUP_DIR"
mkdir -p "$BACKUP_DIR"

TEMP_DIR=$(mktemp -d)
echo "Using temporary directory: $TEMP_DIR"

echo "Backing up network configuration..."

echo "1. Saving IP addresses..."
ip addr show > "$TEMP_DIR/ip_addresses.txt"

echo "2. Saving routing table..."
ip route show > "$TEMP_DIR/routes.txt"
ip route show table all > "$TEMP_DIR/routes_all.txt"

echo "3. Saving interface information..."
ip link show > "$TEMP_DIR/interfaces.txt"

echo "4. Saving VLAN interfaces..."
ip link show | grep "@" > "$TEMP_DIR/vlans.txt" || echo "No VLAN interfaces" > "$TEMP_DIR/vlans.txt"

echo "5. Saving DNS configuration..."
cp /etc/resolv.conf "$TEMP_DIR/resolv.conf" 2>/dev/null || echo "Could not backup resolv.conf"

echo "6. Saving network statistics..."
cat /proc/net/dev > "$TEMP_DIR/net_dev.txt"

echo "7. Saving ARP table..."
ip neigh show > "$TEMP_DIR/arp_table.txt"

echo "8. Saving network namespace info..."
ip netns list > "$TEMP_DIR/netns.txt" 2>/dev/null || echo "No network namespaces" > "$TEMP_DIR/netns.txt"

echo "9. Saving bridge information..."
bridge link show > "$TEMP_DIR/bridges.txt" 2>/dev/null || echo "No bridges" > "$TEMP_DIR/bridges.txt"

echo "10. Saving current working directory..."
echo "$(pwd)" > "$TEMP_DIR/workdir.txt"

echo "11. Creating metadata file..."
cat > "$TEMP_DIR/backup_info.txt" << EOF
Backup created: $(date)
Hostname: $(hostname)
Kernel: $(uname -r)
Distribution: $(cat /etc/os-release 2>/dev/null | head -1 || echo "Unknown")
Working directory: $(pwd)
Backup tool: NetUtility
EOF

echo "Creating compressed backup..."
cd "$TEMP_DIR" || exit 1
tar -czf "$BACKUP_FILE" ./*

echo "Cleaning up temporary files..."
rm -rf "$TEMP_DIR"

echo "Backup completed successfully!"
echo "Backup file: $BACKUP_FILE"
echo "Backup size: $(du -h "$BACKUP_FILE" | cut -f1)"

echo
echo "Backup contents:"
tar -tzf "$BACKUP_FILE" | head -20
echo

echo "To restore this backup, use the restore_config.sh script"
echo "Backup file path: $BACKUP_FILE"