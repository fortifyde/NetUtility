#!/bin/sh

echo "=== Network Configuration Restore ==="
echo

BACKUP_DIR="${NETUTIL_WORKDIR:-$HOME}/netutil_backups"

echo "Available backup files:"
if [ -d "$BACKUP_DIR" ]; then
    ls -la "$BACKUP_DIR"/*.tar.gz 2>/dev/null || {
        echo "No backup files found in $BACKUP_DIR"
        exit 1
    }
else
    echo "Backup directory $BACKUP_DIR not found"
    exit 1
fi

echo
read -p "Enter full path to backup file: " backup_file

if [ ! -f "$backup_file" ]; then
    echo "Error: Backup file not found"
    exit 1
fi

echo "Backup file: $backup_file"
echo "Backup contents:"
tar -tzf "$backup_file"

echo
read -p "Are you sure you want to restore this configuration? (y/N): " confirm
if ! echo "$confirm" | grep -E '^[Yy]$' >/dev/null; then
    echo "Restore cancelled"
    exit 0
fi

TEMP_DIR=$(mktemp -d)
echo "Extracting backup to: $TEMP_DIR"

cd "$TEMP_DIR" || exit 1
tar -xzf "$backup_file"

echo "Backup information:"
cat backup_info.txt 2>/dev/null || echo "No backup info available"

echo
echo "Restoring network configuration..."

echo "WARNING: This will modify your current network configuration!"
read -p "Continue? (y/N): " final_confirm
if ! echo "$final_confirm" | grep -E '^[Yy]$' >/dev/null; then
    echo "Restore cancelled"
    rm -rf "$TEMP_DIR"
    exit 0
fi

echo "1. Restoring working directory..."
if [ -f "workdir.txt" ]; then
    workdir=$(cat workdir.txt)
    if [ -d "$workdir" ]; then
        cd "$workdir" || echo "Could not change to $workdir"
        export NETUTIL_WORKDIR="$workdir"
        echo "Working directory restored to: $workdir"
    else
        echo "Original working directory $workdir no longer exists"
    fi
fi

echo "2. Restoring DNS configuration..."
if [ -f "resolv.conf" ]; then
    cp resolv.conf /etc/resolv.conf
    echo "DNS configuration restored"
else
    echo "No DNS configuration to restore"
fi

echo "3. Displaying interface information from backup..."
if [ -f "interfaces.txt" ]; then
    echo "Interfaces that were configured:"
    cat interfaces.txt
    echo
fi

echo "4. Displaying IP addresses from backup..."
if [ -f "ip_addresses.txt" ]; then
    echo "IP addresses that were configured:"
    cat ip_addresses.txt
    echo
fi

echo "5. Displaying routes from backup..."
if [ -f "routes.txt" ]; then
    echo "Routes that were configured:"
    cat routes.txt
    echo
fi

echo "6. Displaying VLAN information from backup..."
if [ -f "vlans.txt" ]; then
    echo "VLAN interfaces that were configured:"
    cat vlans.txt
    echo
fi

echo "Manual restoration required for:"
echo "- IP addresses (use configure_ip.sh)"
echo "- Routes (use configure_routes.sh)"  
echo "- VLAN interfaces (use add_vlan.sh)"
echo "- Interface states (use network_interfaces.sh)"

echo
echo "Current configuration:"
echo "--- IP addresses ---"
ip addr show
echo
echo "--- Routes ---"
ip route show
echo
echo "--- DNS ---"
cat /etc/resolv.conf

echo "Cleaning up..."
rm -rf "$TEMP_DIR"

echo "Restore process completed!"
echo "Note: Some configurations may require manual restoration using the appropriate scripts."