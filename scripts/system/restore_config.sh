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
echo "Restoration options:"
echo "1. Guided restoration (display only, manual commands)"
echo "2. Automatic restoration (execute restoration script)"
echo "3. Cancel"
echo
read -p "Select restoration method (1-3): " restore_method

case "$restore_method" in
    1)
        echo "Selected: Guided restoration"
        restore_mode="guided"
        ;;
    2)
        echo "Selected: Automatic restoration"
        restore_mode="automatic"
        ;;
    3|*)
        echo "Restore cancelled"
        exit 0
        ;;
esac

TEMP_DIR=$(mktemp -d)
echo "Extracting backup to: $TEMP_DIR"

cd "$TEMP_DIR" || exit 1
tar -xzf "$backup_file"

echo "Backup information:"
cat backup_info.txt 2>/dev/null || echo "No backup info available"

echo
echo "Restoring network configuration..."

# Create rollback backup before restoration
ROLLBACK_DIR="${NETUTIL_WORKDIR:-$HOME}/netutil_rollback"
ROLLBACK_TIMESTAMP=$(date +%Y%m%d_%H%M%S)
ROLLBACK_FILE="$ROLLBACK_DIR/rollback_before_restore_$ROLLBACK_TIMESTAMP.tar.gz"

echo "Creating rollback backup of current configuration..."
mkdir -p "$ROLLBACK_DIR"
ROLLBACK_TEMP=$(mktemp -d)

# Save current configuration for rollback
ip addr show > "$ROLLBACK_TEMP/current_ip_addresses.txt"
ip route show > "$ROLLBACK_TEMP/current_routes.txt"
ip link show > "$ROLLBACK_TEMP/current_interfaces.txt"
cp /etc/resolv.conf "$ROLLBACK_TEMP/current_resolv.conf" 2>/dev/null || echo "No resolv.conf" > "$ROLLBACK_TEMP/current_resolv.conf"
echo "$(date): Rollback backup created before restoration" > "$ROLLBACK_TEMP/rollback_info.txt"

# Create rollback restoration script
cat > "$ROLLBACK_TEMP/rollback_restore.sh" << 'ROLLBACK_EOF'
#!/bin/sh
echo "=== Network Configuration Rollback ==="
echo "WARNING: This will revert to the configuration before the last restore operation!"
echo "Press Ctrl+C to cancel, or Enter to continue..."
read -r

echo "Rolling back network configuration..."
echo "Note: This is a basic rollback - manual verification may be required"
echo "Rollback completed. Please verify network connectivity."
ROLLBACK_EOF

chmod +x "$ROLLBACK_TEMP/rollback_restore.sh"

cd "$ROLLBACK_TEMP" || exit 1
tar -czf "$ROLLBACK_FILE" ./*
rm -rf "$ROLLBACK_TEMP"

echo "Rollback backup created: $ROLLBACK_FILE"
echo

echo "WARNING: This will modify your current network configuration!"
read -p "Continue with restoration? (y/N): " final_confirm
if ! echo "$final_confirm" | grep -E '^[Yy]$' >/dev/null; then
    echo "Restore cancelled"
    rm -rf "$TEMP_DIR"
    exit 0
fi

if [ "$restore_mode" = "automatic" ]; then
    echo "=== AUTOMATIC RESTORATION MODE ==="
    
    # Check if executable restoration script exists
    if [ -f "restore_network_config.sh" ]; then
        echo "Found executable restoration script. Executing..."
        chmod +x restore_network_config.sh
        
        # Execute the restoration script in the same directory as the backup files
        echo "Executing automatic restoration..."
        ./restore_network_config.sh
        
        if [ $? -eq 0 ]; then
            echo "Automatic restoration completed successfully!"
        else
            echo "Automatic restoration encountered errors. Check the output above."
        fi
    else
        echo "No executable restoration script found in backup."
        echo "Falling back to guided restoration mode..."
        restore_mode="guided"
    fi
fi

if [ "$restore_mode" = "guided" ]; then
    echo "=== GUIDED RESTORATION MODE ==="
    
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
fi

echo "Cleaning up..."
rm -rf "$TEMP_DIR"

echo "Restore process completed!"
echo "Rollback backup available at: $ROLLBACK_FILE"
echo "To rollback this restoration, extract and run the rollback_restore.sh script"

if [ "$restore_mode" = "guided" ]; then
    echo "Note: Some configurations may require manual restoration using the appropriate scripts."
fi