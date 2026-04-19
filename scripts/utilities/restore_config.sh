#!/bin/sh
#
# Network Configuration Restoration Script
# Restores network configuration from backup created by backup_config.sh
# Features: Interactive selection, preview, automatic rollback
#

set -e

# Source common utilities for select_file function
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMMON_DIR="${SCRIPT_DIR}/../common"
if [ -f "${COMMON_DIR}/utils.sh" ]; then
    . "${COMMON_DIR}/utils.sh"
else
    echo "ERROR: Cannot find common utilities" >&2
    exit 1
fi
. "${COMMON_DIR}/colors.sh" 2>/dev/null || true
. "${COMMON_DIR}/logging.sh"
SCRIPT_NAME="$(basename "$0")"

# Configuration
BACKUP_DIR="${NETUTIL_WORKDIR:-$HOME}/netutil_backups"
ROLLBACK_DIR="${BACKUP_DIR}/rollback"
TEMP_EXTRACT_DIR=$(mktemp -d)

# Cleanup on exit
trap 'rm -rf "$TEMP_EXTRACT_DIR"' EXIT

echo "=== Network Configuration Restoration ==="
log_info "=== Script started ===" "$SCRIPT_NAME"
echo
echo "Backup directory: $BACKUP_DIR"
echo

# ============================================================================
# Phase 1: Select Backup File
# ============================================================================

echo "Phase 1: Selecting backup file..."
echo

# Check if backup directory exists
if [ ! -d "$BACKUP_DIR" ]; then
    log_error "Backup directory does not exist: $BACKUP_DIR" "$SCRIPT_NAME"
    echo "ERROR: Backup directory does not exist: $BACKUP_DIR" >&2
    exit 1
fi

# Check if any backups exist
if ! ls "$BACKUP_DIR"/network_config_*.tar.gz >/dev/null 2>&1; then
    log_error "No backup files found in $BACKUP_DIR" "$SCRIPT_NAME"
    echo "ERROR: No backup files found in $BACKUP_DIR" >&2
    echo "Create a backup first using: backup_config.sh" >&2
    exit 1
fi

# List available backups with metadata
echo "Available backups:"
echo

backup_count=0
rm -f /tmp/netutil_backups.$$

for backup in "$BACKUP_DIR"/network_config_*.tar.gz; do
    backup_count=$((backup_count + 1))
    filename=$(basename "$backup")

    # Extract timestamp from filename (network_config_YYYYMMDD_HHMMSS.tar.gz)
    timestamp=$(echo "$filename" | sed 's/network_config_\(.*\)\.tar\.gz/\1/')

    # Try to extract metadata from backup
    metadata=""
    if tar -xzf "$backup" -O metadata.txt 2>/dev/null | grep -q "Interface Count"; then
        interface_count=$(tar -xzf "$backup" -O metadata.txt 2>/dev/null | grep "Interface Count:" | cut -d: -f2 | tr -d ' ')
        vlan_count=$(tar -xzf "$backup" -O metadata.txt 2>/dev/null | grep "VLAN Count:" | cut -d: -f2 | tr -d ' ')
        ip_count=$(tar -xzf "$backup" -O metadata.txt 2>/dev/null | grep "IP Address Count:" | cut -d: -f2 | tr -d ' ')

        metadata="$interface_count interfaces, $vlan_count VLANs, $ip_count IPs"
    else
        metadata="metadata unavailable"
    fi

    # Get file size
    size=$(du -h "$backup" | cut -f1)

    # Display with number
    printf "%d. %s (%s, %s)\n" "$backup_count" "$filename" "$metadata" "$size"

    # Store mapping
    echo "$backup_count:$backup" >> /tmp/netutil_backups.$$
done

echo

# Get selection from user
while true; do
    echo >&2
    if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
        printf "%sSelect backup to restore (1-%s) or 'q' to quit: %s\n" "$PROMPT_COLOR" "$backup_count" "$COLOR_RESET" >&2
    else
        printf "Select backup to restore (1-%s) or 'q' to quit: \n" "$backup_count" >&2
    fi
    read -r selection

    if [ "$selection" = "q" ] || [ "$selection" = "Q" ]; then
        echo "Restoration cancelled."
        rm -f /tmp/netutil_backups.$$
        exit 0
    fi

    # Validate selection
    case "$selection" in
        ''|*[!0-9]*)
            echo "ERROR: Invalid selection. Please enter a number between 1 and $backup_count" >&2
            ;;
        *)
            if [ "$selection" -ge 1 ] && [ "$selection" -le "$backup_count" ]; then
                # Get selected backup path
                backup_file=$(grep "^${selection}:" /tmp/netutil_backups.$$ | cut -d: -f2-)
                break
            else
                echo "ERROR: Invalid selection. Please enter a number between 1 and $backup_count" >&2
            fi
            ;;
    esac
done

rm -f /tmp/netutil_backups.$$

echo
echo "Selected backup: $(basename "$backup_file")"
log_info "Backup selected: $backup_file" "$SCRIPT_NAME"
echo

# ============================================================================
# Phase 2: Extract and Validate Backup
# ============================================================================

echo "Phase 2: Extracting and validating backup..."

# Extract backup to temporary directory
if ! tar -xzf "$backup_file" -C "$TEMP_EXTRACT_DIR" 2>/dev/null; then
    log_error "Failed to extract backup: $backup_file" "$SCRIPT_NAME"
    echo "ERROR: Failed to extract backup file" >&2
    exit 1
fi

# Validate required files exist
if [ ! -f "$TEMP_EXTRACT_DIR/restore.sh" ]; then
    log_error "Backup missing restore.sh: $backup_file" "$SCRIPT_NAME"
    echo "ERROR: Backup is missing restore.sh script" >&2
    exit 1
fi

if [ ! -f "$TEMP_EXTRACT_DIR/metadata.txt" ]; then
    echo "WARNING: Backup is missing metadata.txt" >&2
else
    echo "  Backup metadata:"
    cat "$TEMP_EXTRACT_DIR/metadata.txt" | while read -r line; do
        echo "    $line"
    done
    echo >&2
fi

# Make restore script executable
chmod +x "$TEMP_EXTRACT_DIR/restore.sh"

echo "  Backup validated successfully"
echo

# ============================================================================
# Phase 3: Preview Restoration
# ============================================================================

echo "Phase 3: Previewing restoration..."
echo

# Run restore script in preview mode
cd "$TEMP_EXTRACT_DIR"
./restore.sh

echo
echo "========================================"
echo

# ============================================================================
# Phase 4: Confirmation
# ============================================================================

echo "Phase 4: Confirmation required"
echo

echo "WARNING: This will modify your current network configuration!"
echo "All network interfaces will be reconfigured according to the backup."
echo

while true; do
    echo >&2
    if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
        printf "%sDo you want to proceed with restoration? (yes/no): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
    else
        printf "Do you want to proceed with restoration? (yes/no): \n" >&2
    fi
    read -r confirmation

    case "$confirmation" in
        yes|YES|y|Y)
            echo "Proceeding with restoration..."
            break
            ;;
        no|NO|n|N)
            echo "Restoration cancelled by user."
            exit 0
            ;;
        *)
            echo "Please answer 'yes' or 'no'" >&2
            ;;
    esac
done

echo

# ============================================================================
# Phase 5: Create Rollback Backup
# ============================================================================

echo "Phase 5: Creating rollback backup..."

# Create rollback directory
mkdir -p "$ROLLBACK_DIR"

# Generate rollback backup name
ROLLBACK_TIMESTAMP=$(date +%Y%m%d_%H%M%S)
ROLLBACK_NAME="rollback_before_restore_$ROLLBACK_TIMESTAMP"

echo "  Creating current configuration backup for rollback..."

# Create temporary directory for rollback backup
ROLLBACK_TEMP=$(mktemp -d)
trap 'rm -rf "$TEMP_EXTRACT_DIR" "$ROLLBACK_TEMP"' EXIT

# Use same backup logic as backup_config.sh (simplified version for rollback)
# Just capture essentials for quick rollback

# Capture current state
ip link show > "$ROLLBACK_TEMP/ip_link_before.txt"
ip addr show > "$ROLLBACK_TEMP/ip_addr_before.txt"
ip route show > "$ROLLBACK_TEMP/ip_route_before.txt"
cp /etc/resolv.conf "$ROLLBACK_TEMP/resolv.conf.before" 2>/dev/null || true

# Create rollback info
cat > "$ROLLBACK_TEMP/rollback_info.txt" << ROLLBACK_INFO_EOF
Rollback Backup Created: $ROLLBACK_TIMESTAMP
Before restoration of: $(basename "$backup_file")
Hostname: $(hostname)
Kernel: $(uname -r)
ROLLBACK_INFO_EOF

# Package rollback
cd "$ROLLBACK_TEMP"
tar czf "$ROLLBACK_DIR/$ROLLBACK_NAME.tar.gz" ./*

echo "  Rollback backup saved: $ROLLBACK_DIR/$ROLLBACK_NAME.tar.gz"
log_info "Rollback backup created: $ROLLBACK_DIR/$ROLLBACK_NAME.tar.gz" "$SCRIPT_NAME"
echo

# ============================================================================
# Phase 6: Execute Restoration
# ============================================================================

echo "Phase 6: Executing restoration..."
echo

echo "========================================"
echo "RESTORATION IN PROGRESS"
echo "========================================"
echo

# Execute restore script
cd "$TEMP_EXTRACT_DIR"
if ./restore.sh --execute; then
    restoration_success=true
else
    restoration_success=false
fi

echo
echo "========================================"

# ============================================================================
# Phase 7: Validation and Summary
# ============================================================================

echo "Phase 7: Validation and summary"
echo

if [ "$restoration_success" = "true" ]; then
    echo "✓ Network configuration restoration completed successfully!"
    log_info "Restoration successful from: $backup_file" "$SCRIPT_NAME"
    echo >&2

    echo "Current network state:"
    echo >&2

    # Show interface summary
    interface_count=$(ip link show | grep -c "^[0-9]*:" || true)
    vlan_count=$(ip link show | grep -c "@" || true)
    echo "  Interfaces: $interface_count ($vlan_count VLANs)"

    # Show IP summary
    ipv4_count=$(ip -4 addr show | grep -c "inet " || true)
    ipv6_count=$(ip -6 addr show | grep -c "inet6" || true)
    echo "  IP Addresses: $((ipv4_count + ipv6_count)) ($ipv4_count IPv4, $ipv6_count IPv6)"

    # Show route summary
    route_count=$(ip route show | wc -l)
    echo "  Routes: $route_count"

    echo >&2
    echo "Verification commands:"
    echo "  ip addr show         # List all IP addresses"
    echo "  ip link show         # List all interfaces"
    echo "  ip route show        # List all routes"
    echo "  cat /etc/resolv.conf # Check DNS configuration"
    echo >&2

    echo "Rollback information:"
    echo "  If you need to revert this restoration, your previous"
    echo "  configuration was saved to:"
    echo "  $ROLLBACK_DIR/$ROLLBACK_NAME.tar.gz"
    echo >&2
    echo "  To rollback, run restore_config.sh and select the rollback file."
    echo >&2

else
    echo "✗ Network configuration restoration encountered errors!"
    log_error "Restoration encountered errors from backup: $backup_file" "$SCRIPT_NAME"
    echo >&2
    echo "Some configuration steps may have failed. Review the output above."
    echo >&2
    echo "Rollback option:"
    echo "  Your previous configuration was saved before restoration:"
    echo "  $ROLLBACK_DIR/$ROLLBACK_NAME.tar.gz"
    echo >&2
    echo "  To restore your previous configuration, run:"
    echo "    cd $ROLLBACK_DIR"
    echo "    tar -xzf $ROLLBACK_NAME.tar.gz"
    echo "    # Then manually review the before_*.txt files"
    echo >&2
    echo "  Or run restore_config.sh and select the rollback file."
    echo >&2
fi

# ============================================================================
# Cleanup
# ============================================================================

# Cleanup happens automatically via trap

echo "=== Restoration Complete ==="
echo
