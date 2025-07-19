#!/bin/sh

# Source shared utility functions
. "$(dirname "$0")/../common/utils.sh"

echo "=== Network Packet Capture ==="
echo

interface=$(select_interface "Select interface for capture" "capture")
if [ -z "$interface" ]; then
    error_message "No interface selected"
    exit 1
fi

success_message "Selected interface: $interface"

# Normalize workspace path to avoid double slashes
WORKSPACE_DIR="${NETUTIL_WORKDIR:-$HOME}"
WORKSPACE_DIR="${WORKSPACE_DIR%/}"  # Remove trailing slash
CAPTURE_DIR="$WORKSPACE_DIR/captures"

# Ensure capture directory exists and is writable
if ! mkdir -p "$CAPTURE_DIR" 2>/dev/null; then
    warning_message "Failed to create capture directory: $CAPTURE_DIR"
    # Fallback to system temp directory
    CAPTURE_DIR="/tmp/netutil-captures"
    mkdir -p "$CAPTURE_DIR"
    warning_message "Using fallback directory: $CAPTURE_DIR"
fi

# Additional fallback for permission issues - use /tmp directly for root
if [ "$(id -u)" -eq 0 ]; then
    # Test if we can actually write to the current capture directory
    test_capture_file="$CAPTURE_DIR/test_$(date +%s).pcap"
    if ! touch "$test_capture_file" 2>/dev/null; then
        warning_message "Root cannot write to $CAPTURE_DIR, using /tmp/netutil-captures"
        CAPTURE_DIR="/tmp/netutil-captures"
        mkdir -p "$CAPTURE_DIR"
        chmod 755 "$CAPTURE_DIR"
    else
        rm -f "$test_capture_file"
    fi
fi

# Test write permissions
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
CAPTURE_FILE="$CAPTURE_DIR/capture_${interface}_${TIMESTAMP}.pcap"

# If running as root, temporarily change ownership of capture directory
if [ "$(id -u)" -eq 0 ]; then
    echo "Running as root - adjusting capture directory ownership..."
    chown root:root "$CAPTURE_DIR" 2>/dev/null || true
fi

# Test if we can write to the directory
TEST_FILE="$CAPTURE_DIR/.netutil_write_test"
if ! touch "$TEST_FILE" 2>/dev/null; then
    error_message "Cannot write to capture directory: $CAPTURE_DIR"
    echo "This may be due to permission issues when running as root."
    echo "Please ensure the workspace directory is accessible."
    exit 1
fi
rm -f "$TEST_FILE"

# Remove any existing capture file to let tshark create it fresh
rm -f "$CAPTURE_FILE"

echo "Capture will be saved to: $CAPTURE_FILE"

echo "Capture duration options:"
echo "1. 5 minutes"
echo "2. 10 minutes (default)"
echo "3. 30 minutes"
echo "4. 1 hour"
echo "5. Custom duration"
echo "6. Manual stop (Ctrl+C)"

read -p "Select option (1-6): " option

case $option in
    1)
        duration=300
        duration_text="5 minutes"
        ;;
    2)
        duration=600
        duration_text="10 minutes"
        ;;
    3)
        duration=1800
        duration_text="30 minutes"
        ;;
    4)
        duration=3600
        duration_text="1 hour"
        ;;
    5)
        read -p "Enter duration in seconds: " duration
        case "$duration" in
            *[!0-9]*|'')
                error_message "Invalid duration"
                exit 1
                ;;
        esac
        duration_text="$duration seconds"
        ;;
    6)
        duration=0
        duration_text="manual stop"
        ;;
    *)
        warning_message "Invalid option, using default 10 minutes"
        duration=600
        duration_text="10 minutes"
        ;;
esac

echo "Starting packet capture on interface $interface..."
echo "Duration: $duration_text"
echo "Capture file: $CAPTURE_FILE"
echo "Running as user: $(whoami)"
echo "File exists before capture: $(ls -la "$CAPTURE_FILE" 2>/dev/null || echo "File not found (this is expected)")"
echo "Directory permissions: $(ls -ld "$CAPTURE_DIR")"

# Try tshark capture - if it fails with permission denied, retry in /tmp
run_tshark_capture() {
    if [ "$duration" -eq 0 ]; then
        echo "Press Ctrl+C to stop capture"
        echo "Running: tshark -i \"$interface\" -w \"$1\" -q"
        tshark -i "$interface" -w "$1" -q
    else
        echo "Capturing for $duration_text..."
        echo "Running: timeout \"$duration\" tshark -i \"$interface\" -w \"$1\" -q"
        timeout "$duration" tshark -i "$interface" -w "$1" -q
    fi
}

# First attempt with original location
run_tshark_capture "$CAPTURE_FILE"
capture_exit_code=$?

# If tshark failed and we're running as root, try fallback location
if [ $capture_exit_code -ne 0 ] && [ "$(id -u)" -eq 0 ]; then
    echo "Capture failed in workspace directory, trying fallback location..."
    FALLBACK_DIR="/tmp/netutil-captures"
    mkdir -p "$FALLBACK_DIR"
    chmod 755 "$FALLBACK_DIR"
    FALLBACK_FILE="$FALLBACK_DIR/capture_${interface}_${TIMESTAMP}.pcap"
    
    echo "Fallback capture file: $FALLBACK_FILE"
    run_tshark_capture "$FALLBACK_FILE"
    capture_exit_code=$?
    
    # If successful (exit code 0 or 124 for timeout), copy to original location
    if ([ $capture_exit_code -eq 0 ] || [ $capture_exit_code -eq 124 ]) && [ -f "$FALLBACK_FILE" ]; then
        echo "Capture successful in fallback location, copying to workspace..."
        if cp "$FALLBACK_FILE" "$CAPTURE_FILE" 2>/dev/null; then
            success_message "Capture copied to workspace: $CAPTURE_FILE"
            # Update file permissions for original user if running as root
            if [ "$(id -u)" -eq 0 ] && [ -n "$SUDO_UID" ] && [ -n "$SUDO_GID" ]; then
                chown "$SUDO_UID:$SUDO_GID" "$CAPTURE_FILE" 2>/dev/null || true
            fi
        else
            warning_message "Failed to copy to workspace, using fallback location"
            CAPTURE_FILE="$FALLBACK_FILE"
        fi
        success_message "Capture completed in fallback location: $FALLBACK_FILE"
    fi
fi

echo "tshark exit code: $capture_exit_code"

# Restore original ownership if we changed it
if [ "$(id -u)" -eq 0 ] && [ -n "$SUDO_UID" ] && [ -n "$SUDO_GID" ]; then
    echo "Restoring original ownership of capture directory..."
    chown "$SUDO_UID:$SUDO_GID" "$CAPTURE_DIR" 2>/dev/null || true
    # Also fix ownership of any files we created
    chown "$SUDO_UID:$SUDO_GID" "$CAPTURE_FILE" 2>/dev/null || true
fi

echo
success_message "Capture completed!"
echo "Capture file: $CAPTURE_FILE"
echo "File size: $(du -h "$CAPTURE_FILE" | cut -f1)"

echo
echo "Capture statistics:"
capinfos "$CAPTURE_FILE" 2>/dev/null || echo "Could not get capture statistics"

echo
echo "Extracting VLAN information..."
VLAN_FILE="$CAPTURE_DIR/vlans_${interface}_${TIMESTAMP}.txt"

tshark -r "$CAPTURE_FILE" -Y "vlan" -T fields -e vlan.id 2>/dev/null | sort -u > "$VLAN_FILE"

if [ -s "$VLAN_FILE" ]; then
    echo "VLAN IDs detected:"
    cat "$VLAN_FILE"
    echo "VLAN IDs saved to: $VLAN_FILE"
    
    echo
    if confirm_action "Create VLAN subinterfaces for detected VLANs?"; then
        while read -r vlan_id; do
            case "$vlan_id" in
                *[!0-9]*|'') continue ;;
                *)
                    vlan_interface="${interface}.${vlan_id}"
                if ! ip link show "$vlan_interface" >/dev/null 2>&1; then
                    echo "Creating VLAN interface: $vlan_interface"
                    ip link add link "$interface" name "$vlan_interface" type vlan id "$vlan_id"
                    ip link set "$vlan_interface" up
                    success_message "VLAN interface $vlan_interface created"
                    else
                        warning_message "VLAN interface $vlan_interface already exists"
                    fi
                    ;;
            esac
        done < "$VLAN_FILE"
    fi
else
    echo "No VLAN traffic detected"
fi

echo
echo "Basic traffic analysis:"
echo "--- Top protocols ---"
tshark -r "$CAPTURE_FILE" -q -z io,phs 2>/dev/null | head -20

echo "--- Top conversations ---"
tshark -r "$CAPTURE_FILE" -q -z conv,ip 2>/dev/null | head -10

echo "Packet capture analysis complete!"
echo "Files created:"
echo "  Capture: $CAPTURE_FILE"
echo "  VLANs: $VLAN_FILE"