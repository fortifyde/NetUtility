#!/bin/sh

# Source shared utility functions
source "$(dirname "$0")/../common/utils.sh"

echo "=== Network Packet Capture ==="
echo

interface=$(select_interface "Select interface for capture")
if [ -z "$interface" ]; then
    error_message "No interface selected"
    exit 1
fi

success_message "Selected interface: $interface"

CAPTURE_DIR="${NETUTIL_WORKDIR:-$HOME}/captures"
mkdir -p "$CAPTURE_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
CAPTURE_FILE="$CAPTURE_DIR/capture_${interface}_${TIMESTAMP}.pcap"

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
            error_message "Invalid duration"
            exit 1
        fi
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

if [ "$duration" -eq 0 ]; then
    echo "Press Ctrl+C to stop capture"
    tshark -i "$interface" -w "$CAPTURE_FILE" -q
else
    echo "Capturing for $duration_text..."
    timeout "$duration" tshark -i "$interface" -w "$CAPTURE_FILE" -q
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