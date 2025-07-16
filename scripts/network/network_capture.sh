#!/bin/bash

echo "=== Network Packet Capture ==="
echo

echo "Available network interfaces:"
ip link show | grep -E "^[0-9]+:" | cut -d: -f2 | sed 's/^ *//'

echo
read -p "Enter interface name for capture: " interface

if ! ip link show "$interface" >/dev/null 2>&1; then
    echo "Error: Interface $interface not found"
    exit 1
fi

CAPTURE_DIR="${NETUTIL_WORKDIR:-$HOME}/captures"
mkdir -p "$CAPTURE_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
CAPTURE_FILE="$CAPTURE_DIR/capture_${interface}_${TIMESTAMP}.pcap"

echo "Capture will be saved to: $CAPTURE_FILE"

echo "Capture options:"
echo "1. Capture for 10 minutes (default)"
echo "2. Capture for custom duration"
echo "3. Capture until stopped manually"

read -p "Select option (1-3): " option

case $option in
    1)
        duration=600
        ;;
    2)
        read -p "Enter duration in seconds: " duration
        if [[ ! $duration =~ ^[0-9]+$ ]]; then
            echo "Error: Invalid duration"
            exit 1
        fi
        ;;
    3)
        duration=0
        ;;
    *)
        echo "Invalid option, using default 10 minutes"
        duration=600
        ;;
esac

echo "Starting packet capture on interface $interface..."
echo "Capture file: $CAPTURE_FILE"

if [ "$duration" -eq 0 ]; then
    echo "Press Ctrl+C to stop capture"
    tshark -i "$interface" -w "$CAPTURE_FILE" -q
else
    echo "Capturing for $duration seconds..."
    timeout "$duration" tshark -i "$interface" -w "$CAPTURE_FILE" -q
fi

echo
echo "Capture completed!"
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
    read -p "Create VLAN subinterfaces for detected VLANs? (y/N): " create_vlans
    if [[ $create_vlans =~ ^[Yy]$ ]]; then
        while read -r vlan_id; do
            if [[ $vlan_id =~ ^[0-9]+$ ]]; then
                vlan_interface="${interface}.${vlan_id}"
                if ! ip link show "$vlan_interface" >/dev/null 2>&1; then
                    echo "Creating VLAN interface: $vlan_interface"
                    ip link add link "$interface" name "$vlan_interface" type vlan id "$vlan_id"
                    ip link set "$vlan_interface" up
                    echo "VLAN interface $vlan_interface created"
                else
                    echo "VLAN interface $vlan_interface already exists"
                fi
            fi
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