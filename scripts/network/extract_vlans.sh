#!/bin/bash

echo "=== VLAN Extraction from Capture Files ==="
echo

CAPTURE_DIR="${NETUTIL_WORKDIR:-$HOME}/captures"

if [ ! -d "$CAPTURE_DIR" ]; then
    echo "Capture directory $CAPTURE_DIR not found"
    exit 1
fi

echo "Available capture files:"
ls -la "$CAPTURE_DIR"/*.pcap 2>/dev/null || {
    echo "No capture files found in $CAPTURE_DIR"
    exit 1
}

echo
read -p "Enter path to capture file: " capture_file

if [ ! -f "$capture_file" ]; then
    echo "Error: Capture file not found"
    exit 1
fi

echo "Analyzing capture file: $capture_file"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
VLAN_FILE="$CAPTURE_DIR/extracted_vlans_${TIMESTAMP}.txt"
VLAN_DETAIL_FILE="$CAPTURE_DIR/vlan_details_${TIMESTAMP}.txt"

echo "Extracting VLAN information..."

echo "=== VLAN Analysis Report ===" > "$VLAN_DETAIL_FILE"
echo "Capture file: $capture_file" >> "$VLAN_DETAIL_FILE"
echo "Analysis time: $(date)" >> "$VLAN_DETAIL_FILE"
echo >> "$VLAN_DETAIL_FILE"

echo "--- VLAN IDs found ---" >> "$VLAN_DETAIL_FILE"
tshark -r "$capture_file" -Y "vlan" -T fields -e vlan.id 2>/dev/null | sort -u | tee -a "$VLAN_DETAIL_FILE" > "$VLAN_FILE"

if [ -s "$VLAN_FILE" ]; then
    echo "VLAN IDs extracted:"
    cat "$VLAN_FILE"
    
    echo >> "$VLAN_DETAIL_FILE"
    echo "--- VLAN Statistics ---" >> "$VLAN_DETAIL_FILE"
    
    while read -r vlan_id; do
        if [[ $vlan_id =~ ^[0-9]+$ ]]; then
            echo "VLAN $vlan_id:" >> "$VLAN_DETAIL_FILE"
            packet_count=$(tshark -r "$capture_file" -Y "vlan.id == $vlan_id" 2>/dev/null | wc -l)
            echo "  Packets: $packet_count" >> "$VLAN_DETAIL_FILE"
            
            echo "  Source IPs:" >> "$VLAN_DETAIL_FILE"
            tshark -r "$capture_file" -Y "vlan.id == $vlan_id" -T fields -e ip.src 2>/dev/null | sort -u | head -10 | sed 's/^/    /' >> "$VLAN_DETAIL_FILE"
            
            echo "  Destination IPs:" >> "$VLAN_DETAIL_FILE"
            tshark -r "$capture_file" -Y "vlan.id == $vlan_id" -T fields -e ip.dst 2>/dev/null | sort -u | head -10 | sed 's/^/    /' >> "$VLAN_DETAIL_FILE"
            
            echo >> "$VLAN_DETAIL_FILE"
        fi
    done < "$VLAN_FILE"
    
    echo >> "$VLAN_DETAIL_FILE"
    echo "--- Protocol Distribution in VLAN Traffic ---" >> "$VLAN_DETAIL_FILE"
    tshark -r "$capture_file" -Y "vlan" -q -z io,phs 2>/dev/null >> "$VLAN_DETAIL_FILE"
    
    echo
    echo "VLAN analysis complete!"
    echo "Files created:"
    echo "  VLAN IDs: $VLAN_FILE"
    echo "  Detailed report: $VLAN_DETAIL_FILE"
    
    echo
    echo "Available interfaces for VLAN configuration:"
    ip link show | grep -E "^[0-9]+:" | cut -d: -f2 | sed 's/^ *//'
    
    echo
    read -p "Create VLAN subinterfaces? (y/N): " create_vlans
    if [[ $create_vlans =~ ^[Yy]$ ]]; then
        read -p "Enter parent interface name: " parent_interface
        
        if ! ip link show "$parent_interface" >/dev/null 2>&1; then
            echo "Error: Parent interface $parent_interface not found"
            exit 1
        fi
        
        while read -r vlan_id; do
            if [[ $vlan_id =~ ^[0-9]+$ ]]; then
                vlan_interface="${parent_interface}.${vlan_id}"
                if ! ip link show "$vlan_interface" >/dev/null 2>&1; then
                    echo "Creating VLAN interface: $vlan_interface"
                    ip link add link "$parent_interface" name "$vlan_interface" type vlan id "$vlan_id"
                    ip link set "$vlan_interface" up
                    echo "VLAN interface $vlan_interface created and brought up"
                else
                    echo "VLAN interface $vlan_interface already exists"
                fi
            fi
        done < "$VLAN_FILE"
        
        echo
        echo "Current VLAN interfaces:"
        ip link show | grep "@"
    fi
    
else
    echo "No VLAN traffic found in capture file"
    echo "This could mean:"
    echo "1. No VLAN tags were present in the captured traffic"
    echo "2. The capture was done on a port that strips VLAN tags"
    echo "3. The network doesn't use VLANs"
fi

echo
echo "Analysis complete!"
echo "Report saved to: $VLAN_DETAIL_FILE"