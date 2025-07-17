#!/bin/sh

# Source shared utility functions
source "$(dirname "$0")/../common/utils.sh"

echo "=== VLAN Extraction from Capture Files ==="
echo

capture_file=$(select_capture_file)
if [ -z "$capture_file" ]; then
    error_message "No capture file selected"
    exit 1
fi

success_message "Selected capture file: $capture_file"
echo "Analyzing capture file: $capture_file"

CAPTURE_DIR="${NETUTIL_WORKDIR:-$HOME}/captures"
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
        case "$vlan_id" in
            *[!0-9]*|'') continue ;;
            *)
                echo "VLAN $vlan_id:" >> "$VLAN_DETAIL_FILE"
            packet_count=$(tshark -r "$capture_file" -Y "vlan.id == $vlan_id" 2>/dev/null | wc -l)
            echo "  Packets: $packet_count" >> "$VLAN_DETAIL_FILE"
            
            echo "  Source IPs:" >> "$VLAN_DETAIL_FILE"
            tshark -r "$capture_file" -Y "vlan.id == $vlan_id" -T fields -e ip.src 2>/dev/null | sort -u | head -10 | sed 's/^/    /' >> "$VLAN_DETAIL_FILE"
            
            echo "  Destination IPs:" >> "$VLAN_DETAIL_FILE"
            tshark -r "$capture_file" -Y "vlan.id == $vlan_id" -T fields -e ip.dst 2>/dev/null | sort -u | head -10 | sed 's/^/    /' >> "$VLAN_DETAIL_FILE"
            
                echo >> "$VLAN_DETAIL_FILE"
                ;;
        esac
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
    if confirm_action "Create VLAN subinterfaces?"; then
        parent_interface=$(select_interface "Select parent interface for VLAN creation")
        if [ -z "$parent_interface" ]; then
            error_message "No interface selected"
            exit 1
        fi
        
        success_message "Selected parent interface: $parent_interface"
        
        while read -r vlan_id; do
            case "$vlan_id" in
                *[!0-9]*|'') continue ;;
                *)
                    vlan_interface="${parent_interface}.${vlan_id}"
                if ! ip link show "$vlan_interface" >/dev/null 2>&1; then
                    echo "Creating VLAN interface: $vlan_interface"
                    ip link add link "$parent_interface" name "$vlan_interface" type vlan id "$vlan_id"
                    ip link set "$vlan_interface" up
                    success_message "VLAN interface $vlan_interface created and brought up"
                    else
                        warning_message "VLAN interface $vlan_interface already exists"
                    fi
                    ;;
            esac
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