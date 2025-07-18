#!/bin/sh

# Source shared utility functions
. "$(dirname "$0")/../common/utils.sh"
. "$(dirname "$0")/../common/logging.sh"

echo "=== VLAN Extraction from Capture Files ==="
echo

# Log script start
log_script_start "extract_vlans.sh" "$@"

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
            log_error "No interface selected for VLAN creation"
            exit 1
        fi
        
        success_message "Selected parent interface: $parent_interface"
        log_info "Selected parent interface for VLAN creation: $parent_interface"
        
        # Ask about IP address assignment
        echo
        assign_ips=false
        if confirm_action "Automatically assign IP addresses to VLAN interfaces?"; then
            assign_ips=true
            log_info "Automatic IP assignment enabled for VLAN interfaces"
        fi
        
        echo
        echo "Creating VLAN interfaces..."
        vlan_count=0
        
        while read -r vlan_id; do
            case "$vlan_id" in
                *[!0-9]*|'') continue ;;
                *)
                    vlan_interface="${parent_interface}.${vlan_id}"
                    if ! ip link show "$vlan_interface" >/dev/null 2>&1; then
                        echo "Creating VLAN interface: $vlan_interface"
                        
                        # Create VLAN interface
                        if ip link add link "$parent_interface" name "$vlan_interface" type vlan id "$vlan_id" 2>/dev/null; then
                            ip link set "$vlan_interface" up
                            success_message "VLAN interface $vlan_interface created and brought up"
                            log_config_change "VLAN interface created" "$vlan_interface (VLAN ID: $vlan_id)"
                            vlan_count=$((vlan_count + 1))
                            
                            # Automatic IP assignment
                            if [ "$assign_ips" = true ]; then
                                echo "  Analyzing IP ranges for VLAN $vlan_id..."
                                
                                # Extract IP addresses from this VLAN's traffic
                                vlan_ips=$(tshark -r "$capture_file" -Y "vlan.id == $vlan_id" -T fields -e ip.src -e ip.dst 2>/dev/null | \
                                          tr '\t' '\n' | grep -v "^$" | sort -u | head -10)
                                
                                if [ -n "$vlan_ips" ]; then
                                    echo "  Detected IP addresses in VLAN $vlan_id:"
                                    echo "$vlan_ips" | sed 's/^/    /'
                                    
                                    # Try to determine network range
                                    first_ip=$(echo "$vlan_ips" | head -1)
                                    if [ -n "$first_ip" ]; then
                                        # Extract network portion (assuming /24)
                                        network_base=$(echo "$first_ip" | cut -d'.' -f1-3)
                                        suggested_ip="${network_base}.254/24"
                                        
                                        echo "  Suggested IP for $vlan_interface: $suggested_ip"
                                        if confirm_action "    Assign IP $suggested_ip to $vlan_interface?"; then
                                            if ip addr add "$suggested_ip" dev "$vlan_interface" 2>/dev/null; then
                                                success_message "  IP address $suggested_ip assigned to $vlan_interface"
                                                log_config_change "IP assigned to VLAN interface" "$vlan_interface: $suggested_ip"
                                            else
                                                warning_message "  Failed to assign IP $suggested_ip to $vlan_interface"
                                                log_error "Failed to assign IP $suggested_ip to $vlan_interface"
                                            fi
                                        fi
                                    fi
                                else
                                    echo "  No IP addresses found in VLAN $vlan_id traffic"
                                fi
                            fi
                        else
                            error_message "Failed to create VLAN interface $vlan_interface"
                            log_error "Failed to create VLAN interface $vlan_interface"
                        fi
                    else
                        warning_message "VLAN interface $vlan_interface already exists"
                        log_info "VLAN interface $vlan_interface already exists"
                    fi
                    echo
                    ;;
            esac
        done < "$VLAN_FILE"
        
        echo
        echo "VLAN interface creation summary:"
        echo "  VLANs created: $vlan_count"
        log_info "VLAN interface creation completed: $vlan_count interfaces created"
        
        echo
        echo "Current VLAN interfaces:"
        ip link show | grep "@" | while read -r line; do
            interface=$(echo "$line" | cut -d':' -f2 | tr -d ' ')
            echo "  $interface"
            
            # Show IP addresses if assigned
            ip_addrs=$(ip addr show "$interface" 2>/dev/null | grep "inet " | awk '{print $2}')
            if [ -n "$ip_addrs" ]; then
                echo "$ip_addrs" | sed 's/^/    IP: /'
            fi
        done
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
log_info "VLAN extraction and analysis completed successfully"

# Log script completion
log_script_end "extract_vlans.sh" 0