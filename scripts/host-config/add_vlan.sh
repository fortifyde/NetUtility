#!/bin/sh

# Source shared utility functions
. "$(dirname "$0")/../common/utils.sh"
. "$(dirname "$0")/../common/colors.sh" 2>/dev/null || true
. "$(dirname "$0")/../common/logging.sh"
. "$(dirname "$0")/../common/validation.sh"
SCRIPT_NAME="$(basename "$0")"

echo "=== VLAN Interface Management ==="
log_info "=== Script started ===" "$SCRIPT_NAME"
echo >&2

echo "Current VLAN interfaces:"
ip link show | grep "@" | sed 's/^[0-9]*: *\([^@]*\)@.*/  \1/' || echo "  No VLAN interfaces found"

echo >&2
parent_interface=$(select_interface "Select parent interface" "vlan" "true")
if [ -z "$parent_interface" ]; then
    error_message "No interface selected"
    log_error "No parent interface selected" "$SCRIPT_NAME"
    exit 1
fi

success_message "Selected parent interface: $parent_interface"
log_info "Parent interface selected: $parent_interface" "$SCRIPT_NAME"

echo "VLAN options:" >&2
echo "1. Add VLAN interface" >&2
echo "2. Add Multiple VLAN interfaces" >&2
echo "3. Remove VLAN interface" >&2
echo "4. List VLAN interfaces" >&2
echo "5. Exit" >&2

echo >&2
option=$(prompt_for_choice "Select option (1-5)" 1 5)
log_info "VLAN operation selected: option $option" "$SCRIPT_NAME"

case $option in
    1)
        echo >&2
        vlan_id=$(get_validated_input "Enter VLAN ID (1-4094)" validate_vlan_id "")
        vlan_interface="${parent_interface}.${vlan_id}"
        
        if ip link show "$vlan_interface" >/dev/null 2>&1; then
            error_message "VLAN interface $vlan_interface already exists"
            exit 1
        fi
        
        ip link add link "$parent_interface" name "$vlan_interface" type vlan id "$vlan_id"
        ip link set "$vlan_interface" up
        ip -6 addr flush dev "$vlan_interface" scope link 2>/dev/null || true

        success_message "VLAN interface $vlan_interface created and brought up"
        log_info "VLAN interface created: $vlan_interface (parent: $parent_interface, VLAN ID: $vlan_id)" "$SCRIPT_NAME"
        
        if confirm_action "Configure IP address for $vlan_interface?"; then
            ip_addr=$(get_validated_input "Enter IP address with CIDR (e.g., 192.168.100.1/24)" validate_ip_range "")
            ip addr add "$ip_addr" dev "$vlan_interface"
            success_message "IP address $ip_addr assigned to $vlan_interface"
            log_info "IP assigned: $ip_addr -> $vlan_interface" "$SCRIPT_NAME"
        fi
        
        echo "VLAN interface details:" >&2
        ip addr show "$vlan_interface"
        ;;
    2)
        echo "Multiple VLAN creation mode" >&2
        echo >&2
        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
            printf "%sEnter VLAN IDs (comma-separated, space-separated, or range like 100-105): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
        else
            printf "Enter VLAN IDs (comma-separated, space-separated, or range like 100-105): \n" >&2
        fi
        read -r vlan_input
        
        # Parse VLAN input into individual VLAN IDs
        vlan_list=""
        
        # Handle range input (e.g., 100-105)
        if echo "$vlan_input" | grep -q "-"; then
            range_start=$(echo "$vlan_input" | cut -d'-' -f1)
            range_end=$(echo "$vlan_input" | cut -d'-' -f2)
            
            # Validate range
            case "$range_start" in
                *[!0-9]*|'')
                    error_message "Invalid range start: $range_start"
                    exit 1
                    ;;
            esac
            case "$range_end" in
                *[!0-9]*|'')
                    error_message "Invalid range end: $range_end"
                    exit 1
                    ;;
            esac
            if [ "$range_start" -lt 1 ] || [ "$range_start" -gt 4094 ] || \
               [ "$range_end" -lt 1 ] || [ "$range_end" -gt 4094 ] || \
               [ "$range_start" -gt "$range_end" ]; then
                error_message "Invalid VLAN range. Must be between 1-4094 and start <= end"
                exit 1
            fi

            # Generate VLAN list from range
            i="$range_start"
            while [ "$i" -le "$range_end" ]; do
                vlan_list="$vlan_list $i"
                i=$((i + 1))
            done
        else
            # Handle comma or space separated input
            vlan_list=$(echo "$vlan_input" | tr ',' ' ')
        fi

        # Validate each VLAN ID and check for duplicates
        validated_vlans=""
        for vlan_id in $vlan_list; do
            case "$vlan_id" in
                *[!0-9]*|'')
                    error_message "Invalid VLAN ID: $vlan_id. Must be between 1-4094"
                    continue
                    ;;
                *)
                    if [ "$vlan_id" -lt 1 ] || [ "$vlan_id" -gt 4094 ]; then
                        error_message "Invalid VLAN ID: $vlan_id. Must be between 1-4094"
                        continue
                    fi
                    ;;
            esac
            
            # Check for duplicates
            if echo "$validated_vlans" | grep -q " $vlan_id "; then
                echo "Warning: Duplicate VLAN ID $vlan_id skipped" >&2
                continue
            fi
            
            validated_vlans="$validated_vlans $vlan_id "
        done
        
        if [ -z "$validated_vlans" ]; then
            error_message "No valid VLAN IDs provided"
            exit 1
        fi
        
        echo "VLANs to create: $validated_vlans" >&2
        echo >&2
        
        # Ask for IP configuration mode
        echo "IP configuration options:" >&2
        echo "1. Configure IP for each VLAN individually" >&2
        echo "2. Skip IP configuration" >&2
        
        echo >&2
        ip_mode=$(prompt_for_choice "Select IP configuration mode (1-2)" 1 2)
        
        successful_vlans=""
        failed_vlans=""
        
        # Process each VLAN
        for vlan_id in $validated_vlans; do
            echo "Processing VLAN $vlan_id..." >&2
            
            vlan_interface="${parent_interface}.${vlan_id}"
            
            if ip link show "$vlan_interface" >/dev/null 2>&1; then
                echo "Warning: VLAN interface $vlan_interface already exists, skipping" >&2
                failed_vlans="$failed_vlans $vlan_id(already_exists)"
                continue
            fi
            
            # Create VLAN interface
            if ip link add link "$parent_interface" name "$vlan_interface" type vlan id "$vlan_id" 2>/dev/null; then
                ip link set "$vlan_interface" up
                ip -6 addr flush dev "$vlan_interface" scope link 2>/dev/null || true
                echo "✓ VLAN interface $vlan_interface created and brought up" >&2
                log_info "VLAN created: $vlan_interface" "$SCRIPT_NAME"

                # Handle IP configuration based on mode
                case "$ip_mode" in
                    1)
                        echo >&2
                        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
                            printf "%sEnter IP address with CIDR for %s (or press Enter to skip): %s\n" "$PROMPT_COLOR" "$vlan_interface" "$COLOR_RESET" >&2
                        else
                            printf "Enter IP address with CIDR for %s (or press Enter to skip): \n" "$vlan_interface" >&2
                        fi
                        read -r ip_addr
                        
                        if [ -n "$ip_addr" ]; then
                            case "$ip_addr" in
                                [0-9]*.[0-9]*.[0-9]*.[0-9]*/[0-9]*)
                                    # Basic IP/CIDR validation
                                    if ip addr add "$ip_addr" dev "$vlan_interface" 2>/dev/null; then
                                        echo "✓ IP address $ip_addr assigned to $vlan_interface" >&2
                                    else
                                        echo "Warning: Failed to assign IP $ip_addr to $vlan_interface" >&2
                                    fi
                                    ;;
                                *)
                                    echo "Warning: Invalid IP address format for $vlan_interface, skipping IP" >&2
                                    ;;
                            esac
                        fi
                        ;;
                    2)
                        # Skip IP configuration
                        ;;
                    *)
                        echo "Warning: Invalid IP configuration mode, skipping IP for all VLANs" >&2
                        ;;
                esac
                
                successful_vlans="$successful_vlans $vlan_id"
            else
                echo "✗ Failed to create VLAN interface $vlan_interface" >&2
                log_error "Failed to create VLAN interface: $vlan_interface" "$SCRIPT_NAME"
                failed_vlans="$failed_vlans $vlan_id(create_failed)"
            fi
            echo >&2
        done
        
        # Summary
        echo "=== VLAN Creation Summary ===" >&2
        if [ -n "$successful_vlans" ]; then
            echo "Successfully created VLANs:$successful_vlans" >&2
            echo >&2
            echo "Details of created interfaces:" >&2
            for vlan_id in $successful_vlans; do
                vlan_interface="${parent_interface}.${vlan_id}"
                echo "  $vlan_interface:" >&2
                ip addr show "$vlan_interface" | grep -E "(inet|link)" | sed 's/^/    /' >&2
            done
        fi
        
        if [ -n "$failed_vlans" ]; then
            echo "Failed VLANs:$failed_vlans" >&2
        fi
        ;;
    3)
        # Get existing VLAN interfaces using temp file
        rm -f /tmp/netutil_vlan_interfaces.$$
        vlan_count=0
        
        ip link show | grep "@" | while read -r line; do
            # Extract interface name from line like "3: eth0.100@eth0:"
            interface_name=$(echo "$line" | sed 's/^[0-9]*: *\([^@]*\)@.*/\1/')
            if [ -n "$interface_name" ]; then
                vlan_count=$((vlan_count + 1))
                echo "$vlan_count:$interface_name" >> /tmp/netutil_vlan_interfaces.$$
            fi
        done
        
        if [ ! -f /tmp/netutil_vlan_interfaces.$$ ] || [ ! -s /tmp/netutil_vlan_interfaces.$$ ]; then
            error_message "No VLAN interfaces found"
            exit 1
        fi
        
        echo "Available VLAN interfaces to remove:" >&2
        while IFS=':' read -r num interface; do
            echo "$num. $interface" >&2
        done < /tmp/netutil_vlan_interfaces.$$
        echo >&2
        
        # Get max number for validation
        max_vlan_num=0
        while IFS=':' read -r num interface; do
            if [ "$num" -gt "$max_vlan_num" ]; then
                max_vlan_num=$num
            fi
        done < /tmp/netutil_vlan_interfaces.$$
        
        echo "Removal options:" >&2
        echo "1. Remove single VLAN (select from list)" >&2
        echo "2. Remove multiple VLANs (comma/space separated or range)" >&2
        echo "3. Remove ALL VLAN interfaces" >&2
        echo "4. Return to main menu" >&2
        
        echo >&2
        removal_option=$(prompt_for_choice "Select removal option (1-4)" 1 4)
        
        case $removal_option in
            1)
                # Original single VLAN removal (backward compatible)
                echo >&2
                vlan_num=$(prompt_for_choice "Select VLAN interface to remove (1-$max_vlan_num)" 1 "$max_vlan_num")

                # Find the selected interface
                vlan_interface=""
                while IFS=':' read -r num interface; do
                    if [ "$num" = "$vlan_num" ]; then
                        vlan_interface="$interface"
                        break
                    fi
                done < /tmp/netutil_vlan_interfaces.$$

                if [ -n "$vlan_interface" ]; then
                    ip link delete "$vlan_interface" 2>/dev/null
                    success_message "VLAN interface $vlan_interface removed"
                    log_info "VLAN interface removed: $vlan_interface" "$SCRIPT_NAME"
                else
                    error_message "Interface not found"
                fi
                ;;
            2)
                # Multiple VLAN removal
                echo >&2
                if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
                    printf "%sEnter VLAN IDs to remove (comma-separated, space-separated, or range like 100-105): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
                else
                    printf "Enter VLAN IDs to remove (comma-separated, space-separated, or range like 100-105): \n" >&2
                fi
                read -r vlan_input
                
                # Parse VLAN input into individual VLAN IDs
                vlan_list=""
                
                # Handle range input (e.g., 100-105)
                if echo "$vlan_input" | grep -q "-"; then
                    range_start=$(echo "$vlan_input" | cut -d'-' -f1)
                    range_end=$(echo "$vlan_input" | cut -d'-' -f2)
                    
                    # Validate range
                    case "$range_start" in
                        *[!0-9]*|'')
                            error_message "Invalid range start: $range_start"
                            exit 1
                            ;;
                    esac
                    case "$range_end" in
                        *[!0-9]*|'')
                            error_message "Invalid range end: $range_end"
                            exit 1
                            ;;
                    esac
                    if [ "$range_start" -lt 1 ] || [ "$range_start" -gt 4094 ] || \
                       [ "$range_end" -lt 1 ] || [ "$range_end" -gt 4094 ] || \
                       [ "$range_start" -gt "$range_end" ]; then
                        error_message "Invalid VLAN range. Must be between 1-4094 and start <= end"
                        exit 1
                    fi

                    # Generate VLAN list from range
                    i="$range_start"
                    while [ "$i" -le "$range_end" ]; do
                        vlan_list="$vlan_list $i"
                        i=$((i + 1))
                    done
                else
                    # Handle comma or space separated input
                    vlan_list=$(echo "$vlan_input" | tr ',' ' ')
                fi
                
                # Validate each VLAN ID and check for duplicates
                validated_vlans=""
                for vlan_id in $vlan_list; do
                    case "$vlan_id" in
                        *[!0-9]*|'')
                            echo "Warning: Invalid VLAN ID: $vlan_id. Must be between 1-4094" >&2
                            continue
                            ;;
                        *)
                            if [ "$vlan_id" -lt 1 ] || [ "$vlan_id" -gt 4094 ]; then
                                echo "Warning: Invalid VLAN ID: $vlan_id. Must be between 1-4094" >&2
                                continue
                            fi
                            ;;
                    esac
                    
                    # Check for duplicates
                    if echo "$validated_vlans" | grep -q " $vlan_id "; then
                        echo "Warning: Duplicate VLAN ID $vlan_id skipped" >&2
                        continue
                    fi
                    
                    validated_vlans="$validated_vlans $vlan_id "
                done
                
                if [ -z "$validated_vlans" ]; then
                    error_message "No valid VLAN IDs provided"
                    rm -f /tmp/netutil_vlan_interfaces.$$
                    exit 1
                fi
                
                echo "VLANs to remove: $validated_vlans" >&2
                echo >&2
                
                successful_removals=""
                failed_removals=""
                
                # Process each VLAN for removal
                for vlan_id in $validated_vlans; do
                    vlan_interface="${parent_interface}.${vlan_id}"
                    
                    if ip link show "$vlan_interface" >/dev/null 2>&1; then
                        if ip link delete "$vlan_interface" 2>/dev/null; then
                            echo "✓ VLAN interface $vlan_interface removed" >&2
                            successful_removals="$successful_removals $vlan_id"
                        else
                            echo "✗ Failed to remove VLAN interface $vlan_interface" >&2
                            failed_removals="$failed_removals $vlan_id(remove_failed)"
                        fi
                    else
                        echo "Warning: VLAN interface $vlan_interface does not exist, skipping" >&2
                        failed_removals="$failed_removals $vlan_id(not_found)"
                    fi
                done
                
                # Summary
                echo "=== VLAN Removal Summary ===" >&2
                if [ -n "$successful_removals" ]; then
                    echo "Successfully removed VLANs:$successful_removals" >&2
                fi
                
                if [ -n "$failed_removals" ]; then
                    echo "Failed VLANs:$failed_removals" >&2
                fi
                ;;
            3)
                # Remove ALL VLAN interfaces
                echo "⚠️  WARNING: This will remove ALL VLAN interfaces on $parent_interface!" >&2
                echo >&2
                
                # List all VLANs that will be removed
                echo "The following VLAN interfaces will be removed:" >&2
                while IFS=':' read -r num interface; do
                    echo "  - $interface" >&2
                done < /tmp/netutil_vlan_interfaces.$$
                echo >&2
                
                echo "This action cannot be undone!" >&2
                echo >&2
                if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
                    printf "%sTo confirm, type 'REMOVE ALL' (exactly as shown): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
                else
                    printf "To confirm, type 'REMOVE ALL' (exactly as shown): \n" >&2
                fi
                read -r confirmation
                
                if [ "$confirmation" = "REMOVE ALL" ]; then
                    echo "Removing all VLAN interfaces..." >&2
                    echo >&2
                    
                    successful_removals=""
                    failed_removals=""
                    
                    while IFS=':' read -r num interface; do
                        if [ -n "$interface" ]; then
                            if ip link delete "$interface" 2>/dev/null; then
                                echo "✓ VLAN interface $interface removed" >&2
                                successful_removals="$successful_removals $interface"
                            else
                                echo "✗ Failed to remove VLAN interface $interface" >&2
                                failed_removals="$failed_removals $interface"
                            fi
                        fi
                    done < /tmp/netutil_vlan_interfaces.$$
                    
                    echo >&2
                    echo "=== All VLAN Removal Summary ===" >&2
                    if [ -n "$successful_removals" ]; then
                        echo "Successfully removed: $successful_removals" >&2
                    fi
                    
                    if [ -n "$failed_removals" ]; then
                        echo "Failed to remove: $failed_removals" >&2
                    fi
                else
                    echo "Operation cancelled - confirmation not received" >&2
                fi
                ;;
            4)
                # Return to main menu
                echo "Returning to main menu..." >&2
                rm -f /tmp/netutil_vlan_interfaces.$$
                # Continue to main menu loop
                ;;
            *)
                error_message "Invalid removal option"
                ;;
        esac
        
        rm -f /tmp/netutil_vlan_interfaces.$$
        ;;
    4)
        echo "VLAN interfaces:"
        ip link show | grep "@" | while read -r line; do
            interface=$(echo "$line" | sed 's/^[0-9]*: *\([^@]*\)@.*/\1/')
            echo "  $interface"
            ip addr show "$interface" | grep "inet " | sed 's/^/    /'
        done
        ;;
    5)
        echo "Exiting..."
        exit 0
        ;;
    *)
        error_message "Invalid option"
        ;;
esac
