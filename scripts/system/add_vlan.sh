#!/bin/sh

# Source shared utility functions
. "$(dirname "$0")/../common/utils.sh"

echo "=== VLAN Interface Management ==="
echo

echo "Current VLAN interfaces:"
ip link show | grep "@" || echo "No VLAN interfaces found"

echo
parent_interface=$(select_interface "Select parent interface" "vlan")
if [ -z "$parent_interface" ]; then
    error_message "No interface selected"
    exit 1
fi

success_message "Selected parent interface: $parent_interface"

echo "VLAN options:"
echo "1. Add VLAN interface"
echo "2. Remove VLAN interface"
echo "3. List VLAN interfaces"
echo "4. Exit"

echo -n "Select option (1-4): "
read option

case $option in
    1)
        echo -n "Enter VLAN ID (1-4094): "
        read vlan_id
        case "$vlan_id" in
            *[!0-9]*|'')
                error_message "Invalid VLAN ID. Must be between 1-4094"
                exit 1
                ;;
            *)
                if [ "$vlan_id" -lt 1 ] || [ "$vlan_id" -gt 4094 ]; then
                    error_message "Invalid VLAN ID. Must be between 1-4094"
                    exit 1
                fi
                ;;
        esac
        
        vlan_interface="${parent_interface}.${vlan_id}"
        
        if ip link show "$vlan_interface" >/dev/null 2>&1; then
            error_message "VLAN interface $vlan_interface already exists"
            exit 1
        fi
        
        ip link add link "$parent_interface" name "$vlan_interface" type vlan id "$vlan_id"
        ip link set "$vlan_interface" up
        
        success_message "VLAN interface $vlan_interface created and brought up"
        
        if confirm_action "Configure IP address for $vlan_interface?"; then
            echo -n "Enter IP address with CIDR (e.g., 192.168.100.1/24): "
            read ip_addr
            case "$ip_addr" in
                [0-9]*.[0-9]*.[0-9]*.[0-9]*/[0-9]*)
                    # Basic IP/CIDR validation
                    ;;
                *)
                    error_message "Invalid IP address format"
                    exit 1
                    ;;
            esac
                ip addr add "$ip_addr" dev "$vlan_interface"
                success_message "IP address $ip_addr assigned to $vlan_interface"
        fi
        
        echo "VLAN interface details:"
        ip addr show "$vlan_interface"
        ;;
    2)
        # Get existing VLAN interfaces using temp file
        rm -f /tmp/netutil_vlan_interfaces.$$
        vlan_count=0
        
        ip link show | grep "@" | while read -r line; do
            # Extract interface name from line like "3: eth0.100@eth0:"
            interface_name=$(echo "$line" | sed 's/^[0-9]*: *\([^:]*\):.*/\1/')
            if [ -n "$interface_name" ]; then
                vlan_count=$((vlan_count + 1))
                echo "$vlan_count:$interface_name" >> /tmp/netutil_vlan_interfaces.$$
            fi
        done
        
        if [ ! -f /tmp/netutil_vlan_interfaces.$$ ] || [ ! -s /tmp/netutil_vlan_interfaces.$$ ]; then
            error_message "No VLAN interfaces found"
            exit 1
        fi
        
        echo "Available VLAN interfaces to remove:"
        while IFS=':' read -r num interface; do
            printf "%d. %s\n" "$num" "$interface"
        done < /tmp/netutil_vlan_interfaces.$$
        echo
        
        # Get max number for validation
        max_vlan_num=0
        while IFS=':' read -r num interface; do
            if [ "$num" -gt "$max_vlan_num" ]; then
                max_vlan_num=$num
            fi
        done < /tmp/netutil_vlan_interfaces.$$
        
        printf "Select VLAN interface to remove (1-%d): " "$max_vlan_num"
        read vlan_num
        
        case "$vlan_num" in
            *[!0-9]*|'')
                error_message "Invalid selection"
                rm -f /tmp/netutil_vlan_interfaces.$$
                exit 1
                ;;
            *)
                if [ "$vlan_num" -ge 1 ] && [ "$vlan_num" -le "$max_vlan_num" ]; then
                    # Find the selected interface
                    while IFS=':' read -r num interface; do
                        if [ "$num" = "$vlan_num" ]; then
                            vlan_interface="$interface"
                            break
                        fi
                    done < /tmp/netutil_vlan_interfaces.$$
                    
                    if [ -n "$vlan_interface" ]; then
                        ip link delete "$vlan_interface"
                        success_message "VLAN interface $vlan_interface removed"
                    else
                        error_message "Interface not found"
                    fi
                else
                    error_message "Invalid selection"
                    rm -f /tmp/netutil_vlan_interfaces.$$
                    exit 1
                fi
                ;;
        esac
        
        rm -f /tmp/netutil_vlan_interfaces.$$
        ;;
    3)
        echo "VLAN interfaces:"
        ip link show | grep "@" | while read -r line; do
            interface=$(echo "$line" | cut -d: -f2 | sed 's/^ *//')
            echo "  $interface"
            ip addr show "$interface" | grep "inet " | sed 's/^/    /'
        done
        ;;
    4)
        echo "Exiting..."
        exit 0
        ;;
    *)
        error_message "Invalid option"
        exit 1
        ;;
esac