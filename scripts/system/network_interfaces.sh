#!/bin/bash

# Global array to store interface names
declare -a interfaces

# Function to get filtered interfaces (excluding loopback)
get_interfaces() {
    interfaces=()
    while read -r line; do
        # Parse interface name and state from ip link show output
        if [[ $line =~ ^[0-9]+:\ ([^:@]+).*state\ ([A-Z]+) ]]; then
            iface_name="${BASH_REMATCH[1]}"
            iface_state="${BASH_REMATCH[2]}"
            
            # Skip loopback interface
            if [[ "$iface_name" != "lo" ]]; then
                interfaces+=("$iface_name:$iface_state")
            fi
        fi
    done < <(ip link show)
}

# Function to display interfaces in numbered format
display_interfaces() {
    echo "Available network interfaces:"
    for i in "${!interfaces[@]}"; do
        IFS=':' read -r name state <<< "${interfaces[$i]}"
        printf "%d. %-12s (%s)\n" "$((i+1))" "$name" "$state"
    done
    echo
}

# Function to get interface name by number
get_interface_name() {
    local num=$1
    local index=$((num-1))
    
    if [[ $index -ge 0 && $index -lt ${#interfaces[@]} ]]; then
        IFS=':' read -r name state <<< "${interfaces[$index]}"
        echo "$name"
        return 0
    else
        return 1
    fi
}

echo "=== Network Interface Management ==="
echo

# Load and display interfaces
get_interfaces
display_interfaces

echo "Available actions:"
echo "1. Bring interface UP"
echo "2. Bring interface DOWN"
echo "3. Show interface statistics"
echo "4. Exit"

echo -n "Select action (1-4): "
read action

case $action in
    1)
        echo "Select interface to bring UP:"
        display_interfaces
        read -p "Enter interface number: " interface_num
        if interface=$(get_interface_name "$interface_num"); then
            ip link set "$interface" up
            echo "Interface $interface brought UP"
            echo "Current status:"
            ip addr show "$interface"
        else
            echo "Error: Invalid interface number"
            exit 1
        fi
        ;;
    2)
        echo "Select interface to bring DOWN:"
        display_interfaces
        read -p "Enter interface number: " interface_num
        if interface=$(get_interface_name "$interface_num"); then
            ip link set "$interface" down
            echo "Interface $interface brought DOWN"
            echo "Current status:"
            ip addr show "$interface"
        else
            echo "Error: Invalid interface number"
            exit 1
        fi
        ;;
    3)
        echo "Select interface for statistics:"
        display_interfaces
        read -p "Enter interface number: " interface_num
        if interface=$(get_interface_name "$interface_num"); then
            echo "Statistics for $interface:"
            ip -s link show "$interface"
            echo
            echo "Traffic statistics:"
            cat /proc/net/dev | grep "$interface"
        else
            echo "Error: Invalid interface number"
            exit 1
        fi
        ;;
    4)
        echo "Exiting..."
        exit 0
        ;;
    *)
        echo "Invalid option"
        exit 1
        ;;
esac