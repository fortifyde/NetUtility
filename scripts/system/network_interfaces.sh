#!/bin/sh

# Global variables to store interface data
interfaces_data=""
interfaces_count=0

# Function to get filtered interfaces (excluding loopback)
get_interfaces() {
    interfaces_data=""
    interfaces_count=0
    ip link show | while read -r line; do
        # Parse interface name and state from ip link show output
        if echo "$line" | grep -E '^[0-9]+: [^:@]+.*state [A-Z]+' >/dev/null; then
            iface_name=$(echo "$line" | sed -n 's/^[0-9]*: \([^:@]*\).*/\1/p')
            iface_state=$(echo "$line" | sed -n 's/.*state \([A-Z]*\).*/\1/p')
            
            # Skip loopback interface
            if [ "$iface_name" != "lo" ]; then
                if [ -z "$interfaces_data" ]; then
                    interfaces_data="$iface_name:$iface_state"
                else
                    interfaces_data="$interfaces_data
$iface_name:$iface_state"
                fi
                interfaces_count=$((interfaces_count + 1))
            fi
        fi
    done
    # Use temp file to preserve data from subshell
    echo "$interfaces_data" > /tmp/netutil_interfaces.tmp
    echo "$interfaces_count" > /tmp/netutil_interfaces_count.tmp
}

# Function to display interfaces in numbered format
display_interfaces() {
    echo "Available network interfaces:"
    if [ -f /tmp/netutil_interfaces.tmp ]; then
        i=1
        while read -r line; do
            name=$(echo "$line" | cut -d: -f1)
            state=$(echo "$line" | cut -d: -f2)
            printf "%d. %-12s (%s)\n" "$i" "$name" "$state"
            i=$((i + 1))
        done < /tmp/netutil_interfaces.tmp
    fi
    echo
}

# Function to get interface name by number
get_interface_name() {
    num=$1
    index=$((num-1))
    count=$(cat /tmp/netutil_interfaces_count.tmp 2>/dev/null || echo "0")
    
    if [ "$index" -ge 0 ] && [ "$index" -lt "$count" ] && [ -f /tmp/netutil_interfaces.tmp ]; then
        name=$(sed -n "$((index+1))p" /tmp/netutil_interfaces.tmp | cut -d: -f1)
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
# Read data back from temp files
if [ -f /tmp/netutil_interfaces.tmp ]; then
    interfaces_data=$(cat /tmp/netutil_interfaces.tmp)
fi
if [ -f /tmp/netutil_interfaces_count.tmp ]; then
    interfaces_count=$(cat /tmp/netutil_interfaces_count.tmp)
fi
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
        echo -n "Enter interface number: "
        read interface_num
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
        echo -n "Enter interface number: "
        read interface_num
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
        echo -n "Enter interface number: "
        read interface_num
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