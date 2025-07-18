#!/bin/sh

# Source shared utility functions
. "$(dirname "$0")/../common/utils.sh"

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
        interface=$(select_interface "Select interface to bring UP" "management")
        if [ -z "$interface" ]; then
            error_message "No interface selected"
            exit 1
        fi
        
        echo "Bringing interface $interface UP..."
        ip link set "$interface" up
        if [ $? -eq 0 ]; then
            success_message "Interface $interface brought UP"
            echo "Current status:"
            ip addr show "$interface"
        else
            error_message "Failed to bring interface $interface UP"
            exit 1
        fi
        ;;
    2)
        interface=$(select_interface "Select interface to bring DOWN" "management")
        if [ -z "$interface" ]; then
            error_message "No interface selected"
            exit 1
        fi
        
        echo "Bringing interface $interface DOWN..."
        ip link set "$interface" down
        if [ $? -eq 0 ]; then
            success_message "Interface $interface brought DOWN"
            echo "Current status:"
            ip addr show "$interface"
        else
            error_message "Failed to bring interface $interface DOWN"
            exit 1
        fi
        ;;
    3)
        interface=$(select_interface "Select interface to show statistics" "management")
        if [ -z "$interface" ]; then
            error_message "No interface selected"
            exit 1
        fi
        
        echo "=== Interface Statistics for $interface ==="
        echo
        echo "--- Interface Details ---"
        ip addr show "$interface"
        echo
        echo "--- Statistics ---"
        cat /proc/net/dev | grep "$interface" || echo "No statistics available"
        echo
        echo "--- Link Status ---"
        ip link show "$interface"
        ;;
    4)
        echo "Exiting..."
        exit 0
        ;;
    *)
        error_message "Invalid action selected"
        exit 1
        ;;
esac

# Clean up temp files
rm -f /tmp/netutil_interfaces.$$