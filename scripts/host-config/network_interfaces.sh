#!/bin/sh

# Source shared utility functions
. "$(dirname "$0")/../common/utils.sh"

echo "=== Network Interface Management ==="
echo

# Load and display interfaces
get_interfaces
display_interfaces
echo

echo "Available actions:" >&2
echo "1. Bring interface UP" >&2
echo "2. Bring interface DOWN" >&2
echo "3. Bring all VLAN interfaces UP" >&2
echo "4. Bring all VLAN interfaces DOWN" >&2
echo "5. Show interface statistics" >&2
echo "6. Exit" >&2

echo "Select action (1-6): " >&2
read -r action

case $action in
    1)
        interface=$(select_interface "Select interface to bring UP" "management")
        if [ -z "$interface" ]; then
            error_message "No interface selected"
            exit 1
        fi
        
        echo "Bringing interface $interface UP..."
        if ip link set "$interface" up; then
            ip -6 addr flush dev "$interface" scope link 2>/dev/null || true
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
        if ip link set "$interface" down; then
            success_message "Interface $interface brought DOWN"
            echo "Current status:"
            ip addr show "$interface"
        else
            error_message "Failed to bring interface $interface DOWN"
            exit 1
        fi
        ;;
    3)
        echo "Bringing all interfaces UP (excluding loopback and parent interfaces)..."
        echo "Only affecting VLAN interfaces (interfaces with '.' in name)"

        ip link show | grep -E "^[0-9]+:" | grep -v "lo:" | while read -r line; do
            interface=$(echo "$line" | sed 's/^[0-9]*: *\([^:@]*\)[@:].*/\1/')
            # Only affect VLAN interfaces (contain dot) and exclude loopback
            if [ -n "$interface" ] && [ "$interface" != "lo" ] && echo "$interface" | grep -q "\."; then
                if ip link set "$interface" up 2>/dev/null; then
                    ip -6 addr flush dev "$interface" scope link 2>/dev/null || true
                    echo "  ✓ $interface UP (VLAN)"
                else
                    echo "  ✗ $interface FAILED (VLAN)"
                fi
            fi
        done

        success_message "All VLAN interfaces brought UP"
        ;;
    4)
        echo "Bringing all interfaces DOWN (excluding loopback and parent interfaces)..."
        echo "Only affecting VLAN interfaces (interfaces with '.' in name)"

        ip link show | grep -E "^[0-9]+:" | grep -v "lo:" | while read -r line; do
            interface=$(echo "$line" | sed 's/^[0-9]*: *\([^:@]*\)[@:].*/\1/')
            # Only affect VLAN interfaces (contain dot) and exclude loopback
            if [ -n "$interface" ] && [ "$interface" != "lo" ] && echo "$interface" | grep -q "\."; then
                if ip link set "$interface" down 2>/dev/null; then
                    echo "  ✓ $interface DOWN (VLAN)"
                else
                    echo "  ✗ $interface FAILED (VLAN)"
                fi
            fi
        done

        success_message "All VLAN interfaces brought DOWN"
        ;;
    5)
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
    6)
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
