#!/bin/sh

echo "=== IP Route Configuration ==="
echo

echo "Current routing table:"
ip route show

echo
echo "Route management options:"
echo "1. Add route"
echo "2. Delete route"
echo "3. Show detailed routing table"
echo "4. Show route to specific destination"
echo "5. Exit"

echo "Select option (1-5): " >&2
read option

case $option in
    1)
        echo "Adding a new route:"
        echo "Enter destination network (e.g., 192.168.2.0/24): " >&2
        read dest_network
        echo "Enter gateway IP: " >&2
        read gateway
        echo "Enter interface (optional, press Enter to skip): " >&2
        read interface
        
        if ! echo "$dest_network" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$' >/dev/null; then
            echo "Error: Invalid network format"
            exit 1
        fi
        
        if ! echo "$gateway" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' >/dev/null; then
            echo "Error: Invalid gateway IP format"
            exit 1
        fi
        
        if [ -n "$interface" ]; then
            if ! ip link show "$interface" >/dev/null 2>&1; then
                echo "Error: Interface $interface not found"
                exit 1
            fi
            ip route add "$dest_network" via "$gateway" dev "$interface"
            echo "Route added: $dest_network via $gateway dev $interface"
        else
            ip route add "$dest_network" via "$gateway"
            echo "Route added: $dest_network via $gateway"
        fi
        ;;
    2)
        echo "Deleting a route:"
        echo "Enter destination network to delete (e.g., 192.168.2.0/24): " >&2
        read dest_network
        
        if ! echo "$dest_network" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$' >/dev/null; then
            echo "Error: Invalid network format"
            exit 1
        fi
        
        if ip route show "$dest_network" >/dev/null 2>&1; then
            ip route del "$dest_network"
            echo "Route deleted: $dest_network"
        else
            echo "Error: Route to $dest_network not found"
            exit 1
        fi
        ;;
    3)
        echo "Detailed routing table:"
        ip route show table all
        echo
        echo "Routing cache:"
        ip route show cache 2>/dev/null || echo "No cached routes"
        ;;
    4)
        echo "Enter destination IP: " >&2
        read dest_ip
        if ! echo "$dest_ip" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' >/dev/null; then
            echo "Error: Invalid IP format"
            exit 1
        fi
        
        echo "Route to $dest_ip:"
        ip route get "$dest_ip"
        ;;
    5)
        echo "Exiting..."
        exit 0
        ;;
    *)
        echo "Invalid option"
        exit 1
        ;;
esac

echo
echo "Updated routing table:"
ip route show