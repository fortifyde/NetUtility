#!/bin/bash

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

read -p "Select option (1-5): " option

case $option in
    1)
        echo "Adding a new route:"
        read -p "Enter destination network (e.g., 192.168.2.0/24): " dest_network
        read -p "Enter gateway IP: " gateway
        read -p "Enter interface (optional, press Enter to skip): " interface
        
        if [[ ! $dest_network =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
            echo "Error: Invalid network format"
            exit 1
        fi
        
        if [[ ! $gateway =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
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
        read -p "Enter destination network to delete (e.g., 192.168.2.0/24): " dest_network
        
        if [[ ! $dest_network =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
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
        read -p "Enter destination IP: " dest_ip
        if [[ ! $dest_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
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