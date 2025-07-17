#!/bin/bash

echo "=== Network Interface Management ==="
echo

echo "Current network interfaces:"
ip link show

echo
echo "Interface details:"
ip addr show

echo
echo "Available actions:"
echo "1. Bring interface UP"
echo "2. Bring interface DOWN"
echo "3. Show interface statistics"
echo "4. Exit"

echo -n "Select action (1-4): "
read action

case $action in
    1)
        read -p "Enter interface name to bring UP: " interface
        if ip link show "$interface" >/dev/null 2>&1; then
            ip link set "$interface" up
            echo "Interface $interface brought UP"
            ip addr show "$interface"
        else
            echo "Error: Interface $interface not found"
            exit 1
        fi
        ;;
    2)
        read -p "Enter interface name to bring DOWN: " interface
        if ip link show "$interface" >/dev/null 2>&1; then
            ip link set "$interface" down
            echo "Interface $interface brought DOWN"
            ip addr show "$interface"
        else
            echo "Error: Interface $interface not found"
            exit 1
        fi
        ;;
    3)
        read -p "Enter interface name for statistics: " interface
        if ip link show "$interface" >/dev/null 2>&1; then
            echo "Statistics for $interface:"
            ip -s link show "$interface"
            echo
            echo "Traffic statistics:"
            cat /proc/net/dev | grep "$interface"
        else
            echo "Error: Interface $interface not found"
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