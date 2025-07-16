#!/bin/bash

echo "=== IP Address Configuration ==="
echo

echo "Current IP configuration:"
ip addr show

echo
echo "Available interfaces:"
ip link show | grep -E "^[0-9]+:" | cut -d: -f2 | sed 's/^ *//'

echo
read -p "Enter interface name: " interface

if ! ip link show "$interface" >/dev/null 2>&1; then
    echo "Error: Interface $interface not found"
    exit 1
fi

echo "Current configuration for $interface:"
ip addr show "$interface"

echo
echo "IP Configuration options:"
echo "1. Add IP address"
echo "2. Remove IP address"
echo "3. Flush all IP addresses"
echo "4. Exit"

read -p "Select option (1-4): " option

case $option in
    1)
        read -p "Enter IP address with CIDR (e.g., 192.168.1.100/24): " ip_addr
        if [[ $ip_addr =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
            ip addr add "$ip_addr" dev "$interface"
            echo "IP address $ip_addr added to $interface"
            ip addr show "$interface"
        else
            echo "Error: Invalid IP address format"
            exit 1
        fi
        ;;
    2)
        read -p "Enter IP address with CIDR to remove: " ip_addr
        if [[ $ip_addr =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
            ip addr del "$ip_addr" dev "$interface"
            echo "IP address $ip_addr removed from $interface"
            ip addr show "$interface"
        else
            echo "Error: Invalid IP address format"
            exit 1
        fi
        ;;
    3)
        read -p "Are you sure you want to flush all IP addresses from $interface? (y/N): " confirm
        if [[ $confirm =~ ^[Yy]$ ]]; then
            ip addr flush dev "$interface"
            echo "All IP addresses flushed from $interface"
            ip addr show "$interface"
        else
            echo "Operation cancelled"
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