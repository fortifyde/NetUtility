#!/bin/bash

echo "=== VLAN Interface Management ==="
echo

echo "Current interfaces:"
ip link show | grep -E "^[0-9]+:" | cut -d: -f2 | sed 's/^ *//'

echo
echo "Current VLAN interfaces:"
ip link show | grep "@" || echo "No VLAN interfaces found"

echo
read -p "Enter parent interface name: " parent_interface

if ! ip link show "$parent_interface" >/dev/null 2>&1; then
    echo "Error: Parent interface $parent_interface not found"
    exit 1
fi

echo "VLAN options:"
echo "1. Add VLAN interface"
echo "2. Remove VLAN interface"
echo "3. List VLAN interfaces"
echo "4. Exit"

read -p "Select option (1-4): " option

case $option in
    1)
        read -p "Enter VLAN ID (1-4094): " vlan_id
        if [[ ! $vlan_id =~ ^[0-9]+$ ]] || [ "$vlan_id" -lt 1 ] || [ "$vlan_id" -gt 4094 ]; then
            echo "Error: Invalid VLAN ID. Must be between 1-4094"
            exit 1
        fi
        
        vlan_interface="${parent_interface}.${vlan_id}"
        
        if ip link show "$vlan_interface" >/dev/null 2>&1; then
            echo "Error: VLAN interface $vlan_interface already exists"
            exit 1
        fi
        
        ip link add link "$parent_interface" name "$vlan_interface" type vlan id "$vlan_id"
        ip link set "$vlan_interface" up
        
        echo "VLAN interface $vlan_interface created and brought up"
        
        read -p "Configure IP address for $vlan_interface? (y/N): " config_ip
        if [[ $config_ip =~ ^[Yy]$ ]]; then
            read -p "Enter IP address with CIDR (e.g., 192.168.100.1/24): " ip_addr
            if [[ $ip_addr =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
                ip addr add "$ip_addr" dev "$vlan_interface"
                echo "IP address $ip_addr assigned to $vlan_interface"
            else
                echo "Error: Invalid IP address format"
            fi
        fi
        
        echo "VLAN interface details:"
        ip addr show "$vlan_interface"
        ;;
    2)
        read -p "Enter VLAN interface to remove (e.g., eth0.100): " vlan_interface
        if ip link show "$vlan_interface" >/dev/null 2>&1; then
            ip link delete "$vlan_interface"
            echo "VLAN interface $vlan_interface removed"
        else
            echo "Error: VLAN interface $vlan_interface not found"
            exit 1
        fi
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
        echo "Invalid option"
        exit 1
        ;;
esac