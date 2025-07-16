#!/bin/bash

echo "=== DNS Configuration ==="
echo

echo "Current DNS configuration:"
echo "--- /etc/resolv.conf ---"
cat /etc/resolv.conf

echo
echo "--- systemd-resolved status ---"
systemctl is-active systemd-resolved >/dev/null 2>&1 && {
    systemd-resolve --status 2>/dev/null || resolvectl status 2>/dev/null
} || echo "systemd-resolved not active"

echo
echo "DNS configuration options:"
echo "1. Add nameserver"
echo "2. Remove nameserver"
echo "3. Set search domain"
echo "4. Backup current configuration"
echo "5. Restore from backup"
echo "6. Exit"

read -p "Select option (1-6): " option

case $option in
    1)
        read -p "Enter nameserver IP: " nameserver
        if [[ ! $nameserver =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "Error: Invalid IP format"
            exit 1
        fi
        
        if grep -q "nameserver $nameserver" /etc/resolv.conf; then
            echo "Nameserver $nameserver already exists"
        else
            echo "nameserver $nameserver" >> /etc/resolv.conf
            echo "Nameserver $nameserver added"
        fi
        ;;
    2)
        read -p "Enter nameserver IP to remove: " nameserver
        if [[ ! $nameserver =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "Error: Invalid IP format"
            exit 1
        fi
        
        if grep -q "nameserver $nameserver" /etc/resolv.conf; then
            sed -i "/nameserver $nameserver/d" /etc/resolv.conf
            echo "Nameserver $nameserver removed"
        else
            echo "Nameserver $nameserver not found"
        fi
        ;;
    3)
        read -p "Enter search domain (e.g., example.com): " domain
        if [[ ! $domain =~ ^[a-zA-Z0-9.-]+$ ]]; then
            echo "Error: Invalid domain format"
            exit 1
        fi
        
        if grep -q "search " /etc/resolv.conf; then
            sed -i "s/search .*/search $domain/" /etc/resolv.conf
        else
            echo "search $domain" >> /etc/resolv.conf
        fi
        echo "Search domain set to $domain"
        ;;
    4)
        backup_file="/tmp/resolv.conf.backup.$(date +%Y%m%d_%H%M%S)"
        cp /etc/resolv.conf "$backup_file"
        echo "DNS configuration backed up to $backup_file"
        ;;
    5)
        echo "Available backup files:"
        ls -la /tmp/resolv.conf.backup.* 2>/dev/null || {
            echo "No backup files found"
            exit 1
        }
        
        read -p "Enter backup file path: " backup_file
        if [ -f "$backup_file" ]; then
            cp "$backup_file" /etc/resolv.conf
            echo "DNS configuration restored from $backup_file"
        else
            echo "Error: Backup file not found"
            exit 1
        fi
        ;;
    6)
        echo "Exiting..."
        exit 0
        ;;
    *)
        echo "Invalid option"
        exit 1
        ;;
esac

echo
echo "Updated DNS configuration:"
cat /etc/resolv.conf

echo
echo "Testing DNS resolution:"
nslookup google.com || echo "DNS test failed"