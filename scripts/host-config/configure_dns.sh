#!/bin/sh

. "$(dirname "$0")/../common/colors.sh" 2>/dev/null || true
. "$(dirname "$0")/../common/logging.sh" 2>/dev/null || true
. "$(dirname "$0")/../common/validation.sh" 2>/dev/null || true
SCRIPT_NAME="$(basename "$0")"

echo "=== DNS Configuration ==="
log_info "=== Script started ===" "$SCRIPT_NAME"
echo >&2

echo "Current DNS configuration:"
echo "--- /etc/resolv.conf ---"
cat /etc/resolv.conf

echo >&2
echo "--- systemd-resolved status ---"
systemctl is-active systemd-resolved >/dev/null 2>&1 && {
    systemd-resolve --status 2>/dev/null || resolvectl status 2>/dev/null
} || echo "systemd-resolved not active"

echo >&2
echo "DNS configuration options:"
echo "1. Add nameserver"
echo "2. Remove nameserver"
echo "3. Set search domain"
echo "4. Backup current configuration"
echo "5. Restore from backup"
echo "6. Exit"

option=$(prompt_for_choice "Select option (1-6)" 1 6)
log_info "DNS option selected: $option" "$SCRIPT_NAME"

case $option in
    1)
        nameserver=$(prompt_for_ip "Enter nameserver IP" "")

        if grep -q "nameserver $nameserver" /etc/resolv.conf; then
            echo "Nameserver $nameserver already exists"
        else
            echo "nameserver $nameserver" >> /etc/resolv.conf
            echo "Nameserver $nameserver added"
            log_info "Nameserver added: $nameserver" "$SCRIPT_NAME"
        fi
        ;;
    2)
        nameserver=$(prompt_for_ip "Enter nameserver IP to remove" "")

        if grep -q "nameserver $nameserver" /etc/resolv.conf; then
            sed -i "/nameserver $nameserver/d" /etc/resolv.conf
            echo "Nameserver $nameserver removed"
            log_info "Nameserver removed from /etc/resolv.conf" "$SCRIPT_NAME"
        else
            echo "Nameserver $nameserver not found"
        fi
        ;;
    3)
        domain=$(get_validated_input "Enter search domain (e.g., example.com)" validate_domain_input "")

        if grep -q "search " /etc/resolv.conf; then
            sed -i "s/search .*/search $domain/" /etc/resolv.conf
        else
            echo "search $domain" >> /etc/resolv.conf
        fi
        echo "Search domain set to $domain"
        log_info "Search domain set" "$SCRIPT_NAME"
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
        
        backup_file=$(get_validated_input "Enter backup file path" validate_file_path "")
        cp "$backup_file" /etc/resolv.conf
        echo "DNS configuration restored from $backup_file"
        ;;
    6)
        echo "Exiting..."
        exit 0
        ;;
    *)
        echo "Invalid option"
        ;;
esac

echo >&2
echo "Updated DNS configuration:"
cat /etc/resolv.conf

echo >&2
ns=$(awk '/^nameserver/{print $2; exit}' /etc/resolv.conf)
if [ -n "$ns" ]; then
    echo "Testing DNS resolution (querying $ns):"
    nslookup "$ns" "$ns" || echo "DNS test failed"
else
    echo "No nameserver configured, skipping DNS test"
fi