#!/bin/sh

. "$(dirname "$0")/../common/colors.sh" 2>/dev/null || true
. "$(dirname "$0")/../common/logging.sh" 2>/dev/null || true
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

echo >&2
if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
    printf "%sSelect option (1-6): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
else
    printf "Select option (1-6): \n" >&2
fi
read -r option
log_info "DNS option selected: $option" "$SCRIPT_NAME"

case $option in
    1)
        echo >&2
        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
            printf "%sEnter nameserver IP: %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
        else
            printf "Enter nameserver IP: \n" >&2
        fi
        read -r nameserver
        if ! echo "$nameserver" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' >/dev/null; then
            echo "Error: Invalid IP format"
            log_error "Failed to add nameserver" "$SCRIPT_NAME"
            exit 1
        fi

        if grep -q "nameserver $nameserver" /etc/resolv.conf; then
            echo "Nameserver $nameserver already exists"
        else
            echo "nameserver $nameserver" >> /etc/resolv.conf
            echo "Nameserver $nameserver added"
            log_info "Nameserver added: $nameserver" "$SCRIPT_NAME"
        fi
        ;;
    2)
        echo >&2
        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
            printf "%sEnter nameserver IP to remove: %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
        else
            printf "Enter nameserver IP to remove: \n" >&2
        fi
        read -r nameserver
        if ! echo "$nameserver" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' >/dev/null; then
            echo "Error: Invalid IP format"
            exit 1
        fi

        if grep -q "nameserver $nameserver" /etc/resolv.conf; then
            sed -i "/nameserver $nameserver/d" /etc/resolv.conf
            echo "Nameserver $nameserver removed"
            log_info "Nameserver removed from /etc/resolv.conf" "$SCRIPT_NAME"
        else
            echo "Nameserver $nameserver not found"
        fi
        ;;
    3)
        echo >&2
        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
            printf "%sEnter search domain (e.g., example.com): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
        else
            printf "Enter search domain (e.g., example.com): \n" >&2
        fi
        read -r domain
        if ! echo "$domain" | grep -E '^[a-zA-Z0-9.-]+$' >/dev/null; then
            echo "Error: Invalid domain format"
            exit 1
        fi

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
        
        echo >&2
        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
            printf "%sEnter backup file path: %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
        else
            printf "Enter backup file path: \n" >&2
        fi
        read -r backup_file
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