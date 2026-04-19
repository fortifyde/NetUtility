#!/bin/sh

# Source shared utility functions
. "$(dirname "$0")/../common/utils.sh"
. "$(dirname "$0")/../common/colors.sh" 2>/dev/null || true
. "$(dirname "$0")/../common/logging.sh"
SCRIPT_NAME="$(basename "$0")"

echo "=== Network Interface Management ==="
log_info "=== Script started ===" "$SCRIPT_NAME"
echo >&2

# Load and display interfaces
get_interfaces
display_interfaces
echo >&2

echo "Available actions:" >&2
echo "1. Bring interface UP" >&2
echo "2. Bring interface DOWN" >&2
echo "3. Bring all VLAN interfaces UP" >&2
echo "4. Bring all VLAN interfaces DOWN" >&2
echo "5. Show interface statistics" >&2
echo "6. Exit" >&2

echo >&2
if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
    printf "%sSelect action (1-6): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
else
    printf "Select action (1-6): \n" >&2
fi
read -r action

case $action in
    1)
        interface=$(select_interface "Select interface to bring UP" "management")
        if [ -z "$interface" ]; then
            log_error "No interface selected" "$SCRIPT_NAME"
            error_message "No interface selected"
            exit 1
        fi

        echo "Bringing interface $interface UP..." >&2
        log_info "Bringing interface $interface UP" "$SCRIPT_NAME"
        if ip link set "$interface" up; then
            log_info "Flushing IPv6 link-local addresses on $interface" "$SCRIPT_NAME"
            ip -6 addr flush dev "$interface" scope link 2>/dev/null || true
            log_info "Interface $interface brought UP successfully" "$SCRIPT_NAME"
            success_message "Interface $interface brought UP"
            echo "Current status:" >&2
            ip addr show "$interface" >&2
        else
            log_error "Failed to bring interface $interface UP" "$SCRIPT_NAME"
            error_message "Failed to bring interface $interface UP"
            exit 1
        fi
        ;;
    2)
        interface=$(select_interface "Select interface to bring DOWN" "management")
        if [ -z "$interface" ]; then
            log_error "No interface selected" "$SCRIPT_NAME"
            error_message "No interface selected"
            exit 1
        fi

        echo "Bringing interface $interface DOWN..." >&2
        log_info "Bringing interface $interface DOWN" "$SCRIPT_NAME"
        if ip link set "$interface" down; then
            log_info "Interface $interface brought DOWN successfully" "$SCRIPT_NAME"
            success_message "Interface $interface brought DOWN"
            echo "Current status:" >&2
            ip addr show "$interface" >&2
        else
            log_error "Failed to bring interface $interface DOWN" "$SCRIPT_NAME"
            error_message "Failed to bring interface $interface DOWN"
            exit 1
        fi
        ;;
    3)
        echo "Bringing all interfaces UP (excluding loopback and parent interfaces)..." >&2
        echo "Only affecting VLAN interfaces (interfaces with '.' in name)" >&2
        log_info "Bringing all VLAN interfaces UP" "$SCRIPT_NAME"

        ip link show | grep -E "^[0-9]+:" | grep -v "lo:" | while read -r line; do
            interface=$(echo "$line" | sed 's/^[0-9]*: *\([^:@]*\)[@:].*/\1/')
            # Only affect VLAN interfaces (contain dot) and exclude loopback
            if [ -n "$interface" ] && [ "$interface" != "lo" ] && echo "$interface" | grep -q "\."; then
                log_info "Bringing VLAN interface $interface UP" "$SCRIPT_NAME"
                if ip link set "$interface" up 2>/dev/null; then
                    log_info "Flushing IPv6 link-local on $interface" "$SCRIPT_NAME"
                    ip -6 addr flush dev "$interface" scope link 2>/dev/null || true
                    echo "  ✓ $interface UP (VLAN)" >&2
                else
                    echo "  ✗ $interface FAILED (VLAN)" >&2
                fi
            fi
        done

        log_info "All VLAN interfaces brought UP" "$SCRIPT_NAME"
        success_message "All VLAN interfaces brought UP"
        ;;
    4)
        echo "Bringing all interfaces DOWN (excluding loopback and parent interfaces)..." >&2
        echo "Only affecting VLAN interfaces (interfaces with '.' in name)" >&2
        log_info "Bringing all VLAN interfaces DOWN" "$SCRIPT_NAME"

        ip link show | grep -E "^[0-9]+:" | grep -v "lo:" | while read -r line; do
            interface=$(echo "$line" | sed 's/^[0-9]*: *\([^:@]*\)[@:].*/\1/')
            # Only affect VLAN interfaces (contain dot) and exclude loopback
            if [ -n "$interface" ] && [ "$interface" != "lo" ] && echo "$interface" | grep -q "\."; then
                log_info "Bringing VLAN interface $interface DOWN" "$SCRIPT_NAME"
                if ip link set "$interface" down 2>/dev/null; then
                    echo "  ✓ $interface DOWN (VLAN)" >&2
                else
                    echo "  ✗ $interface FAILED (VLAN)" >&2
                fi
            fi
        done

        log_info "All VLAN interfaces brought DOWN" "$SCRIPT_NAME"
        success_message "All VLAN interfaces brought DOWN"
        ;;
    5)
        interface=$(select_interface "Select interface to show statistics" "management")
        if [ -z "$interface" ]; then
            log_error "No interface selected" "$SCRIPT_NAME"
            error_message "No interface selected"
            exit 1
        fi

        log_info "Showing statistics for interface: $interface" "$SCRIPT_NAME"
        echo "=== Interface Statistics for $interface ===" >&2
        echo >&2
        echo "--- Interface Details ---" >&2
        ip addr show "$interface" >&2
        echo >&2
        echo "--- Statistics ---" >&2
        cat /proc/net/dev | grep "$interface" || echo "No statistics available" >&2
        echo >&2
        echo "--- Link Status ---" >&2
        ip link show "$interface" >&2
        ;;
    6)
        echo "Exiting..."
        exit 0
        ;;
    *)
        log_error "Invalid action selected: $action" "$SCRIPT_NAME"
        error_message "Invalid action selected"
        exit 1
        ;;
esac

# Clean up temp files
rm -f /tmp/netutil_interfaces.$$
