#!/bin/sh

# Source shared utility functions
. "$(dirname "$0")/../common/utils.sh"
. "$(dirname "$0")/../common/colors.sh" 2>/dev/null || true
. "$(dirname "$0")/../common/logging.sh"
. "$(dirname "$0")/../common/validation.sh"
SCRIPT_NAME="$(basename "$0")"

echo "=== IP Route Configuration ===" >&2
log_info "=== Script started ===" "$SCRIPT_NAME"
echo >&2

echo "Current routing table:" >&2
ip route show >&2

echo >&2
echo "Route management options:" >&2
echo "1. Add route" >&2
echo "2. Delete route" >&2
echo "3. Set default gateway" >&2
echo "4. Show detailed routing table" >&2
echo "5. Show route to specific destination" >&2
echo "6. Exit" >&2

echo >&2
option=$(prompt_for_choice "Select option (1-6)" 1 6)
log_info "Route option selected: $option" "$SCRIPT_NAME"

case $option in
    1)
        echo "Adding a new route:" >&2
        echo >&2
        dest_network=$(prompt_for_cidr "Enter destination network (e.g., 192.168.2.0/24)" "")

        gateway=$(prompt_for_ip "Enter gateway IP" "")

        # Initialize interface as empty
        interface=""

        # Ask confirmation before requesting interface
        if confirm_action "Do you want to specify an interface?"; then
            echo >&2
            if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
                printf "%sEnter interface: %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
            else
                printf "Enter interface: \n" >&2
            fi
            read -r interface
        fi

        if [ -n "$interface" ]; then
            if ! ip link show "$interface" >/dev/null 2>&1; then
                log_error "Failed to add route: Interface $interface not found" "$SCRIPT_NAME"
                echo "Error: Interface $interface not found" >&2
                exit 1
            fi
            log_debug "Adding route: ip route add $dest_network via $gateway dev $interface" "$SCRIPT_NAME"
            ip route add "$dest_network" via "$gateway" dev "$interface"
            log_info "Route added: $dest_network via $gateway dev $interface" "$SCRIPT_NAME"
            echo "Route added: $dest_network via $gateway dev $interface"
        else
            log_debug "Adding route: ip route add $dest_network via $gateway" "$SCRIPT_NAME"
            ip route add "$dest_network" via "$gateway"
            log_info "Route added: $dest_network via $gateway" "$SCRIPT_NAME"
            echo "Route added: $dest_network via $gateway"
        fi
        ;;
    2)
        echo "Deleting a route:" >&2
        echo >&2
        dest_network=$(prompt_for_cidr "Enter destination network to delete (e.g., 192.168.2.0/24)" "")

        if ip route show "$dest_network" >/dev/null 2>&1; then
            log_debug "Deleting route: ip route del $dest_network" "$SCRIPT_NAME"
            ip route del "$dest_network"
            log_info "Route deleted: $dest_network" "$SCRIPT_NAME"
            echo "Route deleted: $dest_network"
        else
            log_error "Failed to delete route: $dest_network not found" "$SCRIPT_NAME"
            echo "Error: Route to $dest_network not found" >&2
            exit 1
        fi
        ;;
    3)
        echo "Setting default gateway:" >&2
        echo >&2

        # Show current default gateway if one exists
        current_gw=$(ip route show default 2>/dev/null | head -n 1)
        if [ -n "$current_gw" ]; then
            echo "Current default gateway: $current_gw" >&2
        else
            echo "No default gateway currently configured" >&2
        fi
        echo >&2

        gateway=$(prompt_for_ip "Enter gateway IP" "")

        # Initialize interface as empty
        interface=""

        if confirm_action "Do you want to specify an interface?"; then
            echo >&2
            if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
                printf "%sEnter interface: %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
            else
                printf "Enter interface: \n" >&2
            fi
            read -r interface
        fi

        if [ -n "$interface" ]; then
            if ! ip link show "$interface" >/dev/null 2>&1; then
                log_error "Failed to set default gateway: Interface $interface not found" "$SCRIPT_NAME"
                echo "Error: Interface $interface not found" >&2
                exit 1
            fi
            log_debug "Setting default gateway: ip route replace default via $gateway dev $interface" "$SCRIPT_NAME"
            ip route replace default via "$gateway" dev "$interface"
            log_info "Default gateway set: via $gateway dev $interface" "$SCRIPT_NAME"
            echo "Default gateway set: via $gateway dev $interface"
        else
            log_debug "Setting default gateway: ip route replace default via $gateway" "$SCRIPT_NAME"
            ip route replace default via "$gateway"
            log_info "Default gateway set: via $gateway" "$SCRIPT_NAME"
            echo "Default gateway set: via $gateway"
        fi
        ;;
    4)
        echo "Detailed routing table:"
        ip route show table all
        echo
        echo "Routing cache:"
        ip route show cache 2>/dev/null || echo "No cached routes"
        ;;
    5)
        dest_ip=$(prompt_for_ip "Enter destination IP" "")

        echo "Route to $dest_ip:"
        ip route get "$dest_ip"
        ;;
    6)
        echo "Exiting..." >&2
        exit 0
        ;;
    *)
        log_error "Invalid option selected: $option" "$SCRIPT_NAME"
        echo "Invalid option" >&2
        exit 1
        ;;
esac

echo >&2
echo "Updated routing table:" >&2
ip route show >&2