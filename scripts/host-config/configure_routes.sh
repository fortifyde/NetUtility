#!/bin/sh

# Source shared utility functions
. "$(dirname "$0")/../common/utils.sh"
. "$(dirname "$0")/../common/colors.sh" 2>/dev/null || true

echo "=== IP Route Configuration ===" >&2
echo >&2

echo "Current routing table:" >&2
ip route show >&2

echo >&2
echo "Route management options:" >&2
echo "1. Add route" >&2
echo "2. Delete route" >&2
echo "3. Show detailed routing table" >&2
echo "4. Show route to specific destination" >&2
echo "5. Exit" >&2

echo >&2
if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
    printf "%sSelect option (1-5): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
else
    printf "Select option (1-5): \n" >&2
fi
read -r option

case $option in
    1)
        echo "Adding a new route:" >&2
        echo >&2
        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
            printf "%sEnter destination network (e.g., 192.168.2.0/24): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
        else
            printf "Enter destination network (e.g., 192.168.2.0/24): \n" >&2
        fi
        read -r dest_network
        echo >&2
        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
            printf "%sEnter gateway IP: %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
        else
            printf "Enter gateway IP: \n" >&2
        fi
        read -r gateway

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

        if ! echo "$dest_network" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$' >/dev/null; then
            echo "Error: Invalid network format" >&2
            exit 1
        fi

        if ! echo "$gateway" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' >/dev/null; then
            echo "Error: Invalid gateway IP format" >&2
            exit 1
        fi

        if [ -n "$interface" ]; then
            if ! ip link show "$interface" >/dev/null 2>&1; then
                echo "Error: Interface $interface not found" >&2
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
        echo "Deleting a route:" >&2
        echo >&2
        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
            printf "%sEnter destination network to delete (e.g., 192.168.2.0/24): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
        else
            printf "Enter destination network to delete (e.g., 192.168.2.0/24): \n" >&2
        fi
        read -r dest_network

        if ! echo "$dest_network" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$' >/dev/null; then
            echo "Error: Invalid network format" >&2
            exit 1
        fi

        if ip route show "$dest_network" >/dev/null 2>&1; then
            ip route del "$dest_network"
            echo "Route deleted: $dest_network"
        else
            echo "Error: Route to $dest_network not found" >&2
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
        echo >&2
        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
            printf "%sEnter destination IP: %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
        else
            printf "Enter destination IP: \n" >&2
        fi
        read -r dest_ip
        if ! echo "$dest_ip" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' >/dev/null; then
            echo "Error: Invalid IP format" >&2
            exit 1
        fi

        echo "Route to $dest_ip:"
        ip route get "$dest_ip"
        ;;
    5)
        echo "Exiting..." >&2
        exit 0
        ;;
    *)
        echo "Invalid option" >&2
        exit 1
        ;;
esac

echo >&2
echo "Updated routing table:" >&2
ip route show >&2