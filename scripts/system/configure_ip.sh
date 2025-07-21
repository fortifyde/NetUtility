#!/bin/sh

# IP Address Configuration Script
# Enhanced version demonstrating standardized patterns and security improvements

# =============================================================================
# INITIALIZATION AND IMPORTS
# =============================================================================

# Get the script directory for reliable imports
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Source shared utilities (order matters)
. "$SCRIPT_DIR/../common/logging.sh"
. "$SCRIPT_DIR/../common/utils.sh"
. "$SCRIPT_DIR/../common/validation.sh"

# =============================================================================
# SCRIPT CONFIGURATION
# =============================================================================

# Script metadata
SCRIPT_NAME="configure_ip"
SCRIPT_VERSION="2.0"
SCRIPT_DESCRIPTION="Configure IP addresses on network interfaces"

# =============================================================================
# FUNCTION DEFINITIONS
# =============================================================================

# Function to display script usage
show_usage() {
    cat << EOF
Usage: $SCRIPT_NAME [OPTIONS]

Description:
    $SCRIPT_DESCRIPTION

Options:
    -h, --help              Show this help message
    -v, --version           Show script version
    -i, --interface IFACE   Pre-select interface
    -a, --add IP/CIDR       Add IP address directly
    -r, --remove IP/CIDR    Remove IP address directly
    --flush IFACE           Flush all addresses from interface
    
Examples:
    $SCRIPT_NAME                                    # Interactive mode
    $SCRIPT_NAME -i eth0 -a 192.168.1.100/24      # Add IP directly
    $SCRIPT_NAME -i eth0 -r 192.168.1.100/24      # Remove IP directly
    $SCRIPT_NAME --flush eth0                      # Flush all IPs

EOF
}

# Function to parse command line arguments
parse_arguments() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -h|--help)
                show_usage
                exit 0
                ;;
            -v|--version)
                echo "$SCRIPT_NAME version $SCRIPT_VERSION"
                exit 0
                ;;
            -i|--interface)
                if [ -n "$2" ] && validate_interface "$2"; then
                    SELECTED_INTERFACE="$2"
                    shift
                else
                    handle_error "Invalid interface: $2"
                fi
                ;;
            -a|--add)
                if [ -n "$2" ] && validate_ip_range "$2"; then
                    OPERATION="add"
                    IP_ADDRESS="$2"
                    shift
                else
                    handle_error "Invalid IP address: $2"
                fi
                ;;
            -r|--remove)
                if [ -n "$2" ] && validate_ip_range "$2"; then
                    OPERATION="remove"
                    IP_ADDRESS="$2"
                    shift
                else
                    handle_error "Invalid IP address: $2"
                fi
                ;;
            --flush)
                if [ -n "$2" ] && validate_interface "$2"; then
                    OPERATION="flush"
                    SELECTED_INTERFACE="$2"
                    shift
                else
                    handle_error "Invalid interface: $2"
                fi
                ;;
            *)
                handle_error "Unknown option: $1"
                ;;
        esac
        shift
    done
}

# Function to check dependencies
check_dependencies() {
    local missing_tools=""
    local required_tools="ip grep"
    
    for tool in $required_tools; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools="$missing_tools $tool"
        fi
    done
    
    if [ -n "$missing_tools" ]; then
        handle_error "Missing required tools:$missing_tools"
    fi
    
    log_info "All dependencies satisfied" "$SCRIPT_NAME"
}

# Function to initialize script environment
initialize_script() {
    log_script_start "$SCRIPT_NAME" "$@"
    check_dependencies
    trap cleanup_and_exit INT TERM
    log_info "Script initialization completed" "$SCRIPT_NAME"
}

# Function to cleanup on exit
cleanup_and_exit() {
    local exit_code=${1:-0}
    log_script_end "$SCRIPT_NAME" "$exit_code"
    exit "$exit_code"
}

# Function to handle errors consistently
handle_error() {
    local error_message="$1"
    local exit_code="${2:-1}"
    
    error_message "$error_message"
    log_error "$error_message" "$SCRIPT_NAME"
    cleanup_and_exit "$exit_code"
}

# Function to show current IP configuration
show_current_config() {
    echo "=== Current IP Configuration ==="
    echo
    
    if [ -n "$1" ]; then
        # Show specific interface
        log_command "ip addr show $1" "$SCRIPT_NAME"
        ip addr show "$1"
    else
        # Show all interfaces
        log_command "ip addr show" "$SCRIPT_NAME"
        ip addr show
    fi
    echo
}

# Function to safely add IP address
add_ip_address() {
    local interface="$1"
    local ip_addr="$2"
    
    # Validate inputs
    if ! validate_interface "$interface"; then
        handle_error "Invalid interface: $interface"
    fi
    
    if ! validate_ip_range "$ip_addr"; then
        handle_error "Invalid IP address: $ip_addr"
    fi
    
    # Security check
    if ! security_validate "$ip_addr" "IP address"; then
        handle_error "Security validation failed for IP address"
    fi
    
    # Check if IP already exists
    if ip addr show "$interface" | grep -q "$ip_addr"; then
        warning_message "IP address $ip_addr already exists on $interface"
        return 1
    fi
    
    log_config_change "add_ip" "Adding $ip_addr to $interface"
    log_command "ip addr add $ip_addr dev $interface" "$SCRIPT_NAME"
    
    if ip addr add "$ip_addr" dev "$interface" 2>/dev/null; then
        log_command_result "ip addr add $ip_addr dev $interface" 0 "$SCRIPT_NAME"
        success_message "IP address $ip_addr added to $interface"
        show_current_config "$interface"
        return 0
    else
        log_command_result "ip addr add $ip_addr dev $interface" 1 "$SCRIPT_NAME"
        handle_error "Failed to add IP address $ip_addr to $interface"
    fi
}

# Function to safely remove IP address
remove_ip_address() {
    local interface="$1"
    local ip_addr="$2"
    
    # Validate inputs
    if ! validate_interface "$interface"; then
        handle_error "Invalid interface: $interface"
    fi
    
    if ! validate_ip_range "$ip_addr"; then
        handle_error "Invalid IP address: $ip_addr"
    fi
    
    # Check if IP exists
    if ! ip addr show "$interface" | grep -q "$ip_addr"; then
        warning_message "IP address $ip_addr not found on $interface"
        return 1
    fi
    
    log_config_change "remove_ip" "Removing $ip_addr from $interface"
    log_command "ip addr del $ip_addr dev $interface" "$SCRIPT_NAME"
    
    if ip addr del "$ip_addr" dev "$interface" 2>/dev/null; then
        log_command_result "ip addr del $ip_addr dev $interface" 0 "$SCRIPT_NAME"
        success_message "IP address $ip_addr removed from $interface"
        show_current_config "$interface"
        return 0
    else
        log_command_result "ip addr del $ip_addr dev $interface" 1 "$SCRIPT_NAME"
        handle_error "Failed to remove IP address $ip_addr from $interface"
    fi
}

# Function to safely flush all IP addresses
flush_ip_addresses() {
    local interface="$1"
    
    # Validate input
    if ! validate_interface "$interface"; then
        handle_error "Invalid interface: $interface"
    fi
    
    # Confirm dangerous operation
    if ! confirm_action "Are you sure you want to flush all IP addresses from $interface?"; then
        warning_message "Operation cancelled by user"
        return 1
    fi
    
    log_config_change "flush_ip" "Flushing all IPs from $interface"
    log_command "ip addr flush dev $interface" "$SCRIPT_NAME"
    
    if ip addr flush dev "$interface" 2>/dev/null; then
        log_command_result "ip addr flush dev $interface" 0 "$SCRIPT_NAME"
        success_message "All IP addresses flushed from $interface"
        show_current_config "$interface"
        return 0
    else
        log_command_result "ip addr flush dev $interface" 1 "$SCRIPT_NAME"
        handle_error "Failed to flush IP addresses from $interface"
    fi
}

# Function to get valid IP address with CIDR
get_ip_with_cidr() {
    local prompt="$1"
    
    if result=$(prompt_and_validate "$prompt" "validate_ip_range" 3); then
        echo "$result"
        return 0
    else
        handle_error "Failed to get valid IP address"
    fi
}

# Function to run interactive mode
run_interactive_mode() {
    echo "=== IP Address Configuration ==="
    echo
    
    # Show current configuration
    show_current_config
    
    # Get interface if not already selected
    if [ -z "$SELECTED_INTERFACE" ]; then
        SELECTED_INTERFACE=$(select_interface "Select interface for IP configuration" "ip")
        if [ -z "$SELECTED_INTERFACE" ]; then
            handle_error "No interface selected"
        fi
    fi
    
    # Validate selected interface
    if ! validate_interface "$SELECTED_INTERFACE"; then
        handle_error "Invalid interface: $SELECTED_INTERFACE"
    fi
    
    success_message "Selected interface: $SELECTED_INTERFACE"
    echo
    echo "Current configuration for $SELECTED_INTERFACE:"
    show_current_config "$SELECTED_INTERFACE"
    
    # Show menu options
    echo "IP Configuration options:"
    echo "1. Add IP address"
    echo "2. Remove IP address"
    echo "3. Flush all IP addresses"
    echo "4. Exit"
    echo
    
    # Get user choice with validation
    choice=$(get_validated_input "Select option (1-4)" "validate_numeric_choice 1 4")
    
    case "$choice" in
        1)
            ip_addr=$(get_ip_with_cidr "Enter IP address with CIDR (e.g., 192.168.1.100/24)")
            add_ip_address "$SELECTED_INTERFACE" "$ip_addr"
            ;;
        2)
            ip_addr=$(get_ip_with_cidr "Enter IP address with CIDR to remove")
            remove_ip_address "$SELECTED_INTERFACE" "$ip_addr"
            ;;
        3)
            flush_ip_addresses "$SELECTED_INTERFACE"
            ;;
        4)
            echo "Exiting..."
            cleanup_and_exit 0
            ;;
    esac
}

# Function to run command-line mode
run_command_mode() {
    case "$OPERATION" in
        add)
            add_ip_address "$SELECTED_INTERFACE" "$IP_ADDRESS"
            ;;
        remove)
            remove_ip_address "$SELECTED_INTERFACE" "$IP_ADDRESS"
            ;;
        flush)
            flush_ip_addresses "$SELECTED_INTERFACE"
            ;;
        *)
            handle_error "Invalid operation: $OPERATION"
            ;;
    esac
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    # Initialize variables
    SELECTED_INTERFACE=""
    OPERATION=""
    IP_ADDRESS=""
    
    # Parse command line arguments
    parse_arguments "$@"
    
    # Initialize script
    initialize_script "$@"
    
    # Run appropriate mode
    if [ -n "$OPERATION" ]; then
        run_command_mode
    else
        run_interactive_mode
    fi
    
    # Clean exit
    cleanup_and_exit 0
}

# Only run main if script is executed directly (not sourced)
if [ "${0##*/}" = "configure_ip.sh" ]; then
    main "$@"
fi