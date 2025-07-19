#!/bin/sh

# NetUtility Script Template
# This template demonstrates the standardized patterns all scripts should follow
# Copy this template when creating new scripts

# =============================================================================
# SCRIPT METADATA (for automatic discovery)
# =============================================================================
# Corresponding .meta.yaml file should exist for this script
# See: script_template.meta.yaml

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
SCRIPT_NAME="$(basename "$0")"
SCRIPT_VERSION="1.0"
SCRIPT_DESCRIPTION="Template script demonstrating standardized patterns"

# Default configuration
DEFAULT_TIMEOUT=300
MAX_RETRIES=3

# Results directory
RESULTS_DIR="${NETUTIL_WORKDIR:-$HOME}/template-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

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
    -h, --help      Show this help message
    -v, --version   Show script version
    -t, --timeout   Set timeout in seconds (default: $DEFAULT_TIMEOUT)
    
Examples:
    $SCRIPT_NAME                    # Interactive mode
    $SCRIPT_NAME --timeout 600      # Set custom timeout

Environment Variables:
    NETUTIL_WORKDIR    Working directory for output files
    NETUTIL_LOG_LEVEL  Logging level (0=DEBUG, 1=INFO, 2=WARN, 3=ERROR)

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
            -t|--timeout)
                if [ -n "$2" ] && validate_duration "$2"; then
                    DEFAULT_TIMEOUT="$2"
                    shift
                else
                    error_message "Invalid timeout value: $2"
                    exit 1
                fi
                ;;
            *)
                error_message "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
        shift
    done
}

# Function to check dependencies
check_dependencies() {
    local missing_tools=""
    
    # List of required tools (customize per script)
    local required_tools="ip grep sed awk"
    
    for tool in $required_tools; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools="$missing_tools $tool"
        fi
    done
    
    if [ -n "$missing_tools" ]; then
        error_message "Missing required tools:$missing_tools"
        log_error "Missing dependencies:$missing_tools" "$SCRIPT_NAME"
        return 1
    fi
    
    log_info "All dependencies satisfied" "$SCRIPT_NAME"
    return 0
}

# Function to initialize script environment
initialize_script() {
    # Log script start
    log_script_start "$SCRIPT_NAME" "$@"
    
    # Check dependencies
    if ! check_dependencies; then
        exit 1
    fi
    
    # Create results directory
    if ! mkdir -p "$RESULTS_DIR"; then
        error_message "Failed to create results directory: $RESULTS_DIR"
        exit 1
    fi
    
    # Set up signal handlers for graceful cleanup
    trap cleanup_and_exit INT TERM
    
    log_info "Script initialization completed" "$SCRIPT_NAME"
}

# Function to cleanup on exit
cleanup_and_exit() {
    local exit_code=${1:-0}
    
    log_info "Cleaning up..." "$SCRIPT_NAME"
    
    # Remove temporary files
    rm -f /tmp/netutil_*.$$ 2>/dev/null
    
    # Log script end
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

# =============================================================================
# MAIN SCRIPT FUNCTIONS
# =============================================================================

# Function to get user input with validation
get_validated_input() {
    local prompt="$1"
    local validation_function="$2"
    local max_attempts="${3:-3}"
    
    if result=$(prompt_and_validate "$prompt" "$validation_function" "$max_attempts"); then
        echo "$result"
        return 0
    else
        handle_error "Failed to get valid input for: $prompt"
    fi
}

# Main script logic function
run_main_logic() {
    echo "=== $SCRIPT_DESCRIPTION ==="
    echo
    
    # Example: Get network interface with validation
    echo "Selecting network interface..."
    interface=$(select_interface "Select interface for operation" "template")
    if [ -z "$interface" ]; then
        handle_error "No interface selected"
    fi
    
    # Validate the interface
    if ! validate_interface "$interface"; then
        handle_error "Invalid interface: $interface"
    fi
    
    success_message "Selected interface: $interface"
    log_config_change "interface_selection" "Selected interface: $interface"
    
    # Example: Get target with validation
    echo
    echo "Selecting target..."
    target=$(select_target)
    if [ -z "$target" ]; then
        handle_error "No target selected"
    fi
    
    # Validate the target
    if ! validate_target "$target"; then
        handle_error "Invalid target: $target"
    fi
    
    success_message "Selected target: $target"
    log_info "Target selected: $target" "$SCRIPT_NAME"
    
    # Example: Perform the main operation
    echo
    echo "Performing main operation..."
    
    # Create output file
    output_file="$RESULTS_DIR/template_output_${TIMESTAMP}.txt"
    
    # Log the operation
    log_info "Starting main operation" "$SCRIPT_NAME"
    log_command "ip addr show $interface" "$SCRIPT_NAME"
    
    # Execute the operation with error handling
    if ip addr show "$interface" > "$output_file" 2>&1; then
        log_command_result "ip addr show $interface" 0 "$SCRIPT_NAME"
        success_message "Operation completed successfully"
        echo "Output saved to: $output_file"
    else
        log_command_result "ip addr show $interface" 1 "$SCRIPT_NAME"
        handle_error "Operation failed"
    fi
    
    # Example: Show results summary
    echo
    echo "=== Results Summary ==="
    echo "Interface: $interface"
    echo "Target: $target"
    echo "Output file: $output_file"
    echo "File size: $(du -h "$output_file" | cut -f1)"
    
    log_info "Operation completed successfully" "$SCRIPT_NAME"
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    # Parse command line arguments
    parse_arguments "$@"
    
    # Initialize script
    initialize_script "$@"
    
    # Run main logic
    run_main_logic
    
    # Clean exit
    cleanup_and_exit 0
}

# Only run main if script is executed directly (not sourced)
if [ "${0##*/}" = "script_template.sh" ]; then
    main "$@"
fi