#!/bin/sh

# Enhanced Network Enumeration Script
# Demonstrates progress indicators, cancellation support, and standardized patterns

# =============================================================================
# INITIALIZATION AND IMPORTS
# =============================================================================

# Get the script directory for reliable imports
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Source shared utilities (order matters)
. "$SCRIPT_DIR/../common/logging.sh"
. "$SCRIPT_DIR/../common/utils.sh"
. "$SCRIPT_DIR/../common/validation.sh"
. "$SCRIPT_DIR/../common/progress.sh"

# =============================================================================
# SCRIPT CONFIGURATION
# =============================================================================

# Script metadata
SCRIPT_NAME="network_enum_enhanced"
SCRIPT_VERSION="2.0"
SCRIPT_DESCRIPTION="Enhanced network enumeration with progress tracking and cancellation"

# Default configuration
DEFAULT_TIMEOUT=300
RESULTS_DIR="${NETUTIL_WORKDIR:-$HOME}/enumeration"
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
    -h, --help          Show this help message
    -v, --version       Show script version
    -t, --target TARGET Target IP, range, or file
    -s, --scan-type TYPE Scan type (quick|detailed|comprehensive)
    --timeout SECONDS   Set timeout (default: $DEFAULT_TIMEOUT)
    
Scan Types:
    quick           Fast discovery scan (30s)
    detailed        Standard enumeration (2-5 min)
    comprehensive   Full enumeration (10+ min)
    
Examples:
    $SCRIPT_NAME                               # Interactive mode
    $SCRIPT_NAME -t 192.168.1.0/24 -s quick  # Quick scan
    $SCRIPT_NAME -t hosts.txt -s detailed     # Scan from file

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
            -t|--target)
                if [ -n "$2" ] && validate_target "$2"; then
                    TARGET="$2"
                    shift
                else
                    handle_error "Invalid target: $2"
                fi
                ;;
            -s|--scan-type)
                if [ -n "$2" ] && validate_choice "$2" "quick detailed comprehensive"; then
                    SCAN_TYPE="$2"
                    shift
                else
                    handle_error "Invalid scan type: $2"
                fi
                ;;
            --timeout)
                if [ -n "$2" ] && validate_duration "$2"; then
                    DEFAULT_TIMEOUT="$2"
                    shift
                else
                    handle_error "Invalid timeout: $2"
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
    local required_tools="nmap fping ip grep awk"
    
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
    
    if ! mkdir -p "$RESULTS_DIR"; then
        handle_error "Failed to create results directory: $RESULTS_DIR"
    fi
    
    setup_cancellation
    log_info "Script initialization completed" "$SCRIPT_NAME"
}

# Function to cleanup on exit
cleanup_and_exit() {
    local exit_code=${1:-0}
    
    log_info "Cleaning up..." "$SCRIPT_NAME"
    
    # Stop any running progress indicators
    progress_spinner_stop
    
    # Remove temporary files
    rm -f /tmp/netutil_*.$$ 2>/dev/null
    
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

# Function to detect target networks
detect_networks() {
    echo "Detecting local networks..."
    
    networks=$(ip route | grep -E "192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\." | grep -v default | awk '{print $1}' | head -5)
    
    if [ -z "$networks" ]; then
        echo "No private networks found, using default ranges"
        networks="192.168.1.0/24 192.168.0.0/24 10.0.0.0/24"
    fi
    
    echo "Networks to scan: $networks"
    echo "$networks"
}

# Function to perform host discovery with progress
perform_host_discovery() {
    local networks="$1"
    local ping_results="$RESULTS_DIR/ping_results_${TIMESTAMP}.txt"
    
    echo "=== Phase 1: Host Discovery ==="
    
    # Estimate total hosts for progress tracking
    total_hosts=0
    for network in $networks; do
        # Simple estimation: /24 = 254 hosts, /16 = 65534, etc.
        case "$network" in
            */24) total_hosts=$((total_hosts + 254)) ;;
            */16) total_hosts=$((total_hosts + 65534)) ;;
            */8)  total_hosts=$((total_hosts + 16777214)) ;;
            *)    total_hosts=$((total_hosts + 254)) ;;
        esac
    done
    
    progress_spinner_start "Discovering hosts with fping"
    
    # Perform host discovery
    > "$ping_results"
    for network in $networks; do
        if [ "$PROGRESS_ACTIVE" != "true" ]; then
            return 130  # Cancelled
        fi
        
        log_command "fping -a -g $network" "$SCRIPT_NAME"
        fping -a -g "$network" 2>/dev/null >> "$ping_results"
        log_command_result "fping -a -g $network" $? "$SCRIPT_NAME"
    done
    
    progress_spinner_stop
    
    # Fallback to nmap if no hosts found
    if [ ! -s "$ping_results" ]; then
        echo "No hosts discovered with fping, trying nmap ping scan..."
        progress_spinner_start "Discovering hosts with nmap"
        
        for network in $networks; do
            if [ "$PROGRESS_ACTIVE" != "true" ]; then
                return 130
            fi
            
            nmap -sn "$network" | grep "Nmap scan report" | awk '{print $5}' >> "$ping_results"
        done
        
        progress_spinner_stop
    fi
    
    if [ ! -s "$ping_results" ]; then
        handle_error "No hosts discovered"
    fi
    
    host_count=$(wc -l < "$ping_results")
    success_message "Discovered $host_count hosts"
    
    echo "$ping_results"
}

# Function to perform port scanning with progress
perform_port_scan() {
    local ping_results="$1"
    local scan_type="$2"
    local nmap_results="$RESULTS_DIR/nmap_results_${TIMESTAMP}.txt"
    
    echo
    echo "=== Phase 2: Port Scanning ==="
    
    # Set scan parameters based on type
    case "$scan_type" in
        "quick")
            ports="--top-ports 100"
            scan_options="-T4"
            ;;
        "detailed")
            ports="--top-ports 1000"
            scan_options="-sS -O -sV -T3"
            ;;
        "comprehensive")
            ports="-p-"
            scan_options="-sS -O -sV -sC -T2"
            ;;
    esac
    
    # Count hosts for progress
    host_count=$(wc -l < "$ping_results")
    
    if [ "$host_count" -eq 0 ]; then
        echo "No hosts to scan"
        return 0
    fi
    
    progress_init "$host_count" "Port scanning hosts"
    
    # Scan each host
    current_host=0
    while read -r host; do
        if [ "$PROGRESS_ACTIVE" != "true" ]; then
            return 130
        fi
        
        if echo "$host" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' >/dev/null; then
            current_host=$((current_host + 1))
            
            log_command "nmap $scan_options $ports $host" "$SCRIPT_NAME"
            nmap_output=$(nmap $scan_options $ports "$host" 2>/dev/null)
            echo "$nmap_output" >> "$nmap_results"
            log_command_result "nmap $scan_options $ports $host" $? "$SCRIPT_NAME"
            
            progress_update "$current_host" "Scanning $host"
        fi
    done < "$ping_results"
    
    progress_complete "Port scanning complete"
    echo "$nmap_results"
}

# Function to perform host categorization
perform_host_categorization() {
    local ping_results="$1"
    local nmap_results="$2"
    
    echo
    echo "=== Phase 3: Host Categorization ==="
    
    local windows_hosts="$RESULTS_DIR/hosts_windows_${TIMESTAMP}.txt"
    local linux_hosts="$RESULTS_DIR/hosts_linux_${TIMESTAMP}.txt"
    local network_devices="$RESULTS_DIR/hosts_network_devices_${TIMESTAMP}.txt"
    local unknown_hosts="$RESULTS_DIR/hosts_unknown_${TIMESTAMP}.txt"
    
    # Initialize files
    > "$windows_hosts"
    > "$linux_hosts"
    > "$network_devices"
    > "$unknown_hosts"
    
    # Count hosts for progress
    host_count=$(wc -l < "$ping_results")
    progress_init "$host_count" "Categorizing hosts"
    
    current_host=0
    while read -r host; do
        if [ "$PROGRESS_ACTIVE" != "true" ]; then
            return 130
        fi
        
        if echo "$host" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' >/dev/null; then
            current_host=$((current_host + 1))
            
            # Extract host information from nmap results
            host_info=$(grep -A 20 "$host" "$nmap_results" 2>/dev/null || echo "")
            
            # Categorize based on detected services and OS
            if echo "$host_info" | grep -qi "microsoft\|windows\|3389/tcp\|445/tcp\|139/tcp"; then
                echo "$host" >> "$windows_hosts"
            elif echo "$host_info" | grep -qi "linux\|unix\|22/tcp.*ssh"; then
                echo "$host" >> "$linux_hosts"
            elif echo "$host_info" | grep -qi "cisco\|router\|switch\|snmp\|telnet\|23/tcp"; then
                echo "$host" >> "$network_devices"
            else
                echo "$host" >> "$unknown_hosts"
            fi
            
            progress_update "$current_host" "Categorizing $host"
        fi
    done < "$ping_results"
    
    progress_complete "Host categorization complete"
    
    # Show categorization summary
    echo "Host categorization results:"
    echo "  Windows hosts: $(wc -l < "$windows_hosts")"
    echo "  Linux hosts: $(wc -l < "$linux_hosts")"
    echo "  Network devices: $(wc -l < "$network_devices")"
    echo "  Unknown hosts: $(wc -l < "$unknown_hosts")"
}

# Function to generate comprehensive report
generate_report() {
    local ping_results="$1"
    local nmap_results="$2"
    local report_file="$RESULTS_DIR/enhanced_enum_report_${TIMESTAMP}.txt"
    
    echo
    echo "=== Generating Report ==="
    
    progress_spinner_start "Generating comprehensive report"
    
    cat > "$report_file" << EOF
=== Enhanced Network Enumeration Report ===
Scan time: $(date)
Scan type: $SCAN_TYPE
Target: $TARGET
Script: $SCRIPT_NAME v$SCRIPT_VERSION

--- SUMMARY ---
Total hosts discovered: $(wc -l < "$ping_results")
Windows hosts: $(wc -l < "$RESULTS_DIR/hosts_windows_${TIMESTAMP}.txt")
Linux hosts: $(wc -l < "$RESULTS_DIR/hosts_linux_${TIMESTAMP}.txt")
Network devices: $(wc -l < "$RESULTS_DIR/hosts_network_devices_${TIMESTAMP}.txt")
Unknown hosts: $(wc -l < "$RESULTS_DIR/hosts_unknown_${TIMESTAMP}.txt")

--- DISCOVERED HOSTS ---
EOF
    
    cat "$ping_results" >> "$report_file"
    
    echo "" >> "$report_file"
    echo "--- DETAILED SCAN RESULTS ---" >> "$report_file"
    cat "$nmap_results" >> "$report_file"
    
    progress_spinner_stop
    
    success_message "Report generated: $report_file"
    echo "Report file: $report_file"
}

# Function to run interactive mode
run_interactive_mode() {
    echo "=== Enhanced Network Enumeration ==="
    echo
    
    # Get target if not specified
    if [ -z "$TARGET" ]; then
        echo "Target selection:"
        echo "1. Auto-detect local networks"
        echo "2. Custom IP range"
        echo "3. Single IP address"
        echo "4. Host file"
        
        choice=$(get_validated_input "Select target type (1-4)" "validate_numeric_choice 1 4")
        
        case "$choice" in
            1)
                TARGET=$(detect_networks)
                ;;
            2)
                TARGET=$(get_validated_input "Enter IP range (e.g., 192.168.1.0/24)" "validate_ip_range")
                ;;
            3)
                TARGET=$(get_validated_input "Enter IP address" "validate_ip_address")
                ;;
            4)
                TARGET=$(select_host_file)
                if [ -n "$TARGET" ]; then
                    TARGET="-iL $TARGET"
                fi
                ;;
        esac
    fi
    
    # Get scan type if not specified
    if [ -z "$SCAN_TYPE" ]; then
        echo
        echo "Scan type selection:"
        echo "1. Quick scan (fast, basic ports)"
        echo "2. Detailed scan (standard enumeration)"
        echo "3. Comprehensive scan (all ports, full detection)"
        
        choice=$(get_validated_input "Select scan type (1-3)" "validate_numeric_choice 1 3")
        
        case "$choice" in
            1) SCAN_TYPE="quick" ;;
            2) SCAN_TYPE="detailed" ;;
            3) SCAN_TYPE="comprehensive" ;;
        esac
    fi
    
    success_message "Target: $TARGET"
    success_message "Scan type: $SCAN_TYPE"
    
    if ! confirm_action "Start enumeration?"; then
        echo "Operation cancelled"
        cleanup_and_exit 0
    fi
}

# Function to get validated input wrapper
get_validated_input() {
    local prompt="$1"
    local validation_function="$2"
    
    if result=$(prompt_and_validate "$prompt" "$validation_function" 3); then
        echo "$result"
        return 0
    else
        handle_error "Failed to get valid input for: $prompt"
    fi
}

# Function to run main enumeration logic
run_enumeration() {
    local start_time=$(date +%s)
    
    log_info "Starting enhanced enumeration: $TARGET ($SCAN_TYPE)" "$SCRIPT_NAME"
    
    # Phase 1: Host Discovery
    ping_results=$(perform_host_discovery "$TARGET")
    if [ $? -ne 0 ]; then
        handle_error "Host discovery failed or was cancelled"
    fi
    
    # Phase 2: Port Scanning
    nmap_results=$(perform_port_scan "$ping_results" "$SCAN_TYPE")
    if [ $? -ne 0 ]; then
        handle_error "Port scanning failed or was cancelled"
    fi
    
    # Phase 3: Host Categorization
    perform_host_categorization "$ping_results" "$nmap_results"
    if [ $? -ne 0 ]; then
        handle_error "Host categorization failed or was cancelled"
    fi
    
    # Phase 4: Report Generation
    generate_report "$ping_results" "$nmap_results"
    
    local end_time=$(date +%s)
    show_operation_summary "Enhanced Network Enumeration" "$start_time" "$end_time"
    
    success_message "Enhanced enumeration completed successfully!"
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    # Initialize variables
    TARGET=""
    SCAN_TYPE=""
    
    # Parse command line arguments
    parse_arguments "$@"
    
    # Initialize script
    initialize_script "$@"
    
    # Run appropriate mode
    if [ -z "$TARGET" ] || [ -z "$SCAN_TYPE" ]; then
        run_interactive_mode
    fi
    
    # Run enumeration
    run_enumeration
    
    # Clean exit
    cleanup_and_exit 0
}

# Only run main if script is executed directly (not sourced)
if [ "${0##*/}" = "network_enum_enhanced.sh" ]; then
    main "$@"
fi