#!/bin/sh
#
# Network Config Gatherer
# Extracts running configurations and compliance data from network devices
# Supports: Cisco IOS, Cisco Nexus, HP Comware, HP ProVision, HP Aruba
# POSIX-compliant for maximum portability
#

set -e

# Source common utilities
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMMON_DIR="${SCRIPT_DIR}/../common"
if [ -f "${COMMON_DIR}/utils.sh" ]; then
    . "${COMMON_DIR}/utils.sh"
else
    echo "ERROR: Cannot find common utilities" >&2
    exit 1
fi

# Global variables
VERSION="1.0.0"
NETUTIL_WORKDIR="${NETUTIL_WORKDIR:-$HOME}"
SESSION_DIR=""
SESSION_ID=""
COMMANDS_DIR="${SCRIPT_DIR}/commands"
FAILURES_FILE=""
DRY_RUN=0
CONCURRENCY=5
CRED_MODE="common"
CRED_FILE=""
COMMON_USER=""
COMMON_PASS=""
PROCESSED_COUNT=0
SUCCESS_COUNT=0
FAILURE_COUNT=0

# Color codes
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' CYAN='' NC=''
fi

# Print functions (all output to stderr for TUI compatibility)
print_header() {
    printf "${BLUE}===================================================${NC}\n" >&2
    printf "${BLUE}  Network Config Gatherer v%s${NC}\n" "$VERSION" >&2
    printf "${BLUE}===================================================${NC}\n\n" >&2
}

print_success() {
    printf "${GREEN}✓ %s${NC}\n" "$1" >&2
}

print_error() {
    printf "${RED}✗ ERROR: %s${NC}\n" "$1" >&2
}

print_warning() {
    printf "${YELLOW}⚠ WARNING: %s${NC}\n" "$1" >&2
}

print_info() {
    printf "${BLUE}ℹ %s${NC}\n" "$1" >&2
}

print_step() {
    printf "${CYAN}→ %s${NC}\n" "$1" >&2
}

# Print help
print_help() {
    cat >&2 << EOF
Network Config Gatherer v${VERSION}

Usage: $0 [OPTIONS]

OPTIONS:
    --dry-run           Test connectivity only, don't extract configs
    --concurrency N     Max parallel connections (default: 5)
    --cred-mode MODE    Credential mode: common|file|interactive (default: common)
    --cred-file FILE    Path to credentials file (IP,username,password)
    --targets LIST      Comma-separated IP list or file path
    -h, --help          Show this help message

EXAMPLES:
    # Interactive mode with common credentials
    $0

    # Dry-run to test connectivity
    $0 --dry-run

    # Use categorized host file from discovery
    $0 --targets /path/to/network_devices.txt

    # Process specific IPs with higher concurrency
    $0 --targets "192.168.1.1,192.168.1.2,192.168.1.3" --concurrency 10

    # Use credentials file
    $0 --cred-mode file --cred-file creds.csv

OUTPUT:
    Results saved to: \${NETUTIL_WORKDIR}/configs/gather_YYYYMMDD_HHMMSS/

    Per-device directories contain:
      - version.txt                  Version information
      - running_config.txt           Running configuration
      - running_config_all.txt       Running config with all defaults
      - startup_config.txt           Startup/saved configuration
      - compliance_commands.txt      Additional compliance data
      - metadata.txt                 Device metadata
      - connection.log               Connection log

SUPPORTED VENDORS:
    - Cisco IOS
    - Cisco Nexus (NX-OS)
    - HP Comware
    - HP ProVision
    - HP Aruba (ArubaOS-CX)
    - HP Aruba (ArubaOS-Switch)

EOF
}

# Initialize session directory
init_session() {
    SESSION_ID="gather_$(date +%Y%m%d_%H%M%S)"
    SESSION_DIR="${NETUTIL_WORKDIR}/configs/${SESSION_ID}"

    mkdir -p "$SESSION_DIR" || {
        print_error "Failed to create session directory: $SESSION_DIR"
        exit 1
    }

    FAILURES_FILE="${SESSION_DIR}/failures.txt"
    touch "$FAILURES_FILE"

    print_success "Session initialized: $SESSION_ID"
    print_info "Output directory: $SESSION_DIR"
}

# Clean output - remove ANSI codes, pagination prompts, command echoes
clean_output() {
    # Remove ANSI escape sequences
    sed 's/\x1b\[[0-9;]*m//g' | \
    # Remove carriage returns
    tr -d '\r' | \
    # Remove pagination prompts
    grep -v -- '--More--' | grep -v -- '---- More ----' | \
    # Remove lines with only prompts
    grep -v '^[A-Za-z0-9._-]*[#>]$' || true
}

# Try version detection commands in order with fallback
try_version_command() {
    device_ip="$1"
    username="$2"
    password="$3"

    # Try commands in priority order
    for cmd in "show version" "display version" "show system" "show system information"; do
        output=$(sshpass -p "$password" ssh -o ConnectTimeout=5 \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR \
            "$username@$device_ip" "$cmd" 2>/dev/null | clean_output)

        if [ -n "$output" ] && [ "$(echo "$output" | wc -l)" -gt 2 ]; then
            echo "$output"
            return 0
        fi
    done

    return 1
}

# Detect vendor and OS from version output
detect_vendor() {
    version_output="$1"

    # Cisco IOS
    if echo "$version_output" | grep -qi "Cisco IOS Software\|IOS (tm)\|Cisco Internetwork"; then
        echo "cisco_ios"
        return 0
    fi

    # Cisco Nexus
    if echo "$version_output" | grep -qi "NX-OS\|Nexus Operating System\|cisco Nexus"; then
        echo "cisco_nexus"
        return 0
    fi

    # HP Comware
    if echo "$version_output" | grep -qi "Comware Software\|HPE Comware\|HP Comware Platform"; then
        echo "hp_comware"
        return 0
    fi

    # HP ProVision
    if echo "$version_output" | grep -qi "ProVision\|HP J\|Image stamp"; then
        echo "hp_provision"
        return 0
    fi

    # HP Aruba CX
    if echo "$version_output" | grep -qi "ArubaOS-CX"; then
        echo "aruba_cx"
        return 0
    fi

    # HP Aruba Switch
    if echo "$version_output" | grep -qi "ArubaOS-Switch\|Aruba"; then
        echo "aruba_switch"
        return 0
    fi

    # Fallback to generic
    echo "generic"
    return 0
}

# Get terminal setup commands based on vendor
get_terminal_setup() {
    vendor="$1"

    case "$vendor" in
        cisco_ios|cisco_nexus)
            echo "terminal length 0"
            ;;
        hp_comware)
            echo "screen-length disable"
            ;;
        hp_provision|aruba_switch)
            echo "no page"
            ;;
        aruba_cx)
            echo "no paging"
            ;;
        *)
            echo ""
            ;;
    esac
}

# Execute command on device via SSH
exec_ssh_command() {
    device_ip="$1"
    username="$2"
    password="$3"
    command="$4"

    sshpass -p "$password" ssh -o ConnectTimeout=10 \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        "$username@$device_ip" "$command" 2>/dev/null | clean_output
}

# Load command file for vendor
load_vendor_commands() {
    vendor="$1"
    cmd_file="${COMMANDS_DIR}/${vendor}.cmds"

    if [ ! -f "$cmd_file" ]; then
        print_warning "Command file not found: $cmd_file, using generic"
        cmd_file="${COMMANDS_DIR}/generic.cmds"
    fi

    # Read commands, skip comments and blank lines
    grep -v '^#' "$cmd_file" | grep -v '^$' || true
}

# Process a single device
process_device() {
    device_ip="$1"
    username="$2"
    password="$3"
    device_dir="${SESSION_DIR}/device_${device_ip}"

    mkdir -p "$device_dir"

    log_file="${device_dir}/connection.log"
    metadata_file="${device_dir}/metadata.txt"

    echo "=== Connection Log for $device_ip ===" > "$log_file"
    echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')" >> "$log_file"
    echo "Username: $username" >> "$log_file"
    echo "" >> "$log_file"

    # Test connectivity
    print_step "Connecting to $device_ip..."

    if ! sshpass -p "$password" ssh -o ConnectTimeout=5 \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        "$username@$device_ip" "exit" 2>/dev/null; then

        print_error "Failed to connect to $device_ip"
        echo "$device_ip,connection_failed,Failed to establish SSH connection" >> "$FAILURES_FILE"
        echo "FAILURE: Connection failed" >> "$log_file"
        return 1
    fi

    echo "SUCCESS: Connection established" >> "$log_file"

    # Get version output with fallbacks
    print_step "Detecting vendor for $device_ip..."
    version_output=$(try_version_command "$device_ip" "$username" "$password")

    if [ -z "$version_output" ]; then
        print_error "Failed to get version info from $device_ip"
        echo "$device_ip,version_detection_failed,Could not retrieve version information" >> "$FAILURES_FILE"
        echo "FAILURE: Version detection failed" >> "$log_file"
        return 1
    fi

    # Save version output
    echo "$version_output" > "${device_dir}/version.txt"
    echo "SUCCESS: Version retrieved" >> "$log_file"

    # Detect vendor
    vendor=$(detect_vendor "$version_output")
    print_success "Detected vendor: $vendor for $device_ip"
    echo "Vendor: $vendor" >> "$log_file"

    # Write metadata
    echo "IP Address: $device_ip" > "$metadata_file"
    echo "Vendor/OS: $vendor" >> "$metadata_file"
    echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')" >> "$metadata_file"
    echo "Username: $username" >> "$metadata_file"
    echo "" >> "$metadata_file"

    # Extract hostname from version if possible
    hostname=$(echo "$version_output" | grep -i "hostname\|system name" | head -1 || echo "Unknown")
    echo "Hostname: $hostname" >> "$metadata_file"

    # If dry-run mode, stop here
    if [ "$DRY_RUN" -eq 1 ]; then
        print_success "Dry-run complete for $device_ip"
        return 0
    fi

    # Setup terminal
    terminal_cmd=$(get_terminal_setup "$vendor")
    if [ -n "$terminal_cmd" ]; then
        print_step "Configuring terminal for $device_ip..."
        exec_ssh_command "$device_ip" "$username" "$password" "$terminal_cmd" >/dev/null
    fi

    # Load vendor commands
    commands=$(load_vendor_commands "$vendor")

    if [ -z "$commands" ]; then
        print_warning "No commands found for vendor: $vendor"
        return 1
    fi

    # Process commands
    compliance_file="${device_dir}/compliance_commands.txt"
    echo "=== Compliance Commands Output for $device_ip ===" > "$compliance_file"
    echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')" >> "$compliance_file"
    echo "" >> "$compliance_file"

    echo "$commands" | while IFS= read -r line; do
        # Skip empty lines
        [ -z "$line" ] && continue

        # Check for special markers
        case "$line" in
            @VERSION*)
                cmd=$(echo "$line" | sed 's/@VERSION //')
                print_step "Executing: $cmd (already saved to version.txt)"
                continue
                ;;
            @RUNNING_CONFIG*)
                cmd=$(echo "$line" | sed 's/@RUNNING_CONFIG //')
                output_file="${device_dir}/running_config.txt"
                marker="RUNNING_CONFIG"
                ;;
            @RUNNING_CONFIG_ALL*)
                cmd=$(echo "$line" | sed 's/@RUNNING_CONFIG_ALL //')
                output_file="${device_dir}/running_config_all.txt"
                marker="RUNNING_CONFIG_ALL"
                ;;
            @STARTUP_CONFIG*)
                cmd=$(echo "$line" | sed 's/@STARTUP_CONFIG //')
                output_file="${device_dir}/startup_config.txt"
                marker="STARTUP_CONFIG"
                ;;
            *)
                cmd="$line"
                output_file="$compliance_file"
                marker="COMPLIANCE"
                ;;
        esac

        print_step "Executing: $cmd on $device_ip"

        # Execute command
        output=$(exec_ssh_command "$device_ip" "$username" "$password" "$cmd" 2>&1)

        if [ $? -eq 0 ] && [ -n "$output" ]; then
            if [ "$marker" = "COMPLIANCE" ]; then
                echo "=== Command: $cmd ===" >> "$compliance_file"
                echo "$output" >> "$compliance_file"
                echo "" >> "$compliance_file"
            else
                echo "$output" > "$output_file"
                print_success "Saved: $(basename "$output_file")"
            fi
            echo "SUCCESS: $cmd" >> "$log_file"
        else
            print_warning "Failed or empty output: $cmd"
            echo "FAILED: $cmd" >> "$log_file"
        fi
    done

    print_success "Completed extraction for $device_ip"
    return 0
}

# Generate summary report
generate_summary() {
    summary_file="${SESSION_DIR}/session_summary.txt"

    cat > "$summary_file" << EOF
==================================================
Network Config Gatherer - Session Summary
==================================================

Session Information:
  Session ID:        $SESSION_ID
  Start Time:        $(date '+%Y-%m-%d %H:%M:%S')
  Working Directory: $SESSION_DIR
  Mode:              $([ "$DRY_RUN" -eq 1 ] && echo "Dry-run" || echo "Full extraction")

Statistics:
  Total Devices:     $PROCESSED_COUNT
  Successful:        $SUCCESS_COUNT
  Failed:            $FAILURE_COUNT
  Success Rate:      $([ "$PROCESSED_COUNT" -gt 0 ] && echo "$((SUCCESS_COUNT * 100 / PROCESSED_COUNT))%" || echo "N/A")

EOF

    # Add vendor distribution if devices were processed
    if [ -d "$SESSION_DIR" ] && [ "$(find "$SESSION_DIR" -type d -name 'device_*' | wc -l)" -gt 0 ]; then
        echo "Vendor Distribution:" >> "$summary_file"
        find "$SESSION_DIR" -type d -name 'device_*' -exec cat {}/metadata.txt \; 2>/dev/null | \
            grep "Vendor/OS:" | sort | uniq -c | sed 's/^/  /' >> "$summary_file" || echo "  No vendor data available" >> "$summary_file"
        echo "" >> "$summary_file"
    fi

    # Add failed devices if any
    if [ "$FAILURE_COUNT" -gt 0 ] && [ -f "$FAILURES_FILE" ]; then
        echo "Failed Devices:" >> "$summary_file"
        cat "$FAILURES_FILE" | sed 's/^/  /' >> "$summary_file"
        echo "" >> "$summary_file"
    fi

    # Add storage information
    echo "Storage Information:" >> "$summary_file"
    echo "  Total Size:        $(du -sh "$SESSION_DIR" | cut -f1)" >> "$summary_file"
    echo "  Device Folders:    $(find "$SESSION_DIR" -type d -name 'device_*' | wc -l)" >> "$summary_file"
    echo "  Total Files:       $(find "$SESSION_DIR" -type f | wc -l)" >> "$summary_file"
    echo "" >> "$summary_file"

    echo "===================================================" >> "$summary_file"
    echo "End of Summary Report" >> "$summary_file"
    echo "===================================================" >> "$summary_file"

    print_success "Summary report generated: session_summary.txt"
}

# Generate retry script for failed devices
generate_retry_script() {
    if [ "$FAILURE_COUNT" -eq 0 ]; then
        return 0
    fi

    retry_script="${SESSION_DIR}/retry_failures.sh"

    cat > "$retry_script" << 'EOF'
#!/bin/sh
# Auto-generated retry script for failed devices
# Run this script to retry configuration extraction for devices that failed

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PARENT_DIR="$(dirname "$SCRIPT_DIR")"

EOF

    echo "# Failed devices from session: $SESSION_ID" >> "$retry_script"
    echo "FAILED_IPS=\"$(cut -d',' -f1 "$FAILURES_FILE" | tr '\n' ',' | sed 's/,$//')\"" >> "$retry_script"
    echo "" >> "$retry_script"

    cat >> "$retry_script" << 'EOF'
# Run the config gatherer with failed devices
"${PARENT_DIR}/../gather_network_configs.sh" --targets "$FAILED_IPS" "$@"
EOF

    chmod +x "$retry_script"
    print_info "Retry script generated: retry_failures.sh"
}

# Offer retry for failed devices
offer_retry() {
    if [ "$FAILURE_COUNT" -eq 0 ]; then
        return 0
    fi

    echo "" >&2
    print_warning "$FAILURE_COUNT device(s) failed during extraction"
    echo "Would you like to retry failed devices with different credentials? (y/n): " >&2
    read -r retry_response

    if [ "$retry_response" = "y" ] || [ "$retry_response" = "Y" ]; then
        print_info "Re-enter credentials for retry:"
        echo "Username: " >&2
        read -r new_user
        echo "Password: " >&2
        read -r new_pass
        echo "" >&2

        # Extract failed IPs
        failed_ips=$(cut -d',' -f1 "$FAILURES_FILE")

        print_info "Retrying $(echo "$failed_ips" | wc -l) failed device(s)..."
        echo "" >&2

        # Retry each failed device
        for ip in $failed_ips; do
            [ -z "$ip" ] && continue

            print_step "Retrying $ip..."
            if process_device "$ip" "$new_user" "$new_pass"; then
                SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
                FAILURE_COUNT=$((FAILURE_COUNT - 1))
            fi
        done

        print_success "Retry complete"
    fi
}

# Main execution
main() {
    print_header

    # Parse arguments
    MODE="extract"
    TARGETS=""

    while [ $# -gt 0 ]; do
        case "$1" in
            --dry-run)
                DRY_RUN=1
                MODE="dry-run"
                shift
                ;;
            --concurrency)
                CONCURRENCY="$2"
                shift 2
                ;;
            --cred-mode)
                CRED_MODE="$2"
                shift 2
                ;;
            --cred-file)
                CRED_FILE="$2"
                shift 2
                ;;
            --targets)
                TARGETS="$2"
                shift 2
                ;;
            -h|--help)
                print_help
                exit 0
                ;;
            *)
                shift
                ;;
        esac
    done

    # Initialize session
    init_session

    # Get targets if not provided
    if [ -z "$TARGETS" ]; then
        print_info "Select target devices:"
        TARGETS=$(select_config_targets)

        if [ -z "$TARGETS" ]; then
            print_error "No targets selected"
            exit 1
        fi
    fi

    print_success "Targets selected"

    # Get credentials based on mode
    if [ "$CRED_MODE" = "common" ]; then
        print_info "Enter common credentials for all devices:"
        echo "Username: " >&2
        read -r COMMON_USER
        echo "Password: " >&2
        read -r COMMON_PASS
        echo "" >&2
    fi

    # Build device list
    if echo "$TARGETS" | grep -q "^-iL "; then
        # Host file
        host_file=$(echo "$TARGETS" | sed 's/^-iL //')
        device_list=$(cat "$host_file" | grep -v '^#' | grep -v '^$')
    else
        # Direct IP or range (simplified - just handle single IP for now)
        device_list="$TARGETS"
    fi

    total_devices=$(echo "$device_list" | wc -l)
    print_info "Processing $total_devices device(s) in $MODE mode with concurrency: $CONCURRENCY"
    echo "" >&2

    # Process devices
    for ip in $device_list; do
        [ -z "$ip" ] && continue

        PROCESSED_COUNT=$((PROCESSED_COUNT + 1))

        if process_device "$ip" "$COMMON_USER" "$COMMON_PASS"; then
            SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        else
            FAILURE_COUNT=$((FAILURE_COUNT + 1))
        fi

        echo "" >&2
    done

    # Generate summary
    echo "" >&2
    generate_summary
    generate_retry_script

    # Display summary
    print_header
    print_success "Processing Complete!"
    echo "" >&2
    printf "Total Devices:    %d\n" "$total_devices" >&2
    printf "Successful:       %d\n" "$SUCCESS_COUNT" >&2
    printf "Failed:           %d\n" "$FAILURE_COUNT" >&2
    echo "" >&2
    print_info "Results saved to: $SESSION_DIR"

    if [ "$FAILURE_COUNT" -gt 0 ]; then
        print_warning "Some devices failed. Check failures.txt for details."

        # Offer retry
        offer_retry

        # Regenerate summary after retry
        if [ "$FAILURE_COUNT" -gt 0 ]; then
            generate_summary
        fi
    fi

    echo "" >&2
    print_success "Session complete. Review session_summary.txt for full details."
}

# Run main
main "$@"
