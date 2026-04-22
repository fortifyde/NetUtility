#!/bin/sh

# Full Port Scan Script
# Performs comprehensive port scanning with configurable intensity
# Saves results in multiple formats for further analysis

# Source shared utility functions
# shellcheck source=../common/utils.sh
. "$(dirname "$0")/../common/utils.sh"
. "$(dirname "$0")/../common/colors.sh" 2>/dev/null || true
. "$(dirname "$0")/../common/logging.sh"
. "$(dirname "$0")/../common/validation.sh"
SCRIPT_NAME="$(basename "$0")"

echo "=========================================="
echo "Full Port Scan"
echo "=========================================="
log_info "=== Script started ===" "$SCRIPT_NAME"
echo >&2
echo "This script performs comprehensive port scanning with:"
echo "  - Configurable scan intensity (quick/full/custom)"
echo "  - Service version detection"
echo "  - Multiple output formats (normal/XML/greppable)"
echo "  - Organized session-based output"
echo >&2

# Setup results directory
RESULTS_BASE="${NETUTIL_WORKDIR:-$HOME}/port_and_security_scans"
mkdir -p "$RESULTS_BASE"

# Create timestamped session directory
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SESSION_DIR="$RESULTS_BASE/full_scan_$TIMESTAMP"
mkdir -p "$SESSION_DIR"

# Target selection
targets=$(select_target)
if [ -z "$targets" ]; then
    log_error "No target selected" "$SCRIPT_NAME"
    error_message "No target selected"
    exit 1
fi

success_message "Selected target: $targets"
log_info "Target selected: $targets" "$SCRIPT_NAME"
echo >&2

# Scan intensity selection
echo "Scan intensity:" >&2
echo "1. Quick scan (Top 1000 ports)" >&2
echo "2. Full scan (All 65535 ports)" >&2
echo "3. Custom port range" >&2
echo >&2
intensity=$(prompt_for_choice "Select scan intensity" 1 3)

case $intensity in
    1)
        ports="--top-ports 1000"
        scan_type="quick"
        ;;
    2)
        ports="-p-"
        scan_type="full"
        ;;
    3)
        custom_ports=$(get_validated_input "Enter port range (e.g., 1-1000 or 80,443,8080)" validate_port_range "")
        ports="-p $custom_ports"
        scan_type="custom"
        ;;
    *)
        warning_message "Invalid option, using quick scan"
        ports="--top-ports 1000"
        scan_type="quick"
        ;;
esac

success_message "Scan type: $scan_type"
log_info "Scan type: $scan_type, ports: $ports" "$SCRIPT_NAME"
echo >&2

# Define output file paths
SCAN_BASE="$SESSION_DIR/scan_results"
REPORT_FILE="$SESSION_DIR/port_scan_report.txt"

# Display scan information
echo "Session directory: $SESSION_DIR"
echo >&2
echo "Starting port scan..."
echo "Command: nmap -sS -sV -T4 $ports $targets -oA $SCAN_BASE"
echo >&2

# Execute nmap scan with all output formats
# shellcheck disable=SC2086
log_debug "Executing: nmap -sS -sV -T4 $ports $targets -oA $SCAN_BASE" "$SCRIPT_NAME"
if ! nmap -sS -sV -T4 $ports $targets -oA "$SCAN_BASE"; then
    log_error "nmap scan failed for target: $targets" "$SCRIPT_NAME"
    error_message "Nmap scan failed"
    exit 1
fi

success_message "Port scan completed"
echo >&2

# Generate comprehensive report
echo "Generating comprehensive report..."

{
    echo "=========================================="
    echo "Full Port Scan Report"
    echo "=========================================="
    echo >&2
    echo "Scan Information:"
    echo "  Scan time: $(date)"
    echo "  Targets: $targets"
    echo "  Scan type: $scan_type"
    echo "  Ports: $ports"
    echo "  Session directory: $SESSION_DIR"
    echo >&2
    echo "=========================================="
    echo "Open Ports Summary"
    echo "=========================================="
    echo >&2

    # Extract and display open ports
    if [ -f "$SCAN_BASE.nmap" ]; then
        grep "^[0-9]" "$SCAN_BASE.nmap" | grep "open"
    else
        echo "No scan results found"
    fi

    echo >&2
    echo "=========================================="
    echo "Service Detection Summary"
    echo "=========================================="
    echo >&2

    # Extract service information
    if [ -f "$SCAN_BASE.nmap" ]; then
        grep -A 1 "PORT.*STATE.*SERVICE" "$SCAN_BASE.nmap" | tail -n +2
    fi

    echo >&2
    echo "=========================================="
    echo "Output Files"
    echo "=========================================="
    echo >&2
    echo "All scan outputs are located in: $SESSION_DIR"
    echo >&2
    echo "  scan_results.nmap    - Normal format (human-readable)"
    echo "  scan_results.xml     - XML format (for tools)"
    echo "  scan_results.gnmap   - Greppable format (for parsing)"
    echo "  port_scan_report.txt - This summary report"
    echo >&2

} > "$REPORT_FILE"

success_message "Report generated"
echo >&2

# Display results summary
echo "=========================================="
echo "Scan Complete"
echo "=========================================="
echo >&2

# Show open ports count
open_ports_count=$(grep -c "open" "$SCAN_BASE.nmap" 2>/dev/null || echo "0")
echo "Open ports found: $open_ports_count"
echo >&2

echo "Files created:"
echo "  Report:           $REPORT_FILE"
echo "  Normal output:    $SCAN_BASE.nmap"
echo "  XML output:       $SCAN_BASE.xml"
echo "  Greppable output: $SCAN_BASE.gnmap"
echo >&2

# Display top services if any found
if [ "$open_ports_count" -gt 0 ]; then
    echo "Top discovered services:"
    grep "^[0-9]" "$SCAN_BASE.nmap" | grep "open" | head -10
    echo >&2
fi

log_info "Scan complete. Open ports: $open_ports_count. Session: $SESSION_DIR" "$SCRIPT_NAME"
success_message "Full port scan session completed: $SESSION_DIR"
