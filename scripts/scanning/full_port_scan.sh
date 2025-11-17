#!/bin/sh

# Full Port Scan Script
# Performs comprehensive port scanning with configurable intensity
# Saves results in multiple formats for further analysis

# Source shared utility functions
# shellcheck source=../common/utils.sh
. "$(dirname "$0")/../common/utils.sh"

echo "=========================================="
echo "Full Port Scan"
echo "=========================================="
echo
echo "This script performs comprehensive port scanning with:"
echo "  - Configurable scan intensity (quick/full/custom)"
echo "  - Service version detection"
echo "  - Multiple output formats (normal/XML/greppable)"
echo "  - Organized session-based output"
echo

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
    error_message "No target selected"
    exit 1
fi

success_message "Selected target: $targets"
echo

# Scan intensity selection
echo "Scan intensity:"
echo "1. Quick scan (Top 1000 ports)"
echo "2. Full scan (All 65535 ports)"
echo "3. Custom port range"
echo

echo "Select scan intensity (1-3): " >&2
read -r intensity

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
        echo "Enter port range (e.g., 1-1000 or 80,443,8080): " >&2
        read -r custom_ports
        if [ -z "$custom_ports" ]; then
            error_message "No port range specified"
            exit 1
        fi
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
echo

# Define output file paths
SCAN_BASE="$SESSION_DIR/scan_results"
REPORT_FILE="$SESSION_DIR/port_scan_report.txt"

# Display scan information
echo "Session directory: $SESSION_DIR"
echo
echo "Starting port scan..."
echo "Command: nmap -sS -sV -T4 $ports $targets -oA $SCAN_BASE"
echo

# Execute nmap scan with all output formats
# shellcheck disable=SC2086
if ! nmap -sS -sV -T4 $ports $targets -oA "$SCAN_BASE"; then
    error_message "Nmap scan failed"
    exit 1
fi

success_message "Port scan completed"
echo

# Generate comprehensive report
echo "Generating comprehensive report..."

{
    echo "=========================================="
    echo "Full Port Scan Report"
    echo "=========================================="
    echo
    echo "Scan Information:"
    echo "  Scan time: $(date)"
    echo "  Targets: $targets"
    echo "  Scan type: $scan_type"
    echo "  Ports: $ports"
    echo "  Session directory: $SESSION_DIR"
    echo
    echo "=========================================="
    echo "Open Ports Summary"
    echo "=========================================="
    echo

    # Extract and display open ports
    if [ -f "$SCAN_BASE.nmap" ]; then
        grep "^[0-9]" "$SCAN_BASE.nmap" | grep "open"
    else
        echo "No scan results found"
    fi

    echo
    echo "=========================================="
    echo "Service Detection Summary"
    echo "=========================================="
    echo

    # Extract service information
    if [ -f "$SCAN_BASE.nmap" ]; then
        grep -A 1 "PORT.*STATE.*SERVICE" "$SCAN_BASE.nmap" | tail -n +2
    fi

    echo
    echo "=========================================="
    echo "Output Files"
    echo "=========================================="
    echo
    echo "All scan outputs are located in: $SESSION_DIR"
    echo
    echo "  scan_results.nmap    - Normal format (human-readable)"
    echo "  scan_results.xml     - XML format (for tools)"
    echo "  scan_results.gnmap   - Greppable format (for parsing)"
    echo "  port_scan_report.txt - This summary report"
    echo

} > "$REPORT_FILE"

success_message "Report generated"
echo

# Display results summary
echo "=========================================="
echo "Scan Complete"
echo "=========================================="
echo

# Show open ports count
open_ports_count=$(grep -c "open" "$SCAN_BASE.nmap" 2>/dev/null || echo "0")
echo "Open ports found: $open_ports_count"
echo

echo "Files created:"
echo "  Report:           $REPORT_FILE"
echo "  Normal output:    $SCAN_BASE.nmap"
echo "  XML output:       $SCAN_BASE.xml"
echo "  Greppable output: $SCAN_BASE.gnmap"
echo

# Display top services if any found
if [ "$open_ports_count" -gt 0 ]; then
    echo "Top discovered services:"
    grep "^[0-9]" "$SCAN_BASE.nmap" | grep "open" | head -10
    echo
fi

success_message "Full port scan session completed: $SESSION_DIR"
