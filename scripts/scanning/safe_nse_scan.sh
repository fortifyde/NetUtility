#!/bin/sh

# Source shared utility functions
# shellcheck source=../common/utils.sh
. "$(dirname "$0")/../common/utils.sh"
. "$(dirname "$0")/../common/colors.sh" 2>/dev/null || true
. "$(dirname "$0")/../common/logging.sh"
. "$(dirname "$0")/../common/validation.sh"
SCRIPT_NAME="$(basename "$0")"

echo "=== Safe NSE Service Enumeration Scan ==="
log_info "=== Script started ===" "$SCRIPT_NAME"
echo >&2
echo "ℹ️  This script uses SAFE NSE scripts for service enumeration"
echo "ℹ️  These scripts:"
echo "    - Gather service information without exploitation"
echo "    - Are non-intrusive and safe for production systems"
echo "    - Do NOT attempt vulnerability verification"
echo "    - Generate minimal network traffic"
echo >&2
echo "✓  Safe for use in:"
echo "    - Production environments (with authorization)"
echo "    - Network inventory and documentation"
echo "    - Service discovery and mapping"
echo "    - Baseline security assessments"
echo >&2

RESULTS_DIR="${NETUTIL_WORKDIR:-$HOME}/port_and_security_scans"
mkdir -p "$RESULTS_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)

targets=$(select_target)
if [ -z "$targets" ]; then
    log_error "No target selected" "$SCRIPT_NAME"
    error_message "No target selected"
    exit 1
fi

success_message "Selected target: $targets"
log_info "Target selected: $targets" "$SCRIPT_NAME"

echo "Scan intensity:"
echo "1. Quick scan (Top 1000 ports)"
echo "2. Comprehensive scan (All 65535 ports)"
echo "3. Custom port range"

echo >&2
intensity=$(prompt_for_choice "Select scan intensity" 1 3)

case $intensity in
    1)
        ports="--top-ports 1000"
        scan_type="quick"
        ;;
    2)
        ports="-p-"
        scan_type="comprehensive"
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

log_info "Scan type: $scan_type, ports: $ports" "$SCRIPT_NAME"

SCAN_RESULTS="$RESULTS_DIR/service_scan_${scan_type}_${TIMESTAMP}.txt"
NSE_RESULTS="$RESULTS_DIR/nse_enum_${TIMESTAMP}.txt"
REPORT_FILE="$RESULTS_DIR/service_report_${TIMESTAMP}.txt"

echo "Starting safe service enumeration scan..."
echo "Results will be saved to: $RESULTS_DIR"
echo >&2

{
    echo "=== Safe NSE Service Enumeration Report ==="
    echo "Scan time: $(date)"
    echo "Targets: $targets"
    echo "Scan type: $scan_type"
    echo "Ports: $ports"
    echo "Note: Using safe NSE scripts (non-intrusive service enumeration)"
    echo >&2
} > "$REPORT_FILE"

echo "Phase 1: Deep port scan with service detection..."
echo "Command: nmap -sS -sV -O $ports $targets"

log_debug "Phase 1 nmap: nmap -sS -sV -O $ports $targets -oN $SCAN_RESULTS" "$SCRIPT_NAME"
# shellcheck disable=SC2086
nmap -sS -sV -O $ports $targets -oN "$SCAN_RESULTS"

echo "Phase 2: Safe NSE service enumeration..."
echo "Running safe NSE enumeration scripts..."

log_debug "Phase 2 nmap: nmap --script 'safe and discovery' $targets -oN $NSE_RESULTS" "$SCRIPT_NAME"
# shellcheck disable=SC2086
nmap --script "safe and discovery and not (brute or dos or intrusive)" $targets -oN "$NSE_RESULTS"

echo "Phase 3: Service information extraction..."

{
    echo "--- SERVICE DETECTION ---"
    echo >&2
    grep -A 50 "PORT.*STATE.*SERVICE" "$SCAN_RESULTS"
    echo >&2
    echo "--- OS DETECTION ---"
    echo >&2
    grep -A 10 "OS details" "$SCAN_RESULTS"
    echo >&2
    echo "--- NSE ENUMERATION RESULTS ---"
    echo >&2
    cat "$NSE_RESULTS"
    echo >&2
} >> "$REPORT_FILE"

echo "Phase 4: Targeted safe NSE scripts based on detected services..."

detected_services=$(grep "open" "$SCAN_RESULTS" | grep -E "http|https|ssh|ftp|smb|mysql|postgres|mssql|vnc|rdp" | head -20)

if echo "$detected_services" | grep -q "80/tcp\|443/tcp\|8080/tcp"; then
    echo "Running HTTP service enumeration..."
    # shellcheck disable=SC2086
    nmap --script "http-headers,http-title,http-server-header,http-robots.txt,http-methods,http-security-headers" $targets >> "$REPORT_FILE"
fi

if echo "$detected_services" | grep -q "22/tcp.*ssh"; then
    echo "Running SSH service enumeration..."
    # shellcheck disable=SC2086
    nmap --script "ssh-hostkey,ssh2-enum-algos,ssh-auth-methods,banner" $targets >> "$REPORT_FILE"
fi

if echo "$detected_services" | grep -q "445/tcp\|139/tcp"; then
    echo "Running SMB service enumeration..."
    # shellcheck disable=SC2086
    nmap --script "smb-os-discovery,smb-protocols,smb-security-mode,smb2-capabilities" $targets >> "$REPORT_FILE"
fi

if echo "$detected_services" | grep -q "3306/tcp.*mysql"; then
    echo "Running MySQL service enumeration..."
    # shellcheck disable=SC2086
    nmap --script "mysql-info,banner" $targets >> "$REPORT_FILE"
fi

if echo "$detected_services" | grep -q "1433/tcp.*mssql"; then
    echo "Running MSSQL service enumeration..."
    # shellcheck disable=SC2086
    nmap --script "ms-sql-info,banner" $targets >> "$REPORT_FILE"
fi

if echo "$detected_services" | grep -q "21/tcp.*ftp"; then
    echo "Running FTP service enumeration..."
    # shellcheck disable=SC2086
    nmap --script "ftp-anon,ftp-syst,banner" $targets >> "$REPORT_FILE"
fi

echo "Phase 5: SSL/TLS information gathering..."
if echo "$detected_services" | grep -q "443/tcp\|ssl\|tls"; then
    echo "Gathering SSL/TLS certificate and cipher information..."
    # shellcheck disable=SC2086
    nmap --script "ssl-cert,ssl-enum-ciphers,ssl-date" $targets >> "$REPORT_FILE"
fi

echo "Phase 6: Service inventory and classification..."

service_count=$(grep -c "open" "$SCAN_RESULTS" 2>/dev/null || echo "0")

{
    echo "--- SERVICE INVENTORY ---"
    echo >&2

    echo "Discovered Services:"
    echo "  Total open ports: $service_count"
    echo >&2

    if echo "$detected_services" | grep -q "http\|https"; then
        echo "Web Services:"
        grep -E "80/tcp|443/tcp|8080/tcp|8443/tcp" "$SCAN_RESULTS" | grep "open" 2>/dev/null || echo "  None detected"
        echo >&2
    fi

    if echo "$detected_services" | grep -q "ssh\|telnet"; then
        echo "Remote Access Services:"
        grep -E "22/tcp|23/tcp|3389/tcp" "$SCAN_RESULTS" | grep "open" 2>/dev/null || echo "  None detected"
        echo >&2
    fi

    if echo "$detected_services" | grep -q "smb"; then
        echo "File Sharing Services:"
        grep -E "139/tcp|445/tcp|21/tcp" "$SCAN_RESULTS" | grep "open" 2>/dev/null || echo "  None detected"
        echo >&2
    fi

    if echo "$detected_services" | grep -q "mysql\|postgres\|mssql"; then
        echo "Database Services:"
        grep -E "3306/tcp|5432/tcp|1433/tcp" "$SCAN_RESULTS" | grep "open" 2>/dev/null || echo "  None detected"
        echo >&2
    fi

    echo "--- PROTOCOL ANALYSIS ---"
    echo >&2

    if grep -q "ssl-enum-ciphers" "$NSE_RESULTS"; then
        echo "SSL/TLS Configuration:"
        grep -A 10 "TLSv" "$NSE_RESULTS" | head -20 2>/dev/null || echo "  No SSL/TLS services detected"
        echo >&2
    fi

    if grep -q "ssh2-enum-algos" "$NSE_RESULTS"; then
        echo "SSH Algorithm Support:"
        grep -A 5 "encryption_algorithms" "$NSE_RESULTS" | head -10 2>/dev/null || echo "  SSH details not available"
        echo >&2
    fi

    if grep -q "smb-protocols" "$NSE_RESULTS"; then
        echo "SMB Protocol Versions:"
        grep -A 3 "Protocol" "$NSE_RESULTS" | head -10 2>/dev/null || echo "  SMB protocol info not available"
        echo >&2
    fi

    echo "--- CERTIFICATE INFORMATION ---"
    echo >&2

    if grep -q "ssl-cert" "$NSE_RESULTS"; then
        echo "SSL/TLS Certificates:"
        grep -A 15 "Subject:" "$NSE_RESULTS" | head -25 2>/dev/null || echo "  No certificate information available"
        echo >&2
    fi

    echo "--- AUTHENTICATION METHODS ---"
    echo >&2

    if grep -q "ssh-auth-methods" "$NSE_RESULTS"; then
        echo "SSH Authentication:"
        grep -A 3 "ssh-auth-methods" "$NSE_RESULTS" 2>/dev/null || echo "  SSH auth methods not detected"
        echo >&2
    fi

    if grep -q "ftp-anon" "$NSE_RESULTS"; then
        echo "FTP Anonymous Access:"
        if grep -q "Anonymous FTP login allowed" "$NSE_RESULTS"; then
            echo "  WARNING: Anonymous FTP access is enabled"
        else
            echo "  Anonymous FTP access is disabled"
        fi
        echo >&2
    fi

    echo >&2
} >> "$REPORT_FILE"

log_info "Scan complete. Open services: $service_count. Results: $RESULTS_DIR" "$SCRIPT_NAME"
echo "Service enumeration scan complete!"
echo >&2
echo "Files created:"
echo "  Port scan results: $SCAN_RESULTS"
echo "  NSE enumeration results: $NSE_RESULTS"
echo "  Service report: $REPORT_FILE"
echo >&2
echo "Summary:"
echo "  Total services discovered: $service_count"

echo >&2
echo "--- SERVICE REPORT ---"
cat "$REPORT_FILE"
