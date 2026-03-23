#!/bin/sh

# Source shared utility functions
# shellcheck source=../common/utils.sh
. "$(dirname "$0")/../common/utils.sh"
. "$(dirname "$0")/../common/colors.sh" 2>/dev/null || true

echo "=== Deep Port Scan with NSE Vulnerability Detection ==="
echo >&2
echo "⚠️  WARNING: This script uses NSE vulnerability scripts (vuln category)"
echo "⚠️  These scripts may:"
echo "    - Attempt exploit verification"
echo "    - Cause service disruptions or crashes"
echo "    - Trigger intrusion detection systems"
echo "    - Generate significant network traffic"
echo >&2
echo "⚠️  Only run this scan:"
echo "    - On systems you own or have explicit authorization to test"
echo "    - During authorized penetration testing"
echo "    - In isolated test environments"
echo >&2

RESULTS_DIR="${NETUTIL_WORKDIR:-$HOME}/port_and_security_scans"
mkdir -p "$RESULTS_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)

targets=$(select_target)
if [ -z "$targets" ]; then
    error_message "No target selected"
    exit 1
fi

success_message "Selected target: $targets"

if ! confirm_action "Do you want to proceed with the vulnerability scan?"; then
    echo "Scan cancelled by user"
    exit 0
fi

echo "Scan intensity:"
echo "1. Quick scan (Top 1000 ports)"
echo "2. Comprehensive scan (All 65535 ports)"
echo "3. Custom port range"

echo >&2
if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
    printf "%sSelect scan intensity (1-3): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
else
    printf "Select scan intensity (1-3): \n" >&2
fi
read -r intensity

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
        echo >&2
        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
            printf "%sEnter port range (e.g., 1-1000 or 80,443,8080): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
        else
            printf "Enter port range (e.g., 1-1000 or 80,443,8080): \n" >&2
        fi
        read -r custom_ports
        ports="-p $custom_ports"
        scan_type="custom"
        ;;
    *)
        warning_message "Invalid option, using quick scan"
        ports="--top-ports 1000"
        scan_type="quick"
        ;;
esac

SCAN_RESULTS="$RESULTS_DIR/deep_scan_${scan_type}_${TIMESTAMP}.txt"
NSE_RESULTS="$RESULTS_DIR/nse_vuln_scan_${TIMESTAMP}.txt"
REPORT_FILE="$RESULTS_DIR/vulnerability_report_${TIMESTAMP}.txt"

echo "Starting deep port scan with NSE vulnerability detection..."
echo "Results will be saved to: $RESULTS_DIR"
echo >&2

{
    echo "=== Deep Port Scan with NSE Vulnerability Detection Report ==="
    echo "Scan time: $(date)"
    echo "Targets: $targets"
    echo "Scan type: $scan_type"
    echo "Ports: $ports"
    echo "Note: Using vuln category NSE scripts (excludes brute-force and DoS)"
    echo >&2
} > "$REPORT_FILE"

echo "Phase 1: Deep port scan with service detection..."
echo "Command: nmap -sS -sV -O $ports $targets"

# shellcheck disable=SC2086
nmap -sS -sV -O $ports $targets -oN "$SCAN_RESULTS"

echo "Phase 2: NSE vulnerability scanning..."
echo "Running NSE vuln scripts (excludes brute-force and DoS)..."

# shellcheck disable=SC2086
nmap --script "vuln and not brute and not dos" $targets -oN "$NSE_RESULTS"

echo "Phase 3: Service enumeration..."

{
    echo "--- SERVICE DETECTION ---"
    echo >&2
    grep -A 50 "PORT.*STATE.*SERVICE" "$SCAN_RESULTS"
    echo >&2
    echo "--- OS DETECTION ---"
    echo >&2
    grep -A 10 "OS details" "$SCAN_RESULTS"
    echo >&2
    echo "--- VULNERABILITY SCAN RESULTS ---"
    echo >&2
    cat "$NSE_RESULTS"
    echo >&2
} >> "$REPORT_FILE"

echo "Phase 4: Targeted NSE scripts based on detected services..."

detected_services=$(grep "open" "$SCAN_RESULTS" | grep -E "http|https|ssh|ftp|smb|mysql|postgres|mssql|vnc|rdp" | head -20)

if echo "$detected_services" | grep -q "80/tcp\|443/tcp\|8080/tcp"; then
    echo "Running HTTP enumeration scripts..."
    # shellcheck disable=SC2086
    nmap --script "http-enum,http-headers,http-methods,http-title,http-server-header" $targets >> "$REPORT_FILE"
fi

if echo "$detected_services" | grep -q "22/tcp.*ssh"; then
    echo "Running SSH enumeration scripts..."
    # shellcheck disable=SC2086
    nmap --script "ssh-auth-methods,ssh-hostkey,ssh2-enum-algos" $targets >> "$REPORT_FILE"
fi

if echo "$detected_services" | grep -q "445/tcp\|139/tcp"; then
    echo "Running SMB enumeration scripts..."
    # shellcheck disable=SC2086
    nmap --script "smb-os-discovery,smb-protocols,smb-security-mode,smb-enum-shares" $targets >> "$REPORT_FILE"
fi

if echo "$detected_services" | grep -q "3306/tcp.*mysql"; then
    echo "Running MySQL enumeration scripts..."
    # shellcheck disable=SC2086
    nmap --script "mysql-info,mysql-enum" $targets >> "$REPORT_FILE"
fi

if echo "$detected_services" | grep -q "1433/tcp.*mssql"; then
    echo "Running MSSQL enumeration scripts..."
    # shellcheck disable=SC2086
    nmap --script "ms-sql-info,ms-sql-config" $targets >> "$REPORT_FILE"
fi

if echo "$detected_services" | grep -q "21/tcp.*ftp"; then
    echo "Running FTP enumeration scripts..."
    # shellcheck disable=SC2086
    nmap --script "ftp-anon,ftp-bounce,ftp-syst" $targets >> "$REPORT_FILE"
fi

echo "Phase 5: SSL/TLS security assessment..."
if echo "$detected_services" | grep -q "443/tcp\|ssl\|tls"; then
    echo "Running SSL/TLS security checks..."
    # shellcheck disable=SC2086
    nmap --script "ssl-cert,ssl-enum-ciphers,ssl-heartbleed,ssl-poodle,ssl-ccs-injection" $targets >> "$REPORT_FILE"
fi

echo "Phase 6: Comprehensive vulnerability analysis..."

{
    echo "--- VULNERABILITY CLASSIFICATION ---"
    echo >&2

    echo "1. SSL/TLS Vulnerabilities:"
    if grep -q "ssl-heartbleed" "$NSE_RESULTS"; then
        echo "  - Heartbleed (CVE-2014-0160): Critical OpenSSL vulnerability"
        echo "    Impact: Private key and sensitive data exposure"
        echo "    Mitigation: Update OpenSSL to 1.0.1g or later"
    fi

    if grep -q "ssl-poodle" "$NSE_RESULTS"; then
        echo "  - POODLE (CVE-2014-3566): SSLv3 vulnerability"
        echo "    Impact: Decrypt secure connections"
        echo "    Mitigation: Disable SSLv3, use TLS 1.2+"
    fi

    if grep -q "ssl-ccs-injection" "$NSE_RESULTS"; then
        echo "  - CCS Injection (CVE-2014-0224): OpenSSL vulnerability"
        echo "    Impact: Man-in-the-middle attacks"
        echo "    Mitigation: Update OpenSSL to 1.0.1h or later"
    fi

    echo >&2

    echo "2. SMB Vulnerabilities:"
    if grep -q "smb-vuln-ms17-010" "$NSE_RESULTS"; then
        echo "  - EternalBlue (MS17-010): Critical SMB vulnerability"
        echo "    Impact: Remote code execution, ransomware propagation"
        echo "    Mitigation: Apply MS17-010 patch immediately"
    fi

    if grep -q "smb-vuln-ms08-067" "$NSE_RESULTS"; then
        echo "  - MS08-067: Critical Windows vulnerability"
        echo "    Impact: Remote code execution without authentication"
        echo "    Mitigation: Apply MS08-067 patch"
    fi

    echo >&2

    echo "3. Web Application Vulnerabilities:"
    if grep -q "http-vuln" "$NSE_RESULTS"; then
        echo "  - Web application vulnerabilities detected"
        echo "    Common issues: XSS, SQL injection, directory traversal"
        echo "    Mitigation: Update web applications, implement WAF"
    fi

    echo >&2

    echo "4. Service-Specific Vulnerabilities:"
    if grep -q "ssh-" "$NSE_RESULTS"; then
        echo "  - SSH service analysis:"
        if grep -q "ssh-auth-methods" "$NSE_RESULTS"; then
            echo "    Authentication methods detected"
        fi
        echo "    Recommendation: Use key-based authentication, disable root login"
    fi

    if grep -q "ftp-anon" "$NSE_RESULTS"; then
        echo "  - FTP anonymous access detected"
        echo "    Impact: Unauthorized file access"
        echo "    Mitigation: Disable anonymous FTP, use SFTP"
    fi

    echo >&2
} >> "$REPORT_FILE"

critical_count=$(grep -ic "critical\|heartbleed\|ms17-010\|ms08-067" "$NSE_RESULTS" || true)
high_count=$(grep -ic "high\|poodle\|ccs-injection" "$NSE_RESULTS" || true)
medium_count=$(grep -ic "medium" "$NSE_RESULTS" || true)
low_count=$(grep -ic "low" "$NSE_RESULTS" || true)

{
    echo "--- RISK ASSESSMENT ---"
    echo >&2

    echo "Risk Level Distribution:"
    echo "  Critical: $critical_count"
    echo "  High: $high_count"
    echo "  Medium: $medium_count"
    echo "  Low: $low_count"
    echo >&2

    if [ "$critical_count" -gt 0 ]; then
        echo "CRITICAL RISK LEVEL: Immediate action required"
    elif [ "$high_count" -gt 0 ]; then
        echo "HIGH RISK LEVEL: Urgent remediation needed"
    elif [ "$medium_count" -gt 0 ]; then
        echo "MEDIUM RISK LEVEL: Plan remediation within 30 days"
    else
        echo "LOW RISK LEVEL: Address during next maintenance window"
    fi

    echo >&2

    echo "--- ATTACK VECTORS ---"
    echo >&2

    echo "Potential attack vectors based on findings:"

    if grep -q "telnet\|23/tcp" "$NSE_RESULTS"; then
        echo "  - Credential interception via Telnet"
    fi

    if grep -q "ftp\|21/tcp" "$NSE_RESULTS"; then
        echo "  - Credential interception via FTP"
    fi

    if grep -q "http\|80/tcp" "$NSE_RESULTS"; then
        echo "  - Man-in-the-middle attacks on HTTP traffic"
    fi

    if grep -q "smb\|445/tcp\|139/tcp" "$NSE_RESULTS"; then
        echo "  - SMB-based attacks (lateral movement)"
    fi

    if grep -q "ssh\|22/tcp" "$NSE_RESULTS"; then
        echo "  - SSH brute force attempts (if weak authentication)"
    fi

    echo >&2
} >> "$REPORT_FILE"

echo "Vulnerability scan complete!"
echo >&2
echo "Files created:"
echo "  Port scan results: $SCAN_RESULTS"
echo "  NSE vuln scan results: $NSE_RESULTS"
echo "  Comprehensive report: $REPORT_FILE"
echo >&2
echo "Summary:"
echo "  Critical vulnerabilities: $critical_count"
echo "  High vulnerabilities: $high_count"
echo "  Medium vulnerabilities: $medium_count"
echo "  Low vulnerabilities: $low_count"

if [ "$critical_count" -gt 0 ]; then
    echo >&2
    echo "⚠️  CRITICAL VULNERABILITIES DETECTED!"
fi

echo >&2
echo "--- VULNERABILITY REPORT ---"
cat "$REPORT_FILE"
