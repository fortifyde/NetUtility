#!/bin/sh

echo "=== Host Categorization ==="
echo

RESULTS_DIR="${NETUTIL_WORKDIR:-$HOME}/discovery"

if [ ! -d "$RESULTS_DIR" ]; then
    echo "Results directory $RESULTS_DIR not found"
    echo "Please run network discovery first"
    exit 1
fi

echo "Available discovery results:"
ls -la "$RESULTS_DIR"/host_summary_*.txt 2>/dev/null || {
    echo "No host summary files found"
    exit 1
}

echo
echo -n "Enter path to host summary file: "
read summary_file

if [ ! -f "$summary_file" ]; then
    echo "Error: Summary file not found"
    exit 1
fi

echo "Analyzing host summary: $summary_file"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
CATEGORIZED_REPORT="$RESULTS_DIR/categorized_hosts_${TIMESTAMP}.txt"

echo "=== Host Categorization Report ===" > "$CATEGORIZED_REPORT"
echo "Source file: $summary_file" >> "$CATEGORIZED_REPORT"
echo "Analysis time: $(date)" >> "$CATEGORIZED_REPORT"
echo >> "$CATEGORIZED_REPORT"

WINDOWS_HOSTS="$RESULTS_DIR/hosts_windows_${TIMESTAMP}.txt"
LINUX_HOSTS="$RESULTS_DIR/hosts_linux_${TIMESTAMP}.txt"
NETWORK_DEVICES="$RESULTS_DIR/hosts_network_devices_${TIMESTAMP}.txt"
UNKNOWN_HOSTS="$RESULTS_DIR/hosts_unknown_${TIMESTAMP}.txt"

> "$WINDOWS_HOSTS"
> "$LINUX_HOSTS"
> "$NETWORK_DEVICES"
> "$UNKNOWN_HOSTS"

echo "Categorizing hosts based on detected services and OS fingerprints..."

grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$" "$summary_file" | while read -r host; do
    if echo "$host" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' >/dev/null; then
        host_block=$(awk "/Host: $host/,/^$/" "$summary_file")
        
        category="unknown"
        confidence="low"
        reasons=""
        
        if echo "$host_block" | grep -qi "microsoft\|windows\|win32"; then
            category="windows"
            confidence="high"
            reasons="$reasons\nOS detection: Windows"
        elif echo "$host_block" | grep -qi "445/tcp.*open"; then
            category="windows"
            confidence="high"
            reasons="$reasons\nService: SMB (445/tcp)"
        elif echo "$host_block" | grep -qi "3389/tcp.*open"; then
            category="windows"
            confidence="high"
            reasons="$reasons\nService: RDP (3389/tcp)"
        elif echo "$host_block" | grep -qi "139/tcp.*open"; then
            category="windows"
            confidence="medium"
            reasons="$reasons\nService: NetBIOS (139/tcp)"
        elif echo "$host_block" | grep -qi "1433/tcp.*open"; then
            category="windows"
            confidence="medium"
            reasons="$reasons\nService: MSSQL (1433/tcp)"
        elif echo "$host_block" | grep -qi "linux\|unix"; then
            category="linux"
            confidence="high"
            reasons="$reasons\nOS detection: Linux/Unix"
        elif echo "$host_block" | grep -qi "22/tcp.*open.*ssh"; then
            category="linux"
            confidence="medium"
            reasons="$reasons\nService: SSH (22/tcp)"
        elif echo "$host_block" | grep -qi "5432/tcp.*open"; then
            category="linux"
            confidence="medium"
            reasons="$reasons\nService: PostgreSQL (5432/tcp)"
        elif echo "$host_block" | grep -qi "cisco\|router\|switch"; then
            category="network_device"
            confidence="high"
            reasons="$reasons\nOS detection: Network device"
        elif echo "$host_block" | grep -qi "23/tcp.*open.*telnet"; then
            category="network_device"
            confidence="medium"
            reasons="$reasons\nService: Telnet (23/tcp)"
        elif echo "$host_block" | grep -qi "161/udp.*open.*snmp"; then
            category="network_device"
            confidence="medium"
            reasons="$reasons\nService: SNMP (161/udp)"
        elif echo "$host_block" | grep -qi "80/tcp.*open\|443/tcp.*open"; then
            if echo "$host_block" | grep -qi "apache\|nginx\|iis"; then
                category="linux"
                confidence="medium"
                reasons="$reasons\nWeb server detected"
            fi
        fi
        
        case $category in
            "windows")
                echo "$host" >> "$WINDOWS_HOSTS"
                ;;
            "linux")
                echo "$host" >> "$LINUX_HOSTS"
                ;;
            "network_device")
                echo "$host" >> "$NETWORK_DEVICES"
                ;;
            *)
                echo "$host" >> "$UNKNOWN_HOSTS"
                ;;
        esac
        
        echo "Host: $host" >> "$CATEGORIZED_REPORT"
        echo "  Category: $category" >> "$CATEGORIZED_REPORT"
        echo "  Confidence: $confidence" >> "$CATEGORIZED_REPORT"
        echo "  Reasons:" >> "$CATEGORIZED_REPORT"
        echo "$reasons" | while read -r reason; do
            if [ -n "$reason" ]; then
                echo "    - $reason" >> "$CATEGORIZED_REPORT"
            fi
        done
        echo >> "$CATEGORIZED_REPORT"
    fi
done

echo >> "$CATEGORIZED_REPORT"
echo "--- CATEGORIZATION SUMMARY ---" >> "$CATEGORIZED_REPORT"
echo >> "$CATEGORIZED_REPORT"

windows_count=$(wc -l < "$WINDOWS_HOSTS" 2>/dev/null || echo 0)
linux_count=$(wc -l < "$LINUX_HOSTS" 2>/dev/null || echo 0)
network_count=$(wc -l < "$NETWORK_DEVICES" 2>/dev/null || echo 0)
unknown_count=$(wc -l < "$UNKNOWN_HOSTS" 2>/dev/null || echo 0)

echo "Windows hosts: $windows_count" >> "$CATEGORIZED_REPORT"
if [ "$windows_count" -gt 0 ]; then
    cat "$WINDOWS_HOSTS" | sed 's/^/  /' >> "$CATEGORIZED_REPORT"
fi
echo >> "$CATEGORIZED_REPORT"

echo "Linux hosts: $linux_count" >> "$CATEGORIZED_REPORT"
if [ "$linux_count" -gt 0 ]; then
    cat "$LINUX_HOSTS" | sed 's/^/  /' >> "$CATEGORIZED_REPORT"
fi
echo >> "$CATEGORIZED_REPORT"

echo "Network devices: $network_count" >> "$CATEGORIZED_REPORT"
if [ "$network_count" -gt 0 ]; then
    cat "$NETWORK_DEVICES" | sed 's/^/  /' >> "$CATEGORIZED_REPORT"
fi
echo >> "$CATEGORIZED_REPORT"

echo "Unknown hosts: $unknown_count" >> "$CATEGORIZED_REPORT"
if [ "$unknown_count" -gt 0 ]; then
    cat "$UNKNOWN_HOSTS" | sed 's/^/  /' >> "$CATEGORIZED_REPORT"
fi

echo >> "$CATEGORIZED_REPORT"
echo "--- RECOMMENDATIONS ---" >> "$CATEGORIZED_REPORT"
echo >> "$CATEGORIZED_REPORT"

if [ "$windows_count" -gt 0 ]; then
    echo "Windows hosts detected:" >> "$CATEGORIZED_REPORT"
    echo "  - Check for SMB vulnerabilities" >> "$CATEGORIZED_REPORT"
    echo "  - Verify RDP security settings" >> "$CATEGORIZED_REPORT"
    echo "  - Ensure proper patch management" >> "$CATEGORIZED_REPORT"
    echo >> "$CATEGORIZED_REPORT"
fi

if [ "$linux_count" -gt 0 ]; then
    echo "Linux hosts detected:" >> "$CATEGORIZED_REPORT"
    echo "  - Verify SSH configuration" >> "$CATEGORIZED_REPORT"
    echo "  - Check for outdated services" >> "$CATEGORIZED_REPORT"
    echo "  - Review running services" >> "$CATEGORIZED_REPORT"
    echo >> "$CATEGORIZED_REPORT"
fi

if [ "$network_count" -gt 0 ]; then
    echo "Network devices detected:" >> "$CATEGORIZED_REPORT"
    echo "  - Change default credentials" >> "$CATEGORIZED_REPORT"
    echo "  - Disable unnecessary services" >> "$CATEGORIZED_REPORT"
    echo "  - Update firmware" >> "$CATEGORIZED_REPORT"
    echo >> "$CATEGORIZED_REPORT"
fi

if [ "$unknown_count" -gt 0 ]; then
    echo "Unknown hosts detected:" >> "$CATEGORIZED_REPORT"
    echo "  - Perform deeper reconnaissance" >> "$CATEGORIZED_REPORT"
    echo "  - Check for IoT devices" >> "$CATEGORIZED_REPORT"
    echo "  - Verify authorized presence" >> "$CATEGORIZED_REPORT"
fi

echo "Host categorization complete!"
echo
echo "Files created:"
echo "  Categorization report: $CATEGORIZED_REPORT"
echo "  Windows hosts: $WINDOWS_HOSTS"
echo "  Linux hosts: $LINUX_HOSTS"
echo "  Network devices: $NETWORK_DEVICES"
echo "  Unknown hosts: $UNKNOWN_HOSTS"
echo
echo "Summary:"
echo "  Windows hosts: $windows_count"
echo "  Linux hosts: $linux_count"
echo "  Network devices: $network_count"
echo "  Unknown hosts: $unknown_count"

echo
echo "--- CATEGORIZATION REPORT ---"
cat "$CATEGORIZED_REPORT"