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
        
        # Multi-factor scoring system for more accurate categorization
        windows_score=0
        linux_score=0
        network_score=0
        
        # Windows indicators (strong)
        if echo "$host_block" | grep -qi "microsoft\|windows\|win32"; then
            windows_score=$((windows_score + 10))
            reasons="$reasons\nOS fingerprint: Windows"
        fi
        if echo "$host_block" | grep -qi "445/tcp.*open"; then
            windows_score=$((windows_score + 8))
            reasons="$reasons\nSMB service (445/tcp)"
        fi
        if echo "$host_block" | grep -qi "3389/tcp.*open"; then
            windows_score=$((windows_score + 8))
            reasons="$reasons\nRDP service (3389/tcp)"
        fi
        if echo "$host_block" | grep -qi "139/tcp.*open"; then
            windows_score=$((windows_score + 5))
            reasons="$reasons\nNetBIOS service (139/tcp)"
        fi
        if echo "$host_block" | grep -qi "135/tcp.*open"; then
            windows_score=$((windows_score + 6))
            reasons="$reasons\nRPC Endpoint Mapper (135/tcp)"
        fi
        if echo "$host_block" | grep -qi "1433/tcp.*open"; then
            windows_score=$((windows_score + 4))
            reasons="$reasons\nMS SQL Server (1433/tcp)"
        fi
        if echo "$host_block" | grep -qi "5985/tcp.*open\|5986/tcp.*open"; then
            windows_score=$((windows_score + 5))
            reasons="$reasons\nWinRM service"
        fi
        
        # Linux indicators (strong)
        if echo "$host_block" | grep -qi "linux\|unix\|ubuntu\|debian\|centos\|redhat"; then
            linux_score=$((linux_score + 10))
            reasons="$reasons\nOS fingerprint: Linux/Unix"
        fi
        if echo "$host_block" | grep -qi "22/tcp.*open.*ssh"; then
            linux_score=$((linux_score + 7))
            reasons="$reasons\nSSH service (22/tcp)"
        fi
        if echo "$host_block" | grep -qi "5432/tcp.*open"; then
            linux_score=$((linux_score + 3))
            reasons="$reasons\nPostgreSQL service (5432/tcp)"
        fi
        
        # Network/Appliance indicators (comprehensive)
        if echo "$host_block" | grep -qi "cisco\|juniper\|hp.*procurve\|netgear\|d-link\|tp-link"; then
            network_score=$((network_score + 10))
            reasons="$reasons\nNetwork vendor fingerprint"
        fi
        if echo "$host_block" | grep -qi "router\|switch\|firewall\|gateway"; then
            network_score=$((network_score + 8))
            reasons="$reasons\nNetwork device type"
        fi
        if echo "$host_block" | grep -qi "23/tcp.*open.*telnet"; then
            network_score=$((network_score + 6))
            reasons="$reasons\nTelnet management (23/tcp)"
        fi
        if echo "$host_block" | grep -qi "161/udp.*open.*snmp"; then
            network_score=$((network_score + 7))
            reasons="$reasons\nSNMP management (161/udp)"
        fi
        if echo "$host_block" | grep -qi "162/udp.*open"; then
            network_score=$((network_score + 5))
            reasons="$reasons\nSNMP trap (162/udp)"
        fi
        
        # Printer/Print Server detection
        if echo "$host_block" | grep -qi "631/tcp.*open.*ipp\|515/tcp.*open.*lpd\|9100/tcp.*open"; then
            network_score=$((network_score + 8))
            reasons="$reasons\nPrint services detected"
        fi
        if echo "$host_block" | grep -qi "printer\|canon\|hp.*laserjet\|epson\|brother\|lexmark"; then
            network_score=$((network_score + 9))
            reasons="$reasons\nPrinter device detected"
        fi
        
        # UPS/Power Management detection
        if echo "$host_block" | grep -qi "apc\|ups\|eaton\|schneider.*electric\|tripp.*lite"; then
            network_score=$((network_score + 9))
            reasons="$reasons\nUPS/Power management device"
        fi
        if echo "$host_block" | grep -qi "3052/tcp.*open\|161.*ups\|power.*management"; then
            network_score=$((network_score + 7))
            reasons="$reasons\nPower management services"
        fi
        
        # Lights-out Management (IPMI, iLO, iDRAC, etc.)
        if echo "$host_block" | grep -qi "623/udp.*open.*ipmi\|623/tcp.*open"; then
            network_score=$((network_score + 8))
            reasons="$reasons\nIPMI management interface"
        fi
        if echo "$host_block" | grep -qi "ilo\|idrac\|imm\|bmc\|ipmi"; then
            network_score=$((network_score + 9))
            reasons="$reasons\nLights-out management detected"
        fi
        if echo "$host_block" | grep -qi "443.*ilo\|443.*idrac\|17988/tcp.*open\|17990/tcp.*open"; then
            network_score=$((network_score + 8))
            reasons="$reasons\nServer management interface"
        fi
        
        # NTP Server detection
        if echo "$host_block" | grep -qi "123/udp.*open.*ntp"; then
            network_score=$((network_score + 7))
            reasons="$reasons\nNTP time server (123/udp)"
        fi
        if echo "$host_block" | grep -qi "meinberg\|trimble\|spectracom\|microsemi\|ntp.*server"; then
            network_score=$((network_score + 9))
            reasons="$reasons\nDedicated NTP appliance"
        fi
        
        # Network Attached Storage
        if echo "$host_block" | grep -qi "synology\|qnap\|netapp\|drobo\|buffalo.*nas"; then
            network_score=$((network_score + 8))
            reasons="$reasons\nNetwork Attached Storage"
        fi
        if echo "$host_block" | grep -qi "2049/tcp.*open.*nfs\|548/tcp.*open.*afp"; then
            network_score=$((network_score + 6))
            reasons="$reasons\nNetwork file services"
        fi
        
        # IoT and Smart Devices
        if echo "$host_block" | grep -qi "8080.*web.*interface\|camera\|ip.*cam\|axis\|hikvision"; then
            network_score=$((network_score + 7))
            reasons="$reasons\nIP camera/surveillance device"
        fi
        if echo "$host_block" | grep -qi "smart.*plug\|iot.*device\|esp8266\|esp32\|arduino"; then
            network_score=$((network_score + 6))
            reasons="$reasons\nIoT device detected"
        fi
        
        # KVM/Console servers
        if echo "$host_block" | grep -qi "kvm\|console.*server\|raritan\|avocent"; then
            network_score=$((network_score + 8))
            reasons="$reasons\nKVM/Console management"
        fi
        
        # Environmental monitoring
        if echo "$host_block" | grep -qi "temperature\|humidity\|environmental.*monitor\|sensatronics"; then
            network_score=$((network_score + 7))
            reasons="$reasons\nEnvironmental monitoring device"
        fi
        
        # Determine final category based on highest score
        if [ $windows_score -gt $linux_score ] && [ $windows_score -gt $network_score ] && [ $windows_score -ge 5 ]; then
            category="windows"
            if [ $windows_score -ge 10 ]; then
                confidence="high"
            elif [ $windows_score -ge 7 ]; then
                confidence="medium"
            else
                confidence="low"
            fi
        elif [ $linux_score -gt $windows_score ] && [ $linux_score -gt $network_score ] && [ $linux_score -ge 5 ]; then
            category="linux"
            if [ $linux_score -ge 10 ]; then
                confidence="high"
            elif [ $linux_score -ge 7 ]; then
                confidence="medium"
            else
                confidence="low"
            fi
        elif [ $network_score -gt $windows_score ] && [ $network_score -gt $linux_score ] && [ $network_score -ge 5 ]; then
            category="network_device"
            if [ $network_score -ge 10 ]; then
                confidence="high"
            elif [ $network_score -ge 7 ]; then
                confidence="medium"
            else
                confidence="low"
            fi
        else
            category="unknown"
            confidence="low"
            if [ $windows_score -gt 0 ] || [ $linux_score -gt 0 ] || [ $network_score -gt 0 ]; then
                reasons="$reasons\nScores: Windows=$windows_score, Linux=$linux_score, Network=$network_score (insufficient for classification)"
            else
                reasons="$reasons\nNo distinctive characteristics detected"
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
    echo "Network devices and appliances detected:" >> "$CATEGORIZED_REPORT"
    echo "  - Change default credentials on all network equipment" >> "$CATEGORIZED_REPORT"
    echo "  - Update firmware on routers, switches, and appliances" >> "$CATEGORIZED_REPORT"
    echo "  - Secure SNMP communities and disable unnecessary protocols" >> "$CATEGORIZED_REPORT"
    echo "  - Review printer and UPS management interfaces" >> "$CATEGORIZED_REPORT"
    echo "  - Audit lights-out management (IPMI/iLO/iDRAC) access" >> "$CATEGORIZED_REPORT"
    echo "  - Verify NTP server configurations and time synchronization" >> "$CATEGORIZED_REPORT"
    echo "  - Check IoT device security and network segmentation" >> "$CATEGORIZED_REPORT"
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