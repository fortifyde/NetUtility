#!/bin/sh

echo "=== Unsafe Protocol Detection ==="
echo

CAPTURE_DIR="${NETUTIL_WORKDIR:-$HOME}/captures"

if [ ! -d "$CAPTURE_DIR" ]; then
    echo "Capture directory $CAPTURE_DIR not found"
    exit 1
fi

echo "Available capture files:"
ls -la "$CAPTURE_DIR"/*.pcap 2>/dev/null || {
    echo "No capture files found in $CAPTURE_DIR"
    exit 1
}

echo
read -p "Enter path to capture file: " capture_file

if [ ! -f "$capture_file" ]; then
    echo "Error: Capture file not found"
    exit 1
fi

echo "Analyzing capture file for unsafe protocols: $capture_file"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="$CAPTURE_DIR/unsafe_protocols_${TIMESTAMP}.txt"

echo "=== Unsafe Protocol Analysis Report ===" > "$REPORT_FILE"
echo "Capture file: $capture_file" >> "$REPORT_FILE"
echo "Analysis time: $(date)" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Detecting unsafe protocols..."

echo "--- CLEAR TEXT PROTOCOLS ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "1. HTTP (Port 80) - Unencrypted web traffic" >> "$REPORT_FILE"
http_count=$(tshark -r "$capture_file" -Y "http" 2>/dev/null | wc -l)
echo "HTTP packets: $http_count" >> "$REPORT_FILE"
if [ "$http_count" -gt 0 ]; then
    echo "HTTP hosts:" >> "$REPORT_FILE"
    tshark -r "$capture_file" -Y "http" -T fields -e http.host 2>/dev/null | sort -u | head -20 | sed 's/^/  /' >> "$REPORT_FILE"
fi
echo >> "$REPORT_FILE"

echo "2. FTP (Port 21) - Unencrypted file transfer" >> "$REPORT_FILE"
ftp_count=$(tshark -r "$capture_file" -Y "ftp" 2>/dev/null | wc -l)
echo "FTP packets: $ftp_count" >> "$REPORT_FILE"
if [ "$ftp_count" -gt 0 ]; then
    echo "FTP connections:" >> "$REPORT_FILE"
    tshark -r "$capture_file" -Y "ftp" -T fields -e ip.src -e ip.dst 2>/dev/null | sort -u | head -10 | sed 's/^/  /' >> "$REPORT_FILE"
fi
echo >> "$REPORT_FILE"

echo "3. Telnet (Port 23) - Unencrypted remote access" >> "$REPORT_FILE"
telnet_count=$(tshark -r "$capture_file" -Y "telnet" 2>/dev/null | wc -l)
echo "Telnet packets: $telnet_count" >> "$REPORT_FILE"
if [ "$telnet_count" -gt 0 ]; then
    echo "Telnet sessions:" >> "$REPORT_FILE"
    tshark -r "$capture_file" -Y "telnet" -T fields -e ip.src -e ip.dst 2>/dev/null | sort -u | head -10 | sed 's/^/  /' >> "$REPORT_FILE"
fi
echo >> "$REPORT_FILE"

echo "4. SMTP (Port 25) - Unencrypted email" >> "$REPORT_FILE"
smtp_count=$(tshark -r "$capture_file" -Y "smtp" 2>/dev/null | wc -l)
echo "SMTP packets: $smtp_count" >> "$REPORT_FILE"
if [ "$smtp_count" -gt 0 ]; then
    echo "SMTP servers:" >> "$REPORT_FILE"
    tshark -r "$capture_file" -Y "smtp" -T fields -e ip.dst 2>/dev/null | sort -u | head -10 | sed 's/^/  /' >> "$REPORT_FILE"
fi
echo >> "$REPORT_FILE"

echo "5. POP3 (Port 110) - Unencrypted email retrieval" >> "$REPORT_FILE"
pop3_count=$(tshark -r "$capture_file" -Y "pop" 2>/dev/null | wc -l)
echo "POP3 packets: $pop3_count" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "6. IMAP (Port 143) - Unencrypted email access" >> "$REPORT_FILE"
imap_count=$(tshark -r "$capture_file" -Y "imap" 2>/dev/null | wc -l)
echo "IMAP packets: $imap_count" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "7. SNMP (Port 161) - Network management protocol" >> "$REPORT_FILE"
snmp_count=$(tshark -r "$capture_file" -Y "snmp" 2>/dev/null | wc -l)
echo "SNMP packets: $snmp_count" >> "$REPORT_FILE"
if [ "$snmp_count" -gt 0 ]; then
    echo "SNMP communities detected:" >> "$REPORT_FILE"
    tshark -r "$capture_file" -Y "snmp" -T fields -e snmp.community 2>/dev/null | sort -u | head -10 | sed 's/^/  /' >> "$REPORT_FILE"
fi
echo >> "$REPORT_FILE"

echo "--- NETWORK ARCHITECTURE REVEALING PROTOCOLS ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "1. CDP (Cisco Discovery Protocol)" >> "$REPORT_FILE"
cdp_count=$(tshark -r "$capture_file" -Y "cdp" 2>/dev/null | wc -l)
echo "CDP packets: $cdp_count" >> "$REPORT_FILE"
if [ "$cdp_count" -gt 0 ]; then
    echo "CDP device information:" >> "$REPORT_FILE"
    tshark -r "$capture_file" -Y "cdp" -T fields -e cdp.deviceid 2>/dev/null | sort -u | head -10 | sed 's/^/  /' >> "$REPORT_FILE"
fi
echo >> "$REPORT_FILE"

echo "2. LLDP (Link Layer Discovery Protocol)" >> "$REPORT_FILE"
lldp_count=$(tshark -r "$capture_file" -Y "lldp" 2>/dev/null | wc -l)
echo "LLDP packets: $lldp_count" >> "$REPORT_FILE"
if [ "$lldp_count" -gt 0 ]; then
    echo "LLDP system names:" >> "$REPORT_FILE"
    tshark -r "$capture_file" -Y "lldp" -T fields -e lldp.tlv.system.name 2>/dev/null | sort -u | head -10 | sed 's/^/  /' >> "$REPORT_FILE"
fi
echo >> "$REPORT_FILE"

echo "3. STP (Spanning Tree Protocol)" >> "$REPORT_FILE"
stp_count=$(tshark -r "$capture_file" -Y "stp" 2>/dev/null | wc -l)
echo "STP packets: $stp_count" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "4. DHCP (Dynamic Host Configuration Protocol)" >> "$REPORT_FILE"
dhcp_count=$(tshark -r "$capture_file" -Y "dhcp" 2>/dev/null | wc -l)
echo "DHCP packets: $dhcp_count" >> "$REPORT_FILE"
if [ "$dhcp_count" -gt 0 ]; then
    echo "DHCP servers:" >> "$REPORT_FILE"
    tshark -r "$capture_file" -Y "dhcp.option.dhcp == 2" -T fields -e ip.src 2>/dev/null | sort -u | head -10 | sed 's/^/  /' >> "$REPORT_FILE"
fi
echo >> "$REPORT_FILE"

echo "--- SECURITY SUMMARY ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

total_unsafe=$((http_count + ftp_count + telnet_count + smtp_count + pop3_count + imap_count + snmp_count))
total_architecture=$((cdp_count + lldp_count + stp_count + dhcp_count))

echo "Total unsafe protocol packets: $total_unsafe" >> "$REPORT_FILE"
echo "Total architecture revealing packets: $total_architecture" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

if [ "$total_unsafe" -gt 0 ]; then
    echo "WARNING: Unsafe protocols detected!" >> "$REPORT_FILE"
    echo "Recommendations:" >> "$REPORT_FILE"
    echo "- Replace HTTP with HTTPS" >> "$REPORT_FILE"
    echo "- Replace FTP with SFTP/FTPS" >> "$REPORT_FILE"
    echo "- Replace Telnet with SSH" >> "$REPORT_FILE"
    echo "- Use encrypted email protocols (IMAPS, POP3S, SMTPS)" >> "$REPORT_FILE"
    echo "- Secure SNMP with SNMPv3" >> "$REPORT_FILE"
    echo >> "$REPORT_FILE"
fi

if [ "$total_architecture" -gt 0 ]; then
    echo "NOTICE: Network architecture information exposed!" >> "$REPORT_FILE"
    echo "Consider:" >> "$REPORT_FILE"
    echo "- Disabling CDP/LLDP on edge ports" >> "$REPORT_FILE"
    echo "- Implementing network segmentation" >> "$REPORT_FILE"
    echo "- Monitoring for reconnaissance activities" >> "$REPORT_FILE"
fi

echo "Analysis complete!"
echo "Report saved to: $REPORT_FILE"
echo
echo "Summary:"
echo "- Unsafe protocol packets: $total_unsafe"
echo "- Architecture revealing packets: $total_architecture"

if [ "$total_unsafe" -gt 0 ] || [ "$total_architecture" -gt 0 ]; then
    echo
    echo "⚠️  Security issues detected! Review the full report for details."
fi

echo
cat "$REPORT_FILE"