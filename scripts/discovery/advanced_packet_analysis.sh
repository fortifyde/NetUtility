#!/bin/sh

# Advanced Packet Analysis Script
# Deep protocol analysis with statistical reports and security assessment

. "$(dirname "$0")/../common/utils.sh"

echo "=== Advanced Packet Analysis ==="
echo

CAPTURE_DIR="${NETUTIL_WORKDIR:-$HOME}/captures"
ANALYSIS_DIR="${NETUTIL_WORKDIR:-$HOME}/analysis"

# Create analysis directory if it doesn't exist
mkdir -p "$ANALYSIS_DIR"

# Parse command line arguments or read from stdin
provided_file="$1"

if [ -n "$provided_file" ]; then
    # Use provided file path
    capture_file="$provided_file"
    echo "Using provided capture file: $capture_file"
elif [ ! -t 0 ]; then
    # Read from stdin (piped input)
    read -r capture_file
    echo "Using piped capture file: $capture_file"
else
    # Interactive mode - show available files and prompt for selection
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
    capture_file=$(select_file "$CAPTURE_DIR" "*.pcap" "Select capture file for analysis:")
fi

if [ ! -f "$capture_file" ]; then
    echo "Error: Capture file not found"
    exit 1
fi

echo "Performing advanced analysis on: $capture_file"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASENAME=$(basename "$capture_file" .pcap)
REPORT_FILE="$ANALYSIS_DIR/advanced_analysis_${BASENAME}_${TIMESTAMP}.txt"
TEMP_DIR=$(mktemp -d)

# Cleanup on exit
trap 'rm -rf "$TEMP_DIR"' EXIT

echo "=== Advanced Network Analysis Report ===" > "$REPORT_FILE"
echo "Capture file: $capture_file" >> "$REPORT_FILE"
echo "Analysis time: $(date)" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Extracting network information..."

# VLAN Analysis
echo "--- VLAN ANALYSIS ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Detected VLAN IDs:" >> "$REPORT_FILE"
tshark -r "$capture_file" -T fields -e vlan.id 2>/dev/null | sort -nu | grep -v "^$" > "$TEMP_DIR/vlan_ids.txt"
if [ -s "$TEMP_DIR/vlan_ids.txt" ]; then
    cat "$TEMP_DIR/vlan_ids.txt" >> "$REPORT_FILE"
    echo >> "$REPORT_FILE"
    
    echo "VLAN-IP Correlations:" >> "$REPORT_FILE"
    while read -r vlan_id; do
        echo "VLAN $vlan_id IP addresses:" >> "$REPORT_FILE"
        tshark -r "$capture_file" -T fields -e vlan.id -e ip.src -Y "vlan.id==$vlan_id and ip.src!=0.0.0.0" 2>/dev/null | \
            awk -v vlan="$vlan_id" '$1==vlan {print "  " $2}' | sort -u >> "$REPORT_FILE"
    done < "$TEMP_DIR/vlan_ids.txt"
else
    echo "No VLAN tags detected - likely access port only" >> "$REPORT_FILE"
fi
echo >> "$REPORT_FILE"

# IPv4 Endpoint Analysis
echo "--- IPv4 ENDPOINT ANALYSIS ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Active IPv4 addresses:" >> "$REPORT_FILE"
tshark -r "$capture_file" -q -z endpoints,ip 2>/dev/null | grep -E "^\s*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | \
    awk '{print $1}' | grep -v "224\." | sort -u > "$TEMP_DIR/ipv4_endpoints.txt"
cat "$TEMP_DIR/ipv4_endpoints.txt" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Check for APIPA addresses
if grep -q "^169\.254\." "$TEMP_DIR/ipv4_endpoints.txt"; then
    echo "⚠️  APIPA addresses detected - possible DHCP issues!" >> "$REPORT_FILE"
    grep "^169\.254\." "$TEMP_DIR/ipv4_endpoints.txt" | sed 's/^/  /' >> "$REPORT_FILE"
    echo >> "$REPORT_FILE"
fi

# Check for invalid addresses
if grep -q "^0\.0\.0\.0$" "$TEMP_DIR/ipv4_endpoints.txt"; then
    echo "⚠️  Invalid IPv4 addresses detected!" >> "$REPORT_FILE"
    echo "  Filter with: ip.addr==0.0.0.0 for detailed analysis" >> "$REPORT_FILE"
    echo >> "$REPORT_FILE"
fi

# Protocol Statistics
echo "--- PROTOCOL STATISTICS ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Protocol hierarchy:" >> "$REPORT_FILE"
tshark -r "$capture_file" -q -z io,phs 2>/dev/null | grep -v "^=" | grep -v "^$" | head -20 >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Windows Proxy Auto-Discovery (WPAD) Analysis
echo "--- WINDOWS PROXY AUTO-DISCOVERY (WPAD) ANALYSIS ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Systems requesting WPAD:" >> "$REPORT_FILE"
tshark -r "$capture_file" -Y 'dns.qry.name contains "wpad"' -T fields -e ip.src 2>/dev/null | sort -u > "$TEMP_DIR/wpad_dns.txt"
tshark -r "$capture_file" -Y 'nbns.name contains "wpad"' -T fields -e ip.src 2>/dev/null | sort -u > "$TEMP_DIR/wpad_nbns.txt"

if [ -s "$TEMP_DIR/wpad_dns.txt" ] || [ -s "$TEMP_DIR/wpad_nbns.txt" ]; then
    cat "$TEMP_DIR/wpad_dns.txt" "$TEMP_DIR/wpad_nbns.txt" | sort -u | sed 's/^/  /' >> "$REPORT_FILE"
    echo >> "$REPORT_FILE"
    echo "⚠️  WPAD requests detected - potential security risk!" >> "$REPORT_FILE"
    echo "Recommendation: Disable WPAD or configure proper proxy settings" >> "$REPORT_FILE"
else
    echo "No WPAD requests detected" >> "$REPORT_FILE"
fi
echo >> "$REPORT_FILE"

# Windows Domain/Workgroup Analysis (BROWSER Protocol)
echo "--- WINDOWS DOMAIN/WORKGROUP ANALYSIS (BROWSER) ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

tshark -r "$capture_file" -Y "browser" -T fields -e ip.src 2>/dev/null | sort -u > "$TEMP_DIR/browser_systems.txt"
if [ -s "$TEMP_DIR/browser_systems.txt" ]; then
    echo "Systems participating in browser protocol:" >> "$REPORT_FILE"
    cat "$TEMP_DIR/browser_systems.txt" | sed 's/^/  /' >> "$REPORT_FILE"
    echo >> "$REPORT_FILE"
    
    echo "Domain/Workgroup names:" >> "$REPORT_FILE"
    tshark -r "$capture_file" -Y "browser" -T fields -e _ws.col.Info 2>/dev/null | \
        grep -o "Domain/Workgroup Announcement [A-Za-z0-9_-]*" | \
        awk '{print $3}' | sort -u | sed 's/^/  /' >> "$REPORT_FILE"
    echo >> "$REPORT_FILE"
    
    echo "Domain Controllers:" >> "$REPORT_FILE"
    tshark -r "$capture_file" -Y "browser" -T fields -e ip.src -e _ws.col.Info 2>/dev/null | \
        grep "Domain Controller" | awk '{print $1}' | sort -u | sed 's/^/  /' >> "$REPORT_FILE"
    echo >> "$REPORT_FILE"
    
    echo "Backup Domain Controllers:" >> "$REPORT_FILE"
    tshark -r "$capture_file" -Y "browser" -T fields -e ip.src -e _ws.col.Info 2>/dev/null | \
        grep "Backup Controller" | awk '{print $1}' | sort -u | sed 's/^/  /' >> "$REPORT_FILE"
    echo >> "$REPORT_FILE"
    
    echo "SQL Servers:" >> "$REPORT_FILE"
    tshark -r "$capture_file" -Y "browser" -T fields -e ip.src -e _ws.col.Info 2>/dev/null | \
        grep "SQL Server" | awk '{print $1}' | sort -u | sed 's/^/  /' >> "$REPORT_FILE"
    echo >> "$REPORT_FILE"
    
    echo "Host Announcements:" >> "$REPORT_FILE"
    tshark -r "$capture_file" -Y 'browser.command==0x01' -T fields -e ip.src -e _ws.col.Info 2>/dev/null | \
        awk '{print $1 "\t" $4}' | sort -u | head -10 | sed 's/^/  /' >> "$REPORT_FILE"
else
    echo "No browser protocol activity detected" >> "$REPORT_FILE"
fi
echo >> "$REPORT_FILE"

# Simple Service Discovery Protocol (SSDP) Analysis
echo "--- SIMPLE SERVICE DISCOVERY PROTOCOL (SSDP) ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "SSDP M-SEARCH requests (service seekers):" >> "$REPORT_FILE"
tshark -r "$capture_file" -Y 'ssdp and http.request.method=="M-SEARCH"' -T fields -e ip.src 2>/dev/null | \
    sort -u | sed 's/^/  /' >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "SSDP NOTIFY announcements (service providers):" >> "$REPORT_FILE"
tshark -r "$capture_file" -Y 'ssdp and http.request.method=="NOTIFY"' -T fields -e ip.src 2>/dev/null | \
    sort -u | sed 's/^/  /' >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "SSDP service locations:" >> "$REPORT_FILE"
tshark -r "$capture_file" -Y "ssdp" -T fields -e http.location 2>/dev/null | \
    grep -v "^$" | sort -u | head -10 | sed 's/^/  /' >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Spanning Tree Protocol (STP) Analysis
echo "--- SPANNING TREE PROTOCOL (STP) ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

stp_count=$(tshark -r "$capture_file" -Y "stp" 2>/dev/null | wc -l)
if [ "$stp_count" -gt 0 ]; then
    echo "STP packets detected: $stp_count" >> "$REPORT_FILE"
    echo "Root bridge information:" >> "$REPORT_FILE"
    tshark -r "$capture_file" -Y "stp" -T fields -e stp.root.hw 2>/dev/null | \
        sort -u | sed 's/^/  /' >> "$REPORT_FILE"
    echo >> "$REPORT_FILE"
    
    echo "Switch MAC addresses:" >> "$REPORT_FILE"
    tshark -r "$capture_file" -Y "stp" -T fields -e eth.src 2>/dev/null | \
        sort -u | head -10 | sed 's/^/  /' >> "$REPORT_FILE"
else
    echo "No STP packets detected" >> "$REPORT_FILE"
fi
echo >> "$REPORT_FILE"

# MAC Address Analysis with OUI Information
echo "--- MAC ADDRESS ANALYSIS ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Top MAC address prefixes (OUI):" >> "$REPORT_FILE"
tshark -r "$capture_file" -T fields -e eth.src 2>/dev/null | \
    cut -d: -f1-3 | sort | uniq -c | sort -nr | head -10 | \
    while read -r count oui; do
        echo "  $oui ($count occurrences)" >> "$REPORT_FILE"
    done
echo >> "$REPORT_FILE"

# Security Assessment
echo "--- SECURITY ASSESSMENT ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Count various security-relevant protocols
http_count=$(tshark -r "$capture_file" -Y "http" 2>/dev/null | wc -l)
ftp_count=$(tshark -r "$capture_file" -Y "ftp" 2>/dev/null | wc -l)
telnet_count=$(tshark -r "$capture_file" -Y "telnet" 2>/dev/null | wc -l)
snmp_count=$(tshark -r "$capture_file" -Y "snmp" 2>/dev/null | wc -l)
dns_count=$(tshark -r "$capture_file" -Y "dns" 2>/dev/null | wc -l)

echo "Security-relevant protocol counts:" >> "$REPORT_FILE"
echo "  HTTP (unencrypted): $http_count" >> "$REPORT_FILE"
echo "  FTP (unencrypted): $ftp_count" >> "$REPORT_FILE"
echo "  Telnet (unencrypted): $telnet_count" >> "$REPORT_FILE"
echo "  SNMP: $snmp_count" >> "$REPORT_FILE"
echo "  DNS: $dns_count" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Security Recommendations
echo "--- SECURITY RECOMMENDATIONS ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

if [ "$http_count" -gt 0 ]; then
    echo "⚠️  HTTP traffic detected - consider HTTPS migration" >> "$REPORT_FILE"
fi

if [ "$ftp_count" -gt 0 ]; then
    echo "⚠️  FTP traffic detected - consider SFTP/FTPS migration" >> "$REPORT_FILE"
fi

if [ "$telnet_count" -gt 0 ]; then
    echo "⚠️  Telnet traffic detected - migrate to SSH immediately" >> "$REPORT_FILE"
fi

if [ "$snmp_count" -gt 0 ]; then
    echo "ℹ️  SNMP traffic detected - ensure SNMPv3 is used" >> "$REPORT_FILE"
fi

if [ -s "$TEMP_DIR/wpad_dns.txt" ] || [ -s "$TEMP_DIR/wpad_nbns.txt" ]; then
    echo "⚠️  WPAD requests detected - potential security vulnerability" >> "$REPORT_FILE"
fi

echo >> "$REPORT_FILE"
echo "Analysis completed at $(date)" >> "$REPORT_FILE"

echo "Analysis complete!"
echo "Report saved to: $REPORT_FILE"

# Update latest symlinks
update_latest_links "analysis" "$REPORT_FILE"

echo
echo "Opening report..."
echo
cat "$REPORT_FILE"