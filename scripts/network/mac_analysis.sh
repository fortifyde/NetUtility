#!/bin/sh

# MAC Address Intelligence and OUI Database Integration
# Analyzes MAC addresses from network captures and provides vendor identification

. "$(dirname "$0")/../common/utils.sh"

echo "=== MAC Address Intelligence Analysis ==="
echo

CAPTURE_DIR="${NETUTIL_WORKDIR:-$HOME}/captures"
ANALYSIS_DIR="${NETUTIL_WORKDIR:-$HOME}/analysis"

# Create necessary directories
mkdir -p "$ANALYSIS_DIR"

# OUI Helper binary path (try to find in PATH or relative to script)
OUIHELPER_BIN=""
if command -v ouihelper >/dev/null 2>&1; then
    OUIHELPER_BIN="ouihelper"
elif [ -f "$(dirname "$0")/../../cmd/ouihelper/ouihelper" ]; then
    OUIHELPER_BIN="$(dirname "$0")/../../cmd/ouihelper/ouihelper"
elif [ -f "$(dirname "$0")/../../ouihelper" ]; then
    OUIHELPER_BIN="$(dirname "$0")/../../ouihelper"
fi

# Fallback OUI database locations
FALLBACK_OUI_LOCATIONS="
$(dirname "$0")/../../data/oui.txt
$(dirname "$0")/../../internal/oui/data/oui.txt
${NETUTIL_WORKDIR:-$HOME}/oui_db/oui.txt
$HOME/.netutil/oui.txt
"

# Function to lookup MAC vendor using Go helper or fallback to text parsing
lookup_mac_vendor() {
    mac_prefix="$1"
    
    # Try using the Go helper first (faster and more reliable)
    if [ -n "$OUIHELPER_BIN" ] && [ -x "$OUIHELPER_BIN" ]; then
        vendor=$($OUIHELPER_BIN lookup "$mac_prefix" 2>/dev/null)
        if [ $? -eq 0 ] && [ -n "$vendor" ]; then
            echo "$vendor"
            return 0
        fi
    fi
    
    # Fallback to text file parsing
    for oui_file in $FALLBACK_OUI_LOCATIONS; do
        if [ -f "$oui_file" ]; then
            # Convert MAC prefix to uppercase and format for OUI lookup
            oui_prefix=$(echo "$mac_prefix" | tr '[:lower:]' '[:upper:]' | tr -d ':' | tr -d '-')
            
            # Look up in OUI database
            vendor=$(grep "^$oui_prefix" "$oui_file" | head -1 | sed 's/^[0-9A-F]*[[:space:]]*[^ ]*[[:space:]]*//' | sed 's/[[:space:]]*$//')
            
            if [ -n "$vendor" ]; then
                echo "$vendor"
                return 0
            fi
        fi
    done
    
    echo "Unknown"
    return 1
}

# Function to categorize device type based on MAC vendor
categorize_device() {
    vendor="$1"
    
    case "$vendor" in
        *"Cisco"*|*"CISCO"*)
            echo "Network Infrastructure"
            ;;
        *"VMware"*|*"VMWARE"*)
            echo "Virtual Machine"
            ;;
        *"Microsoft"*|*"MICROSOFT"*)
            echo "Microsoft Device"
            ;;
        *"Apple"*|*"APPLE"*)
            echo "Apple Device"
            ;;
        *"Dell"*|*"DELL"*)
            echo "Dell Computer"
            ;;
        *"HP"*|*"Hewlett"*|*"HEWLETT"*)
            echo "HP Device"
            ;;
        *"Intel"*|*"INTEL"*)
            echo "Intel Network Card"
            ;;
        *"Broadcom"*|*"BROADCOM"*)
            echo "Broadcom Network Card"
            ;;
        *"Realtek"*|*"REALTEK"*)
            echo "Realtek Network Card"
            ;;
        *"TP-Link"*|*"TP-LINK"*)
            echo "TP-Link Network Device"
            ;;
        *"D-Link"*|*"D-LINK"*)
            echo "D-Link Network Device"
            ;;
        *"Netgear"*|*"NETGEAR"*)
            echo "Netgear Network Device"
            ;;
        *"Ubiquiti"*|*"UBIQUITI"*)
            echo "Ubiquiti Network Device"
            ;;
        *"Samsung"*|*"SAMSUNG"*)
            echo "Samsung Device"
            ;;
        *"LG"*|*"Electronics"*)
            echo "Consumer Electronics"
            ;;
        *"Unknown"*)
            echo "Unknown Device"
            ;;
        *)
            echo "Generic Device"
            ;;
    esac
}

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
capture_file=$(select_file "$CAPTURE_DIR" "*.pcap" "Select capture file for MAC analysis:")

if [ ! -f "$capture_file" ]; then
    echo "Error: Capture file not found"
    exit 1
fi

# OUI database is now always available offline
# Use 'netutil update-oui' to update the database when needed

echo "Analyzing MAC addresses in: $capture_file"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASENAME=$(basename "$capture_file" .pcap)
REPORT_FILE="$ANALYSIS_DIR/mac_analysis_${BASENAME}_${TIMESTAMP}.txt"
TEMP_DIR=$(mktemp -d)

# Cleanup on exit
trap 'rm -rf "$TEMP_DIR"' EXIT

echo "=== MAC Address Intelligence Report ===" > "$REPORT_FILE"
echo "Capture file: $capture_file" >> "$REPORT_FILE"
echo "Analysis time: $(date)" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Extracting MAC addresses..."

# Extract all source MAC addresses
echo "--- ALL MAC ADDRESSES ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

tshark -r "$capture_file" -T fields -e eth.src 2>/dev/null | \
    grep -v "^$" | sort -u > "$TEMP_DIR/all_macs.txt"

echo "Total unique MAC addresses found: $(wc -l < "$TEMP_DIR/all_macs.txt")" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Analyze each MAC address
echo "--- MAC ADDRESS ANALYSIS ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

printf "%-18s %-30s %-20s\n" "MAC Address" "Vendor" "Device Type" >> "$REPORT_FILE"
printf "%-18s %-30s %-20s\n" "-------------------" "------------------------------" "--------------------" >> "$REPORT_FILE"

while read -r mac_addr; do
    if [ -n "$mac_addr" ]; then
        # Extract OUI (first 3 octets)
        oui=$(echo "$mac_addr" | cut -d: -f1-3)
        
        # Look up vendor
        vendor=$(lookup_mac_vendor "$oui")
        
        # Categorize device
        device_type=$(categorize_device "$vendor")
        
        # Format output
        printf "%-18s %-30s %-20s\n" "$mac_addr" "$vendor" "$device_type" >> "$REPORT_FILE"
    fi
done < "$TEMP_DIR/all_macs.txt"

echo >> "$REPORT_FILE"

# Vendor statistics
echo "--- VENDOR STATISTICS ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Top vendors by MAC address count:" >> "$REPORT_FILE"
while read -r mac_addr; do
    if [ -n "$mac_addr" ]; then
        oui=$(echo "$mac_addr" | cut -d: -f1-3)
        vendor=$(lookup_mac_vendor "$oui")
        echo "$vendor"
    fi
done < "$TEMP_DIR/all_macs.txt" | sort | uniq -c | sort -nr | head -10 | \
    while read -r count vendor; do
        printf "  %-30s %s\n" "$vendor" "$count" >> "$REPORT_FILE"
    done

echo >> "$REPORT_FILE"

# Device type statistics
echo "--- DEVICE TYPE STATISTICS ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Device categories:" >> "$REPORT_FILE"
while read -r mac_addr; do
    if [ -n "$mac_addr" ]; then
        oui=$(echo "$mac_addr" | cut -d: -f1-3)
        vendor=$(lookup_mac_vendor "$oui")
        device_type=$(categorize_device "$vendor")
        echo "$device_type"
    fi
done < "$TEMP_DIR/all_macs.txt" | sort | uniq -c | sort -nr | \
    while read -r count device_type; do
        printf "  %-20s %s\n" "$device_type" "$count" >> "$REPORT_FILE"
    done

echo >> "$REPORT_FILE"

# Multicast and broadcast analysis
echo "--- MULTICAST AND BROADCAST ANALYSIS ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Multicast MAC addresses:" >> "$REPORT_FILE"
tshark -r "$capture_file" -T fields -e eth.dst 2>/dev/null | \
    grep -E "^01:|^33:" | sort -u | head -10 | \
    while read -r mac_addr; do
        echo "  $mac_addr" >> "$REPORT_FILE"
    done

echo >> "$REPORT_FILE"

echo "Broadcast traffic:" >> "$REPORT_FILE"
broadcast_count=$(tshark -r "$capture_file" -Y "eth.dst==ff:ff:ff:ff:ff:ff" 2>/dev/null | wc -l)
echo "  Broadcast packets: $broadcast_count" >> "$REPORT_FILE"

echo >> "$REPORT_FILE"

# Security analysis
echo "--- SECURITY ANALYSIS ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Check for MAC address randomization
echo "MAC address randomization analysis:" >> "$REPORT_FILE"
locally_administered=$(tshark -r "$capture_file" -T fields -e eth.src 2>/dev/null | \
    grep -E "^.[26ae]:" | sort -u | wc -l)
globally_unique=$(tshark -r "$capture_file" -T fields -e eth.src 2>/dev/null | \
    grep -vE "^.[26ae]:" | sort -u | wc -l)

echo "  Locally administered addresses: $locally_administered" >> "$REPORT_FILE"
echo "  Globally unique addresses: $globally_unique" >> "$REPORT_FILE"

if [ "$locally_administered" -gt 0 ]; then
    echo "  ℹ️  Locally administered addresses detected - possible MAC randomization" >> "$REPORT_FILE"
fi

echo >> "$REPORT_FILE"

# Unknown vendor analysis
echo "Unknown vendor analysis:" >> "$REPORT_FILE"
unknown_count=$(while read -r mac_addr; do
    if [ -n "$mac_addr" ]; then
        oui=$(echo "$mac_addr" | cut -d: -f1-3)
        vendor=$(lookup_mac_vendor "$oui")
        if [ "$vendor" = "Unknown" ]; then
            echo "$mac_addr"
        fi
    fi
done < "$TEMP_DIR/all_macs.txt" | wc -l)

echo "  Unknown vendor MAC addresses: $unknown_count" >> "$REPORT_FILE"

if [ "$unknown_count" -gt 0 ]; then
    echo "  ⚠️  Unknown vendors detected - possible custom/private devices" >> "$REPORT_FILE"
    echo "  Unknown MAC addresses:" >> "$REPORT_FILE"
    while read -r mac_addr; do
        if [ -n "$mac_addr" ]; then
            oui=$(echo "$mac_addr" | cut -d: -f1-3)
            vendor=$(lookup_mac_vendor "$oui")
            if [ "$vendor" = "Unknown" ]; then
                echo "    $mac_addr" >> "$REPORT_FILE"
            fi
        fi
    done < "$TEMP_DIR/all_macs.txt"
fi

echo >> "$REPORT_FILE"

# Recommendations
echo "--- RECOMMENDATIONS ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Network security recommendations:" >> "$REPORT_FILE"
echo "- Monitor for unknown MAC addresses that appear frequently" >> "$REPORT_FILE"
echo "- Implement MAC address filtering on critical network segments" >> "$REPORT_FILE"
echo "- Be aware that MAC addresses can be spoofed" >> "$REPORT_FILE"
echo "- Consider MAC address randomization as a privacy feature" >> "$REPORT_FILE"

if [ "$unknown_count" -gt 5 ]; then
    echo "- High number of unknown vendors detected - investigate further" >> "$REPORT_FILE"
fi

if [ "$locally_administered" -gt 10 ]; then
    echo "- Significant MAC randomization detected - normal for modern mobile devices" >> "$REPORT_FILE"
fi

echo >> "$REPORT_FILE"
echo "Analysis completed at $(date)" >> "$REPORT_FILE"

echo "Analysis complete!"
echo "Report saved to: $REPORT_FILE"
echo
echo "Summary:"
echo "- Total MAC addresses analyzed: $(wc -l < "$TEMP_DIR/all_macs.txt")"
echo "- Unknown vendor addresses: $unknown_count"
echo "- Locally administered addresses: $locally_administered"
echo
echo "Opening report..."
echo
cat "$REPORT_FILE"