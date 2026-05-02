#!/bin/sh

# ARP Table Ingestion Script
# Snapshots the local ARP table, parses entries, and outputs structured results
# for correlation engine consumption.

. "$(dirname "$0")/../common/utils.sh"
. "$(dirname "$0")/../common/colors.sh" 2>/dev/null || true
. "$(dirname "$0")/../common/logging.sh" 2>/dev/null || true
. "$(dirname "$0")/../common/validation.sh" 2>/dev/null || true
SCRIPT_NAME="$(basename "$0")"

echo "=== ARP Table Ingestion ==="
log_info "=== Script started ===" "$SCRIPT_NAME"
echo

WORKDIR="${NETUTIL_WORKDIR:-$HOME}"
WORKDIR="${WORKDIR%/}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_BASE="$WORKDIR/discovery/arp"
SESSION_DIR="$RESULTS_BASE/arp_ingest_${TIMESTAMP}"

mkdir -p "$SESSION_DIR"

# Temporary file for parsed entries (IP MAC INTERFACE STATE)
TEMP_ENTRIES="${SESSION_DIR}/.entries_$$"
> "$TEMP_ENTRIES"

ENTRY_COUNT=0
SKIP_COUNT=0

# =============================================================================
# Phase 1: Capture ARP table
# =============================================================================

print_phase_header "Phase 1: Capture ARP Table"

ARP_RAW="$SESSION_DIR/arp_raw.txt"

if command -v ip >/dev/null 2>&1; then
    log_info "Using 'ip neigh' to capture ARP table" "$SCRIPT_NAME"
    ip neigh show > "$ARP_RAW" 2>/dev/null
    CAPTURE_TOOL="ip"
else
    log_info "Falling back to 'arp -an' to capture ARP table" "$SCRIPT_NAME"
    arp -an > "$ARP_RAW" 2>/dev/null
    CAPTURE_TOOL="arp"
fi

if [ ! -s "$ARP_RAW" ]; then
    error_message "ARP table is empty or could not be read"
    log_error "ARP table empty or unreadable" "$SCRIPT_NAME"
    rm -f "$TEMP_ENTRIES"
    exit 1
fi

RAW_LINES=$(wc -l < "$ARP_RAW")
success_message "Captured ARP table ($RAW_LINES lines) using '$CAPTURE_TOOL'"
log_info "Raw ARP output saved: $ARP_RAW ($RAW_LINES lines)" "$SCRIPT_NAME"

# =============================================================================
# Phase 2: Parse and structure
# =============================================================================

print_phase_header "Phase 2: Parse and Structure"

print_subphase "Parsing ARP entries"

normalize_mac() {
    echo "$1" | tr '[:lower:]' '[:upper:]'
}

_escape_xml() { sed 's/&/\&amp;/g;s/</\&lt;/g;s/>/\&gt;/g'; }

if [ "$CAPTURE_TOOL" = "ip" ]; then
    # ip neigh format: IP dev INTERFACE lladdr MAC [router] STATUS
    # e.g.: 192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
    # Also handle entries without lladdr (INCOMPLETE entries)
    while IFS= read -r line; do
        # Skip empty lines
        [ -z "$line" ] && continue

        ip_addr=$(echo "$line" | awk '{print $1}')

        # Look for lladdr field
        mac_addr=""
        iface=""
        state=""

        # Parse: IP dev IFACE [lladdr MAC] [router] STATE
        set -- $line
        _ip="$1"
        shift # skip IP
        if [ "$1" = "dev" ]; then
            shift
            iface="$1"
            shift
        fi

        # Walk remaining tokens looking for lladdr and state
        while [ $# -gt 0 ]; do
            case "$1" in
                lladdr)
                    shift
                    mac_addr="${1:-}"
                    shift
                    ;;
                router)
                    shift
                    ;;
                *)
                    # Last non-special token is the state
                    state="$1"
                    shift
                    ;;
            esac
        done

        # Skip incomplete entries
        if [ -z "$mac_addr" ] || [ "$mac_addr" = "<incomplete>" ]; then
            SKIP_COUNT=$((SKIP_COUNT + 1))
            log_debug "Skipping incomplete entry: $ip_addr" "$SCRIPT_NAME"
            continue
        fi

        mac_addr=$(normalize_mac "$mac_addr")
        echo "${ip_addr} ${mac_addr} ${iface} ${state}" >> "$TEMP_ENTRIES"
        ENTRY_COUNT=$((ENTRY_COUNT + 1))
    done < "$ARP_RAW"
else
    # arp -an format: ? (IP) at MAC [ether] on IFACE
    # e.g.: ? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0
    while IFS= read -r line; do
        [ -z "$line" ] && continue

        # Extract IP from ? (IP)
        ip_addr=$(echo "$line" | sed -n 's/.*(\([^)]*\)).*/\1/p')

        # Extract MAC from 'at MAC'
        mac_addr=$(echo "$line" | sed -n 's/.*at \([^ ]*\).*/\1/p')

        # Extract interface from 'on IFACE'
        iface=$(echo "$line" | sed -n 's/.*on \([^ ]*\).*/\1/p')

        # Skip incomplete / no-MAC entries
        if [ -z "$mac_addr" ] || [ "$mac_addr" = "<incomplete>" ] || [ "$mac_addr" = "(incomplete)" ]; then
            SKIP_COUNT=$((SKIP_COUNT + 1))
            log_debug "Skipping incomplete entry: $ip_addr" "$SCRIPT_NAME"
            continue
        fi

        mac_addr=$(normalize_mac "$mac_addr")
        state="UNKNOWN"
        echo "${ip_addr} ${mac_addr} ${iface} ${state}" >> "$TEMP_ENTRIES"
        ENTRY_COUNT=$((ENTRY_COUNT + 1))
    done < "$ARP_RAW"
fi

success_message "Parsed $ENTRY_COUNT entries (skipped $SKIP_COUNT incomplete)"
log_info "Parsed entries: $ENTRY_COUNT valid, $SKIP_COUNT skipped" "$SCRIPT_NAME"

# =============================================================================
# Phase 3: Output results
# =============================================================================

print_phase_header "Phase 3: Output Results"

# --- XML output ---
print_subphase "Generating XML output"
XML_FILE="$SESSION_DIR/arp_results.xml"

{
    echo '<?xml version="1.0" encoding="UTF-8"?>'
    echo "<arp_results>"
    echo "  <metadata>"
    echo "    <timestamp>$(date -Iseconds)</timestamp>"
    echo "    <source>$CAPTURE_TOOL</source>"
    echo "    <entry_count>$ENTRY_COUNT</entry_count>"
    echo "  </metadata>"
    while read -r ip mac iface state; do
        _e_ip=$(echo "$ip" | _escape_xml)
        _e_mac=$(echo "$mac" | _escape_xml)
        _e_iface=$(echo "$iface" | _escape_xml)
        _e_state=$(echo "$state" | _escape_xml)
        echo "  <entry ip=\"$_e_ip\" mac=\"$_e_mac\" interface=\"$_e_iface\" state=\"$_e_state\"/>"
    done < "$TEMP_ENTRIES"
    echo "</arp_results>"
} > "$XML_FILE"

success_message "XML output: $XML_FILE"
log_info "XML output written: $XML_FILE" "$SCRIPT_NAME"

# --- Summary text report ---
print_subphase "Generating summary report"
REPORT_FILE="$SESSION_DIR/arp_summary.txt"

{
    echo "=== ARP Table Ingestion Summary ==="
    echo "Timestamp : $(date)"
    echo "Source    : $CAPTURE_TOOL"
    echo "Session   : $SESSION_DIR"
    echo
    echo "Total entries: $ENTRY_COUNT"
    echo "Skipped     : $SKIP_COUNT (incomplete/no MAC)"
    echo
    echo "--- ARP Entries ---"
    printf "%-40s %-18s %-12s %-12s\n" "IP Address" "MAC Address" "Interface" "State"
    printf "%-40s %-18s %-12s %-12s\n" "----------------------------------------" "------------------" "------------" "------------"
    while read -r ip mac iface state; do
        printf "%-40s %-18s %-12s %-12s\n" "$ip" "$mac" "$iface" "$state"
    done < "$TEMP_ENTRIES"

    # Per-interface breakdown
    echo
    echo "--- Per-Interface Summary ---"
    awk '{print $3}' "$TEMP_ENTRIES" | sort | uniq -c | sort -nr | while read -r count iface; do
        printf "  %-20s %s entries\n" "$iface" "$count"
    done

    # Per-state breakdown
    echo
    echo "--- Per-State Summary ---"
    awk '{print $4}' "$TEMP_ENTRIES" | sort | uniq -c | sort -nr | while read -r count state; do
        printf "  %-20s %s entries\n" "$state" "$count"
    done
} > "$REPORT_FILE"

success_message "Summary report: $REPORT_FILE"
log_info "Summary report written: $REPORT_FILE" "$SCRIPT_NAME"

# Clean up temp file
rm -f "$TEMP_ENTRIES"

echo
echo "=== Results ==="
echo "  Session directory: $SESSION_DIR"
echo "  Raw ARP table:    $ARP_RAW"
echo "  XML results:      $XML_FILE"
echo "  Summary report:   $REPORT_FILE"
echo

log_info "=== Script completed: $ENTRY_COUNT entries ingested ===" "$SCRIPT_NAME"
