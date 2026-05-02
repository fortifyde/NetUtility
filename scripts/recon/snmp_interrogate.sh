#!/bin/sh

# SNMP Device Interrogation Script
# Queries SNMP-enabled devices for system info, interfaces, ARP tables, VLANs, and routes.
# Supports SNMPv2c with configurable community strings.

# shellcheck source=../common/utils.sh
. "$(dirname "$0")/../common/utils.sh"
# shellcheck source=../common/colors.sh
. "$(dirname "$0")/../common/colors.sh" 2>/dev/null || true
# shellcheck source=../common/logging.sh
. "$(dirname "$0")/../common/logging.sh"
# shellcheck source=../common/validation.sh
. "$(dirname "$0")/../common/validation.sh" 2>/dev/null || true

SCRIPT_NAME="$(basename "$0")"

# Check for snmpwalk dependency
if ! command -v snmpwalk >/dev/null 2>&1; then
    warning_message "snmpwalk not found. Install net-snmp package to use this script."
    log_error "snmpwalk not found on system" "$SCRIPT_NAME"
    echo "  On Debian/Ubuntu: sudo apt install snmp" >&2
    echo "  On RHEL/Fedora:   sudo dnf install net-snmp-utils" >&2
    echo "  On Arch:          sudo pacman -S net-snmp" >&2
    exit 1
fi

SNMPWALK_VERSION=$(snmpwalk --version 2>&1 || true)
log_debug "snmpwalk available: $SNMPWALK_VERSION" "$SCRIPT_NAME"

print_phase_header "SNMP Device Interrogation"
log_info "=== Script started ===" "$SCRIPT_NAME"
echo >&2
echo "This script interrogates SNMP-enabled network devices for:"
echo "  - System description and uptime"
echo "  - Interface table (names, speeds, status, counters)"
echo "  - ARP/cache table entries"
echo "  - VLAN membership (Cisco)"
echo "  - Routing table entries"
echo >&2

# Setup results directory
WORKDIR="${NETUTIL_WORKDIR:-$HOME}"
RESULTS_BASE="$WORKDIR/scans/snmp"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SESSION_DIR="$RESULTS_BASE/snmp_${TIMESTAMP}"
mkdir -p "$SESSION_DIR"

# Output files
RAW_OUTPUT="$SESSION_DIR/snmp_walk_output.txt"
XML_OUTPUT="$SESSION_DIR/snmp_device_info.xml"
SUMMARY_OUTPUT="$SESSION_DIR/snmp_summary.txt"

SNMP_TIMEOUT=10
SNMP_RETRIES=1

# ===========================================================================
# Phase 1: Target Selection + Community String Configuration
# ===========================================================================
emit_progress "Target Selection and Configuration" 1 3
print_subphase "Phase 1: Target Selection and Configuration"

# Try to auto-discover SNMP hostlists from discovery sessions
_snmp_hostlists=""
if [ -d "$WORKDIR/discovery" ]; then
    # Find the most recent snmp_targets.txt from multi-phase discovery
    _snmp_hostlists=$(find "$WORKDIR/discovery" -name "snmp_targets.txt" -path "*/service_targets/*" 2>/dev/null | sort -r | head -5)
fi

if [ -n "$_snmp_hostlists" ]; then
    echo "Found SNMP target lists from previous discovery:" >&2
    _hl_num=0
    echo "$_snmp_hostlists" | while IFS= read -r _hl_file; do
        _hl_num=$((_hl_num + 1))
        _hl_count=$(wc -l < "$_hl_file" 2>/dev/null || echo 0)
        # Show relative path from workspace for readability
        _hl_display=$(echo "$_hl_file" | sed "s|^$WORKDIR/||")
        printf "  %d) %s (%s hosts)\n" "$_hl_num" "$_hl_display" "$_hl_count" >&2
    done
    _hl_total=$(echo "$_snmp_hostlists" | wc -l | tr -d ' ')
    _hl_next=$((_hl_total + 1))
    echo "  $_hl_next) Manual target selection" >&2
    echo >&2
    _hl_choice=$(prompt_for_choice "Select target source" 1 "$_hl_next")

    if [ "$_hl_choice" -ge 1 ] && [ "$_hl_choice" -le "$_hl_total" ]; then
        # Use the selected hostlist
        _hl_selected=$(echo "$_snmp_hostlists" | sed -n "${_hl_choice}p")
        _hl_host_count=$(wc -l < "$_hl_selected" 2>/dev/null || echo 0)
        target="-iL $_hl_selected"
        success_message "Using SNMP target list: $_hl_selected ($_hl_host_count hosts)"
        log_info "Using discovered SNMP hostlist: $_hl_selected" "$SCRIPT_NAME"
    else
        target=$(select_target "Select SNMP target")
    fi
else
    target=$(select_target "Select SNMP target")
fi
if [ -z "$target" ]; then
    log_error "No target selected" "$SCRIPT_NAME"
    error_message "No target selected"
    exit 1
fi

# Determine target list
TARGETS=""
TARGET_FILE=""
case "$target" in
    -iL\ *)
        TARGET_FILE="${target#-iL }"
        if [ ! -f "$TARGET_FILE" ]; then
            error_message "Target file not found: $TARGET_FILE"
            exit 1
        fi
        TARGETS=$(grep -v '^\s*#' "$TARGET_FILE" | grep -v '^\s*$' | tr '\n' ' ')
        ;;
    */*)
        # CIDR range - expand with nmap or similar
        warning_message "CIDR ranges require individual host scanning. Using as single target."
        TARGETS="$target"
        ;;
    *)
        TARGETS="$target"
        ;;
esac

if [ -z "$TARGETS" ]; then
    error_message "No valid targets specified"
    exit 1
fi

success_message "Target(s): $TARGETS"
log_info "SNMP targets: $TARGETS" "$SCRIPT_NAME"

# Community string configuration
echo >&2
echo "SNMP Community String Configuration:" >&2
echo "  1) Use default community string (public)" >&2
echo "  2) Use custom community strings" >&2
echo "  3) Use default + custom community strings" >&2
echo >&2

community_choice=$(prompt_for_choice "Select community string mode" 1 3)

COMMUNITIES=""
validate_community() {
    _vc_val="$1"
    # Allow only alphanumeric, underscore, hyphen, and at-sign
    if echo "$_vc_val" | grep -qE '^[a-zA-Z0-9_@-]+$'; then
        return 0
    fi
    return 1
}

case "$community_choice" in
    1)
        COMMUNITIES="public"
        ;;
    2)
        while true; do
            echo >&2
            if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
                printf "%sEnter community string: %s" "$PROMPT_COLOR" "$COLOR_RESET" >&2
            else
                printf "Enter community string: " >&2
            fi
            read -r custom_community
            if [ -z "$custom_community" ]; then
                warning_message "Community string cannot be empty"
                continue
            fi
            if validate_community "$custom_community"; then
                COMMUNITIES="$custom_community"
                break
            else
                warning_message "Community string contains invalid characters. Use alphanumeric, _, -, or @"
            fi
        done
        ;;
    3)
        COMMUNITIES="public"
        while true; do
            echo >&2
            if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
                printf "%sEnter additional community string (empty to finish): %s" "$PROMPT_COLOR" "$COLOR_RESET" >&2
            else
                printf "Enter additional community string (empty to finish): " >&2
            fi
            read -r custom_community
            if [ -z "$custom_community" ]; then
                break
            fi
            if validate_community "$custom_community"; then
                COMMUNITIES="$COMMUNITIES $custom_community"
            else
                warning_message "Community string contains invalid characters. Use alphanumeric, _, -, or @"
            fi
        done
        ;;
esac

log_info "Community strings configured: $(echo "$COMMUNITIES" | wc -w | tr -d ' ') string(s)" "$SCRIPT_NAME"
success_message "Community strings configured"

# ===========================================================================
# Helper: try snmpwalk with each community string until one works
# ===========================================================================
try_snmpwalk() {
    _ts_oid="$1"
    _ts_host="$2"
    _ts_output_file="$3"

    for _comm in $COMMUNITIES; do
        _result=$(snmpwalk -v2c -c "$_comm" -t "$SNMP_TIMEOUT" -r "$SNMP_RETRIES" "$_ts_host" "$_ts_oid" 2>/dev/null) || continue
        if [ -n "$_result" ]; then
            echo "$_result" >> "$_ts_output_file"
            echo "$_result"
            return 0
        fi
    done
    return 1
}

try_snmpget() {
    _tg_oid="$1"
    _tg_host="$2"

    for _comm in $COMMUNITIES; do
        _result=$(snmpget -v2c -c "$_comm" -t "$SNMP_TIMEOUT" -r "$SNMP_RETRIES" "$_tg_host" "$_tg_oid" 2>/dev/null) || continue
        if [ -n "$_result" ]; then
            echo "$_result"
            return 0
        fi
    done
    return 1
}

# Extract string value from SNMP result: ... = STRING: "value"
snmp_extract_string() {
    echo "$1" | sed -n 's/.*=.*STRING: *\(".*"\|.*\)/\1/p' | sed 's/^"//;s/"$//' | head -1
}

# Extract integer value from SNMP result: ... = INTEGER: 42
snmp_extract_int() {
    echo "$1" | sed -n 's/.*=.*INTEGER: *\(.*\)/\1/p' | head -1
}

# Extract Timeticks value: ... = Timeticks: (12345) 0:02:03.45
snmp_extract_timeticks() {
    echo "$1" | sed -n 's/.*=.*Timeticks: *(.*) *\(.*\)/\1/p' | head -1
}

# Extract Hex-STRING as MAC address
snmp_extract_mac() {
    echo "$1" | sed -n 's/.*=.*Hex-STRING: *\(.*\)/\1/p' | head -1 | \
        sed 's/ \+/:/g' | sed 's/^://;s/:$//' | tr 'A-F' 'a-f'
}

# Extract IP address from SNMP result
snmp_extract_ip() {
    echo "$1" | sed -n 's/.*=.*IpAddress: *\(.*\)/\1/p' | head -1
}

# ===========================================================================
# Phase 2: SNMP Walks
# ===========================================================================
emit_progress "SNMP Walks" 2 3
print_subphase "Phase 2: SNMP Device Walks"

echo "=== SNMP Walk Output ===" > "$RAW_OUTPUT"
echo "Scan started: $(date)" >> "$RAW_OUTPUT"
echo "Targets: $TARGETS" >> "$RAW_OUTPUT"
echo "" >> "$RAW_OUTPUT"

# Initialize XML file
echo '<?xml version="1.0" encoding="UTF-8"?>' > "$XML_OUTPUT"
echo '<snmp_results>' >> "$XML_OUTPUT"

# Temp file cleanup on early exit
_CLEANUP_FILES=""
_cleanup() { [ -n "$_CLEANUP_FILES" ] && rm -f $_CLEANUP_FILES; }
trap _cleanup INT TERM EXIT

for host in $TARGETS; do
    log_info "Interrogating host: $host" "$SCRIPT_NAME"
    echo "" >&2
    echo "--- Interrogating $host ---" >&2

    echo "" >> "$RAW_OUTPUT"
    echo "========================================" >> "$RAW_OUTPUT"
    echo "Host: $host" >> "$RAW_OUTPUT"
    echo "========================================" >> "$RAW_OUTPUT"
    echo "" >> "$RAW_OUTPUT"

    # -- System Description and Uptime --
    echo "  Querying system information..." >&2
    sys_desc_result=$(try_snmpget "1.3.6.1.2.1.1.1.0" "$host" "$RAW_OUTPUT")
    sys_uptime_result=$(try_snmpget "1.3.6.1.2.1.1.3.0" "$host" "$RAW_OUTPUT")
    sys_name_result=$(try_snmpget "1.3.6.1.2.1.1.5.0" "$host" "$RAW_OUTPUT")

    sys_desc=$(snmp_extract_string "$sys_desc_result")
    sys_uptime=$(snmp_extract_timeticks "$sys_uptime_result")
    sys_hostname=$(snmp_extract_string "$sys_name_result")

    if [ -z "$sys_desc" ] && [ -z "$sys_uptime" ]; then
        warning_message "No SNMP response from $host (timeout or wrong community string)"
        log_info "No SNMP response from $host" "$SCRIPT_NAME"
        echo "  <device ip=\"${host}\">" >> "$XML_OUTPUT"
        echo "    <error>No SNMP response received</error>" >> "$XML_OUTPUT"
        echo "  </device>" >> "$XML_OUTPUT"
        echo "SNMP query to $host failed - no response" >> "$RAW_OUTPUT"
        continue
    fi

    success_message "System info retrieved for $host"

    # -- Interface Table --
    echo "  Querying interface table..." >&2
    echo "" >> "$RAW_OUTPUT"
    echo "--- Interface Table (1.3.6.1.2.1.2.2.1) ---" >> "$RAW_OUTPUT"
    if_walk=$(try_snmpwalk "1.3.6.1.2.1.2.2.1" "$host" "$RAW_OUTPUT" 2>/dev/null || echo "")

    # Parse interface data into temp files
    IF_NAMES_FILE=$(mktemp)
    IF_STATUS_FILE=$(mktemp)
    IF_SPEED_FILE=$(mktemp)
    IF_OCTETS_IN_FILE=$(mktemp)
    IF_OCTETS_OUT_FILE=$(mktemp)
_CLEANUP_FILES="$_CLEANUP_FILES $IF_NAMES_FILE $IF_STATUS_FILE $IF_SPEED_FILE $IF_OCTETS_IN_FILE $IF_OCTETS_OUT_FILE"

    # ifDescr (1.3.6.1.2.1.2.2.1.2)
    echo "$if_walk" | grep "1.3.6.1.2.1.2.2.1.2\." > "$IF_NAMES_FILE" 2>/dev/null || true
    # ifOperStatus (1.3.6.1.2.1.2.2.1.8) - 1=up, 2=down, 3=testing
    echo "$if_walk" | grep "1.3.6.1.2.1.2.2.1.8\." > "$IF_STATUS_FILE" 2>/dev/null || true
    # ifHighSpeed (1.3.6.1.2.1.31.1.1.1.15) or ifSpeed (1.3.6.1.2.1.2.2.1.5)
    high_speed=$(try_snmpwalk "1.3.6.1.2.1.31.1.1.1.15" "$host" "$RAW_OUTPUT" 2>/dev/null || echo "")
    if [ -z "$high_speed" ]; then
        echo "$if_walk" | grep "1.3.6.1.2.1.2.2.1.5\." > "$IF_SPEED_FILE" 2>/dev/null || true
    else
        echo "$high_speed" > "$IF_SPEED_FILE"
    fi
    # ifHCInOctets (1.3.6.1.2.1.31.1.1.1.6) or ifInOctets (1.3.6.1.2.1.2.2.1.10)
    hc_in=$(try_snmpwalk "1.3.6.1.2.1.31.1.1.1.6" "$host" "$RAW_OUTPUT" 2>/dev/null || echo "")
    if [ -z "$hc_in" ]; then
        echo "$if_walk" | grep "1.3.6.1.2.1.2.2.1.10\." > "$IF_OCTETS_IN_FILE" 2>/dev/null || true
    else
        echo "$hc_in" > "$IF_OCTETS_IN_FILE"
    fi
    # ifHCOutOctets (1.3.6.1.2.1.31.1.1.1.10) or ifOutOctets (1.3.6.1.2.1.2.2.1.16)
    hc_out=$(try_snmpwalk "1.3.6.1.2.1.31.1.1.1.10" "$host" "$RAW_OUTPUT" 2>/dev/null || echo "")
    if [ -z "$hc_out" ]; then
        echo "$if_walk" | grep "1.3.6.1.2.1.2.2.1.16\." > "$IF_OCTETS_OUT_FILE" 2>/dev/null || true
    else
        echo "$hc_out" > "$IF_OCTETS_OUT_FILE"
    fi

    # -- ARP Table --
    echo "  Querying ARP table..." >&2
    echo "" >> "$RAW_OUTPUT"
    echo "--- ARP Table (1.3.6.1.2.1.4.22.1) ---" >> "$RAW_OUTPUT"
    arp_walk=$(try_snmpwalk "1.3.6.1.2.1.4.22.1" "$host" "$RAW_OUTPUT" 2>/dev/null || echo "")

    # -- VLAN Membership (Cisco) --
    echo "  Querying VLAN membership..." >&2
    echo "" >> "$RAW_OUTPUT"
    echo "--- VLAN Membership (1.3.6.1.4.1.9.9.46.2.1.5.1) ---" >> "$RAW_OUTPUT"
    vlan_walk=$(try_snmpwalk "1.3.6.1.4.1.9.9.46.2.1.5.1" "$host" "$RAW_OUTPUT" 2>/dev/null || echo "")
    # Also try VLAN name table
    vlan_name_walk=$(try_snmpwalk "1.3.6.1.4.1.9.9.46.1.3.1.1.4.1" "$host" "$RAW_OUTPUT" 2>/dev/null || echo "")

    # -- Routing Table --
    echo "  Querying routing table..." >&2
    echo "" >> "$RAW_OUTPUT"
    echo "--- Routing Table (1.3.6.1.2.1.4.21) ---" >> "$RAW_OUTPUT"
    route_walk=$(try_snmpwalk "1.3.6.1.2.1.4.21" "$host" "$RAW_OUTPUT" 2>/dev/null || echo "")

    success_message "SNMP walks complete for $host"

    # Build XML device element for this host
    echo "  <device ip=\"${host}\">" >> "$XML_OUTPUT"
    echo "    <sys_description>$(echo "$sys_desc" | sed 's/&/\&amp;/g;s/</\&lt;/g;s/>/\&gt;/g')</sys_description>" >> "$XML_OUTPUT"
    echo "    <sys_uptime>${sys_uptime}</sys_uptime>" >> "$XML_OUTPUT"
    echo "    <hostname>${sys_hostname}</hostname>" >> "$XML_OUTPUT"

    # -- Interfaces XML --
    echo "    <interfaces>" >> "$XML_OUTPUT"

    while IFS= read -r line; do
        [ -z "$line" ] && continue
        # Extract index from OID: .1.3.6.1.2.1.2.2.1.2.N = STRING: "name"
        idx=$(echo "$line" | sed -n 's/.*1\.3\.6\.1\.2\.1\.2\.2\.1\.2\.\([0-9]*\).*/\1/p')
        [ -z "$idx" ] && continue

        if_name=$(echo "$line" | sed 's/.*=.*STRING: *//' | sed 's/^"//;s/"$//')

        # Find status for this index
        if_status_raw=$(grep "1.3.6.1.2.1.2.2.1.8\.${idx}" "$IF_STATUS_FILE" 2>/dev/null | head -1)
        if_status_int=$(snmp_extract_int "$if_status_raw")
        case "$if_status_int" in
            1) if_status="up" ;;
            2) if_status="down" ;;
            3) if_status="testing" ;;
            *) if_status="unknown" ;;
        esac

        # Find speed for this index
        if_speed_val=""
        speed_line=$(grep "1.3.6.1.2.1.31.1.1.1.15\.${idx}\|1.3.6.1.2.1.2.2.1.5\.${idx}" "$IF_SPEED_FILE" 2>/dev/null | head -1)
        if [ -n "$speed_line" ]; then
            if_speed_val=$(snmp_extract_int "$speed_line")
            # ifHighSpeed is in Mbps, ifSpeed is in bps
            if echo "$speed_line" | grep -q "1.3.6.1.2.1.31.1.1.1.15"; then
                if_speed_val="${if_speed_val}000000"
            fi
        fi

        # XML-escape the interface name
        if_name_escaped=$(echo "$if_name" | sed 's/&/\&amp;/g;s/</\&lt;/g;s/>/\&gt;/g')

        echo "      <interface>" >> "$XML_OUTPUT"
        echo "        <name>${if_name_escaped}</name>" >> "$XML_OUTPUT"
        echo "        <status>${if_status}</status>" >> "$XML_OUTPUT"
        if [ -n "$if_speed_val" ]; then
            echo "        <speed>${if_speed_val}</speed>" >> "$XML_OUTPUT"
        fi
        echo "      </interface>" >> "$XML_OUTPUT"
    done < "$IF_NAMES_FILE"

    echo "    </interfaces>" >> "$XML_OUTPUT"

    # Cleanup temp files
    rm -f "$IF_NAMES_FILE" "$IF_STATUS_FILE" "$IF_SPEED_FILE" "$IF_OCTETS_IN_FILE" "$IF_OCTETS_OUT_FILE"

    # -- ARP Entries XML --
    echo "    <arp_entries>" >> "$XML_OUTPUT"

    # ipNetToMediaPhysAddress (1.3.6.1.2.1.4.22.1.2)
    echo "$arp_walk" | grep "1.3.6.1.2.1.4.22.1.2\." | while IFS= read -r line; do
        [ -z "$line" ] && continue
        # OID: .1.3.6.1.2.1.4.22.1.2.ifindex.ipaddr
        mac_raw=$(snmp_extract_mac "$line")
        [ -z "$mac_raw" ] && continue

        # Extract IP from OID suffix: the last 4 octets after the ifindex
        oid_suffix=$(echo "$line" | sed -n 's/.*1\.3\.6\.1\.2\.1\.4\.22\.1\.2\.\(.*\)=.*/\1/p' | sed 's/ *$//')
        # Remove leading ifindex: first number followed by dots
        ip_part=$(echo "$oid_suffix" | sed 's/^[0-9]*\.//')
        arp_ip=$(echo "$ip_part" | tr '.' ' ' | awk '{print $1"."$2"."$3"."$4}')

        # Get the interface index from the OID
        if_idx=$(echo "$oid_suffix" | sed 's/\..*//')

        echo "      <entry mac=\"${mac_raw}\" ip=\"${arp_ip}\" interface=\"ifIndex.${if_idx}\"/>" >> "$XML_OUTPUT"
    done

    echo "    </arp_entries>" >> "$XML_OUTPUT"

    # -- VLANs XML --
    echo "    <vlans>" >> "$XML_OUTPUT"

    # Parse VLAN data from Cisco VLAN MIB
    echo "$vlan_walk" | while IFS= read -r line; do
        [ -z "$line" ] && continue
        vlan_val=$(snmp_extract_int "$line")
        [ -z "$vlan_val" ] && continue
        # Extract VLAN ID from OID suffix
        vlan_id=$(echo "$line" | sed -n 's/.*1\.3\.6\.1\.4\.1\.9\.9\.46\.2\.1\.5\.1\.\([0-9]*\).*/\1/p')
        [ -z "$vlan_id" ] && continue
        # Try to find VLAN name
        vlan_name=""
        if [ -n "$vlan_name_walk" ]; then
            vlan_name=$(echo "$vlan_name_walk" | grep "1.3.6.1.4.1.9.9.46.1.3.1.1.4.1\.${vlan_id}" | sed 's/.*=.*STRING: *//' | sed 's/^"//;s/"$//' | head -1)
        fi
        echo "      <vlan id=\"${vlan_id}\" name=\"${vlan_name:-VLAN${vlan_id}}\"/>" >> "$XML_OUTPUT"
    done

    echo "    </vlans>" >> "$XML_OUTPUT"

    # -- Routes XML --
    echo "    <routes>" >> "$XML_OUTPUT"

    # ipRouteDest (1.3.6.1.2.1.4.21.1.1) + ipRouteNextHop (1.3.6.1.2.1.4.21.1.7) + ipRouteIfIndex (1.3.6.1.2.1.4.21.1.2)
    route_dests=$(echo "$route_walk" | grep "1.3.6.1.2.1.4.21.1.1\.")
    echo "$route_dests" | while IFS= read -r line; do
        [ -z "$line" ] && continue
        dest_ip=$(echo "$line" | sed 's/.*=.*IpAddress: *//' | sed 's/.*=.*STRING: *//' | head -1)
        # Extract OID suffix (the destination IP from the OID itself)
        dest_suffix=$(echo "$line" | sed -n 's/.*1\.3\.6\.1\.2\.1\.4\.21\.1\.1\.\(.*\)=.*/\1/p' | sed 's/ *$//')
        [ -z "$dest_ip" ] && dest_ip=$(echo "$dest_suffix" | tr '.' ' ' | awk '{print $1"."$2"."$3"."$4}')

        # Find corresponding next hop
        gateway=""
        if [ -n "$dest_suffix" ]; then
            gateway_line=$(echo "$route_walk" | grep "1.3.6.1.2.1.4.21.1.7\.${dest_suffix}" | head -1)
            gateway=$(echo "$gateway_line" | sed 's/.*=.*IpAddress: *//' | head -1)
        fi

        # Find corresponding interface index
        route_if=""
        if [ -n "$dest_suffix" ]; then
            rif_line=$(echo "$route_walk" | grep "1.3.6.1.2.1.4.21.1.2\.${dest_suffix}" | head -1)
            route_if=$(snmp_extract_int "$rif_line")
        fi

        # Get route mask for CIDR notation
        route_mask=""
        if [ -n "$dest_suffix" ]; then
            mask_line=$(echo "$route_walk" | grep "1.3.6.1.2.1.4.21.1.11\.${dest_suffix}" | head -1)
            route_mask=$(echo "$mask_line" | sed 's/.*=.*IpAddress: *//' | head -1)
        fi

        # Convert mask to CIDR prefix
        cidr=""
        if [ -n "$route_mask" ]; then
            cidr=$(echo "$route_mask" | tr '.' '\n' | while read -r octet; do
                echo "$octet" | awk '{printf "%08d", $1}'
            done | tr -d '1' | wc -c | awk '{print 32 - ($1 - 1)}')
        fi

        dest_cidr="${dest_ip}"
        [ -n "$cidr" ] && [ "$cidr" != "0" ] && dest_cidr="${dest_ip}/${cidr}"

        echo "      <route dest=\"${dest_cidr}\" gateway=\"${gateway}\" interface=\"ifIndex.${route_if}\"/>" >> "$XML_OUTPUT"
    done

    echo "    </routes>" >> "$XML_OUTPUT"
    echo "  </device>" >> "$XML_OUTPUT"

    success_message "XML generated for $host"
done

echo '</snmp_results>' >> "$XML_OUTPUT"

# ===========================================================================
# Phase 3: Generate Summary
# ===========================================================================
emit_progress "Generating Summary" 3 3
print_subphase "Phase 3: Generating Summary"

{
    echo "=========================================="
    echo "SNMP Device Interrogation Summary"
    echo "=========================================="
    echo ""
    echo "Scan Information:"
    echo "  Scan time: $(date)"
    echo "  Session directory: $SESSION_DIR"
    echo "  SNMP timeout: ${SNMP_TIMEOUT}s per host"
    echo "  Community strings tried: $(echo "$COMMUNITIES" | wc -w | tr -d ' ')"
    echo ""
    echo "=========================================="
    echo "Targets"
    echo "=========================================="
    echo ""

    for host in $TARGETS; do
        echo "--- $host ---"

        # Re-extract system info from raw output for summary
        sys_desc_line=$(grep -A0 "1.3.6.1.2.1.1.1.0.*=.*STRING:" "$RAW_OUTPUT" | tail -1)
        sys_desc_val=$(echo "$sys_desc_line" | sed 's/.*=.*STRING: *//' | sed 's/^"//;s/"$//')

        sys_name_line=$(grep -A0 "1.3.6.1.2.1.1.5.0.*=.*STRING:" "$RAW_OUTPUT" | tail -1)
        sys_name_val=$(echo "$sys_name_line" | sed 's/.*=.*STRING: *//' | sed 's/^"//;s/"$//')

        sys_uptime_line=$(grep -A0 "1.3.6.1.2.1.1.3.0.*=.*Timeticks:" "$RAW_OUTPUT" | tail -1)
        sys_uptime_val=$(echo "$sys_uptime_line" | sed -n 's/.*Timeticks: *(.*) *\(.*\)/\1/p')

        if [ -n "$sys_desc_val" ]; then
            echo "  System: $sys_desc_val"
        else
            echo "  System: No response"
        fi
        [ -n "$sys_name_val" ] && echo "  Hostname: $sys_name_val"
        [ -n "$sys_uptime_val" ] && echo "  Uptime: $sys_uptime_val"

        # Count interfaces
        if_count=$(grep -c "1.3.6.1.2.1.2.2.1.2\." "$RAW_OUTPUT" 2>/dev/null || echo "0")
        echo "  Interfaces found: $if_count"

        # Count ARP entries
        arp_count=$(grep -c "1.3.6.1.2.1.4.22.1.2\." "$RAW_OUTPUT" 2>/dev/null || echo "0")
        echo "  ARP entries: $arp_count"

        # Count routes
        route_count=$(grep -c "1.3.6.1.2.1.4.21.1.1\." "$RAW_OUTPUT" 2>/dev/null || echo "0")
        echo "  Route entries: $route_count"

        echo ""
    done

    echo "=========================================="
    echo "Output Files"
    echo "=========================================="
    echo ""
    echo "All outputs located in: $SESSION_DIR"
    echo ""
    echo "  snmp_walk_output.txt  - Raw snmpwalk output"
    echo "  snmp_device_info.xml  - Structured XML for parser consumption"
    echo "  snmp_summary.txt      - This summary report"
} > "$SUMMARY_OUTPUT"

success_message "Summary generated"

echo >&2
success_message "SNMP interrogation complete"
log_info "=== Script finished ===" "$SCRIPT_NAME"
echo "Results saved to: $SESSION_DIR" >&2
