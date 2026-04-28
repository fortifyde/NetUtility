#!/bin/sh

# LLDP/CDP Neighbor Discovery Script
# Captures LLDP and CDP frames to discover Layer-2 network topology:
# device hostnames, management IPs, interface mappings, device types, and VLANs.

# shellcheck source=../common/utils.sh
. "$(dirname "$0")/../common/utils.sh"
# shellcheck source=../common/colors.sh
. "$(dirname "$0")/../common/colors.sh" 2>/dev/null || true
# shellcheck source=../common/logging.sh
. "$(dirname "$0")/../common/logging.sh"
# shellcheck source=../common/validation.sh
. "$(dirname "$0")/../common/validation.sh" 2>/dev/null || true

SCRIPT_NAME="$(basename "$0")"

print_phase_header "LLDP/CDP Neighbor Discovery"
log_info "=== Script started ===" "$SCRIPT_NAME"
echo >&2
echo "This script discovers Layer-2 network neighbors via LLDP and CDP:"
echo "  - Device hostname and management IP"
echo "  - Local/remote interface mapping"
echo "  - Device type (switch, router, phone, AP)"
echo "  - VLAN advertisements"
echo >&2

# Setup results directory under workspace
WORKDIR="${NETUTIL_WORKDIR:-$HOME}"
RESULTS_BASE="$WORKDIR/discovery/lldp_cdp"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SESSION_DIR="$RESULTS_BASE/lldp_cdp_${TIMESTAMP}"
mkdir -p "$SESSION_DIR"

# Interface selection
interface=$(select_interface "Select interface for LLDP/CDP capture" "lldp_cdp")
if [ -z "$interface" ]; then
    log_error "No interface selected" "$SCRIPT_NAME"
    error_message "No interface selected"
    exit 1
fi

success_message "Selected interface: $interface"
log_info "Interface selected: $interface" "$SCRIPT_NAME"
echo >&2

# Capture duration
echo "Capture duration for LLDP/CDP frames:" >&2
echo "  LLDP frames are sent every 30 seconds by default." >&2
echo "  CDP frames are sent every 60 seconds by default." >&2
echo "  1) 90 seconds  - Quick (1 LLDP interval)" >&2
echo "  2) 180 seconds - Standard (recommended, 2 intervals)" >&2
echo "  3) 300 seconds - Comprehensive (5 minutes)" >&2
echo "  4) Custom duration" >&2
echo >&2
duration_choice=$(prompt_for_choice "Select capture duration" 2 4)

case "$duration_choice" in
    1) capture_duration=90 ;;
    2) capture_duration=180 ;;
    3) capture_duration=300 ;;
    4)
        capture_duration=$(get_validated_input "Enter duration in seconds" validate_positive_number "180")
        ;;
    *)  capture_duration=180 ;;
esac

log_info "Capture duration: ${capture_duration}s" "$SCRIPT_NAME"

# Output files
PCAP_FILE="$SESSION_DIR/lldp_cdp_capture.pcap"
LLDP_OUTPUT="$SESSION_DIR/lldp_neighbors.txt"
CDP_OUTPUT="$SESSION_DIR/cdp_neighbors.txt"
COMBINED_OUTPUT="$SESSION_DIR/neighbors_combined.txt"
XML_OUTPUT="$SESSION_DIR/lldp_cdp_results.xml"

# ===========================================================================
# Phase 1: Packet Capture for LLDP/CDP Frames
# ===========================================================================
emit_progress "Capturing LLDP/CDP Frames" 1 3
print_subphase "Phase 1: Capturing LLDP/CDP Frames"
echo "Capturing LLDP/CDP frames on $interface for ${capture_duration} seconds..."
echo "LLDP frames use multicast 01:80:C2:00:00:0E (EtherType 0x88CC)"
echo "CDP frames use multicast 01:00:0C:CC:CC:CC"
echo "Note: Interface must be connected to a switch/router that sends LLDP/CDP."
echo "      If nothing is captured, the upstream device may not advertise neighbors."
echo >&2

# Capture LLDP and CDP frames via tshark
# LLDP: ethertype == 0x88cc
# CDP: cisco dissector uses LLC SNAP OUI 0x00000c pid 0x2000
# We use a capture filter for both
# -p omitted: tshark defaults to promiscuous mode (requires root)
# --ifflags promisc explicitly sets promiscuous if supported
tshark_err_file="$SESSION_DIR/tshark_capture.err"
log_debug "Phase 1: tshark capture on $interface for ${capture_duration}s" "$SCRIPT_NAME"

# Capture stderr to detect real errors (permission denied, missing interface, etc.)
tshark -i "$interface" \
    -c 500 \
    -a "duration:${capture_duration}" \
    -f "ether proto 0x88cc or ether dst 01:00:0c:cc:cc:cc" \
    -w "$PCAP_FILE" \
    2>"$tshark_err_file"
tshark_exit=$?

# Check for tshark errors (not just empty capture)
if [ $tshark_exit -ne 0 ]; then
    if [ -s "$tshark_err_file" ]; then
        error_message "tshark capture failed (exit $tshark_exit):"
        cat "$tshark_err_file" >&2
    else
        error_message "tshark capture failed with exit code $tshark_exit"
    fi
    echo >&2
    echo "Common causes:" >&2
    echo "  - Not running as root (need CAP_NET_RAW for packet capture)" >&2
    echo "  - Interface does not exist or is down" >&2
    echo "  - Another capture process is using the interface" >&2
    echo "  - Missing libpcap / dumpcap permissions" >&2
    rm -f "$tshark_err_file"
    exit 1
fi
rm -f "$tshark_err_file"

# Also try lldpctl as an alternative if tshark captured nothing
if [ ! -s "$PCAP_FILE" ]; then
    if command -v lldpctl >/dev/null 2>&1; then
        echo "No LLDP frames captured via tshark. Trying lldpctl..."
        log_info "Trying lldpctl as fallback" "$SCRIPT_NAME"
        {
            echo "=== LLDP Neighbor Discovery Results (lldpctl) ==="
            echo "Capture time: $(date)"
            echo "Interface: $interface"
            echo ""
            lldpctl -f keyvalue 2>/dev/null || lldpctl 2>/dev/null
        } > "$LLDP_OUTPUT"
        if [ -s "$LLDP_OUTPUT" ]; then
            success_message "Found LLDP neighbors via lldpctl"
            log_info "lldpctl found neighbors" "$SCRIPT_NAME"
        fi
    else
        warning_message "No LLDP/CDP frames captured. No neighbors visible on this interface."
        log_info "No LLDP/CDP frames captured and lldpctl not available" "$SCRIPT_NAME"
    fi
    # Create empty output files
    : > "$CDP_OUTPUT"
    : > "$COMBINED_OUTPUT"
    echo "No LLDP/CDP frames captured on interface $interface" > "$COMBINED_OUTPUT"
else
    success_message "LLDP/CDP frames captured successfully"
    log_info "LLDP/CDP capture complete: $PCAP_FILE" "$SCRIPT_NAME"

    # ===========================================================================
    # Phase 2: Parse LLDP Frames
    # ===========================================================================
    emit_progress "Parsing LLDP Neighbors" 2 3
    print_subphase "Phase 2: Parsing LLDP Neighbors"

    echo "Parsing LLDP neighbor information..."

    # Extract LLDP details from capture using tshark display filters
    {
        echo "=== LLDP Neighbor Discovery Results ==="
        echo "Capture time: $(date)"
        echo "Interface: $interface"
        echo "Capture file: $PCAP_FILE"
        echo ""

        # Extract LLDP neighbor summary (one line per unique neighbor)
        tshark -r "$PCAP_FILE" \
            -Y "lldp" \
            -T fields \
            -e lldp.system.name \
            -e lldp.mgmt.addr \
            -e lldp.port.id \
            -e lldp.port.description \
            -e lldp.system.descr \
            -e lldp.system.cap.enabled \
            -e lldp.vlan.id \
            -e lldp.vlan.name \
            -E separator="|" \
            -E quote=n \
            -E occurrence=l \
            2>/dev/null | sort -u
    } > "$LLDP_OUTPUT"

    # Extract CDP details
    echo "Parsing CDP neighbor information..."

    {
        echo "=== CDP Neighbor Discovery Results ==="
        echo "Capture time: $(date)"
        echo "Interface: $interface"
        echo "Capture file: $PCAP_FILE"
        echo ""

        tshark -r "$PCAP_FILE" \
            -Y "cdp" \
            -T fields \
            -e cdp.device.id \
            -e cdp.address \
            -e cdp.port.id \
            -e cdp.platform \
            -e cdp.capabilities \
            -e cdp.version \
            -e cdp.vlan.id \
            -E separator="|" \
            -E quote=n \
            -E occurrence=l \
            2>/dev/null | sort -u
    } > "$CDP_OUTPUT"

    # Generate structured XML output for parser consumption
    {
        echo '<?xml version="1.0" encoding="UTF-8"?>'
        echo '<lldp_cdp_results>'

        tshark -r "$PCAP_FILE" \
            -Y "lldp" \
            -T fields \
            -e lldp.system.name \
            -e lldp.mgmt.addr \
            -e lldp.port.id \
            -e lldp.port.description \
            -e lldp.system.descr \
            -e lldp.system.cap.enabled \
            -e lldp.vlan.id \
            -e lldp.vlan.name \
            -E separator="|" \
            -E quote=n \
            -E occurrence=l \
            2>/dev/null | sort -u | while IFS='|' read -r sys_name mgmt_ip port_id port_desc sys_desc caps vlan_id vlan_name; do
            [ -z "$sys_name" ] && [ -z "$mgmt_ip" ] && continue
            sys_name=$(echo "$sys_name" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
            mgmt_ip=$(echo "$mgmt_ip" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
            port_id=$(echo "$port_id" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
            port_desc=$(echo "$port_desc" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
            sys_desc=$(echo "$sys_desc" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
            caps=$(echo "$caps" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
            vlan_id=$(echo "$vlan_id" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
            vlan_name=$(echo "$vlan_name" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
            echo "  <neighbor protocol=\"lldp\">"
            echo "    <hostname>${sys_name}</hostname>"
            echo "    <management_ip>${mgmt_ip}</management_ip>"
            echo "    <remote_port>${port_id}</remote_port>"
            echo "    <remote_port_desc>${port_desc}</remote_port_desc>"
            echo "    <system_description>${sys_desc}</system_description>"
            echo "    <capabilities>${caps}</capabilities>"
            echo "    <vlan_id>${vlan_id}</vlan_id>"
            echo "    <vlan_name>${vlan_name}</vlan_name>"
            echo "    <local_interface>${interface}</local_interface>"
            echo "  </neighbor>"
        done

        tshark -r "$PCAP_FILE" \
            -Y "cdp" \
            -T fields \
            -e cdp.device.id \
            -e cdp.address \
            -e cdp.port.id \
            -e cdp.platform \
            -e cdp.capabilities \
            -e cdp.version \
            -e cdp.vlan.id \
            -E separator="|" \
            -E quote=n \
            -E occurrence=l \
            2>/dev/null | sort -u | while IFS='|' read -r device_id address port_id platform capabilities version vlan_id; do
            [ -z "$device_id" ] && continue
            device_id=$(echo "$device_id" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
            address=$(echo "$address" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
            port_id=$(echo "$port_id" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
            platform=$(echo "$platform" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
            capabilities=$(echo "$capabilities" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
            version=$(echo "$version" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
            vlan_id=$(echo "$vlan_id" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
            echo "  <neighbor protocol=\"cdp\">"
            echo "    <hostname>${device_id}</hostname>"
            echo "    <management_ip>${address}</management_ip>"
            echo "    <remote_port>${port_id}</remote_port>"
            echo "    <platform>${platform}</platform>"
            echo "    <capabilities>${capabilities}</capabilities>"
            echo "    <software_version>${version}</software_version>"
            echo "    <vlan_id>${vlan_id}</vlan_id>"
            echo "    <local_interface>${interface}</local_interface>"
            echo "  </neighbor>"
        done

        echo '</lldp_cdp_results>'
    } > "$XML_OUTPUT"

    # ===========================================================================
    # Phase 3: Combined Summary
    # ===========================================================================
    emit_progress "Generating Summary" 3 3
    print_subphase "Phase 3: Combined Neighbor Summary"

    {
        echo "=========================================="
        echo "LLDP/CDP Neighbor Discovery Summary"
        echo "=========================================="
        echo ""
        echo "Scan Information:"
        echo "  Capture time: $(date)"
        echo "  Interface: $interface"
        echo "  Duration: ${capture_duration}s"
        echo "  Session directory: $SESSION_DIR"
        echo ""
        echo "=========================================="
        echo "LLDP Neighbors"
        echo "=========================================="
        echo ""
        if [ -s "$LLDP_OUTPUT" ]; then
            cat "$LLDP_OUTPUT"
        else
            echo "No LLDP neighbors found"
        fi
        echo ""
        echo "=========================================="
        echo "CDP Neighbors"
        echo "=========================================="
        echo ""
        if [ -s "$CDP_OUTPUT" ]; then
            cat "$CDP_OUTPUT"
        else
            echo "No CDP neighbors found"
        fi
        echo ""
        echo "=========================================="
        echo "Output Files"
        echo "=========================================="
        echo ""
        echo "All outputs located in: $SESSION_DIR"
        echo ""
        echo "  lldp_cdp_capture.pcap     - Raw packet capture"
        echo "  lldp_neighbors.txt        - LLDP neighbor details"
        echo "  cdp_neighbors.txt         - CDP neighbor details"
        echo "  lldp_cdp_results.xml      - Structured XML for correlation"
        echo "  neighbors_combined.txt    - This summary report"
    } > "$COMBINED_OUTPUT"

    success_message "Phase 3 complete: Summary generated"
fi

echo >&2
success_message "LLDP/CDP discovery complete"
log_info "=== Script completed ===" "$SCRIPT_NAME"
echo "Results saved to: $SESSION_DIR"
echo "$SESSION_DIR"
