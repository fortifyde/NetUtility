#!/bin/sh

# Auto-Discovery Workflow
# VLAN-aware network discovery with intelligent configuration:
# 1. Interface UP verification → 2. Promiscuous capture → 3. VLAN analysis → 4. User VLAN selection → 5. Smart IP configuration → 6. VLAN-specific discovery

# shellcheck source=../common/utils.sh
. "$(dirname "$0")/../common/utils.sh" 2>/dev/null || true
# shellcheck source=../common/logging.sh
. "$(dirname "$0")/../common/logging.sh"
# shellcheck source=../common/colors.sh
. "$(dirname "$0")/../common/colors.sh" 2>/dev/null || true
# shellcheck source=../common/validation.sh
. "$(dirname "$0")/../common/validation.sh" 2>/dev/null || true
# shellcheck source=../common/progress.sh
. "$(dirname "$0")/../common/progress.sh" 2>/dev/null || true

# Disable SC3059: Case modification (${var^^}) is a bashism but works in sh on modern systems
# Disable SC2126: grep|wc is clearer than grep -c in context
# Disable SC2129: Individual redirects are clearer than grouped redirects in this context
# Disable SC2034: Some variables are used in sourced scripts or future features
# Disable SC2086: Word splitting is intentional in some cases
# Disable SC2012: Using ls with parsing is acceptable for this use case
# Disable SC2188: Lone redirects used to initialize files
# Disable SC2235: Subshell syntax is clearer for complex conditions
# Disable SC3037: echo -n is more reliable than printf for prompts to avoid buffering issues
# Disable SC1091: Source files are checked separately
# shellcheck disable=SC3059,SC2162,SC2129,SC2034,SC2086,SC2012,SC2188,SC2235,SC3037,SC2126,SC1091

if command -v print_phase_header >/dev/null 2>&1; then
    print_phase_header "AUTO-DISCOVERY WORKFLOW"
else
    echo "=== Auto-Discovery Workflow ===" >&2
    echo >&2
fi

# Log script start
log_script_start "auto_discover.sh" "$@"

WORKDIR="${NETUTIL_WORKDIR:-$HOME}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORTS_DIR="$WORKDIR/reports"
SESSION_NAME="auto_discover_${TIMESTAMP}"
REPORT_SESSION_DIR="$REPORTS_DIR/$SESSION_NAME"
TEMP_DIR=$(mktemp -d)

# Cleanup on exit
trap 'rm -rf "$TEMP_DIR"' EXIT

# Create reports session directory
mkdir -p "$REPORT_SESSION_DIR"
# Enable clean Ctrl+C handling during long-running discovery operations
setup_cancellation

# Convert dotted-decimal IP to a 32-bit integer
ip_to_int() {
    _a="${1%%.*}"; _r="${1#*.}"
    _b="${_r%%.*}"; _r="${_r#*.}"
    _c="${_r%%.*}"; _d="${_r#*.}"
    printf '%d\n' $(( (_a * 16777216) + (_b * 65536) + (_c * 256) + _d ))
}

# Convert a 32-bit integer to dotted-decimal IP
int_to_ip() {
    printf '%d.%d.%d.%d\n' \
        $(( $1 / 16777216 )) \
        $(( ($1 / 65536) % 256 )) \
        $(( ($1 / 256) % 256 )) \
        $(( $1 % 256 ))
}

is_ip_in_cidr() {
    _iic_ip="$1"
    _iic_cidr="$2"
    _iic_net=$(echo "$_iic_cidr" | cut -d/ -f1)
    _iic_prefix=$(echo "$_iic_cidr" | cut -d/ -f2)
    _iic_ip_int=$(ip_to_int "$_iic_ip")
    _iic_net_int=$(ip_to_int "$_iic_net")
    _iic_bits=$((32 - _iic_prefix))
    _iic_size=1
    _iic_n=0
    while [ "$_iic_n" -lt "$_iic_bits" ]; do
        _iic_size=$((_iic_size * 2))
        _iic_n=$((_iic_n + 1))
    done
    _iic_mask=$((_iic_size - 1))
    _iic_network=$((_iic_net_int & ~_iic_mask))
    _iic_broadcast=$((_iic_network + _iic_size - 1))
    if [ "$_iic_ip_int" -ge "$_iic_network" ] && [ "$_iic_ip_int" -le "$_iic_broadcast" ]; then
        return 0
    fi
    return 1
}

# Function to prompt user for IP address choice with validation
prompt_ip_choice() {
    suggested_ip="$1"
    network_base="$2"
    vlan_interface="$3"

    printf "%sChoose IP assignment for VLAN interface %s:%s\n" "$COLOR_MINTCREAM" "$vlan_interface" "$COLOR_RESET" >&2
    echo "1) Accept suggested IP ($suggested_ip)" >&2
    echo "2) Provide custom IP address" >&2
    echo >&2
    if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
        printf "%sChoice [1-2]: %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
    else
        printf "Choice [1-2]: \n" >&2
    fi
    read -r choice

    case "$choice" in
        1|"")
            echo "$suggested_ip"
            return 0
            ;;
        2)
            while true; do
                echo >&2
                if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
                    printf "%sEnter IP address (with CIDR, e.g., 192.168.1.100/24): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
                else
                    printf "Enter IP address (with CIDR, e.g., 192.168.1.100/24): \n" >&2
                fi
                read -r custom_ip

                # Basic validation
                if [ -z "$custom_ip" ]; then
                    echo "⚠ Empty IP address. Try again or press Ctrl+C to cancel." >&2
                    continue
                fi

                # Check if it contains CIDR notation
                if ! echo "$custom_ip" | grep -q "/"; then
                    echo "⚠ IP address must include CIDR notation (e.g., /24). Try again." >&2
                    continue
                fi

                # Extract IP part for validation
                ip_part=$(echo "$custom_ip" | cut -d'/' -f1)
                cidr_part=$(echo "$custom_ip" | cut -d'/' -f2)

                # Basic IP format validation
                if ! echo "$ip_part" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'; then
                    echo "⚠ Invalid IP format. Use format: X.X.X.X/XX" >&2
                    continue
                fi

                # Basic CIDR validation
                if ! echo "$cidr_part" | grep -qE '^[0-9]{1,2}$' || [ "$cidr_part" -lt 8 ] || [ "$cidr_part" -gt 30 ]; then
                    echo "⚠ Invalid CIDR. Use range 8-30 (e.g., /24)" >&2
                    continue
                fi

                # Check if IP is in same network (optional warning)
                custom_network_base=$(echo "$ip_part" | cut -d'.' -f1-3)
                if [ "$custom_network_base" != "$network_base" ]; then
                    echo "⚠ Warning: Custom IP ($custom_network_base.X) differs from discovered network ($network_base.0)" >&2
                    echo >&2
                    if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
                        printf "%sContinue anyway? [y/N]: %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
                    else
                        printf "Continue anyway? [y/N]: \n" >&2
                    fi
                    read -r confirm
                    case "$confirm" in
                        y|Y|yes|YES)
                            ;;
                        *)
                            continue
                            ;;
                    esac
                fi

                echo "$custom_ip"
                return 0
            done
            ;;
        *)
            echo "⚠ Invalid choice. Using suggested IP: $suggested_ip" >&2
            echo "$suggested_ip"
            return 0
            ;;
    esac
}

# Auto-discovery report
WORKFLOW_REPORT="$REPORT_SESSION_DIR/auto_discovery_report.txt"

echo "=== Auto-Discovery Workflow Report ===" > "$WORKFLOW_REPORT"
echo "Workflow started: $(date)" >> "$WORKFLOW_REPORT"
echo "Reports directory: $REPORT_SESSION_DIR" >> "$WORKFLOW_REPORT"
echo >> "$WORKFLOW_REPORT"

echo "This VLAN-aware workflow follows logical sequence for comprehensive network discovery:"
echo "1. Interface state verification"
echo "2. Promiscuous packet capture"
echo "3. VLAN analysis (identify VLANs and network ranges)"
echo "4. VLAN Host configuration"
echo "5. IP configuration"
echo "6. VLAN-specific discovery"
echo "7. Analysis"
echo

log_info "Starting VLAN-aware auto-discovery workflow"

# Get target interface
target_interface=$(select_interface "Select parent interface for VLAN discovery" "auto_discover" "true")

if [ -z "$target_interface" ]; then
    echo "No interface selected" >&2
    log_error "No interface selected for auto-discovery workflow"
    exit 1
fi

echo "Selected interface: $target_interface" >&2
log_info "Selected interface for auto-discovery workflow: $target_interface"

# Verify interface is UP and bring it up if needed
interface_state=$(ip link show "$target_interface" 2>/dev/null | grep -o "state [A-Z]*" | cut -d' ' -f2)
if [ "$interface_state" != "UP" ]; then
    echo "Interface $target_interface is not UP (current state: ${interface_state:-UNKNOWN})" >&2
    echo "Bringing interface up..." >&2
    if ip link set "$target_interface" up 2>/dev/null; then
        echo "✓ Interface $target_interface brought up successfully" >&2
        log_info "Interface $target_interface brought up from state: $interface_state"
        # Wait a moment for interface to stabilize
        sleep 2
    else
        echo "✗ Failed to bring interface $target_interface up (may require root privileges)" >&2
        log_error "Failed to bring interface $target_interface up"
        exit 1
    fi
else
    echo "✓ Interface $target_interface is already UP" >&2
    log_info "Interface $target_interface is already UP"
fi

# ── Discovery mode selection ──────────────────────────────────────────────────
discovery_mode="l2"
echo >&2
if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
    printf "%sDiscovery mode:%s\n" "$SECTION_COLOR" "$COLOR_RESET" >&2
else
    printf "Discovery mode:\n" >&2
fi
printf "  1) L2 — Create VLAN sub-interfaces (tag into each VLAN)\n" >&2
printf "  2) L3 — Routed access from a single source VLAN\n" >&2
if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
    printf "%sSelect mode [1-2, default 1]: %s" "$PROMPT_COLOR" "$COLOR_RESET" >&2
else
    printf "Select mode [1-2, default 1]: " >&2
fi
read -r _mode_input
case "$_mode_input" in
    2) discovery_mode="l3" ;;
    *) discovery_mode="l2" ;;
esac
echo >&2

# Workflow configuration
echo
echo "Workflow configuration:" >&2
echo "The auto-discovery workflow will capture network traffic in promiscuous mode" >&2
echo "to discover VLANs and network topology before performing discovery." >&2
echo >&2
echo "Capture duration options:" >&2
echo "  • 2 minutes  - Quick scan for basic VLAN discovery" >&2
echo "  • 5 minutes  - Standard capture" >&2
echo "  • 10 minutes - Extended capture (recommended)" >&2
echo "  • 15+ minutes - Comprehensive capture for complex environments" >&2
echo
echo "Enter capture duration in minutes (default 10): " >&2
read capture_duration
capture_duration=${capture_duration:-10}

# Validate capture duration
case "$capture_duration" in
    ''|*[!0-9]*)
        echo "Invalid duration. Using default 10 minutes." >&2
        capture_duration=10
        ;;
    *)
        if [ "$capture_duration" -lt 1 ] || [ "$capture_duration" -gt 60 ]; then
            echo "Duration must be between 1 and 60 minutes. Using default 10 minutes." >&2
            capture_duration=10
        fi
        ;;
esac

echo "Capture duration: $capture_duration minutes" >&2
    log_info "Auto-discovery capture duration: $capture_duration minutes"

# Add workflow details to report
echo "--- WORKFLOW CONFIGURATION ---" >> "$WORKFLOW_REPORT"
echo "Target interface: $target_interface" >> "$WORKFLOW_REPORT"
echo "Capture duration: $capture_duration minutes" >> "$WORKFLOW_REPORT"
echo >> "$WORKFLOW_REPORT"

# Stage 1: Promiscuous Packet Capture
if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
    printf "%s%s%s\n" "$COLOR_YELLOW" "Stage 1/5: PACKET CAPTURE — Promiscuous capture" "$COLOR_RESET"
elif command -v print_phase_header >/dev/null 2>&1; then
    print_phase_header "STAGE 1: PACKET CAPTURE"
else
    echo >&2
    echo "=== Stage 1: Packet Capture ===" >&2
fi
echo "--- STAGE 1: PACKET CAPTURE ---" >> "$WORKFLOW_REPORT"
echo "Started: $(date)" >> "$WORKFLOW_REPORT"

log_info "Starting Stage 1: Promiscuous packet capture"

# Enable promiscuous mode
echo "Enabling promiscuous mode on $target_interface..." >&2
if ip link set "$target_interface" promisc on 2>/dev/null; then
    echo "✓ Promiscuous mode enabled" >&2
    log_info "Promiscuous mode enabled on $target_interface"
    promisc_enabled=true
else
    echo "⚠ Warning: Could not enable promiscuous mode (may require root privileges)" >&2
    log_warn "Could not enable promiscuous mode on $target_interface"
    promisc_enabled=false
fi

# Capture traffic
CAPTURE_DIR="$WORKDIR/captures"
mkdir -p "$CAPTURE_DIR"
capture_file="$CAPTURE_DIR/auto_discover_capture_${TIMESTAMP}.pcap"

# Test if directory is writable before attempting capture
test_file="$CAPTURE_DIR/.write_test_$$"
if ! touch "$test_file" 2>/dev/null; then
    echo "⚠ Capture directory not writable, will use fallback location if needed" >&2
else
    rm -f "$test_file"
fi

echo "Starting promiscuous capture for $capture_duration minutes..." >&2
echo "Capture file: $capture_file" >&2

if command -v tshark >/dev/null 2>&1; then
    # Use tshark for capture - first attempt
    timeout $((capture_duration * 60)) tshark -i "$target_interface" -w "$capture_file" -q 2>/dev/null
    capture_exit_code=$?
    
    # If tshark failed with permission issue and we're root, try fallback location
    if [ $capture_exit_code -ne 0 ] && [ $capture_exit_code -ne 124 ] && [ "$(id -u)" -eq 0 ]; then
        echo "Capture failed in workflow directory, trying fallback location..." >&2
        FALLBACK_DIR="/tmp/netutil-captures"
        mkdir -p "$FALLBACK_DIR"
        chmod 755 "$FALLBACK_DIR"
        FALLBACK_FILE="$FALLBACK_DIR/promiscuous_capture_$(date +%Y%m%d_%H%M%S).pcap"
        
        echo "Fallback capture file: $FALLBACK_FILE" >&2
        timeout $((capture_duration * 60)) tshark -i "$target_interface" -w "$FALLBACK_FILE" -q 2>/dev/null
        capture_exit_code=$?
        
        # If successful in fallback location, copy to workflow directory
        if ([ $capture_exit_code -eq 0 ] || [ $capture_exit_code -eq 124 ]) && [ -f "$FALLBACK_FILE" ]; then
            echo "Capture successful in fallback location, copying to workflow directory..." >&2
            if cp "$FALLBACK_FILE" "$capture_file" 2>/dev/null; then
                echo "✓ Capture copied to workflow directory" >&2
                # Update file permissions for original user if running as root
                if [ -n "$SUDO_UID" ] && [ -n "$SUDO_GID" ]; then
                    chown "$SUDO_UID:$SUDO_GID" "$capture_file" 2>/dev/null || true
                fi
            else
                echo "⚠ Failed to copy to workflow directory, using fallback location" >&2
                capture_file="$FALLBACK_FILE"
            fi
        fi
    fi
    
    if [ $capture_exit_code -eq 0 ] || [ $capture_exit_code -eq 124 ]; then  # 124 = timeout
        echo "✓ Promiscuous capture completed successfully" >&2
        echo "Status: SUCCESS" >> "$WORKFLOW_REPORT"
        log_network_operation "Promiscuous capture" "$target_interface" "Completed - $(du -h "$capture_file" | cut -f1)"

        # Ensure proper file ownership if running as sudo
        if [ -n "$SUDO_UID" ] && [ -n "$SUDO_GID" ]; then
            chown "$SUDO_UID:$SUDO_GID" "$capture_file" 2>/dev/null || true
        fi

        # Get basic capture stats
        if command -v capinfos >/dev/null 2>&1; then
            # Use capinfos for more reliable packet count
            packet_count=$(capinfos -c "$capture_file" 2>/dev/null | grep "Number of packets" | awk '{print $4}')
        else
            # Fallback to tshark method
            packet_count=$(tshark -r "$capture_file" -q -z io,stat,0 2>/dev/null | grep -o "frames:[0-9]*" | cut -d: -f2 | head -1)
        fi
echo "Packets captured: ${packet_count:-unknown}" >&2
echo "Capture size: $(du -h "$capture_file" | cut -f1)" >&2
        echo "Packets captured: ${packet_count:-unknown}" >> "$WORKFLOW_REPORT"
        echo "Capture size: $(du -h "$capture_file" | cut -f1)" >> "$WORKFLOW_REPORT"
    else
        echo "✗ Promiscuous capture failed" >&2
        echo "Status: FAILED" >> "$WORKFLOW_REPORT"
        log_error "Promiscuous capture failed on $target_interface"
        exit 1
    fi
else
    echo "✗ tshark not available - cannot perform capture" >&2
    echo "Status: FAILED (tshark not available)" >> "$WORKFLOW_REPORT"
    log_error "tshark not available for promiscuous capture"
    exit 1
fi

# Disable promiscuous mode
if [ "$promisc_enabled" = true ]; then
    echo "Disabling promiscuous mode..." >&2
    ip link set "$target_interface" promisc off 2>/dev/null
    log_info "Promiscuous mode disabled on $target_interface"
fi

echo "Completed: $(date)" >> "$WORKFLOW_REPORT"
echo >> "$WORKFLOW_REPORT"

# Stage 2: Traffic Analysis
if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
    printf "%s%s%s\n" "$COLOR_YELLOW" "Stage 2/5: TRAFFIC ANALYSIS — VLAN and network extraction" "$COLOR_RESET"
elif command -v print_phase_header >/dev/null 2>&1; then
    print_phase_header "STAGE 2: TRAFFIC ANALYSIS"
else
    echo >&2
    echo "=== Stage 2: Traffic Analysis ===" >&2
fi
echo "--- STAGE 2: TRAFFIC ANALYSIS ---" >> "$WORKFLOW_REPORT"
echo "Started: $(date)" >> "$WORKFLOW_REPORT"

log_info "Starting Stage 2: Traffic analysis"

echo "Analyzing captured traffic for VLANs and network information..." >&2

# Extract VLAN information
echo "Extracting VLAN information..." >> "$WORKFLOW_REPORT"
tshark -r "$capture_file" -T fields -e vlan.id 2>/dev/null | sort -nu | grep -v "^$" > "$TEMP_DIR/discovered_vlans.txt"

vlan_count=$(wc -l < "$TEMP_DIR/discovered_vlans.txt")
echo "VLANs discovered: $vlan_count" >&2
    echo "VLANs discovered: $vlan_count" >> "$WORKFLOW_REPORT"

if [ "$vlan_count" -gt 0 ]; then
    echo "VLAN IDs found:" >> "$WORKFLOW_REPORT"
    cat "$TEMP_DIR/discovered_vlans.txt" | sed 's/^/  /' >> "$WORKFLOW_REPORT"

    if [ "$discovery_mode" = "l2" ]; then
    # Display discovered VLANs to user for selection
    echo >&2
    echo "=== VLAN Discovery Results ===" >&2
    echo "The following VLANs and sample IPs were discovered in the captured traffic:" >&2
    echo >&2
    
    vlan_info=""
    while read -r vlan_id; do
        if [ -n "$vlan_id" ]; then
            # Get sample IPs for this VLAN (filtered for valid unicast addresses)
            sample_ips=$(tshark -r "$capture_file" -Y "vlan.id == $vlan_id" -T fields -e ip.src -e ip.dst 2>/dev/null | \
                tr '\t' '\n' | grep -v "^$" | filter_valid_unicast_ips | sort -u | head -3 | tr '\n' ' ')
            
            echo "  VLAN $vlan_id: ${sample_ips:-No IPs found}" >&2
            vlan_info="$vlan_info$vlan_id:$sample_ips\n"
            
            # Add to report
            echo "  VLAN $vlan_id IP analysis:" >> "$WORKFLOW_REPORT"
            echo "$sample_ips" | tr ' ' '\n' | sed 's/^/    /' >> "$WORKFLOW_REPORT"
        fi
    done < "$TEMP_DIR/discovered_vlans.txt"
    
    echo >&2
    echo "Which VLANs would you like to configure interfaces for?" >&2
    echo "Enter VLAN IDs separated by spaces (or 'all' for all VLANs, 'none' to skip):" >&2
    echo >&2
    if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
        printf "%sVLAN selection: %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
    else
        printf "VLAN selection: \n" >&2
    fi
    read -r vlan_selection
    
    # Process user selection
    case "$vlan_selection" in
        "all"|"ALL"|"")
            selected_vlans=$(cat "$TEMP_DIR/discovered_vlans.txt" | tr '\n' ' ')
            echo "Selected all VLANs: $selected_vlans" >&2
            ;;
        "none"|"NONE"|"skip"|"SKIP")
            selected_vlans=""
            echo "Skipping VLAN configuration" >&2
            ;;
        *)
            # Validate selected VLANs exist in discovered list
            selected_vlans=""
            for vlan in $vlan_selection; do
                if grep -q "^$vlan$" "$TEMP_DIR/discovered_vlans.txt"; then
                    selected_vlans="$selected_vlans $vlan"
                else
                    echo "⚠ Warning: VLAN $vlan was not discovered in traffic, skipping"
                fi
            done
            if [ -n "$selected_vlans" ]; then
                echo "Selected VLANs:$selected_vlans" >&2
            else
                echo "No valid VLANs selected, skipping VLAN configuration" >&2
            fi
            ;;
    esac
    
    # Update temp file with selected VLANs only
    if [ -n "$selected_vlans" ]; then
        echo "$selected_vlans" | tr ' ' '\n' | grep -v "^$" > "$TEMP_DIR/selected_vlans.txt"
        selected_vlan_count=$(wc -l < "$TEMP_DIR/selected_vlans.txt")
        echo "Will configure $selected_vlan_count VLAN interfaces" >&2

        # VLAN Priority Configuration (if multiple VLANs selected)
        if [ "$selected_vlan_count" -gt 1 ]; then
            echo >&2
            echo "=== VLAN Scan Priority Configuration ===" >&2
            echo "Network discovery may take a long time for multiple VLANs." >&2
            echo "You can prioritize specific VLANs to scan first." >&2
            echo >&2
            echo "Selected VLANs:" >&2

            # Display VLANs with context
            vlan_num=1
            while read -r vlan_id <&3; do
                # Get sample IPs for context
                vlan_ips=$(tshark -r "$capture_file" -Y "vlan.id == $vlan_id" -T fields -e ip.src 2>/dev/null | \
                           sort -u | head -3 | tr '\n' ' ')
                echo "  $vlan_num. VLAN $vlan_id: ${vlan_ips:-No sample IPs}" >&2
                vlan_num=$((vlan_num + 1))
            done 3< "$TEMP_DIR/selected_vlans.txt"

            echo >&2
            echo "Do you want to prioritize certain VLANs for early scanning?" >&2
            echo >&2
            if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
                printf "%sPrioritize VLANs? (y/n) [n]: %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
            else
                printf "Prioritize VLANs? (y/n) [n]: \n" >&2
            fi
            read -r prioritize_choice

            case "$prioritize_choice" in
                y|Y|yes|YES)
                    echo >&2
                    echo "Enter VLAN IDs to scan first (space-separated):" >&2
                    echo "Example: 300 500" >&2
                    echo >&2
                    if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
                        printf "%sPriority VLANs: %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
                    else
                        printf "Priority VLANs: \n" >&2
                    fi
                    read -r priority_vlans

                    if [ -n "$priority_vlans" ]; then
                        # Validate priority VLANs
                        priority_list=""

                        for pvlan in $priority_vlans; do
                            if grep -q "^$pvlan$" "$TEMP_DIR/selected_vlans.txt"; then
                                # Check for duplicates in priority list
                                if echo "$priority_list" | grep -q "^$pvlan$"; then
                                    echo "⚠ Warning: VLAN $pvlan specified multiple times. Ignoring duplicates." >&2
                                else
                                    priority_list="$priority_list$pvlan
"
                                fi
                            else
                                echo "⚠ Warning: VLAN $pvlan was not in your selection. Skipping." >&2
                            fi
                        done

                        # If we have valid priority VLANs, reorder
                        if [ -n "$priority_list" ]; then
                            # Create new ordered list: priority VLANs first, then remaining
                            temp_reordered="$TEMP_DIR/reordered_vlans.txt"

                            # Add priority VLANs first
                            echo "$priority_list" | grep -v "^$" > "$temp_reordered"

                            # Add remaining VLANs (those not in priority list)
                            while read -r vlan_id <&3; do
                                if ! echo "$priority_list" | grep -q "^$vlan_id$"; then
                                    echo "$vlan_id" >> "$temp_reordered"
                                fi
                            done 3< "$TEMP_DIR/selected_vlans.txt"

                            # Replace original with reordered list
                            mv "$temp_reordered" "$TEMP_DIR/selected_vlans.txt"

                            # Display new order
                            priority_count=$(echo "$priority_list" | grep -v "^$" | wc -l)
                            remaining_count=$((selected_vlan_count - priority_count))

                            echo "✓ Scan order configured:" >&2
                            echo "  Priority ($priority_count): $(echo "$priority_list" | tr '\n' ' ')" >&2
                            if [ $remaining_count -gt 0 ]; then
                                remaining_vlans=$(tail -n "$remaining_count" "$TEMP_DIR/selected_vlans.txt" | tr '\n' ' ')
                                echo "  Remaining ($remaining_count): $remaining_vlans" >&2
                            fi
                        else
                            echo "No valid priority VLANs provided. Using original order." >&2
                        fi
                    else
                        echo "No priority VLANs specified. Using original order." >&2
                    fi
                    ;;
                *)
                    echo "Using original order for VLAN scanning." >&2
                    ;;
            esac
            echo >&2
        fi
    else
        touch "$TEMP_DIR/selected_vlans.txt"  # Create empty file
        selected_vlan_count=0
        echo "No VLANs will be configured"
    fi
    else
        # L3 mode: no sub-interface selection needed; source VLAN selected later
        touch "$TEMP_DIR/selected_vlans.txt"
        selected_vlan_count=0
    fi  # end L2 VLAN selection
else
    echo "No VLANs detected in capture" >> "$WORKFLOW_REPORT"
    echo "No VLANs detected in capture" >&2
    touch "$TEMP_DIR/selected_vlans.txt"  # Create empty file
    selected_vlan_count=0
fi

# Extract general network information
echo "Extracting network ranges..." >> "$WORKFLOW_REPORT"
echo "Extracting network ranges..." >&2
tshark -r "$capture_file" -T fields -e ip.src -e ip.dst 2>/dev/null | \
    tr '\t' '\n' | grep -v "^$" | sort -u | head -20 > "$TEMP_DIR/discovered_ips.txt"

ip_count=$(wc -l < "$TEMP_DIR/discovered_ips.txt")
echo "Unique IP addresses found: $ip_count" >&2
    echo "Unique IP addresses found: $ip_count" >> "$WORKFLOW_REPORT"

echo "✓ Traffic analysis completed successfully" >&2
echo "Status: SUCCESS" >> "$WORKFLOW_REPORT"
echo "Completed: $(date)" >> "$WORKFLOW_REPORT"
echo >> "$WORKFLOW_REPORT"

# L3 mode: identify source VLAN/interface after traffic analysis
l3_source_vlan=""
l3_source_interface="$target_interface"

if [ "$discovery_mode" = "l3" ]; then
    echo >&2
    if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
        printf "%s=== L3 Source VLAN Selection ===%s\n" "$COLOR_MINTCREAM" "$COLOR_RESET" >&2
    else
        echo "=== L3 Source VLAN Selection ===" >&2
    fi

    if [ "$vlan_count" -gt 0 ]; then
        echo "Discovered VLANs (with sample IPs):" >&2
        while read -r _sv_id; do
            [ -n "$_sv_id" ] || continue
            _sv_ips=$(tshark -r "$capture_file" -Y "vlan.id == $_sv_id" -T fields -e ip.src 2>/dev/null | \
                filter_valid_unicast_ips | sort -u | head -3 | tr '\n' ' ')
            echo "  VLAN $_sv_id: ${_sv_ips:-no IPs captured}" >&2
        done < "$TEMP_DIR/discovered_vlans.txt"
        echo >&2
        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
            printf "%sWhich VLAN is your source (routed access)? Enter VLAN ID or press Enter for main interface: %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
        else
            printf "Which VLAN is your source (routed access)? Enter VLAN ID or press Enter for main interface: \n" >&2
        fi
        read -r l3_source_vlan
        if [ -n "$l3_source_vlan" ]; then
            if ! grep -q "^${l3_source_vlan}$" "$TEMP_DIR/discovered_vlans.txt" 2>/dev/null; then
                echo "⚠ VLAN $l3_source_vlan not in discovered list — proceeding anyway." >&2
            fi
            l3_source_interface="${target_interface}.${l3_source_vlan}"
            echo "  ✓ Source interface: $l3_source_interface" >&2
            log_info "L3 source interface: $l3_source_interface"
        else
            l3_source_interface="$target_interface"
            echo "  ✓ Using main interface: $target_interface" >&2
            log_info "L3 source interface: main ($target_interface)"
        fi
    else
        echo "No VLANs discovered — using main interface $target_interface as source." >&2
        l3_source_interface="$target_interface"
    fi
fi

# Stage 3: Interface Configuration
if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
    printf "%s%s%s\n" "$COLOR_YELLOW" "Stage 3/5: INTERFACE CONFIGURATION — VLAN interface setup" "$COLOR_RESET"
elif command -v print_phase_header >/dev/null 2>&1; then
    print_phase_header "STAGE 3: INTERFACE CONFIGURATION"
else
    echo >&2
    echo "=== Stage 3: Interface Configuration ===" >&2
fi
echo "--- STAGE 3: INTERFACE CONFIGURATION ---" >> "$WORKFLOW_REPORT"
echo "Started: $(date)" >> "$WORKFLOW_REPORT"

log_info "Starting Stage 3: Interface configuration"

interfaces_configured=0

if [ "$discovery_mode" = "l3" ]; then
    # L3: configure source interface only
    echo "Configuring source interface: $l3_source_interface" >&2

    if [ -n "$l3_source_vlan" ]; then
        # Create VLAN sub-interface if needed
        if ! ip link show "$l3_source_interface" >/dev/null 2>&1; then
            echo "Creating source VLAN interface: $l3_source_interface" >&2
            if ip link add link "$target_interface" name "$l3_source_interface" type vlan id "$l3_source_vlan" 2>/dev/null; then
                ip link set "$l3_source_interface" up
                ip -6 addr flush dev "$l3_source_interface" scope link 2>/dev/null || true
                echo "✓ $l3_source_interface created and brought up" >&2
                log_config_change "Source VLAN interface created" "$l3_source_interface"
            else
                echo "✗ Failed to create $l3_source_interface" >&2
                log_error "Failed to create source VLAN interface $l3_source_interface"
                exit 1
            fi
        else
            echo "  ✓ $l3_source_interface already exists" >&2
        fi

        # Assign IP to source interface (reuse captured traffic for suggestion)
        _src_existing_ip=$(ip addr show "$l3_source_interface" 2>/dev/null | grep "inet " | head -1 | awk '{print $2}')
        if [ -n "$_src_existing_ip" ]; then
            echo "  ✓ $l3_source_interface already has IP: $_src_existing_ip" >&2
            l3_source_cidr="$_src_existing_ip"
        else
            _src_vlan_ips=$(tshark -r "$capture_file" -Y "vlan.id == $l3_source_vlan" -T fields -e ip.src -e ip.dst 2>/dev/null | \
                tr '\t' '\n' | grep -v "^$" | filter_valid_unicast_ips | sort -u)
            if [ -n "$_src_vlan_ips" ]; then
                _src_first=$(echo "$_src_vlan_ips" | head -1)
                _src_base=$(echo "$_src_first" | cut -d'.' -f1-3)
                _src_max=$(echo "$_src_vlan_ips" | cut -d'.' -f4 | sort -n | tail -1)
                _src_min=$(echo "$_src_vlan_ips" | cut -d'.' -f4 | sort -n | head -1)
                if [ "$_src_max" -gt 200 ] || [ "$_src_min" -lt 50 ]; then
                    _src_suggested="${_src_base}.253/24"
                else
                    _src_suggested="${_src_base}.$(( _src_max + 10 > 253 ? 253 : _src_max + 10 ))/24"
                fi
                echo "  Suggested IP: $_src_suggested" >&2
                _src_chosen=$(prompt_ip_choice "$_src_suggested" "$_src_base" "$l3_source_interface")
            else
                echo "  No IPs captured for VLAN $l3_source_vlan — enter IP manually." >&2
                if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
                    printf "%s  Enter IP for %s (CIDR, e.g. 192.168.66.10/24): %s\n" "$PROMPT_COLOR" "$l3_source_interface" "$COLOR_RESET" >&2
                else
                    printf "  Enter IP for %s (CIDR, e.g. 192.168.66.10/24): \n" "$l3_source_interface" >&2
                fi
                read -r _src_chosen
            fi
            if [ -z "$_src_chosen" ] || ! echo "$_src_chosen" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$'; then
                echo "✗ Invalid or empty IP/CIDR: '$_src_chosen' — cannot continue." >&2
                log_error "Invalid IP/CIDR for source VLAN interface $l3_source_interface: $_src_chosen"
                exit 1
            fi
            if ip addr add "$_src_chosen" dev "$l3_source_interface" 2>/dev/null; then
                echo "✓ IP $_src_chosen assigned to $l3_source_interface" >&2
                log_config_change "IP assigned to source VLAN interface" "$l3_source_interface: $_src_chosen"
                l3_source_cidr="$_src_chosen"
            else
                echo "✗ Failed to assign IP to $l3_source_interface — cannot continue." >&2
                log_error "Failed to assign IP to source VLAN interface $l3_source_interface"
                exit 1
            fi
        fi
    else
        # Main interface — get existing IP
        l3_source_cidr=$(ip addr show "$target_interface" 2>/dev/null | grep "inet " | head -1 | awk '{print $2}')
        if [ -z "$l3_source_cidr" ]; then
            echo "✗ Main interface $target_interface has no IP — cannot proceed in L3 mode." >&2
            log_error "Main interface has no IP for L3 routed mode"
            exit 1
        fi
        echo "  ✓ Source interface $target_interface has IP: $l3_source_cidr" >&2
    fi

    # Gateway configuration
    echo >&2
    _gw_assigned=false
    _existing_gw=$(ip route show default 2>/dev/null | awk '/^default/ {print $3}' | head -1)
    if [ -n "$_existing_gw" ]; then
        echo "  Existing default route: via $_existing_gw" >&2
        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
            printf "%s  Replace with new gateway? [y/N]: %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
        else
            printf "  Replace with new gateway? [y/N]: \n" >&2
        fi
        read -r _gw_replace
        case "$_gw_replace" in
            y|Y|yes|YES) ;;
            *) _gw_assigned=true ;;  # keep existing
        esac
    fi

    if [ "$_gw_assigned" = "false" ]; then
        while true; do
            if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
                printf "%s  Enter gateway IP for routed access (must be within %s): %s\n" "$PROMPT_COLOR" "$l3_source_cidr" "$COLOR_RESET" >&2
            else
                printf "  Enter gateway IP for routed access (must be within %s): \n" "$l3_source_cidr" >&2
            fi
            read -r _gw_ip

            # Validate format
            if ! echo "$_gw_ip" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'; then
                echo "⚠ Invalid IP format." >&2
                continue
            fi

            # Validate gateway is within source subnet
            if ! is_ip_in_cidr "$_gw_ip" "$l3_source_cidr"; then
                echo "⚠ $_gw_ip is not within $l3_source_cidr — must use a gateway in the same subnet." >&2
                continue
            fi

            # Remove existing default route if replacing
            if [ -n "$_existing_gw" ]; then
                ip route del default 2>/dev/null || true
            fi

            if ip route add default via "$_gw_ip" 2>/dev/null; then
                echo "✓ Default route set via $_gw_ip" >&2
                log_config_change "Default gateway configured" "$_gw_ip (via $l3_source_interface)"
                echo "    Gateway: $_gw_ip" >> "$WORKFLOW_REPORT"
                _gw_assigned=true
                break
            else
                echo "✗ Failed to add route via $_gw_ip — try another gateway." >&2
            fi
        done
    fi

    interfaces_configured=1
    echo "✓ L3 source interface configuration complete" >&2
    echo "  Source interface: $l3_source_interface" >> "$WORKFLOW_REPORT"
    echo "  Source IP: $l3_source_cidr" >> "$WORKFLOW_REPORT"

else
if [ "$selected_vlan_count" -gt 0 ]; then
echo "Creating VLAN interfaces for selected VLANs..." >&2
echo "Creating VLAN interfaces..." >> "$WORKFLOW_REPORT"

    while read -r vlan_id <&3; do
        if [ -n "$vlan_id" ]; then
            vlan_interface="${target_interface}.${vlan_id}"
            
            # Create VLAN interface if it doesn't exist
            if ! ip link show "$vlan_interface" >/dev/null 2>&1; then
                echo "Creating VLAN interface: $vlan_interface" >&2
                
                if ip link add link "$target_interface" name "$vlan_interface" type vlan id "$vlan_id" 2>/dev/null; then
                    ip link set "$vlan_interface" up
                    ip -6 addr flush dev "$vlan_interface" scope link 2>/dev/null || true
echo "✓ VLAN interface $vlan_interface created and brought up" >&2
echo "  Created: $vlan_interface" >> "$WORKFLOW_REPORT"
                    log_config_change "VLAN interface created" "$vlan_interface (VLAN ID: $vlan_id)"
                    interfaces_configured=$((interfaces_configured + 1))
                    
                    # Try to assign IP address based on discovered traffic with improved calculation
                    # Filter out multicast, broadcast, and other special-purpose addresses
                    vlan_ips=$(tshark -r "$capture_file" -Y "vlan.id == $vlan_id" -T fields -e ip.src -e ip.dst 2>/dev/null | \
                              tr '\t' '\n' | grep -v "^$" | filter_valid_unicast_ips | sort -u)
                    
                    if [ -n "$vlan_ips" ]; then
                        # Use first IP to determine network characteristics
                        first_ip=$(echo "$vlan_ips" | head -1)
                        
                        # Try to determine subnet size by analyzing IP distribution
                        network_base=$(echo "$first_ip" | cut -d'.' -f1-3)
                        fourth_octets=$(echo "$vlan_ips" | cut -d'.' -f4 | sort -n)
                        min_octet=$(echo "$fourth_octets" | head -1)
                        max_octet=$(echo "$fourth_octets" | tail -1)
                        
                        # Estimate subnet size based on IP range
                        if [ "$max_octet" -gt 200 ] || [ "$min_octet" -lt 50 ]; then
                            # Likely /24 network
                            suggested_cidr="/24"
                            # Avoid .254 (often gateway) and .255 (broadcast), try .253
                            suggested_ip="${network_base}.253${suggested_cidr}"
                        else
                            # Possibly smaller subnet, default to /24 but suggest different IP
                            suggested_cidr="/24"
                            # Try an IP that's not in the discovered range
                            if [ "$max_octet" -lt 100 ]; then
                                suggested_ip="${network_base}.$((max_octet + 50))${suggested_cidr}"
                            else
                                suggested_ip="${network_base}.$((min_octet - 10))${suggested_cidr}"
                            fi
                        fi
                        
                        # Use ipcalc if available to calculate proper network
                        if command -v ipcalc >/dev/null 2>&1; then
                            _ipcalc_out=$(ipcalc "$first_ip$suggested_cidr" 2>/dev/null)
                            calc_network=$(printf '%s\n' "$_ipcalc_out" | \
                                sed -n 's/^NETWORK=\([0-9.]*\).*/\1/p;s/^Network:[[:space:]]*\([0-9.]*\)\/.*/\1/p' | \
                                head -1)
                            calc_broadcast=$(printf '%s\n' "$_ipcalc_out" | \
                                sed -n 's/^BROADCAST=\([0-9.]*\).*/\1/p;s/^Broadcast:[[:space:]]*\([0-9.]*\).*/\1/p' | \
                                head -1)
                            if [ -n "$calc_network" ]; then
                                network_base=$(echo "$calc_network" | cut -d'.' -f1-3)
                                echo "  Calculated network: $calc_network"
                            fi
                            if [ -n "$calc_broadcast" ]; then
                                suggested_ip="$(int_to_ip $(( $(ip_to_int "$calc_broadcast") - 2 )))${suggested_cidr}"
                            fi
                        fi
                        
                        echo "  Discovered IPs: $(echo "$vlan_ips" | head -3 | tr '\n' ' ')"
                        echo "  Estimated network: $network_base.0$suggested_cidr"
                        echo "  Suggested IP: $suggested_ip"
                        echo >&2
                        
                        # Prompt user for IP choice
                        chosen_ip=$(prompt_ip_choice "$suggested_ip" "$network_base" "$vlan_interface")
                        
                        if [ -n "$chosen_ip" ]; then
                            echo "  Assigning IP: $chosen_ip"
                            
                            if ip addr add "$chosen_ip" dev "$vlan_interface" 2>/dev/null; then
                                echo "✓ IP address $chosen_ip assigned to $vlan_interface"
                                echo "    IP assigned: $chosen_ip" >> "$WORKFLOW_REPORT"
                                log_config_change "IP assigned to VLAN interface" "$vlan_interface: $chosen_ip"
                            else
                                echo "⚠ Failed to assign IP $chosen_ip to $vlan_interface"
                                log_warn "Failed to assign IP $chosen_ip to $vlan_interface"
                            fi
                        else
                            echo "⚠ No valid IP provided, skipping IP assignment for $vlan_interface"
                            log_warn "No valid IP provided for $vlan_interface"
                        fi
                    else
                        # No valid unicast IPs found (only multicast/broadcast traffic)
                        echo "  No valid unicast IP addresses found for VLAN $vlan_id during capture" >&2
                        echo "  Manual IP configuration required for $vlan_interface" >&2
                        echo >&2

                        # Prompt user for manual IP configuration
                        ip_assigned=0
                        retry_count=0
                        max_retries=3

                        while [ $ip_assigned -eq 0 ] && [ $retry_count -lt $max_retries ]; do
                            retry_count=$((retry_count + 1))

                            echo >&2
                            if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
                                printf "%s  Enter IP address for %s (with CIDR, e.g., 192.168.1.100/24): %s\n" "$PROMPT_COLOR" "$vlan_interface" "$COLOR_RESET" >&2
                            else
                                printf "  Enter IP address for %s (with CIDR, e.g., 192.168.1.100/24): \n" "$vlan_interface" >&2
                            fi
                            read -r custom_ip

                            # Validate IP format
                            if [ -n "$custom_ip" ] && echo "$custom_ip" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$'; then
                                echo "  Assigning IP: $custom_ip" >&2

                                if ip addr add "$custom_ip" dev "$vlan_interface" 2>/dev/null; then
                                    echo "✓ IP address $custom_ip assigned to $vlan_interface" >&2
                                    echo "    IP assigned: $custom_ip" >> "$WORKFLOW_REPORT"
                                    log_config_change "IP assigned to VLAN interface" "$vlan_interface: $custom_ip"
                                    ip_assigned=1
                                else
                                    echo "✗ Failed to assign IP address $custom_ip to $vlan_interface" >&2
                                    echo "    Error: IP may already be in use or interface issue" >&2
                                    log_error "Failed to assign IP address $custom_ip to $vlan_interface"

                                    if [ $retry_count -lt $max_retries ]; then
                                        echo "    Please try a different IP address (attempt $retry_count of $max_retries)..." >&2
                                    fi
                                fi
                            else
                                echo "✗ Invalid IP address format: '$custom_ip'" >&2
                                echo "    Format should be: x.x.x.x/xx (e.g., 192.168.1.100/24)" >&2
                                log_error "Invalid IP address format provided: $custom_ip"

                                if [ $retry_count -lt $max_retries ]; then
                                    echo "    Please try again (attempt $retry_count of $max_retries)..." >&2
                                fi
                            fi
                        done

                        if [ $ip_assigned -eq 0 ]; then
                            echo "⚠ Warning: Failed to assign IP address to $vlan_interface after $max_retries attempts" >&2
                            echo "    VLAN interface created but has no IP configuration" >&2
                            log_warn "No IP address assigned to $vlan_interface after $max_retries attempts"
                        fi
                    fi
                else
                    echo "✗ Failed to create VLAN interface $vlan_interface" >&2
                    log_error "Failed to create VLAN interface $vlan_interface"
                fi
            else
                # Interface already exists — ensure it is UP before proceeding.
                _iface_state=$(ip -br link show "$vlan_interface" 2>/dev/null | awk '{print $2}')
                case "$_iface_state" in
                    UP)
                        : ;;
                    *)
                        echo "  ⚠ Interface $vlan_interface exists but is $_iface_state — bringing up..." >&2
                        if ! ip link set "$vlan_interface" up; then
                            log_error "Failed to bring up interface $vlan_interface"
                            echo "✗ Failed to bring up $vlan_interface" >&2
                        fi
                        ip -6 addr flush dev "$vlan_interface" scope link 2>/dev/null || true
                        ;;
                esac

                existing_ip=$(ip addr show "$vlan_interface" 2>/dev/null | grep "inet " | head -1 | awk '{print $2}')
                if [ -n "$existing_ip" ]; then
                    echo "  ✓ Already configured with IP: $existing_ip" >&2
                    echo "  Exists: $vlan_interface ($existing_ip)" >> "$WORKFLOW_REPORT"
                    interfaces_configured=$((interfaces_configured + 1))
                else
                    echo "  ⚠ Interface exists but has no IP address — assigning now..." >&2
                    echo "  Exists: $vlan_interface (no IP)" >> "$WORKFLOW_REPORT"
                    interfaces_configured=$((interfaces_configured + 1))

                    vlan_ips=$(tshark -r "$capture_file" -Y "vlan.id == $vlan_id" -T fields -e ip.src -e ip.dst 2>/dev/null | \
                              tr '\t' '\n' | grep -v "^$" | filter_valid_unicast_ips | sort -u)

                    if [ -n "$vlan_ips" ]; then
                        first_ip=$(echo "$vlan_ips" | head -1)
                        network_base=$(echo "$first_ip" | cut -d'.' -f1-3)
                        fourth_octets=$(echo "$vlan_ips" | cut -d'.' -f4 | sort -n)
                        min_octet=$(echo "$fourth_octets" | head -1)
                        max_octet=$(echo "$fourth_octets" | tail -1)

                        if [ "$max_octet" -gt 200 ] || [ "$min_octet" -lt 50 ]; then
                            suggested_cidr="/24"
                            suggested_ip="${network_base}.253${suggested_cidr}"
                        else
                            suggested_cidr="/24"
                            if [ "$max_octet" -lt 100 ]; then
                                suggested_ip="${network_base}.$((max_octet + 50))${suggested_cidr}"
                            else
                                suggested_ip="${network_base}.$((min_octet - 10))${suggested_cidr}"
                            fi
                        fi

                        if command -v ipcalc >/dev/null 2>&1; then
                            _ipcalc_out=$(ipcalc "$first_ip$suggested_cidr" 2>/dev/null)
                            calc_network=$(printf '%s\n' "$_ipcalc_out" | \
                                sed -n 's/^NETWORK=\([0-9.]*\).*/\1/p;s/^Network:[[:space:]]*\([0-9.]*\)\/.*/\1/p' | \
                                head -1)
                            calc_broadcast=$(printf '%s\n' "$_ipcalc_out" | \
                                sed -n 's/^BROADCAST=\([0-9.]*\).*/\1/p;s/^Broadcast:[[:space:]]*\([0-9.]*\).*/\1/p' | \
                                head -1)
                            if [ -n "$calc_network" ]; then
                                network_base=$(echo "$calc_network" | cut -d'.' -f1-3)
                                echo "  Calculated network: $calc_network"
                            fi
                            if [ -n "$calc_broadcast" ]; then
                                suggested_ip="$(int_to_ip $(( $(ip_to_int "$calc_broadcast") - 2 )))${suggested_cidr}"
                            fi
                        fi

                        echo "  Discovered IPs: $(echo "$vlan_ips" | head -3 | tr '\n' ' ')"
                        echo "  Estimated network: $network_base.0$suggested_cidr"
                        echo "  Suggested IP: $suggested_ip"
                        echo >&2

                        chosen_ip=$(prompt_ip_choice "$suggested_ip" "$network_base" "$vlan_interface")

                        if [ -n "$chosen_ip" ]; then
                            echo "  Assigning IP: $chosen_ip"
                            if ip addr add "$chosen_ip" dev "$vlan_interface" 2>/dev/null; then
                                echo "✓ IP address $chosen_ip assigned to $vlan_interface"
                                echo "    IP assigned: $chosen_ip" >> "$WORKFLOW_REPORT"
                                log_config_change "IP assigned to VLAN interface" "$vlan_interface: $chosen_ip"
                            else
                                echo "⚠ Failed to assign IP $chosen_ip to $vlan_interface"
                                log_warn "Failed to assign IP $chosen_ip to $vlan_interface"
                            fi
                        else
                            echo "⚠ No valid IP provided, skipping IP assignment for $vlan_interface"
                            log_warn "No valid IP provided for $vlan_interface"
                        fi
                    else
                        echo "  No valid unicast IP addresses found for VLAN $vlan_id during capture" >&2
                        echo "  Manual IP configuration required for $vlan_interface" >&2
                        echo >&2

                        ip_assigned=0
                        retry_count=0
                        max_retries=3

                        while [ $ip_assigned -eq 0 ] && [ $retry_count -lt $max_retries ]; do
                            retry_count=$((retry_count + 1))
                            echo >&2
                            if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
                                printf "%s  Enter IP address for %s (with CIDR, e.g., 192.168.1.100/24): %s\n" "$PROMPT_COLOR" "$vlan_interface" "$COLOR_RESET" >&2
                            else
                                printf "  Enter IP address for %s (with CIDR, e.g., 192.168.1.100/24): \n" "$vlan_interface" >&2
                            fi
                            read -r custom_ip

                            if [ -n "$custom_ip" ] && echo "$custom_ip" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$'; then
                                echo "  Assigning IP: $custom_ip" >&2
                                if ip addr add "$custom_ip" dev "$vlan_interface" 2>/dev/null; then
                                    echo "✓ IP address $custom_ip assigned to $vlan_interface" >&2
                                    echo "    IP assigned: $custom_ip" >> "$WORKFLOW_REPORT"
                                    log_config_change "IP assigned to VLAN interface" "$vlan_interface: $custom_ip"
                                    ip_assigned=1
                                else
                                    echo "✗ Failed to assign IP address $custom_ip to $vlan_interface" >&2
                                    echo "    Error: IP may already be in use or interface issue" >&2
                                    log_error "Failed to assign IP address $custom_ip to $vlan_interface"
                                    if [ $retry_count -lt $max_retries ]; then
                                        echo "    Please try a different IP address (attempt $retry_count of $max_retries)..." >&2
                                    fi
                                fi
                            else
                                echo "✗ Invalid IP address format: '$custom_ip'" >&2
                                echo "    Format should be: x.x.x.x/xx (e.g., 192.168.1.100/24)" >&2
                                log_error "Invalid IP address format provided: $custom_ip"
                                if [ $retry_count -lt $max_retries ]; then
                                    echo "    Please try again (attempt $retry_count of $max_retries)..." >&2
                                fi
                            fi
                        done

                        if [ $ip_assigned -eq 0 ]; then
                            echo "⚠ Warning: Failed to assign IP address to $vlan_interface after $max_retries attempts" >&2
                            echo "    VLAN interface exists but has no IP configuration" >&2
                            log_warn "No IP address assigned to $vlan_interface after $max_retries attempts"
                        fi
                    fi
                fi
            fi
        fi
    done 3< "$TEMP_DIR/selected_vlans.txt"
else
    # No VLANs scenario - handle main interface configuration
echo "No VLANs detected or selected for configuration" >&2
echo "No VLANs selected for configuration" >> "$WORKFLOW_REPORT"
    
echo "Checking main interface configuration: $target_interface" >&2
echo "Main interface configuration check:" >> "$WORKFLOW_REPORT"
    
    # Check if target_interface already has an IP address configured
    current_ip_info=$(ip addr show "$target_interface" 2>/dev/null | grep "inet " | head -1 | awk '{print $2}')
    
    if [ -n "$current_ip_info" ] && [ "$current_ip_info" != "127.0.0.1/8" ]; then
        # Interface already has IP configured
echo "✓ Interface $target_interface already has IP configured: $current_ip_info" >&2
echo "    Current IP: $current_ip_info" >> "$WORKFLOW_REPORT"
        log_info "Interface $target_interface already configured with IP: $current_ip_info"
        
        # Interface is already configured
        interfaces_configured=$((interfaces_configured + 1))
        
    else
        # No IP configured - need to assign one
echo "Interface $target_interface has no IP configured - assignment required" >&2
echo "    No IP configured - assignment required" >> "$WORKFLOW_REPORT"
        log_info "Interface $target_interface requires IP configuration"
        
        # Extract non-VLAN IP addresses from captured traffic for suggestions
        # Filter out multicast, broadcast, and other special-purpose addresses
        main_ips=$(tshark -r "$capture_file" -Y "not vlan" -T fields -e ip.src -e ip.dst 2>/dev/null | \
                  tr '\t' '\n' | grep -v "^$" | filter_valid_unicast_ips | sort -u)
        
        if [ -n "$main_ips" ]; then
            # Use captured traffic to suggest IP
            first_ip=$(echo "$main_ips" | head -1)
            
            # Analyze IP distribution for network characteristics
            network_base=$(echo "$first_ip" | cut -d'.' -f1-3)
            fourth_octets=$(echo "$main_ips" | cut -d'.' -f4 | sort -n)
            min_octet=$(echo "$fourth_octets" | head -1)
            max_octet=$(echo "$fourth_octets" | tail -1)
            
            # Estimate subnet size and suggest safe IP
            suggested_cidr="/24"
            if [ "$max_octet" -gt 200 ] || [ "$min_octet" -lt 50 ]; then
                # Likely /24 network - suggest .253 to avoid common gateway/broadcast
                suggested_ip="${network_base}.253${suggested_cidr}"
            else
                # Try an IP outside the discovered range
                if [ "$max_octet" -lt 100 ]; then
                    # Add 50 to max found IP
                    new_octet=$((max_octet + 50))
                    if [ "$new_octet" -gt 253 ]; then
                        new_octet=253
                    fi
                    suggested_ip="${network_base}.${new_octet}${suggested_cidr}"
                else
                    # Subtract 10 from min found IP
                    new_octet=$((min_octet - 10))
                    if [ "$new_octet" -lt 2 ]; then
                        new_octet=253
                    fi
                    suggested_ip="${network_base}.${new_octet}${suggested_cidr}"
                fi
            fi

            if command -v ipcalc >/dev/null 2>&1; then
                _ipcalc_out=$(ipcalc "$first_ip$suggested_cidr" 2>/dev/null)
                calc_network=$(printf '%s\n' "$_ipcalc_out" | \
                    sed -n 's/^NETWORK=\([0-9.]*\).*/\1/p;s/^Network:[[:space:]]*\([0-9.]*\)\/.*/\1/p' | \
                    head -1)
                calc_broadcast=$(printf '%s\n' "$_ipcalc_out" | \
                    sed -n 's/^BROADCAST=\([0-9.]*\).*/\1/p;s/^Broadcast:[[:space:]]*\([0-9.]*\).*/\1/p' | \
                    head -1)
                if [ -n "$calc_network" ]; then
                    network_base=$(echo "$calc_network" | cut -d'.' -f1-3)
                    echo "  Calculated network: $calc_network" >&2
                fi
                if [ -n "$calc_broadcast" ]; then
                    suggested_ip="$(int_to_ip $(( $(ip_to_int "$calc_broadcast") - 2 )))${suggested_cidr}"
                fi
            fi

echo "  Traffic analysis results:" >&2
echo "    Discovered IPs: $(echo "$main_ips" | head -3 | tr '\n' ' ')" >&2
echo "    Suggested IP: $suggested_ip" >&2
            echo >&2
            
        else
            echo "  No valid IPs found in captured traffic for IP suggestion" >&2
            suggested_ip=""
        fi
        
        # Enforce IP assignment with retry loop
        ip_assigned=0
        retry_count=0
        max_retries=3
        
        while [ $ip_assigned -eq 0 ] && [ $retry_count -lt $max_retries ]; do
            retry_count=$((retry_count + 1))
            
            # Prompt user for IP assignment
            if [ -n "$suggested_ip" ]; then
                chosen_ip=$(prompt_ip_choice "$suggested_ip" "$network_base" "$target_interface")
            else
                echo "No network traffic detected for IP suggestion." >&2
                echo "Please provide an IP address for interface $target_interface." >&2
                echo >&2
                if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
                    printf "%sEnter IP address in CIDR notation (e.g., 192.168.1.100/24): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
                else
                    printf "Enter IP address in CIDR notation (e.g., 192.168.1.100/24): \n" >&2
                fi
                read -r chosen_ip
            fi
            
            # Validate IP format
            if [ -n "$chosen_ip" ] && echo "$chosen_ip" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$'; then
                echo "  Assigning IP: $chosen_ip"
                
                if ip addr add "$chosen_ip" dev "$target_interface" 2>/dev/null; then
                    echo "✓ IP address $chosen_ip assigned to $target_interface"
                    echo "    IP assigned: $chosen_ip" >> "$WORKFLOW_REPORT"
                    log_config_change "IP assigned to main interface" "$target_interface: $chosen_ip"
                    interfaces_configured=$((interfaces_configured + 1))
                    ip_assigned=1
                else
                    echo "✗ Failed to assign IP address $chosen_ip to $target_interface"
                    echo "    Error: IP may already be in use or interface issue"
                    echo "    IP assignment failed: $chosen_ip" >> "$WORKFLOW_REPORT"
                    log_error "Failed to assign IP address $chosen_ip to $target_interface"
                    
                    if [ $retry_count -lt $max_retries ]; then
                        echo "    Please try a different IP address (attempt $retry_count of $max_retries)..."
                        suggested_ip=""  # Clear suggestion for retry
                    fi
                fi
            else
                echo "✗ Invalid IP address format: '$chosen_ip'"
                echo "    Format should be: x.x.x.x/xx (e.g., 192.168.1.100/24)"
                echo "    Invalid IP format: $chosen_ip" >> "$WORKFLOW_REPORT"
                log_error "Invalid IP address format provided: $chosen_ip"
                
                if [ $retry_count -lt $max_retries ]; then
                    echo "    Please try again (attempt $retry_count of $max_retries)..."
                    suggested_ip=""  # Clear suggestion for retry
                fi
            fi
        done
        
        # Ensure IP was assigned - critical requirement
        if [ $ip_assigned -eq 0 ]; then
            echo "✗ CRITICAL ERROR: Failed to assign IP address after $max_retries attempts"
            echo "    Cannot proceed with discovery without interface IP configuration"
            echo "    Status: FAILED (no IP assigned)" >> "$WORKFLOW_REPORT"
            log_error "Critical failure: No IP address assigned to main interface after $max_retries attempts"
            exit 1
        fi
    fi
fi
fi  # end L2/L3 Stage 3 branch

echo "✓ Interface configuration completed" >&2
echo "VLAN interfaces configured: $interfaces_configured" >&2
echo "Status: SUCCESS" >> "$WORKFLOW_REPORT"
echo "Interfaces configured: $interfaces_configured" >> "$WORKFLOW_REPORT"
echo "Completed: $(date)" >> "$WORKFLOW_REPORT"
echo >> "$WORKFLOW_REPORT"

# L3 mode: collect target networks from discovered VLANs + manual input
if [ "$discovery_mode" = "l3" ]; then
    echo >&2
    if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
        printf "%s=== L3 Network Collection ===%s\n" "$COLOR_MINTCREAM" "$COLOR_RESET" >&2
    else
        echo "=== L3 Network Collection ===" >&2
    fi
    echo "Building list of networks to scan from source interface $l3_source_interface..." >&2

    # Build L3-specific VLAN_NETWORKS_FILE using same "label network" format as L2
    L3_NETWORKS_FILE="$TEMP_DIR/vlan_networks.txt"
    > "$L3_NETWORKS_FILE"

    # 1. Source VLAN local network — always first
    _l3_src_net=$(get_network_range "$l3_source_interface")
    if [ -n "$_l3_src_net" ]; then
        _l3_src_label="vlan_${l3_source_vlan:-main}"
        echo >&2
        echo "  Source network: $_l3_src_net" >&2
        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
            printf "%s  Use this as first scan target? (Enter=yes / custom CIDR): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
        else
            printf "  Use this as first scan target? (Enter=yes / custom CIDR): \n" >&2
        fi
        read -r _l3_src_confirm
        if [ -z "$_l3_src_confirm" ]; then
            echo "$_l3_src_label $_l3_src_net" >> "$L3_NETWORKS_FILE"
            echo "  ✓ Added source network: $_l3_src_net" >&2
        elif echo "$_l3_src_confirm" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$'; then
            echo "$_l3_src_label $_l3_src_confirm" >> "$L3_NETWORKS_FILE"
            echo "  ✓ Added custom source network: $_l3_src_confirm" >&2
        else
            echo "  ⚠ Invalid CIDR — skipping source network." >&2
        fi
    else
        echo "  ⚠ Could not determine network for $l3_source_interface." >&2
    fi

    # 2. Other discovered VLANs — infer network from captured IPs
    if [ -f "$TEMP_DIR/discovered_vlans.txt" ]; then
        while read -r _ov_id <&3; do
            [ -n "$_ov_id" ] || continue
            [ "$_ov_id" = "$l3_source_vlan" ] && continue  # skip source VLAN

            # Infer network from captured IPs for this VLAN
            _ov_ips=$(tshark -r "$capture_file" -Y "vlan.id == $_ov_id" -T fields -e ip.src -e ip.dst 2>/dev/null | \
                tr '\t' '\n' | grep -v "^$" | filter_valid_unicast_ips | sort -u)

            echo >&2
            if [ -n "$_ov_ips" ]; then
                _ov_first=$(echo "$_ov_ips" | head -1)
                _ov_base=$(echo "$_ov_first" | cut -d'.' -f1-3)
                _ov_inferred="${_ov_base}.0/24"
                echo "  VLAN $_ov_id: inferred $_ov_inferred" >&2
                if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
                    printf "%s  VLAN %s — use %s? (Enter=yes / custom CIDR / s=skip): %s\n" "$PROMPT_COLOR" "$_ov_id" "$_ov_inferred" "$COLOR_RESET" >&2
                else
                    printf "  VLAN %s — use %s? (Enter=yes / custom CIDR / s=skip): \n" "$_ov_id" "$_ov_inferred" >&2
                fi
            else
                echo "  VLAN $_ov_id: no IPs captured" >&2
                # No IPs — loop until user provides CIDR or explicitly skips
                while true; do
                    if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
                        printf "%s  VLAN %s — enter network range (CIDR) or s=skip: %s\n" "$PROMPT_COLOR" "$_ov_id" "$COLOR_RESET" >&2
                    else
                        printf "  VLAN %s — enter network range (CIDR) or s=skip: \n" "$_ov_id" >&2
                    fi
                    read -r _ov_answer
                    case "$_ov_answer" in
                        s|S|skip|SKIP)
                            echo "  Skipping VLAN $_ov_id" >&2
                            break
                            ;;
                        "")
                            echo "  Enter a CIDR (e.g. 10.20.0.0/24) or type 's' to skip." >&2
                            ;;
                        *)
                            if echo "$_ov_answer" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$'; then
                                echo "vlan_${_ov_id} $_ov_answer" >> "$L3_NETWORKS_FILE"
                                echo "  ✓ VLAN $_ov_id: $_ov_answer" >&2
                                break
                            else
                                echo "  ⚠ Invalid CIDR — try again." >&2
                            fi
                            ;;
                    esac
                done
                continue  # next VLAN in outer while loop
            fi

            read -r _ov_answer
            case "$_ov_answer" in
                s|S|skip|SKIP)
                    echo "  Skipping VLAN $_ov_id" >&2
                    continue
                    ;;
                "")
                    if [ -n "$_ov_inferred" ]; then
                        echo "vlan_${_ov_id} $_ov_inferred" >> "$L3_NETWORKS_FILE"
                        echo "  ✓ VLAN $_ov_id: $_ov_inferred" >&2
                    else
                        echo "  ⚠ No inferred network and no input — skipping VLAN $_ov_id." >&2
                    fi
                    ;;
                *)
                    if echo "$_ov_answer" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$'; then
                        echo "vlan_${_ov_id} $_ov_answer" >> "$L3_NETWORKS_FILE"
                        echo "  ✓ VLAN $_ov_id: $_ov_answer" >&2
                    else
                        echo "  ⚠ Invalid CIDR — skipping VLAN $_ov_id." >&2
                    fi
                    ;;
            esac
        done 3< "$TEMP_DIR/discovered_vlans.txt"
    fi

    # 3. Manual additional networks
    echo >&2
    while true; do
        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
            printf "%sAdd another network? (enter CIDR or press Enter to finish): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
        else
            printf "Add another network? (enter CIDR or press Enter to finish): \n" >&2
        fi
        read -r _extra_cidr
        [ -z "$_extra_cidr" ] && break
        if echo "$_extra_cidr" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$'; then
            _extra_label="network_$(echo "$_extra_cidr" | sed 's|/|_|g')"
            echo "$_extra_label $_extra_cidr" >> "$L3_NETWORKS_FILE"
            echo "  ✓ Added: $_extra_cidr" >&2
        else
            echo "  ⚠ Invalid CIDR — try again." >&2
        fi
    done

    VLAN_NETWORKS_FILE="$L3_NETWORKS_FILE"
    selected_vlan_count=$(wc -l < "$VLAN_NETWORKS_FILE" | tr -d ' ')

    # Summary
    echo >&2
    echo "Networks to scan ($selected_vlan_count):" >&2
    while read -r _lbl _net; do
        printf "  %-30s %s\n" "$_lbl" "$_net" >&2
    done < "$VLAN_NETWORKS_FILE"

    # Gate: verify and correct network ranges before scan
    review_and_confirm_networks "$VLAN_NETWORKS_FILE"

    # Create session discovery directory for L3
    DISCOVERY_DIR="$WORKDIR/discovery"
    SESSION_DISCOVERY_DIR="$DISCOVERY_DIR/auto_discovery"
    ensure_clean_session_dir "$SESSION_DISCOVERY_DIR"

    SESSION_METADATA="$SESSION_DISCOVERY_DIR/session_metadata.txt"
    {
        echo "=== Auto-Discovery L3 Session Metadata ==="
        echo "Session ID: auto_discovery"
        echo "Started: $(date)"
        echo "Mode: L3 Routed"
        echo "Interface: $target_interface"
        echo "Source VLAN: ${l3_source_vlan:-main}"
        echo "Source interface: $l3_source_interface"
        echo "Networks: $selected_vlan_count"
        echo "Session directory: $SESSION_DISCOVERY_DIR"
        echo ""
    } > "$SESSION_METADATA"

    echo "Status: SUCCESS" >> "$WORKFLOW_REPORT"
    echo "Networks collected: $selected_vlan_count" >> "$WORKFLOW_REPORT"
    log_info "L3 network collection complete: $selected_vlan_count networks"
fi

# Print a per-VLAN at-a-glance table for the final summary
print_vlan_discovery_overview() {
    sel_file="$1"
    net_file="$2"
    disc_dir="$3"

    [ -f "$sel_file" ] || return 0

    printf "  %-6s  %-20s  %-8s  %-6s  %s\n" \
        "VLAN" "Network" "Status" "Hosts" "Services" >&2
    echo "  ──────────────────────────────────────────────────────────────" >&2

    while read -r vlan_id; do
        [ -n "$vlan_id" ] || continue

        vlan_net=""
        if [ -f "$net_file" ]; then
            vlan_net=$(grep "^$vlan_id " "$net_file" | awk '{print $2}')
        fi
        [ -n "$vlan_net" ] || vlan_net="(no network)"

        vlan_dir="$disc_dir/vlan_$vlan_id"
        [ -d "$vlan_dir" ] || vlan_dir="$disc_dir/$vlan_id"
        host_count=0
        status="⊘ SKIP"
        if [ -d "$vlan_dir" ]; then
            if [ -f "$vlan_dir/hostfiles/all_discovered_hosts.txt" ]; then
                host_count=$(wc -l < "$vlan_dir/hostfiles/all_discovered_hosts.txt" 2>/dev/null || echo 0)
                status="✓ OK"
            else
                status="✗ FAIL"
            fi
        fi

        svc_summary=""
        for svc in ssh http smb ftp snmp rdp dns; do
            svc_file="$vlan_dir/service_targets/${svc}_targets.txt"
            if [ -f "$svc_file" ]; then
                cnt=$(wc -l < "$svc_file" 2>/dev/null || echo 0)
                [ "$cnt" -gt 0 ] && svc_summary="$svc_summary ${svc}:${cnt}"
            fi
        done
        svc_summary="${svc_summary# }"
        [ -n "$svc_summary" ] || svc_summary="-"
        [ "$host_count" -gt 0 ] || host_count="-"

        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
            case "$status" in
                "✓ OK")   status_col="${COLOR_GREEN}${status}${COLOR_RESET}" ;;
                "✗ FAIL") status_col="${COLOR_RED}${status}${COLOR_RESET}" ;;
                *)         status_col="${COLOR_YELLOW}${status}${COLOR_RESET}" ;;
            esac
            printf "  %-6s  %-20s  %-8s  %-6s  %s\n" \
                "$vlan_id" "$vlan_net" "$status_col" "$host_count" "$svc_summary" >&2
        else
            printf "  %-6s  %-20s  %-8s  %-6s  %s\n" \
                "$vlan_id" "$vlan_net" "$status" "$host_count" "$svc_summary" >&2
        fi
    done < "$sel_file"

    echo "  ──────────────────────────────────────────────────────────────" >&2
}

# Session-level consolidation and reporting functions
create_session_consolidation_reports() {
    if [ -z "$SESSION_DISCOVERY_DIR" ]; then
        echo "No session directory available for consolidation"
        return 1
    fi
    
    echo "Creating session-level consolidated reports..." >&2
    
    # Create consolidated session report
    CONSOLIDATED_REPORT="$SESSION_DISCOVERY_DIR/consolidated_report.txt"
    {
        echo "==============================================="
        echo "    AUTO-DISCOVERY SESSION CONSOLIDATED REPORT"
        echo "==============================================="
        echo "Generated: $(date)"
        echo "Session: auto_discovery"
        echo ""
        
        # Session overview
        echo "SESSION OVERVIEW:"
        if [ -f "$SESSION_METADATA" ]; then
            grep -E "(Session ID|Started|Interface|VLANs|Network|Total)" "$SESSION_METADATA" | sed 's/^/  /'
        fi
        echo ""
        
        # Consolidate host counts across all VLANs/networks
        echo "CONSOLIDATED HOST INVENTORY:"
        total_hosts=0
        total_services=0
        
        # Process each VLAN/network directory
        for net_dir in "$SESSION_DISCOVERY_DIR"/vlan_* "$SESSION_DISCOVERY_DIR"/main_network "$SESSION_DISCOVERY_DIR"/network_*; do
            if [ -d "$net_dir" ]; then
                net_name=$(basename "$net_dir")
                echo "  $net_name:"
                
                # Count hosts if file exists
                if [ -f "$net_dir/hostfiles/all_discovered_hosts.txt" ]; then
                    host_count=$(wc -l < "$net_dir/hostfiles/all_discovered_hosts.txt" 2>/dev/null || echo 0)
                    echo "    Hosts: $host_count"
                    total_hosts=$((total_hosts + host_count))
                fi
                
                # Count services from service_targets if available
                if [ -d "$net_dir/service_targets" ]; then
                    service_count=$(find "$net_dir/service_targets" -name "*_targets.txt" -exec wc -l {} + 2>/dev/null | tail -1 | awk '{print $1}' || echo 0)
                    echo "    Services: $service_count"
                    total_services=$((total_services + service_count))
                fi
            fi
        done
        
        echo ""
        echo "TOTAL SESSION INVENTORY:"
        echo "  Total Hosts: $total_hosts"
        echo "  Total Services: $total_services"
        echo ""
        
        # Cross-VLAN service summary
        echo "CROSS-VLAN SERVICE DISTRIBUTION:"
        for service_type in ssh smb web database dns snmp rdp; do
            service_total=0
            for net_dir in "$SESSION_DISCOVERY_DIR"/vlan_* "$SESSION_DISCOVERY_DIR"/main_network "$SESSION_DISCOVERY_DIR"/network_*; do
                if [ -f "$net_dir/service_targets/${service_type}_targets.txt" ]; then
                    count=$(wc -l < "$net_dir/service_targets/${service_type}_targets.txt" 2>/dev/null || echo 0)
                    service_total=$((service_total + count))
                fi
            done
            if [ $service_total -gt 0 ]; then
                printf "  %-12s: %d hosts\n" "$(echo "$service_type" | tr 'a-z' 'A-Z')" "$service_total"
            fi
        done
        echo ""

        echo "DIRECTORY STRUCTURE:"
        echo "  Session Directory: $SESSION_DISCOVERY_DIR"
        for net_dir in "$SESSION_DISCOVERY_DIR"/vlan_* "$SESSION_DISCOVERY_DIR"/main_network "$SESSION_DISCOVERY_DIR"/network_*; do
            if [ -d "$net_dir" ]; then
                echo "    $(basename "$net_dir")/: Individual network results"
            fi
        done
        echo "  session_team_handoff/: Cross-VLAN team coordination"
        echo "  consolidated_report.txt: This summary report"
        
    } > "$CONSOLIDATED_REPORT"
    
    # Create session-level team handoff consolidation
    SESSION_TEAM_HANDOFF_DIR="$SESSION_DISCOVERY_DIR/session_team_handoff"
    mkdir -p "$SESSION_TEAM_HANDOFF_DIR"
    
    # Consolidate team targets across all VLANs from categorized directories
    {
        echo "=== SESSION-LEVEL TEAM COORDINATION ==="
        echo "Generated: $(date)"
        echo "Session: auto_discovery"
        echo ""
        echo "This file consolidates team assignments across all VLANs/networks"
        echo "in this auto-discovery session for coordinated assessment planning."
        echo ""
        
        # For each team, consolidate targets from categorized directories
        for team in windows linux network; do
            echo "== $(echo "$team" | tr 'a-z' 'A-Z') TEAM SESSION SUMMARY =="
            total_targets=0
            
            for net_dir in "$SESSION_DISCOVERY_DIR"/vlan_* "$SESSION_DISCOVERY_DIR"/main_network "$SESSION_DISCOVERY_DIR"/network_*; do
                if [ -d "$net_dir/hostfiles" ]; then
                    net_name=$(basename "$net_dir")
                    echo "$net_name targets:"
                    
                    # Extract target counts from categorized files
                    case "$team" in
                        "windows")
                            windows_count=0
                            if [ -f "$net_dir/hostfiles/windows_hosts.txt" ]; then
                                windows_count=$(wc -l < "$net_dir/hostfiles/windows_hosts.txt" 2>/dev/null || echo 0)
                                echo "  Windows hosts: $windows_count"
                                total_targets=$((total_targets + windows_count))
                            fi
                            ;;
                        "linux")
                            linux_count=0
                            if [ -f "$net_dir/hostfiles/linux_hosts.txt" ]; then
                                linux_count=$(wc -l < "$net_dir/hostfiles/linux_hosts.txt" 2>/dev/null || echo 0)
                                echo "  Linux/Unix hosts: $linux_count"
                                total_targets=$((total_targets + linux_count))
                            fi
                            ;;
                        "network")
                            network_count=0
                            if [ -f "$net_dir/hostfiles/network_devices.txt" ]; then
                                network_count=$(wc -l < "$net_dir/hostfiles/network_devices.txt" 2>/dev/null || echo 0)
                                echo "  Network devices: $network_count"
                                total_targets=$((total_targets + network_count))
                            fi
                            ;;
                    esac
                fi
            done
            
            echo "Total $(echo "$team" | tr 'a-z' 'A-Z') targets: $total_targets"
            echo ""
        done
        
        echo "== MANUAL ASSIGNMENT COORDINATION =="
        echo "Web and database services requiring manual assignment:"
        for net_dir in "$SESSION_DISCOVERY_DIR"/vlan_* "$SESSION_DISCOVERY_DIR"/main_network "$SESSION_DISCOVERY_DIR"/network_*; do
            if [ -d "$net_dir/hostfiles" ]; then
                net_name=$(basename "$net_dir")
                web_count=0
                db_count=0
                
                if [ -f "$net_dir/hostfiles/web_servers.txt" ]; then
                    web_count=$(wc -l < "$net_dir/hostfiles/web_servers.txt" 2>/dev/null || echo 0)
                fi
                if [ -f "$net_dir/hostfiles/database_servers.txt" ]; then
                    db_count=$(wc -l < "$net_dir/hostfiles/database_servers.txt" 2>/dev/null || echo 0)
                fi
                
                if [ $web_count -gt 0 ] || [ $db_count -gt 0 ]; then
                    echo "$net_name: Web: $web_count, Database: $db_count"
                fi
            fi
        done
        
    } > "$SESSION_TEAM_HANDOFF_DIR/SESSION_TEAM_COORDINATION.txt"
    
    echo "Session consolidation complete" >&2
echo "  Consolidated report: $CONSOLIDATED_REPORT" >&2
echo "  Team coordination: $SESSION_TEAM_HANDOFF_DIR/SESSION_TEAM_COORDINATION.txt" >&2
}

# ensure_clean_session_dir — offer to remove or reuse an existing session directory,
# then create it. Args: $1=directory path
ensure_clean_session_dir() {
    if [ -d "$1" ] && [ -f "$1/session_metadata.txt" ]; then
        echo "Found existing auto-discovery session: $1" >&2
        if confirm_action "Remove existing session and start fresh?"; then
            echo "Removing existing session..." >&2
            rm -rf "$1"
        else
            echo "Reusing existing session directory." >&2
        fi
    fi
    mkdir -p "$1"
}

# review_and_confirm_networks — interactive pre-scan review of collected network ranges.
# Args: $1=path to networks file ("id network" per line)
# Lets the user correct any entry before discovery begins; calls exit 0 on cancel.
review_and_confirm_networks() {
    _rcn_file="$1"
    while true; do
        echo "" >&2
        echo "=== Pre-Discovery Network Review ===" >&2
        if [ ! -s "$_rcn_file" ]; then
            echo "  No networks configured for discovery." >&2
            if ! confirm_action "Proceed anyway (no networks will be scanned)?"; then
                echo "Discovery cancelled by user." >&2
                echo "Status: CANCELLED" >> "$WORKFLOW_REPORT"
                exit 0
            fi
            return 0
        fi
        echo "  The following networks are scheduled for discovery:" >&2
        echo "" >&2
        _rcn_idx=1
        while IFS=' ' read -r _rcn_id _rcn_net; do
            [ -n "$_rcn_id" ] || continue
            case "$_rcn_id" in
                [0-9]*)
                    _rcn_label="VLAN $_rcn_id" ;;
                vlan_*)
                    _rcn_label="VLAN ${_rcn_id#vlan_}" ;;
                *)
                    _rcn_label="$_rcn_id" ;;
            esac
            printf "  %3d)  %-24s  %s\n" "$_rcn_idx" "$_rcn_label" "$_rcn_net" >&2
            _rcn_idx=$((_rcn_idx + 1))
        done < "$_rcn_file"
        _rcn_total=$((_rcn_idx - 1))
        echo "" >&2
        echo "  p) Proceed with discovery" >&2
        echo "  r) Reconfigure a network range" >&2
        echo "  x) Cancel" >&2
        echo "" >&2
        _rcn_choice=$(get_validated_input "Choice [p/r/x]" "" "p")
        case "$_rcn_choice" in
            p|P)
                return 0
                ;;
            r|R)
                _rcn_sel=$(prompt_for_choice "Select entry to reconfigure (1-$_rcn_total)" 1 "$_rcn_total")
                _rcn_line=$(awk "NR==$_rcn_sel" "$_rcn_file")
                _rcn_vid=$(echo "$_rcn_line" | awk '{print $1}')
                _rcn_cur=$(echo "$_rcn_line" | awk '{print $2}')
                echo "" >&2
                echo "  Network: $_rcn_vid" >&2
                echo "  Current: $_rcn_cur" >&2
                _rcn_new=$(prompt_for_cidr "New CIDR for $_rcn_vid" "$_rcn_cur")
                _rcn_tmp=$(mktemp)
                awk -v n="$_rcn_sel" -v vid="$_rcn_vid" -v net="$_rcn_new" \
                    'NR==n { print vid " " net; next } { print }' "$_rcn_file" > "$_rcn_tmp"
                mv "$_rcn_tmp" "$_rcn_file"
                echo "  ✓ Updated: $_rcn_vid -> $_rcn_new" >&2
                ;;
            x|X|q|Q)
                echo "Discovery cancelled by user." >&2
                echo "Status: CANCELLED" >> "$WORKFLOW_REPORT"
                exit 0
                ;;
            *)
                echo "  Enter p to proceed, r to reconfigure, or x to cancel." >&2
                ;;
        esac
    done
}

# Stage 4: Network Discovery
if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
    printf "%s%s%s\n" "$COLOR_YELLOW" "Stage 4/5: NETWORK DISCOVERY — Multi-phase scan execution" "$COLOR_RESET"
elif command -v print_phase_header >/dev/null 2>&1; then
    print_phase_header "STAGE 4: NETWORK DISCOVERY"
else
    echo >&2
    echo "=== Stage 4: Network Discovery ==="
fi
echo "--- STAGE 4: NETWORK DISCOVERY ---" >> "$WORKFLOW_REPORT"
echo "Started: $(date)" >> "$WORKFLOW_REPORT"

log_info "Starting Stage 4: Network discovery"

echo "Preparing VLAN-aware discovery..." >&2
discovery_script="$(dirname "$0")/../discovery/multi_phase_discovery.sh"

if [ -x "$discovery_script" ]; then
    if [ "$selected_vlan_count" -gt 0 ]; then
        echo "Running VLAN-aware discovery with separate results per VLAN..."
        echo "VLAN-aware discovery initiated" >&2 >> "$WORKFLOW_REPORT"
        
        # Create session-based discovery structure with VLAN organization
        if [ -z "$SESSION_DISCOVERY_DIR" ]; then
            DISCOVERY_DIR="$WORKDIR/discovery"
            SESSION_DISCOVERY_DIR="$DISCOVERY_DIR/auto_discovery"
            ensure_clean_session_dir "$SESSION_DISCOVERY_DIR"

            # Create session metadata (L2 mode — L3 metadata was written during network collection)
            SESSION_METADATA="$SESSION_DISCOVERY_DIR/session_metadata.txt"
            {
                echo "=== Auto-Discovery Session Metadata ==="
                echo "Session ID: auto_discovery"
                echo "Started: $(date)"
                echo "Interface: $target_interface"
                echo "VLANs discovered: $selected_vlan_count"
                echo "Session directory: $SESSION_DISCOVERY_DIR"
                echo ""
            } > "$SESSION_METADATA"
        fi
        discovery_success=0
        
        if [ "$discovery_mode" = "l2" ]; then
        # Stage 4a: Network Collection
        # Collect all VLAN networks upfront before starting discoveries
        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
            printf "%s%s%s\n" "$COLOR_YELLOW" "Stage 4a: NETWORK COLLECTION — Collecting discovery networks for all VLANs" "$COLOR_RESET"
        elif command -v print_phase_header >/dev/null 2>&1; then
            print_phase_header "STAGE 4a: NETWORK COLLECTION" >&2
            color_info "Collecting discovery networks for all VLANs..." >&2
        else
            echo >&2
            echo "=== Stage 4a: Network Collection ===" >&2
            echo "Collecting discovery networks for all VLANs..." >&2
            echo >&2
        fi

        # Create temp file for network storage
        VLAN_NETWORKS_FILE="$TEMP_DIR/vlan_networks.txt"
        > "$VLAN_NETWORKS_FILE"  # Initialize empty file

        # Loop through each VLAN and collect network choices
        _vlan_current=0
        while read -r vlan_id <&3; do
            if [ -n "$vlan_id" ]; then
                _vlan_current=$((_vlan_current + 1))
                vlan_interface="${target_interface}.${vlan_id}"

                if command -v print_progress >/dev/null 2>&1; then
                    print_progress "$_vlan_current" "$selected_vlan_count" "Processing VLAN $vlan_id: Collecting network configuration" >&2
                else
                    echo "=== VLAN $vlan_id Network Configuration ===" >&2
                fi

                # Check if interface exists and has IP
                if ip addr show "$vlan_interface" >/dev/null 2>&1; then
                    vlan_network=$(get_network_range "$vlan_interface")
                    if [ -n "$vlan_network" ]; then
                        echo "  VLAN $vlan_id interface network: $vlan_network" >&2

                        # Prompt user to confirm scan network for this VLAN
                        echo "  VLAN $vlan_id Discovery Network Configuration:" >&2
                        echo "  1. Use interface network: $vlan_network" >&2
                        echo "  2. Enter custom network range" >&2
                        echo >&2
                        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
                            printf "%s  Select discovery network for VLAN %s (1-2): %s\n" "$PROMPT_COLOR" "$vlan_id" "$COLOR_RESET" >&2
                        else
                            printf "  Select discovery network for VLAN %s (1-2): \n" "$vlan_id" >&2
                        fi
                        read -r vlan_network_choice

                        case "$vlan_network_choice" in
                            1|"")
                                vlan_discovery_network="$vlan_network"
                                echo "  ✓ Using interface network: $vlan_discovery_network" >&2
                                ;;
                            2)
                                echo >&2
                                if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
                                    printf "%s  Enter network range in CIDR notation (e.g., 192.168.1.0/24): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
                                else
                                    printf "  Enter network range in CIDR notation (e.g., 192.168.1.0/24): \n" >&2
                                fi
                                read -r vlan_custom_network

                                if [ -n "$vlan_custom_network" ] && echo "$vlan_custom_network" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$'; then
                                    vlan_discovery_network="$vlan_custom_network"
                                    echo "  ✓ Using custom network: $vlan_discovery_network" >&2
                                else
                                    echo "  Invalid format, using interface network: $vlan_network" >&2
                                    vlan_discovery_network="$vlan_network"
                                fi
                                ;;
                            *)
                                echo "  Invalid choice, using interface network: $vlan_network" >&2
                                vlan_discovery_network="$vlan_network"
                                ;;
                        esac

                        # Store VLAN and network in temp file
                        echo "$vlan_id $vlan_discovery_network" >> "$VLAN_NETWORKS_FILE"
                        echo "  Recorded: VLAN $vlan_id → $vlan_discovery_network" >&2

                    else
                        echo "  ⚠ No IP configured on $vlan_interface — cannot auto-detect network" >&2
                        echo >&2
                        echo "  1. Enter network range manually (CIDR, e.g. 192.168.10.0/24)" >&2
                        echo "  2. Skip VLAN $vlan_id" >&2
                        echo >&2
                        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
                            printf "%s  Choice [1-2]: %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
                        else
                            printf "  Choice [1-2]: \n" >&2
                        fi
                        read -r fallback_choice
                        case "$fallback_choice" in
                            1)
                                echo >&2
                                if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
                                    printf "%s  Enter network range in CIDR notation (e.g., 192.168.10.0/24): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
                                else
                                    printf "  Enter network range in CIDR notation (e.g., 192.168.10.0/24): \n" >&2
                                fi
                                read -r fallback_cidr
                                if [ -n "$fallback_cidr" ] && echo "$fallback_cidr" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$'; then
                                    echo "$vlan_id $fallback_cidr" >> "$VLAN_NETWORKS_FILE"
                                    echo "  ✓ Recorded: VLAN $vlan_id → $fallback_cidr" >&2
                                else
                                    echo "  ✗ Invalid CIDR format, skipping VLAN $vlan_id" >&2
                                fi
                                ;;
                            *)
                                echo "  Skipping VLAN $vlan_id" >&2
                                ;;
                        esac
                    fi
                else
                    echo "  ⚠ VLAN interface $vlan_interface not found or not configured" >&2
                    echo "  VLAN $vlan_id will be skipped during discovery" >&2
                fi
                echo >&2
            fi
        done 3< "$TEMP_DIR/selected_vlans.txt"

        # Show summary of collected networks
        if command -v color_success >/dev/null 2>&1; then
            echo >&2
            color_success "Network collection complete" >&2
        else
            echo >&2
            echo "==========================================" >&2
            echo "   Network Collection Complete" >&2
            echo "==========================================" >&2
        fi
        echo >&2

        if [ -s "$VLAN_NETWORKS_FILE" ]; then
            vlan_network_count=$(wc -l < "$VLAN_NETWORKS_FILE" | tr -d ' ')
            echo "  $vlan_network_count network(s) collected. Review before scanning." >&2
            echo >&2

        else
            echo "⚠ No VLANs configured for discovery" >&2
            echo "Status: SKIPPED (no networks)" >> "$WORKFLOW_REPORT"
            log_warn "No VLANs configured for discovery"
        fi

        fi  # end L2 Stage 4a

        # Gate: verify and correct collected VLAN network ranges before scan
        review_and_confirm_networks "$VLAN_NETWORKS_FILE"

        # Stage 4b: Network Discovery Execution
        # Execute discoveries using pre-collected network ranges
        # In L3 mode Stage 4a is skipped; derive vlan_network_count from the already-populated file
        if [ "$discovery_mode" = "l3" ]; then
            vlan_network_count=$(wc -l < "$VLAN_NETWORKS_FILE" | tr -d ' ')
        fi
        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
            printf "%s%s%s\n" "$COLOR_YELLOW" "Stage 4b: NETWORK DISCOVERY EXECUTION — Running network discovery on configured VLANs" "$COLOR_RESET"
        elif command -v print_phase_header >/dev/null 2>&1; then
            print_phase_header "STAGE 4b: NETWORK DISCOVERY EXECUTION" >&2
            color_info "Running network discovery on configured VLANs..." >&2
        else
            echo >&2
            echo "=== Stage 4b: Network Discovery Execution ===" >&2
            echo "Running network discovery on configured VLANs..." >&2
            echo >&2
        fi

        # Pre-flight: resolve resume/fresh decisions before background launch.
        # Subprocess output is fully captured, so interactive prompts must happen here.
        # Leaving .phase_progress in place signals resume; deleting it signals fresh start.
        while IFS=' ' read -r _pf_id _; do
            [ -n "$_pf_id" ] || continue
            if [ "$discovery_mode" = "l3" ]; then
                _pf_dir="$SESSION_DISCOVERY_DIR/$_pf_id"
            else
                _pf_dir="$SESSION_DISCOVERY_DIR/vlan_$_pf_id"
            fi
            if [ -f "$_pf_dir/.phase_progress" ]; then
                _pf_done=$(tr '\n' ' ' < "$_pf_dir/.phase_progress" | sed 's/phase//g; s/  */ /g; s/^ //; s/ $//')
                echo "" >&2
                echo "  Incomplete session found for $_pf_id:" >&2
                echo "  Phases completed: $_pf_done" >&2
                if confirm_action "  Resume $_pf_id from last completed phase?"; then
                    echo "  Will resume $_pf_id." >&2
                else
                    rm -f "$_pf_dir/.phase_progress"
                    echo "  Will restart $_pf_id from the beginning." >&2
                fi
            fi
        done < "$VLAN_NETWORKS_FILE"

        # Concurrency cap: how many VLANs to scan simultaneously.
        _vlan_default_cap=4
        [ "$vlan_network_count" -gt 0 ] && [ "$_vlan_default_cap" -gt "$vlan_network_count" ] && _vlan_default_cap="$vlan_network_count"
        echo >&2
        echo "Concurrent VLAN scan limit (default $_vlan_default_cap):" >&2
        echo "  Higher = faster overall; lower = less network/CPU load." >&2
        echo >&2
        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
            printf "%sMax concurrent VLANs [1-%s, default %s]: %s\n" "$PROMPT_COLOR" "$vlan_network_count" "$_vlan_default_cap" "$COLOR_RESET" >&2
        else
            printf "Max concurrent VLANs [1-%s, default %s]: \n" "$vlan_network_count" "$_vlan_default_cap" >&2
        fi
        read -r vlan_cap
        vlan_cap=${vlan_cap:-$_vlan_default_cap}
        case "$vlan_cap" in
            *[!0-9]*)
                echo "  Invalid input. Using default: $_vlan_default_cap" >&2
                vlan_cap=$_vlan_default_cap
                ;;
            *)
                [ "$vlan_network_count" -gt 0 ] && [ "$vlan_cap" -gt "$vlan_network_count" ] && vlan_cap="$vlan_network_count"
                [ "$vlan_cap" -lt 1 ] && vlan_cap=1
                ;;
        esac
        echo "  Concurrency cap: $vlan_cap of $vlan_network_count VLANs at a time" >&2
        echo >&2

        # FIFO counting semaphore on FD9 ($vlan_cap tokens pre-loaded).
        # The launch loop acquires a token before each background job; the subshell
        # releases it on completion. FD3 is reserved for VLAN_NETWORKS_FILE reads.
        _sem_fifo="$TEMP_DIR/sem_$$"
        mkfifo "$_sem_fifo"
        exec 9<>"$_sem_fifo"
        _i=0
        while [ "$_i" -lt "$vlan_cap" ]; do
            printf 'x\n' >&9
            _i=$((_i + 1))
        done
        echo "Discovery will now begin on $vlan_network_count VLAN(s). This may take some time." >&2
        echo "You can safely leave this running." >&2
        echo >&2
        # Launch VLAN discoveries — each in an isolated subshell, capped by the semaphore.
        _vlan_pids=""
        _vlan_current=0
        while read -r vlan_id vlan_discovery_network <&3; do
            [ -n "$vlan_id" ] && [ -n "$vlan_discovery_network" ] || continue

            _vlan_current=$((_vlan_current + 1))
            vlan_interface="${target_interface}.${vlan_id}"
            if [ "$discovery_mode" = "l3" ]; then
                vlan_discovery_dir="$SESSION_DISCOVERY_DIR/$vlan_id"
            else
                vlan_discovery_dir="$SESSION_DISCOVERY_DIR/vlan_$vlan_id"
            fi
            _disc_status="$TEMP_DIR/status_${vlan_id}.txt"

            mkdir -p "$vlan_discovery_dir/meta"

            read -r _tok <&9  # acquire token — blocks here when cap is reached

            emit_progress "VLAN $vlan_id ($vlan_discovery_network)" "$_vlan_current" "$vlan_network_count"
            echo "  VLAN $vlan_id: launching discovery on $vlan_discovery_network..." >&2
            echo "  VLAN $vlan_id discovery:" >> "$WORKFLOW_REPORT"
            echo "    Discovery network: $vlan_discovery_network" >> "$WORKFLOW_REPORT"

            log_info "VLAN $vlan_id discovery launching (background): $vlan_discovery_network"

            # Subshell isolates environment; child output captured per-VLAN, not to terminal.
            # 9>&- closes FD9 in the discovery script subprocess only; the subshell keeps it
            # open to release the semaphore token with printf after the script exits.
            (
                export MANUAL_NETWORK_RANGE="$vlan_discovery_network"
                export AUTO_DISCOVERY_SESSION="true"
                export AUTO_DISCOVERY_LIGHTWEIGHT="true"
                export AUTO_DISCOVERY_VLAN_ID="$vlan_id"
                export AUTO_DISCOVERY_VLAN_DIR="$vlan_discovery_dir"
                export AUTO_DISCOVERY_SESSION_DIR="$SESSION_DISCOVERY_DIR"
                if [ "$discovery_mode" = "l3" ]; then
                    _subinv_iface="$l3_source_interface"
                    if [ "$vlan_id" != "${_l3_src_label:-}" ]; then
                        export ROUTED_VLAN_MODE="true"
                    fi
                else
                    _subinv_iface="$vlan_interface"
                fi
                { "$discovery_script" "$_subinv_iface" "1" 3<&- 9>&-; echo $? > "$_disc_status"; } 2>&1 | \
                    tee "$vlan_discovery_dir/meta/discovery_output.txt" > /dev/null
                printf 'x\n' >&9  # release token
            ) &
            _vlan_pids="$_vlan_pids $!"

        done 3< "$VLAN_NETWORKS_FILE"

        echo "  Waiting for all $vlan_network_count VLAN discoveries to complete..." >&2

        # Build VLAN ID list for the poller (re-read file; FD3 was closed by the loop above).
        _poll_ids=""
        while IFS=' ' read -r _pv_id _; do
            [ -n "$_pv_id" ] || continue
            _poll_ids="$_poll_ids $_pv_id"
        done < "$VLAN_NETWORKS_FILE"

        # Sentinel file: poller exits when this appears.
        _poll_sentinel="$TEMP_DIR/poll_sentinel_$$"

        # Background progress poller — emits aggregated ##NETUTIL:PROGRESS## every 2s.
        (
            _pv_total=$vlan_network_count
            while [ ! -f "$_poll_sentinel" ]; do
                _pv_done=0
                _pv_parts=""
                for _pv_id in $_poll_ids; do
                    case "$_pv_id" in
                    vlan_*) _pv_short="V${_pv_id#vlan_}" ;;
                        network_*) _pv_short="net:$(echo "${_pv_id#network_}" | sed 's/_\([0-9]*\)$/\/\1/')" ;;
                        [0-9]*) _pv_short="V$_pv_id" ;;
                        *) _pv_short="$_pv_id" ;;
                    esac
                    if [ -f "$TEMP_DIR/status_${_pv_id}.txt" ]; then
                        _pv_done=$((_pv_done + 1))
                        _pv_parts="$_pv_parts ${_pv_short}:done"
                    elif [ -f "$SESSION_DISCOVERY_DIR/vlan_${_pv_id}/phase_progress" ] || \
                         [ -f "$SESSION_DISCOVERY_DIR/${_pv_id}/phase_progress" ]; then
                        _pp_file="$SESSION_DISCOVERY_DIR/vlan_${_pv_id}/phase_progress"
                        [ -f "$_pp_file" ] || _pp_file="$SESSION_DISCOVERY_DIR/${_pv_id}/phase_progress"
                        read -r _pv_line < "$_pp_file"
                        _pv_cur="${_pv_line%% *}"
                        _pv_rest="${_pv_line#* }"
                        _pv_tot="${_pv_rest%% *}"
                        _pv_parts="$_pv_parts ${_pv_short}:${_pv_cur}/${_pv_tot}"
                    else
                        _pv_parts="$_pv_parts ${_pv_short}:0/8"
                    fi
                done
                printf '##NETUTIL:PROGRESS## [%s/%s VLANs]%s\n' \
                    "$_pv_done" "$_pv_total" "$_pv_parts"
                sleep 2
            done
        ) &
        _poll_pid=$!

        for _vpid in $_vlan_pids; do
            wait "$_vpid" 2>/dev/null
        done
        exec 9>&-  # close semaphore FD

        # Terminate poller
        touch "$_poll_sentinel"
        wait "$_poll_pid" 2>/dev/null
        rm -f "$_poll_sentinel"
        # Remove phase_progress files now that all VLANs have finished
        for _cleanup_id in $_poll_ids; do
            rm -f "$SESSION_DISCOVERY_DIR/vlan_${_cleanup_id}/phase_progress" \
                  "$SESSION_DISCOVERY_DIR/${_cleanup_id}/phase_progress" \
                  2>/dev/null || true
        done

        # Collect results now that all background jobs have finished
        while read -r vlan_id vlan_discovery_network <&3; do
            [ -n "$vlan_id" ] || continue
            if [ "$discovery_mode" = "l3" ]; then
                vlan_discovery_dir="$SESSION_DISCOVERY_DIR/$vlan_id"
            else
                vlan_discovery_dir="$SESSION_DISCOVERY_DIR/vlan_$vlan_id"
            fi
            _disc_status="$TEMP_DIR/status_${vlan_id}.txt"

            vlan_discovery_exit=$(cat "$_disc_status" 2>/dev/null || echo 1)
            rm -f "$_disc_status"

            if [ "$vlan_discovery_exit" -eq 0 ]; then
                echo "  ✓ VLAN $vlan_id ($vlan_discovery_network) completed" >&2
                echo "    Status: SUCCESS" >> "$WORKFLOW_REPORT"
                discovery_success=$((discovery_success + 1))
                echo "VLAN $vlan_id: SUCCESS - Network $vlan_discovery_network" >> "$SESSION_METADATA"
            else
                echo "  ✗ VLAN $vlan_id ($vlan_discovery_network) failed" >&2
                echo "    Status: FAILED" >> "$WORKFLOW_REPORT"
                log_warn "Discovery failed for VLAN $vlan_id"
            fi

            echo "    Output summary:" >> "$WORKFLOW_REPORT"
            head -20 "$vlan_discovery_dir/meta/discovery_output.txt" 2>/dev/null | sed 's/^/      /' >> "$WORKFLOW_REPORT"
        done 3< "$VLAN_NETWORKS_FILE"
        
        # Summary
        if [ $discovery_success -gt 0 ]; then
            echo "✓ VLAN-aware discovery completed: $discovery_success VLANs discovered successfully"
            echo "Status: SUCCESS ($discovery_success VLANs)" >> "$WORKFLOW_REPORT"
            echo "Discovery results organized in session: $SESSION_DISCOVERY_DIR"
            
            # Update latest symlinks for session results
            update_latest_links "discovery" "$SESSION_DISCOVERY_DIR"
            
            # Create overall summary
            discovery_summary="$REPORT_SESSION_DIR/vlan_discovery_summary.txt"
            echo "VLAN Discovery Summary:" > "$discovery_summary"
            if [ "$discovery_mode" = "l3" ]; then
                find "$SESSION_DISCOVERY_DIR" -mindepth 1 -maxdepth 1 -type d
            else
                find "$SESSION_DISCOVERY_DIR" -maxdepth 1 \( -name "vlan_*" -o -name "main_network" -o -name "network_*" \) -type d
            fi | while read -r vlan_dir; do
                vlan_name=$(basename "$vlan_dir")
                echo "- $vlan_name: $([ -f "$vlan_dir/meta/discovery_output.txt" ] && echo "SUCCESS" || echo "FAILED")" >> "$discovery_summary"
            done
            echo "VLAN discovery summary: $discovery_summary"
            
            # Finalize session metadata
            echo "Session completed: $(date)" >> "$SESSION_METADATA"
            echo "Total successful VLANs: $discovery_success"
            
            # Create session-level consolidation and reporting
            create_session_consolidation_reports >> "$SESSION_METADATA"
        else
            echo "✗ All VLAN discoveries failed"
            echo "Status: FAILED" >> "$WORKFLOW_REPORT"
            log_error "All VLAN discoveries failed in auto-discovery workflow"
        fi
    else
        # No VLANs scenario - standard discovery on main interface with network confirmation
        echo "Running standard discovery on main interface..."
        echo "Standard discovery initiated" >> "$WORKFLOW_REPORT"
        
        # Get current network range from main interface
        main_interface_network=$(get_network_range "$target_interface")
        
        if [ -n "$main_interface_network" ]; then
            echo "Current interface network: $main_interface_network"
            echo "    Interface network: $main_interface_network" >> "$WORKFLOW_REPORT"
            
            # Extract captured traffic networks for additional suggestions
            main_ips=$(tshark -r "$capture_file" -Y "not vlan" -T fields -e ip.src -e ip.dst 2>/dev/null | \
                      tr '\t' '\n' | grep -v "^$" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | \
                      grep -v '^127\.' | grep -v '^169\.254\.' | sort -u)
            
            # Suggest scan network (user must confirm)
            echo >&2
            echo "Network Discovery Configuration:" >&2
            echo "1. Use interface network: $main_interface_network" >&2

            if [ -n "$main_ips" ]; then
                # Analyze traffic for alternative networks
                traffic_networks=$(echo "$main_ips" | while read -r ip; do
                    if [ -n "$ip" ]; then
                        network_base=$(echo "$ip" | cut -d'.' -f1-3)
                        echo "${network_base}.0/24"
                    fi
                done | sort -u)

                echo "2. Networks from captured traffic:" >&2
                echo "$traffic_networks" | head -3 | sed 's/^/   /' >&2
                echo "3. Enter custom network range" >&2
            else
                echo "2. Enter custom network range" >&2
            fi
            echo >&2
            if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
                if [ -n "$main_ips" ]; then
                    printf "%sSelect discovery network (1-3): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
                else
                    printf "%sSelect discovery network (1,2): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
                fi
            else
                if [ -n "$main_ips" ]; then
                    printf "Select discovery network (1-3): \n" >&2
                else
                    printf "Select discovery network (1,2): \n" >&2
                fi
            fi
            read -r network_choice
            
            case "$network_choice" in
                1)
                    discovery_network="$main_interface_network"
                    echo "✓ Using interface network: $discovery_network"
                    echo "    Discovery network: $discovery_network (interface)" >> "$WORKFLOW_REPORT"
                    ;;
                2)
                    if [ -n "$main_ips" ]; then
                        # Show traffic networks for selection
                        echo "Available networks from traffic:"
                        echo "$traffic_networks" | head -5 | nl -v1 -w2 -s') '
                        echo >&2
                        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
                            printf "%sSelect network (1-%s): %s\n" "$PROMPT_COLOR" "$(echo "$traffic_networks" | head -5 | wc -l)" "$COLOR_RESET" >&2
                        else
                            printf "Select network (1-%s): \n" "$(echo "$traffic_networks" | head -5 | wc -l)" >&2
                        fi
                        read -r traffic_choice
                        
                        discovery_network=$(echo "$traffic_networks" | sed -n "${traffic_choice}p")
                        if [ -n "$discovery_network" ]; then
                            echo "✓ Using traffic network: $discovery_network"
                            echo "    Discovery network: $discovery_network (traffic)" >> "$WORKFLOW_REPORT"
                        else
                            echo "Invalid selection, using interface network: $main_interface_network"
                            discovery_network="$main_interface_network"
                            echo "    Discovery network: $discovery_network (fallback)" >> "$WORKFLOW_REPORT"
                        fi
                    else
                        echo >&2
                        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
                            printf "%sEnter network range in CIDR notation (e.g., 192.168.1.0/24): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
                        else
                            printf "Enter network range in CIDR notation (e.g., 192.168.1.0/24): \n" >&2
                        fi
                        read -r custom_network

                        if [ -n "$custom_network" ] && echo "$custom_network" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$'; then
                            discovery_network="$custom_network"
                            echo "✓ Using custom network: $discovery_network"
                            echo "    Discovery network: $discovery_network (custom)" >> "$WORKFLOW_REPORT"
                        else
                            echo "Invalid format, using interface network: $main_interface_network"
                            discovery_network="$main_interface_network"
                            echo "    Discovery network: $discovery_network (fallback)" >> "$WORKFLOW_REPORT"
                        fi
                    fi
                    ;;
                3)
                    echo >&2
                    if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
                        printf "%sEnter network range in CIDR notation (e.g., 192.168.1.0/24): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
                    else
                        printf "Enter network range in CIDR notation (e.g., 192.168.1.0/24): \n" >&2
                    fi
                    read -r custom_network
                    
                    if [ -n "$custom_network" ] && echo "$custom_network" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$'; then
                        discovery_network="$custom_network"
                        echo "✓ Using custom network: $discovery_network"
                        echo "    Discovery network: $discovery_network (custom)" >> "$WORKFLOW_REPORT"
                    else
                        echo "Invalid format, using interface network: $main_interface_network"
                        discovery_network="$main_interface_network"
                        echo "    Discovery network: $discovery_network (fallback)" >> "$WORKFLOW_REPORT"
                    fi
                    ;;
                *)
                    echo "Invalid choice, using interface network: $main_interface_network"
                    discovery_network="$main_interface_network"
                    echo "    Discovery network: $discovery_network (default)" >> "$WORKFLOW_REPORT"
                    ;;
            esac
            
            log_info "Discovery network selected: $discovery_network"
            
        else
            echo "⚠ No network range found for interface $target_interface"
            echo "    Status: SKIPPED (no network)" >> "$WORKFLOW_REPORT"
            log_error "No network range found for main interface $target_interface"
            echo "✗ Cannot proceed with discovery - interface has no network configuration"
            exit 1
        fi
        
        # Create session-based discovery structure for main network
        DISCOVERY_DIR="$WORKDIR/discovery"
        SESSION_DISCOVERY_DIR="$DISCOVERY_DIR/auto_discovery"
        ensure_clean_session_dir "$SESSION_DISCOVERY_DIR"
        MAIN_NETWORK_DIR="$SESSION_DISCOVERY_DIR/main_network"
        mkdir -p "$MAIN_NETWORK_DIR/meta"

        # Create session metadata
        SESSION_METADATA="$SESSION_DISCOVERY_DIR/session_metadata.txt"
        {
            echo "=== Auto-Discovery Session Metadata ==="
            echo "Session ID: auto_discovery"
            echo "Started: $(date)"
            echo "Interface: $target_interface"
            echo "Discovery Mode: Standard (main network)"
            echo "Network: $discovery_network"
            echo "Session directory: $SESSION_DISCOVERY_DIR"
            echo ""
        } > "$SESSION_METADATA"

        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
            printf "%s%s%s\n" "$COLOR_YELLOW" "Stage 4: NETWORK DISCOVERY EXECUTION — Running network discovery on main interface" "$COLOR_RESET"
        elif command -v print_phase_header >/dev/null 2>&1; then
            print_phase_header "STAGE 4: NETWORK DISCOVERY EXECUTION" >&2
            color_info "Running network discovery on $discovery_network..." >&2
        else
            echo >&2
            echo "=== Stage 4: Network Discovery Execution ===" >&2
            echo "Running network discovery on $discovery_network..." >&2
            echo >&2
        fi

        emit_progress "Main network ($discovery_network)" "1" "1"

        # Set environment variables for multiphase script context
        export MANUAL_NETWORK_RANGE="$discovery_network"
        export AUTO_DISCOVERY_SESSION="true"
        export AUTO_DISCOVERY_MAIN_NETWORK="true"
        export AUTO_DISCOVERY_MAIN_DIR="$MAIN_NETWORK_DIR"
        export AUTO_DISCOVERY_SESSION_DIR="$SESSION_DISCOVERY_DIR"

        _disc_status=$(mktemp)
        { "$discovery_script" "$target_interface" "1"; echo $? > "$_disc_status"; } 2>&1 | \
            tee "$MAIN_NETWORK_DIR/meta/discovery_output.txt"
        discovery_exit_code=$(cat "$_disc_status" 2>/dev/null || echo 1)
        rm -f "$_disc_status"
        
        # Clean up environment variables
        unset MANUAL_NETWORK_RANGE AUTO_DISCOVERY_SESSION AUTO_DISCOVERY_MAIN_NETWORK
        unset AUTO_DISCOVERY_MAIN_DIR AUTO_DISCOVERY_SESSION_DIR
        
        if [ $discovery_exit_code -eq 0 ]; then
            echo "✓ Network discovery completed successfully"
            echo "Status: SUCCESS" >> "$WORKFLOW_REPORT"
            
            # Results are now directly in main network directory
            echo "Discovery results saved to: $SESSION_DISCOVERY_DIR"
            echo "Main network results in: $MAIN_NETWORK_DIR"
            
            # Update session metadata with success
            echo "Main Network: SUCCESS - Network $discovery_network" >> "$SESSION_METADATA"
            echo "Session completed: $(date)" >> "$SESSION_METADATA"
            
            # Create session-level consolidation and reporting
            create_session_consolidation_reports
            
            # Update latest symlinks for session results
            update_latest_links "discovery" "$SESSION_DISCOVERY_DIR"
            
            # Include discovery output in report (first 50 lines)
            echo "Discovery output (summary):" >> "$WORKFLOW_REPORT"
            head -50 "$MAIN_NETWORK_DIR/meta/discovery_output.txt" >> "$WORKFLOW_REPORT"
            echo "... (full output in session results)" >> "$WORKFLOW_REPORT"
        else
            echo "✗ Network discovery failed"
            echo "Status: FAILED" >> "$WORKFLOW_REPORT"
            log_error "Network discovery failed in auto-discovery workflow"
        fi
    fi
else
    echo "✗ Discovery script not found"
    echo "Status: FAILED (script not found)" >> "$WORKFLOW_REPORT"
    log_error "Discovery script not found for auto-discovery workflow"
fi

echo "Completed: $(date)" >> "$WORKFLOW_REPORT"
echo >> "$WORKFLOW_REPORT"

# Stage 5: Advanced Analysis
if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
    printf "%s%s%s\n" "$COLOR_YELLOW" "Stage 5/5: ADVANCED ANALYSIS — Packet analysis and reporting" "$COLOR_RESET"
elif command -v print_phase_header >/dev/null 2>&1; then
    print_phase_header "STAGE 5: ADVANCED ANALYSIS"
else
    echo >&2
    echo "=== Stage 5: Advanced Analysis ==="
fi
echo "--- STAGE 5: ADVANCED ANALYSIS ---" >> "$WORKFLOW_REPORT"
echo "Started: $(date)" >> "$WORKFLOW_REPORT"

log_info "Starting Stage 5: Advanced analysis"

echo "Running advanced packet analysis..."
analysis_script="$(dirname "$0")/../analysis/advanced_packet_analysis.sh"

if [ -x "$analysis_script" ]; then
    "$analysis_script" "$capture_file" > "$TEMP_DIR/analysis_output.txt" 2>&1
    analysis_exit_code=$?
    
    if [ $analysis_exit_code -eq 0 ]; then
        echo "✓ Advanced analysis completed successfully"
        echo "Status: SUCCESS" >> "$WORKFLOW_REPORT"
        
        # Update latest symlinks for analysis results
        ANALYSIS_DIR="$WORKDIR/analysis"
        latest_analysis=$(ls -t "$ANALYSIS_DIR/advanced_analysis_"* 2>/dev/null | head -1)
        if [ -n "$latest_analysis" ]; then
            update_latest_links "analysis" "$latest_analysis"
            # Copy analysis report to session reports
            cp "$latest_analysis" "$REPORT_SESSION_DIR/advanced_analysis.txt" 2>/dev/null || true
            echo "Advanced analysis report copied to session reports"
        fi
    else
        echo "✗ Advanced analysis failed"
        echo "Status: FAILED" >> "$WORKFLOW_REPORT"
        log_error "Advanced analysis failed in auto-discovery workflow"
    fi
else
    echo "✗ Advanced analysis script not found"
    echo "Status: FAILED (script not found)" >> "$WORKFLOW_REPORT"
    log_error "Advanced analysis script not found for auto-discovery workflow"
fi

echo "Completed: $(date)" >> "$WORKFLOW_REPORT"
echo >> "$WORKFLOW_REPORT"

# Generate workflow summary
echo "--- WORKFLOW SUMMARY ---" >> "$WORKFLOW_REPORT"
echo "Workflow completed: $(date)" >> "$WORKFLOW_REPORT"
echo "Total VLANs discovered: $vlan_count" >> "$WORKFLOW_REPORT"
echo "VLANs selected for configuration: ${selected_vlan_count:-0}" >> "$WORKFLOW_REPORT"
echo "VLAN interfaces configured: $interfaces_configured" >> "$WORKFLOW_REPORT"
echo "Capture file: $capture_file" >> "$WORKFLOW_REPORT"
echo "Capture size: $(du -h "$capture_file" | cut -f1)" >> "$WORKFLOW_REPORT"

if [ "$interfaces_configured" -gt 0 ]; then
    echo "VLAN-specific discovery directories created:" >> "$WORKFLOW_REPORT"
    find "$SESSION_DISCOVERY_DIR" -maxdepth 1 -name "vlan_*" -type d 2>/dev/null | while read -r vlan_dir; do
        vlan_name=$(basename "$vlan_dir")
        echo "  - $vlan_name" >> "$WORKFLOW_REPORT"
    done
fi

# Final summary
if command -v print_phase_header >/dev/null 2>&1; then
    print_phase_header "AUTO-DISCOVERY COMPLETE" >&2
else
    echo >&2
    echo "=== Auto-Discovery Complete ===" >&2
fi
if [ "$discovery_mode" = "l3" ] && [ -f "$VLAN_NETWORKS_FILE" ]; then
    echo
    echo "L3 Network Discovery Overview:"
    # Extract labels column for overview function
    cut -d' ' -f1 "$VLAN_NETWORKS_FILE" > "$TEMP_DIR/l3_labels.txt"
    print_vlan_discovery_overview \
        "$TEMP_DIR/l3_labels.txt" \
        "$VLAN_NETWORKS_FILE" \
        "$SESSION_DISCOVERY_DIR"
elif [ -f "$TEMP_DIR/selected_vlans.txt" ]; then
    echo
    echo "VLAN Discovery Overview:"
    print_vlan_discovery_overview \
        "$TEMP_DIR/selected_vlans.txt" \
        "$VLAN_NETWORKS_FILE" \
        "$SESSION_DISCOVERY_DIR"
fi

# Update latest symlinks for capture and reports
update_latest_links "captures" "$capture_file"
update_latest_links "reports" "$REPORT_SESSION_DIR"

echo
echo "Results:"
echo "  📁 $WORKDIR/"
echo "    ├── 📊 reports/$SESSION_NAME/ (consolidated reports)"
echo "    │   ├── auto_discovery_report.txt"
if [ "$interfaces_configured" -gt 0 ]; then
    echo "    │   ├── vlan_discovery_summary.txt"
fi
if [ -f "$REPORT_SESSION_DIR/advanced_analysis.txt" ]; then
    echo "    │   └── advanced_analysis.txt"
fi
echo "    ├── 📦 captures/ (packet captures)"
echo "    │   └── auto_discover_capture_${TIMESTAMP}.pcap"
echo "    ├── 🔍 discovery/ (network discovery results)"
if [ "$interfaces_configured" -gt 0 ]; then
    find "$SESSION_DISCOVERY_DIR" -maxdepth 1 -name "vlan_*" -type d 2>/dev/null | while read -r vlan_dir; do
        vlan_name=$(basename "$vlan_dir")
        echo "    │   └── $vlan_name/"
    done
fi
echo "    └── 🔗 latest/ (symlinks to most recent results)"
echo "        ├── discovery -> (latest discovery session)"
echo "        ├── analysis -> (latest analysis results)"
echo "        ├── captures -> (latest capture file)"
echo "        └── reports -> (latest reports session)"
echo

fix_ownership "$WORKDIR/discovery" "$REPORT_SESSION_DIR"
log_info "Auto-discovery workflow completed successfully"
log_script_end "auto_discover.sh" 0
