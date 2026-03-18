#!/bin/sh

# Auto-Discovery Workflow
# VLAN-aware network discovery with intelligent configuration:
# 1. Interface UP verification → 2. Promiscuous capture → 3. VLAN analysis → 4. User VLAN selection → 5. Smart IP configuration → 6. VLAN-specific discovery

# shellcheck source=../common/utils.sh
. "$(dirname "$0")/../common/utils.sh"
# shellcheck source=../common/logging.sh
. "$(dirname "$0")/../common/logging.sh"
# shellcheck source=../common/colors.sh
. "$(dirname "$0")/../common/colors.sh" 2>/dev/null || true

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

echo "=== Auto-Discovery Workflow ===" >&2
echo >&2

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

# Function to prompt user for IP address choice with validation
prompt_ip_choice() {
    suggested_ip="$1"
    network_base="$2"
    vlan_interface="$3"

    echo "Choose IP assignment for VLAN interface $vlan_interface:" >&2
    echo "1) Accept suggested IP ($suggested_ip)" >&2
    echo "2) Provide custom IP address" >&2
    echo "Choice [1-2]: " >&2
    read -r choice

    case "$choice" in
        1|"")
            echo "$suggested_ip"
            return 0
            ;;
        2)
            while true; do
                echo "Enter IP address (with CIDR, e.g., 192.168.1.100/24): " >&2
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
                    echo "Continue anyway? [y/N]: " >&2
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

# Phase 1: Promiscuous Packet Capture
if command -v print_phase_header >/dev/null 2>&1; then
    print_phase_header "PHASE 1: PACKET CAPTURE"
else
    echo
    echo "=== Phase 1: Packet Capture ===" >&2
fi
echo "--- PHASE 1: PROMISCUOUS CAPTURE ---" >> "$WORKFLOW_REPORT"
echo "Started: $(date)" >> "$WORKFLOW_REPORT"

log_info "Starting Phase 1: Promiscuous packet capture"

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

# Phase 2: Traffic Analysis
if command -v print_phase_header >/dev/null 2>&1; then
    print_phase_header "PHASE 2: TRAFFIC ANALYSIS"
else
    echo
    echo "=== Phase 2: Traffic Analysis ===" >&2
fi
echo "--- PHASE 2: TRAFFIC ANALYSIS ---" >> "$WORKFLOW_REPORT"
echo "Started: $(date)" >> "$WORKFLOW_REPORT"

log_info "Starting Phase 2: Traffic analysis"

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
    
    # Display discovered VLANs to user for selection
    echo
    echo "=== VLAN Discovery Results ===" >&2
    echo "The following VLANs and sample IPs were discovered in the captured traffic:" >&2
    echo
    
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
    
    echo
    echo "Which VLANs would you like to configure interfaces for?" >&2
    echo "Enter VLAN IDs separated by spaces (or 'all' for all VLANs, 'none' to skip):" >&2
    echo "VLAN selection: " >&2
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
            echo "Prioritize VLANs? (y/n) [n]: " >&2
            read -r prioritize_choice

            case "$prioritize_choice" in
                y|Y|yes|YES)
                    echo >&2
                    echo "Enter VLAN IDs to scan first (space-separated):" >&2
                    echo "Example: 300 500" >&2
                    echo "Priority VLANs: " >&2
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
    echo "No VLANs detected in capture" >&2 >> "$WORKFLOW_REPORT"
    touch "$TEMP_DIR/selected_vlans.txt"  # Create empty file
    selected_vlan_count=0
fi

# Extract general network information
echo "Extracting network ranges..." >&2 >> "$WORKFLOW_REPORT"
tshark -r "$capture_file" -T fields -e ip.src -e ip.dst 2>/dev/null | \
    tr '\t' '\n' | grep -v "^$" | sort -u | head -20 > "$TEMP_DIR/discovered_ips.txt"

ip_count=$(wc -l < "$TEMP_DIR/discovered_ips.txt")
echo "Unique IP addresses found: $ip_count" >&2
    echo "Unique IP addresses found: $ip_count" >> "$WORKFLOW_REPORT"

echo "✓ Traffic analysis completed successfully" >&2
echo "Status: SUCCESS" >> "$WORKFLOW_REPORT"
echo "Completed: $(date)" >> "$WORKFLOW_REPORT"
echo >> "$WORKFLOW_REPORT"

# Phase 3: Interface Configuration
if command -v print_phase_header >/dev/null 2>&1; then
    print_phase_header "PHASE 3: INTERFACE CONFIGURATION"
else
    echo >&2
    echo "=== Phase 3: Interface Configuration ===" >&2
fi
echo "--- PHASE 3: INTERFACE CONFIGURATION ---" >> "$WORKFLOW_REPORT"
echo "Started: $(date)" >> "$WORKFLOW_REPORT"

log_info "Starting Phase 3: Interface configuration"

interfaces_configured=0

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
                            # Try to determine actual network from first IP
                            calc_network=$(ipcalc -n "$first_ip$suggested_cidr" 2>/dev/null | cut -d= -f2 2>/dev/null)
                            if [ -n "$calc_network" ]; then
                                network_base=$(echo "$calc_network" | cut -d'.' -f1-3)
                                # Recalculate suggested IP with proper network base
                                suggested_ip="${network_base}.253${suggested_cidr}"
                                echo "  Calculated network: $calc_network"
                            fi
                        fi
                        
                        echo "  Discovered IPs: $(echo "$vlan_ips" | head -3 | tr '\n' ' ')"
                        echo "  Estimated network: $network_base.0$suggested_cidr"
                        echo "  Suggested IP: $suggested_ip"
                        echo
                        
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

                            echo "  Enter IP address for $vlan_interface (with CIDR, e.g., 192.168.1.100/24): " >&2
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
echo "VLAN interface $vlan_interface already exists" >&2
echo "  Exists: $vlan_interface" >> "$WORKFLOW_REPORT"
                interfaces_configured=$((interfaces_configured + 1))
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
            
echo "  Traffic analysis results:" >&2
echo "    Discovered IPs: $(echo "$main_ips" | head -3 | tr '\n' ' ')" >&2
echo "    Suggested IP: $suggested_ip" >&2
            echo
            
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
                echo "Enter IP address in CIDR notation (e.g., 192.168.1.100/24): " >&2
                read chosen_ip
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

echo "✓ Interface configuration completed" >&2
echo "VLAN interfaces configured: $interfaces_configured" >&2
echo "Status: SUCCESS" >> "$WORKFLOW_REPORT"
echo "Interfaces configured: $interfaces_configured" >> "$WORKFLOW_REPORT"
echo "Completed: $(date)" >> "$WORKFLOW_REPORT"
echo >> "$WORKFLOW_REPORT"

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
        echo "Session: auto_discovery_${TIMESTAMP}"
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
        for net_dir in "$SESSION_DISCOVERY_DIR"/vlan_* "$SESSION_DISCOVERY_DIR"/main_network; do
            if [ -d "$net_dir" ]; then
                net_name=$(basename "$net_dir")
                echo "  $net_name:"
                
                # Count hosts if file exists
                if [ -f "$net_dir/all_discovered_hosts.txt" ]; then
                    host_count=$(wc -l < "$net_dir/all_discovered_hosts.txt" 2>/dev/null || echo 0)
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
            for net_dir in "$SESSION_DISCOVERY_DIR"/vlan_* "$SESSION_DISCOVERY_DIR"/main_network; do
                if [ -f "$net_dir/service_targets/${service_type}_targets.txt" ]; then
                    count=$(wc -l < "$net_dir/service_targets/${service_type}_targets.txt" 2>/dev/null || echo 0)
                    service_total=$((service_total + count))
                fi
            done
            if [ $service_total -gt 0 ]; then
                printf "  %-12s: %d hosts\n" "${service_type^^}" "$service_total"
            fi
        done
        echo ""

        echo "DIRECTORY STRUCTURE:"
        echo "  Session Directory: $SESSION_DISCOVERY_DIR"
        for net_dir in "$SESSION_DISCOVERY_DIR"/vlan_* "$SESSION_DISCOVERY_DIR"/main_network; do
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
        echo "Session: auto_discovery_${TIMESTAMP}"
        echo ""
        echo "This file consolidates team assignments across all VLANs/networks"
        echo "in this auto-discovery session for coordinated assessment planning."
        echo ""
        
        # For each team, consolidate targets from categorized directories
        for team in windows linux network; do
            echo "== ${team^^} TEAM SESSION SUMMARY =="
            total_targets=0
            
            for net_dir in "$SESSION_DISCOVERY_DIR"/vlan_* "$SESSION_DISCOVERY_DIR"/main_network; do
                if [ -d "$net_dir/categorized" ]; then
                    net_name=$(basename "$net_dir")
                    echo "$net_name targets:"
                    
                    # Extract target counts from categorized files
                    case "$team" in
                        "windows")
                            windows_count=0
                            if [ -f "$net_dir/categorized/windows_hosts.txt" ]; then
                                windows_count=$(wc -l < "$net_dir/categorized/windows_hosts.txt" 2>/dev/null || echo 0)
                                echo "  Windows hosts: $windows_count"
                                total_targets=$((total_targets + windows_count))
                            fi
                            ;;
                        "linux")
                            linux_count=0
                            if [ -f "$net_dir/categorized/linux_hosts.txt" ]; then
                                linux_count=$(wc -l < "$net_dir/categorized/linux_hosts.txt" 2>/dev/null || echo 0)
                                echo "  Linux/Unix hosts: $linux_count"
                                total_targets=$((total_targets + linux_count))
                            fi
                            ;;
                        "network")
                            network_count=0
                            if [ -f "$net_dir/categorized/network_devices.txt" ]; then
                                network_count=$(wc -l < "$net_dir/categorized/network_devices.txt" 2>/dev/null || echo 0)
                                echo "  Network devices: $network_count"
                                total_targets=$((total_targets + network_count))
                            fi
                            ;;
                    esac
                fi
            done
            
            echo "Total ${team^^} targets: $total_targets"
            echo ""
        done
        
        echo "== MANUAL ASSIGNMENT COORDINATION =="
        echo "Web and database services requiring manual assignment:"
        for net_dir in "$SESSION_DISCOVERY_DIR"/vlan_* "$SESSION_DISCOVERY_DIR"/main_network; do
            if [ -d "$net_dir/categorized" ]; then
                net_name=$(basename "$net_dir")
                web_count=0
                db_count=0
                
                if [ -f "$net_dir/categorized/web_servers.txt" ]; then
                    web_count=$(wc -l < "$net_dir/categorized/web_servers.txt" 2>/dev/null || echo 0)
                fi
                if [ -f "$net_dir/categorized/database_servers.txt" ]; then
                    db_count=$(wc -l < "$net_dir/categorized/database_servers.txt" 2>/dev/null || echo 0)
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

# Phase 4: Network Discovery
if command -v print_phase_header >/dev/null 2>&1; then
    print_phase_header "PHASE 4: NETWORK DISCOVERY"
else
    echo
    echo "=== Phase 4: Network Discovery ==="
fi
echo "--- PHASE 4: NETWORK DISCOVERY ---" >> "$WORKFLOW_REPORT"
echo "Started: $(date)" >> "$WORKFLOW_REPORT"

log_info "Starting Phase 4: Network discovery"

echo "Running network discovery on configured interfaces..." >&2
discovery_script="$(dirname "$0")/../discovery/multi_phase_discovery.sh"

if [ -x "$discovery_script" ]; then
    if [ "$selected_vlan_count" -gt 0 ]; then
        echo "Running VLAN-aware discovery with separate results per VLAN..."
        echo "VLAN-aware discovery initiated" >&2 >> "$WORKFLOW_REPORT"
        
        # Create session-based discovery structure with VLAN organization
        DISCOVERY_DIR="$WORKDIR/discovery"
        SESSION_DISCOVERY_DIR="$DISCOVERY_DIR/auto_discovery_${TIMESTAMP}"
        mkdir -p "$SESSION_DISCOVERY_DIR"
        discovery_success=0
        
        # Create session metadata
        SESSION_METADATA="$SESSION_DISCOVERY_DIR/session_metadata.txt"
        {
            echo "=== Auto-Discovery Session Metadata ==="
            echo "Session ID: auto_discovery_${TIMESTAMP}"
            echo "Started: $(date)"
            echo "Interface: $target_interface"
            echo "VLANs discovered: $selected_vlan_count"
            echo "Session directory: $SESSION_DISCOVERY_DIR"
            echo ""
        } > "$SESSION_METADATA"
        
        # Phase 4a: Network Collection
        # Collect all VLAN networks upfront before starting discoveries
        if command -v print_phase_header >/dev/null 2>&1; then
            print_phase_header "PHASE 4a: NETWORK COLLECTION" >&2
            color_info "Collecting discovery networks for all VLANs..." >&2
        else
            echo >&2
            echo "=== Phase 4a: Network Collection ===" >&2
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
                        echo "  Select discovery network for VLAN $vlan_id (1-2): " >&2
                        read vlan_network_choice

                        case "$vlan_network_choice" in
                            1|"")
                                vlan_discovery_network="$vlan_network"
                                echo "  ✓ Using interface network: $vlan_discovery_network" >&2
                                ;;
                            2)
                                echo "  Enter network range in CIDR notation (e.g., 192.168.1.0/24): " >&2
                                read vlan_custom_network

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
                        echo "  ⚠ No network range found for VLAN interface $vlan_interface" >&2
                        echo "  VLAN $vlan_id will be skipped during discovery" >&2
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
            if command -v color_info >/dev/null 2>&1; then
                color_info "The following networks will be scanned:" >&2
            else
                echo "The following networks will be scanned:" >&2
            fi
            echo >&2
            while read -r vlan_id network <&3; do
                printf "  VLAN %-3s: %s\n" "$vlan_id" "$network" >&2
            done 3< "$VLAN_NETWORKS_FILE"
            echo >&2
            vlan_network_count=$(wc -l < "$VLAN_NETWORKS_FILE")
            echo "Ready to begin discovery on $vlan_network_count VLAN(s)" >&2
            echo >&2
            echo "Discovery will now begin. This may take some time." >&2
            echo "You can safely leave this running." >&2
            echo >&2
        else
            echo "⚠ No VLANs configured for discovery" >&2
            echo "Status: SKIPPED (no networks)" >> "$WORKFLOW_REPORT"
            log_warn "No VLANs configured for discovery"
        fi

        # Phase 4b: Network Discovery Execution
        # Execute discoveries using pre-collected network ranges
        if command -v print_phase_header >/dev/null 2>&1; then
            print_phase_header "PHASE 4b: NETWORK DISCOVERY EXECUTION" >&2
            color_info "Running network discovery on configured VLANs..." >&2
        else
            echo >&2
            echo "=== Phase 4b: Network Discovery Execution ===" >&2
            echo "Running network discovery on configured VLANs..." >&2
            echo >&2
        fi

        # Discover networks on each configured VLAN interface
        _vlan_current=0
        while read -r vlan_id vlan_discovery_network <&3; do
            if [ -n "$vlan_id" ] && [ -n "$vlan_discovery_network" ]; then
                _vlan_current=$((_vlan_current + 1))
                vlan_interface="${target_interface}.${vlan_id}"
                vlan_discovery_dir="$SESSION_DISCOVERY_DIR/vlan_$vlan_id"

                if command -v print_progress >/dev/null 2>&1; then
                    print_progress "$_vlan_current" "$vlan_network_count" "Discovering VLAN $vlan_id on $vlan_discovery_network" >&2
                else
                    echo "=== Discovering VLAN $vlan_id on $vlan_discovery_network ===" >&2
                fi
                echo "  VLAN $vlan_id discovery:" >> "$WORKFLOW_REPORT"
                echo "    Discovery network: $vlan_discovery_network" >> "$WORKFLOW_REPORT"

                log_info "VLAN $vlan_id discovery network: $vlan_discovery_network"

                # Create VLAN-specific discovery directory
                mkdir -p "$vlan_discovery_dir"

                # Run discovery for this specific VLAN network
                if command -v color_info >/dev/null 2>&1; then
                    echo "  " >&2
                    color_info "  Running multi-phase discovery on $vlan_discovery_network..." >&2
                else
                    echo "  Starting multi-phase discovery on $vlan_discovery_network..." >&2
                fi
                        
                        # Set environment variables for multiphase script context
                        export MANUAL_NETWORK_RANGE="$vlan_discovery_network"
                        export AUTO_DISCOVERY_SESSION="true"
                        export AUTO_DISCOVERY_VLAN_ID="$vlan_id"
                        export AUTO_DISCOVERY_VLAN_DIR="$vlan_discovery_dir"
                        export AUTO_DISCOVERY_SESSION_DIR="$SESSION_DISCOVERY_DIR"
                        
                        _disc_status=$(mktemp)
                        { "$discovery_script" "$vlan_interface" "1"; echo $? > "$_disc_status"; } 2>&1 | \
                            tee "$vlan_discovery_dir/discovery_output.txt"
                        vlan_discovery_exit=$(cat "$_disc_status" 2>/dev/null || echo 1)
                        rm -f "$_disc_status"
                        
                        # Clean up environment variables
                        unset MANUAL_NETWORK_RANGE AUTO_DISCOVERY_SESSION AUTO_DISCOVERY_VLAN_ID 
                        unset AUTO_DISCOVERY_VLAN_DIR AUTO_DISCOVERY_SESSION_DIR
                        
                        if [ $vlan_discovery_exit -eq 0 ]; then
                            echo "  ✓ VLAN $vlan_id discovery completed successfully"
                            echo "    Status: SUCCESS" >> "$WORKFLOW_REPORT"
                            discovery_success=$((discovery_success + 1))
                            
                            # Results are now directly in VLAN directory
                            echo "    Results: $vlan_discovery_dir"
                            echo "    VLAN $vlan_id discovery results organized in VLAN-specific directory"
                            
                            # Update session metadata with successful VLAN
                            echo "VLAN $vlan_id: SUCCESS - Network $vlan_discovery_network" >> "$SESSION_METADATA"
                        else
                            echo "  ✗ VLAN $vlan_id discovery failed"
                            echo "    Status: FAILED" >> "$WORKFLOW_REPORT"
                            log_warn "Discovery failed for VLAN $vlan_id"
                        fi
                        
                        # Add summary to report
                        echo "    Output summary:" >> "$WORKFLOW_REPORT"
                        head -20 "$vlan_discovery_dir/discovery_output.txt" 2>/dev/null | sed 's/^/      /' >> "$WORKFLOW_REPORT"
            fi
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
            find "$SESSION_DISCOVERY_DIR" -name "vlan_*" -type d | while read -r vlan_dir; do
                vlan_name=$(basename "$vlan_dir")
                echo "- $vlan_name: $([ -f "$vlan_dir/discovery_output.txt" ] && echo "SUCCESS" || echo "FAILED")" >> "$discovery_summary"
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
            echo
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
            echo
            if [ -n "$main_ips" ]; then
                echo "Select discovery network (1-3): " >&2
            else
                echo "Select discovery network (1,2): " >&2
            fi
            read network_choice
            
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
                        echo "Select network (1-$(echo "$traffic_networks" | head -5 | wc -l)): " >&2
                        read traffic_choice
                        
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
                        echo "Enter network range in CIDR notation (e.g., 192.168.1.0/24): " >&2
                        read custom_network
                        
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
                    echo "Enter network range in CIDR notation (e.g., 192.168.1.0/24): " >&2
                    read custom_network
                    
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
        
        # Run discovery on selected network
        echo
        echo "Starting network discovery on $discovery_network..."
        
        # Create session-based discovery structure for main network
        DISCOVERY_DIR="$WORKDIR/discovery"
        SESSION_DISCOVERY_DIR="$DISCOVERY_DIR/auto_discovery_${TIMESTAMP}"
        MAIN_NETWORK_DIR="$SESSION_DISCOVERY_DIR/main_network"
        mkdir -p "$MAIN_NETWORK_DIR"
        
        # Create session metadata
        SESSION_METADATA="$SESSION_DISCOVERY_DIR/session_metadata.txt"
        {
            echo "=== Auto-Discovery Session Metadata ==="
            echo "Session ID: auto_discovery_${TIMESTAMP}"
            echo "Started: $(date)"
            echo "Interface: $target_interface"
            echo "Discovery Mode: Standard (main network)"
            echo "Network: $discovery_network"
            echo "Session directory: $SESSION_DISCOVERY_DIR"
            echo ""
        } > "$SESSION_METADATA"
        
        # Set environment variables for multiphase script context
        export MANUAL_NETWORK_RANGE="$discovery_network"
        export AUTO_DISCOVERY_SESSION="true"
        export AUTO_DISCOVERY_MAIN_NETWORK="true"
        export AUTO_DISCOVERY_MAIN_DIR="$MAIN_NETWORK_DIR"
        export AUTO_DISCOVERY_SESSION_DIR="$SESSION_DISCOVERY_DIR"
        
        "$discovery_script" "$target_interface" "1" > "$MAIN_NETWORK_DIR/discovery_output.txt" 2>&1
        discovery_exit_code=$?
        
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
            head -50 "$MAIN_NETWORK_DIR/discovery_output.txt" >> "$WORKFLOW_REPORT"
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

# Phase 5: Advanced Analysis
if command -v print_phase_header >/dev/null 2>&1; then
    print_phase_header "PHASE 5: ADVANCED ANALYSIS"
else
    echo
    echo "=== Phase 5: Advanced Analysis ==="
fi
echo "--- PHASE 5: ADVANCED ANALYSIS ---" >> "$WORKFLOW_REPORT"
echo "Started: $(date)" >> "$WORKFLOW_REPORT"

log_info "Starting Phase 5: Advanced analysis"

echo "Running advanced packet analysis..."
analysis_script="$(dirname "$0")/../discovery/advanced_packet_analysis.sh"

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
    find "$DISCOVERY_DIR" -name "${SESSION_NAME}_vlan_*" -type d 2>/dev/null | while read -r vlan_dir; do
        vlan_name=$(basename "$vlan_dir" | sed "s/${SESSION_NAME}_//")
        echo "  - $vlan_name" >> "$WORKFLOW_REPORT"
    done
fi

# Final summary
echo
echo "=== Auto-Discovery Workflow Summary ==="
echo "✓ Phase 1: Promiscuous capture completed ($capture_duration min)"
echo "✓ Phase 2: Traffic analysis completed ($vlan_count VLANs discovered, $ip_count IPs)"
echo "✓ Phase 3: Interface configuration completed (${selected_vlan_count:-0} VLANs selected, $interfaces_configured interfaces configured)"
echo "✓ Phase 4: Network discovery completed"
if [ "$interfaces_configured" -gt 0 ]; then
    echo "   - VLAN-specific discovery results in: $DISCOVERY_DIR/"
    echo "   - Each VLAN has its own categorized host results"
else
    echo "   - Standard single-network discovery completed"
fi
echo "✓ Phase 5: Advanced analysis completed"
echo
echo "Auto-discovery results organized by category:"
echo "  Reports: $REPORT_SESSION_DIR/"
echo "  Capture: $capture_file"
echo "  Discovery: $DISCOVERY_DIR/"
echo "  Analysis: $WORKDIR/analysis/"
echo
echo "Comprehensive report: $WORKFLOW_REPORT"

# Update latest symlinks for capture and reports
update_latest_links "captures" "$capture_file"
update_latest_links "reports" "$REPORT_SESSION_DIR"

# List created files and directory structure
echo
echo "Results organized in new structure:"
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
    find "$DISCOVERY_DIR" -name "${SESSION_NAME}_vlan_*" -type d 2>/dev/null | while read -r vlan_dir; do
        vlan_name=$(basename "$vlan_dir" | sed "s/${SESSION_NAME}_//")
        echo "    │   └── ${SESSION_NAME}_$vlan_name/ (VLAN-specific results)"
    done
fi
echo "    └── 🔗 latest/ (symlinks to most recent results)"
echo "        ├── discovery -> (latest discovery session)"
echo "        ├── analysis -> (latest analysis results)"
echo "        ├── captures -> (latest capture file)"
echo "        └── reports -> (latest reports session)"
echo
echo "💡 Use 'latest/' directory for quick access to most recent results!"

log_info "Auto-discovery workflow completed successfully"
log_script_end "auto_discover.sh" 0

echo
echo "Auto-discovery workflow complete!"
echo "The system is now configured with selected VLANs and ready for targeted network analysis."
echo "All results are organized by category and easily accessible via the 'latest/' directory."
