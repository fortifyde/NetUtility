#!/bin/sh

# Auto-Discovery Workflow
# VLAN-aware network discovery with intelligent configuration:
# 1. Interface UP verification → 2. Promiscuous capture → 3. VLAN analysis → 4. User VLAN selection → 5. Smart IP configuration → 6. VLAN-specific discovery

. "$(dirname "$0")/../common/utils.sh"
. "$(dirname "$0")/../common/logging.sh"

echo "=== Auto-Discovery Workflow ==="
echo

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
    
    echo "Choose IP assignment for VLAN interface $vlan_interface:"
    echo "1) Accept suggested IP ($suggested_ip)"
    echo "2) Provide custom IP address"
    printf "Choice [1-2]: "
    read -r choice
    
    case "$choice" in
        1|"")
            echo "$suggested_ip"
            return 0
            ;;
        2)
            while true; do
                printf "Enter IP address (with CIDR, e.g., 192.168.1.100/24): "
                read -r custom_ip
                
                # Basic validation
                if [ -z "$custom_ip" ]; then
                    echo "⚠ Empty IP address. Try again or press Ctrl+C to cancel."
                    continue
                fi
                
                # Check if it contains CIDR notation
                if ! echo "$custom_ip" | grep -q "/"; then
                    echo "⚠ IP address must include CIDR notation (e.g., /24). Try again."
                    continue
                fi
                
                # Extract IP part for validation
                ip_part=$(echo "$custom_ip" | cut -d'/' -f1)
                cidr_part=$(echo "$custom_ip" | cut -d'/' -f2)
                
                # Basic IP format validation
                if ! echo "$ip_part" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'; then
                    echo "⚠ Invalid IP format. Use format: X.X.X.X/XX"
                    continue
                fi
                
                # Basic CIDR validation
                if ! echo "$cidr_part" | grep -qE '^[0-9]{1,2}$' || [ "$cidr_part" -lt 8 ] || [ "$cidr_part" -gt 30 ]; then
                    echo "⚠ Invalid CIDR. Use range 8-30 (e.g., /24)"
                    continue
                fi
                
                # Check if IP is in same network (optional warning)
                custom_network_base=$(echo "$ip_part" | cut -d'.' -f1-3)
                if [ "$custom_network_base" != "$network_base" ]; then
                    echo "⚠ Warning: Custom IP ($custom_network_base.X) differs from discovered network ($network_base.0)"
                    printf "Continue anyway? [y/N]: "
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
            echo "⚠ Invalid choice. Using suggested IP: $suggested_ip"
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

echo "This VLAN-aware workflow follows an intelligent sequence for comprehensive network discovery:"
echo "1. Interface UP verification (ensure connectivity)"
echo "2. Promiscuous packet capture (capture all traffic)"
echo "3. VLAN analysis (identify VLANs and network ranges)"
echo "4. User VLAN selection (choose which VLANs to configure)"
echo "5. Smart IP configuration (avoid gateway conflicts, use ipcalc)"
echo "6. VLAN-specific discovery (separate categorized results per VLAN)"
echo "7. Advanced analysis (security and protocol analysis)"
echo

log_info "Starting VLAN-aware auto-discovery workflow"

# Get target interface
echo "Available network interfaces:"
target_interface=$(select_interface)

if [ -z "$target_interface" ]; then
    echo "No interface selected"
    log_error "No interface selected for auto-discovery workflow"
    exit 1
fi

echo "Selected interface: $target_interface"
log_info "Selected interface for auto-discovery workflow: $target_interface"

# Verify interface is UP and bring it up if needed
interface_state=$(ip link show "$target_interface" 2>/dev/null | grep -o "state [A-Z]*" | cut -d' ' -f2)
if [ "$interface_state" != "UP" ]; then
    echo "Interface $target_interface is not UP (current state: ${interface_state:-UNKNOWN})"
    echo "Bringing interface up..."
    if ip link set "$target_interface" up 2>/dev/null; then
        echo "✓ Interface $target_interface brought up successfully"
        log_info "Interface $target_interface brought up from state: $interface_state"
        # Wait a moment for interface to stabilize
        sleep 2
    else
        echo "✗ Failed to bring interface $target_interface up (may require root privileges)"
        log_error "Failed to bring interface $target_interface up"
        exit 1
    fi
else
    echo "✓ Interface $target_interface is already UP"
    log_info "Interface $target_interface is already UP"
fi

# Workflow configuration
echo
echo "Workflow configuration:"
echo "The auto-discovery workflow will capture network traffic in promiscuous mode"
echo "to discover VLANs and network topology before performing discovery."
echo
echo "Capture duration options:"
echo "  • 2 minutes  - Quick scan for basic VLAN discovery"
echo "  • 5 minutes  - Standard capture"
echo "  • 10 minutes - Extended capture (recommended)"
echo "  • 15+ minutes - Comprehensive capture for complex environments"
echo
read -p "Enter capture duration in minutes (default 10): " capture_duration
capture_duration=${capture_duration:-10}

# Validate capture duration
case "$capture_duration" in
    ''|*[!0-9]*)
        echo "Invalid duration. Using default 10 minutes."
        capture_duration=10
        ;;
    *)
        if [ "$capture_duration" -lt 1 ] || [ "$capture_duration" -gt 60 ]; then
            echo "Duration must be between 1 and 60 minutes. Using default 10 minutes."
            capture_duration=10
        fi
        ;;
esac

echo "Capture duration: $capture_duration minutes"
log_info "Auto-discovery capture duration: $capture_duration minutes"

# Add workflow details to report
echo "--- WORKFLOW CONFIGURATION ---" >> "$WORKFLOW_REPORT"
echo "Target interface: $target_interface" >> "$WORKFLOW_REPORT"
echo "Capture duration: $capture_duration minutes" >> "$WORKFLOW_REPORT"
echo >> "$WORKFLOW_REPORT"

# Phase 1: Promiscuous Packet Capture
echo
echo "=== Phase 1: Promiscuous Packet Capture ==="
echo "--- PHASE 1: PROMISCUOUS CAPTURE ---" >> "$WORKFLOW_REPORT"
echo "Started: $(date)" >> "$WORKFLOW_REPORT"

log_info "Starting Phase 1: Promiscuous packet capture"

# Enable promiscuous mode
echo "Enabling promiscuous mode on $target_interface..."
if ip link set "$target_interface" promisc on 2>/dev/null; then
    echo "✓ Promiscuous mode enabled"
    log_info "Promiscuous mode enabled on $target_interface"
    promisc_enabled=true
else
    echo "⚠ Warning: Could not enable promiscuous mode (may require root privileges)"
    log_warn "Could not enable promiscuous mode on $target_interface"
    promisc_enabled=false
fi

# Capture traffic  
CAPTURE_DIR="$WORKDIR/captures"
mkdir -p "$CAPTURE_DIR"
capture_file="$CAPTURE_DIR/auto_discover_capture_${TIMESTAMP}.pcap"
echo "Starting promiscuous capture for $capture_duration minutes..."
echo "Capture file: $capture_file"

if command -v tshark >/dev/null 2>&1; then
    # Use tshark for capture - first attempt
    timeout $((capture_duration * 60)) tshark -i "$target_interface" -w "$capture_file" -q 2>/dev/null
    capture_exit_code=$?
    
    # If tshark failed with permission issue and we're root, try fallback location
    if [ $capture_exit_code -ne 0 ] && [ $capture_exit_code -ne 124 ] && [ "$(id -u)" -eq 0 ]; then
        echo "Capture failed in workflow directory, trying fallback location..."
        FALLBACK_DIR="/tmp/netutil-captures"
        mkdir -p "$FALLBACK_DIR"
        chmod 755 "$FALLBACK_DIR"
        FALLBACK_FILE="$FALLBACK_DIR/promiscuous_capture_$(date +%Y%m%d_%H%M%S).pcap"
        
        echo "Fallback capture file: $FALLBACK_FILE"
        timeout $((capture_duration * 60)) tshark -i "$target_interface" -w "$FALLBACK_FILE" -q 2>/dev/null
        capture_exit_code=$?
        
        # If successful in fallback location, copy to workflow directory
        if ([ $capture_exit_code -eq 0 ] || [ $capture_exit_code -eq 124 ]) && [ -f "$FALLBACK_FILE" ]; then
            echo "Capture successful in fallback location, copying to workflow directory..."
            if cp "$FALLBACK_FILE" "$capture_file" 2>/dev/null; then
                echo "✓ Capture copied to workflow directory"
                # Update file permissions for original user if running as root
                if [ -n "$SUDO_UID" ] && [ -n "$SUDO_GID" ]; then
                    chown "$SUDO_UID:$SUDO_GID" "$capture_file" 2>/dev/null || true
                fi
            else
                echo "⚠ Failed to copy to workflow directory, using fallback location"
                capture_file="$FALLBACK_FILE"
            fi
        fi
    fi
    
    if [ $capture_exit_code -eq 0 ] || [ $capture_exit_code -eq 124 ]; then  # 124 = timeout
        echo "✓ Promiscuous capture completed successfully"
        echo "Status: SUCCESS" >> "$WORKFLOW_REPORT"
        log_network_operation "Promiscuous capture" "$target_interface" "Completed - $(du -h "$capture_file" | cut -f1)"
        
        # Copy capture file to captures directory for compatibility with analysis scripts
        CAPTURES_DIR="${NETUTIL_WORKDIR:-$HOME}/captures"
        mkdir -p "$CAPTURES_DIR"
        CAPTURES_FILE="$CAPTURES_DIR/$(basename "$capture_file")"
        if cp "$capture_file" "$CAPTURES_FILE" 2>/dev/null; then
            echo "✓ Capture file also saved to: $CAPTURES_FILE"
            # Update file permissions for original user if running as root
            if [ -n "$SUDO_UID" ] && [ -n "$SUDO_GID" ]; then
                chown "$SUDO_UID:$SUDO_GID" "$CAPTURES_FILE" 2>/dev/null || true
            fi
            # Update capture_file variable to point to captures location for subsequent operations
            capture_file="$CAPTURES_FILE"
        else
            echo "⚠ Warning: Failed to copy capture file to captures directory"
            log_warn "Failed to copy capture file to captures directory: $CAPTURES_DIR"
        fi
        
        # Get basic capture stats
        if command -v capinfos >/dev/null 2>&1; then
            # Use capinfos for more reliable packet count
            packet_count=$(capinfos -c "$capture_file" 2>/dev/null | grep "Number of packets" | awk '{print $4}')
        else
            # Fallback to tshark method
            packet_count=$(tshark -r "$capture_file" -q -z io,stat,0 2>/dev/null | grep -o "frames:[0-9]*" | cut -d: -f2 | head -1)
        fi
        echo "Packets captured: ${packet_count:-unknown}"
        echo "Capture size: $(du -h "$capture_file" | cut -f1)"
        echo "Packets captured: ${packet_count:-unknown}" >> "$WORKFLOW_REPORT"
        echo "Capture size: $(du -h "$capture_file" | cut -f1)" >> "$WORKFLOW_REPORT"
    else
        echo "✗ Promiscuous capture failed"
        echo "Status: FAILED" >> "$WORKFLOW_REPORT"
        log_error "Promiscuous capture failed on $target_interface"
        exit 1
    fi
else
    echo "✗ tshark not available - cannot perform capture"
    echo "Status: FAILED (tshark not available)" >> "$WORKFLOW_REPORT"
    log_error "tshark not available for promiscuous capture"
    exit 1
fi

# Disable promiscuous mode
if [ "$promisc_enabled" = true ]; then
    echo "Disabling promiscuous mode..."
    ip link set "$target_interface" promisc off 2>/dev/null
    log_info "Promiscuous mode disabled on $target_interface"
fi

echo "Completed: $(date)" >> "$WORKFLOW_REPORT"
echo >> "$WORKFLOW_REPORT"

# Phase 2: Traffic Analysis
echo
echo "=== Phase 2: Traffic Analysis ==="
echo "--- PHASE 2: TRAFFIC ANALYSIS ---" >> "$WORKFLOW_REPORT"
echo "Started: $(date)" >> "$WORKFLOW_REPORT"

log_info "Starting Phase 2: Traffic analysis"

echo "Analyzing captured traffic for VLANs and network information..."

# Extract VLAN information
echo "Extracting VLAN information..." >> "$WORKFLOW_REPORT"
tshark -r "$capture_file" -T fields -e vlan.id 2>/dev/null | sort -nu | grep -v "^$" > "$TEMP_DIR/discovered_vlans.txt"

vlan_count=$(wc -l < "$TEMP_DIR/discovered_vlans.txt")
echo "VLANs discovered: $vlan_count"
echo "VLANs discovered: $vlan_count" >> "$WORKFLOW_REPORT"

if [ "$vlan_count" -gt 0 ]; then
    echo "VLAN IDs found:" >> "$WORKFLOW_REPORT"
    cat "$TEMP_DIR/discovered_vlans.txt" | sed 's/^/  /' >> "$WORKFLOW_REPORT"
    
    # Display discovered VLANs to user for selection
    echo
    echo "=== VLAN Discovery Results ==="
    echo "The following VLANs were discovered in the captured traffic:"
    echo
    
    vlan_info=""
    while read -r vlan_id; do
        if [ -n "$vlan_id" ]; then
            # Get sample IPs for this VLAN
            sample_ips=$(tshark -r "$capture_file" -Y "vlan.id == $vlan_id" -T fields -e ip.src -e ip.dst 2>/dev/null | \
                tr '\t' '\n' | grep -v "^$" | sort -u | head -3 | tr '\n' ' ')
            
            echo "  VLAN $vlan_id: ${sample_ips:-No IPs found}"
            vlan_info="$vlan_info$vlan_id:$sample_ips\n"
            
            # Add to report
            echo "  VLAN $vlan_id IP analysis:" >> "$WORKFLOW_REPORT"
            echo "$sample_ips" | tr ' ' '\n' | sed 's/^/    /' >> "$WORKFLOW_REPORT"
        fi
    done < "$TEMP_DIR/discovered_vlans.txt"
    
    echo
    echo "Which VLANs would you like to configure interfaces for?"
    echo "Enter VLAN IDs separated by spaces (or 'all' for all VLANs, 'none' to skip):"
    printf "VLAN selection: "
    read -r vlan_selection
    
    # Process user selection
    case "$vlan_selection" in
        "all"|"ALL"|"")
            selected_vlans=$(cat "$TEMP_DIR/discovered_vlans.txt" | tr '\n' ' ')
            echo "Selected all VLANs: $selected_vlans"
            ;;
        "none"|"NONE"|"skip"|"SKIP")
            selected_vlans=""
            echo "Skipping VLAN configuration"
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
                echo "Selected VLANs:$selected_vlans"
            else
                echo "No valid VLANs selected, skipping VLAN configuration"
            fi
            ;;
    esac
    
    # Update temp file with selected VLANs only
    if [ -n "$selected_vlans" ]; then
        echo "$selected_vlans" | tr ' ' '\n' | grep -v "^$" > "$TEMP_DIR/selected_vlans.txt"
        selected_vlan_count=$(wc -l < "$TEMP_DIR/selected_vlans.txt")
        echo "Will configure $selected_vlan_count VLAN interfaces"
    else
        touch "$TEMP_DIR/selected_vlans.txt"  # Create empty file
        selected_vlan_count=0
        echo "No VLANs will be configured"
    fi
else
    echo "No VLANs detected in capture" >> "$WORKFLOW_REPORT"
    touch "$TEMP_DIR/selected_vlans.txt"  # Create empty file
    selected_vlan_count=0
fi

# Extract general network information
echo "Extracting network ranges..." >> "$WORKFLOW_REPORT"
tshark -r "$capture_file" -T fields -e ip.src -e ip.dst 2>/dev/null | \
    tr '\t' '\n' | grep -v "^$" | sort -u | head -20 > "$TEMP_DIR/discovered_ips.txt"

ip_count=$(wc -l < "$TEMP_DIR/discovered_ips.txt")
echo "Unique IP addresses found: $ip_count"
echo "Unique IP addresses found: $ip_count" >> "$WORKFLOW_REPORT"

echo "✓ Traffic analysis completed successfully"
echo "Status: SUCCESS" >> "$WORKFLOW_REPORT"
echo "Completed: $(date)" >> "$WORKFLOW_REPORT"
echo >> "$WORKFLOW_REPORT"

# Phase 3: Interface Configuration
echo
echo "=== Phase 3: Interface Configuration ==="
echo "--- PHASE 3: INTERFACE CONFIGURATION ---" >> "$WORKFLOW_REPORT"
echo "Started: $(date)" >> "$WORKFLOW_REPORT"

log_info "Starting Phase 3: Interface configuration"

interfaces_configured=0

if [ "$selected_vlan_count" -gt 0 ]; then
    echo "Creating VLAN interfaces for selected VLANs..."
    echo "Creating VLAN interfaces..." >> "$WORKFLOW_REPORT"
    
    while read -r vlan_id; do
        if [ -n "$vlan_id" ]; then
            vlan_interface="${target_interface}.${vlan_id}"
            
            # Create VLAN interface if it doesn't exist
            if ! ip link show "$vlan_interface" >/dev/null 2>&1; then
                echo "Creating VLAN interface: $vlan_interface"
                
                if ip link add link "$target_interface" name "$vlan_interface" type vlan id "$vlan_id" 2>/dev/null; then
                    ip link set "$vlan_interface" up
                    echo "✓ VLAN interface $vlan_interface created and brought up"
                    echo "  Created: $vlan_interface" >> "$WORKFLOW_REPORT"
                    log_config_change "VLAN interface created" "$vlan_interface (VLAN ID: $vlan_id)"
                    interfaces_configured=$((interfaces_configured + 1))
                    
                    # Try to assign IP address based on discovered traffic with improved calculation
                    vlan_ips=$(tshark -r "$capture_file" -Y "vlan.id == $vlan_id" -T fields -e ip.src -e ip.dst 2>/dev/null | \
                              tr '\t' '\n' | grep -v "^$" | sort -u)
                    
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
                        echo "  Suggested IP: $suggested_ip (avoiding common gateway/firewall IPs)"
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
                    fi
                else
                    echo "✗ Failed to create VLAN interface $vlan_interface"
                    log_error "Failed to create VLAN interface $vlan_interface"
                fi
            else
                echo "VLAN interface $vlan_interface already exists"
                echo "  Exists: $vlan_interface" >> "$WORKFLOW_REPORT"
                interfaces_configured=$((interfaces_configured + 1))
            fi
        fi
    done < "$TEMP_DIR/selected_vlans.txt"
else
    echo "No VLANs selected for configuration"
    echo "No VLANs selected for configuration" >> "$WORKFLOW_REPORT"
fi

echo "✓ Interface configuration completed"
echo "VLAN interfaces configured: $interfaces_configured"
echo "Status: SUCCESS" >> "$WORKFLOW_REPORT"
echo "Interfaces configured: $interfaces_configured" >> "$WORKFLOW_REPORT"
echo "Completed: $(date)" >> "$WORKFLOW_REPORT"
echo >> "$WORKFLOW_REPORT"

# Phase 4: Network Discovery
echo
echo "=== Phase 4: Network Discovery ==="
echo "--- PHASE 4: NETWORK DISCOVERY ---" >> "$WORKFLOW_REPORT"
echo "Started: $(date)" >> "$WORKFLOW_REPORT"

log_info "Starting Phase 4: Network discovery"

echo "Running network discovery on configured interfaces..."
discovery_script="$(dirname "$0")/../network/multi_phase_discovery.sh"

if [ -x "$discovery_script" ]; then
    if [ "$interfaces_configured" -gt 0 ]; then
        echo "Running VLAN-aware discovery with separate results per VLAN..."
        echo "VLAN-aware discovery initiated" >> "$WORKFLOW_REPORT"
        
        # Create VLAN-specific discovery directories
        DISCOVERY_DIR="$WORKDIR/discovery"
        mkdir -p "$DISCOVERY_DIR"
        discovery_success=0
        
        # Discover networks on each configured VLAN interface
        while read -r vlan_id; do
            if [ -n "$vlan_id" ]; then
                vlan_interface="${target_interface}.${vlan_id}"
                vlan_discovery_dir="$DISCOVERY_DIR/${SESSION_NAME}_vlan_$vlan_id"
                
                echo "=== Discovering VLAN $vlan_id on interface $vlan_interface ==="
                echo "  VLAN $vlan_id discovery:" >> "$WORKFLOW_REPORT"
                
                # Check if interface exists and has IP
                if ip addr show "$vlan_interface" >/dev/null 2>&1; then
                    vlan_network=$(get_network_range "$vlan_interface")
                    if [ -n "$vlan_network" ]; then
                        echo "  Network range for VLAN $vlan_id: $vlan_network"
                        echo "    Network: $vlan_network" >> "$WORKFLOW_REPORT"
                        
                        # Create VLAN-specific discovery directory
                        mkdir -p "$vlan_discovery_dir"
                        
                        # Run discovery for this specific VLAN network
                        echo "  Starting multi-phase discovery on $vlan_network..."
                        NETUTIL_WORKDIR="$vlan_discovery_dir" "$discovery_script" "$vlan_interface" "1" > "$vlan_discovery_dir/discovery_output.txt" 2>&1
                        vlan_discovery_exit=$?
                        
                        if [ $vlan_discovery_exit -eq 0 ]; then
                            echo "  ✓ VLAN $vlan_id discovery completed successfully"
                            echo "    Status: SUCCESS" >> "$WORKFLOW_REPORT"
                            discovery_success=$((discovery_success + 1))
                            
                            # Link to any created discovery results
                            if [ -d "$vlan_discovery_dir/discovery" ]; then
                                latest_vlan_discovery=$(ls -t "$vlan_discovery_dir/discovery/discovery_"* 2>/dev/null | head -1)
                                if [ -n "$latest_vlan_discovery" ] && [ -d "$latest_vlan_discovery" ]; then
                                    ln -sf "$latest_vlan_discovery" "$vlan_discovery_dir/results"
                                    echo "    Results: $vlan_discovery_dir/results"
                                fi
                            fi
                        else
                            echo "  ✗ VLAN $vlan_id discovery failed"
                            echo "    Status: FAILED" >> "$WORKFLOW_REPORT"
                            log_warn "Discovery failed for VLAN $vlan_id"
                        fi
                        
                        # Add summary to report
                        echo "    Output summary:" >> "$WORKFLOW_REPORT"
                        head -20 "$vlan_discovery_dir/discovery_output.txt" 2>/dev/null | sed 's/^/      /' >> "$WORKFLOW_REPORT"
                    else
                        echo "  ⚠ No network range found for VLAN interface $vlan_interface"
                        echo "    Status: SKIPPED (no network)" >> "$WORKFLOW_REPORT"
                        log_warn "No network range found for VLAN interface $vlan_interface"
                    fi
                else
                    echo "  ⚠ VLAN interface $vlan_interface not found or not configured"
                    echo "    Status: SKIPPED (interface not found)" >> "$WORKFLOW_REPORT"
                    log_warn "VLAN interface $vlan_interface not found for discovery"
                fi
            fi
        done < "$TEMP_DIR/selected_vlans.txt"
        
        # Summary
        if [ $discovery_success -gt 0 ]; then
            echo "✓ VLAN-aware discovery completed: $discovery_success VLANs discovered successfully"
            echo "Status: SUCCESS ($discovery_success VLANs)" >> "$WORKFLOW_REPORT"
            echo "Discovery results organized in: $DISCOVERY_DIR/"
            
            # Create overall summary
            discovery_summary="$REPORT_SESSION_DIR/vlan_discovery_summary.txt"
            echo "VLAN Discovery Summary:" > "$discovery_summary"
            find "$DISCOVERY_DIR" -name "${SESSION_NAME}_vlan_*" -type d | while read -r vlan_dir; do
                vlan_name=$(basename "$vlan_dir" | sed "s/${SESSION_NAME}_//")
                echo "- $vlan_name: $([ -d "$vlan_dir/results" ] && echo "SUCCESS" || echo "FAILED")" >> "$discovery_summary"
            done
            echo "VLAN discovery summary: $discovery_summary"
        else
            echo "✗ All VLAN discoveries failed"
            echo "Status: FAILED" >> "$WORKFLOW_REPORT"
            log_error "All VLAN discoveries failed in auto-discovery workflow"
        fi
    else
        echo "Running standard discovery on main interface..."
        echo "Standard discovery initiated" >> "$WORKFLOW_REPORT"
        "$discovery_script" "$target_interface" "1" > "$TEMP_DIR/discovery_output.txt" 2>&1
        discovery_exit_code=$?
        
        if [ $discovery_exit_code -eq 0 ]; then
            echo "✓ Network discovery completed successfully"
            echo "Status: SUCCESS" >> "$WORKFLOW_REPORT"
            
            # Update latest symlinks for discovery results
            latest_discovery=$(ls -t "$DISCOVERY_DIR/discovery_"* 2>/dev/null | head -1 | tr -d '\n\r:')
            if [ -n "$latest_discovery" ] && [ -d "$latest_discovery" ]; then
                update_latest_links "discovery" "$latest_discovery"
                echo "Linked to: $latest_discovery"
            else
                echo "⚠ Warning: Could not find or link discovery results directory"
                log_warn "Discovery results directory not found or not accessible: $latest_discovery"
            fi
            
            # Include discovery output in report (first 50 lines)
            echo "Discovery output (summary):" >> "$WORKFLOW_REPORT"
            head -50 "$TEMP_DIR/discovery_output.txt" >> "$WORKFLOW_REPORT"
            echo "... (full output in discovery_results)" >> "$WORKFLOW_REPORT"
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
echo
echo "=== Phase 5: Advanced Analysis ==="
echo "--- PHASE 5: ADVANCED ANALYSIS ---" >> "$WORKFLOW_REPORT"
echo "Started: $(date)" >> "$WORKFLOW_REPORT"

log_info "Starting Phase 5: Advanced analysis"

echo "Running advanced packet analysis..."
analysis_script="$(dirname "$0")/../network/advanced_packet_analysis.sh"

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