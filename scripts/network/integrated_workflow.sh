#!/bin/sh

# Integrated Discovery Workflow
# Comprehensive network analysis with proper sequencing:
# 1. Promiscuous capture → 2. Traffic analysis → 3. Interface configuration → 4. Discovery

. "$(dirname "$0")/../common/utils.sh"
. "$(dirname "$0")/../common/logging.sh"

echo "=== Integrated Network Discovery Workflow ==="
echo

# Log script start
log_script_start "integrated_workflow.sh" "$@"

WORKFLOW_DIR="${NETUTIL_WORKDIR:-$HOME}/workflows"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SESSION_DIR="$WORKFLOW_DIR/integrated_workflow_${TIMESTAMP}"
TEMP_DIR=$(mktemp -d)

# Cleanup on exit
trap 'rm -rf "$TEMP_DIR"' EXIT

# Create workflow directory
mkdir -p "$SESSION_DIR"

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

# Workflow report
WORKFLOW_REPORT="$SESSION_DIR/integrated_workflow_report.txt"

echo "=== Integrated Network Discovery Workflow Report ===" > "$WORKFLOW_REPORT"
echo "Workflow started: $(date)" >> "$WORKFLOW_REPORT"
echo "Session directory: $SESSION_DIR" >> "$WORKFLOW_REPORT"
echo >> "$WORKFLOW_REPORT"

echo "This workflow follows the proper sequence for comprehensive network analysis:"
echo "1. Promiscuous packet capture (capture all traffic)"
echo "2. Traffic analysis (identify VLANs and network ranges)"
echo "3. Interface configuration (create VLAN interfaces and assign IPs)"
echo "4. Network discovery (multi-phase discovery on configured interfaces)"
echo "5. Advanced analysis (security and protocol analysis)"
echo

log_info "Starting integrated workflow with proper sequencing"

# Get target interface
echo "Available network interfaces:"
target_interface=$(select_interface)

if [ -z "$target_interface" ]; then
    echo "No interface selected"
    log_error "No interface selected for integrated workflow"
    exit 1
fi

echo "Selected interface: $target_interface"
log_info "Selected interface for integrated workflow: $target_interface"

# Workflow configuration
echo
echo "Workflow configuration:"
echo "The integrated workflow will capture network traffic in promiscuous mode"
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
log_info "Workflow capture duration: $capture_duration minutes"

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
capture_file="$SESSION_DIR/promiscuous_capture.pcap"
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
    
    # Analyze each VLAN for IP ranges
    echo "Analyzing IP ranges per VLAN..." >> "$WORKFLOW_REPORT"
    while read -r vlan_id; do
        if [ -n "$vlan_id" ]; then
            echo "  VLAN $vlan_id IP analysis:" >> "$WORKFLOW_REPORT"
            tshark -r "$capture_file" -Y "vlan.id == $vlan_id" -T fields -e ip.src -e ip.dst 2>/dev/null | \
                tr '\t' '\n' | grep -v "^$" | sort -u | head -5 | sed 's/^/    /' >> "$WORKFLOW_REPORT"
        fi
    done < "$TEMP_DIR/discovered_vlans.txt"
else
    echo "No VLANs detected in capture" >> "$WORKFLOW_REPORT"
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

if [ "$vlan_count" -gt 0 ]; then
    echo "Creating VLAN interfaces based on discovered traffic..."
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
                    
                    # Try to assign IP address based on discovered traffic
                    vlan_ips=$(tshark -r "$capture_file" -Y "vlan.id == $vlan_id" -T fields -e ip.src -e ip.dst 2>/dev/null | \
                              tr '\t' '\n' | grep -v "^$" | sort -u | head -1)
                    
                    if [ -n "$vlan_ips" ]; then
                        # Extract network portion (assuming /24)
                        network_base=$(echo "$vlan_ips" | cut -d'.' -f1-3)
                        suggested_ip="${network_base}.254/24"
                        
                        echo "  Discovered network: $network_base.0/24"
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
                    fi
                else
                    echo "✗ Failed to create VLAN interface $vlan_interface"
                    log_error "Failed to create VLAN interface $vlan_interface"
                fi
            else
                echo "VLAN interface $vlan_interface already exists"
                echo "  Exists: $vlan_interface" >> "$WORKFLOW_REPORT"
            fi
        fi
    done < "$TEMP_DIR/discovered_vlans.txt"
else
    echo "No VLANs to configure"
    echo "No VLANs to configure" >> "$WORKFLOW_REPORT"
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

echo "Running multi-phase discovery on configured interfaces..."
discovery_script="$(dirname "$0")/multi_phase_discovery.sh"

if [ -x "$discovery_script" ]; then
    # Run discovery in VLAN-aware mode if VLANs were configured
    if [ "$interfaces_configured" -gt 0 ]; then
        echo "Running VLAN-aware discovery..."
        "$discovery_script" "$target_interface" "2" > "$TEMP_DIR/discovery_output.txt" 2>&1
    else
        echo "Running standard discovery..."
        "$discovery_script" "$target_interface" "1" > "$TEMP_DIR/discovery_output.txt" 2>&1
    fi
    
    discovery_exit_code=$?
    
    if [ $discovery_exit_code -eq 0 ]; then
        echo "✓ Network discovery completed successfully"
        echo "Status: SUCCESS" >> "$WORKFLOW_REPORT"
        
        # Link discovery results to workflow directory
        latest_discovery=$(ls -t "${NETUTIL_WORKDIR:-$HOME}/discovery/discovery_"* 2>/dev/null | head -1 | tr -d '\n\r:')
        if [ -n "$latest_discovery" ] && [ -d "$latest_discovery" ]; then
            ln -sf "$latest_discovery" "$SESSION_DIR/discovery_results"
            echo "Discovery results linked: $SESSION_DIR/discovery_results"
            echo "Linked to: $latest_discovery"
        else
            echo "⚠ Warning: Could not find or link discovery results directory"
            log_warn "Discovery results directory not found or not accessible: $latest_discovery"
        fi
    else
        echo "✗ Network discovery failed"
        echo "Status: FAILED" >> "$WORKFLOW_REPORT"
        log_error "Network discovery failed in integrated workflow"
    fi
    
    # Include discovery output in report (first 50 lines)
    echo "Discovery output (summary):" >> "$WORKFLOW_REPORT"
    head -50 "$TEMP_DIR/discovery_output.txt" >> "$WORKFLOW_REPORT"
    echo "... (full output in discovery_results)" >> "$WORKFLOW_REPORT"
else
    echo "✗ Discovery script not found"
    echo "Status: FAILED (script not found)" >> "$WORKFLOW_REPORT"
    log_error "Discovery script not found for integrated workflow"
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
analysis_script="$(dirname "$0")/advanced_packet_analysis.sh"

if [ -x "$analysis_script" ]; then
    "$analysis_script" "$capture_file" > "$TEMP_DIR/analysis_output.txt" 2>&1
    analysis_exit_code=$?
    
    if [ $analysis_exit_code -eq 0 ]; then
        echo "✓ Advanced analysis completed successfully"
        echo "Status: SUCCESS" >> "$WORKFLOW_REPORT"
        
        # Link analysis results
        latest_analysis=$(ls -t "${NETUTIL_WORKDIR:-$HOME}/analysis/advanced_analysis_"* 2>/dev/null | head -1)
        if [ -n "$latest_analysis" ]; then
            ln -sf "$latest_analysis" "$SESSION_DIR/advanced_analysis.txt"
            echo "Advanced analysis linked: $SESSION_DIR/advanced_analysis.txt"
        fi
    else
        echo "✗ Advanced analysis failed"
        echo "Status: FAILED" >> "$WORKFLOW_REPORT"
        log_error "Advanced analysis failed in integrated workflow"
    fi
else
    echo "✗ Advanced analysis script not found"
    echo "Status: FAILED (script not found)" >> "$WORKFLOW_REPORT"
    log_error "Advanced analysis script not found for integrated workflow"
fi

echo "Completed: $(date)" >> "$WORKFLOW_REPORT"
echo >> "$WORKFLOW_REPORT"

# Generate workflow summary
echo "--- WORKFLOW SUMMARY ---" >> "$WORKFLOW_REPORT"
echo "Workflow completed: $(date)" >> "$WORKFLOW_REPORT"
echo "Total VLANs discovered: $vlan_count" >> "$WORKFLOW_REPORT"
echo "VLAN interfaces configured: $interfaces_configured" >> "$WORKFLOW_REPORT"
echo "Capture file: $capture_file" >> "$WORKFLOW_REPORT"
echo "Capture size: $(du -h "$capture_file" | cut -f1)" >> "$WORKFLOW_REPORT"

# Final summary
echo
echo "=== Integrated Workflow Summary ==="
echo "✓ Phase 1: Promiscuous capture completed ($capture_duration min)"
echo "✓ Phase 2: Traffic analysis completed ($vlan_count VLANs, $ip_count IPs)"
echo "✓ Phase 3: Interface configuration completed ($interfaces_configured VLAN interfaces)"
echo "✓ Phase 4: Network discovery completed"
echo "✓ Phase 5: Advanced analysis completed"
echo
echo "Workflow results saved to: $SESSION_DIR"
echo "Comprehensive report: $WORKFLOW_REPORT"
echo "Main capture file: $capture_file"

# List created files and links
echo
echo "Files and links created:"
find "$SESSION_DIR" -type f -o -type l | while read -r file; do
    echo "  - $(basename "$file")"
done

log_info "Integrated workflow completed successfully"
log_script_end "integrated_workflow.sh" 0

echo
echo "Integrated workflow complete!"
echo "The system is now configured with discovered VLANs and ready for further analysis."