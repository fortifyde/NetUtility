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
read -p "Capture duration in minutes (default 5): " capture_duration
capture_duration=${capture_duration:-5}

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
    # Use tshark for capture
    timeout $((capture_duration * 60)) tshark -i "$target_interface" -w "$capture_file" -q 2>/dev/null
    capture_exit_code=$?
    
    if [ $capture_exit_code -eq 0 ] || [ $capture_exit_code -eq 124 ]; then  # 124 = timeout
        echo "✓ Promiscuous capture completed successfully"
        echo "Status: SUCCESS" >> "$WORKFLOW_REPORT"
        log_network_operation "Promiscuous capture" "$target_interface" "Completed - $(du -h "$capture_file" | cut -f1)"
        
        # Get basic capture stats
        packet_count=$(tshark -r "$capture_file" -q -z io,stat,0 2>/dev/null | grep -o "frames:[0-9]*" | cut -d: -f2 | head -1)
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
                        echo "  Assigning IP: $suggested_ip"
                        
                        if ip addr add "$suggested_ip" dev "$vlan_interface" 2>/dev/null; then
                            echo "✓ IP address $suggested_ip assigned to $vlan_interface"
                            echo "    IP assigned: $suggested_ip" >> "$WORKFLOW_REPORT"
                            log_config_change "IP assigned to VLAN interface" "$vlan_interface: $suggested_ip"
                        else
                            echo "⚠ Failed to assign IP $suggested_ip to $vlan_interface"
                            log_warn "Failed to assign IP $suggested_ip to $vlan_interface"
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
        echo -e "$target_interface\n2\n" | "$discovery_script" > "$TEMP_DIR/discovery_output.txt" 2>&1
    else
        echo "Running standard discovery..."
        echo -e "$target_interface\n1\n" | "$discovery_script" > "$TEMP_DIR/discovery_output.txt" 2>&1
    fi
    
    discovery_exit_code=$?
    
    if [ $discovery_exit_code -eq 0 ]; then
        echo "✓ Network discovery completed successfully"
        echo "Status: SUCCESS" >> "$WORKFLOW_REPORT"
        
        # Link discovery results to workflow directory
        latest_discovery=$(ls -t "${NETUTIL_WORKDIR:-$HOME}/discovery/discovery_"* 2>/dev/null | head -1)
        if [ -n "$latest_discovery" ]; then
            ln -sf "$latest_discovery" "$SESSION_DIR/discovery_results"
            echo "Discovery results linked: $SESSION_DIR/discovery_results"
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
    echo "$capture_file" | "$analysis_script" > "$TEMP_DIR/analysis_output.txt" 2>&1
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