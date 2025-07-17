#!/bin/sh

# NetUtility Shared Utility Functions
# This library provides common functions for interface selection, file selection, and network helpers
# POSIX shell compatible - works with bash, zsh, dash, fish

# =============================================================================
# INTERFACE SELECTION LIBRARY
# =============================================================================

# Function to get filtered interfaces (excluding loopback)
get_interfaces() {
    # Clear previous interface data
    rm -f /tmp/netutil_interfaces.$$
    interface_count=0
    
    # Parse interface information using POSIX-compliant pattern matching
    ip link show | while read -r line; do
        case "$line" in
            [0-9]*:\ *@*:*state\ *)
                # Handle VLAN interfaces (name@parent:)
                interface_name=$(echo "$line" | sed 's/^[0-9]*: *\([^@]*\)@.*/\1/')
                state=$(echo "$line" | sed 's/.*state \([A-Z]*\).*/\1/')
                ;;
            [0-9]*:\ *:*state\ *)
                # Handle regular interfaces (name:)
                interface_name=$(echo "$line" | sed 's/^[0-9]*: *\([^:]*\):.*/\1/')
                state=$(echo "$line" | sed 's/.*state \([A-Z]*\).*/\1/')
                ;;
            *)
                continue
                ;;
        esac
        
        # Skip loopback interface
        if [ "$interface_name" != "lo" ]; then
            interface_count=$((interface_count + 1))
            echo "$interface_count:$interface_name:$state" >> /tmp/netutil_interfaces.$$
        fi
    done
}

# Function to display interfaces in numbered format
display_interfaces() {
    echo "Available network interfaces:" >&2
    if [ -f /tmp/netutil_interfaces.$$ ]; then
        while IFS=':' read -r num name state; do
            printf "%d. %-12s (%s)\n" "$num" "$name" "$state" >&2
        done < /tmp/netutil_interfaces.$$
    fi
    echo >&2
}

# Function to get interface name by number
get_interface_name() {
    requested_num=$1
    
    if [ -f /tmp/netutil_interfaces.$$ ]; then
        while IFS=':' read -r num name state; do
            if [ "$num" = "$requested_num" ]; then
                echo "$name"
                return 0
            fi
        done < /tmp/netutil_interfaces.$$
    fi
    return 1
}

# Function to validate interface number input
validate_interface_number() {
    input_num=$1
    
    # Check if it's a valid number using POSIX pattern matching
    case "$input_num" in
        ''|*[!0-9]*)
            echo "Error: Please enter a number" >&2
            return 1
            ;;
    esac
    
    # Count available interfaces
    max_num=0
    if [ -f /tmp/netutil_interfaces.$$ ]; then
        while IFS=':' read -r num name state; do
            if [ "$num" -gt "$max_num" ]; then
                max_num=$num
            fi
        done < /tmp/netutil_interfaces.$$
    fi
    
    if [ "$input_num" -lt 1 ] || [ "$input_num" -gt "$max_num" ]; then
        echo "Error: Please enter a number between 1 and $max_num" >&2
        return 1
    fi
    
    return 0
}

# Main function for interface selection
select_interface() {
    prompt_text="${1:-Select interface}"
    
    get_interfaces
    
    # Check if any interfaces were found
    if [ ! -f /tmp/netutil_interfaces.$$ ] || [ ! -s /tmp/netutil_interfaces.$$ ]; then
        echo "Error: No network interfaces found" >&2
        return 1
    fi
    
    display_interfaces
    
    # Count interfaces for prompt
    max_num=0
    while IFS=':' read -r num name state; do
        if [ "$num" -gt "$max_num" ]; then
            max_num=$num
        fi
    done < /tmp/netutil_interfaces.$$
    
    while true; do
        printf "%s (1-%d): " "$prompt_text" "$max_num"
        read interface_num
        
        if validate_interface_number "$interface_num"; then
            if selected_interface=$(get_interface_name "$interface_num"); then
                echo "$selected_interface"
                # Clean up temp file
                rm -f /tmp/netutil_interfaces.$$
                return 0
            else
                echo "Error: Invalid interface selection" >&2
            fi
        fi
    done
}

# =============================================================================
# FILE SELECTION LIBRARY
# =============================================================================

# Function to get files from directory with optional filter
get_files() {
    directory=$1
    filter=${2:-"*"}
    
    # Clear previous file data
    rm -f /tmp/netutil_files.$$
    file_count=0
    
    if [ ! -d "$directory" ]; then
        echo "Error: Directory $directory not found"
        return 1
    fi
    
    # Use find with POSIX-compliant options
    find "$directory" -maxdepth 1 -name "$filter" -type f | sort | while read -r file; do
        if [ -f "$file" ]; then
            file_count=$((file_count + 1))
            echo "$file_count:$file" >> /tmp/netutil_files.$$
        fi
    done
    
    return 0
}

# Function to display files in numbered format
display_files() {
    show_path=${1:-false}
    
    echo "Available files:"
    if [ -f /tmp/netutil_files.$$ ]; then
        while IFS=':' read -r num filepath; do
            if [ "$show_path" = "true" ]; then
                printf "%d. %s\n" "$num" "$filepath"
            else
                basename_file=$(basename "$filepath")
                printf "%d. %s\n" "$num" "$basename_file"
            fi
        done < /tmp/netutil_files.$$
    fi
    echo
}

# Function to get file path by number
get_file_path() {
    requested_num=$1
    
    if [ -f /tmp/netutil_files.$$ ]; then
        while IFS=':' read -r num filepath; do
            if [ "$num" = "$requested_num" ]; then
                echo "$filepath"
                return 0
            fi
        done < /tmp/netutil_files.$$
    fi
    return 1
}

# Function to validate file number input
validate_file_number() {
    input_num=$1
    
    # Check if it's a valid number using POSIX pattern matching
    case "$input_num" in
        ''|*[!0-9]*)
            echo "Error: Please enter a number"
            return 1
            ;;
    esac
    
    # Count available files
    max_num=0
    if [ -f /tmp/netutil_files.$$ ]; then
        while IFS=':' read -r num filepath; do
            if [ "$num" -gt "$max_num" ]; then
                max_num=$num
            fi
        done < /tmp/netutil_files.$$
    fi
    
    if [ "$input_num" -lt 1 ] || [ "$input_num" -gt "$max_num" ]; then
        echo "Error: Please enter a number between 1 and $max_num"
        return 1
    fi
    
    return 0
}

# Main function for file selection
select_file() {
    directory=$1
    filter=${2:-"*"}
    prompt_text="${3:-Select file}"
    show_path=${4:-false}
    
    if ! get_files "$directory" "$filter"; then
        return 1
    fi
    
    # Check if any files were found
    if [ ! -f /tmp/netutil_files.$$ ] || [ ! -s /tmp/netutil_files.$$ ]; then
        echo "Error: No files found matching pattern '$filter' in $directory"
        return 1
    fi
    
    display_files "$show_path"
    
    # Count files for prompt
    max_num=0
    while IFS=':' read -r num filepath; do
        if [ "$num" -gt "$max_num" ]; then
            max_num=$num
        fi
    done < /tmp/netutil_files.$$
    
    while true; do
        printf "%s (1-%d): " "$prompt_text" "$max_num"
        read file_num
        
        if validate_file_number "$file_num"; then
            if selected_file=$(get_file_path "$file_num"); then
                echo "$selected_file"
                # Clean up temp file
                rm -f /tmp/netutil_files.$$
                return 0
            else
                echo "Error: Invalid file selection"
            fi
        fi
    done
}

# Specialized function for capture file selection
select_capture_file() {
    if [ -n "$NETUTIL_WORKDIR" ]; then
        capture_dir="$NETUTIL_WORKDIR/captures"
    else
        capture_dir="$HOME/captures"
    fi
    select_file "$capture_dir" "*.pcap" "Select capture file" true
}

# Specialized function for host file selection
select_host_file() {
    if [ -n "$NETUTIL_WORKDIR" ]; then
        host_dir="$NETUTIL_WORKDIR/enumeration"
    else
        host_dir="$HOME/enumeration"
    fi
    select_file "$host_dir" "hosts_*.txt" "Select host file" true
}

# =============================================================================
# IP/NETWORK HELPER FUNCTIONS
# =============================================================================

# Function to detect common IP ranges from interfaces
detect_common_ranges() {
    # Clear previous range data
    rm -f /tmp/netutil_ranges.$$
    
    # Get IP addresses from interfaces
    ip addr show | while read -r line; do
        case "$line" in
            *inet\ [0-9]*.[0-9]*.[0-9]*.[0-9]*/[0-9]*)
                # Extract IP and prefix using sed
                ip_with_prefix=$(echo "$line" | sed -n 's/.*inet \([0-9]*\.[0-9]*\.[0-9]*\.[0-9]*\/[0-9]*\).*/\1/p')
                if [ -n "$ip_with_prefix" ]; then
                    ip=$(echo "$ip_with_prefix" | cut -d/ -f1)
                    prefix=$(echo "$ip_with_prefix" | cut -d/ -f2)
                    
                    # Try to calculate network (fallback to simple method if ipcalc unavailable)
                    if command -v ipcalc >/dev/null 2>&1; then
                        network=$(ipcalc -n "$ip_with_prefix" 2>/dev/null | cut -d= -f2 2>/dev/null)
                        if [ -n "$network" ]; then
                            echo "$network/$prefix" >> /tmp/netutil_ranges.$$
                        fi
                    else
                        # Simple fallback - just use the IP range as-is
                        echo "$ip_with_prefix" >> /tmp/netutil_ranges.$$
                    fi
                fi
                ;;
        esac
    done
    
    # Add common ranges if not already present
    common_ranges="192.168.1.0/24 192.168.0.0/24 10.0.0.0/8 172.16.0.0/12"
    for range in $common_ranges; do
        if [ -f /tmp/netutil_ranges.$$ ]; then
            if ! grep -q "^$range$" /tmp/netutil_ranges.$$ 2>/dev/null; then
                echo "$range" >> /tmp/netutil_ranges.$$
            fi
        else
            echo "$range" >> /tmp/netutil_ranges.$$
        fi
    done
    
    # Output ranges
    if [ -f /tmp/netutil_ranges.$$ ]; then
        cat /tmp/netutil_ranges.$$
        rm -f /tmp/netutil_ranges.$$
    fi
}

# Function to validate IP address format
validate_ip() {
    ip=$1
    case "$ip" in
        [0-9]*.[0-9]*.[0-9]*.[0-9]*)
            # Basic pattern match, could be enhanced with more specific validation
            return 0
            ;;
        *)
            echo "Error: Invalid IP address format. Expected: x.x.x.x"
            return 1
            ;;
    esac
}

# Function to validate IP range format
validate_ip_range() {
    range=$1
    case "$range" in
        [0-9]*.[0-9]*.[0-9]*.[0-9]*/[0-9]*)
            # Basic pattern match for CIDR notation
            return 0
            ;;
        *)
            echo "Error: Invalid IP range format. Expected: x.x.x.x/xx"
            return 1
            ;;
    esac
}

# Function for smart target selection
select_target() {
    echo "Target selection:"
    echo "1. Single IP address"
    echo "2. IP range (CIDR)"
    echo "3. Host file"
    echo "4. Auto-detect from network ranges"
    echo
    
    while true; do
        printf "Select target type (1-4): "
        read target_type
        
        case $target_type in
            1)
                printf "Enter IP address: "
                read target_value
                if validate_ip "$target_value"; then
                    echo "$target_value"
                    return 0
                fi
                ;;
            2)
                printf "Enter IP range (e.g., 192.168.1.0/24): "
                read target_value
                if validate_ip_range "$target_value"; then
                    echo "$target_value"
                    return 0
                fi
                ;;
            3)
                if target_value=$(select_host_file); then
                    echo "-iL $target_value"
                    return 0
                fi
                ;;
            4)
                echo "Common IP ranges:"
                # Get ranges and store in temp file
                rm -f /tmp/netutil_target_ranges.$$
                range_count=0
                detect_common_ranges | while read -r range; do
                    range_count=$((range_count + 1))
                    echo "$range_count:$range" >> /tmp/netutil_target_ranges.$$
                done
                
                # Display ranges
                if [ -f /tmp/netutil_target_ranges.$$ ]; then
                    while IFS=':' read -r num range; do
                        printf "%d. %s\n" "$num" "$range"
                    done < /tmp/netutil_target_ranges.$$
                    echo
                    
                    # Get max range number
                    max_range_num=0
                    while IFS=':' read -r num range; do
                        if [ "$num" -gt "$max_range_num" ]; then
                            max_range_num=$num
                        fi
                    done < /tmp/netutil_target_ranges.$$
                    
                    printf "Select range (1-%d): " "$max_range_num"
                    read range_num
                    
                    # Validate range selection
                    case "$range_num" in
                        ''|*[!0-9]*)
                            echo "Error: Invalid range selection"
                            ;;
                        *)
                            if [ "$range_num" -ge 1 ] && [ "$range_num" -le "$max_range_num" ]; then
                                # Find selected range
                                while IFS=':' read -r num range; do
                                    if [ "$num" = "$range_num" ]; then
                                        echo "$range"
                                        rm -f /tmp/netutil_target_ranges.$$
                                        return 0
                                    fi
                                done < /tmp/netutil_target_ranges.$$
                            else
                                echo "Error: Invalid range selection"
                            fi
                            ;;
                    esac
                    rm -f /tmp/netutil_target_ranges.$$
                fi
                ;;
            *)
                echo "Error: Invalid option. Please select 1-4"
                ;;
        esac
    done
}

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

# Function to show loading indicator
show_loading() {
    message=$1
    delay=${2:-0.5}
    
    echo -n "$message"
    i=1
    while [ $i -le 3 ]; do
        echo -n "."
        sleep "$delay"
        i=$((i + 1))
    done
    echo
}

# Function to confirm action
confirm_action() {
    prompt=$1
    
    printf "%s (y/N): " "$prompt"
    read response
    case $response in
        [Yy]|[Yy][Ee][Ss])
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# Function to display success message
success_message() {
    echo "✓ $1"
}

# Function to display error message
error_message() {
    echo "✗ Error: $1" >&2
}

# Function to display warning message
warning_message() {
    echo "⚠ Warning: $1" >&2
}