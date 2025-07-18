#!/bin/sh

# NetUtility Shared Utility Functions
# This library provides common functions for interface selection, file selection, and network helpers
# POSIX shell compatible - works with bash, zsh, dash, fish

# =============================================================================
# INTERFACE SELECTION LIBRARY
# =============================================================================

# Function to get filtered interfaces with enhanced information
get_interfaces() {
    # Clear previous interface data
    rm -f /tmp/netutil_interfaces.$$
    interface_count=0
    
    # Create temporary file with interface information
    ip link show > /tmp/netutil_ip_output.$$
    
    # Parse interface information using POSIX-compliant pattern matching
    while read -r line; do
        case "$line" in
            [0-9]*:\ *@*:*state\ *)
                # Handle VLAN interfaces (name@parent:)
                interface_name=$(echo "$line" | sed 's/^[0-9]*: *\([^@]*\)@.*/\1/')
                state=$(echo "$line" | sed 's/.*state \([A-Z]*\).*/\1/')
                parent_interface=$(echo "$line" | sed 's/^[0-9]*: *[^@]*@\([^:]*\):.*/\1/')
                ;;
            [0-9]*:\ *:*state\ *)
                # Handle regular interfaces (name:)
                interface_name=$(echo "$line" | sed 's/^[0-9]*: *\([^:]*\):.*/\1/')
                state=$(echo "$line" | sed 's/.*state \([A-Z]*\).*/\1/')
                parent_interface=""
                ;;
            *)
                continue
                ;;
        esac
        
        # Skip loopback interface
        if [ "$interface_name" != "lo" ]; then
            # Get IP address information
            ip_info=$(ip addr show "$interface_name" 2>/dev/null | grep "inet " | head -1 | awk '{print $2}')
            if [ -z "$ip_info" ]; then
                ip_info="No IP"
            fi
            
            # Determine interface type
            interface_type="Unknown"
            if echo "$interface_name" | grep -q "^eth"; then
                interface_type="Ethernet"
            elif echo "$interface_name" | grep -q "^wl"; then
                interface_type="WiFi"
            elif echo "$interface_name" | grep -q "^en"; then
                interface_type="Ethernet"
            elif echo "$interface_name" | grep -q "^ww"; then
                interface_type="WWAN"
            elif echo "$interface_name" | grep -q "\."; then
                interface_type="VLAN"
            elif echo "$interface_name" | grep -q "^tun"; then
                interface_type="VPN"
            elif echo "$interface_name" | grep -q "^tap"; then
                interface_type="TAP"
            elif echo "$interface_name" | grep -q "^br"; then
                interface_type="Bridge"
            fi
            
            # Create smart alias
            if [ "$state" = "UP" ] && [ "$ip_info" != "No IP" ]; then
                smart_alias="$interface_name (${ip_info} - $interface_type)"
            else
                smart_alias="$interface_name ($state - $interface_type)"
            fi
            
            interface_count=$((interface_count + 1))
            echo "$interface_count:$interface_name:$state:$ip_info:$interface_type:$smart_alias" >> /tmp/netutil_interfaces.$$
        fi
    done < /tmp/netutil_ip_output.$$
    
    # Clean up temporary file
    rm -f /tmp/netutil_ip_output.$$
}

# Function to display interfaces in numbered format with smart aliases
display_interfaces() {
    echo "Available network interfaces:" >&2
    if [ -f /tmp/netutil_interfaces.$$ ]; then
        while IFS=':' read -r num name state ip_info interface_type smart_alias; do
            printf "%d. %s\n" "$num" "$smart_alias" >&2
        done < /tmp/netutil_interfaces.$$
    fi
    echo >&2
}

# Function to get interface name by number
get_interface_name() {
    requested_num=$1
    
    if [ -f /tmp/netutil_interfaces.$$ ]; then
        while IFS=':' read -r num name state ip_info interface_type smart_alias; do
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
        while IFS=':' read -r num name state ip_info interface_type smart_alias; do
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

# Enhanced interface selection with memory
select_interface() {
    prompt_text="${1:-Select interface}"
    category="${2:-general}"
    
    get_interfaces
    
    # Check if any interfaces were found
    if [ ! -f /tmp/netutil_interfaces.$$ ] || [ ! -s /tmp/netutil_interfaces.$$ ]; then
        echo "Error: No network interfaces found" >&2
        return 1
    fi
    
    # Try to get last used interface for this category
    last_used=$(get_last_used_interface "$category")
    default_option=""
    
    if [ -n "$last_used" ]; then
        # Find the number for the last used interface
        while IFS=':' read -r num name state ip_info interface_type smart_alias; do
            if [ "$name" = "$last_used" ]; then
                default_option="$num"
                break
            fi
        done < /tmp/netutil_interfaces.$$
    fi
    
    # If no last used interface, try to find best default
    if [ -z "$default_option" ]; then
        # Prefer interfaces with IP addresses that are UP
        while IFS=':' read -r num name state ip_info interface_type smart_alias; do
            if [ "$state" = "UP" ] && [ "$ip_info" != "No IP" ]; then
                default_option="$num"
                break
            fi
        done < /tmp/netutil_interfaces.$$
    fi
    
    display_interfaces
    
    # Count interfaces for prompt
    max_num=0
    while IFS=':' read -r num name state ip_info interface_type smart_alias; do
        if [ "$num" -gt "$max_num" ]; then
            max_num=$num
        fi
    done < /tmp/netutil_interfaces.$$
    
    # Show smart default prompt
    if [ -n "$default_option" ]; then
        default_interface=$(get_interface_name "$default_option")
        printf "%s (1-%d, default: %s): " "$prompt_text" "$max_num" "$default_interface" >&2
    else
        printf "%s (1-%d): " "$prompt_text" "$max_num" >&2
    fi
    
    read interface_num
    
    # Use default if no input provided
    if [ -z "$interface_num" ] && [ -n "$default_option" ]; then
        interface_num="$default_option"
    fi
    
    while true; do
        if validate_interface_number "$interface_num"; then
            if selected_interface=$(get_interface_name "$interface_num"); then
                # Save as last used for this category
                save_last_used_interface "$category" "$selected_interface"
                echo "$selected_interface"
                # Clean up temp file
                rm -f /tmp/netutil_interfaces.$$
                return 0
            else
                echo "Error: Invalid interface selection" >&2
            fi
        fi
        
        # If we get here, the input was invalid, ask again
        printf "%s (1-%d): " "$prompt_text" "$max_num" >&2
        read interface_num
    done
}

# =============================================================================
# INTERFACE MEMORY FUNCTIONS
# =============================================================================

# Function to get last used interface for a category
get_last_used_interface() {
    category=$1
    config_file="$HOME/.netutil/interface_memory"
    
    if [ -f "$config_file" ]; then
        grep "^${category}:" "$config_file" | cut -d: -f2
    fi
}

# Function to save last used interface for a category
save_last_used_interface() {
    category=$1
    interface=$2
    config_file="$HOME/.netutil/interface_memory"
    
    # Create directory if it doesn't exist
    mkdir -p "$(dirname "$config_file")"
    
    # Remove existing entry for this category
    if [ -f "$config_file" ]; then
        grep -v "^${category}:" "$config_file" > "${config_file}.tmp"
        mv "${config_file}.tmp" "$config_file"
    fi
    
    # Add new entry
    echo "${category}:${interface}" >> "$config_file"
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
        echo "Error: Directory $directory not found" >&2
        return 1
    fi
    
    # Use find with POSIX-compliant options and avoid subshell issues
    find "$directory" -maxdepth 1 -name "$filter" -type f | sort > /tmp/netutil_find_output.$$
    
    # Process the results
    while read -r file; do
        if [ -f "$file" ]; then
            file_count=$((file_count + 1))
            echo "$file_count:$file" >> /tmp/netutil_files.$$
        fi
    done < /tmp/netutil_find_output.$$
    
    # Clean up temporary file
    rm -f /tmp/netutil_find_output.$$
    
    return 0
}

# Function to display files in numbered format
display_files() {
    show_path=${1:-false}
    
    echo "Available files:" >&2
    if [ -f /tmp/netutil_files.$$ ]; then
        while IFS=':' read -r num filepath; do
            if [ "$show_path" = "true" ]; then
                printf "%d. %s\n" "$num" "$filepath" >&2
            else
                basename_file=$(basename "$filepath")
                printf "%d. %s\n" "$num" "$basename_file" >&2
            fi
        done < /tmp/netutil_files.$$
    fi
    echo >&2
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
            echo "Error: Please enter a number" >&2
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
        echo "Error: Please enter a number between 1 and $max_num" >&2
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
        echo "Error: No files found matching pattern '$filter' in $directory" >&2
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
        printf "%s (1-%d): " "$prompt_text" "$max_num" >&2
        read file_num
        
        if validate_file_number "$file_num"; then
            if selected_file=$(get_file_path "$file_num"); then
                echo "$selected_file"
                # Clean up temp file
                rm -f /tmp/netutil_files.$$
                return 0
            else
                echo "Error: Invalid file selection" >&2
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
# TARGET MEMORY FUNCTIONS
# =============================================================================

# Function to get recent targets
get_recent_targets() {
    config_file="$HOME/.netutil/target_memory"
    
    if [ -f "$config_file" ]; then
        cat "$config_file" | head -10
    fi
}

# Function to save target to memory
save_target() {
    target=$1
    config_file="$HOME/.netutil/target_memory"
    
    # Create directory if it doesn't exist
    mkdir -p "$(dirname "$config_file")"
    
    # Remove existing entry if it exists
    if [ -f "$config_file" ]; then
        grep -v "^${target}$" "$config_file" > "${config_file}.tmp"
        mv "${config_file}.tmp" "$config_file"
    fi
    
    # Add new entry at the beginning
    echo "$target" | cat - "$config_file" > "${config_file}.tmp" 2>/dev/null
    mv "${config_file}.tmp" "$config_file"
    
    # Keep only last 10 entries
    head -10 "$config_file" > "${config_file}.tmp"
    mv "${config_file}.tmp" "$config_file"
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

# Function for smart target selection with memory
select_target() {
    echo "Target selection:"
    echo "1. Single IP address"
    echo "2. IP range (CIDR)"
    echo "3. Host file"
    echo "4. Auto-detect from network ranges"
    echo "5. Recent targets"
    echo
    
    while true; do
        printf "Select target type (1-5): "
        read target_type
        
        case $target_type in
            1)
                printf "Enter IP address: "
                read target_value
                if validate_ip "$target_value"; then
                    save_target "$target_value"
                    echo "$target_value"
                    return 0
                fi
                ;;
            2)
                printf "Enter IP range (e.g., 192.168.1.0/24): "
                read target_value
                if validate_ip_range "$target_value"; then
                    save_target "$target_value"
                    echo "$target_value"
                    return 0
                fi
                ;;
            3)
                if target_value=$(select_host_file); then
                    save_target "$target_value"
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
                                        save_target "$range"
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
            5)
                echo "Recent targets:"
                # Get recent targets and store in temp file
                rm -f /tmp/netutil_recent_targets.$$
                target_count=0
                get_recent_targets | while read -r target; do
                    if [ -n "$target" ]; then
                        target_count=$((target_count + 1))
                        echo "$target_count:$target" >> /tmp/netutil_recent_targets.$$
                    fi
                done
                
                # Display recent targets
                if [ -f /tmp/netutil_recent_targets.$$ ] && [ -s /tmp/netutil_recent_targets.$$ ]; then
                    while IFS=':' read -r num target; do
                        printf "%d. %s\n" "$num" "$target"
                    done < /tmp/netutil_recent_targets.$$
                    echo
                    
                    # Get max target number
                    max_target_num=0
                    while IFS=':' read -r num target; do
                        if [ "$num" -gt "$max_target_num" ]; then
                            max_target_num=$num
                        fi
                    done < /tmp/netutil_recent_targets.$$
                    
                    printf "Select target (1-%d): " "$max_target_num"
                    read target_num
                    
                    # Validate target selection
                    case "$target_num" in
                        ''|*[!0-9]*)
                            echo "Error: Invalid target selection"
                            ;;
                        *)
                            if [ "$target_num" -ge 1 ] && [ "$target_num" -le "$max_target_num" ]; then
                                # Find selected target
                                while IFS=':' read -r num target; do
                                    if [ "$num" = "$target_num" ]; then
                                        save_target "$target"
                                        echo "$target"
                                        rm -f /tmp/netutil_recent_targets.$$
                                        return 0
                                    fi
                                done < /tmp/netutil_recent_targets.$$
                            else
                                echo "Error: Invalid target selection"
                            fi
                            ;;
                    esac
                    rm -f /tmp/netutil_recent_targets.$$
                else
                    echo "No recent targets found."
                fi
                ;;
            *)
                echo "Error: Invalid option. Please select 1-5"
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