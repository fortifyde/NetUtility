#!/bin/sh

# NetUtility Shared Utility Functions
# This library provides common functions for interface selection, file selection, and network helpers
# POSIX shell compatible - works with bash, zsh, dash, fish

# Private temp directory for interface selection helpers.
# Created once at library load and cleaned up via trap on script exit.
_netutil_tmpdir="${TMPDIR:-/tmp}/netutil.$$"
mkdir -p "$_netutil_tmpdir"
trap 'rm -rf "$_netutil_tmpdir"' EXIT

# =============================================================================
# INTERFACE SELECTION LIBRARY
# =============================================================================

# Function to get filtered interfaces with enhanced information
get_interfaces() {
    exclude_vlans="${1:-false}"  # Optional parameter to exclude VLAN interfaces

    # Clear previous interface data
    rm -f "$_netutil_tmpdir/interfaces"
    interface_count=0

    # Create temporary file with interface information
    ip link show > "$_netutil_tmpdir/ip_output"
    
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
            if echo "$interface_name" | grep -q "\."; then
                interface_type="VLAN"
            elif echo "$interface_name" | grep -q "^eth"; then
                interface_type="Ethernet"
            elif echo "$interface_name" | grep -q "^wl"; then
                interface_type="WiFi"
            elif echo "$interface_name" | grep -q "^en"; then
                interface_type="Ethernet"
            elif echo "$interface_name" | grep -q "^ww"; then
                interface_type="WWAN"
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

            # Skip VLAN interfaces if requested
            if [ "$exclude_vlans" = "true" ] && [ "$interface_type" = "VLAN" ]; then
                continue
            fi

            interface_count=$((interface_count + 1))
            echo "$interface_count:$interface_name:$state:$ip_info:$interface_type:$smart_alias" >> "$_netutil_tmpdir/interfaces"
        fi
    done < "$_netutil_tmpdir/ip_output"
    
    # Clean up temporary file
    rm -f "$_netutil_tmpdir/ip_output"
}

# Function to display interfaces in numbered format with smart aliases
display_interfaces() {
    echo "Available network interfaces:" >&2
    if [ -f "$_netutil_tmpdir/interfaces" ]; then
        while IFS=':' read -r num name state ip_info interface_type smart_alias; do
            printf "%d. %s\n" "$num" "$smart_alias" >&2
        done < "$_netutil_tmpdir/interfaces"
    fi
    echo >&2
}

# Function to get interface name by number
get_interface_name() {
    requested_num=$1
    
    if [ -f "$_netutil_tmpdir/interfaces" ]; then
        while IFS=':' read -r num name state ip_info interface_type smart_alias; do
            if [ "$num" = "$requested_num" ]; then
                echo "$name"
                return 0
            fi
        done < "$_netutil_tmpdir/interfaces"
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
    if [ -f "$_netutil_tmpdir/interfaces" ]; then
        while IFS=':' read -r num name state ip_info interface_type smart_alias; do
            if [ "$num" -gt "$max_num" ]; then
                max_num=$num
            fi
        done < "$_netutil_tmpdir/interfaces"
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
    exclude_vlans="${3:-false}"  # Optional parameter to exclude VLAN interfaces

    get_interfaces "$exclude_vlans"
    
    # Check if any interfaces were found
    if [ ! -f "$_netutil_tmpdir/interfaces" ] || [ ! -s "$_netutil_tmpdir/interfaces" ]; then
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
        done < "$_netutil_tmpdir/interfaces"
    fi
    
    # If no last used interface, try to find best default
    if [ -z "$default_option" ]; then
        # Prefer interfaces with IP addresses that are UP
        while IFS=':' read -r num name state ip_info interface_type smart_alias; do
            if [ "$state" = "UP" ] && [ "$ip_info" != "No IP" ]; then
                default_option="$num"
                break
            fi
        done < "$_netutil_tmpdir/interfaces"
    fi
    
    display_interfaces
    
    # Count interfaces for prompt
    max_num=0
    while IFS=':' read -r num name state ip_info interface_type smart_alias; do
        if [ "$num" -gt "$max_num" ]; then
            max_num=$num
        fi
    done < "$_netutil_tmpdir/interfaces"
    
    # Show smart default prompt with immediate visibility
    if [ -n "$default_option" ]; then
        default_interface=$(get_interface_name "$default_option")
        echo >&2
        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
            printf "%s%s (1-%s, default: %s)%s\n" "$PROMPT_COLOR" "$prompt_text" "$max_num" "$default_interface" "$COLOR_RESET" >&2
        else
            printf "%s (1-%s, default: %s): \n" "$prompt_text" "$max_num" "$default_interface" >&2
        fi
        read -r interface_num
    else
        echo >&2
        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
            printf "%s%s (1-%s): %s\n" "$PROMPT_COLOR" "$prompt_text" "$max_num" "$COLOR_RESET" >&2
        else
            printf "%s (1-%s): \n" "$prompt_text" "$max_num" >&2
        fi
        read -r interface_num
    fi
    
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
                rm -f "$_netutil_tmpdir/interfaces"
                return 0
            else
                echo "Error: Invalid interface selection" >&2
            fi
        fi
        
        # If we get here, the input was invalid, ask again
        echo >&2
        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
            printf "%s%s (1-%s): %s\n" "$PROMPT_COLOR" "$prompt_text" "$max_num" "$COLOR_RESET" >&2
        else
            printf "%s (1-%s): \n" "$prompt_text" "$max_num" >&2
        fi
        read -r interface_num
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
        echo >&2
        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
            printf "%s%s (1-%s): %s\n" "$PROMPT_COLOR" "$prompt_text" "$max_num" "$COLOR_RESET" >&2
        else
            printf "%s (1-%s): \n" "$prompt_text" "$max_num" >&2
        fi
        read -r file_num

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

# Specialized function for host file selection from categorized discovery outputs
select_host_file() {
    # Optional filter parameter (e.g., "network_devices")
    filter="$1"

    if [ -n "$NETUTIL_WORKDIR" ]; then
        base_dir="$NETUTIL_WORKDIR/discovery"
    else
        base_dir="$HOME/discovery"
    fi

    # Check if discovery directory exists
    if [ ! -d "$base_dir" ]; then
        echo "Error: Discovery directory $base_dir not found" >&2
        return 1
    fi

    # Clear previous file data
    rm -f /tmp/netutil_files.$$
    file_count=0

    # Find all session directories (standalone + auto_discover).
    # Standalone: main_network_<ts>, vlan<ID>_<ts>, routed_<sanitized>_<ts>
    # Auto-discover: auto_discovery_<ts>
    find "$base_dir" -maxdepth 1 -type d ! -name "." ! -name ".." ! -name "raw" | sort -r > /tmp/netutil_sessions.$$

    # Check if any sessions found
    if [ ! -s /tmp/netutil_sessions.$$ ]; then
        echo "Error: No discovery sessions found in $base_dir" >&2
        rm -f /tmp/netutil_sessions.$$
        return 1
    fi

    # Process each discovery session
    while read -r session_dir; do
        session_name=$(basename "$session_dir")

        # Use session name as the display label (it already contains timestamp)
        display_session="$session_name"

        # Helper: process a hostfiles directory and add its files to the selection list
        # Args: $1=hostfiles_dir $2=display_prefix
        _process_hostfiles_dir() {
            _hf_dir="$1"
            _hf_prefix="$2"

            if [ ! -d "$_hf_dir" ]; then
                return
            fi

            # Apply filter if specified
            if [ -n "$filter" ]; then
                # Match both <filter>_hosts.txt and <filter>.txt naming conventions
                find "$_hf_dir" -maxdepth 1 -type f \( -name "${filter}_hosts.txt" -o -name "${filter}.txt" \) | sort > /tmp/netutil_catfiles.$$
            else
                # Find all categorized host files (exclude enriched and debug files)
                find "$_hf_dir" -maxdepth 1 -type f -name "*.txt" ! -name "*_enriched.txt" | sort > /tmp/netutil_catfiles.$$
            fi

            while read -r host_file; do
                [ -z "$host_file" ] && continue
                category=$(basename "$host_file" .txt)
                display_name="$_hf_prefix/$category"
                file_count=$((file_count + 1))
                echo "$file_count:$host_file:$display_name" >> /tmp/netutil_files.$$
            done < /tmp/netutil_catfiles.$$
            rm -f /tmp/netutil_catfiles.$$
            # Find vendor-specific network device files (cisco, fortinet, etc.)
            # These live flat in hostfiles/ alongside the main category files.
            # Only needed for the filtered network_devices case — unfiltered search
            # already finds all .txt files above.
            if [ "$filter" = "network_devices" ]; then
                find "$_hf_dir" -maxdepth 1 -type f -name "*.txt" \
                    ! -name "*_hosts.txt" \
                    ! -name "*_enriched.txt" \
                    ! -name "all_discovered_hosts.txt" \
                    ! -name "network_devices.txt" \
                    ! -name "unknown.txt" \
                    | sort > /tmp/netutil_vendorfiles.$$

                while read -r vendor_file; do
                    [ -z "$vendor_file" ] && continue
                    vendor=$(basename "$vendor_file" .txt)
                    display_name="$_hf_prefix/$vendor"
                    file_count=$((file_count + 1))
                    echo "$file_count:$vendor_file:$display_name" >> /tmp/netutil_files.$$
                done < /tmp/netutil_vendorfiles.$$
                rm -f /tmp/netutil_vendorfiles.$$
            fi
        }

        # Check if this is an auto_discover session (has subdirectories with hostfiles)
        # or a standalone session (has hostfiles directly)
        if [ -d "$session_dir/hostfiles" ]; then
            # Standalone session: hostfiles is directly in the session directory
            _process_hostfiles_dir "$session_dir/hostfiles" "$display_session"
        else
            # Auto-discover session: find subdirectories containing hostfiles
            # Matches: main_network, vlan_*, and bare numeric directories (L3 mode)
            find "$session_dir" -maxdepth 1 -type d \( -name "main_network" -o -name "vlan_*" -o -name "[0-9]*" \) | sort > /tmp/netutil_networks.$$

            while read -r network_dir; do
                [ -z "$network_dir" ] && continue
                network_name=$(basename "$network_dir")
                hostfiles_dir="$network_dir/hostfiles"

                if [ -d "$hostfiles_dir" ]; then
                    _process_hostfiles_dir "$hostfiles_dir" "$display_session/$network_name"
                fi
            done < /tmp/netutil_networks.$$
            rm -f /tmp/netutil_networks.$$
        fi

    done < /tmp/netutil_sessions.$$

    rm -f /tmp/netutil_sessions.$$

    # Check if any files were found
    if [ ! -f /tmp/netutil_files.$$ ] || [ ! -s /tmp/netutil_files.$$ ]; then
        echo "Error: No categorized host files found in discovery sessions" >&2
        return 1
    fi

    # Display files with compact format
    echo "Available categorized host files:" >&2
    while IFS=':' read -r num filepath display_name; do
        printf "%d. %s\n" "$num" "$display_name" >&2
    done < /tmp/netutil_files.$$
    echo >&2

    # Get max file number for prompt
    max_num=0
    while IFS=':' read -r num filepath display_name; do
        if [ "$num" -gt "$max_num" ]; then
            max_num=$num
        fi
    done < /tmp/netutil_files.$$

    # Prompt user for selection
    while true; do
        echo >&2
        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
            printf "%sSelect host file (1-%s): %s\n" "$PROMPT_COLOR" "$max_num" "$COLOR_RESET" >&2
        else
            printf "Select host file (1-%s): \n" "$max_num" >&2
        fi
        read -r file_num

        # Validate input is a number
        case "$file_num" in
            ''|*[!0-9]*)
                echo "Error: Please enter a number" >&2
                continue
                ;;
        esac

        # Check range
        if [ "$file_num" -lt 1 ] || [ "$file_num" -gt "$max_num" ]; then
            echo "Error: Please enter a number between 1 and $max_num" >&2
            continue
        fi

        # Get selected file path
        selected_file=""
        while IFS=':' read -r num filepath display_name; do
            if [ "$num" = "$file_num" ]; then
                selected_file="$filepath"
                break
            fi
        done < /tmp/netutil_files.$$

        if [ -n "$selected_file" ]; then
            echo "$selected_file"
            rm -f /tmp/netutil_files.$$
            return 0
        else
            echo "Error: Invalid file selection" >&2
        fi
    done
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
    
    # Collect IPv4 addresses only from interfaces that are UP
    # ip -br addr show outputs: NAME STATE IP/...
    ip -br addr show 2>/dev/null | while read -r iface state rest; do
        case "$state" in
            UP|UNKNOWN)
                # UNKNOWN covers interfaces like tailscale0 that are
                # operationally active but report UNKNOWN state
                ;;
            *)
                # Skip DOWN and other inactive states
                continue
                ;;
        esac

        # Skip loopback
        case "$iface" in
            lo) continue ;;
        esac

        # Extract IPv4 addresses from this interface's detailed output
        ip -4 addr show "$iface" 2>/dev/null | while read -r line; do
            case "$line" in
                *inet\ *[0-9]*.[0-9]*.[0-9]*.[0-9]*/[0-9]*)
                    ip_with_prefix=$(echo "$line" | sed -n 's/.*inet \([0-9]*\.[0-9]*\.[0-9]*\.[0-9]*\/[0-9]*\).*/\1/p')
                    if [ -n "$ip_with_prefix" ]; then
                        ip_addr=$(echo "$ip_with_prefix" | cut -d/ -f1)
                        prefix=$(echo "$ip_with_prefix" | cut -d/ -f2)
                        
                        # Skip link-local and loopback addresses
                        case "$ip_addr" in
                            127.*|169.254.*) continue ;;
                        esac
                        
                        # Try to calculate network address via ipcalc
                        if command -v ipcalc >/dev/null 2>&1; then
                            network=$(ipcalc -n "$ip_with_prefix" 2>/dev/null | cut -d= -f2 2>/dev/null)
                            if [ -n "$network" ]; then
                                range_entry="$network/$prefix"
                            else
                                range_entry="$ip_with_prefix"
                            fi
                        else
                            # No ipcalc - use IP/prefix as-is
                            range_entry="$ip_with_prefix"
                        fi
                        
                        # Deduplicate
                        if [ -f /tmp/netutil_ranges.$$ ]; then
                            if ! grep -q "^$range_entry$" /tmp/netutil_ranges.$$ 2>/dev/null; then
                                echo "$range_entry" >> /tmp/netutil_ranges.$$
                            fi
                        else
                            echo "$range_entry" >> /tmp/netutil_ranges.$$
                        fi
                    fi
                    ;;
            esac
        done
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

# Function to filter out special-purpose IP addresses, keeping only valid unicast addresses
# Filters: loopback, link-local, multicast, broadcast, network/broadcast addresses
# Input: IP addresses via stdin (one per line)
# Output: Filtered IP addresses via stdout
filter_valid_unicast_ips() {
    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | \
    grep -v '^0\.' | \
    grep -v '^127\.' | \
    grep -v '^169\.254\.' | \
    grep -v '^224\.' | \
    grep -v '^225\.' | \
    grep -v '^226\.' | \
    grep -v '^227\.' | \
    grep -v '^228\.' | \
    grep -v '^229\.' | \
    grep -v '^23[0-9]\.' | \
    grep -v '^255\.' | \
    grep -v '\.0$' | \
    grep -v '\.255$'
}

# Function to get all local IP addresses from network interfaces
# Returns: List of IP addresses (one per line) assigned to local interfaces
# Output: IP addresses via stdout
get_local_ips() {
    # Use ip command if available (preferred), fallback to hostname -I
    if command -v ip >/dev/null 2>&1; then
        # Extract IPv4 addresses from all interfaces
        ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '^127\.'
    elif command -v hostname >/dev/null 2>&1; then
        # Fallback to hostname -I and filter loopback
        hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | grep -v '^127\.'
    else
        # Last resort: use ifconfig
        ifconfig 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '^127\.'
    fi
}

# Function to filter out local IP addresses from a list
# Input: IP addresses via stdin (one per line)
# Output: Filtered IP addresses (excluding local IPs) via stdout
filter_local_ips() {
    local temp_input
    local temp_local
    local filtered_result

    # Create temporary files for processing
    temp_input=$(mktemp)
    temp_local=$(mktemp)

    # Read stdin to temp file
    cat > "$temp_input"

    # Get local IPs
    get_local_ips > "$temp_local"

    # Filter out local IPs using grep with fixed strings
    if [ -s "$temp_local" ]; then
        grep -vxFf "$temp_local" "$temp_input" || true
    else
        # If no local IPs found, pass through all input
        cat "$temp_input"
    fi

    # Clean up
    rm -f "$temp_input" "$temp_local"
}

# Function for smart target selection with memory
select_target() {
    echo "Target selection:" >&2
    echo "1. Single IP address" >&2
    echo "2. IP range (CIDR)" >&2
    echo "3. Host file" >&2
    echo "4. Auto-detect from network ranges" >&2
    echo "5. Recent targets" >&2
    echo >&2

    while true; do
        echo >&2
        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
            printf "%sSelect target type (1-5): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
        else
            printf "Select target type (1-5): \n" >&2
        fi
        read -r target_type

        case $target_type in
            1)
                echo >&2
                if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
                    printf "%sEnter IP address: %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
                else
                    printf "Enter IP address: \n" >&2
                fi
                read -r target_value
                if validate_ip "$target_value"; then
                    save_target "$target_value"
                    echo "$target_value"
                    return 0
                fi
                ;;
            2)
                echo >&2
                if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
                    printf "%sEnter IP range (e.g., 192.168.1.0/24): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
                else
                    printf "Enter IP range (e.g., 192.168.1.0/24): \n" >&2
                fi
                read -r target_value
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
                echo "Common IP ranges:" >&2
                # Get ranges and store in temp file
                rm -f /tmp/netutil_target_ranges.$$
                rm -f /tmp/netutil_target_ranges_raw.$$
                detect_common_ranges > /tmp/netutil_target_ranges_raw.$$
                range_count=0
                while read -r range; do
                    range_count=$((range_count + 1))
                    echo "$range_count:$range" >> /tmp/netutil_target_ranges.$$
                done < /tmp/netutil_target_ranges_raw.$$
                rm -f /tmp/netutil_target_ranges_raw.$$
                
                # Display ranges
                if [ -f /tmp/netutil_target_ranges.$$ ]; then
                    while IFS=':' read -r num range; do
                        printf "%d. %s\n" "$num" "$range" >&2
                    done < /tmp/netutil_target_ranges.$$
                    echo >&2
                    
                    # Get max range number
                    max_range_num=0
                    while IFS=':' read -r num range; do
                        if [ "$num" -gt "$max_range_num" ]; then
                            max_range_num=$num
                        fi
                    done < /tmp/netutil_target_ranges.$$
                    
                    echo >&2
                    if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
                        printf "%sSelect range (1-%s): %s\n" "$PROMPT_COLOR" "$max_range_num" "$COLOR_RESET" >&2
                    else
                        printf "Select range (1-%s): \n" "$max_range_num" >&2
                    fi
                    read -r range_num
                    
                    # Validate range selection
                    case "$range_num" in
                        ''|*[!0-9]*)
                            echo "Error: Invalid range selection" >&2
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
                                echo "Error: Invalid range selection" >&2
                            fi
                            ;;
                    esac
                    rm -f /tmp/netutil_target_ranges.$$
                fi
                ;;
            5)
                echo "Recent targets:" >&2
                # Get recent targets and store in temp file
                rm -f /tmp/netutil_recent_targets.$$
                rm -f /tmp/netutil_recent_targets_raw.$$
                get_recent_targets > /tmp/netutil_recent_targets_raw.$$
                target_count=0
                while read -r target; do
                    if [ -n "$target" ]; then
                        target_count=$((target_count + 1))
                        echo "$target_count:$target" >> /tmp/netutil_recent_targets.$$
                    fi
                done < /tmp/netutil_recent_targets_raw.$$
                rm -f /tmp/netutil_recent_targets_raw.$$
                
                # Display recent targets
                if [ -f /tmp/netutil_recent_targets.$$ ] && [ -s /tmp/netutil_recent_targets.$$ ]; then
                    while IFS=':' read -r num target; do
                        printf "%d. %s\n" "$num" "$target" >&2
                    done < /tmp/netutil_recent_targets.$$
                    echo >&2
                    
                    # Get max target number
                    max_target_num=0
                    while IFS=':' read -r num target; do
                        if [ "$num" -gt "$max_target_num" ]; then
                            max_target_num=$num
                        fi
                    done < /tmp/netutil_recent_targets.$$
                    
                    echo >&2
                    if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
                        printf "%sSelect target (1-%s): %s\n" "$PROMPT_COLOR" "$max_target_num" "$COLOR_RESET" >&2
                    else
                        printf "Select target (1-%s): \n" "$max_target_num" >&2
                    fi
                    read -r target_num

                    # Validate target selection
                    case "$target_num" in
                        ''|*[!0-9]*)
                            echo "Error: Invalid target selection" >&2
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
                                echo "Error: Invalid target selection" >&2
                            fi
                            ;;
                    esac
                    rm -f /tmp/netutil_recent_targets.$$
                else
                    echo "No recent targets found." >&2
                fi
                ;;
            *)
                echo "Error: Invalid option. Please select 1-5" >&2
                ;;
        esac
    done
}

# Target selection specifically for config gathering
# More focused than select_target() - only specific devices, no ranges
select_config_targets() {
    echo "Target selection for config gathering:" >&2
    echo "1. Single IP address" >&2
    echo "2. Custom host file (manual path)" >&2
    echo "3. Discovered network devices" >&2
    echo "4. Recent targets" >&2
    echo >&2

    while true; do
        echo >&2
        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
            printf "%sSelect target type (1-4): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
        else
            printf "Select target type (1-4): \n" >&2
        fi
        read -r target_type

        case $target_type in
            1)
                # Single IP address
                echo >&2
                if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
                    printf "%sEnter IP address: %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
                else
                    printf "Enter IP address: \n" >&2
                fi
                read -r target_value
                if validate_ip "$target_value"; then
                    save_target "$target_value"
                    echo "$target_value"
                    return 0
                fi
                ;;
            2)
                # Custom host file (manual path)
                echo >&2
                if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
                    printf "%sEnter path to host file: %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
                else
                    printf "Enter path to host file: \n" >&2
                fi
                read -r target_value
                if [ -f "$target_value" ]; then
                    target_value=$(readlink -f "$target_value")
                    save_target "$target_value"
                    echo "-iL $target_value"
                    return 0
                else
                    echo "Error: File not found: $target_value" >&2
                fi
                ;;
            3)
                # Discovered network devices (filtered)
                if target_value=$(select_host_file "network_devices"); then
                    save_target "$target_value"
                    echo "-iL $target_value"
                    return 0
                fi
                ;;
            4)
                # Recent targets
                echo "Recent targets:" >&2
                # Get recent targets and store in temp file
                rm -f /tmp/netutil_recent_targets.$$
                rm -f /tmp/netutil_recent_targets_raw.$$
                get_recent_targets > /tmp/netutil_recent_targets_raw.$$
                target_count=0
                while read -r target; do
                    if [ -n "$target" ]; then
                        target_count=$((target_count + 1))
                        echo "$target_count:$target" >> /tmp/netutil_recent_targets.$$
                    fi
                done < /tmp/netutil_recent_targets_raw.$$
                rm -f /tmp/netutil_recent_targets_raw.$$

                # Display recent targets
                if [ -f /tmp/netutil_recent_targets.$$ ] && [ -s /tmp/netutil_recent_targets.$$ ]; then
                    while IFS=':' read -r num target; do
                        printf "%d. %s\n" "$num" "$target" >&2
                    done < /tmp/netutil_recent_targets.$$
                    echo >&2

                    # Get max target number
                    max_target_num=0
                    while IFS=':' read -r num target; do
                        if [ "$num" -gt "$max_target_num" ]; then
                            max_target_num=$num
                        fi
                    done < /tmp/netutil_recent_targets.$$

                    echo >&2
                    if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
                        printf "%sSelect target (1-%s): %s\n" "$PROMPT_COLOR" "$max_target_num" "$COLOR_RESET" >&2
                    else
                        printf "Select target (1-%s): \n" "$max_target_num" >&2
                    fi
                    read -r target_num

                    # Validate target selection
                    case "$target_num" in
                        ''|*[!0-9]*)
                            echo "Error: Invalid target selection" >&2
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
                                echo "Error: Invalid target selection" >&2
                            fi
                            ;;
                    esac
                    rm -f /tmp/netutil_recent_targets.$$
                else
                    echo "No recent targets found." >&2
                fi
                ;;
            *)
                echo "Error: Invalid option. Please select 1-4" >&2
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
    
    printf "%s" "$message"
    i=1
    while [ $i -le 3 ]; do
        printf "."
        sleep "$delay"
        i=$((i + 1))
    done
    echo >&2
}

# Function to prompt with immediate visibility for Go subprocess environment
prompt_and_read() {
    prompt="$1"
    var_name="$2"
    
    # Force immediate prompt visibility in Go subprocess environment
    echo >&2
    if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
        printf "%s%s%s\n" "$PROMPT_COLOR" "$prompt" "$COLOR_RESET" >&2
    else
        printf "%s\n" "$prompt" >&2
    fi
    read -r value
    
    # Assign to variable name if provided
    if [ -n "$var_name" ]; then
        eval "$var_name='$value'"
    else
        echo "$value"
    fi
}

# Function to confirm action
confirm_action() {
    prompt=$1
    
    echo >&2
    if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
        printf "%s%s (y/N): %s\n" "$PROMPT_COLOR" "$prompt" "$COLOR_RESET" >&2
    else
        printf "%s (y/N): \n" "$prompt" >&2
    fi
    read -r response
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

# Function to get network range for an interface
get_network_range() {
    interface=$1
    
    if [ -z "$interface" ]; then
        return 1
    fi
    
    # Get IP address and CIDR from interface
    ip_info=$(ip addr show "$interface" 2>/dev/null | grep "inet " | head -1 | awk '{print $2}')
    
    if [ -n "$ip_info" ]; then
        # Extract IP and prefix
        ip=$(echo "$ip_info" | cut -d'/' -f1)
        prefix=$(echo "$ip_info" | cut -d'/' -f2)
        
        # Calculate network address using ipcalc with proper output parsing
        if command -v ipcalc >/dev/null 2>&1; then
            # Capture full ipcalc output and parse it properly
            ipcalc_output=$(ipcalc "$ip_info" 2>/dev/null)
            
            # Try to extract network from different possible output formats
            # Format 1: "Network=192.168.1.0/24" or "NETWORK=192.168.1.0"
            network=$(echo "$ipcalc_output" | grep -i "^network" | head -1 | cut -d= -f2 | cut -d'/' -f1 | tr -d ' ')
            
            # Format 2: "Network:   192.168.1.0/24"
            if [ -z "$network" ]; then
                network=$(echo "$ipcalc_output" | grep "^Network:" | head -1 | awk '{print $2}' | cut -d'/' -f1)
            fi
            
            # Validate we got a proper IP address
            if [ -n "$network" ] && echo "$network" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'; then
                echo "$network/$prefix"
                return 0
            fi
        fi
        
        # Fallback method - simple network calculation for common prefixes
        case "$prefix" in
            24)
                # /24 network - zero out last octet
                network=$(echo "$ip" | cut -d'.' -f1-3).0
                echo "$network/24"
                return 0
                ;;
            16)
                # /16 network - zero out last two octets
                network=$(echo "$ip" | cut -d'.' -f1-2).0.0
                echo "$network/16"
                return 0
                ;;
            8)
                # /8 network - zero out last three octets
                network=$(echo "$ip" | cut -d'.' -f1).0.0.0
                echo "$network/8"
                return 0
                ;;
            *)
                # For other prefixes, just return the IP with prefix
                echo "$ip_info"
                return 0
                ;;
        esac
    fi
    
    return 1
}

# Function to prompt for manual network range input
prompt_network_range() {
    echo "Could not automatically determine network range."
    echo "Please enter the network range to scan manually."
    echo >&2
    echo "Examples:"
    echo "  192.168.1.0/24   (Class C network)"
    echo "  10.0.0.0/8       (Class A network)"
    echo "  172.16.0.0/16    (Class B network)"
    echo >&2
    
    while true; do
        echo >&2
        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
            printf "%sEnter network range (CIDR notation): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
        else
            printf "Enter network range (CIDR notation): \n" >&2
        fi
        read -r network_range
        
        if [ -n "$network_range" ] && validate_ip_range "$network_range"; then
            echo "$network_range"
            return 0
        else
            echo "Invalid network range format. Please use CIDR notation (e.g., 192.168.1.0/24)"
        fi
    done
}

# =============================================================================
# WORKSPACE AND SYMLINK MANAGEMENT
# =============================================================================

# Function to update latest symlinks for all result categories
update_latest_links() {
    local category="$1"      # Category: discovery, analysis, vulnerability, reports, captures
    local result_path="$2"   # Full path to the result (file or directory)
    local workdir="${NETUTIL_WORKDIR:-$HOME}"
    
    if [ -z "$category" ] || [ -z "$result_path" ]; then
        echo "Usage: update_latest_links <category> <result_path>" >&2
        return 1
    fi
    
    # Ensure result path exists
    if [ ! -e "$result_path" ]; then
        echo "Warning: Result path does not exist: $result_path" >&2
        return 1
    fi
    
    # Create latest directory if it doesn't exist
    latest_dir="$workdir/latest"
    mkdir -p "$latest_dir" 2>/dev/null || true
    
    # Create category symlink in latest/
    category_link="$latest_dir/$category"
    
    # Remove old symlink if it exists
    [ -L "$category_link" ] && rm -f "$category_link"
    
    # Create new symlink (use relative path for portability)
    if command -v realpath >/dev/null 2>&1; then
        # Use realpath if available for proper relative path calculation
        if cd "$latest_dir" 2>/dev/null; then
            relative_path=$(realpath --relative-to="$latest_dir" "$result_path" 2>/dev/null)
            if [ -n "$relative_path" ]; then
                ln -sf "$relative_path" "$category_link" 2>/dev/null
            else
                # Fallback to absolute path
                ln -sf "$result_path" "$category_link" 2>/dev/null
            fi
            cd - >/dev/null
        fi
    else
        # Simple fallback - use absolute path
        ln -sf "$result_path" "$category_link" 2>/dev/null
    fi
    
    # Verify symlink was created successfully
    if [ -L "$category_link" ]; then
        echo "✓ Latest $category results: $category_link -> $(basename "$result_path")"
        return 0
    else
        echo "⚠ Warning: Failed to create latest symlink for $category" >&2
        return 1
    fi
}

# Function to clean up broken symlinks in latest/ directory
cleanup_latest_links() {
    local workdir="${NETUTIL_WORKDIR:-$HOME}"
    local latest_dir="$workdir/latest"
    
    if [ ! -d "$latest_dir" ]; then
        return 0
    fi
    
    # Find and remove broken symlinks
    find "$latest_dir" -type l ! -exec test -e {} \; -delete 2>/dev/null || true
    
    echo "✓ Cleaned up broken symlinks in $latest_dir"
}

# Function to show current latest results
show_latest_results() {
    local workdir="${NETUTIL_WORKDIR:-$HOME}"
    local latest_dir="$workdir/latest"
    
    if [ ! -d "$latest_dir" ]; then
        echo "No latest results directory found"
        return 1
    fi
    
    echo "=== Latest Results ==="

    # Check each expected category
    for category in discovery analysis scans reports captures; do
        category_link="$latest_dir/$category"
        if [ -L "$category_link" ] && [ -e "$category_link" ]; then
            target=$(readlink "$category_link" 2>/dev/null)
            if [ -n "$target" ]; then
                echo "  $category: $(basename "$target")"
            fi
        else
            echo "  $category: (none)"
        fi
    done

    echo >&2
}

# =============================================================================
# NMAP OUTPUT FILTERING
# =============================================================================

# Filter nmap output to show only important information
# Usage: nmap ... | filter_nmap_output
# Or: filter_nmap_output < nmap_output.txt
filter_nmap_output() {
    awk '
    /^Starting Nmap/ { print; next }
    /^Nmap scan report for/ { print; next }
    /^Host is up/ { print; next }
    /^PORT[[:space:]]+STATE[[:space:]]+SERVICE/ { print; header_printed=1; next }
    header_printed && /^[0-9]+\/(tcp|udp)[[:space:]]+open/ { print; next }
    /^Discovered open port/ { print; next }
    /^Service Info:/ { print; next }
    /^OS details:/ { print; next }
    /^Device type:/ { print; next }
    /^Running:/ { print; next }
    /^OS CPE:/ { print; next }
    /^\|/ { print; next }
    /^Nmap done:/ { print; next }
    /hosts up/ { print; next }
    /WARNING/ { print; next }
    /ERROR/ { print; next }
    /^Failed/ { print; next }
    '
}

# Run nmap with filtered output and progress indicator
# Usage: run_nmap_filtered "target" "description" [extra args...]
run_nmap_filtered() {
    _rnf_target="$1"
    _rnf_description="$2"
    shift 2

    # Source colors if available
    if [ -f "$(dirname "$0")/../common/colors.sh" ]; then
        # shellcheck source=scripts/common/colors.sh
        . "$(dirname "$0")/../common/colors.sh" 2>/dev/null || true
    fi

    if command -v color_info >/dev/null 2>&1; then
        color_info "$_rnf_description"
    else
        echo "$_rnf_description"
    fi

    # Run nmap and filter output
    nmap "$@" "$_rnf_target" 2>&1 | filter_nmap_output

    _rnf_status=$?

    if [ $_rnf_status -eq 0 ]; then
        if command -v color_success >/dev/null 2>&1; then
            color_success "Scan complete"
        else
            echo "✓ Scan complete"
        fi
    else
        if command -v color_error >/dev/null 2>&1; then
            color_error "Scan failed with exit code $_rnf_status"
        else
            echo "✗ Error: Scan failed with exit code $_rnf_status" >&2
        fi
    fi

    return $_rnf_status
}

# Fix ownership of paths to the invoking user when running as root via sudo.
# Silently skips if not root or no sudo context.
# Usage: fix_ownership <path> [<path> ...]
fix_ownership() {
    [ $# -gt 0 ] || return 0
    [ "$(id -u)" -eq 0 ] || return 0
    if [ -n "$SUDO_UID" ] && [ -n "$SUDO_GID" ]; then
        chown -R "$SUDO_UID:$SUDO_GID" "$@" 2>/dev/null || true
    elif [ -n "$SUDO_USER" ]; then
        chown -R "$SUDO_USER:$SUDO_USER" "$@" 2>/dev/null || true
    fi
}
