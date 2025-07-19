#!/bin/sh

# NetUtility Input Validation Library
# Provides secure input validation functions to prevent injection attacks
# POSIX shell compatible - works with bash, zsh, dash, fish

# Source logging functions if not already loaded
if [ -z "$NETUTIL_LOGGING_LOADED" ]; then
    . "$(dirname "$0")/logging.sh"
fi

# =============================================================================
# BASIC VALIDATION FUNCTIONS
# =============================================================================

# Function to validate if input contains only alphanumeric characters and allowed special chars
validate_safe_input() {
    input="$1"
    allowed_chars="$2"  # Optional: additional allowed characters
    field_name="${3:-input}"
    
    if [ -z "$input" ]; then
        log_error "Empty $field_name provided" "validation"
        return 1
    fi
    
    # Basic alphanumeric + common safe characters
    safe_pattern="[A-Za-z0-9._-]"
    
    # Add allowed characters if specified
    if [ -n "$allowed_chars" ]; then
        safe_pattern="[A-Za-z0-9._-$allowed_chars]"
    fi
    
    # Check if input contains only safe characters
    case "$input" in
        *[!A-Za-z0-9._-]*) 
            if [ -n "$allowed_chars" ]; then
                # More complex validation needed - use grep
                if ! echo "$input" | grep -q "^${safe_pattern}*$"; then
                    log_error "Invalid characters in $field_name: $input" "validation"
                    return 1
                fi
            else
                log_error "Invalid characters in $field_name: $input" "validation"
                return 1
            fi
            ;;
    esac
    
    log_debug "Input validation passed for $field_name: $input" "validation"
    return 0
}

# Function to validate and sanitize file paths
validate_file_path() {
    path="$1"
    allow_create="${2:-false}"  # Whether to allow non-existent files
    
    if [ -z "$path" ]; then
        log_error "Empty file path provided" "validation"
        return 1
    fi
    
    # Check for dangerous patterns
    case "$path" in
        *../*|*/../*|../*|*/..)
            log_error "Path traversal detected: $path" "validation"
            return 1
            ;;
        *\;*|*\&*|*\|*|*\`*|*\$*|*\(*|*\)*)
            log_error "Dangerous characters in path: $path" "validation"
            return 1
            ;;
    esac
    
    # Check if file exists (unless we're allowing creation)
    if [ "$allow_create" != "true" ] && [ ! -e "$path" ]; then
        log_error "File does not exist: $path" "validation"
        return 1
    fi
    
    # Check if parent directory exists for new files
    if [ "$allow_create" = "true" ] && [ ! -e "$path" ]; then
        parent_dir=$(dirname "$path")
        if [ ! -d "$parent_dir" ]; then
            log_error "Parent directory does not exist: $parent_dir" "validation"
            return 1
        fi
    fi
    
    log_debug "File path validation passed: $path" "validation"
    return 0
}

# =============================================================================
# NETWORK VALIDATION FUNCTIONS
# =============================================================================

# Function to validate IP address format
validate_ip_address() {
    ip="$1"
    
    if [ -z "$ip" ]; then
        log_error "Empty IP address provided" "validation"
        return 1
    fi
    
    # Basic IPv4 format check
    case "$ip" in
        [0-9]*.[0-9]*.[0-9]*.[0-9]*)
            # More detailed validation
            ;;
        *)
            log_error "Invalid IP address format: $ip" "validation"
            return 1
            ;;
    esac
    
    # Split IP into octets and validate each
    octet1=$(echo "$ip" | cut -d. -f1)
    octet2=$(echo "$ip" | cut -d. -f2)
    octet3=$(echo "$ip" | cut -d. -f3)
    octet4=$(echo "$ip" | cut -d. -f4)
    
    # Validate each octet
    for octet in "$octet1" "$octet2" "$octet3" "$octet4"; do
        case "$octet" in
            ''|*[!0-9]*)
                log_error "Invalid IP octet: $octet in $ip" "validation"
                return 1
                ;;
            *)
                if [ "$octet" -lt 0 ] || [ "$octet" -gt 255 ]; then
                    log_error "IP octet out of range: $octet in $ip" "validation"
                    return 1
                fi
                ;;
        esac
    done
    
    log_debug "IP address validation passed: $ip" "validation"
    return 0
}

# Function to validate IP range in CIDR notation
validate_ip_range() {
    range="$1"
    
    if [ -z "$range" ]; then
        log_error "Empty IP range provided" "validation"
        return 1
    fi
    
    # Check CIDR format
    case "$range" in
        [0-9]*.[0-9]*.[0-9]*.[0-9]*/[0-9]*)
            ip=$(echo "$range" | cut -d/ -f1)
            prefix=$(echo "$range" | cut -d/ -f2)
            ;;
        *)
            log_error "Invalid IP range format: $range" "validation"
            return 1
            ;;
    esac
    
    # Validate IP part
    if ! validate_ip_address "$ip"; then
        return 1
    fi
    
    # Validate prefix length
    case "$prefix" in
        ''|*[!0-9]*)
            log_error "Invalid prefix length: $prefix in $range" "validation"
            return 1
            ;;
        *)
            if [ "$prefix" -lt 1 ] || [ "$prefix" -gt 32 ]; then
                log_error "Prefix length out of range: $prefix in $range" "validation"
                return 1
            fi
            ;;
    esac
    
    log_debug "IP range validation passed: $range" "validation"
    return 0
}

# Function to validate port number
validate_port() {
    port="$1"
    
    if [ -z "$port" ]; then
        log_error "Empty port number provided" "validation"
        return 1
    fi
    
    case "$port" in
        ''|*[!0-9]*)
            log_error "Invalid port number: $port" "validation"
            return 1
            ;;
        *)
            if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
                log_error "Port number out of range: $port" "validation"
                return 1
            fi
            ;;
    esac
    
    log_debug "Port validation passed: $port" "validation"
    return 0
}

# Function to validate port range
validate_port_range() {
    range="$1"
    
    if [ -z "$range" ]; then
        log_error "Empty port range provided" "validation"
        return 1
    fi
    
    # Handle different port range formats
    case "$range" in
        [0-9]*-[0-9]*)
            # Range format: 80-443
            start_port=$(echo "$range" | cut -d- -f1)
            end_port=$(echo "$range" | cut -d- -f2)
            
            if ! validate_port "$start_port" || ! validate_port "$end_port"; then
                return 1
            fi
            
            if [ "$start_port" -gt "$end_port" ]; then
                log_error "Invalid port range: start port $start_port > end port $end_port" "validation"
                return 1
            fi
            ;;
        [0-9]*,[0-9]*)
            # Comma-separated format: 80,443,8080
            for port in $(echo "$range" | tr ',' ' '); do
                if ! validate_port "$port"; then
                    return 1
                fi
            done
            ;;
        [0-9]*)
            # Single port
            if ! validate_port "$range"; then
                return 1
            fi
            ;;
        *)
            log_error "Invalid port range format: $range" "validation"
            return 1
            ;;
    esac
    
    log_debug "Port range validation passed: $range" "validation"
    return 0
}

# Function to validate interface name
validate_interface() {
    interface="$1"
    
    if [ -z "$interface" ]; then
        log_error "Empty interface name provided" "validation"
        return 1
    fi
    
    # Check for valid interface name pattern
    case "$interface" in
        *[!A-Za-z0-9._-]*)
            log_error "Invalid interface name: $interface" "validation"
            return 1
            ;;
    esac
    
    # Check if interface exists
    if ! ip link show "$interface" >/dev/null 2>&1; then
        log_error "Interface does not exist: $interface" "validation"
        return 1
    fi
    
    log_debug "Interface validation passed: $interface" "validation"
    return 0
}

# Function to validate VLAN ID
validate_vlan_id() {
    vlan_id="$1"
    
    if [ -z "$vlan_id" ]; then
        log_error "Empty VLAN ID provided" "validation"
        return 1
    fi
    
    case "$vlan_id" in
        ''|*[!0-9]*)
            log_error "Invalid VLAN ID: $vlan_id" "validation"
            return 1
            ;;
        *)
            if [ "$vlan_id" -lt 1 ] || [ "$vlan_id" -gt 4094 ]; then
                log_error "VLAN ID out of range: $vlan_id" "validation"
                return 1
            fi
            ;;
    esac
    
    log_debug "VLAN ID validation passed: $vlan_id" "validation"
    return 0
}

# =============================================================================
# TIME AND DURATION VALIDATION
# =============================================================================

# Function to validate duration in seconds
validate_duration() {
    duration="$1"
    max_duration="${2:-86400}"  # Default max: 24 hours
    
    if [ -z "$duration" ]; then
        log_error "Empty duration provided" "validation"
        return 1
    fi
    
    case "$duration" in
        ''|*[!0-9]*)
            log_error "Invalid duration: $duration" "validation"
            return 1
            ;;
        *)
            if [ "$duration" -lt 1 ] || [ "$duration" -gt "$max_duration" ]; then
                log_error "Duration out of range: $duration (max: $max_duration)" "validation"
                return 1
            fi
            ;;
    esac
    
    log_debug "Duration validation passed: $duration seconds" "validation"
    return 0
}

# =============================================================================
# CHOICE VALIDATION FUNCTIONS
# =============================================================================

# Function to validate choice from a list
validate_choice() {
    choice="$1"
    valid_choices="$2"  # Space-separated list of valid choices
    field_name="${3:-choice}"
    
    if [ -z "$choice" ]; then
        log_error "Empty $field_name provided" "validation"
        return 1
    fi
    
    # Check if choice is in valid list
    for valid_choice in $valid_choices; do
        if [ "$choice" = "$valid_choice" ]; then
            log_debug "Choice validation passed: $choice" "validation"
            return 0
        fi
    done
    
    log_error "Invalid $field_name: $choice (valid: $valid_choices)" "validation"
    return 1
}

# Function to validate numeric choice within range
validate_numeric_choice() {
    choice="$1"
    min_value="$2"
    max_value="$3"
    field_name="${4:-choice}"
    
    if [ -z "$choice" ]; then
        log_error "Empty $field_name provided" "validation"
        return 1
    fi
    
    case "$choice" in
        ''|*[!0-9]*)
            log_error "Invalid $field_name: $choice (must be numeric)" "validation"
            return 1
            ;;
        *)
            if [ "$choice" -lt "$min_value" ] || [ "$choice" -gt "$max_value" ]; then
                log_error "$field_name out of range: $choice (valid: $min_value-$max_value)" "validation"
                return 1
            fi
            ;;
    esac
    
    log_debug "Numeric choice validation passed: $choice" "validation"
    return 0
}

# =============================================================================
# SANITIZATION FUNCTIONS
# =============================================================================

# Function to sanitize input for safe use in commands
sanitize_input() {
    input="$1"
    
    # Remove dangerous characters
    sanitized=$(echo "$input" | tr -d ';<>&|`$()[]{}*?')
    
    # Trim whitespace
    sanitized=$(echo "$sanitized" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    
    echo "$sanitized"
}

# Function to escape input for safe shell usage
escape_shell_input() {
    input="$1"
    
    # Single quote the input and escape any single quotes within
    escaped=$(printf '%s\n' "$input" | sed "s/'/'\\\\''/g")
    echo "'$escaped'"
}

# =============================================================================
# COMPOUND VALIDATION FUNCTIONS
# =============================================================================

# Function to validate and prompt for safe input
prompt_and_validate() {
    prompt_text="$1"
    validation_function="$2"
    max_attempts="${3:-3}"
    
    attempts=0
    while [ $attempts -lt $max_attempts ]; do
        printf "%s: " "$prompt_text" >&2
        read user_input
        
        if $validation_function "$user_input"; then
            echo "$user_input"
            return 0
        fi
        
        attempts=$((attempts + 1))
        if [ $attempts -lt $max_attempts ]; then
            echo "Please try again ($((max_attempts - attempts)) attempts remaining)..." >&2
        fi
    done
    
    log_error "Maximum validation attempts exceeded for: $prompt_text" "validation"
    return 1
}

# Function to validate target specification (IP, range, or file)
validate_target() {
    target="$1"
    
    if [ -z "$target" ]; then
        log_error "Empty target provided" "validation"
        return 1
    fi
    
    # Check if it's a file input (starts with -iL)
    case "$target" in
        -iL\ *)
            file_path=$(echo "$target" | cut -d' ' -f2-)
            validate_file_path "$file_path"
            return $?
            ;;
        *)
            # Try IP address first
            if validate_ip_address "$target" 2>/dev/null; then
                return 0
            fi
            
            # Try IP range
            if validate_ip_range "$target" 2>/dev/null; then
                return 0
            fi
            
            log_error "Invalid target format: $target" "validation"
            return 1
            ;;
    esac
}

# =============================================================================
# SECURITY VALIDATION FUNCTIONS
# =============================================================================

# Function to check for command injection attempts
detect_command_injection() {
    input="$1"
    field_name="${2:-input}"
    
    # List of dangerous patterns
    dangerous_patterns="; & | \` \$ ( ) [ ] { } < > * ?"
    
    for pattern in $dangerous_patterns; do
        case "$input" in
            *$pattern*)
                log_security_event "Command injection attempt detected" "Field: $field_name, Input: $input, Pattern: $pattern"
                return 1
                ;;
        esac
    done
    
    return 0
}

# Function to validate that input doesn't contain path traversal
detect_path_traversal() {
    input="$1"
    field_name="${2:-input}"
    
    case "$input" in
        *../*|*/../*|../*|*/..)
            log_security_event "Path traversal attempt detected" "Field: $field_name, Input: $input"
            return 1
            ;;
    esac
    
    return 0
}

# Function to perform comprehensive security validation
security_validate() {
    input="$1"
    field_name="${2:-input}"
    
    if ! detect_command_injection "$input" "$field_name"; then
        return 1
    fi
    
    if ! detect_path_traversal "$input" "$field_name"; then
        return 1
    fi
    
    log_debug "Security validation passed for $field_name" "validation"
    return 0
}