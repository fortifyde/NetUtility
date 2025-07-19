#!/bin/sh

# Centralized Logging System for NetUtility
# Provides consistent logging across all NetUtility scripts

# Log levels
LOG_LEVEL_DEBUG=0
LOG_LEVEL_INFO=1
LOG_LEVEL_WARN=2
LOG_LEVEL_ERROR=3
LOG_LEVEL_FATAL=4

# Default log level (INFO)
NETUTIL_LOG_LEVEL=${NETUTIL_LOG_LEVEL:-$LOG_LEVEL_INFO}

# Log directory
LOG_DIR="${NETUTIL_WORKDIR:-$HOME}/logs"
LOG_FILE="$LOG_DIR/netutil.log"

# Ensure log directory exists
mkdir -p "$LOG_DIR"

# Function to get log level name
get_log_level_name() {
    case "$1" in
        $LOG_LEVEL_DEBUG) echo "DEBUG" ;;
        $LOG_LEVEL_INFO)  echo "INFO" ;;
        $LOG_LEVEL_WARN)  echo "WARN" ;;
        $LOG_LEVEL_ERROR) echo "ERROR" ;;
        $LOG_LEVEL_FATAL) echo "FATAL" ;;
        *)                echo "UNKNOWN" ;;
    esac
}

# Core logging function
log_message() {
    level="$1"
    message="$2"
    script_name="${3:-$(basename "$0")}"
    
    # Check if message should be logged based on log level
    if [ "$level" -lt "$NETUTIL_LOG_LEVEL" ]; then
        return 0
    fi
    
    # Format: YYYY-MM-DD HH:MM:SS [LEVEL] [SCRIPT] MESSAGE
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    level_name=$(get_log_level_name "$level")
    
    # Log to file
    echo "$timestamp [$level_name] [$script_name] $message" >> "$LOG_FILE"
    
    # Also output to console for WARN, ERROR, and FATAL
    if [ "$level" -ge "$LOG_LEVEL_WARN" ]; then
        echo "$timestamp [$level_name] $message" >&2
    fi
}

# Convenience functions for different log levels
log_debug() {
    log_message "$LOG_LEVEL_DEBUG" "$1" "$2"
}

log_info() {
    log_message "$LOG_LEVEL_INFO" "$1" "$2"
}

log_warn() {
    log_message "$LOG_LEVEL_WARN" "$1" "$2"
}

log_error() {
    log_message "$LOG_LEVEL_ERROR" "$1" "$2"
}

log_fatal() {
    log_message "$LOG_LEVEL_FATAL" "$1" "$2"
}

# Function to log script start
log_script_start() {
    script_name="${1:-$(basename "$0")}"
    log_info "=== Script started: $script_name ===" "$script_name"
    log_info "Command line: $*" "$script_name"
    log_info "Working directory: $(pwd)" "$script_name"
    log_info "User: $(whoami)" "$script_name"
}

# Function to log script end
log_script_end() {
    script_name="${1:-$(basename "$0")}"
    exit_code="${2:-0}"
    log_info "=== Script ended: $script_name (exit code: $exit_code) ===" "$script_name"
}

# Function to log command execution
log_command() {
    command="$1"
    script_name="${2:-$(basename "$0")}"
    log_debug "Executing command: $command" "$script_name"
}

# Function to log command result
log_command_result() {
    command="$1"
    exit_code="$2"
    script_name="${3:-$(basename "$0")}"
    if [ "$exit_code" -eq 0 ]; then
        log_debug "Command succeeded: $command" "$script_name"
    else
        log_error "Command failed (exit code $exit_code): $command" "$script_name"
    fi
}

# Function to log network operations
log_network_operation() {
    operation="$1"
    target="$2"
    result="$3"
    script_name="${4:-$(basename "$0")}"
    log_info "Network operation: $operation on $target - $result" "$script_name"
}

# Function to log security events
log_security_event() {
    event="$1"
    details="$2"
    script_name="${3:-$(basename "$0")}"
    log_warn "Security event: $event - $details" "$script_name"
}

# Function to log configuration changes
log_config_change() {
    change_type="$1"
    details="$2"
    script_name="${3:-$(basename "$0")}"
    log_info "Configuration change: $change_type - $details" "$script_name"
}

# Function to rotate log files
rotate_logs() {
    if [ -f "$LOG_FILE" ]; then
        log_size=$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)
        max_size=10485760  # 10MB
        
        if [ "$log_size" -gt "$max_size" ]; then
            timestamp=$(date '+%Y%m%d_%H%M%S')
            mv "$LOG_FILE" "${LOG_FILE}.${timestamp}"
            log_info "Log file rotated: ${LOG_FILE}.${timestamp}"
            
            # Keep only last 5 log files
            ls -t "${LOG_FILE}."* 2>/dev/null | tail -n +6 | while read -r old_log; do
                rm -f "$old_log"
                log_info "Removed old log file: $old_log"
            done
        fi
    fi
}

# Function to get log statistics
get_log_stats() {
    if [ -f "$LOG_FILE" ]; then
        echo "=== NetUtility Log Statistics ==="
        echo "Log file: $LOG_FILE"
        echo "Log file size: $(du -h "$LOG_FILE" | cut -f1)"
        echo "Total log entries: $(wc -l < "$LOG_FILE")"
        echo "Recent activity:"
        echo "  INFO entries: $(grep -c "\\[INFO\\]" "$LOG_FILE")"
        echo "  WARN entries: $(grep -c "\\[WARN\\]" "$LOG_FILE")"
        echo "  ERROR entries: $(grep -c "\\[ERROR\\]" "$LOG_FILE")"
        echo "  FATAL entries: $(grep -c "\\[FATAL\\]" "$LOG_FILE")"
        echo
        echo "Last 10 entries:"
        tail -10 "$LOG_FILE"
    else
        echo "No log file found at $LOG_FILE"
    fi
}

# Function to search logs
search_logs() {
    pattern="$1"
    context="${2:-0}"
    
    if [ -f "$LOG_FILE" ]; then
        echo "=== Search Results for: $pattern ==="
        if [ "$context" -gt 0 ]; then
            grep -C "$context" "$pattern" "$LOG_FILE"
        else
            grep "$pattern" "$LOG_FILE"
        fi
    else
        echo "No log file found at $LOG_FILE"
    fi
}

# Function to clear logs
clear_logs() {
    if [ -f "$LOG_FILE" ]; then
        log_info "Log file cleared by user request"
        > "$LOG_FILE"
        echo "Log file cleared: $LOG_FILE"
    else
        echo "No log file to clear"
    fi
}

# Initialize logging system
init_logging() {
    # Rotate logs if needed
    rotate_logs
    
    # Set script name if not provided
    if [ -z "$NETUTIL_SCRIPT_NAME" ]; then
        NETUTIL_SCRIPT_NAME=$(basename "$0")
    fi
    
    # Log system initialization
    log_info "NetUtility logging system initialized" "logging.sh"
    log_info "Log level: $(get_log_level_name "$NETUTIL_LOG_LEVEL")" "logging.sh"
    log_info "Log directory: $LOG_DIR" "logging.sh"
}

# Set loaded marker
NETUTIL_LOGGING_LOADED=1

# Auto-initialize if sourced
if [ "${0##*/}" != "logging.sh" ]; then
    init_logging
fi