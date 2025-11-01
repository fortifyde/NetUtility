#!/bin/sh

# NetUtility Progress Indicator Library
# Provides progress display and cancellation support for long-running operations
# POSIX shell compatible - works with bash, zsh, dash, fish

# Source logging functions if not already loaded
if [ -z "$NETUTIL_LOGGING_LOADED" ]; then
    . "$(dirname "$0")/logging.sh"
fi

# =============================================================================
# PROGRESS CONFIGURATION
# =============================================================================

# Progress display settings
PROGRESS_WIDTH=50
PROGRESS_CHAR="="
PROGRESS_EMPTY_CHAR=" "
PROGRESS_BRACKETS="[]"

# Progress state
PROGRESS_CURRENT=0
PROGRESS_TOTAL=0
PROGRESS_MESSAGE=""
PROGRESS_PID=""
PROGRESS_ACTIVE=false

# =============================================================================
# SIGNAL HANDLING FOR CANCELLATION
# =============================================================================

# Function to handle cancellation signals
handle_cancellation() {
    log_info "Operation cancelled by user" "progress"
    PROGRESS_ACTIVE=false
    
    # Kill background process if running
    if [ -n "$PROGRESS_PID" ]; then
        kill "$PROGRESS_PID" 2>/dev/null
        wait "$PROGRESS_PID" 2>/dev/null
    fi
    
    echo
    echo "Operation cancelled."
    exit 130  # Standard exit code for SIGINT
}

# Function to set up cancellation handling
setup_cancellation() {
    trap handle_cancellation INT TERM
    log_debug "Cancellation handler set up" "progress"
}

# =============================================================================
# PROGRESS DISPLAY FUNCTIONS
# =============================================================================

# Function to initialize progress tracking
progress_init() {
    total="$1"
    message="${2:-Processing}"
    
    PROGRESS_TOTAL="$total"
    PROGRESS_CURRENT=0
    PROGRESS_MESSAGE="$message"
    PROGRESS_ACTIVE=true
    
    setup_cancellation
    
    log_info "Progress tracking initialized: $message (0/$total)" "progress"
}

# Function to update progress
progress_update() {
    current="$1"
    message="${2:-$PROGRESS_MESSAGE}"
    
    if [ "$PROGRESS_ACTIVE" != "true" ]; then
        return 1
    fi
    
    PROGRESS_CURRENT="$current"
    if [ -n "$message" ]; then
        PROGRESS_MESSAGE="$message"
    fi
    
    # Calculate percentage
    if [ "$PROGRESS_TOTAL" -gt 0 ]; then
        percentage=$((current * 100 / PROGRESS_TOTAL))
    else
        percentage=0
    fi
    
    # Calculate progress bar width
    filled_width=$((current * PROGRESS_WIDTH / PROGRESS_TOTAL))
    
    # Build progress bar
    progress_bar=""
    i=0
    while [ $i -lt $filled_width ]; do
        progress_bar="${progress_bar}${PROGRESS_CHAR}"
        i=$((i + 1))
    done
    
    while [ $i -lt $PROGRESS_WIDTH ]; do
        progress_bar="${progress_bar}${PROGRESS_EMPTY_CHAR}"
        i=$((i + 1))
    done
    
    # Display progress (overwrite previous line)
    printf "\r%s [%s] %d%% (%d/%d)" "$PROGRESS_MESSAGE" "$progress_bar" "$percentage" "$current" "$PROGRESS_TOTAL"
    
    log_debug "Progress updated: $current/$PROGRESS_TOTAL ($percentage%)" "progress"
}

# Function to complete progress
progress_complete() {
    message="${1:-Complete}"
    
    PROGRESS_CURRENT="$PROGRESS_TOTAL"
    PROGRESS_MESSAGE="$message"
    PROGRESS_ACTIVE=false
    
    # Show final progress
    progress_update "$PROGRESS_TOTAL" "$message"
    echo  # New line after completion
    
    log_info "Progress completed: $message" "progress"
}

# Function to show indeterminate progress (spinner)
progress_spinner() {
    message="${1:-Working}"
    
    PROGRESS_MESSAGE="$message"
    PROGRESS_ACTIVE=true
    setup_cancellation
    
    spinner_chars="/-\\|"
    spinner_pos=0
    
    while [ "$PROGRESS_ACTIVE" = "true" ]; do
        char=$(printf "%s" "$spinner_chars" | cut -c$((spinner_pos + 1)))
        printf "\r%s %s" "$message" "$char"
        
        spinner_pos=$(((spinner_pos + 1) % 4))
        sleep 0.1
        
        # Check if parent process still exists
        if ! kill -0 $$ 2>/dev/null; then
            break
        fi
    done
    
    echo  # New line after spinner
}

# Function to start spinner in background
progress_spinner_start() {
    message="${1:-Working}"
    
    if [ "$PROGRESS_ACTIVE" = "true" ]; then
        progress_spinner_stop
    fi
    
    PROGRESS_ACTIVE=true
    progress_spinner "$message" &
    PROGRESS_PID=$!
    
    log_debug "Spinner started with PID: $PROGRESS_PID" "progress"
}

# Function to stop background spinner
progress_spinner_stop() {
    if [ -n "$PROGRESS_PID" ]; then
        PROGRESS_ACTIVE=false
        kill "$PROGRESS_PID" 2>/dev/null
        wait "$PROGRESS_PID" 2>/dev/null
        PROGRESS_PID=""
        echo  # Clear spinner line
        log_debug "Spinner stopped" "progress"
    fi
}

# =============================================================================
# PROGRESS WITH TIMEOUTS
# =============================================================================

# Function to run command with timeout and progress
progress_with_timeout() {
    command="$1"
    timeout_seconds="$2"
    message="${3:-Running command}"
    
    setup_cancellation
    
    # Start the command in background
    eval "$command" &
    command_pid=$!
    
    # Initialize progress
    progress_init "$timeout_seconds" "$message"
    
    # Monitor progress
    elapsed=0
    while [ $elapsed -lt $timeout_seconds ]; do
        # Check if command is still running
        if ! kill -0 "$command_pid" 2>/dev/null; then
            # Command completed
            wait "$command_pid"
            exit_code=$?
            progress_complete "Command completed"
            return $exit_code
        fi
        
        # Update progress
        progress_update $elapsed
        
        sleep 1
        elapsed=$((elapsed + 1))
    done
    
    # Timeout reached
    log_warn "Command timed out after $timeout_seconds seconds" "progress"
    kill "$command_pid" 2>/dev/null
    wait "$command_pid" 2>/dev/null
    
    echo
    echo "Command timed out after $timeout_seconds seconds"
    return 124  # Standard timeout exit code
}

# =============================================================================
# FILE PROCESSING PROGRESS
# =============================================================================

# Function to process file with progress
progress_process_file() {
    file_path="$1"
    process_function="$2"
    message="${3:-Processing file}"
    
    if [ ! -f "$file_path" ]; then
        log_error "File not found: $file_path" "progress"
        return 1
    fi
    
    # Count total lines
    total_lines=$(wc -l < "$file_path")
    
    if [ "$total_lines" -eq 0 ]; then
        log_warn "File is empty: $file_path" "progress"
        return 0
    fi
    
    # Initialize progress
    progress_init "$total_lines" "$message"
    
    # Process file line by line
    line_number=0
    while IFS= read -r line; do
        if [ "$PROGRESS_ACTIVE" != "true" ]; then
            return 130  # Cancelled
        fi
        
        line_number=$((line_number + 1))
        
        # Call processing function
        if command -v "$process_function" >/dev/null 2>&1; then
            "$process_function" "$line" "$line_number"
        fi
        
        # Update progress every 10 lines or at end
        if [ $((line_number % 10)) -eq 0 ] || [ $line_number -eq $total_lines ]; then
            progress_update $line_number
        fi
    done < "$file_path"
    
    progress_complete "File processed"
    return 0
}

# =============================================================================
# NETWORK OPERATION PROGRESS
# =============================================================================

# Function to monitor network scan progress
progress_network_scan() {
    target="$1"
    scan_type="${2:-basic}"
    
    case "$scan_type" in
        "quick")
            estimated_time=30
            ;;
        "basic")
            estimated_time=120
            ;;
        "comprehensive")
            estimated_time=600
            ;;
        *)
            estimated_time=120
            ;;
    esac
    
    progress_spinner_start "Scanning $target ($scan_type scan)"
    
    # Let the caller handle the actual scan
    # This function just provides the progress indication
}

# Function to monitor packet capture progress
progress_packet_capture() {
    interface="$1"
    duration="$2"
    
    progress_init "$duration" "Capturing packets on $interface"
    
    start_time=$(date +%s)
    while [ "$PROGRESS_ACTIVE" = "true" ]; do
        current_time=$(date +%s)
        elapsed=$((current_time - start_time))
        
        if [ $elapsed -ge $duration ]; then
            progress_complete "Capture complete"
            break
        fi
        
        progress_update $elapsed
        sleep 1
    done
}

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

# Function to estimate operation time
estimate_operation_time() {
    operation="$1"
    target="$2"
    
    case "$operation" in
        "ping_sweep")
            # Estimate based on target range
            echo 60
            ;;
        "port_scan")
            # Estimate based on port range
            echo 300
            ;;
        "nse_scan")
            # NSE scans take longer
            echo 600
            ;;
        "packet_capture")
            # User-specified duration
            echo "${3:-300}"
            ;;
        *)
            echo 120
            ;;
    esac
}

# Function to format time duration
format_duration() {
    seconds="$1"
    
    if [ $seconds -lt 60 ]; then
        echo "${seconds}s"
    elif [ $seconds -lt 3600 ]; then
        minutes=$((seconds / 60))
        remaining_seconds=$((seconds % 60))
        echo "${minutes}m${remaining_seconds}s"
    else
        hours=$((seconds / 3600))
        remaining_minutes=$(((seconds % 3600) / 60))
        echo "${hours}h${remaining_minutes}m"
    fi
}

# Function to show operation summary
show_operation_summary() {
    operation="$1"
    start_time="$2"
    end_time="$3"
    
    duration=$((end_time - start_time))
    formatted_duration=$(format_duration $duration)
    
    echo
    echo "=== Operation Summary ==="
    echo "Operation: $operation"
    echo "Duration: $formatted_duration"
    echo "Completed: $(date)"
    
    log_info "Operation summary: $operation completed in $formatted_duration" "progress"
}

# =============================================================================
# INITIALIZATION
# =============================================================================

# Set up signal handlers on script load
setup_cancellation() {
    trap handle_cancellation INT TERM
}

log_debug "Progress library loaded" "progress"