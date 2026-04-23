#!/bin/sh

# Web Screenshot Capture Script
# Captures screenshots of web services using gowitness
# Supports discovery sessions and custom target sources

. "$(dirname "$0")/../common/utils.sh" 2>/dev/null || true
. "$(dirname "$0")/../common/colors.sh" 2>/dev/null || true
. "$(dirname "$0")/../common/logging.sh"

SCRIPT_NAME="$(basename "$0")"

echo "==========================================" >&2
echo "Web Screenshot Capture" >&2
echo "==========================================" >&2
log_info "=== Script started ===" "$SCRIPT_NAME"
echo >&2

echo "This script captures screenshots of web services using gowitness:" >&2
echo "  - Scans discovery sessions for web targets" >&2
echo "  - Supports custom target files and URLs" >&2
echo "  - Generates timestamped screenshot collections" >&2
echo "  - Outputs structured screenshot markers for correlation" >&2
echo >&2

# Check for gowitness dependency
if ! command -v gowitness >/dev/null 2>&1; then
    log_error "gowitness not found" "$SCRIPT_NAME"
    error_message "gowitness is required but not installed. Install with: go install github.com/sensepost/gowitness@latest"
    exit 1
fi

# Setup results directory
RESULTS_BASE="${NETUTIL_WORKDIR:-$HOME}/captures/screenshots"
mkdir -p "$RESULTS_BASE"

# Create timestamped session directory
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SESSION_DIR="$RESULTS_BASE/$TIMESTAMP"
mkdir -p "$SESSION_DIR"

# Target source selection
echo "Target source:" >&2
echo "1. All discovery sessions (default)" >&2
echo "2. Specific discovery session" >&2
echo "3. Custom target file" >&2
echo "4. Single URL" >&2
echo >&2

if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
    printf "%sSelect target source (1-4, default=1): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
else
    printf "Select target source (1-4, default=1): \n" >&2
fi
read -r target_source

# Default to '1' if empty
target_source="${target_source:-1}"

URL_LIST_FILE=""
SESSION_NAME=""

case $target_source in
    1)
        # All discovery sessions
        log_info "Scanning all discovery sessions for web targets" "$SCRIPT_NAME"
        SESSION_NAME="all_sessions"
        ;;
    2)
        # Specific session
        echo >&2
        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
            printf "%sEnter discovery session name (e.g., main_network_20250120_120000): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
        else
            printf "Enter discovery session name (e.g., main_network_20250120_120000): \n" >&2
        fi
        read -r session_name
        if [ -z "$session_name" ]; then
            log_error "No session name provided" "$SCRIPT_NAME"
            error_message "Session name is required"
            exit 1
        fi
        SESSION_NAME="$session_name"
        log_info "Using specific discovery session: $SESSION_NAME" "$SCRIPT_NAME"
        ;;
    3)
        # Custom target file
        echo >&2
        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
            printf "%sEnter path to target file (one URL/IP per line): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
        else
            printf "Enter path to target file (one URL/IP per line): \n" >&2
        fi
        read -r target_file
        if [ -z "$target_file" ] || [ ! -f "$target_file" ]; then
            log_error "Invalid or missing target file: $target_file" "$SCRIPT_NAME"
            error_message "Target file not found or not specified"
            exit 1
        fi
        URL_LIST_FILE="$target_file"
        SESSION_NAME="custom_file"
        log_info "Using custom target file: $URL_LIST_FILE" "$SCRIPT_NAME"
        ;;
    4)
        # Single URL
        echo >&2
        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
            printf "%sEnter URL (e.g., http://192.168.1.1 or https://example.com): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
        else
            printf "Enter URL (e.g., http://192.168.1.1 or https://example.com): \n" >&2
        fi
        read -r single_url
        if [ -z "$single_url" ]; then
            log_error "No URL provided" "$SCRIPT_NAME"
            error_message "URL is required"
            exit 1
        fi
        SINGLE_URL="$single_url"
        SESSION_NAME="single_url"
        log_info "Using single URL: $SINGLE_URL" "$SCRIPT_NAME"
        ;;
    *)
        warning_message "Invalid option, using all discovery sessions"
        log_info "Invalid option, defaulting to all discovery sessions" "$SCRIPT_NAME"
        SESSION_NAME="all_sessions"
        ;;
esac

success_message "Target source: $SESSION_NAME" >&2
echo >&2

# Build URL list
TEMP_URL_LIST=$(mktemp)
trap 'rm -f "$TEMP_URL_LIST"' EXIT

build_url_list() {
    _session_filter="$1"
    _target_file="$2"
    _single_url="$3"

    if [ -n "$_single_url" ]; then
        # Single URL mode
        echo "$_single_url" > "$TEMP_URL_LIST"
        log_info "Added single URL: $_single_url" "$SCRIPT_NAME"
        return
    fi

    if [ -n "$_target_file" ]; then
        # Custom file mode - use entries as-is
        while IFS= read -r line || [ -n "$line" ]; do
            # Skip empty lines and comments
            _line=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sed 's/#.*$//')
            if [ -n "$_line" ]; then
                echo "$_line" >> "$TEMP_URL_LIST"
                log_debug "Added URL from file: $_line" "$SCRIPT_NAME"
            fi
        done < "$_target_file"
        return
    fi

    # Discovery session mode - scan for web_targets.txt files
    _discovery_dir="${NETUTIL_WORKDIR:-$HOME}/discovery"

    if [ ! -d "$_discovery_dir" ]; then
        log_warning "Discovery directory not found: $_discovery_dir" "$SCRIPT_NAME"
        return
    fi

    # Find all web_targets.txt files recursively.
    # This handles both 1-level (standalone sessions) and 2-level (auto-discovery) nesting.
    # Write results to a temp file so the while loop runs in the current shell,
    # keeping file writes to TEMP_URL_LIST visible after the loop.
    _find_tmp=$(mktemp)
    find "$_discovery_dir" -name "web_targets.txt" -type f 2>/dev/null > "$_find_tmp"

    if [ ! -s "$_find_tmp" ]; then
        log_warning "No web_targets.txt files found in discovery directory" "$SCRIPT_NAME"
        rm -f "$_find_tmp"
        return
    fi

    # Process each web_targets.txt file
    while IFS= read -r _web_file; do
        # Check if we should filter by session
        if [ "$_session_filter" != "all_sessions" ]; then
            # Check if this file belongs to the specified session
            _file_path=$(dirname "$_web_file")
            case "$_file_path" in
                *"$_session_filter"*|*"$_session_filter"/*)
                    # File belongs to the session or its sub-sessions
                    ;;
                *)
                    # Skip this file
                    continue
                    ;;
            esac
        fi

        log_debug "Processing web targets file: $_web_file" "$SCRIPT_NAME"

        # Read IPs from web_targets.txt
        while IFS= read -r _ip || [ -n "$_ip" ]; do
            # Skip empty lines and comments
            _ip=$(echo "$_ip" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sed 's/#.*$//')
            if [ -z "$_ip" ]; then
                continue
            fi

            # Skip if not an IP address (basic validation)
            if ! echo "$_ip" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'; then
                log_debug "Skipping non-IP entry: $_ip" "$SCRIPT_NAME"
                continue
            fi

            # Add standard HTTP and HTTPS URLs
            echo "http://$_ip" >> "$TEMP_URL_LIST"
            echo "https://$_ip" >> "$TEMP_URL_LIST"

            # Check enriched web targets file for alternative web ports.
            # Format: IP:PORT HOSTNAME VERSION OS [FLAGS]
            _service_targets_dir=$(dirname "$_web_file")
            _enriched_file="$_service_targets_dir/web_targets_enriched.txt"

            if [ -f "$_enriched_file" ]; then
                # Look for common non-standard web ports in enriched data
                _web_ports="8080 8443 8000 8888 3000 9090"
                for _port in $_web_ports; do
                    if grep -q "^${_ip}:${_port}[[:space:]]" "$_enriched_file" 2>/dev/null; then
                        echo "http://${_ip}:${_port}" >> "$TEMP_URL_LIST"
                        echo "https://${_ip}:${_port}" >> "$TEMP_URL_LIST"
                        log_debug "Added web port $_port for $_ip" "$SCRIPT_NAME"
                    fi
                done
            fi

        done < "$_web_file"
    done < "$_find_tmp"

    rm -f "$_find_tmp"
}

# Build the URL list
case $target_source in
    1)
        build_url_list "all_sessions" "" ""
        ;;
    2)
        build_url_list "$SESSION_NAME" "" ""
        ;;
    3)
        build_url_list "" "$URL_LIST_FILE" ""
        ;;
    4)
        build_url_list "" "" "$SINGLE_URL"
        ;;
esac

# Check if we have any URLs to process
_url_count=$(wc -l < "$TEMP_URL_LIST" 2>/dev/null || echo "0")
if [ "$_url_count" -eq 0 ]; then
    log_error "No URLs found to process" "$SCRIPT_NAME"
    error_message "No web targets found. Run discovery scripts first or provide valid targets."
    exit 1
fi

success_message "Found $_url_count URLs to screenshot" >&2
echo >&2

# Deduplicate URLs
sort -u "$TEMP_URL_LIST" > "${TEMP_URL_LIST}.sorted"
mv "${TEMP_URL_LIST}.sorted" "$TEMP_URL_LIST"
_dedup_count=$(wc -l < "$TEMP_URL_LIST" 2>/dev/null || echo "0")

if [ "$_dedup_count" -lt "$_url_count" ]; then
    log_info "Deduplicated URLs: $_url_count → $_dedup_count" "$SCRIPT_NAME"
fi
emit_progress "Starting web screenshot capture ($_dedup_count URLs)" "0" "$_dedup_count"

# Display scan information
echo "Session directory: $SESSION_DIR" >&2
echo "URLs to screenshot: $_dedup_count" >&2
echo "Starting gowitness screenshot capture..." >&2
echo "Command: gowitness scan file -f $TEMP_URL_LIST -s $SESSION_DIR --threads 4 --timeout 30" >&2
echo >&2

# Run gowitness in background to capture PID for progress polling
# Note: gowitness file creates a JSONL file with screenshot results
log_debug "Executing: gowitness scan file -f $TEMP_URL_LIST -s $SESSION_DIR --threads 4 --timeout 30 --write-jsonl --write-jsonl-file $SESSION_DIR/gowitness.jsonl --http-code-filter 200" "$SCRIPT_NAME"

gowitness scan file -f "$TEMP_URL_LIST" \
    -s "$SESSION_DIR" \
    --threads 4 \
    --timeout 30 \
    --write-jsonl \
    --write-jsonl-file "$SESSION_DIR/gowitness.jsonl" \
    --http-code-filter 200 > "$SESSION_DIR/gowitness_output.txt" 2>&1 &
_GOWITNESS_PID=$!

# Background progress poller for TUI status bar
(
    _p_total=$_dedup_count
    _p_last=0
    sleep 3
    while [ ! -f "$SESSION_DIR/gowitness.jsonl" ] && kill -0 $_GOWITNESS_PID 2>/dev/null; do
        sleep 1
    done
    while kill -0 $_GOWITNESS_PID 2>/dev/null; do
        _p_done=$(grep -c '"file_name"' "$SESSION_DIR/gowitness.jsonl" 2>/dev/null || echo 0)
        if [ "$_p_done" -ne "$_p_last" ]; then
            emit_progress "Capturing web screenshots" "$_p_done" "$_p_total"
            _p_last=$_p_done
        fi
        sleep 2
    done
    # Final count
    _p_done=$(grep -c '"file_name"' "$SESSION_DIR/gowitness.jsonl" 2>/dev/null || echo 0)
    emit_progress "Capture complete" "$_p_done" "$_p_total"
) &
_PROGRESS_PID=$!

# Wait for gowitness to complete
wait $_GOWITNESS_PID
_gowitness_exit=$?

# Kill progress poller
kill $_PROGRESS_PID 2>/dev/null
wait $_PROGRESS_PID 2>/dev/null

if [ "$_gowitness_exit" -ne 0 ]; then
    log_error "gowitness execution failed" "$SCRIPT_NAME"
    error_message "Screenshot capture failed. Check $SESSION_DIR/gowitness_output.txt for details."
    exit 1
fi

success_message "Screenshot capture completed" >&2
echo >&2

# Parse gowitness JSONL output and emit NETUTIL markers
JSONL_FILE="$SESSION_DIR/gowitness.jsonl"

if [ -f "$JSONL_FILE" ]; then
    log_info "gowitness JSONL output: $JSONL_FILE" "$SCRIPT_NAME"
    _screenshot_count=$(grep -c '"file_name":"[^"]' "$JSONL_FILE" 2>/dev/null) || _screenshot_count=0
    echo >&2
    success_message "Captured $_screenshot_count screenshots" >&2
else
    _screenshot_count=0
    log_warning "gowitness JSONL output not found at $JSONL_FILE" "$SCRIPT_NAME"
    echo "Warning: Screenshot results file not found. Screenshots may still exist in $SESSION_DIR" >&2
fi

echo >&2

# Generate summary report
REPORT_FILE="$SESSION_DIR/screenshot_report.txt"

{
    echo "=========================================="
    echo "Web Screenshot Report"
    echo "=========================================="
    echo
    echo "Screenshot Information:"
    echo "  Capture time: $(date)"
    echo "  Target source: $SESSION_NAME"
    echo "  Total URLs: $_dedup_count"
    echo "  Screenshots captured: ${_screenshot_count:-0}"
    echo "  Session directory: $SESSION_DIR"
    echo
    echo "=========================================="
    echo "Output Files"
    echo "=========================================="
    echo
    echo "All screenshot files are located in: $SESSION_DIR"
    echo
    echo "  gowitness.jsonl    - JSONL metadata file"
    echo "  gowitness_output.txt - gowitness execution log"
    echo "  screenshot_report.txt - This summary report"
    echo "  *.jpeg             - Screenshot images"
    echo

} > "$REPORT_FILE"

success_message "Report generated" >&2
echo >&2

# Display final summary
echo "==========================================" >&2
echo "Screenshot Capture Complete" >&2
echo "==========================================" >&2
echo >&2
echo "Total URLs processed: $_dedup_count" >&2
echo "Screenshots captured: ${_screenshot_count:-0}" >&2
echo >&2
echo "Files created:" >&2
echo "  Report:           $REPORT_FILE" >&2
echo "  JSONL metadata:   $JSONL_FILE" >&2
echo "  Screenshots:      $SESSION_DIR/*.jpeg" >&2
echo >&2

log_info "Screenshot capture complete. Total: ${_screenshot_count:-0}. Session: $SESSION_DIR" "$SCRIPT_NAME"
success_message "Web screenshot session completed: $SESSION_DIR" >&2
