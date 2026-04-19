#!/bin/sh

# Log Management Script for NetUtility
# Provides utilities for managing NetUtility logs

. "$(dirname "$0")/../common/logging.sh"
. "$(dirname "$0")/../common/colors.sh" 2>/dev/null || true

echo "=== NetUtility Log Management ==="
echo

# Log script start
log_script_start "log_management.sh" "$@"

show_menu() {
    echo "Log Management Options:"
    echo "1. View log statistics"
    echo "2. View recent log entries"
    echo "3. Search logs"
    echo "4. Clear logs"
    echo "5. Rotate logs manually"
    echo "6. Set log level"
    echo "7. Export logs"
    echo "8. Exit"
    echo >&2
}

view_recent_logs() {
    echo "Recent log entries:"
    lines="${1:-50}"
    if [ -f "$LOG_FILE" ]; then
        echo "--- Last $lines entries ---"
        tail -n "$lines" "$LOG_FILE"
    else
        echo "No log file found"
    fi
}

export_logs() {
    echo "Exporting logs..."
    timestamp=$(date +%Y%m%d_%H%M%S)
    export_dir="${NETUTIL_WORKDIR:-$HOME}/log_exports"
    mkdir -p "$export_dir"
    
    if [ -f "$LOG_FILE" ]; then
        export_file="$export_dir/netutil_logs_${timestamp}.txt"
        cp "$LOG_FILE" "$export_file"
        
        # Also export any rotated logs
        rotated_logs=$(ls "${LOG_FILE}."* 2>/dev/null | wc -l)
        if [ "$rotated_logs" -gt 0 ]; then
            export_archive="$export_dir/netutil_logs_complete_${timestamp}.tar.gz"
            tar -czf "$export_archive" "$LOG_FILE" "${LOG_FILE}."* 2>/dev/null
            echo "Complete logs exported to: $export_archive"
        fi
        
        echo "Current log exported to: $export_file"
        echo "Export size: $(du -h "$export_file" | cut -f1)"
        log_info "Logs exported to $export_file"
    else
        echo "No log file to export"
    fi
}

set_log_level() {
    echo "Current log level: $(get_log_level_name "$NETUTIL_LOG_LEVEL")"
    echo >&2
    echo "Available log levels:"
    echo "0. DEBUG (most verbose)"
    echo "1. INFO (default)"
    echo "2. WARN"
    echo "3. ERROR"
    echo "4. FATAL (least verbose)"
    echo >&2
    echo >&2
    if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
        printf "%sSelect log level (0-4): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
    else
        printf "Select log level (0-4): \n" >&2
    fi
    read -r new_level
    
    case "$new_level" in
        0|1|2|3|4)
            sed -i '/^export NETUTIL_LOG_LEVEL=/d' "$HOME/.profile"
            echo "export NETUTIL_LOG_LEVEL=$new_level" >> "$HOME/.profile"
            export NETUTIL_LOG_LEVEL="$new_level"
            log_info "Log level changed to $(get_log_level_name "$new_level")"
            echo "Log level set to: $(get_log_level_name "$new_level")"
            echo "Note: This will take effect for new shell sessions"
            ;;
        *)
            echo "Invalid log level selection"
            ;;
    esac
}

search_logs_interactive() {
    echo "Log Search"
    echo >&2
    if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
        printf "%sEnter search pattern (regex supported): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
    else
        printf "Enter search pattern (regex supported): \n" >&2
    fi
    read -r pattern
    echo >&2
    if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
        printf "%sLines of context (0 for none): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
    else
        printf "Lines of context (0 for none): \n" >&2
    fi
    read -r context
    
    if [ -z "$pattern" ]; then
        echo "No search pattern provided"
        return
    fi
    
    echo "Searching for: $pattern"
    search_logs "$pattern" "$context"
    log_info "Log search performed: $pattern"
}

while true; do
    show_menu
    echo >&2
    if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
        printf "%sSelect option (1-8): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
    else
        printf "Select option (1-8): \n" >&2
    fi
    read -r choice
    
    case "$choice" in
        1)
            get_log_stats
            ;;
        2)
            echo >&2
            echo >&2
            if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
                printf "%sNumber of recent entries to show (default 50): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
            else
                printf "Number of recent entries to show (default 50): \n" >&2
            fi
            read -r lines
            lines=${lines:-50}
            view_recent_logs "$lines"
            ;;
        3)
            echo >&2
            search_logs_interactive
            ;;
        4)
            echo >&2
            echo "WARNING: This will permanently delete all log entries!"
            echo >&2
            if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
                printf "%sAre you sure? (y/N): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
            else
                printf "Are you sure? (y/N): \n" >&2
            fi
            read -r confirm
            if echo "$confirm" | grep -E '^[Yy]$' >/dev/null; then
                clear_logs
                log_info "Logs cleared by user request"
            else
                echo "Log clearing cancelled"
            fi
            ;;
        5)
            echo >&2
            echo "Rotating logs manually..."
            rotate_logs
            echo "Log rotation completed"
            ;;
        6)
            echo >&2
            set_log_level
            ;;
        7)
            echo >&2
            export_logs
            ;;
        8)
            echo "Exiting log management"
            break
            ;;
        *)
            echo "Invalid option. Please select 1-8."
            ;;
    esac
    
    echo >&2
    echo >&2
    if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
        printf "%sPress Enter to continue...%s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
    else
        printf "Press Enter to continue...\n" >&2
    fi
    read -r REPLY
    echo >&2
done

log_script_end "log_management.sh" 0