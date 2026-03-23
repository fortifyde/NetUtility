#!/bin/sh
# Color and formatting utilities using tput for portability
# Gracefully degrades when colors are not available
# POSIX compliant - no bashisms

# Detect color support
# Check NETUTIL_FORCE_COLOR first (set by Go executor for TUI mode)
HAS_COLORS=false
if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
    HAS_COLORS=true
elif command -v tput >/dev/null 2>&1; then
    if [ -t 1 ] && [ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]; then
        HAS_COLORS=true
    fi
fi

# Initialize color codes
if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
    # Direct ANSI — Go TUI renderer expects these exact single-code sequences
    COLOR_RESET=$(printf '\033[0m')
    COLOR_BOLD=$(printf '\033[1m')
    COLOR_DIM=$(printf '\033[2m')
    COLOR_RED=$(printf '\033[31m')
    COLOR_GREEN=$(printf '\033[32m')
    COLOR_YELLOW=$(printf '\033[33m')
    COLOR_BLUE=$(printf '\033[34m')
    COLOR_MAGENTA=$(printf '\033[35m')
    COLOR_CYAN=$(printf '\033[36m')
    COLOR_PLUM=$(printf '\033[38;2;221;160;221m')
    PROMPT_COLOR="$COLOR_PLUM"
elif [ "$HAS_COLORS" = "true" ]; then
    # tput for real terminals
    COLOR_RESET=$(tput sgr0)
    COLOR_BOLD=$(tput bold)
    COLOR_DIM=$(tput dim 2>/dev/null || echo "")
    COLOR_RED=$(tput setaf 1)
    COLOR_GREEN=$(tput setaf 2)
    COLOR_YELLOW=$(tput setaf 3)
    COLOR_BLUE=$(tput setaf 4)
    COLOR_MAGENTA=$(tput setaf 5)
    COLOR_CYAN=$(tput setaf 6)
    COLOR_PLUM=""
    PROMPT_COLOR=""
else
    COLOR_RESET=""
    COLOR_BOLD=""
    COLOR_DIM=""
    COLOR_RED=""
    COLOR_GREEN=""
    COLOR_YELLOW=""
    COLOR_BLUE=""
    COLOR_MAGENTA=""
    COLOR_CYAN=""
    COLOR_PLUM=""
    PROMPT_COLOR=""
fi

# Color wrapper functions
color_reset() {
    printf "%s" "$COLOR_RESET"
}

color_bold() {
    printf "%s%s%s" "$COLOR_BOLD" "$1" "$COLOR_RESET"
}

color_red() {
    printf "%s%s%s" "$COLOR_RED" "$1" "$COLOR_RESET"
}

color_green() {
    printf "%s%s%s" "$COLOR_GREEN" "$1" "$COLOR_RESET"
}

color_yellow() {
    printf "%s%s%s" "$COLOR_YELLOW" "$1" "$COLOR_RESET"
}

color_blue() {
    printf "%s%s%s" "$COLOR_BLUE" "$1" "$COLOR_RESET"
}

color_cyan() {
    printf "%s%s%s" "$COLOR_CYAN" "$1" "$COLOR_RESET"
}

color_magenta() {
    printf "%s%s%s" "$COLOR_MAGENTA" "$1" "$COLOR_RESET"
}

# Styled message functions
color_error() {
    printf "%s✗ Error: %s%s\n" "$COLOR_RED$COLOR_BOLD" "$1" "$COLOR_RESET" >&2
}

color_success() {
    printf "%s✓ %s%s\n" "$COLOR_GREEN$COLOR_BOLD" "$1" "$COLOR_RESET"
}

color_warning() {
    printf "%s⚠ Warning: %s%s\n" "$COLOR_YELLOW$COLOR_BOLD" "$1" "$COLOR_RESET" >&2
}

color_info() {
    printf "%s%s%s\n" "$COLOR_BOLD" "$1" "$COLOR_RESET"
}

# Phase header with full-width separator
print_phase_header() {
    _pph_title="$1"
    _pph_width=70

    echo ""
    echo ""
    printf "%s%s" "$COLOR_CYAN$COLOR_BOLD" "$(awk -v n="$_pph_width" 'BEGIN{for(i=0;i<n;i++) printf "="}')"
    color_reset
    echo ""
    printf "%s=== %s%s\n" "$COLOR_CYAN$COLOR_BOLD" "$_pph_title" "$COLOR_RESET"
    printf "%s%s" "$COLOR_CYAN$COLOR_BOLD" "$(awk -v n="$_pph_width" 'BEGIN{for(i=0;i<n;i++) printf "="}')"
    color_reset
    echo ""
    echo ""
}

# Sub-phase header with dashes
print_subphase() {
    _ps_title="$1"
    _ps_width=70

    echo ""
    printf "%s  " "$COLOR_BLUE$COLOR_BOLD"
    printf "%s" "$(awk -v n="$_ps_width" 'BEGIN{for(i=0;i<n;i++) printf "-"}')"
    color_reset
    echo ""
    printf "%s  --- %s%s\n" "$COLOR_BLUE$COLOR_BOLD" "$_ps_title" "$COLOR_RESET"
    printf "%s  " "$COLOR_BLUE$COLOR_BOLD"
    printf "%s" "$(awk -v n="$_ps_width" 'BEGIN{for(i=0;i<n;i++) printf "-"}')"
    color_reset
    echo ""
}

# Progress indicator for VLAN/phase operations
print_progress() {
    _pp_current="$1"
    _pp_total="$2"
    _pp_description="$3"

    printf "%s[%d/%d]%s %s\n" "$COLOR_CYAN$COLOR_BOLD" "$_pp_current" "$_pp_total" "$COLOR_RESET" "$_pp_description"
}

# Status message with timestamp
print_status() {
    _pst_message="$1"
    _pst_timestamp=$(date '+%H:%M:%S')

    printf "%s[%s]%s %s\n" "$COLOR_DIM" "$_pst_timestamp" "$COLOR_RESET" "$_pst_message"
}

# Horizontal separator
print_separator() {
    _psep_char="${1--}"
    _psep_width="${2:-70}"

    printf "%s" "$(awk -v c="$_psep_char" -v n="$_psep_width" 'BEGIN{for(i=0;i<n;i++) printf c}')"
    echo ""
}

# Emit a live progress marker — intercepted by Go tool, not shown in text stream
# Usage: emit_progress "Phase name" current total
emit_progress() {
    [ "$NETUTIL_FORCE_COLOR" = "1" ] || return 0
    printf '##NETUTIL:PROGRESS## [%s/%s] %s\n' "$2" "$3" "$1"
}

# Emit a summary marker at script completion
# Usage: emit_summary "key=value" "key=value" ...
emit_summary() {
    [ "$NETUTIL_FORCE_COLOR" = "1" ] || return 0
    printf '##NETUTIL:SUMMARY##'
    for _es_pair in "$@"; do
        printf ' %s' "$_es_pair"
    done
    printf '\n'
}
