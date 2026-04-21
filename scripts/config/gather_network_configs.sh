#!/bin/sh
#
# Network Config Gatherer
# Extracts running configurations and compliance data from network devices
# Supports: Cisco IOS, Cisco Nexus, HP Comware, HP ProVision, HP Aruba
# POSIX-compliant for maximum portability
#

set -e

# Source common utilities
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMMON_DIR="${SCRIPT_DIR}/../common"
if [ -f "${COMMON_DIR}/utils.sh" ]; then
    . "${COMMON_DIR}/utils.sh"
else
    echo "ERROR: Cannot find common utilities" >&2
    exit 1
fi
. "${COMMON_DIR}/colors.sh" 2>/dev/null || true
. "${COMMON_DIR}/logging.sh"
SCRIPT_NAME="$(basename "$0")"

# Check for required dependencies
if ! command -v sshpass >/dev/null 2>&1; then
    log_error "sshpass is required but not installed" "$SCRIPT_NAME"
    echo "ERROR: sshpass is required but not installed" >&2
    echo "" >&2
    echo "This script uses sshpass for non-interactive SSH password authentication." >&2
    echo "Please install it using your package manager:" >&2
    echo "" >&2
    echo "  Fedora/RHEL/CentOS:  sudo dnf install sshpass" >&2
    echo "  Debian/Ubuntu:       sudo apt-get install sshpass" >&2
    echo "  Arch Linux:          sudo pacman -S sshpass" >&2
    echo "" >&2
    exit 1
fi

HAS_EXPECT=0
command -v expect >/dev/null 2>&1 && HAS_EXPECT=1

# Detect ChannelTimeout support (OpenSSH 9.6+)
# ssh -o ChannelTimeout=session=1 -V exits 0 if supported, 255 if unknown option
CHANNEL_TIMEOUT_OPT=""
if ssh -o ChannelTimeout=session=1 -V >/dev/null 2>&1; then
    CHANNEL_TIMEOUT_OPT="-o ChannelTimeout=session=30"
fi


# Global variables
VERSION="1.0.0"
NETUTIL_WORKDIR="${NETUTIL_WORKDIR:-$HOME}"
SESSION_DIR=""
SESSION_ID=""
COMMANDS_DIR="${SCRIPT_DIR}/commands"
FAILURES_FILE=""
DRY_RUN=0
CONCURRENCY=5
CRED_MODE="common"
CRED_FILE=""
COMMON_USER=""
COMMON_PASS=""
COMMON_ENABLE=""
LEGACY_SSH_MODE=0
SSH_OPTS_FILE=""
SSH_REQUIRES_PTY=0
PROCESSED_COUNT=0
SUCCESS_COUNT=0
FAILURE_COUNT=0

# Color codes
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' CYAN='' NC=''
fi

# Print functions (all output to stderr for TUI compatibility)
print_header() {
    printf "${BLUE}===================================================${NC}\n" >&2
    printf "${BLUE}  Network Config Gatherer v%s${NC}\n" "$VERSION" >&2
    printf "${BLUE}===================================================${NC}\n\n" >&2
}

print_success() {
    printf "${GREEN}✓ %s${NC}\n" "$1" >&2
}

print_error() {
    printf "${RED}✗ ERROR: %s${NC}\n" "$1" >&2
}

print_warning() {
    printf "${YELLOW}⚠ WARNING: %s${NC}\n" "$1" >&2
}

print_info() {
    printf "${BLUE}ℹ %s${NC}\n" "$1" >&2
}

print_step() {
    printf "${CYAN}→ %s${NC}\n" "$1" >&2
}

# Print help
print_help() {
    cat >&2 << EOF
Network Config Gatherer v${VERSION}

Usage: $0 [OPTIONS]

OPTIONS:
    --dry-run           Test connectivity only, don't extract configs
    --concurrency N     Max parallel connections (default: 5)
    --cred-mode MODE    Credential mode: common|file|interactive (default: common)
    --cred-file FILE    Path to credentials file (IP,username,password)
    --targets LIST      Comma-separated IP list or file path
    -h, --help          Show this help message

EXAMPLES:
    # Interactive mode with common credentials
    $0

    # Dry-run to test connectivity
    $0 --dry-run

    # Use categorized host file from discovery
    $0 --targets /path/to/network_devices.txt

    # Process specific IPs with higher concurrency
    $0 --targets "192.168.1.1,192.168.1.2,192.168.1.3" --concurrency 10

    # Use credentials file
    $0 --cred-mode file --cred-file creds.csv

OUTPUT:
    Results saved to: \${NETUTIL_WORKDIR}/configs/gather_YYYYMMDD_HHMMSS/

    Per-device directories contain:
      - version.txt                  Version information
      - running_config.txt           Running configuration
      - running_config_all.txt       Running config with all defaults
      - startup_config.txt           Startup/saved configuration
      - compliance_commands.txt      Additional compliance data
      - metadata.txt                 Device metadata
      - connection.log               Connection log

SUPPORTED VENDORS:
    - Cisco IOS
    - Cisco Nexus (NX-OS)
    - HP Comware
    - HP ProVision
    - HP Aruba (ArubaOS-CX)
    - HP Aruba (ArubaOS-Switch)

OPTIONAL DEPENDENCIES:
    - expect          Reliable paginated output collection for PTY-mode
                     devices (e.g. Cisco Nexus). Install with:
                       Fedora/RHEL:  sudo dnf install expect
                       Debian/Ubuntu: sudo apt-get install expect

EOF
}

# Initialize session directory
init_session() {
    SESSION_ID="gather_$(date +%Y%m%d_%H%M%S)"
    SESSION_DIR="${NETUTIL_WORKDIR}/configs/${SESSION_ID}"

    mkdir -p "$SESSION_DIR" || {
        log_error "Failed to create session directory: $SESSION_DIR" "$SCRIPT_NAME"
        print_error "Failed to create session directory: $SESSION_DIR"
        exit 1
    }

    FAILURES_FILE="${SESSION_DIR}/failures.txt"
    touch "$FAILURES_FILE"

    print_success "Session initialized: $SESSION_ID"
    print_info "Output directory: $SESSION_DIR"
}

# Clean output - remove ANSI codes, pagination prompts, command echoes
clean_output() {
    sed 's/\x1b\[[^A-Za-z]*[A-Za-z]//g' | \
    tr -d '\r' | \
    grep -v -- '--More--' | grep -v -- '---- More ----' | \
    grep -v -i 'press any key to continue' | \
    grep -v '^[A-Za-z0-9._-]*[#>]$' | \
    grep -v '^[A-Za-z0-9._-]*[#>] ' || true
}

# Like clean_output but keeps PTY command echoes (HOSTNAME# cmd) as command separators
clean_output_compliance() {
    sed 's/\x1b\[[^A-Za-z]*[A-Za-z]//g' | \
    tr -d '\r' | \
    grep -v -- '--More--' | grep -v -- '---- More ----' | \
    grep -v -i 'press any key to continue' | \
    grep -v '^[A-Za-z0-9._-]*[#>]$' || true
}

# Runs sshpass + ssh, inserting -F for legacy algorithm config when set
run_sshpass() {
    _rsp_pass="$1"
    shift
    if [ -n "$SSH_OPTS_FILE" ]; then
        sshpass -p "$_rsp_pass" ssh -F "$SSH_OPTS_FILE" $CHANNEL_TIMEOUT_OPT "$@"
    else
        sshpass -p "$_rsp_pass" ssh $CHANNEL_TIMEOUT_OPT "$@"
    fi
}

# Creates a temp SSH config enabling legacy algorithms for old devices
setup_ssh_opts() {
    [ "$LEGACY_SSH_MODE" != "1" ] && return 0
    SSH_OPTS_FILE=$(mktemp)
    cat > "$SSH_OPTS_FILE" << 'SSHEOF'
KexAlgorithms +diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1
HostKeyAlgorithms +ssh-rsa
Ciphers +aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc
MACs +hmac-sha1,hmac-md5
SSHEOF
}

# Try version detection commands in order with fallback
try_version_command() {
    device_ip="$1"
    username="$2"
    password="$3"

    # Try exec channel first (Cisco IOS, Comware, Aruba CX, etc.).
    # Pipe a leading newline so any "Press any key to continue" banner
    # has a character to consume before the exec command runs.
    for cmd in "show version" "display version" "show system" "show system information"; do
        output=$(printf '\n' | run_sshpass "$password" \
            -o ConnectTimeout=10 \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR \
            "$username@$device_ip" "$cmd" 2>/dev/null | clean_output)

        if echo "$output" | grep -qi "command execution is not supported\|cmd exec error"; then
            break
        fi
        if [ -n "$output" ] && ! echo "$output" | grep -qi "invalid input\|unknown command\|% Invalid\|syntax error"; then
            echo "$output"
            return 0
        fi
    done

    # Exec channel unsupported or all exec attempts failed.
    # Fall back to interactive shell with PTY (required by e.g. HP Aruba ArubaOS-Switch).
    # Signal to the caller via flag file so exec_ssh_command uses PTY for this device too.
    [ -n "${4:-}" ] && echo "1" > "$4"
    for cmd in "show version" "display version" "show system" "show system information"; do
        output=$({ printf '\n%s\nexit\n' "$cmd"; sleep 3; } | run_sshpass "$password" -t \
            -o ConnectTimeout=15 \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR \
            "$username@$device_ip" 2>/dev/null | clean_output)

        if [ -n "$output" ] && ! echo "$output" | grep -qi "invalid input\|unknown command\|% Invalid\|syntax error"; then
            echo "$output"
            return 0
        fi
    done

    return 1
}

# Detect vendor and OS from version output
detect_vendor() {
    version_output="$1"

    # Cisco IOS
    if echo "$version_output" | grep -qi "Cisco IOS Software\|IOS (tm)\|Cisco Internetwork"; then
        echo "cisco_ios"
        return 0
    fi

    # Cisco Nexus
    if echo "$version_output" | grep -qi "NX-OS\|Nexus Operating System\|cisco Nexus"; then
        echo "cisco_nexus"
        return 0
    fi

    # HP Comware
    if echo "$version_output" | grep -qi "Comware Software\|HPE Comware\|HP Comware Platform"; then
        echo "hp_comware"
        return 0
    fi

    # HP Aruba CX
    if echo "$version_output" | grep -qi "ArubaOS-CX"; then
        echo "aruba_cx"
        return 0
    fi

    # HP Aruba Switch (ArubaOS-Switch / ProVision-based)
    # Matches explicit branding OR the two-letter firmware prefix unique to ArubaOS-Switch
    # (YA=2530, WC=2930F/M, WB=2920, KB/KA=2620, RA=5400R, etc.) OR J-series model numbers
    if echo "$version_output" | grep -qi "ArubaOS-Switch\|Aruba"; then
        echo "aruba_switch"
        return 0
    fi
    if echo "$version_output" | grep -q "[A-Z][A-Z]\.[0-9][0-9]\.[0-9]"; then
        echo "aruba_switch"
        return 0
    fi
    if echo "$version_output" | grep -q "J[0-9][0-9][0-9][0-9]"; then
        echo "aruba_switch"
        return 0
    fi

    # HP ProVision (older pre-Aruba firmware without two-letter version prefix)
    if echo "$version_output" | grep -qi "ProVision\|Image stamp"; then
        echo "hp_provision"
        return 0
    fi

    # Fallback to generic
    echo "generic"
    return 0
}

# Get terminal setup commands based on vendor
get_terminal_setup() {
    vendor="$1"

    case "$vendor" in
        cisco_ios|cisco_nexus)
            echo "terminal length 0"
            ;;
        hp_comware)
            echo "screen-length disable"
            ;;
        hp_provision|aruba_switch)
            echo "no page"
            ;;
        aruba_cx)
            echo "no paging"
            ;;
        *)
            echo ""
            ;;
    esac
}

get_terminal_fallback() {
    vendor="$1"

    case "$vendor" in
        cisco_nexus)
            echo "terminal pager cat"
            ;;
        hp_comware)
            echo "screen-length 0 temporary"
            ;;
        hp_provision|aruba_switch)
            echo "terminal length 0"
            ;;
        aruba_cx)
            echo "terminal length 0"
            ;;
        *)
            echo ""
            ;;
    esac
}

exec_ssh_with_expect() {
    _e_ip="$1"
    _e_user="$2"
    _e_pass="$3"
    _e_cmd="$4"
    _e_term="$5"
    _e_enable="$6"

    _e_script=$(mktemp)
    chmod 600 "$_e_script"

    cat > "$_e_script" << 'EXPEOF'
#!/usr/bin/expect -f
set timeout 15
log_user 1
EXPEOF

    printf 'set _password {%s}\n' "$_e_pass" >> "$_e_script"
    printf 'set _username {%s}\n' "$_e_user" >> "$_e_script"
    printf 'set _device_ip {%s}\n' "$_e_ip" >> "$_e_script"
    printf 'set _cmd {%s}\n' "$_e_cmd" >> "$_e_script"

    if [ -n "$CHANNEL_TIMEOUT_OPT" ]; then
        printf 'spawn sshpass -p $_password ssh -tt -o ConnectTimeout=10 %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR $_username@$_device_ip\n' "$CHANNEL_TIMEOUT_OPT" >> "$_e_script"
    else
        printf 'spawn sshpass -p $_password ssh -tt -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR $_username@$_device_ip\n' >> "$_e_script"
    fi

    cat >> "$_e_script" << 'EXPEOF'
expect {
    -re {Press any key to continue} {
        send "\r"
        exp_continue
    }
    -re {[#>]\\s*$} {
    }
    timeout {
        exit 1
    }
}
EXPEOF

    if [ -n "$_e_enable" ]; then
        printf 'set _enable_pass {%s}\n' "$_e_enable" >> "$_e_script"
        cat >> "$_e_script" << 'EXPEOF'
send "enable\r"
expect "Password:"
send "$_enable_pass\r"
expect -re {[#>]\\s*$}
EXPEOF
    fi

    if [ -n "$_e_term" ]; then
        printf 'set _term {%s}\n' "$_e_term" >> "$_e_script"
        cat >> "$_e_script" << 'EXPEOF'
send "$_term\r"
expect -re {[#>]\\s*$}
EXPEOF
    fi

    cat >> "$_e_script" << 'EXPEOF'
send "$_cmd\r"

expect {
    -re {--More--} {
        send " "
        exp_continue
    }
    -re {---- More ----} {
        send " "
        exp_continue
    }
    -re {Press any key} {
        send " "
        exp_continue
    }
    -re {\n\S+[#>] ?$} {
    }
    timeout {
    }
}

send "exit\r"
expect eof
EXPEOF

    expect "$_e_script" 2>/dev/null
    _e_status=$?
    rm -f "$_e_script"
    return $_e_status
}

# Execute command on device via SSH
# Optional 5th arg: terminal_cmd prepended in the same session to disable paging
# Optional 6th arg: enable_pass to enter privileged EXEC mode before running commands
# Optional 7th arg: "compliance" to use clean_output_compliance (keeps command echoes)
# Optional 8th arg: vendor name for pagination fallback commands
exec_ssh_command() {
    device_ip="$1"
    username="$2"
    password="$3"
    command="$4"
    terminal_cmd="${5:-}"
    enable_pass="${6:-}"

    _pty_flag="-T"
    [ "${SSH_REQUIRES_PTY:-0}" = "1" ] && _pty_flag="-tt"

    _filter="clean_output"
    [ "${7:-}" = "compliance" ] && _filter="clean_output_compliance"

    _vendor="${8:-}"
    _raw=$(mktemp)

    {
        printf '\n\n\n'
        [ -n "$enable_pass" ] && printf 'enable\n%s\n' "$enable_pass"
        [ -n "$terminal_cmd" ] && printf '%s\n' "$terminal_cmd"
        printf '%s\nexit\n' "$command"
        [ "$_pty_flag" = "-tt" ] && sleep 3
    } | run_sshpass "$password" "$_pty_flag" \
        -o ConnectTimeout=10 \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        "$username@$device_ip" 2>/dev/null > "$_raw"

    if [ "$_pty_flag" = "-tt" ] && grep -q -- '--More--\|---- More ----' "$_raw" 2>/dev/null; then
        print_warning "Pagination detected in output, attempting fallbacks..."

        _fallback_term=""
        [ -n "$_vendor" ] && _fallback_term=$(get_terminal_fallback "$_vendor")

        if [ -n "$_fallback_term" ]; then
            print_info "Retrying with fallback terminal command: $_fallback_term"
            {
                printf '\n\n\n'
                [ -n "$enable_pass" ] && printf 'enable\n%s\n' "$enable_pass"
                printf '%s\n' "$_fallback_term"
                printf '%s\nexit\n' "$command"
                sleep 3
            } | run_sshpass "$password" "$_pty_flag" \
                -o ConnectTimeout=10 \
                -o StrictHostKeyChecking=no \
                -o UserKnownHostsFile=/dev/null \
                -o LogLevel=ERROR \
                "$username@$device_ip" 2>/dev/null > "$_raw"
        fi

        if grep -q -- '--More--\|---- More ----' "$_raw" 2>/dev/null; then
            if [ "$HAS_EXPECT" = "1" ]; then
                print_info "Using expect for paginated output collection"
                _expect_raw=$(mktemp)
                exec_ssh_with_expect "$device_ip" "$username" "$password" \
                    "$command" "$terminal_cmd" "$enable_pass" > "$_expect_raw" 2>/dev/null
                if [ -s "$_expect_raw" ]; then
                    mv "$_expect_raw" "$_raw"
                else
                    rm -f "$_expect_raw"
                    print_warning "Expect fallback failed, saving potentially truncated output"
                    printf '!!! WARNING: OUTPUT MAY BE TRUNCATED !!!\n' >> "$_raw"
                    printf '!!! Pagination could not be disabled !!!\n' >> "$_raw"
                fi
            else
                print_warning "Output may be truncated (install expect for reliable pagination handling)"
                printf '!!! WARNING: OUTPUT MAY BE TRUNCATED !!!\n' >> "$_raw"
                printf '!!! Pagination could not be disabled and expect is not installed !!!\n' >> "$_raw"
            fi
        else
            print_success "Fallback terminal command resolved pagination"
        fi
    fi

    cat "$_raw" | $_filter
    rm -f "$_raw"
}

# Load command file for vendor
load_vendor_commands() {
    vendor="$1"
    cmd_file="${COMMANDS_DIR}/${vendor}.cmds"

    if [ ! -f "$cmd_file" ]; then
        print_warning "Command file not found: $cmd_file, using generic"
        cmd_file="${COMMANDS_DIR}/generic.cmds"
    fi

    # Read commands, skip comments and blank lines
    grep -v '^#' "$cmd_file" | grep -v '^$' || true
}

# Process a single device
process_device() {
    device_ip="$1"
    username="$2"
    password="$3"
    enable_pass="${4:-}"
    device_dir="${SESSION_DIR}/device_${device_ip}"

    mkdir -p "$device_dir"

    log_info "Processing device: $device_ip" "$SCRIPT_NAME"
    log_file="${device_dir}/connection.log"
    metadata_file="${device_dir}/metadata.txt"

    echo "=== Connection Log for $device_ip ===" > "$log_file"
    echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')" >> "$log_file"
    echo "Username: $username" >> "$log_file"
    echo "" >> "$log_file"

    # Test connectivity (auto-detects legacy SSH need on negotiation failure)
    print_step "Connecting to $device_ip..."

    _ssh_err=$(mktemp)
    if ! run_sshpass "$password" -o ConnectTimeout=5 \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        "$username@$device_ip" "exit" >"$_ssh_err" 2>&1; then

        if grep -qi "no matching\|unable to negotiate\|host key type\|no matching host key" "$_ssh_err"; then
            print_info "Legacy SSH required for $device_ip, retrying..."
            LEGACY_SSH_MODE=1
            setup_ssh_opts
            if ! run_sshpass "$password" -o ConnectTimeout=5 \
                -o StrictHostKeyChecking=no \
                -o UserKnownHostsFile=/dev/null \
                -o LogLevel=ERROR \
                "$username@$device_ip" "exit" >>"$log_file" 2>&1; then
                # Legacy SSH failed too. Try PTY before giving up.
                print_info "Legacy SSH also failed, attempting PTY mode for $device_ip"
                if { printf '\nexit\n'; sleep 3; } | run_sshpass "$password" -t \
                    -o ConnectTimeout=10 \
                    -o StrictHostKeyChecking=no \
                    -o UserKnownHostsFile=/dev/null \
                    -o LogLevel=ERROR \
                    "$username@$device_ip" >/dev/null 2>&1; then
                    SSH_REQUIRES_PTY=1
                    echo "SUCCESS: Connection established (PTY mode after legacy failure)" >> "$log_file"
                else
                    rm -f "$_ssh_err"
                    log_error "Failed to connect to $device_ip (all methods)" "$SCRIPT_NAME"
                    print_error "Failed to connect to $device_ip"
                    echo "$device_ip,connection_failed,Failed to establish SSH connection" >> "$FAILURES_FILE"
                    echo "FAILURE: Connection failed (all methods)" >> "$log_file"
                    return 1
                fi
            fi
        else
            # Exec failed for non-negotiation reason (e.g. "Cmd exec error", unsupported exec).
            # Try PTY mode before giving up.
            print_info "Exec channel failed for $device_ip, attempting PTY mode..."
            if { printf '\nexit\n'; sleep 3; } | run_sshpass "$password" -t \
                -o ConnectTimeout=10 \
                -o StrictHostKeyChecking=no \
                -o UserKnownHostsFile=/dev/null \
                -o LogLevel=ERROR \
                "$username@$device_ip" >/dev/null 2>&1; then
                SSH_REQUIRES_PTY=1
                echo "SUCCESS: Connection established (PTY mode)" >> "$log_file"
            else
                rm -f "$_ssh_err"
                log_error "Failed to connect to $device_ip (exec and PTY)" "$SCRIPT_NAME"
                print_error "Failed to connect to $device_ip"
                echo "$device_ip,connection_failed,Failed to establish SSH connection" >> "$FAILURES_FILE"
                echo "FAILURE: Connection failed (exec and PTY)" >> "$log_file"
                return 1
            fi
        fi
    else
        echo "SUCCESS: Connection established" >> "$log_file"
    fi
    rm -f "$_ssh_err"

    # Get version output with fallbacks.
    # Pass a temp file so try_version_command can signal when PTY is required.
    print_step "Detecting vendor for $device_ip..."
    _pty_flag=$(mktemp)
    echo "0" > "$_pty_flag"
    version_output=$(try_version_command "$device_ip" "$username" "$password" "$_pty_flag")
    SSH_REQUIRES_PTY=$(cat "$_pty_flag")
    rm -f "$_pty_flag"

    if [ -z "$version_output" ]; then
        log_error "Failed to get version info from $device_ip" "$SCRIPT_NAME"
        print_error "Failed to get version info from $device_ip"
        echo "$device_ip,version_detection_failed,Could not retrieve version information" >> "$FAILURES_FILE"
        echo "FAILURE: Version detection failed" >> "$log_file"
        return 1
    fi

    # Save version output
    echo "$version_output" > "${device_dir}/version.txt"
    echo "SUCCESS: Version retrieved" >> "$log_file"

    # Detect vendor
    vendor=$(detect_vendor "$version_output")
    log_info "Vendor detected: $vendor for $device_ip" "$SCRIPT_NAME"
    print_success "Detected vendor: $vendor for $device_ip"
    echo "Vendor: $vendor" >> "$log_file"

    # Write metadata
    echo "IP Address: $device_ip" > "$metadata_file"
    echo "Vendor/OS: $vendor" >> "$metadata_file"
    echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')" >> "$metadata_file"
    echo "Username: $username" >> "$metadata_file"
    echo "" >> "$metadata_file"

    # Extract hostname from version if possible
    hostname=$(echo "$version_output" | grep -i "hostname\|system name" | head -1 || echo "Unknown")
    echo "Hostname: $hostname" >> "$metadata_file"

    # If dry-run mode, stop here
    if [ "$DRY_RUN" -eq 1 ]; then
        print_success "Dry-run complete for $device_ip"
        return 0
    fi

    # Load vendor commands
    terminal_cmd=$(get_terminal_setup "$vendor")
    commands=$(load_vendor_commands "$vendor")

    if [ -z "$commands" ]; then
        print_warning "No commands found for vendor: $vendor"
        return 1
    fi

    # Process commands
    compliance_file="${device_dir}/compliance_commands.txt"
    echo "=== Compliance Commands Output for $device_ip ===" > "$compliance_file"
    echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')" >> "$compliance_file"
    echo "" >> "$compliance_file"

    # Pass 1: per-file config commands (@-markers), each in its own session with terminal setup
    echo "$commands" | while IFS= read -r line; do
        [ -z "$line" ] && continue
        case "$line" in
            @VERSION*)
                continue
                ;;
            @RUNNING_CONFIG_ALL*)
                cmd=$(echo "$line" | sed 's/@RUNNING_CONFIG_ALL //')
                print_step "Executing: $cmd on $device_ip"
                output=$(exec_ssh_command "$device_ip" "$username" "$password" "$cmd" "$terminal_cmd" "$enable_pass" "" "$vendor" 2>&1)
                if [ -n "$output" ]; then
                    echo "$output" > "${device_dir}/running_config_all.txt"
                    print_success "Saved: running_config_all.txt"
                    echo "SUCCESS: $cmd" >> "$log_file"
                else
                    print_warning "Failed or empty output: $cmd"
                    echo "FAILED: $cmd" >> "$log_file"
                fi
                ;;
            @RUNNING_CONFIG*)
                cmd=$(echo "$line" | sed 's/@RUNNING_CONFIG //')
                print_step "Executing: $cmd on $device_ip"
                output=$(exec_ssh_command "$device_ip" "$username" "$password" "$cmd" "$terminal_cmd" "$enable_pass" "" "$vendor" 2>&1)
                if [ -n "$output" ]; then
                    echo "$output" > "${device_dir}/running_config.txt"
                    print_success "Saved: running_config.txt"
                    echo "SUCCESS: $cmd" >> "$log_file"
                else
                    print_warning "Failed or empty output: $cmd"
                    echo "FAILED: $cmd" >> "$log_file"
                fi
                ;;
            @STARTUP_CONFIG*)
                cmd=$(echo "$line" | sed 's/@STARTUP_CONFIG //')
                print_step "Executing: $cmd on $device_ip"
                output=$(exec_ssh_command "$device_ip" "$username" "$password" "$cmd" "$terminal_cmd" "$enable_pass" "" "$vendor" 2>&1)
                if [ -n "$output" ]; then
                    echo "$output" > "${device_dir}/startup_config.txt"
                    print_success "Saved: startup_config.txt"
                    echo "SUCCESS: $cmd" >> "$log_file"
                else
                    print_warning "Failed or empty output: $cmd"
                    echo "FAILED: $cmd" >> "$log_file"
                fi
                ;;
        esac
    done

    # Pass 2: collect compliance commands and run as a single bundled session
    compliance_cmds_file=$(mktemp)
    echo "$commands" | while IFS= read -r line; do
        [ -z "$line" ] && continue
        case "$line" in
            @*) continue ;;
            *)  echo "$line" >> "$compliance_cmds_file" ;;
        esac
    done

    compliance_bundle=$(cat "$compliance_cmds_file")
    rm -f "$compliance_cmds_file"

    if [ -n "$compliance_bundle" ]; then
        print_step "Executing compliance commands on $device_ip (bundled session)..."
        output=$(exec_ssh_command "$device_ip" "$username" "$password" "$compliance_bundle" "$terminal_cmd" "" "compliance" "$vendor" 2>&1)
        if [ -n "$output" ]; then
            echo "$output" >> "$compliance_file"
            print_success "Saved: compliance_commands.txt"
        else
            print_warning "Failed or empty output for compliance commands"
        fi
    fi

    print_success "Completed extraction for $device_ip"
    return 0
}

# Generate summary report
generate_summary() {
    summary_file="${SESSION_DIR}/session_summary.txt"

    cat > "$summary_file" << EOF
==================================================
Network Config Gatherer - Session Summary
==================================================

Session Information:
  Session ID:        $SESSION_ID
  Start Time:        $(date '+%Y-%m-%d %H:%M:%S')
  Working Directory: $SESSION_DIR
  Mode:              $([ "$DRY_RUN" -eq 1 ] && echo "Dry-run" || echo "Full extraction")

Statistics:
  Total Devices:     $PROCESSED_COUNT
  Successful:        $SUCCESS_COUNT
  Failed:            $FAILURE_COUNT
  Success Rate:      $([ "$PROCESSED_COUNT" -gt 0 ] && echo "$((SUCCESS_COUNT * 100 / PROCESSED_COUNT))%" || echo "N/A")

EOF

    # Add vendor distribution if devices were processed
    if [ -d "$SESSION_DIR" ] && [ "$(find "$SESSION_DIR" -type d -name 'device_*' | wc -l)" -gt 0 ]; then
        echo "Vendor Distribution:" >> "$summary_file"
        find "$SESSION_DIR" -type d -name 'device_*' -exec cat {}/metadata.txt \; 2>/dev/null | \
            grep "Vendor/OS:" | sort | uniq -c | sed 's/^/  /' >> "$summary_file" || echo "  No vendor data available" >> "$summary_file"
        echo "" >> "$summary_file"
    fi

    # Add failed devices if any
    if [ "$FAILURE_COUNT" -gt 0 ] && [ -f "$FAILURES_FILE" ]; then
        echo "Failed Devices:" >> "$summary_file"
        cat "$FAILURES_FILE" | sed 's/^/  /' >> "$summary_file"
        echo "" >> "$summary_file"
    fi

    # Add storage information
    echo "Storage Information:" >> "$summary_file"
    echo "  Total Size:        $(du -sh "$SESSION_DIR" | cut -f1)" >> "$summary_file"
    echo "  Device Folders:    $(find "$SESSION_DIR" -type d -name 'device_*' | wc -l)" >> "$summary_file"
    echo "  Total Files:       $(find "$SESSION_DIR" -type f | wc -l)" >> "$summary_file"
    echo "" >> "$summary_file"

    echo "===================================================" >> "$summary_file"
    echo "End of Summary Report" >> "$summary_file"
    echo "===================================================" >> "$summary_file"

    print_success "Summary report generated: session_summary.txt"
}

# Generate retry script for failed devices
generate_retry_script() {
    if [ "$FAILURE_COUNT" -eq 0 ]; then
        return 0
    fi

    retry_script="${SESSION_DIR}/retry_failures.sh"

    cat > "$retry_script" << 'EOF'
#!/bin/sh
# Auto-generated retry script for failed devices
# Run this script to retry configuration extraction for devices that failed

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PARENT_DIR="$(dirname "$SCRIPT_DIR")"

EOF

    echo "# Failed devices from session: $SESSION_ID" >> "$retry_script"
    echo "FAILED_IPS=\"$(cut -d',' -f1 "$FAILURES_FILE" | tr '\n' ',' | sed 's/,$//')\"" >> "$retry_script"
    echo "" >> "$retry_script"

    cat >> "$retry_script" << 'EOF'
# Run the config gatherer with failed devices
"${PARENT_DIR}/../gather_network_configs.sh" --targets "$FAILED_IPS" "$@"
EOF

    chmod +x "$retry_script"
    print_info "Retry script generated: retry_failures.sh"
}

# Offer retry for failed devices
offer_retry() {
    if [ "$FAILURE_COUNT" -eq 0 ]; then
        return 0
    fi

    echo "" >&2
    print_warning "$FAILURE_COUNT device(s) failed during extraction"
    echo >&2
    if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
        printf "%sWould you like to retry failed devices with different credentials? (y/n): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
    else
        printf "Would you like to retry failed devices with different credentials? (y/n): \n" >&2
    fi
    read -r retry_response

    if [ "$retry_response" = "y" ] || [ "$retry_response" = "Y" ]; then
        print_info "Re-enter credentials for retry:"
        echo >&2
        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
            printf "%sUsername: %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
        else
            printf "Username: \n" >&2
        fi
        read -r new_user
        echo >&2
        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
            printf "%sPassword: %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
        else
            printf "Password: \n" >&2
        fi
        read -r new_pass
        echo >&2
        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
            printf "%sEnable (privileged) mode required? (y/n): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
        else
            printf "Enable (privileged) mode required? (y/n): \n" >&2
        fi
        read -r need_enable
        new_enable=""
        if [ "$need_enable" = "y" ] || [ "$need_enable" = "Y" ]; then
            echo >&2
            if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
                printf "%sEnable password: %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
            else
                printf "Enable password: \n" >&2
            fi
            read -r new_enable
        fi
        echo "" >&2

        # Extract failed IPs
        failed_ips=$(cut -d',' -f1 "$FAILURES_FILE")

        print_info "Retrying $(echo "$failed_ips" | wc -l) failed device(s)..."
        echo "" >&2

        # Retry each failed device
        for ip in $failed_ips; do
            [ -z "$ip" ] && continue

            print_step "Retrying $ip..."
            if process_device "$ip" "$new_user" "$new_pass" "$new_enable"; then
                SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
                FAILURE_COUNT=$((FAILURE_COUNT - 1))
            fi
        done

        print_success "Retry complete"
    fi
}

# Main execution
main() {
    log_info "=== Script started ===" "$SCRIPT_NAME"
    print_header

    # Parse arguments
    MODE="extract"
    TARGETS=""

    while [ $# -gt 0 ]; do
        case "$1" in
            --dry-run)
                DRY_RUN=1
                MODE="dry-run"
                shift
                ;;
            --concurrency)
                case "$2" in
                    ''|*[!0-9]*) log_error "Invalid --concurrency value: $2" "$SCRIPT_NAME"; echo "Error: --concurrency requires a positive integer" >&2; exit 1 ;;
                esac
                CONCURRENCY="$2"
                shift 2
                ;;
            --cred-mode)
                CRED_MODE="$2"
                shift 2
                ;;
            --cred-file)
                CRED_FILE="$2"
                shift 2
                ;;
            --targets)
                TARGETS="$2"
                shift 2
                ;;
            -h|--help)
                print_help
                exit 0
                ;;
            *)
                shift
                ;;
        esac
    done

    # Initialize session
    init_session

    # Get targets if not provided
    if [ -z "$TARGETS" ]; then
        print_info "Select target devices:"
        TARGETS=$(select_config_targets)

        if [ -z "$TARGETS" ]; then
            log_error "No targets selected" "$SCRIPT_NAME"
            print_error "No targets selected"
            exit 1
        fi
    fi

    log_info "Targets selected: $TARGETS" "$SCRIPT_NAME"
    print_success "Targets selected"

    # Get credentials based on mode
    if [ "$CRED_MODE" = "common" ]; then
        print_info "Enter common credentials for all devices:"
        echo >&2
        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
            printf "%sUsername: %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
        else
            printf "Username: \n" >&2
        fi
        read -r COMMON_USER
        echo >&2
        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
            printf "%sPassword: %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
        else
            printf "Password: \n" >&2
        fi
        read -r COMMON_PASS
        echo >&2
        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
            printf "%sEnable (privileged) mode required? (y/n): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
        else
            printf "Enable (privileged) mode required? (y/n): \n" >&2
        fi
        read -r need_enable
        if [ "$need_enable" = "y" ] || [ "$need_enable" = "Y" ]; then
            echo >&2
            if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
                printf "%sEnable password: %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
            else
                printf "Enable password: \n" >&2
            fi
            read -r COMMON_ENABLE
        fi
        echo "" >&2
    fi

    # Build device list
    if echo "$TARGETS" | grep -q "^-iL "; then
        # Host file
        host_file=$(echo "$TARGETS" | sed 's/^-iL //')
        device_list=$(cat "$host_file" | grep -v '^#' | grep -v '^$')
    else
        # Direct IP or range (simplified - just handle single IP for now)
        device_list="$TARGETS"
    fi

    total_devices=$(echo "$device_list" | wc -l)
    log_info "Processing $total_devices device(s) in $MODE mode, concurrency: $CONCURRENCY" "$SCRIPT_NAME"
    print_info "Processing $total_devices device(s) in $MODE mode with concurrency: $CONCURRENCY"
    echo "" >&2

    # Process devices concurrently
    results_dir=$(mktemp -d)
    active_pids=""
    active_count=0

    for ip in $device_list; do
        [ -z "$ip" ] && continue
        PROCESSED_COUNT=$((PROCESSED_COUNT + 1))
        result_file="${results_dir}/${ip}.result"

        (
            trap - EXIT INT TERM
            LEGACY_SSH_MODE=0
            SSH_OPTS_FILE=""
            SSH_REQUIRES_PTY=0
            trap '[ -n "$SSH_OPTS_FILE" ] && rm -f "$SSH_OPTS_FILE"' EXIT
            if process_device "$ip" "$COMMON_USER" "$COMMON_PASS" "$COMMON_ENABLE"; then
                echo "success" > "$result_file"
            else
                echo "failure" > "$result_file"
            fi
        ) &
        pid=$!
        active_pids="${active_pids}${pid} "
        active_count=$((active_count + 1))

        if [ "$active_count" -ge "$CONCURRENCY" ]; then
            oldest_pid=$(echo "$active_pids" | cut -d' ' -f1)
            wait "$oldest_pid" 2>/dev/null || true
            active_pids=$(echo "$active_pids" | cut -d' ' -f2-)
            active_count=$((active_count - 1))
        fi
    done

    # Wait for remaining jobs
    for pid in $active_pids; do
        [ -n "$pid" ] && { wait "$pid" 2>/dev/null || true; }
    done

    # Aggregate results
    for result_file in "${results_dir}"/*.result; do
        [ -f "$result_file" ] || continue
        if [ "$(cat "$result_file")" = "success" ]; then
            SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        fi
    done
    FAILURE_COUNT=$((PROCESSED_COUNT - SUCCESS_COUNT))
    rm -rf "$results_dir"

    # Generate summary
    echo "" >&2
    generate_summary
    generate_retry_script

    # Display summary
    print_header
    print_success "Processing Complete!"
    echo "" >&2
    printf "Total Devices:    %d\n" "$total_devices" >&2
    printf "Successful:       %d\n" "$SUCCESS_COUNT" >&2
    printf "Failed:           %d\n" "$FAILURE_COUNT" >&2
    echo "" >&2
    print_info "Results saved to: $SESSION_DIR"

    if [ "$FAILURE_COUNT" -gt 0 ]; then
        print_warning "Some devices failed. Check failures.txt for details."

        # Offer retry
        offer_retry

        # Regenerate summary after retry
        if [ "$FAILURE_COUNT" -gt 0 ]; then
            generate_summary
        fi
    fi

    log_info "Session complete: $SUCCESS_COUNT/$PROCESSED_COUNT devices succeeded" "$SCRIPT_NAME"
    echo "" >&2
    print_success "Session complete. Review session_summary.txt for full details."
}

# Run main
main "$@"
