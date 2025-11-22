#!/bin/sh
#
# NetUtil File Server Setup Script
# Sets up HTTP file server with basic authentication for sharing scan results
# POSIX-compliant for maximum portability
#

set -e

# Color output (with fallback for non-color terminals)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

print_header() {
    printf "${BLUE}===================================================${NC}\n"
    printf "${BLUE}  NetUtil File Server Setup${NC}\n"
    printf "${BLUE}===================================================${NC}\n\n"
}

print_success() {
    printf "${GREEN}✓ %s${NC}\n" "$1"
}

print_error() {
    printf "${RED}✗ ERROR: %s${NC}\n" "$1" >&2
}

print_warning() {
    printf "${YELLOW}⚠ WARNING: %s${NC}\n" "$1"
}

print_info() {
    printf "${BLUE}ℹ %s${NC}\n" "$1"
}

# Check if running as root
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        print_error "This script must be run as root (for systemd service installation)"
        exit 1
    fi
}

# Find fileserver binary
find_fileserver_binary() {
    # Check in PATH
    if command -v netutil-fileserver >/dev/null 2>&1; then
        FILESERVER_BIN="$(command -v netutil-fileserver)"
        return 0
    fi

    # Check common installation locations
    for path in /usr/local/bin/netutil-fileserver /usr/bin/netutil-fileserver /opt/netutil/bin/netutil-fileserver; do
        if [ -x "$path" ]; then
            FILESERVER_BIN="$path"
            return 0
        fi
    done

    return 1
}

# Get workspace directory from netutil config
get_workspace_dir() {
    # Find netutil binary to locate config file
    NETUTIL_BIN=""

    # Check in PATH first
    if command -v netutil >/dev/null 2>&1; then
        NETUTIL_BIN="$(command -v netutil)"
    else
        # Check common installation locations
        for path in /usr/local/bin/netutil /usr/bin/netutil /opt/netutil/bin/netutil; do
            if [ -x "$path" ]; then
                NETUTIL_BIN="$path"
                break
            fi
        done
    fi

    if [ -n "$NETUTIL_BIN" ]; then
        # Get directory where netutil binary is located
        NETUTIL_DIR="$(dirname "$NETUTIL_BIN")"

        # Check for netutil-config.json in the same directory
        CONFIG_FILE="${NETUTIL_DIR}/netutil-config.json"

        if [ -f "$CONFIG_FILE" ]; then
            # Parse workspace_dir from JSON (POSIX-compliant, no jq needed)
            WORKSPACE=$(grep -o '"workspace_dir"[[:space:]]*:[[:space:]]*"[^"]*"' "$CONFIG_FILE" | sed 's/.*:[[:space:]]*"\(.*\)".*/\1/')
            if [ -n "$WORKSPACE" ] && [ -d "$WORKSPACE" ]; then
                printf "%s" "$WORKSPACE"
                return 0
            fi
        fi
    fi

    # Check common default location
    if [ -d "/opt/netutil/workspace" ]; then
        printf "/opt/netutil/workspace"
        return 0
    fi

    return 1
}

# Prompt for user input
prompt() {
    prompt_text="$1"
    default_value="$2"

    if [ -n "$default_value" ]; then
        printf "%s [%s]: " "$prompt_text" "$default_value"
    else
        printf "%s: " "$prompt_text"
    fi

    read -r response

    if [ -z "$response" ] && [ -n "$default_value" ]; then
        printf "%s" "$default_value"
    else
        printf "%s" "$response"
    fi
}

# Prompt for password (no echo)
prompt_password() {
    prompt_text="$1"

    printf "%s: " "$prompt_text"
    stty -echo
    read -r password
    stty echo
    printf "\n"

    printf "%s" "$password"
}

# Main setup
main() {
    print_header
    check_root

    print_info "Checking for required binaries..."

    # Find fileserver binary
    if ! find_fileserver_binary; then
        print_error "netutil-fileserver binary not found"
        print_info "Please build it first with: make build"
        exit 1
    fi
    print_success "Found fileserver: $FILESERVER_BIN"

    # Get workspace directory
    print_info "Determining workspace directory..."
    WORKSPACE=$(get_workspace_dir)
    if [ -z "$WORKSPACE" ]; then
        WORKSPACE=$(prompt "Enter workspace directory path" "/opt/netutil/workspace")
    fi

    if [ ! -d "$WORKSPACE" ]; then
        print_error "Workspace directory does not exist: $WORKSPACE"
        exit 1
    fi
    WORKSPACE=$(readlink -f "$WORKSPACE")
    print_success "Using workspace: $WORKSPACE"

    # Get configuration
    printf "\n${BLUE}Configuration:${NC}\n"
    PORT=$(prompt "Server port" "8080")
    LISTEN_ADDR=$(prompt "Listen address" "0.0.0.0")
    CREDS_FILE=$(prompt "Credentials file path" "/etc/netutil/fileserver.creds")

    # Create credentials directory if needed
    CREDS_DIR=$(dirname "$CREDS_FILE")
    if [ ! -d "$CREDS_DIR" ]; then
        mkdir -p "$CREDS_DIR"
        print_success "Created directory: $CREDS_DIR"
    fi

    # Create or append to credentials file
    printf "\n${BLUE}User Management:${NC}\n"
    if [ -f "$CREDS_FILE" ]; then
        print_warning "Credentials file already exists: $CREDS_FILE"
        ADD_USER=$(prompt "Add another user? (y/n)" "y")
    else
        ADD_USER="y"
        touch "$CREDS_FILE"
        chmod 600 "$CREDS_FILE"
        print_success "Created credentials file: $CREDS_FILE"
    fi

    while [ "$ADD_USER" = "y" ] || [ "$ADD_USER" = "Y" ]; do
        USERNAME=$(prompt "Username")
        if [ -z "$USERNAME" ]; then
            print_error "Username cannot be empty"
            continue
        fi

        # Check if user already exists
        if grep -q "^${USERNAME}:" "$CREDS_FILE" 2>/dev/null; then
            print_warning "User '$USERNAME' already exists"
            OVERWRITE=$(prompt "Overwrite? (y/n)" "n")
            if [ "$OVERWRITE" != "y" ] && [ "$OVERWRITE" != "Y" ]; then
                continue
            fi
            # Remove existing entry
            sed -i "/^${USERNAME}:/d" "$CREDS_FILE"
        fi

        PASSWORD=$(prompt_password "Password")
        if [ -z "$PASSWORD" ]; then
            print_error "Password cannot be empty"
            continue
        fi

        PASSWORD_CONFIRM=$(prompt_password "Confirm password")
        if [ "$PASSWORD" != "$PASSWORD_CONFIRM" ]; then
            print_error "Passwords do not match"
            continue
        fi

        # Hash password using fileserver binary
        print_info "Hashing password..."
        HASH=$(printf "%s" "$PASSWORD" | "$FILESERVER_BIN" -hash -)
        if [ -z "$HASH" ]; then
            print_error "Failed to hash password"
            continue
        fi

        # Add to credentials file
        printf "%s:%s\n" "$USERNAME" "$HASH" >> "$CREDS_FILE"
        print_success "Added user: $USERNAME"

        ADD_USER=$(prompt "Add another user? (y/n)" "n")
    done

    # Create systemd service file
    print_info "Creating systemd service..."
    SERVICE_FILE="/etc/systemd/system/netutil-fileserver.service"

    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=NetUtil File Server
After=network.target
Documentation=https://github.com/yourusername/netutil

[Service]
Type=simple
User=root
ExecStart=${FILESERVER_BIN} -workspace ${WORKSPACE} -credentials ${CREDS_FILE} -port ${PORT} -addr ${LISTEN_ADDR}
Restart=on-failure
RestartSec=5s

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${WORKSPACE}
ReadOnlyPaths=${CREDS_FILE}

[Install]
WantedBy=multi-user.target
EOF

    chmod 644 "$SERVICE_FILE"
    print_success "Created service file: $SERVICE_FILE"

    # Reload systemd
    print_info "Reloading systemd daemon..."
    systemctl daemon-reload
    print_success "Systemd reloaded"

    # Enable and start service
    ENABLE=$(prompt "Enable service to start on boot? (y/n)" "y")
    if [ "$ENABLE" = "y" ] || [ "$ENABLE" = "Y" ]; then
        systemctl enable netutil-fileserver.service
        print_success "Service enabled for auto-start"
    fi

    START=$(prompt "Start service now? (y/n)" "y")
    if [ "$START" = "y" ] || [ "$START" = "Y" ]; then
        systemctl start netutil-fileserver.service
        sleep 1

        if systemctl is-active --quiet netutil-fileserver.service; then
            print_success "Service started successfully"
        else
            print_error "Service failed to start"
            print_info "Check logs with: journalctl -u netutil-fileserver.service -n 50"
            exit 1
        fi
    fi

    # Display access information
    printf "\n${GREEN}===================================================${NC}\n"
    printf "${GREEN}  Setup Complete!${NC}\n"
    printf "${GREEN}===================================================${NC}\n\n"

    # Get primary IP address
    PRIMARY_IP=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[^ ]+' || echo "YOUR_IP")

    printf "${BLUE}Access Information:${NC}\n"
    printf "  Local:     http://localhost:%s\n" "$PORT"
    printf "  Network:   http://%s:%s\n" "$PRIMARY_IP" "$PORT"
    printf "  All IPs:   http://%s:%s\n\n" "$LISTEN_ADDR" "$PORT"

    printf "${BLUE}Service Management:${NC}\n"
    printf "  Status:    systemctl status netutil-fileserver\n"
    printf "  Start:     systemctl start netutil-fileserver\n"
    printf "  Stop:      systemctl stop netutil-fileserver\n"
    printf "  Restart:   systemctl restart netutil-fileserver\n"
    printf "  Logs:      journalctl -u netutil-fileserver -f\n\n"

    printf "${BLUE}Add More Users:${NC}\n"
    printf "  1. Generate hash: %s -hash 'password'\n" "$FILESERVER_BIN"
    printf "  2. Add to file:   echo 'username:hash' >> %s\n" "$CREDS_FILE"
    printf "  3. Restart:       systemctl restart netutil-fileserver\n\n"

    printf "${YELLOW}Network Configuration (Manual):${NC}\n"
    printf "  To enable access across VLANs, configure your router/firewall:\n"
    printf "  1. Allow traffic to %s:%s from all VLANs\n" "$PRIMARY_IP" "$PORT"
    printf "  2. Example iptables rule:\n"
    printf "     iptables -A INPUT -p tcp --dport %s -j ACCEPT\n" "$PORT"
    printf "  3. Configure inter-VLAN routing on your Layer 3 switch\n"
    printf "  4. Add ACLs to permit HTTP traffic to this host\n\n"

    print_success "NetUtil File Server is ready!"
}

main "$@"
