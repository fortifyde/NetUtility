#!/bin/sh
#
# NetUtil File Server Setup Script
# Sets up HTTP file server with basic authentication for sharing scan results
# POSIX-compliant for maximum portability
#

set -e

# Source logging utilities
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/../common/logging.sh"
. "$SCRIPT_DIR/../common/colors.sh" 2>/dev/null || true

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
    echo "${BLUE}===================================================${NC}"
    echo "${BLUE}  NetUtil File Server Setup${NC}"
    echo "${BLUE}===================================================${NC}"
    echo ""
}

print_success() {
    echo "${GREEN}✓ $1${NC}"
}

print_error() {
    echo "${RED}✗ ERROR: $1${NC}" >&2
}

print_warning() {
    echo "${YELLOW}⚠ WARNING: $1${NC}"
}

print_info() {
    echo "${BLUE}ℹ $1${NC}"
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

    # Check relative to script location (scripts/host-config/)
    if [ -x "$(dirname "$0")/../../bin/netutil-fileserver" ]; then
        FILESERVER_BIN="$(dirname "$0")/../../bin/netutil-fileserver"
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
    # Check for config file relative to script location first (for development)
    CONFIG_FILE="$(dirname "$0")/../../netutil-config.json"
    if [ -f "$CONFIG_FILE" ]; then
        # Parse workspace_dir from JSON (POSIX-compliant, no jq needed)
        WORKSPACE=$(grep -o '"workspace_dir"[[:space:]]*:[[:space:]]*"[^"]*"' "$CONFIG_FILE" | sed 's/.*:[[:space:]]*"\(.*\)".*/\1/')
        if [ -n "$WORKSPACE" ] && [ -d "$WORKSPACE" ]; then
            printf "%s" "$WORKSPACE"
            return 0
        fi
    fi

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

        # Check for netutil-config.json in parent directory first (e.g., bin/../netutil-config.json)
        CONFIG_FILE="${NETUTIL_DIR}/../netutil-config.json"
        if [ -f "$CONFIG_FILE" ]; then
            # Parse workspace_dir from JSON (POSIX-compliant, no jq needed)
            WORKSPACE=$(grep -o '"workspace_dir"[[:space:]]*:[[:space:]]*"[^"]*"' "$CONFIG_FILE" | sed 's/.*:[[:space:]]*"\(.*\)".*/\1/')
            if [ -n "$WORKSPACE" ] && [ -d "$WORKSPACE" ]; then
                printf "%s" "$WORKSPACE"
                return 0
            fi
        fi

        # Check for netutil-config.json in the same directory as fallback
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

    echo >&2
    if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
        if [ -n "$default_value" ]; then
            printf "%s%s [%s]: %s\n" "$PROMPT_COLOR" "$prompt_text" "$default_value" "$COLOR_RESET" >&2
        else
            printf "%s%s: %s\n" "$PROMPT_COLOR" "$prompt_text" "$COLOR_RESET" >&2
        fi
    else
        if [ -n "$default_value" ]; then
            printf "%s [%s]: \n" "$prompt_text" "$default_value" >&2
        else
            printf "%s: \n" "$prompt_text" >&2
        fi
    fi

    read -r response

    if [ -z "$response" ] && [ -n "$default_value" ]; then
        printf "%s" "$default_value"
    else
        printf "%s" "$response"
    fi
}

# Prompt for password (visible in TUI but not logged)
prompt_password() {
    prompt_text="$1"

    echo >&2
    if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
        printf "%s%s: %s\n" "$PROMPT_COLOR" "$prompt_text" "$COLOR_RESET" >&2
    else
        printf "%s: \n" "$prompt_text" >&2
    fi
    read -r password
    echo "" >&2

    printf "%s" "$password"
}

# Main setup
main() {
    log_script_start "setup_file_server.sh" "$@"

    print_header
    check_root

    print_info "Checking for required binaries..."

    # Find fileserver binary
    if ! find_fileserver_binary; then
        log_error "netutil-fileserver binary not found" "setup_file_server.sh"
        print_error "netutil-fileserver binary not found"
        print_info "Please build it first with: make build"
        exit 1
    fi
    log_info "Found fileserver binary: $FILESERVER_BIN" "setup_file_server.sh"
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
    log_config_change "workspace_directory" "Workspace: $WORKSPACE" "setup_file_server.sh"
    print_success "Using workspace: $WORKSPACE"

    # Get configuration
    echo "" >&2
    echo "${BLUE}Configuration:${NC}" >&2
    PORT=$(prompt "Server port" "8080")
    log_config_change "server_port" "Port: $PORT" "setup_file_server.sh"
    LISTEN_ADDR=$(prompt "Listen address" "0.0.0.0")
    log_config_change "listen_address" "Listen address: $LISTEN_ADDR" "setup_file_server.sh"
    CREDS_FILE="$(readlink -f "$(dirname "$0")/../../fileserver.creds")"
    log_config_change "credentials_file" "Credentials file: $CREDS_FILE" "setup_file_server.sh"
    print_info "Credentials file: $CREDS_FILE"

    # TLS/HTTPS configuration
    ENABLE_TLS=$(prompt "Enable HTTPS/TLS encryption? (y/n)" "y")
    if [ "$ENABLE_TLS" = "y" ] || [ "$ENABLE_TLS" = "Y" ]; then
        USE_TLS=true
        CERT_FILE="$(readlink -f "$(dirname "$0")/../../cert.pem")"
        KEY_FILE="$(readlink -f "$(dirname "$0")/../../key.pem")"
        log_config_change "tls_enabled" "TLS enabled: true, Cert: $CERT_FILE, Key: $KEY_FILE" "setup_file_server.sh"
        print_info "TLS certificate: $CERT_FILE"
        print_info "TLS key: $KEY_FILE"
    else
        USE_TLS=false
        log_config_change "tls_enabled" "TLS enabled: false" "setup_file_server.sh"
        log_warn "TLS disabled - credentials will be transmitted in cleartext" "setup_file_server.sh"
        print_warning "TLS disabled - credentials will be transmitted in cleartext"
    fi

    # Create credentials directory if needed
    CREDS_DIR=$(dirname "$CREDS_FILE")
    if [ ! -d "$CREDS_DIR" ]; then
        mkdir -p "$CREDS_DIR"
        print_success "Created directory: $CREDS_DIR"
    fi

    # Create or append to credentials file
    echo ""
    echo "${BLUE}User Management:${NC}"
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
            log_security_event "user_overwrite" "User credentials updated: $USERNAME" "setup_file_server.sh"
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
        log_security_event "user_added" "User added: $USERNAME" "setup_file_server.sh"
        print_success "Added user: $USERNAME"

        ADD_USER=$(prompt "Add another user? (y/n)" "n")
    done

    # Generate TLS certificate if enabled
    if [ "$USE_TLS" = true ]; then
        echo ""
        print_info "Generating self-signed TLS certificate..."

        # Get hostname for certificate
        HOSTNAME=$(hostname -f 2>/dev/null || hostname)
        log_info "Generating TLS certificate for hostname: $HOSTNAME" "setup_file_server.sh"

        # Generate self-signed certificate valid for 365 days
        if command -v openssl >/dev/null 2>&1; then
            openssl req -x509 -newkey rsa:4096 -nodes \
                -keyout "$KEY_FILE" -out "$CERT_FILE" -days 365 \
                -subj "/CN=$HOSTNAME/O=NetUtil File Server/C=US" \
                -addext "subjectAltName=DNS:$HOSTNAME,DNS:localhost,IP:127.0.0.1" \
                2>/dev/null

            if [ $? -eq 0 ]; then
                chmod 600 "$KEY_FILE"
                chmod 644 "$CERT_FILE"
                log_config_change "tls_certificate_generated" "Certificate: $CERT_FILE, Key: $KEY_FILE, Hostname: $HOSTNAME, Valid: 365 days" "setup_file_server.sh"
                print_success "TLS certificate generated successfully"
                print_info "Certificate valid for 365 days"
                print_warning "Browsers will show security warnings for self-signed certificates"
            else
                log_error "Failed to generate TLS certificate" "setup_file_server.sh"
                print_error "Failed to generate certificate"
                exit 1
            fi
        else
            log_error "OpenSSL not found - cannot generate TLS certificate" "setup_file_server.sh"
            print_error "OpenSSL not found - cannot generate certificate"
            print_info "Install openssl and run this script again, or disable TLS"
            exit 1
        fi
    fi

    # Create systemd service file
    print_info "Creating systemd service..."
    SERVICE_FILE="/etc/systemd/system/netutil-fileserver.service"

    # Build ExecStart command with optional TLS flags
    EXEC_START="${FILESERVER_BIN} -workspace ${WORKSPACE} -credentials ${CREDS_FILE} -port ${PORT} -addr ${LISTEN_ADDR}"
    READ_ONLY_PATHS="${CREDS_FILE}"

    if [ "$USE_TLS" = true ]; then
        EXEC_START="${EXEC_START} -tls-cert ${CERT_FILE} -tls-key ${KEY_FILE}"
        READ_ONLY_PATHS="${READ_ONLY_PATHS} ${CERT_FILE} ${KEY_FILE}"
    fi

    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=NetUtil File Server
After=network.target
Documentation=https://github.com/fortifyde/NetUtility

[Service]
Type=simple
User=root
ExecStart=${EXEC_START}
Restart=on-failure
RestartSec=5s

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${WORKSPACE}
ReadOnlyPaths=${READ_ONLY_PATHS}

[Install]
WantedBy=multi-user.target
EOF

    chmod 644 "$SERVICE_FILE"
    log_config_change "systemd_service_created" "Created service file: $SERVICE_FILE" "setup_file_server.sh"
    print_success "Created service file: $SERVICE_FILE"

    # Reload systemd
    print_info "Reloading systemd daemon..."
    systemctl daemon-reload
    log_command_result "systemctl daemon-reload" 0 "setup_file_server.sh"
    print_success "Systemd reloaded"

    # Enable and start service
    ENABLE=$(prompt "Enable service to start on boot? (y/n)" "y")
    if [ "$ENABLE" = "y" ] || [ "$ENABLE" = "Y" ]; then
        systemctl enable netutil-fileserver.service
        log_config_change "service_enabled" "Service enabled for auto-start" "setup_file_server.sh"
        print_success "Service enabled for auto-start"
    fi

    START=$(prompt "Start service now? (y/n)" "y")
    if [ "$START" = "y" ] || [ "$START" = "Y" ]; then
        systemctl start netutil-fileserver.service
        sleep 1

        if systemctl is-active --quiet netutil-fileserver.service; then
            log_command_result "systemctl start netutil-fileserver.service" 0 "setup_file_server.sh"
            print_success "Service started successfully"
        else
            log_error "Service failed to start - check journalctl for details" "setup_file_server.sh"
            print_error "Service failed to start"
            print_info "Check logs with: journalctl -u netutil-fileserver.service -n 50"
            exit 1
        fi
    fi

    # Display access information
    echo ""
    echo "${GREEN}===================================================${NC}"
    echo "${GREEN}  Setup Complete!${NC}"
    echo "${GREEN}===================================================${NC}"
    echo ""

    # Get primary IP address
    PRIMARY_IP=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[^ ]+' || echo "YOUR_IP")

    # Determine protocol
    if [ "$USE_TLS" = true ]; then
        PROTOCOL="https"
    else
        PROTOCOL="http"
    fi

    echo "${BLUE}Access Information:${NC}"
    echo "  Local:     $PROTOCOL://localhost:$PORT"
    echo "  Network:   $PROTOCOL://$PRIMARY_IP:$PORT"
    echo "  All IPs:   $PROTOCOL://$LISTEN_ADDR:$PORT"
    echo ""

    if [ "$USE_TLS" = true ]; then
        echo "${YELLOW}TLS/HTTPS Enabled:${NC}"
        echo "  - Browsers will show a security warning (self-signed certificate)"
        echo "  - Click 'Advanced' → 'Accept Risk and Continue' to proceed"
        echo "  - Certificate is valid for $HOSTNAME, localhost, and 127.0.0.1"
        echo "  - All traffic including credentials is encrypted"
        echo ""
    else
        echo "${YELLOW}WARNING - No TLS:${NC}"
        echo "  - Credentials are transmitted in CLEARTEXT"
        echo "  - Use only on isolated/trusted networks"
        echo "  - Consider SSH tunneling for added security"
        echo ""
    fi

    echo "${BLUE}Service Management:${NC}"
    echo "  Status:    systemctl status netutil-fileserver"
    echo "  Start:     systemctl start netutil-fileserver"
    echo "  Stop:      systemctl stop netutil-fileserver"
    echo "  Restart:   systemctl restart netutil-fileserver"
    echo "  Logs:      journalctl -u netutil-fileserver -f"
    echo ""

    echo "${BLUE}Add More Users:${NC}"
    echo "  1. Generate hash: $FILESERVER_BIN -hash 'password'"
    echo "  2. Add to file:   echo 'username:hash' >> $CREDS_FILE"
    echo "  3. Restart:       systemctl restart netutil-fileserver"
    echo ""

    print_success "NetUtil File Server is ready!"
    log_script_end "setup_file_server.sh" 0
}

main "$@"
