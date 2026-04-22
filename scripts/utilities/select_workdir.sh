#!/bin/sh

. "$(dirname "$0")/../common/colors.sh" 2>/dev/null || true
. "$(dirname "$0")/../common/utils.sh" 2>/dev/null || true
. "$(dirname "$0")/../common/logging.sh" 2>/dev/null || true
. "$(dirname "$0")/../common/validation.sh"
SCRIPT_NAME="$(basename "$0")"

echo "=== Working Directory Selection ==="
log_info "=== Script started ===" "$SCRIPT_NAME"
echo "Current working directory: $(pwd)"
echo "Home directory: $HOME"
echo >&2

echo "Available directories:"
ls -la /home/

echo >&2
echo >&2

while true; do
    workdir=$(get_validated_input "Enter the full path to your desired working directory" "" "$(pwd)")
    if [ -d "$workdir" ]; then
        break
    fi
    echo "Directory '$workdir' does not exist. Please try again." >&2
done

export NETUTIL_WORKDIR="$workdir"
echo "Working directory set to: $workdir"
log_info "Working directory set to: $workdir" "$SCRIPT_NAME"
    
# Update NetUtility config file with new workspace directory
update_netutil_config() {
    # Find netutil executable directory
    if [ -n "$NETUTIL_EXEC_DIR" ]; then
        config_file="$NETUTIL_EXEC_DIR/netutil-config.json"
    else
        # Try to find netutil in common locations
        for dir in "$(pwd)" "$(dirname "$0")/../.." "/usr/local/bin" "$HOME/.local/bin"; do
            if [ -f "$dir/netutil" ] || [ -f "$dir/netutil-config.json" ]; then
                config_file="$dir/netutil-config.json"
                break
            fi
        done
    fi
    if [ -n "$config_file" ]; then
        # Create or update config file
        if [ -f "$config_file" ]; then
            # Update existing config using temporary file
            tmp_file=$(mktemp)
            # Simple JSON update - replace workspace_dir value
            sed "s|\"workspace_dir\":[^,]*|\"workspace_dir\": \"$workdir\"|" "$config_file" > "$tmp_file"
            mv "$tmp_file" "$config_file"
            echo "Updated NetUtility configuration: $config_file"
            log_info "Config updated: $config_file" "$SCRIPT_NAME"
        else
            # Create new config file
            cat > "$config_file" << EOF
{
  "last_used_interface": {},
  "recent_targets": [],
  "workspace_dir": "$workdir",
  "recent_commands": [],
  "default_interface": "",
  "auto_create_workspace": false,
  "show_paths_short": true
}
EOF
            echo "Created NetUtility configuration: $config_file"
            log_info "Config created: $config_file" "$SCRIPT_NAME"
        fi
    else
        echo "Warning: Could not locate NetUtility config file"
    fi
}
    
# Update the configuration
update_netutil_config
    
# Create workspace structure
echo "Creating workspace structure..."
mkdir -p "$workdir/captures" "$workdir/discovery" "$workdir/port_and_security_scans" "$workdir/analysis" "$workdir/reports" "$workdir/configs" "$workdir/logs" "$workdir/latest"
fix_ownership "$workdir"
echo "Workspace structure created"
    
if ! cd "$workdir"; then
    log_error "Failed to change to directory: $workdir" "$SCRIPT_NAME"
    exit 1
fi
echo "Changed to directory: $(pwd)"
exit 0
