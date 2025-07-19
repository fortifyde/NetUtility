#!/bin/sh

echo "=== Working Directory Selection ==="
echo "Current working directory: $(pwd)"
echo "Home directory: $HOME"
echo

echo "Available directories:"
ls -la /home/

echo
echo "Enter the full path to your desired working directory (or press Enter for current directory):"
read -r workdir

# Use current directory as default if no input provided
if [ -z "$workdir" ]; then
    workdir="$(pwd)"
    echo "No input provided, using current directory: $workdir"
fi

if [ -d "$workdir" ]; then
    export NETUTIL_WORKDIR="$workdir"
    echo "Working directory set to: $workdir"
    
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
            fi
        else
            echo "Warning: Could not locate NetUtility config file"
        fi
    }
    
    # Update the configuration
    update_netutil_config
    
    # Create workspace structure
    echo "Creating workspace structure..."
    mkdir -p "$workdir/captures" "$workdir/enumeration" "$workdir/vulnerability" "$workdir/configs" "$workdir/logs" "$workdir/latest"
    echo "Workspace structure created"
    
    cd "$workdir" || exit 1
    echo "Changed to directory: $(pwd)"
    exit 0
else
    echo "Error: Directory '$workdir' does not exist"
    exit 1
fi