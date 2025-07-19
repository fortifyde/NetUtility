#!/bin/bash

# Enhanced NetUtility bash completion script with dynamic discovery
# To install: source this file or add to ~/.bashrc or ~/.bash_profile
# Usage: source netutil_completion_enhanced.bash

# Function to get available commands dynamically
_netutil_get_commands() {
    local netutil_path
    
    # Find netutil executable
    if command -v netutil >/dev/null 2>&1; then
        netutil_path="netutil"
    elif [[ -x "./netutil" ]]; then
        netutil_path="./netutil"
    else
        # Fallback to hardcoded commands
        echo "scan enum capture vuln vulnerability config-ip ip interfaces routes dns backup restore workdir vlan protocols categorize vlans analysis device-config"
        return
    fi
    
    # Get commands from netutil --list if available
    if [[ -n "$netutil_path" ]]; then
        local commands
        commands=$($netutil_path --list 2>/dev/null | grep -E "^[[:space:]]*[a-zA-Z0-9-]+[[:space:]]+" | awk '{print $1}' | tr '\n' ' ')
        
        if [[ -n "$commands" ]]; then
            echo "$commands"
            return
        fi
    fi
    
    # Fallback to hardcoded commands
    echo "scan enum capture vuln vulnerability config-ip ip interfaces routes dns backup restore workdir vlan protocols categorize vlans analysis device-config"
}

# Function to get numeric shortcuts
_netutil_get_numeric_shortcuts() {
    local netutil_path
    
    # Find netutil executable
    if command -v netutil >/dev/null 2>&1; then
        netutil_path="netutil"
    elif [[ -x "./netutil" ]]; then
        netutil_path="./netutil"
    else
        echo "1 2 3 4 5"
        return
    fi
    
    # Get numeric shortcuts from netutil --list
    if [[ -n "$netutil_path" ]]; then
        local shortcuts
        shortcuts=$($netutil_path --list 2>/dev/null | grep -E "^[[:space:]]*[0-9]+[[:space:]]+" | awk '{print $1}' | tr '\n' ' ')
        
        if [[ -n "$shortcuts" ]]; then
            echo "$shortcuts"
            return
        fi
    fi
    
    # Fallback
    echo "1 2 3 4 5"
}

# Function to get recent commands
_netutil_get_recent_commands() {
    local netutil_path
    
    # Find netutil executable
    if command -v netutil >/dev/null 2>&1; then
        netutil_path="netutil"
    elif [[ -x "./netutil" ]]; then
        netutil_path="./netutil"
    else
        return
    fi
    
    # Get recent commands
    if [[ -n "$netutil_path" ]]; then
        local recent
        recent=$($netutil_path --recent 2>/dev/null | grep -v "Recent Commands:" | sed 's/^[[:space:]]*[✓✗][[:space:]]*[0-9:]*[[:space:]]*//' | tr '\n' ' ')
        echo "$recent"
    fi
}

# Function to complete file paths for specific arguments
_netutil_complete_file() {
    local file_type="$1"
    local cur="$2"
    
    case "$file_type" in
        "capture")
            # Complete .pcap files in workspace/captures
            local captures_dir
            if [[ -n "$NETUTIL_WORKDIR" ]]; then
                captures_dir="$NETUTIL_WORKDIR/captures"
            else
                captures_dir="$HOME/captures"
            fi
            
            if [[ -d "$captures_dir" ]]; then
                COMPREPLY=($(compgen -f -X "!*.pcap" -- "$captures_dir/$cur"))
            fi
            ;;
        "hosts")
            # Complete host files
            local enum_dir
            if [[ -n "$NETUTIL_WORKDIR" ]]; then
                enum_dir="$NETUTIL_WORKDIR/enumeration"
            else
                enum_dir="$HOME/enumeration"
            fi
            
            if [[ -d "$enum_dir" ]]; then
                COMPREPLY=($(compgen -f -X "!hosts_*.txt" -- "$enum_dir/$cur"))
            fi
            ;;
        "config")
            # Complete configuration files
            local config_dir
            if [[ -n "$NETUTIL_WORKDIR" ]]; then
                config_dir="$NETUTIL_WORKDIR/configs"
            else
                config_dir="$HOME/configs"
            fi
            
            if [[ -d "$config_dir" ]]; then
                COMPREPLY=($(compgen -f -- "$config_dir/$cur"))
            fi
            ;;
        *)
            # Default file completion
            COMPREPLY=($(compgen -f -- "$cur"))
            ;;
    esac
}

# Function to complete network interfaces
_netutil_complete_interfaces() {
    local cur="$1"
    local interfaces
    
    # Get network interfaces using ip command
    if command -v ip >/dev/null 2>&1; then
        interfaces=$(ip link show | grep -E "^[0-9]+:" | sed 's/^[0-9]*: *\([^:]*\):.*/\1/' | grep -v lo | tr '\n' ' ')
        COMPREPLY=($(compgen -W "$interfaces" -- "$cur"))
    fi
}

# Function to complete IP addresses and ranges
_netutil_complete_ip() {
    local cur="$1"
    local suggestions
    
    # Suggest common private IP ranges
    suggestions="192.168.1.0/24 192.168.0.0/24 10.0.0.0/8 172.16.0.0/12"
    
    # Add auto-detected ranges if possible
    if command -v ip >/dev/null 2>&1; then
        local detected_ranges
        detected_ranges=$(ip route | grep -E "192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\." | grep -v default | awk '{print $1}' | head -3 | tr '\n' ' ')
        suggestions="$detected_ranges $suggestions"
    fi
    
    COMPREPLY=($(compgen -W "$suggestions" -- "$cur"))
}

# Main completion function
_netutil_completion() {
    local cur prev words cword
    _init_completion || return
    
    # Cache commands for performance (refresh every 60 seconds)
    local cache_file="/tmp/.netutil_completion_cache_$$"
    local cache_age=0
    
    if [[ -f "$cache_file" ]]; then
        cache_age=$(($(date +%s) - $(stat -c %Y "$cache_file" 2>/dev/null || echo 0)))
    fi
    
    local commands numeric_shortcuts options
    
    if [[ ! -f "$cache_file" || $cache_age -gt 60 ]]; then
        # Refresh cache
        commands=$(_netutil_get_commands)
        numeric_shortcuts=$(_netutil_get_numeric_shortcuts)
        options="--help -h --list -l --recent -r --version -v"
        
        # Cache the results
        {
            echo "commands=\"$commands\""
            echo "numeric_shortcuts=\"$numeric_shortcuts\""
            echo "options=\"$options\""
        } > "$cache_file"
    else
        # Load from cache
        source "$cache_file"
    fi
    
    # Complete first argument (command selection)
    if [[ $cword -eq 1 ]]; then
        local all_completions="$commands $numeric_shortcuts $options"
        
        # Add recent commands as suggestions
        local recent_commands
        recent_commands=$(_netutil_get_recent_commands)
        if [[ -n "$recent_commands" ]]; then
            all_completions="$recent_commands $all_completions"
        fi
        
        COMPREPLY=($(compgen -W "$all_completions" -- "$cur"))
        return 0
    fi
    
    # Handle command-specific completion
    local command="${words[1]}"
    
    case "$command" in
        # Commands that need help
        help|--help|-h)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=($(compgen -W "$commands" -- "$cur"))
            fi
            return 0
            ;;
            
        # No additional args
        list|--list|-l|recent|--recent|-r|--version|-v)
            return 0
            ;;
            
        # Commands with specific argument types
        scan|enum|1)
            case "$prev" in
                -t|--target)
                    _netutil_complete_ip "$cur"
                    return 0
                    ;;
                -i|--interface)
                    _netutil_complete_interfaces "$cur"
                    return 0
                    ;;
                *)
                    if [[ $cword -eq 2 ]]; then
                        COMPREPLY=($(compgen -W "-t --target -i --interface -s --scan-type --timeout --help" -- "$cur"))
                    fi
                    ;;
            esac
            ;;
            
        capture|2)
            case "$prev" in
                -i|--interface)
                    _netutil_complete_interfaces "$cur"
                    return 0
                    ;;
                -f|--file)
                    _netutil_complete_file "capture" "$cur"
                    return 0
                    ;;
                *)
                    if [[ $cword -eq 2 ]]; then
                        COMPREPLY=($(compgen -W "-i --interface -d --duration -f --file --help" -- "$cur"))
                    fi
                    ;;
            esac
            ;;
            
        vuln|vulnerability|3)
            case "$prev" in
                -t|--target)
                    _netutil_complete_ip "$cur"
                    return 0
                    ;;
                -f|--file)
                    _netutil_complete_file "hosts" "$cur"
                    return 0
                    ;;
                *)
                    if [[ $cword -eq 2 ]]; then
                        COMPREPLY=($(compgen -W "-t --target -f --file -s --scan-type --timeout --help" -- "$cur"))
                    fi
                    ;;
            esac
            ;;
            
        config-ip|ip|4)
            case "$prev" in
                -i|--interface)
                    _netutil_complete_interfaces "$cur"
                    return 0
                    ;;
                *)
                    if [[ $cword -eq 2 ]]; then
                        COMPREPLY=($(compgen -W "-i --interface -a --add -r --remove --flush --help" -- "$cur"))
                    fi
                    ;;
            esac
            ;;
            
        interfaces|5)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=($(compgen -W "--help -h" -- "$cur"))
            fi
            ;;
            
        backup|restore)
            case "$prev" in
                -f|--file)
                    _netutil_complete_file "config" "$cur"
                    return 0
                    ;;
                *)
                    if [[ $cword -eq 2 ]]; then
                        COMPREPLY=($(compgen -W "-f --file --help" -- "$cur"))
                    fi
                    ;;
            esac
            ;;
            
        device-config)
            case "$prev" in
                -h|--host)
                    _netutil_complete_ip "$cur"
                    return 0
                    ;;
                *)
                    if [[ $cword -eq 2 ]]; then
                        COMPREPLY=($(compgen -W "-h --host -u --username -p --password --help" -- "$cur"))
                    fi
                    ;;
            esac
            ;;
            
        *)
            # Generic completion for unknown commands
            if [[ $cur == -* ]]; then
                COMPREPLY=($(compgen -W "--help -h" -- "$cur"))
            fi
            ;;
    esac
}

# Function to clean up cache on shell exit
_netutil_cleanup_cache() {
    rm -f "/tmp/.netutil_completion_cache_$$" 2>/dev/null
}

# Register cleanup
trap _netutil_cleanup_cache EXIT

# Register the completion function
complete -F _netutil_completion netutil

# Enhanced aliases with completion support
alias nu='netutil'
alias netutil-scan='netutil scan'
alias netutil-capture='netutil capture'
alias netutil-vuln='netutil vuln'
alias netutil-ip='netutil ip'
alias netutil-interfaces='netutil interfaces'

# Enable completion for aliases
complete -F _netutil_completion nu
complete -F _netutil_completion netutil-scan
complete -F _netutil_completion netutil-capture
complete -F _netutil_completion netutil-vuln
complete -F _netutil_completion netutil-ip
complete -F _netutil_completion netutil-interfaces

# Export functions for use in scripts
export -f _netutil_completion
export -f _netutil_get_commands
export -f _netutil_get_numeric_shortcuts
export -f _netutil_get_recent_commands

echo "Enhanced NetUtility bash completion loaded successfully!"
echo "Available features:"
echo "  - Dynamic command discovery"
echo "  - Smart argument completion"
echo "  - Recent command suggestions"
echo "  - Interface and IP completion"
echo "  - File path completion"
echo "  - Performance caching"