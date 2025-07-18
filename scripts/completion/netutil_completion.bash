#!/bin/bash

# NetUtility bash completion script
# To install: source this file or add to ~/.bashrc or ~/.bash_profile
# Usage: source netutil_completion.bash

_netutil_completion() {
    local cur prev words cword
    _init_completion || return

    # Available commands
    local commands="
        scan enum capture vuln vulnerability config-ip ip interfaces
        routes dns backup restore workdir vlan protocols categorize
        vlans analysis device-config help list recent
    "
    
    # Numeric shortcuts
    local numeric_shortcuts="1 2 3 4 5"
    
    # Options
    local options="--help -h --list -l --recent -r"
    
    # Complete first argument
    if [[ $cword -eq 1 ]]; then
        # Combine all available completions
        local all_completions="$commands $numeric_shortcuts $options"
        COMPREPLY=($(compgen -W "$all_completions" -- "$cur"))
        return 0
    fi
    
    # Handle specific commands if needed
    case "${words[1]}" in
        help|--help|-h)
            # No additional completion for help
            return 0
            ;;
        list|--list|-l)
            # No additional completion for list
            return 0
            ;;
        recent|--recent|-r)
            # No additional completion for recent
            return 0
            ;;
        *)
            # For other commands, no additional completion for now
            return 0
            ;;
    esac
}

# Register the completion function
complete -F _netutil_completion netutil

# Also provide some helpful aliases
alias nu='netutil'
alias netutil-scan='netutil scan'
alias netutil-capture='netutil capture'
alias netutil-vuln='netutil vuln'
alias netutil-ip='netutil ip'
alias netutil-interfaces='netutil interfaces'

# Export completion for use in scripts
export -f _netutil_completion