#!/bin/bash

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
    cd "$workdir" || exit 1
    echo "Changed to directory: $(pwd)"
    exit 0
else
    echo "Error: Directory '$workdir' does not exist"
    exit 1
fi