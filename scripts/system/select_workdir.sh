#!/bin/bash

echo "=== Working Directory Selection ==="
echo "Current working directory: $(pwd)"
echo "Home directory: $HOME"
echo

echo "Available directories:"
ls -la /home/

echo
echo "Enter the full path to your desired working directory:"
read -r workdir

if [ -d "$workdir" ]; then
    export NETUTIL_WORKDIR="$workdir"
    echo "Working directory set to: $workdir"
    cd "$workdir" || exit 1
    echo "Changed to directory: $(pwd)"
else
    echo "Error: Directory $workdir does not exist"
    exit 1
fi