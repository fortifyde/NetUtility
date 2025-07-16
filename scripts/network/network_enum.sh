#!/bin/bash

echo "=== Network Enumeration ==="
echo

RESULTS_DIR="${NETUTIL_WORKDIR:-$HOME}/enumeration"
mkdir -p "$RESULTS_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "Network enumeration options:"
echo "1. Quick network discovery"
echo "2. Detailed network scan"
echo "3. Custom IP range scan"
echo "4. Exit"

read -p "Select option (1-4): " option

case $option in
    1)
        echo "Performing quick network discovery..."
        
        echo "Detecting local networks..."
        networks=$(ip route | grep -E "192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\." | grep -v default | awk '{print $1}' | head -5)
        
        if [ -z "$networks" ]; then
            echo "No private networks found, using default ranges"
            networks="192.168.1.0/24 192.168.0.0/24 10.0.0.0/24"
        fi
        
        echo "Networks to scan: $networks"
        ;;
    2)
        echo "Performing detailed network scan..."
        
        networks=$(ip route | grep -E "192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\." | grep -v default | awk '{print $1}' | head -3)
        
        if [ -z "$networks" ]; then
            echo "No private networks found"
            exit 1
        fi
        
        echo "Networks to scan: $networks"
        ;;
    3)
        read -p "Enter IP range (e.g., 192.168.1.0/24): " custom_range
        if [[ ! $custom_range =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
            echo "Error: Invalid IP range format"
            exit 1
        fi
        networks="$custom_range"
        ;;
    4)
        echo "Exiting..."
        exit 0
        ;;
    *)
        echo "Invalid option"
        exit 1
        ;;
esac

PING_RESULTS="$RESULTS_DIR/ping_results_${TIMESTAMP}.txt"
NMAP_RESULTS="$RESULTS_DIR/nmap_results_${TIMESTAMP}.txt"
HOST_SUMMARY="$RESULTS_DIR/host_summary_${TIMESTAMP}.txt"

echo "Results will be saved to: $RESULTS_DIR"
echo

echo "=== Network Enumeration Report ===" > "$HOST_SUMMARY"
echo "Scan time: $(date)" >> "$HOST_SUMMARY"
echo "Networks scanned: $networks" >> "$HOST_SUMMARY"
echo >> "$HOST_SUMMARY"

echo "Phase 1: Host discovery with fping..."
for network in $networks; do
    echo "Scanning $network..."
    fping -a -g "$network" 2>/dev/null | tee -a "$PING_RESULTS"
done

if [ ! -s "$PING_RESULTS" ]; then
    echo "No hosts discovered with fping, trying nmap ping scan..."
    for network in $networks; do
        nmap -sn "$network" | grep "Nmap scan report" | awk '{print $5}' >> "$PING_RESULTS"
    done
fi

if [ ! -s "$PING_RESULTS" ]; then
    echo "No hosts discovered"
    exit 1
fi

echo "Discovered hosts:"
cat "$PING_RESULTS"

echo >> "$HOST_SUMMARY"
echo "--- DISCOVERED HOSTS ---" >> "$HOST_SUMMARY"
cat "$PING_RESULTS" >> "$HOST_SUMMARY"
echo >> "$HOST_SUMMARY"

echo
echo "Phase 2: Port scanning and OS detection..."

echo "--- PORT SCAN RESULTS ---" >> "$HOST_SUMMARY"
echo >> "$HOST_SUMMARY"

while read -r host; do
    if [[ $host =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "Scanning $host..."
        
        echo "Host: $host" >> "$HOST_SUMMARY"
        
        nmap_output=$(nmap -sS -O -sV -p 21,22,23,25,53,80,110,135,139,143,443,993,995,1433,3389,5432,8080 "$host" 2>/dev/null)
        echo "$nmap_output" >> "$NMAP_RESULTS"
        
        open_ports=$(echo "$nmap_output" | grep "open" | wc -l)
        echo "  Open ports: $open_ports" >> "$HOST_SUMMARY"
        
        if [ "$open_ports" -gt 0 ]; then
            echo "  Services:" >> "$HOST_SUMMARY"
            echo "$nmap_output" | grep "open" | head -10 | sed 's/^/    /' >> "$HOST_SUMMARY"
        fi
        
        os_info=$(echo "$nmap_output" | grep "OS details" | head -1)
        if [ -n "$os_info" ]; then
            echo "  OS: $os_info" >> "$HOST_SUMMARY"
        fi
        
        echo >> "$HOST_SUMMARY"
    fi
done < "$PING_RESULTS"

echo
echo "Phase 3: Reverse DNS lookup..."
echo "--- REVERSE DNS ---" >> "$HOST_SUMMARY"
echo >> "$HOST_SUMMARY"

while read -r host; do
    if [[ $host =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        hostname=$(nslookup "$host" 2>/dev/null | grep "name = " | awk '{print $4}' | sed 's/\.$//')
        if [ -n "$hostname" ]; then
            echo "$host -> $hostname" >> "$HOST_SUMMARY"
        fi
    fi
done < "$PING_RESULTS"

echo
echo "Phase 4: Host categorization..."

WINDOWS_HOSTS="$RESULTS_DIR/hosts_windows_${TIMESTAMP}.txt"
LINUX_HOSTS="$RESULTS_DIR/hosts_linux_${TIMESTAMP}.txt"
NETWORK_DEVICES="$RESULTS_DIR/hosts_network_devices_${TIMESTAMP}.txt"
UNKNOWN_HOSTS="$RESULTS_DIR/hosts_unknown_${TIMESTAMP}.txt"

> "$WINDOWS_HOSTS"
> "$LINUX_HOSTS"
> "$NETWORK_DEVICES"
> "$UNKNOWN_HOSTS"

while read -r host; do
    if [[ $host =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        host_info=$(grep -A 20 "Host: $host" "$HOST_SUMMARY")
        
        if echo "$host_info" | grep -qi "microsoft\|windows\|3389/tcp\|445/tcp\|139/tcp"; then
            echo "$host" >> "$WINDOWS_HOSTS"
        elif echo "$host_info" | grep -qi "linux\|unix\|22/tcp.*ssh"; then
            echo "$host" >> "$LINUX_HOSTS"
        elif echo "$host_info" | grep -qi "cisco\|router\|switch\|snmp\|telnet\|23/tcp"; then
            echo "$host" >> "$NETWORK_DEVICES"
        else
            echo "$host" >> "$UNKNOWN_HOSTS"
        fi
    fi
done < "$PING_RESULTS"

echo >> "$HOST_SUMMARY"
echo "--- HOST CATEGORIZATION ---" >> "$HOST_SUMMARY"
echo >> "$HOST_SUMMARY"

echo "Windows hosts: $(wc -l < "$WINDOWS_HOSTS")" >> "$HOST_SUMMARY"
if [ -s "$WINDOWS_HOSTS" ]; then
    cat "$WINDOWS_HOSTS" | sed 's/^/  /' >> "$HOST_SUMMARY"
fi
echo >> "$HOST_SUMMARY"

echo "Linux hosts: $(wc -l < "$LINUX_HOSTS")" >> "$HOST_SUMMARY"
if [ -s "$LINUX_HOSTS" ]; then
    cat "$LINUX_HOSTS" | sed 's/^/  /' >> "$HOST_SUMMARY"
fi
echo >> "$HOST_SUMMARY"

echo "Network devices: $(wc -l < "$NETWORK_DEVICES")" >> "$HOST_SUMMARY"
if [ -s "$NETWORK_DEVICES" ]; then
    cat "$NETWORK_DEVICES" | sed 's/^/  /' >> "$HOST_SUMMARY"
fi
echo >> "$HOST_SUMMARY"

echo "Unknown hosts: $(wc -l < "$UNKNOWN_HOSTS")" >> "$HOST_SUMMARY"
if [ -s "$UNKNOWN_HOSTS" ]; then
    cat "$UNKNOWN_HOSTS" | sed 's/^/  /' >> "$HOST_SUMMARY"
fi

echo "Network enumeration complete!"
echo
echo "Files created:"
echo "  Summary: $HOST_SUMMARY"
echo "  Detailed nmap: $NMAP_RESULTS"
echo "  Host lists: $WINDOWS_HOSTS, $LINUX_HOSTS, $NETWORK_DEVICES, $UNKNOWN_HOSTS"
echo
echo "Summary:"
echo "  Windows hosts: $(wc -l < "$WINDOWS_HOSTS")"
echo "  Linux hosts: $(wc -l < "$LINUX_HOSTS")"
echo "  Network devices: $(wc -l < "$NETWORK_DEVICES")"
echo "  Unknown hosts: $(wc -l < "$UNKNOWN_HOSTS")"

echo
echo "--- SUMMARY REPORT ---"
cat "$HOST_SUMMARY"