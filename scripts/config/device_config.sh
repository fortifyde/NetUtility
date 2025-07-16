#!/bin/bash

echo "=== Device Configuration Gathering ==="
echo

RESULTS_DIR="${NETUTIL_WORKDIR:-$HOME}/device_configs"
mkdir -p "$RESULTS_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "Device connection information:"
read -p "Enter device IP address: " device_ip
read -p "Enter username: " username
read -s -p "Enter password: " password
echo

if [[ ! $device_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: Invalid IP address format"
    exit 1
fi

echo "Testing connectivity to $device_ip..."
if ! ping -c 1 "$device_ip" >/dev/null 2>&1; then
    echo "Warning: Device $device_ip is not responding to ping"
    read -p "Continue anyway? (y/N): " continue_anyway
    if [[ ! $continue_anyway =~ ^[Yy]$ ]]; then
        echo "Aborting..."
        exit 1
    fi
fi

DEVICE_DIR="$RESULTS_DIR/device_${device_ip}_${TIMESTAMP}"
mkdir -p "$DEVICE_DIR"

REPORT_FILE="$DEVICE_DIR/device_report.txt"
CONFIG_FILE="$DEVICE_DIR/device_config.txt"
COMMANDS_FILE="$DEVICE_DIR/commands_output.txt"

echo "=== Device Configuration Report ===" > "$REPORT_FILE"
echo "Device IP: $device_ip" >> "$REPORT_FILE"
echo "Username: $username" >> "$REPORT_FILE"
echo "Connection time: $(date)" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Phase 1: Testing SSH connectivity..."

ssh_test=$(timeout 10 sshpass -p "$password" ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$username@$device_ip" "echo 'SSH_TEST_SUCCESS'" 2>/dev/null)

if [[ $ssh_test == *"SSH_TEST_SUCCESS"* ]]; then
    echo "SSH connection successful"
    connection_method="ssh"
else
    echo "SSH connection failed, trying Telnet..."
    
    telnet_test=$(timeout 10 expect -c "
        spawn telnet $device_ip
        expect \"login:\"
        send \"$username\r\"
        expect \"Password:\"
        send \"$password\r\"
        expect \"#\"
        send \"echo TELNET_TEST_SUCCESS\r\"
        expect \"TELNET_TEST_SUCCESS\"
        send \"exit\r\"
        expect eof
    " 2>/dev/null)
    
    if [[ $telnet_test == *"TELNET_TEST_SUCCESS"* ]]; then
        echo "Telnet connection successful"
        connection_method="telnet"
    else
        echo "Error: Cannot connect via SSH or Telnet"
        exit 1
    fi
fi

echo "Connection method: $connection_method" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Phase 2: Vendor detection..."

detect_vendor() {
    local commands_output="$1"
    local vendor="unknown"
    
    if echo "$commands_output" | grep -qi "cisco"; then
        vendor="cisco"
    elif echo "$commands_output" | grep -qi "juniper\|junos"; then
        vendor="juniper"
    elif echo "$commands_output" | grep -qi "hp\|hewlett"; then
        vendor="hp"
    elif echo "$commands_output" | grep -qi "aruba"; then
        vendor="aruba"
    elif echo "$commands_output" | grep -qi "dell"; then
        vendor="dell"
    elif echo "$commands_output" | grep -qi "netgear"; then
        vendor="netgear"
    elif echo "$commands_output" | grep -qi "mikrotik"; then
        vendor="mikrotik"
    elif echo "$commands_output" | grep -qi "fortinet\|fortigate"; then
        vendor="fortinet"
    fi
    
    echo "$vendor"
}

echo "Detecting device vendor..." > "$COMMANDS_FILE"

if [ "$connection_method" == "ssh" ]; then
    initial_output=$(timeout 30 sshpass -p "$password" ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$username@$device_ip" "
        echo '=== SYSTEM INFO ==='
        uname -a 2>/dev/null || echo 'uname not available'
        cat /etc/os-release 2>/dev/null || echo 'os-release not available'
        show version 2>/dev/null || echo 'show version not available'
        system info 2>/dev/null || echo 'system info not available'
        echo '=== HOSTNAME ==='
        hostname 2>/dev/null || echo 'hostname not available'
    " 2>/dev/null)
else
    initial_output=$(timeout 30 expect -c "
        spawn telnet $device_ip
        expect \"login:\"
        send \"$username\r\"
        expect \"Password:\"
        send \"$password\r\"
        expect \"#\"
        send \"show version\r\"
        expect \"#\"
        send \"hostname\r\"
        expect \"#\"
        send \"exit\r\"
        expect eof
    " 2>/dev/null)
fi

echo "$initial_output" >> "$COMMANDS_FILE"

vendor=$(detect_vendor "$initial_output")
echo "Detected vendor: $vendor"
echo "Detected vendor: $vendor" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Phase 3: Gathering device configuration..."

run_command_set() {
    local vendor="$1"
    local method="$2"
    
    case $vendor in
        "cisco")
            commands=(
                "show version"
                "show running-config"
                "show startup-config"
                "show interfaces"
                "show ip interface brief"
                "show vlan brief"
                "show spanning-tree"
                "show cdp neighbors"
                "show inventory"
                "show log"
            )
            ;;
        "juniper")
            commands=(
                "show version"
                "show configuration"
                "show interfaces"
                "show route"
                "show vlans"
                "show lldp neighbors"
                "show log messages"
            )
            ;;
        "hp"|"aruba")
            commands=(
                "show version"
                "show running-config"
                "show interfaces"
                "show vlans"
                "show lldp info remote-device"
                "show logging"
            )
            ;;
        "fortinet")
            commands=(
                "get system status"
                "show full-configuration"
                "get system interface"
                "get router info routing-table all"
                "diagnose sys logread"
            )
            ;;
        *)
            commands=(
                "show version"
                "show config"
                "show running-config"
                "show interfaces"
                "show ip route"
                "show arp"
                "show log"
            )
            ;;
    esac
    
    for cmd in "${commands[@]}"; do
        echo "Executing: $cmd" >> "$COMMANDS_FILE"
        echo "=============================" >> "$COMMANDS_FILE"
        
        if [ "$method" == "ssh" ]; then
            timeout 60 sshpass -p "$password" ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$username@$device_ip" "$cmd" 2>/dev/null >> "$COMMANDS_FILE"
        else
            timeout 60 expect -c "
                spawn telnet $device_ip
                expect \"login:\"
                send \"$username\r\"
                expect \"Password:\"
                send \"$password\r\"
                expect \"#\"
                send \"$cmd\r\"
                expect \"#\"
                send \"exit\r\"
                expect eof
            " 2>/dev/null >> "$COMMANDS_FILE"
        fi
        
        echo >> "$COMMANDS_FILE"
        echo "=============================" >> "$COMMANDS_FILE"
        echo >> "$COMMANDS_FILE"
    done
}

run_command_set "$vendor" "$connection_method"

echo "Phase 4: Extracting configuration..."

if [ "$connection_method" == "ssh" ]; then
    config_output=$(timeout 60 sshpass -p "$password" ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$username@$device_ip" "
        show running-config 2>/dev/null || show configuration 2>/dev/null || show config 2>/dev/null || cat /etc/config 2>/dev/null || echo 'Configuration not accessible'
    " 2>/dev/null)
else
    config_output=$(timeout 60 expect -c "
        spawn telnet $device_ip
        expect \"login:\"
        send \"$username\r\"
        expect \"Password:\"
        send \"$password\r\"
        expect \"#\"
        send \"show running-config\r\"
        expect \"#\"
        send \"exit\r\"
        expect eof
    " 2>/dev/null)
fi

echo "$config_output" > "$CONFIG_FILE"

echo "Phase 5: Generating summary report..."

echo "--- DEVICE SUMMARY ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

hostname=$(echo "$initial_output" | grep -i hostname | head -1 | sed 's/.*hostname[[:space:]]*//i' | sed 's/[[:space:]]*$//')
if [ -z "$hostname" ]; then
    hostname="Unknown"
fi

echo "Hostname: $hostname" >> "$REPORT_FILE"
echo "Vendor: $vendor" >> "$REPORT_FILE"
echo "Connection method: $connection_method" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

version_info=$(echo "$initial_output" | grep -i version | head -3)
if [ -n "$version_info" ]; then
    echo "Version information:" >> "$REPORT_FILE"
    echo "$version_info" | sed 's/^/  /' >> "$REPORT_FILE"
    echo >> "$REPORT_FILE"
fi

echo "--- CONFIGURATION SUMMARY ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

config_lines=$(wc -l < "$CONFIG_FILE" 2>/dev/null || echo 0)
echo "Configuration lines captured: $config_lines" >> "$REPORT_FILE"

if [ "$config_lines" -gt 0 ]; then
    echo "Configuration preview (first 20 lines):" >> "$REPORT_FILE"
    head -20 "$CONFIG_FILE" | sed 's/^/  /' >> "$REPORT_FILE"
    echo >> "$REPORT_FILE"
fi

echo "--- FILES CREATED ---" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"
echo "Full report: $REPORT_FILE" >> "$REPORT_FILE"
echo "Device configuration: $CONFIG_FILE" >> "$REPORT_FILE"
echo "Command outputs: $COMMANDS_FILE" >> "$REPORT_FILE"

echo "Device configuration gathering complete!"
echo
echo "Files created:"
echo "  Device directory: $DEVICE_DIR"
echo "  Report: $REPORT_FILE"
echo "  Configuration: $CONFIG_FILE"
echo "  Command outputs: $COMMANDS_FILE"
echo
echo "Summary:"
echo "  Device: $device_ip"
echo "  Hostname: $hostname"
echo "  Vendor: $vendor"
echo "  Connection: $connection_method"
echo "  Config lines: $config_lines"

if [ "$config_lines" -gt 0 ]; then
    echo
    echo "✅ Configuration successfully gathered!"
else
    echo
    echo "⚠️  Configuration gathering may have failed - check command outputs"
fi

echo
echo "--- DEVICE REPORT ---"
cat "$REPORT_FILE"