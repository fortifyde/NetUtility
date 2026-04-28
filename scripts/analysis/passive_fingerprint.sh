#!/bin/sh

# Passive OS Fingerprinting Script
# Analyzes pcap captures with p0f, cross-references MAC OUI vendors,
# and uses open port patterns to infer device types — no active probing.

. "$(dirname "$0")/../common/utils.sh"
. "$(dirname "$0")/../common/colors.sh" 2>/dev/null || true
. "$(dirname "$0")/../common/logging.sh" 2>/dev/null || true
. "$(dirname "$0")/../common/validation.sh" 2>/dev/null || true
# shellcheck source=../common/progress.sh
. "$(dirname "$0")/../common/progress.sh" 2>/dev/null || true
SCRIPT_NAME="$(basename "$0")"

echo "=== Passive OS Fingerprinting ==="
log_info "=== Script started ===" "$SCRIPT_NAME"
echo

WORKDIR="${NETUTIL_WORKDIR:-$HOME}"
WORKDIR="${WORKDIR%/}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_BASE="$WORKDIR/discovery/fingerprint"
SESSION_DIR="$RESULTS_BASE/fingerprint_${TIMESTAMP}"

mkdir -p "$SESSION_DIR"

# Temp directory for intermediate files
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

# =============================================================================
# Known OUI prefixes for infrastructure device classification
# =============================================================================

# Cisco OUI prefixes
CISCO_OUIS="00:1A:A1 00:26:0B 00:1B:D4 00:22:55 00:25:45"
# HP/Aruba OUI prefixes
HP_ARUBA_OUIS="00:1E:0B 24:DE:C6 A0:D3:C1"
# Juniper OUI prefixes
JUNIPER_OUIS="00:05:85 00:12:1E 2C:6B:F5"
# Arista OUI prefixes
ARISTA_OUIS="00:1C:73"

# =============================================================================
# Helper: classify vendor from OUI
# =============================================================================

classify_oui_vendor() {
    _oui="$1"

    for prefix in $CISCO_OUIS; do
        if [ "$_oui" = "$prefix" ]; then echo "Cisco"; return 0; fi
    done
    for prefix in $HP_ARUBA_OUIS; do
        if [ "$_oui" = "$prefix" ]; then echo "HP/Aruba"; return 0; fi
    done
    for prefix in $JUNIPER_OUIS; do
        if [ "$_oui" = "$prefix" ]; then echo "Juniper"; return 0; fi
    done
    for prefix in $ARISTA_OUIS; do
        if [ "$_oui" = "$prefix" ]; then echo "Arista"; return 0; fi
    done

    echo "Unknown"
    return 1
}

# =============================================================================
# Helper: infer device type from vendor + port set
# =============================================================================

infer_device_type() {
    _vendor="$1"
    _ports="$2"

    case "$_vendor" in
        Cisco)
            # Cisco with management ports → switch/router
            case "$_ports" in
                *161*udp*22*tcp*80*tcp*)  echo "switch" ;;
                *161*udp*443*tcp*)        echo "switch/router" ;;
                *23*tcp*161*udp*)         echo "legacy switch" ;;
                *53*tcp*161*udp*)         echo "router" ;;
                *80*tcp*443*tcp*)         echo "AP/web-managed" ;;
                *)                        echo "switch" ;;
            esac
            ;;
        HP/Aruba)
            case "$_ports" in
                *161*udp*22*tcp*)         echo "switch" ;;
                *161*udp*443*tcp*)        echo "switch/AP" ;;
                *80*tcp*443*tcp*)         echo "AP" ;;
                *)                        echo "switch/AP" ;;
            esac
            ;;
        Juniper)
            case "$_ports" in
                *161*udp*22*tcp*)         echo "router/firewall" ;;
                *161*udp*443*tcp*)        echo "router/firewall" ;;
                *)                        echo "router" ;;
            esac
            ;;
        Arista)
            echo "switch"
            ;;
        *)
            # Unknown vendor — rely solely on port patterns
            case "$_ports" in
                *161*udp*22*tcp*80*tcp*)  echo "managed switch" ;;
                *161*udp*443*tcp*)        echo "managed switch/router" ;;
                *23*tcp*161*udp*)         echo "legacy device" ;;
                *53*tcp*161*udp*)         echo "DNS server/router" ;;
                *80*tcp*443*tcp*)         echo "AP/web-managed device" ;;
                *)                        echo "unknown" ;;
            esac
            ;;
    esac
}

# =============================================================================
# Helper: determine confidence from number of evidence sources
# =============================================================================

rate_confidence() {
    _sources="$1"
    _count=0
    [ -n "$_sources" ] && _count=$(echo "$_sources" | tr ',' '\n' | wc -l)

    if [ "$_count" -ge 3 ]; then echo "high"
    elif [ "$_count" -ge 2 ]; then echo "medium"
    else echo "low"
    fi
}

# =============================================================================
# Phase 1: Find existing pcap captures
# =============================================================================

print_phase_header "Phase 1: Locate Packet Captures"

PCAP_FILE=""

# Search in standard locations
CAPTURE_DIR="$WORKDIR/captures"
SCANS_DIR="$WORKDIR/scans"

log_debug "Searching for pcaps in $CAPTURE_DIR and $SCANS_DIR" "$SCRIPT_NAME"

# Collect candidate pcaps
CANDIDATES=""
for dir in "$CAPTURE_DIR" "$SCANS_DIR"; do
    if [ -d "$dir" ]; then
        # Find pcaps (POSIX: use find with -name)
        found=$(find "$dir" -name "*.pcap" -type f 2>/dev/null)
        if [ -n "$found" ]; then
            CANDIDATES="$CANDIDATES
$found"
        fi
    fi
done

# Trim leading blank
CANDIDATES=$(echo "$CANDIDATES" | grep -v "^$" | sort -u)

if [ -n "$CANDIDATES" ]; then
    echo "Found the following pcap files:"
    echo "$CANDIDATES" | while IFS= read -r f; do
        size=$(du -h "$f" 2>/dev/null | cut -f1)
        echo "  $f  ($size)"
    done
    echo

    if [ "$(echo "$CANDIDATES" | wc -l)" -eq 1 ]; then
        PCAP_FILE="$CANDIDATES"
        echo "Using: $PCAP_FILE"
    else
        PCAP_FILE=$(select_file "$CAPTURE_DIR" "*.pcap" "Select a pcap file for fingerprinting:" 2>/dev/null)
        # select_file may return empty or path outside list; validate
        if [ -z "$PCAP_FILE" ] || [ ! -f "$PCAP_FILE" ]; then
            echo "Manual pcap selection:"
            echo "$CANDIDATES" | nl -ba
            echo
            choice=$(prompt_for_choice "Enter number" 1 "$(echo "$CANDIDATES" | wc -l)")
            PCAP_FILE=$(echo "$CANDIDATES" | sed -n "${choice}p")
        fi
    fi
else
    warning_message "No pcap files found in $CAPTURE_DIR or $SCANS_DIR"
    echo
    echo "Options:"
    echo "  1. Enter path to a pcap file manually"
    echo "  2. Exit and run network_capture.sh first"
    echo
    opt=$(prompt_for_choice "Select option" 1 2)
    case "$opt" in
        1)
            PCAP_FILE=$(get_validated_input "Enter full path to pcap file" "test -f \"\$INPUT\"" "")
            if [ ! -f "$PCAP_FILE" ]; then
                error_message "File not found: $PCAP_FILE"
                exit 1
            fi
            ;;
        2)
            echo "Run 'netutil capture' first, then re-run this script."
            exit 0
            ;;
        *)
            error_message "Invalid option"
            exit 1
            ;;
    esac
fi

if [ -z "$PCAP_FILE" ] || [ ! -f "$PCAP_FILE" ]; then
    error_message "No valid pcap file selected"
    log_error "No valid pcap file selected" "$SCRIPT_NAME"
    exit 1
fi

success_message "Using capture: $PCAP_FILE"
log_info "Selected pcap: $PCAP_FILE" "$SCRIPT_NAME"

# =============================================================================
# Phase 2: Passive fingerprinting with p0f
# =============================================================================

print_phase_header "Phase 2: Passive Fingerprinting (p0f)"

P0F_OUTPUT="$SESSION_DIR/p0f_output.txt"
P0F_PARSED="$TEMP_DIR/p0f_parsed.tsv"

if ! command -v p0f >/dev/null 2>&1; then
    warning_message "p0f not found — skipping passive fingerprinting phase"
    log_warn "p0f not available, skipping Phase 2" "$SCRIPT_NAME"
    > "$P0F_OUTPUT"
    > "$P0F_PARSED"
else
    log_info "Running p0f on $PCAP_FILE" "$SCRIPT_NAME"
    p0f -r "$PCAP_FILE" -o "$P0F_OUTPUT" 2>/dev/null
    p0f_rc=$?

    if [ "$p0f_rc" -ne 0 ] && [ ! -s "$P0F_OUTPUT" ]; then
        warning_message "p0f returned no results (may be no SYN packets in capture)"
        log_warn "p0f produced no output" "$SCRIPT_NAME"
        > "$P0F_OUTPUT"
    else
        success_message "p0f analysis complete"
        log_info "p0f output saved: $P0F_OUTPUT" "$SCRIPT_NAME"
    fi

    # Parse p0f output into TSV: client_ip<TAB>server_ip<TAB>mod<TAB>os<TAB>dist<TAB>params
    > "$P0F_PARSED"
    print_subphase "Parsing p0f output"

    while IFS= read -r line; do
        # Skip comments and blank lines
        case "$line" in "#"*|"") continue ;; esac

        # p0f line format example:
        # 192.168.1.1/51652 -> 192.168.1.2/80 (syn) [S1:60] mod=syn|os=Linux 3.11+|dist=0|params=
        # Extract client IP and server IP
        client_ip=$(echo "$line" | sed 's|/[^ ]*||; s|^ *||; s| .*||')
        rest=$(echo "$line" | sed 's|^[^ ]* -> ||')
        server_ip=$(echo "$rest" | sed 's|/[^ ]*.*||')

        # Extract the module section after ')'
        mod_section=$(echo "$line" | sed 's/.*)[[:space:]]*//')

        # Parse mod=...|os=...|dist=...|params=...
        mod_val=""
        os_val=""
        dist_val=""
        params_val=""

        # Use IFS='|' to split
        _saved_ifs="$IFS"
        IFS='|'
        for field in $mod_section; do
            case "$field" in
                mod=*)    mod_val="${field#mod=}" ;;
                os=*)     os_val="${field#os=}" ;;
                dist=*)   dist_val="${field#dist=}" ;;
                params=*) params_val="${field#params=}" ;;
            esac
        done
        IFS="$_saved_ifs"

        # Write parsed entry
        printf "%s\t%s\t%s\t%s\t%s\t%s\n" "$client_ip" "$server_ip" "$mod_val" "$os_val" "$dist_val" "$params_val" >> "$P0F_PARSED"
    done < "$P0F_OUTPUT"

    p0f_count=$(wc -l < "$P0F_PARSED")
    success_message "Parsed $p0f_count fingerprint entries"
    log_info "Parsed p0f entries: $p0f_count" "$SCRIPT_NAME"
fi

# =============================================================================
# Phase 3: MAC OUI Device Classification
# =============================================================================

print_phase_header "Phase 3: MAC OUI Device Classification"

MAC_OUI_MAP="$TEMP_DIR/mac_oui.tsv"
> "$MAC_OUI_MAP"

if ! command -v tshark >/dev/null 2>&1; then
    warning_message "tshark not found — skipping MAC extraction"
    log_warn "tshark not available, skipping Phase 3" "$SCRIPT_NAME"
else
    print_subphase "Extracting MAC addresses from capture"

    tshark -r "$PCAP_FILE" -T fields -e eth.src -e eth.dst -e ip.src -e ip.dst 2>/dev/null | \
        grep -v "^$" > "$TEMP_DIR/mac_ip_raw.tsv"

    # Build a mapping: IP -> MAC by looking at src entries (src mac + src ip on same line)
    > "$TEMP_DIR/ip_mac_raw.txt"
    while IFS='	' read -r src_mac dst_mac src_ip dst_ip; do
        if [ -n "$src_mac" ] && [ -n "$src_ip" ]; then
            echo "$src_ip	$src_mac"
        fi
        if [ -n "$dst_mac" ] && [ -n "$dst_ip" ]; then
            echo "$dst_ip	$dst_mac"
        fi
    done < "$TEMP_DIR/mac_ip_raw.tsv" | sort -u > "$TEMP_DIR/ip_mac_raw.txt"

    # Deduplicate: prefer first MAC per IP
    > "$TEMP_DIR/ip_mac_dedup.txt"
    prev_ip=""
    while IFS='	' read -r ip mac; do
        if [ "$ip" != "$prev_ip" ]; then
            echo "$ip	$mac"
            prev_ip="$ip"
        fi
    done < "$TEMP_DIR/ip_mac_raw.txt" > "$TEMP_DIR/ip_mac_dedup.txt"

    mac_count=$(wc -l < "$TEMP_DIR/ip_mac_dedup.txt")
    success_message "Found $mac_count unique IP/MAC pairs"

    print_subphase "Classifying OUI vendors"

    while IFS='	' read -r ip mac; do
        # Normalize MAC to uppercase
        mac_norm=$(echo "$mac" | tr '[:lower:]' '[:upper:]')
        oui=$(echo "$mac_norm" | cut -d: -f1-3)
        vendor=$(classify_oui_vendor "$oui")
        printf "%s\t%s\t%s\t%s\n" "$ip" "$mac_norm" "$oui" "$vendor" >> "$MAC_OUI_MAP"
    done < "$TEMP_DIR/ip_mac_dedup.txt"

    oui_classified=$(grep -cv "Unknown" "$MAC_OUI_MAP" 2>/dev/null || echo 0)
    oui_unknown=$(grep -c "Unknown" "$MAC_OUI_MAP" 2>/dev/null || echo 0)
    echo "  Classified: $oui_classified   Unknown: $oui_unknown"
    log_info "OUI classification: $oui_classified known, $oui_unknown unknown" "$SCRIPT_NAME"
fi

# =============================================================================
# Phase 4: Port Pattern Analysis
# =============================================================================

print_phase_header "Phase 4: Port Pattern Analysis"

PORT_MAP="$TEMP_DIR/port_patterns.tsv"
> "$PORT_MAP"

print_subphase "Scanning for existing nmap data"

# Look for nmap output in discovery and scans directories
NMAP_FILES=""
for search_dir in "$WORKDIR/discovery" "$WORKDIR/scans"; do
    if [ -d "$search_dir" ]; then
        found=$(find "$search_dir" -name "*.nmap" -type f 2>/dev/null)
        if [ -n "$found" ]; then
            NMAP_FILES="$NMAP_FILES
$found"
        fi
    fi
done
NMAP_FILES=$(echo "$NMAP_FILES" | grep -v "^$" | sort -u)

if [ -z "$NMAP_FILES" ]; then
    warning_message "No nmap scan files found — port pattern analysis skipped"
    log_warn "No nmap data found, Phase 4 skipped" "$SCRIPT_NAME"
else
    success_message "Found $(echo "$NMAP_FILES" | wc -l) nmap scan file(s)"

    print_subphase "Extracting open port patterns"

    # Parse nmap greppable output or standard output for open ports
    while IFS= read -r nmap_file; do
        [ -z "$nmap_file" ] && continue

        # Try greppable format first: Host: IP ()	Ports: 22/open/tcp//ssh///
        if grep -q "Ports:" "$nmap_file" 2>/dev/null; then
            grep "Ports:" "$nmap_file" 2>/dev/null | while IFS='	' read -r host_part ports_part; do
                ip=$(echo "$host_part" | sed 's/Host: \([^ ]*\).*/\1/')
                # Extract open ports
                open_ports=""
                # Parse comma-separated port entries
                _saved_ifs="$IFS"
                IFS=','
                for entry in $ports_part; do
                    case "$entry" in
                        */open/*)
                            proto=$(echo "$entry" | cut -d/ -f3)
                            port=$(echo "$entry" | cut -d/ -f1)
                            open_ports="$open_ports $port/$proto"
                            ;;
                    esac
                done
                IFS="$_saved_ifs"

                if [ -n "$open_ports" ]; then
                    open_ports=$(echo "$open_ports" | sed 's/^ *//')
                    printf "%s\t%s\n" "$ip" "$open_ports" >> "$PORT_MAP"
                fi
            done
        else
            # Standard nmap output: "22/tcp  open  ssh"
            # Find lines with "open" and capture IP from "Nmap scan report for" lines
            current_ip=""
            while IFS= read -r nline; do
                case "$nline" in
                    "Nmap scan report for "*)
                        current_ip=$(echo "$nline" | sed 's/Nmap scan report for \(.*\)/\1/')
                        # Strip hostname in parentheses if present: "host (1.2.3.4)"
                        case "$current_ip" in
                            *" ("*)
                                current_ip=$(echo "$current_ip" | sed 's/.*(\([^)]*\)).*/\1/')
                                ;;
                        esac
                        ;;
                    */open*" "*)
                        if [ -n "$current_ip" ]; then
                            port_proto=$(echo "$nline" | awk '{print $1}')
                            printf "%s\t%s\n" "$current_ip" "$port_proto" >> "$TEMP_DIR/port_raw.tsv"
                        fi
                        ;;
                esac
            done < "$nmap_file"
        fi
    done < "$NMAP_FILES"

    # Aggregate ports per IP from raw entries
    if [ -f "$TEMP_DIR/port_raw.tsv" ]; then
        sort "$TEMP_DIR/port_raw.tsv" | awk -F'\t' '
        {
            ip = $1
            port = $2
            if (ip != prev_ip && prev_ip != "") {
                printf "%s\t%s\n", prev_ip, ports
                ports = ""
            }
            prev_ip = ip
            if (ports != "") ports = ports " " port
            else ports = port
        }
        END {
            if (prev_ip != "") printf "%s\t%s\n", prev_ip, ports
        }' >> "$PORT_MAP"
    fi

    # Deduplicate PORT_MAP by IP (last wins)
    sort "$PORT_MAP" | awk -F'\t' '!seen[$1]++ {print}' > "$TEMP_DIR/port_map_dedup.tsv"
    mv "$TEMP_DIR/port_map_dedup.tsv" "$PORT_MAP"

    port_hosts=$(wc -l < "$PORT_MAP")
    success_message "Port patterns extracted for $port_hosts host(s)"
    log_info "Port patterns extracted: $port_hosts hosts" "$SCRIPT_NAME"
fi

# =============================================================================
# Phase 5: Combined Results
# =============================================================================

print_phase_header "Phase 5: Combined Fingerprint Results"

print_subphase "Merging evidence sources"

# Collect all unique IPs across all evidence sources
{
cat "$P0F_PARSED" 2>/dev/null | cut -f1 | grep -v "^$"
cat "$P0F_PARSED" 2>/dev/null | cut -f2 | grep -v "^$"
cut -f1 "$MAC_OUI_MAP" 2>/dev/null | grep -v "^$"
cut -f1 "$PORT_MAP" 2>/dev/null | grep -v "^$"
} 2>/dev/null | sort -u > "$TEMP_DIR/all_ips.txt"

total_ips=$(wc -l < "$TEMP_DIR/all_ips.txt")

if [ "$total_ips" -eq 0 ]; then
    warning_message "No hosts identified from any evidence source"
    log_warn "No hosts found across all phases" "$SCRIPT_NAME"
    echo
    echo "No fingerprint data could be extracted. Possible causes:"
    echo "  - Capture file has no SYN packets (p0f needs SYN)"
    echo "  - No MAC/IP pairs in capture"
    echo "  - No nmap scan data available"
    echo
    echo "Session directory: $SESSION_DIR"
    log_info "=== Script completed: 0 hosts ===" "$SCRIPT_NAME"
    exit 0
fi

success_message "Found $total_ips unique host(s) across all evidence sources"

# Build combined XML output
XML_FILE="$SESSION_DIR/fingerprint_results.xml"

print_subphase "Generating XML output"

{
    echo '<?xml version="1.0" encoding="UTF-8"?>'
    echo "<fingerprint_results>"
    echo "  <metadata>"
    echo "    <timestamp>$(date -Iseconds)</timestamp>"
    echo "    <pcap_source>$PCAP_FILE</pcap_source>"
    echo "    <session_dir>$SESSION_DIR</session_dir>"
    echo "    <host_count>$total_ips</host_count>"
    echo "  </metadata>"

    while IFS= read -r ip; do
        [ -z "$ip" ] && continue

        # Gather evidence per source
        p0f_os=""
        p0f_mod=""
        mac_addr=""
        oui_vendor="Unknown"
        port_list=""

        # p0f evidence: look for this IP as client or server
        if [ -s "$P0F_PARSED" ]; then
            # Client-side fingerprint
            p0f_match=$(grep "^${ip}	" "$P0F_PARSED" | head -1)
            if [ -n "$p0f_match" ]; then
                p0f_os=$(echo "$p0f_match" | cut -f4)
                p0f_mod=$(echo "$p0f_match" | cut -f3)
            fi
            # If no client match, try server-side
            if [ -z "$p0f_os" ]; then
                p0f_match=$(awk -F'\t' -v ip="$ip" '$2 == ip {print; exit}' "$P0F_PARSED")
                if [ -n "$p0f_match" ]; then
                    p0f_os=$(echo "$p0f_match" | cut -f4)
                    p0f_mod=$(echo "$p0f_match" | cut -f3)
                fi
            fi
        fi

        # MAC OUI evidence
        if [ -s "$MAC_OUI_MAP" ]; then
            mac_line=$(grep "^${ip}	" "$MAC_OUI_MAP" | head -1)
            if [ -n "$mac_line" ]; then
                mac_addr=$(echo "$mac_line" | cut -f2)
                oui_vendor=$(echo "$mac_line" | cut -f4)
            fi
        fi

        # Port pattern evidence
        if [ -s "$PORT_MAP" ]; then
            port_line=$(grep "^${ip}	" "$PORT_MAP" | head -1)
            if [ -n "$port_line" ]; then
                port_list=$(echo "$port_line" | cut -f2-)
            fi
        fi

        # Determine OS guess
        os_guess=""
        if [ -n "$p0f_os" ]; then
            os_guess="$p0f_os"
        elif [ "$oui_vendor" != "Unknown" ]; then
            # Vendor-based OS guess
            case "$oui_vendor" in
                Cisco)      os_guess="Cisco IOS" ;;
                HP/Aruba)   os_guess="ArubaOS" ;;
                Juniper)    os_guess="Juniper Junos" ;;
                Arista)     os_guess="Arista EOS" ;;
                *)          os_guess="Unknown" ;;
            esac
        fi

        # Normalize port list for device type inference
        port_pattern=""
        if [ -n "$port_list" ]; then
            # Sort port entries and create pattern string
            port_pattern=$(echo "$port_list" | tr ' ' '\n' | sort | tr '\n' ' ' | sed 's/^ *//;s/ *$//')
        fi

        # Infer device type
        device_type=$(infer_device_type "$oui_vendor" "$port_pattern")

        # Count evidence sources
        evidence_sources=""
        if [ -n "$p0f_os" ]; then
            evidence_sources="${evidence_sources}p0f,"
            p0f_display="$p0f_mod@$p0f_os"
        else
            p0f_display=""
        fi
        if [ "$oui_vendor" != "Unknown" ]; then
            evidence_sources="${evidence_sources}oui,"
        fi
        if [ -n "$port_pattern" ]; then
            evidence_sources="${evidence_sources}ports,"
        fi
        # Trim trailing comma
        evidence_sources=$(echo "$evidence_sources" | sed 's/,$//')

        confidence=$(rate_confidence "$evidence_sources")

        # Emit XML host entry
        echo "  <host ip=\"$ip\" mac=\"${mac_addr:-unknown}\">"
        echo "    <os_guess>${os_guess:-Unknown}</os_guess>"
        echo "    <device_type>${device_type:-unknown}</device_type>"
        echo "    <confidence>$confidence</confidence>"
        echo "    <evidence>"
        if [ -n "$p0f_display" ]; then
            echo "      <source name=\"p0f\">$p0f_display</source>"
        fi
        if [ "$oui_vendor" != "Unknown" ]; then
            echo "      <source name=\"oui\">$oui_vendor</source>"
        fi
        if [ -n "$port_pattern" ]; then
            echo "      <source name=\"ports\">$port_pattern</source>"
        fi
        echo "    </evidence>"
        echo "  </host>"
    done < "$TEMP_DIR/all_ips.txt"

    echo "</fingerprint_results>"
} > "$XML_FILE"

success_message "XML output: $XML_FILE"
log_info "XML output written: $XML_FILE" "$SCRIPT_NAME"

# --- Summary text report ---
print_subphase "Generating summary report"
REPORT_FILE="$SESSION_DIR/fingerprint_summary.txt"

{
    echo "=== Passive Fingerprint Summary ==="
    echo "Timestamp : $(date)"
    echo "PCAP      : $PCAP_FILE"
    echo "Session   : $SESSION_DIR"
    echo
    echo "Hosts analyzed: $total_ips"
    echo
    echo "--- Per-Host Summary ---"
    printf "%-40s %-18s %-20s %-20s %-12s\n" "IP Address" "MAC Address" "OS Guess" "Device Type" "Confidence"
    printf "%-40s %-18s %-20s %-20s %-12s\n" \
        "----------------------------------------" "------------------" "--------------------" "--------------------" "------------"

    while IFS= read -r ip; do
        [ -z "$ip" ] && continue

        mac_addr="unknown"
        os_guess="Unknown"
        device_type="unknown"
        confidence="low"

        # Quick lookups for summary table
        if [ -s "$MAC_OUI_MAP" ]; then
            mac_line=$(grep "^${ip}	" "$MAC_OUI_MAP" | head -1)
            [ -n "$mac_line" ] && mac_addr=$(echo "$mac_line" | cut -f2)
        fi

        if [ -s "$P0F_PARSED" ]; then
            p0f_match=$(grep "^${ip}	" "$P0F_PARSED" | head -1)
            [ -z "$p0f_match" ] && p0f_match=$(awk -F'\t' -v ip2="$ip" '$2 == ip2 {print; exit}' "$P0F_PARSED")
            [ -n "$p0f_match" ] && os_guess=$(echo "$p0f_match" | cut -f4)
        fi

        # Re-derive device type and confidence from XML (simpler: parse from XML)
        host_block=$(sed -n "/<host ip=\"$ip\"/,/<\/host>/p" "$XML_FILE")
        device_type=$(echo "$host_block" | sed -n 's/.*<device_type>\(.*\)<\/device_type>.*/\1/p')
        confidence=$(echo "$host_block" | sed -n 's/.*<confidence>\(.*\)<\/confidence>.*/\1/p')

        [ -z "$device_type" ] && device_type="unknown"
        [ -z "$confidence" ] && confidence="low"

        printf "%-40s %-18s %-20s %-20s %-12s\n" "$ip" "$mac_addr" "${os_guess:-Unknown}" "$device_type" "$confidence"
    done < "$TEMP_DIR/all_ips.txt"

    echo
    echo "--- Evidence Source Counts ---"
    p0f_entries=0
    oui_known=0
    port_hosts_count=0
    [ -s "$P0F_PARSED" ] && p0f_entries=$(wc -l < "$P0F_PARSED")
    [ -s "$MAC_OUI_MAP" ] && oui_known=$(grep -cv "Unknown" "$MAC_OUI_MAP" 2>/dev/null || echo 0)
    [ -s "$PORT_MAP" ] && port_hosts_count=$(wc -l < "$PORT_MAP")
    echo "  p0f fingerprints : $p0f_entries"
    echo "  OUI classified   : $oui_known"
    echo "  Port patterns    : $port_hosts_count host(s)"
} > "$REPORT_FILE"

success_message "Summary report: $REPORT_FILE"
log_info "Summary report written: $REPORT_FILE" "$SCRIPT_NAME"

echo
echo "=== Results ==="
echo "  Session directory : $SESSION_DIR"
echo "  p0f raw output   : $P0F_OUTPUT"
echo "  XML results      : $XML_FILE"
echo "  Summary report   : $REPORT_FILE"
echo "  Hosts analyzed   : $total_ips"
echo

log_info "=== Script completed: $total_ips hosts fingerprinted ===" "$SCRIPT_NAME"
