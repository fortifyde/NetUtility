#!/bin/sh
# ph7_classify_lib.sh — Evidence collection and classification for Phase 7.
# Sourced by multi_phase_discovery.sh after ph7_registry.sh.
# Depends on: PHASE1_DIR, PHASE2_DIR, PHASE3_DIR, PHASE4_DIR, PHASE5_DIR,
#             PHASE6_DIR, PHASE7_DIR, NMAP_FAST_SCAN,
#             extract_host_data(), detect_device_vendor()

# Build a normalized evidence record for a single host.
# Output: $PHASE7_DIR/evidence/${ip}.ev (one TYPE:VALUE per line)
ph7_collect_evidence() {
    _p7_ip="$1"
    _p7_ev_file="$PHASE7_DIR/evidence/${_p7_ip}.ev"

    mkdir -p "$PHASE7_DIR/evidence"
    : > "$_p7_ev_file"

    # --- TTL (Phase 2.1.1 output: "IP TTL STARTING_TTL") ---
    _p7_ttl_line=$(grep "^${_p7_ip} " "$PHASE2_DIR/icmp_responsive.txt" 2>/dev/null | head -1)
    if [ -n "$_p7_ttl_line" ]; then
        _p7_ttl_raw=$(echo "$_p7_ttl_line"  | awk '{print $2}')
        _p7_ttl_norm=$(echo "$_p7_ttl_line" | awk '{print $3}')
        [ -n "$_p7_ttl_raw" ]  && printf 'ttl_raw:%s\n'        "$_p7_ttl_raw"  >> "$_p7_ev_file"
        [ -n "$_p7_ttl_norm" ] && printf 'ttl_normalized:%s\n' "$_p7_ttl_norm" >> "$_p7_ev_file"
    fi

    # --- Open TCP/UDP ports (Phase 5 fast scan, nmap -oN format) ---
    if [ -f "$NMAP_FAST_SCAN" ]; then
        extract_host_data "$_p7_ip" "$NMAP_FAST_SCAN" \
            | grep -oE "^[0-9]+/tcp[[:space:]]+open" \
            | awk -F'/' '{print "port_open_tcp:" $1}' >> "$_p7_ev_file"
        extract_host_data "$_p7_ip" "$NMAP_FAST_SCAN" \
            | grep -oE "^[0-9]+/udp[[:space:]]+open" \
            | awk -F'/' '{print "port_open_udp:" $1}' >> "$_p7_ev_file"
    fi

    # --- SSH banner (Phase 6 os_hints, tab-separated: IP<TAB>BANNER) ---
    _p7_ssh_banner=$(grep "^${_p7_ip}	" "$PHASE6_DIR/os_hints/ssh_banners.txt" 2>/dev/null \
        | cut -f2- | head -1)
    [ -n "$_p7_ssh_banner" ] && printf 'ssh_banner:%s\n' "$_p7_ssh_banner" >> "$_p7_ev_file"

    # --- HTTP Server header (Phase 6 os_hints, tab-separated: IP<TAB>HEADER) ---
    _p7_http_server=$(grep "^${_p7_ip}	" "$PHASE6_DIR/os_hints/http_server_headers.txt" 2>/dev/null \
        | cut -f2- | head -1)
    [ -n "$_p7_http_server" ] && printf 'http_server:%s\n' "$_p7_http_server" >> "$_p7_ev_file"

    # --- SNMP sysDescr (Phase 1.3 output, tab-separated: IP<TAB>SYSDESCR) ---
    _p7_snmp_sysdescr=$(grep "^${_p7_ip}	" "$PHASE1_DIR/snmp_sysdescr.txt" 2>/dev/null \
        | cut -f2- | head -1)
    [ -n "$_p7_snmp_sysdescr" ] && printf 'snmp_sysdescr:%s\n' "$_p7_snmp_sysdescr" >> "$_p7_ev_file"

    # --- MAC vendor (ouihelper via ARP cache or nmap scan data) ---
    _p7_mac_vendor=$(get_mac_vendor "$_p7_ip")
    [ "$_p7_mac_vendor" = "Unknown" ] && _p7_mac_vendor=""
    [ -n "$_p7_mac_vendor" ] && printf 'mac_vendor:%s\n' "$_p7_mac_vendor" >> "$_p7_ev_file"

    # --- DNS hostname (Phase 3, tab-separated: IP<TAB>HOSTNAME) ---
    _p7_dns_hostname=$(grep "^${_p7_ip}" "$PHASE3_DIR/dns_results.txt" 2>/dev/null \
        | awk -F'\t' '{print $2}' | head -1)
    if [ -n "$_p7_dns_hostname" ] && [ "$_p7_dns_hostname" != "<no hostname>" ]; then
        printf 'dns_hostname:%s\n' "$_p7_dns_hostname" >> "$_p7_ev_file"
    fi

    # --- NetBIOS name (Phase 4, tab-separated: IP<TAB>NETBIOS_NAME) ---
    _p7_netbios_name=$(grep "^${_p7_ip}	" "$PHASE4_DIR/netbios_names.txt" 2>/dev/null \
        | cut -f2- | head -1)
    [ -n "$_p7_netbios_name" ] && printf 'netbios_name:%s\n' "$_p7_netbios_name" >> "$_p7_ev_file"

    # --- Service version strings (Phase 6 version detection, nmap -oA normal format) ---
    if [ -f "$PHASE6_DIR/raw_scans/nmap_version_detection.nmap" ]; then
        extract_host_data "$_p7_ip" "$PHASE6_DIR/raw_scans/nmap_version_detection.nmap" \
            | grep -E "^[0-9]+/tcp[[:space:]]+open" \
            | awk '{
                port = $1
                $1=$2=$3=""
                sub(/^[[:space:]]+/, "")
                printf "service_version:%s:%s\n", port, $0
              }' >> "$_p7_ev_file"
    fi

    # --- nmap OS string (Phase 6 default scripts) ---
    if [ -f "$PHASE6_DIR/raw_scans/nmap_default_scripts.nmap" ]; then
        _p7_nmap_os=$(extract_host_data "$_p7_ip" "$PHASE6_DIR/raw_scans/nmap_default_scripts.nmap" \
            | grep -E "^(Running|OS details):" \
            | head -1 \
            | sed 's/^[^:]*:[[:space:]]*//')
        [ -n "$_p7_nmap_os" ] && printf 'nmap_os_string:%s\n' "$_p7_nmap_os" >> "$_p7_ev_file"
    fi
}

# Classify a single host using the gated tier system.
# Reads:  $PHASE7_DIR/evidence/${ip}.ev
# Writes: $PHASE7_DIR/categorization_debug/${ip}_debug.txt
# Prints: "CATEGORY|VENDOR|CONFIDENCE|SCORE|EVIDENCE_SUMMARY"
ph7_classify() {
    _p7_ip="$1"
    _p7_ev_file="$PHASE7_DIR/evidence/${_p7_ip}.ev"
    _p7_debug_file="$PHASE7_DIR/categorization_debug/${_p7_ip}_debug.txt"

    mkdir -p "$PHASE7_DIR/categorization_debug"

    if [ ! -f "$_p7_ev_file" ]; then
        echo "unknown|-|none|0|no_evidence_file"
        return
    fi

    # --- Read evidence values ---
    _p7_ttl_raw=$(        grep "^ttl_raw:"         "$_p7_ev_file" | cut -d: -f2-)
    _p7_ttl_normalized=$( grep "^ttl_normalized:"  "$_p7_ev_file" | cut -d: -f2-)
    _p7_ssh_banner=$(     grep "^ssh_banner:"      "$_p7_ev_file" | cut -d: -f2-)
    _p7_http_server=$(    grep "^http_server:"     "$_p7_ev_file" | cut -d: -f2-)
    _p7_snmp_sysdescr=$(  grep "^snmp_sysdescr:"   "$_p7_ev_file" | cut -d: -f2-)
    _p7_mac_vendor=$(     grep "^mac_vendor:"      "$_p7_ev_file" | cut -d: -f2-)
    _p7_dns_hostname=$(   grep "^dns_hostname:"    "$_p7_ev_file" | cut -d: -f2-)
    _p7_netbios_name=$(   grep "^netbios_name:"    "$_p7_ev_file" | cut -d: -f2-)
    _p7_nmap_os_string=$( grep "^nmap_os_string:"  "$_p7_ev_file" | cut -d: -f2-)

    # --- Initialize debug log ---
    {
        printf '=== Ph7 Classify: %s ===\nTimestamp: %s\n\n' "$_p7_ip" "$(date)"
        printf '%s\n' '--- EVIDENCE FILE ---'; cat "$_p7_ev_file"; printf '\n'
        printf '%s\n' '--- CLASSIFICATION ---'
    } > "$_p7_debug_file"

    _p7_category="" _p7_vendor="-" _p7_confidence="none" _p7_score=0 _p7_evidence=""
    _p7_gate_fired=false

    # =========================================================
    # STEP 1: TIER 1 GATES
    # =========================================================

    # Gate 1a: SNMP sysDescr
    if [ -n "$_p7_snmp_sysdescr" ]; then
        while IFS= read -r _p7_gate; do
            [ -z "$_p7_gate" ] && continue
            _p7_gp=$(echo "$_p7_gate" | cut -d: -f1)
            _p7_gc=$(echo "$_p7_gate" | cut -d: -f2)
            if echo "$_p7_snmp_sysdescr" | grep -qiF "$_p7_gp"; then
                _p7_category="$_p7_gc"; _p7_score=99; _p7_confidence="very_high"
                _p7_evidence="gate:snmp_sysdescr(${_p7_gp})"
                printf '  GATE: snmp_sysdescr "%s" → %s\n' "$_p7_gp" "$_p7_gc" >> "$_p7_debug_file"
                _p7_gate_fired=true; break
            fi
        done <<EOF
$SNMP_GATES
EOF
    fi

    # Gate 1b: Service version strings
    if [ "$_p7_gate_fired" = false ]; then
        _p7_svc_versions=$(grep "^service_version:" "$_p7_ev_file" | cut -d: -f3-)
        if [ -n "$_p7_svc_versions" ]; then
            while IFS= read -r _p7_gate; do
                [ -z "$_p7_gate" ] && continue
                _p7_gp=$(echo "$_p7_gate" | cut -d: -f1)
                _p7_gc=$(echo "$_p7_gate" | cut -d: -f2)
                if echo "$_p7_svc_versions" | grep -qiF "$_p7_gp"; then
                    _p7_category="$_p7_gc"; _p7_score=99; _p7_confidence="very_high"
                    _p7_evidence="gate:service_version(${_p7_gp})"
                    printf '  GATE: service_version "%s" → %s\n' "$_p7_gp" "$_p7_gc" >> "$_p7_debug_file"
                    _p7_gate_fired=true; break
                fi
            done <<EOF
$SERVICE_VERSION_GATES
EOF
        fi
    fi

    # Gate 1c: NetBIOS name present
    if [ "$_p7_gate_fired" = false ] && [ -n "$_p7_netbios_name" ]; then
        _p7_category="windows"; _p7_score=99; _p7_confidence="very_high"
        _p7_evidence="gate:netbios_name(${_p7_netbios_name})"
        printf '  GATE: netbios_name present → windows\n' >> "$_p7_debug_file"
        _p7_gate_fired=true
    fi

    # Finalize gated classification
    if [ "$_p7_gate_fired" = true ]; then
        if echo "$_p7_category" | grep -q "printer"; then
            _p7_category="network_device"; _p7_vendor="printer"
        elif echo "$_p7_category" | grep -q "network_device"; then
            _p7_vendor=$(detect_device_vendor "$_p7_ip" "$_p7_mac_vendor" "$_p7_ssh_banner" "$_p7_http_server" "$_p7_snmp_sysdescr")
        fi
        printf '  FINAL: %s | %s | %s | %s | %s\n' \
            "$_p7_category" "$_p7_vendor" "$_p7_confidence" "$_p7_score" "$_p7_evidence" >> "$_p7_debug_file"
        printf '%s|%s|%s|%s|%s\n' "$_p7_category" "$_p7_vendor" "$_p7_confidence" "$_p7_score" "$_p7_evidence"
        return
    fi

    # =========================================================
    # STEP 2: PRINTER PORT CHECK
    # =========================================================
    _p7_printer_count=0
    grep -q "^port_open_tcp:515$" "$_p7_ev_file" && _p7_printer_count=$((_p7_printer_count + 1))
    grep -q "^port_open_tcp:631$" "$_p7_ev_file" && _p7_printer_count=$((_p7_printer_count + 1))
    grep -q "^port_open_tcp:9100$" "$_p7_ev_file" && _p7_printer_count=$((_p7_printer_count + 1))

    if [ "$_p7_printer_count" -ge 2 ]; then
        printf '  PRINTER: %d printer ports\n' "$_p7_printer_count" >> "$_p7_debug_file"
        printf 'network_device|printer|high|110|printer_ports(%d)\n' "$_p7_printer_count"
        return
    fi

    if [ "$_p7_printer_count" -eq 1 ] && [ -n "$_p7_mac_vendor" ]; then
        while IFS= read -r _p7_entry; do
            [ -z "$_p7_entry" ] && continue
            _p7_mvp=$(echo "$_p7_entry" | cut -d: -f1)
            _p7_mvc=$(echo "$_p7_entry" | cut -d: -f2)
            if [ "$_p7_mvc" = "network_device/printer" ] && echo "$_p7_mac_vendor" | grep -qiF "$_p7_mvp"; then
                printf '  PRINTER: 1 printer port + MAC %s\n' "$_p7_mvp" >> "$_p7_debug_file"
                printf 'network_device|printer|medium|95|printer_port+mac_printer\n'
                return
            fi
        done <<EOF
$MAC_VENDOR_SIGNALS
EOF
    fi

    # =========================================================
    # STEP 3: SCORE ACCUMULATION
    # =========================================================
    _p7_score_windows=0 _p7_score_linux=0 _p7_score_nd=0
    _p7_ev_win="" _p7_ev_linux="" _p7_ev_nd=""

    # PORT_SIGNALS
    while IFS= read -r _p7_entry; do
        [ -z "$_p7_entry" ] && continue
        _p7_proto=$(echo "$_p7_entry" | cut -d: -f1)
        _p7_pnum=$( echo "$_p7_entry" | cut -d: -f2)
        _p7_cat_raw=$(echo "$_p7_entry" | cut -d: -f3)
        _p7_weight=$( echo "$_p7_entry" | cut -d: -f5)

        _p7_hit=false
        if [ "$_p7_proto" = "tcp" ]; then
            grep -q "^port_open_tcp:${_p7_pnum}$" "$_p7_ev_file" && _p7_hit=true
        else
            grep -q "^port_open_udp:${_p7_pnum}$" "$_p7_ev_file" && _p7_hit=true
        fi

        if [ "$_p7_hit" = true ]; then
            case "$_p7_cat_raw" in
                windows)
                    _p7_score_windows=$((_p7_score_windows + _p7_weight))
                    _p7_ev_win="${_p7_ev_win}p${_p7_pnum}+"
                    printf '  [WIN] +%s: %s port %s\n' "$_p7_weight" "$_p7_proto" "$_p7_pnum" >> "$_p7_debug_file"
                    ;;
                linux)
                    _p7_score_linux=$((_p7_score_linux + _p7_weight))
                    _p7_ev_linux="${_p7_ev_linux}p${_p7_pnum}+"
                    printf '  [LIN] +%s: %s port %s\n' "$_p7_weight" "$_p7_proto" "$_p7_pnum" >> "$_p7_debug_file"
                    ;;
                network_device*)
                    _p7_score_nd=$((_p7_score_nd + _p7_weight))
                    _p7_ev_nd="${_p7_ev_nd}p${_p7_pnum}+"
                    printf '  [ND] +%s: %s port %s\n' "$_p7_weight" "$_p7_proto" "$_p7_pnum" >> "$_p7_debug_file"
                    ;;
            esac
        fi
    done <<EOF
$PORT_SIGNALS
EOF

    # BANNER_SIGNALS
    while IFS= read -r _p7_entry; do
        [ -z "$_p7_entry" ] && continue
        _p7_ftype=$(  echo "$_p7_entry" | cut -d: -f1)
        _p7_pat=$(    echo "$_p7_entry" | cut -d: -f2)
        _p7_cat_raw=$(echo "$_p7_entry" | cut -d: -f3)
        _p7_weight=$( echo "$_p7_entry" | cut -d: -f5)

        case "$_p7_ftype" in
            http_server)    _p7_field_val="$_p7_http_server" ;;
            ssh_banner)     _p7_field_val="$_p7_ssh_banner" ;;
            nmap_os_string) _p7_field_val="$_p7_nmap_os_string" ;;
            snmp_sysdescr)  _p7_field_val="$_p7_snmp_sysdescr" ;;
            *)              _p7_field_val="" ;;
        esac

        if [ -n "$_p7_field_val" ] && echo "$_p7_field_val" | grep -qiE "$_p7_pat"; then
            case "$_p7_cat_raw" in
                windows)
                    _p7_score_windows=$((_p7_score_windows + _p7_weight))
                    _p7_ev_win="${_p7_ev_win}${_p7_ftype}(${_p7_pat})+"
                    printf '  [WIN] +%s: %s matches "%s"\n' "$_p7_weight" "$_p7_ftype" "$_p7_pat" >> "$_p7_debug_file"
                    ;;
                linux)
                    _p7_score_linux=$((_p7_score_linux + _p7_weight))
                    _p7_ev_linux="${_p7_ev_linux}${_p7_ftype}(${_p7_pat})+"
                    printf '  [LIN] +%s: %s matches "%s"\n' "$_p7_weight" "$_p7_ftype" "$_p7_pat" >> "$_p7_debug_file"
                    ;;
                network_device*)
                    _p7_score_nd=$((_p7_score_nd + _p7_weight))
                    _p7_ev_nd="${_p7_ev_nd}${_p7_ftype}(${_p7_pat})+"
                    printf '  [ND] +%s: %s matches "%s"\n' "$_p7_weight" "$_p7_ftype" "$_p7_pat" >> "$_p7_debug_file"
                    ;;
            esac
        fi
    done <<EOF
$BANNER_SIGNALS
EOF

    # MAC_VENDOR_SIGNALS
    if [ -n "$_p7_mac_vendor" ]; then
        while IFS= read -r _p7_entry; do
            [ -z "$_p7_entry" ] && continue
            _p7_mvp=$(   echo "$_p7_entry" | cut -d: -f1)
            _p7_mvc=$(   echo "$_p7_entry" | cut -d: -f2)
            _p7_weight=$(echo "$_p7_entry" | cut -d: -f4)

            if echo "$_p7_mac_vendor" | grep -qiF "$_p7_mvp"; then
                case "$_p7_mvc" in
                    network_device)
                        _p7_score_nd=$((_p7_score_nd + _p7_weight))
                        _p7_ev_nd="${_p7_ev_nd}mac(${_p7_mvp})+"
                        printf '  [ND] +%s: MAC vendor "%s"\n' "$_p7_weight" "$_p7_mvp" >> "$_p7_debug_file"
                        ;;
                    windows)
                        _p7_score_windows=$((_p7_score_windows + _p7_weight))
                        _p7_ev_win="${_p7_ev_win}mac(${_p7_mvp})+"
                        printf '  [WIN] +%s: MAC vendor "%s"\n' "$_p7_weight" "$_p7_mvp" >> "$_p7_debug_file"
                        ;;
                esac
                break
            fi
        done <<EOF
$MAC_VENDOR_SIGNALS
EOF
    fi

    # TTL_SIGNALS — prefer normalized TTL; fall back to raw with fuzzy ranges
    _p7_ttl_used="${_p7_ttl_normalized:-$_p7_ttl_raw}"
    if [ -n "$_p7_ttl_used" ]; then
        _p7_ttl_matched=false
        while IFS= read -r _p7_entry; do
            [ -z "$_p7_entry" ] && continue
            _p7_ttl_val=$(echo "$_p7_entry" | cut -d: -f1)
            _p7_cat_raw=$(echo "$_p7_entry" | cut -d: -f2)
            _p7_weight=$( echo "$_p7_entry" | cut -d: -f4)

            if [ "$_p7_ttl_used" = "$_p7_ttl_val" ]; then
                case "$_p7_cat_raw" in
                    windows)
                        _p7_score_windows=$((_p7_score_windows + _p7_weight))
                        _p7_ev_win="${_p7_ev_win}ttl${_p7_ttl_used}+"
                        printf '  [WIN] +%s: TTL %s (exact)\n' "$_p7_weight" "$_p7_ttl_used" >> "$_p7_debug_file"
                        ;;
                    linux)
                        _p7_score_linux=$((_p7_score_linux + _p7_weight))
                        _p7_ev_linux="${_p7_ev_linux}ttl${_p7_ttl_used}+"
                        printf '  [LIN] +%s: TTL %s (exact)\n' "$_p7_weight" "$_p7_ttl_used" >> "$_p7_debug_file"
                        ;;
                    network_device)
                        _p7_score_nd=$((_p7_score_nd + _p7_weight))
                        _p7_ev_nd="${_p7_ev_nd}ttl${_p7_ttl_used}+"
                        printf '  [ND] +%s: TTL %s (exact)\n' "$_p7_weight" "$_p7_ttl_used" >> "$_p7_debug_file"
                        ;;
                esac
                _p7_ttl_matched=true; break
            fi
        done <<EOF
$TTL_SIGNALS
EOF

        # Fuzzy fallback when traceroute normalization was unavailable
        if [ "$_p7_ttl_matched" = false ] && [ -z "$_p7_ttl_normalized" ]; then
            if [ "$_p7_ttl_used" -ge 115 ] && [ "$_p7_ttl_used" -le 142 ]; then
                _p7_score_windows=$((_p7_score_windows + 25))
                _p7_ev_win="${_p7_ev_win}ttl${_p7_ttl_used}(fuzzy)+"
                printf '  [WIN] +25: TTL %s (fuzzy 115-142)\n' "$_p7_ttl_used" >> "$_p7_debug_file"
            elif [ "$_p7_ttl_used" -ge 55 ] && [ "$_p7_ttl_used" -le 70 ]; then
                _p7_score_linux=$((_p7_score_linux + 25))
                _p7_ev_linux="${_p7_ev_linux}ttl${_p7_ttl_used}(fuzzy)+"
                printf '  [LIN] +25: TTL %s (fuzzy 55-70)\n' "$_p7_ttl_used" >> "$_p7_debug_file"
            elif [ "$_p7_ttl_used" -ge 248 ]; then
                _p7_score_nd=$((_p7_score_nd + 25))
                _p7_ev_nd="${_p7_ev_nd}ttl${_p7_ttl_used}(fuzzy)+"
                printf '  [ND] +25: TTL %s (fuzzy 248-255)\n' "$_p7_ttl_used" >> "$_p7_debug_file"
            fi
        fi
    fi

    # DNS_SIGNALS (Tier 3 — capped at +20 per category)
    if [ -n "$_p7_dns_hostname" ]; then
        _p7_dns_win=0 _p7_dns_linux=0 _p7_dns_nd=0
        while IFS= read -r _p7_entry; do
            [ -z "$_p7_entry" ] && continue
            _p7_pat=$(    echo "$_p7_entry" | cut -d: -f1)
            _p7_cat_raw=$(echo "$_p7_entry" | cut -d: -f2)
            _p7_weight=$( echo "$_p7_entry" | cut -d: -f4)

            if echo "$_p7_dns_hostname" | grep -qiE "$_p7_pat"; then
                case "$_p7_cat_raw" in
                    windows)
                        if [ "$_p7_dns_win" -lt 20 ]; then
                            _p7_dns_win=$((_p7_dns_win + _p7_weight))
                            _p7_score_windows=$((_p7_score_windows + _p7_weight))
                            printf '  [WIN] +%s: DNS "%s" (Tier 3)\n' "$_p7_weight" "$_p7_pat" >> "$_p7_debug_file"
                        fi ;;
                    linux)
                        if [ "$_p7_dns_linux" -lt 20 ]; then
                            _p7_dns_linux=$((_p7_dns_linux + _p7_weight))
                            _p7_score_linux=$((_p7_score_linux + _p7_weight))
                            printf '  [LIN] +%s: DNS "%s" (Tier 3)\n' "$_p7_weight" "$_p7_pat" >> "$_p7_debug_file"
                        fi ;;
                    network_device)
                        if [ "$_p7_dns_nd" -lt 20 ]; then
                            _p7_dns_nd=$((_p7_dns_nd + _p7_weight))
                            _p7_score_nd=$((_p7_score_nd + _p7_weight))
                            printf '  [ND] +%s: DNS "%s" (Tier 3)\n' "$_p7_weight" "$_p7_pat" >> "$_p7_debug_file"
                        fi ;;
                esac
            fi
        done <<EOF
$DNS_SIGNALS
EOF
    fi

    # Compound signals
    if grep -q "^port_open_tcp:22$" "$_p7_ev_file" && \
       grep -q "^port_open_tcp:23$" "$_p7_ev_file" && \
       grep -q "^port_open_udp:161$" "$_p7_ev_file"; then
        _p7_score_nd=$((_p7_score_nd + 40)); _p7_ev_nd="${_p7_ev_nd}ssh+telnet+snmp+"
        printf '  [ND] +40: SSH+Telnet+SNMP compound\n' >> "$_p7_debug_file"
    fi
    if grep -q "^port_open_tcp:22$" "$_p7_ev_file" && \
       ! grep -q "^port_open_tcp:445$" "$_p7_ev_file" && \
       ! grep -q "^port_open_tcp:135$" "$_p7_ev_file"; then
        _p7_score_linux=$((_p7_score_linux + 15)); _p7_ev_linux="${_p7_ev_linux}ssh_no_smb+"
        printf '  [LIN] +15: SSH open, no SMB/MSRPC\n' >> "$_p7_debug_file"
    fi
    if ! grep -q "^port_open_tcp:22$" "$_p7_ev_file"; then
        _p7_score_windows=$((_p7_score_windows + 10)); _p7_ev_win="${_p7_ev_win}no_ssh+"
        printf '  [WIN] +10: no SSH\n' >> "$_p7_debug_file"
    fi

    # =========================================================
    # STEP 4: CONFLICT RESOLUTION
    # =========================================================
    {
        printf '\n--- SCORES ---\n'
        printf '  Windows: %s\n  Linux: %s\n  NetworkDevice: %s\n' \
            "$_p7_score_windows" "$_p7_score_linux" "$_p7_score_nd"
    } >> "$_p7_debug_file"

    _p7_max_other=$_p7_score_windows
    [ "$_p7_score_linux" -gt "$_p7_max_other" ] && _p7_max_other=$_p7_score_linux

    if [ "$_p7_score_nd" -gt 40 ] && [ "$_p7_score_nd" -ge "$((_p7_max_other - 40))" ]; then
        _p7_category="network_device"; _p7_score=$_p7_score_nd; _p7_evidence="$_p7_ev_nd"
        printf '  CONFLICT: ND wins (%s >= %s-40)\n' "$_p7_score_nd" "$_p7_max_other" >> "$_p7_debug_file"
    else
        _p7_win_linux_diff=$((_p7_score_windows - _p7_score_linux))
        [ "$_p7_win_linux_diff" -lt 0 ] && _p7_win_linux_diff=$((-_p7_win_linux_diff))
        if [ "$_p7_score_windows" -ge 60 ] && [ "$_p7_score_linux" -ge 60 ] && \
           [ "$_p7_win_linux_diff" -lt 20 ]; then
            _p7_category="unknown"; _p7_score=0; _p7_confidence="none"
            _p7_evidence="contradictory:win=${_p7_score_windows},linux=${_p7_score_linux}"
            printf '  CONFLICT: contradictory evidence\n' >> "$_p7_debug_file"
        elif [ "$_p7_score_windows" -ge "$_p7_score_linux" ] && \
             [ "$_p7_score_windows" -ge "$_p7_score_nd" ]; then
            _p7_category="windows"; _p7_score=$_p7_score_windows; _p7_evidence="$_p7_ev_win"
        elif [ "$_p7_score_linux" -ge "$_p7_score_nd" ]; then
            _p7_category="linux"; _p7_score=$_p7_score_linux; _p7_evidence="$_p7_ev_linux"
        else
            _p7_category="network_device"; _p7_score=$_p7_score_nd; _p7_evidence="$_p7_ev_nd"
        fi
    fi

    # =========================================================
    # STEP 5: CONFIDENCE THRESHOLD
    # =========================================================
    if [ "$_p7_category" != "unknown" ]; then
        if   [ "$_p7_score" -ge 150 ]; then _p7_confidence="very_high"
        elif [ "$_p7_score" -ge 100 ]; then _p7_confidence="high"
        elif [ "$_p7_score" -ge 60  ]; then _p7_confidence="medium"
        else
            _p7_evidence="${_p7_evidence}:below_threshold(${_p7_score})"
            _p7_category="unknown"; _p7_confidence="none"; _p7_score=0
        fi
    fi

    # =========================================================
    # STEP 6: VENDOR DETECTION (for network_device)
    # =========================================================
    if [ "$_p7_category" = "network_device" ] && [ "$_p7_vendor" = "-" ]; then
        _p7_vendor=$(detect_device_vendor "$_p7_ip" "$_p7_mac_vendor" "$_p7_ssh_banner" "$_p7_http_server" "$_p7_snmp_sysdescr")
    fi

    # Strip trailing +
    _p7_evidence=$(printf '%s' "$_p7_evidence" | sed 's/+$//')

    printf '  FINAL: %s | %s | %s | %s | %s\n' \
        "$_p7_category" "$_p7_vendor" "$_p7_confidence" "$_p7_score" "$_p7_evidence" >> "$_p7_debug_file"
    printf '%s|%s|%s|%s|%s\n' "$_p7_category" "$_p7_vendor" "$_p7_confidence" "$_p7_score" "$_p7_evidence"
}
