#!/bin/sh

# Exclude Audit Team IP Addresses from Discovery Results
#
# Detects team systems by comparing neighbor MAC prefixes (first 4 octets) and
# OUI vendor lookups against the host's own interfaces.  Matching IPs are
# presented for confirmation and then removed from all hostfiles, enriched
# variants, service targets, and both correlation JSON files.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

. "$SCRIPT_DIR/../common/colors.sh"
. "$SCRIPT_DIR/../common/logging.sh"
. "$SCRIPT_DIR/../common/utils.sh"

WORKDIR="${NETUTIL_WORKDIR:-$HOME}"
DISCOVERY_DIR="$WORKDIR/discovery"
CORRELATIONS_DIR="$PROJECT_ROOT/correlations"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# Parse arguments
EXCLUDE_IP_FILE=""
while [ $# -gt 0 ]; do
    case "$1" in
        -f|--file)
            shift
            EXCLUDE_IP_FILE="$1"
            ;;
        -h|--help)
            echo "Usage: $0 [-f|--file <ip_list_file>]"
            echo "  Without arguments: auto-detect team IPs via MAC/OUI"
            echo "  -f, --file: Provide a file of IPs to exclude (one per line)"
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 1
            ;;
    esac
    shift
done

# ---- OUI helper detection (same locations as mac_analysis.sh) ----

OUIHELPER_BIN=""
if command -v ouihelper >/dev/null 2>&1; then
    OUIHELPER_BIN="ouihelper"
elif [ -f "$SCRIPT_DIR/../../bin/ouihelper" ]; then
    OUIHELPER_BIN="$SCRIPT_DIR/../../bin/ouihelper"
elif [ -f "$SCRIPT_DIR/../../cmd/ouihelper/ouihelper" ]; then
    OUIHELPER_BIN="$SCRIPT_DIR/../../cmd/ouihelper/ouihelper"
elif [ -f "$SCRIPT_DIR/../../ouihelper" ]; then
    OUIHELPER_BIN="$SCRIPT_DIR/../../ouihelper"
fi

if [ -z "$OUIHELPER_BIN" ] || [ ! -x "$OUIHELPER_BIN" ]; then
    if command -v color_error >/dev/null 2>&1; then
        color_error "ouihelper binary not found. Required for vendor lookup."
    else
        echo "Error: ouihelper binary not found." >&2
    fi
    exit 1
fi

jq_missing=false
if ! command -v jq >/dev/null 2>&1; then
    jq_missing=true
fi

# ---- Helper functions ----

lookup_vendor() {
    $OUIHELPER_BIN lookup "$1" 2>/dev/null || echo "Unknown"
}

normalize_mac() {
    echo "$1" | tr '[:upper:]' '[:lower:]'
}

mac_prefix4() {
    normalize_mac "$1" | awk -F: '{printf "%s:%s:%s:%s",$1,$2,$3,$4}'
}

mac_oui() {
    normalize_mac "$1" | awk -F: '{printf "%s:%s:%s",$1,$2,$3}'
}

valid_ipv4() {
    case "$1" in
        [0-9]*.[0-9]*.[0-9]*.[0-9]*) return 0 ;;
        *) return 1 ;;
    esac
}

remove_ips_from_file() {
    _fp="$1"
    [ ! -f "$_fp" ] || [ ! -s "$_fp" ] && return 0

    _bn=$(basename "$_fp")
    _before=$(wc -l < "$_fp")

    case "$_bn" in
        *_enriched.txt)
            awk -F'[[:space:]:]' \
                'NR==FNR{e[$1];next} !($1 in e)' \
                "$TMPDIR/final_ips.txt" "$_fp" > "$_fp.tmp"
            ;;
        categorization_details.txt)
            awk -F'\t' \
                'NR==FNR{e[$1];next} !($1 in e)' \
                "$TMPDIR/final_ips.txt" "$_fp" > "$_fp.tmp"
            ;;
        *)
            grep -vxFf "$TMPDIR/final_ips.txt" "$_fp" > "$_fp.tmp" 2>/dev/null || true
            ;;
    esac

    _after=$(wc -l < "$_fp.tmp" 2>/dev/null || echo "$_before")

    if [ "$_before" -ne "$_after" ] 2>/dev/null; then
        mv "$_fp.tmp" "$_fp"
        files_modified=$((files_modified + 1))
        _rel=${_fp#"$WORKDIR"/}
        [ "$_rel" = "$_fp" ] || _fp=".../$_rel"
        printf "%s%s%s\n" "$COLOR_RESET" "  $_fp (-$((_before - _after)) entries)" "$COLOR_RESET" >&2
    else
        rm -f "$_fp.tmp"
    fi
}

process_session_tree() {
    _session="$1"

    for _dir in "$_session" "$_session"/*; do
        [ ! -d "$_dir" ] && continue

        if [ -d "$_dir/hostfiles" ]; then
            for _f in "$_dir/hostfiles"/*.txt; do
                [ -f "$_f" ] && remove_ips_from_file "$_f"
            done
        fi

        if [ -d "$_dir/service_targets" ]; then
            for _f in "$_dir/service_targets"/*.txt; do
                [ -f "$_f" ] && remove_ips_from_file "$_f"
            done
        fi
    done

    # Clean categorization_details.txt files anywhere in the session tree
    find "$_session" -name "categorization_details.txt" -type f > "$TMPDIR/cat_details.txt" 2>/dev/null
    while read -r _f; do
        remove_ips_from_file "$_f"
    done < "$TMPDIR/cat_details.txt"

    # Delete per-IP debug and evidence files for excluded IPs from any categorization_debug/
    # and phase7 evidence/ directories anywhere in the session tree
    find "$_session" -type d \( -name "categorization_debug" -o \( -name "evidence" -path "*/phase7*" \) \) \
        > "$TMPDIR/ip_file_dirs.txt" 2>/dev/null
    while read -r _dbgdir; do
        while read -r _ip; do
            [ -z "$_ip" ] && continue
            for _f in "$_dbgdir/${_ip}_debug.txt" "$_dbgdir/${_ip}.ev"; do
                if [ -f "$_f" ]; then
                    rm -f "$_f"
                    files_modified=$((files_modified + 1))
                    _rel=${_f#"$WORKDIR"/}
                    [ "$_rel" = "$_f" ] && _rel="$_f"
                    printf "%s%s%s\n" "$COLOR_RESET" "  deleted: .../$_rel" "$COLOR_RESET" >&2
                fi
            done
        done < "$TMPDIR/final_ips.txt"
    done < "$TMPDIR/ip_file_dirs.txt"
}


# ---- Interactive mode selection (TUI / terminal) ----
if [ -z "$EXCLUDE_IP_FILE" ]; then
    echo "" >&2
    echo "Select exclusion mode:" >&2
    echo "  1) Auto-detect team IPs via MAC/OUI fingerprinting" >&2
    echo "  2) Provide a list of IPs to exclude" >&2
    echo "" >&2

    while true; do
        echo "  Choice [1/2]: " >&2
        read -r _exclude_mode
        case "$_exclude_mode" in
            1)
                echo "  Using auto-detect." >&2
                break
                ;;
            2)
                while true; do
                    echo "  Enter path to IP list file: " >&2
                    read -r EXCLUDE_IP_FILE
                    if [ -z "$EXCLUDE_IP_FILE" ]; then
                        echo "  No file provided. Please enter a path or press Ctrl+C to cancel." >&2
                        continue
                    elif [ ! -f "$EXCLUDE_IP_FILE" ]; then
                        echo "  Error: File not found: $EXCLUDE_IP_FILE" >&2
                        EXCLUDE_IP_FILE=""
                        continue
                    fi
                    break
                done
                break
                ;;
            *)
                echo "  Invalid choice. Please enter 1 or 2." >&2
                ;;
        esac
    done
fi


# ---- Skip auto-detection if IP file provided ----
if [ -n "$EXCLUDE_IP_FILE" ]; then
    if [ ! -f "$EXCLUDE_IP_FILE" ]; then
        echo "Error: File not found: $EXCLUDE_IP_FILE" >&2
        exit 1
    fi

    : > "$TMPDIR/final_ips.txt"
    ip_count=0
    while read -r line; do
        # Strip leading/trailing whitespace
        line=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

        # Skip blank lines and comments
        case "$line" in
            ''|'#'*) continue ;;
        esac

        # Basic IPv4 validation
        if echo "$line" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
            echo "$line" >> "$TMPDIR/final_ips.txt"
            ip_count=$((ip_count + 1))
        else
            echo "Warning: Skipping invalid IP: $line" >&2
        fi
    done < "$EXCLUDE_IP_FILE"

    if [ "$ip_count" -eq 0 ]; then
        echo "Error: No valid IPs found in $EXCLUDE_IP_FILE" >&2
        exit 1
    fi

    final_count=$ip_count
    echo "" >&2
    echo "Loaded $final_count IP(s) from $EXCLUDE_IP_FILE" >&2
    echo "IPs to exclude ($final_count):" >&2
    while read -r ip; do
        printf "  - %s\n" "$ip" >&2
    done < "$TMPDIR/final_ips.txt"
    echo "" >&2

    if ! confirm_action "Proceed with exclusion?"; then
        echo "Cancelled." >&2
        exit 0
    fi

    # Deduplicate the loaded IPs
    sort -u "$TMPDIR/final_ips.txt" > "${TMPDIR}/final_ips_sorted.txt"
    mv "${TMPDIR}/final_ips_sorted.txt" "$TMPDIR/final_ips.txt"
    final_count=$(wc -l < "$TMPDIR/final_ips.txt")
fi

if [ -z "$EXCLUDE_IP_FILE" ]; then
# ===================================================================
# Phase 1 – Host fingerprinting
# ===================================================================

if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
    printf "%s%s%s\n" "$COLOR_YELLOW" "Phase 1/6: HOST FINGERPRINTING — Collecting local MAC addresses and vendors" "$COLOR_RESET" >&2
elif command -v print_phase_header >/dev/null 2>&1; then
    print_phase_header "PHASE 1: HOST FINGERPRINTING" >&2
    color_info "Collecting local MAC addresses and vendors..." >&2
else
    echo >&2
    echo "Phase 1: Host Fingerprinting - Collecting local MAC addresses and vendors" >&2
fi

ip link show | awk '/link\/ether/ && $2 != "00:00:00:00:00:00"{print $2}' \
    | sort -u > "$TMPDIR/host_macs.txt"

if [ ! -s "$TMPDIR/host_macs.txt" ]; then
    if command -v color_error >/dev/null 2>&1; then
        color_error "No local MAC addresses found."
    else
        echo "Error: No local MAC addresses found." >&2
    fi
    exit 1
fi

host_mac_count=$(wc -l < "$TMPDIR/host_macs.txt")
printf "%s%s%s\n" "$COLOR_RESET" "Found $host_mac_count local MAC address(es)" "$COLOR_RESET" >&2

: > "$TMPDIR/host_fp.txt"
while read -r mac; do
    [ -z "$mac" ] && continue
    p4=$(mac_prefix4 "$mac")
    oui=$(mac_oui "$mac")
    vendor=$(lookup_vendor "$mac")
    printf '%s\t%s\t%s\t%s\n' "$mac" "$p4" "$oui" "$vendor" >> "$TMPDIR/host_fp.txt"
    printf "%s%s%s\n" "$COLOR_RESET" "  $mac  prefix=$p4  vendor=$vendor" "$COLOR_RESET" >&2
done < "$TMPDIR/host_macs.txt"

log_info "Host fingerprints: $host_mac_count" "exclude_team_ips.sh"

# ===================================================================
# Phase 2 – Neighbor scanning
# ===================================================================

if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
    printf "%s%s%s\n" "$COLOR_YELLOW" "Phase 2/6: NEIGHBOR SCANNING — Matching ARP table against host fingerprints" "$COLOR_RESET" >&2
elif command -v print_phase_header >/dev/null 2>&1; then
    print_phase_header "PHASE 2: NEIGHBOR SCANNING" >&2
    color_info "Matching ARP table against host fingerprints..." >&2
else
    echo >&2
    echo "Phase 2: Neighbor Scanning - Matching ARP table against host fingerprints" >&2
fi

printf "%s%s%s\n" "$COLOR_RESET" "Scanning ARP/neighbor table..." "$COLOR_RESET" >&2

: > "$TMPDIR/candidates_raw.txt"

ip neigh show | while read -r line; do
    nip=$(echo "$line" | awk '{print $1}')
    valid_ipv4 "$nip" || continue

    case "$line" in
        *lladdr*) nmac=$(echo "$line" | sed 's/.*lladdr \([0-9a-fA-F:]*\).*/\1/') ;;
        *) continue ;;
    esac

    [ -z "$nmac" ] || [ "$nmac" = "00:00:00:00:00:00" ] && continue

    np4=$(mac_prefix4 "$nmac")

    while IFS="$(printf '\t')" read -r hmac hp4 houil hvendor; do
        [ -z "$hp4" ] && continue
        if [ "$np4" = "$hp4" ]; then
            nvendor=$(lookup_vendor "$nmac")
            if [ "$nvendor" = "$hvendor" ]; then
                printf '%s\t%s\t%s\t%s\n' "$nip" "$nmac" "$nvendor" "$hmac" \
                    >> "$TMPDIR/candidates_raw.txt"
                break
            fi
        fi
    done < "$TMPDIR/host_fp.txt"
done

if [ -s "$TMPDIR/candidates_raw.txt" ]; then
    sort -u -t"$(printf '\t')" -k1,1 "$TMPDIR/candidates_raw.txt" \
        > "$TMPDIR/candidates.txt"
else
    : > "$TMPDIR/candidates.txt"
fi

cand_count=$(wc -l < "$TMPDIR/candidates.txt" 2>/dev/null || echo 0)

if [ "$cand_count" -gt 0 ]; then
    printf "%s%s%s\n" "$COLOR_RESET" "Found $cand_count team system candidate(s)" "$COLOR_RESET" >&2
else
    if command -v color_warning >/dev/null 2>&1; then
        color_warning "No team system candidates detected automatically"
    else
        echo "Warning: No team system candidates detected automatically" >&2
    fi
fi

# ===================================================================
# Phase 3 – User confirmation & custom IPs
# ===================================================================

if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
    printf "%s%s%s\n" "$COLOR_YELLOW" "Phase 3/6: CONFIRM EXCLUSIONS — Review and select IPs to remove" "$COLOR_RESET" >&2
elif command -v print_phase_header >/dev/null 2>&1; then
    print_phase_header "PHASE 3: CONFIRM EXCLUSIONS" >&2
    color_info "Review and select IPs to remove..." >&2
else
    echo >&2
    echo "Phase 3: Confirm Exclusions - Review and select IPs to remove" >&2
fi

: > "$TMPDIR/confirmed_ips.txt"

if [ "$cand_count" -gt 0 ]; then
    echo "" >&2
    printf "%s%-4s %-18s %-20s %-30s %-20s%s\n" \
        "$COLOR_BOLD" "#" "IP Address" "MAC Address" "Vendor" "Host MAC" "$COLOR_RESET" >&2
    printf "%-4s %-18s %-20s %-30s %-20s\n" \
        "---" "------------------" "--------------------" "------------------------------" "--------------------" >&2

    idx=1
    : > "$TMPDIR/cand_ips.txt"
    while IFS="$(printf '\t')" read -r ip mac vendor hmac; do
        printf "%-4s %-18s %-20s %-30s %-20s\n" "$idx" "$ip" "$mac" "$vendor" "$hmac" >&2
        echo "$ip" >> "$TMPDIR/cand_ips.txt"
        idx=$((idx + 1))
    done < "$TMPDIR/candidates.txt"

    echo "" >&2
    while true; do
        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
            printf "%sChoice ( a All / s Select / c Custom / [ Cancel ] ): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
        else
            printf "Choice ( a All / s Select / c Custom / [ Cancel ] ): \n" >&2
        fi
        read -r action

        case "$action" in
            a|A)
                cp "$TMPDIR/cand_ips.txt" "$TMPDIR/confirmed_ips.txt"
                cnt=$(wc -l < "$TMPDIR/confirmed_ips.txt")
                echo "  All $cnt candidate(s) confirmed" >&2
                break
                ;;
            s|S)
                if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
                    printf "%sSelect numbers (space-separated): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
                else
                    printf "Select numbers (space-separated): \n" >&2
                fi
                read -r sels
                _found=0
                for num in $sels; do
                    case "$num" in *[!0-9]*) continue ;; esac
                    sip=$(sed -n "${num}p" "$TMPDIR/cand_ips.txt" 2>/dev/null)
                    if [ -n "$sip" ]; then
                        echo "$sip" >> "$TMPDIR/confirmed_ips.txt"
                        _found=$((_found + 1))
                    fi
                done
                if [ "$_found" -eq 0 ]; then
                    echo "  No valid selections. Please try again." >&2
                    continue
                fi
                echo "  $_found IP(s) selected" >&2
                break
                ;;
            c|C)
                break
                ;;
            *)
                echo "  Invalid choice. Enter a/s/c or press Enter to cancel." >&2
                ;;
        esac
    done
else
    echo "" >&2
    while true; do
        if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
            printf "%sChoice ( c=custom IP / Enter=Cancel ): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
        else
            printf "Choice ( c=custom IP / Enter=Cancel ): \n" >&2
        fi
        read -r action

        case "$action" in
            c|C) break ;;
            *) echo "  Invalid choice. Enter c or press Enter to cancel." >&2 ;;
        esac
    done
fi

# Custom IP entry
while true; do
    if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
        printf "%sIP to exclude (Enter to finish): %s\n" "$PROMPT_COLOR" "$COLOR_RESET" >&2
    else
        printf "IP to exclude (Enter to finish): \n" >&2
    fi
    read -r custom_ip

    [ -z "$custom_ip" ] && break

    if valid_ipv4 "$custom_ip"; then
        echo "$custom_ip" >> "$TMPDIR/confirmed_ips.txt"
        echo "  Added: $custom_ip" >&2
    else
        echo "  Invalid format — expected x.x.x.x" >&2
    fi
done

# Deduplicate final list
if [ -s "$TMPDIR/confirmed_ips.txt" ]; then
    sort -u "$TMPDIR/confirmed_ips.txt" > "$TMPDIR/final_ips.txt"
else
    : > "$TMPDIR/final_ips.txt"
fi

final_count=$(wc -l < "$TMPDIR/final_ips.txt")

if [ "$final_count" -eq 0 ]; then
    echo "" >&2
    echo "No IPs selected for exclusion. Exiting." >&2
    exit 0
fi

echo "" >&2
echo "IPs to exclude ($final_count):" >&2
while read -r ip; do
    printf "  - %s\n" "$ip" >&2
done < "$TMPDIR/final_ips.txt"

echo "" >&2
if ! confirm_action "Proceed with exclusion?"; then
    echo "Cancelled." >&2
    exit 0
fi

fi # end auto-detect phases 1-3

# ===================================================================
# Phase 4 – Remove from discovery files
# ===================================================================

if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
    printf "%s%s%s\n" "$COLOR_YELLOW" "Phase 4/6: CLEANING DISCOVERY FILES — Removing IPs from hostfiles and service targets" "$COLOR_RESET" >&2
elif command -v print_phase_header >/dev/null 2>&1; then
    print_phase_header "PHASE 4: CLEANING DISCOVERY FILES" >&2
    color_info "Removing IPs from hostfiles and service targets..." >&2
else
    echo >&2
    echo "Phase 4: Cleaning Discovery Files - Removing IPs from hostfiles and service targets" >&2
fi

files_modified=0

if [ -d "$DISCOVERY_DIR" ]; then
    printf "%s%s%s\n" "$COLOR_RESET" "Scanning $DISCOVERY_DIR" "$COLOR_RESET" >&2

    for session_dir in "$DISCOVERY_DIR"/*; do
        [ ! -d "$session_dir" ] && continue
        process_session_tree "$session_dir"
    done
else
    echo "  No discovery directory at $DISCOVERY_DIR" >&2
fi

if [ "$files_modified" -gt 0 ]; then
    printf "%s%s%s\n" "$COLOR_RESET" "Modified $files_modified discovery file(s)" "$COLOR_RESET" >&2
else
    printf "%s%s%s\n" "$COLOR_RESET" "  No discovery files contained matching IPs" "$COLOR_RESET" >&2
fi

# ===================================================================
# Phase 5 – Remove from correlation JSON
# ===================================================================

if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
    printf "%s%s%s\n" "$COLOR_YELLOW" "Phase 5/6: CLEANING CORRELATION FILES — Removing IPs from JSON" "$COLOR_RESET" >&2
elif command -v print_phase_header >/dev/null 2>&1; then
    print_phase_header "PHASE 5: CLEANING CORRELATION FILES" >&2
    color_info "Removing IPs from JSON..." >&2
else
    echo >&2
    echo "Phase 5: Cleaning Correlation Files - Removing IPs from JSON" >&2
fi

json_modified=0

if [ "$jq_missing" = "true" ]; then
    if command -v color_warning >/dev/null 2>&1; then
        color_warning "jq not found — skipping JSON cleanup. Install jq to enable."
    else
        echo "Warning: jq not found — skipping JSON cleanup." >&2
    fi
else
    # Build jq filter strings from the IP list
    jq_keys=""
    jq_add="{}"
    while read -r ip; do
        [ -z "$ip" ] && continue
        if [ -z "$jq_keys" ]; then
            jq_keys="\"$ip\""
        else
            jq_keys="$jq_keys, \"$ip\""
        fi
        jq_add="$jq_add + {\"$ip\": true}"
    done < "$TMPDIR/final_ips.txt"

    # Update excluded_hosts.json — used by the TUI correlator to permanently suppress these IPs
    excl_path="$CORRELATIONS_DIR/excluded_hosts.json"
    excl_tmp="$TMPDIR/excluded_hosts.json.tmp"
    if [ -f "$excl_path" ]; then
        if jq ". + $jq_add" "$excl_path" > "$excl_tmp" 2>/dev/null; then
            mv "$excl_tmp" "$excl_path"
            printf "%s%s%s\n" "$COLOR_RESET" "  excluded_hosts.json updated" "$COLOR_RESET" >&2
            json_modified=$((json_modified + 1))
        else
            rm -f "$excl_tmp"
            echo "  Warning: failed to update excluded_hosts.json" >&2
        fi
    else
        if jq -n "$jq_add" > "$excl_tmp" 2>/dev/null; then
            mv "$excl_tmp" "$excl_path"
            printf "%s%s%s\n" "$COLOR_RESET" "  excluded_hosts.json created" "$COLOR_RESET" >&2
            json_modified=$((json_modified + 1))
        else
            rm -f "$excl_tmp"
            echo "  Warning: failed to create excluded_hosts.json" >&2
        fi
    fi

    # Remove IPs from correlations.json and manual_categories.json
    for jf in correlations.json manual_categories.json; do
        jpath="$CORRELATIONS_DIR/$jf"
        [ -f "$jpath" ] || continue

        tmpj="$TMPDIR/$jf.tmp"
        if jq "del(.[$jq_keys])" "$jpath" > "$tmpj" 2>/dev/null; then
            if ! cmp -s "$jpath" "$tmpj" 2>/dev/null; then
                mv "$tmpj" "$jpath"
                json_modified=$((json_modified + 1))
                printf "%s%s%s\n" "$COLOR_RESET" "  $jf updated" "$COLOR_RESET" >&2
            else
                rm -f "$tmpj"
                printf "%s%s%s\n" "$COLOR_RESET" "  $jf — no matching IPs" "$COLOR_RESET" >&2
            fi
        else
            rm -f "$tmpj"
            echo "  Warning: failed to process $jf" >&2
        fi
    done

    if [ "$json_modified" -gt 0 ]; then
        printf "%s%s%s\n" "$COLOR_RESET" "Updated $json_modified correlation file(s)" "$COLOR_RESET" >&2
    fi
fi

# ===================================================================
# Summary
# ===================================================================

if [ "$NETUTIL_FORCE_COLOR" = "1" ]; then
    printf "%s%s%s\n" "$COLOR_YELLOW" "Phase 6/6: SUMMARY" "$COLOR_RESET" >&2
elif command -v print_phase_header >/dev/null 2>&1; then
    print_phase_header "SUMMARY" >&2
else
    echo >&2
    echo "=== Summary ===" >&2
fi

echo "" >&2
echo "IPs excluded:      $final_count" >&2
echo "Discovery files:   $files_modified modified" >&2
echo "Correlation files: $json_modified updated" >&2
echo "" >&2

log_info "Team IP exclusion complete: $final_count IPs, $files_modified discovery files, $json_modified JSON files" "exclude_team_ips.sh"

if command -v color_success >/dev/null 2>&1; then
    color_success "Exclusion complete" >&2
else
    echo "Exclusion complete" >&2
fi
