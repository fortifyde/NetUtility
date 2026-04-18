#!/bin/sh
# ph7_registry.sh — Evidence signal registry for Phase 7 host categorization.
# Sourced by multi_phase_discovery.sh. Do not execute directly.
#
# Signal entry formats (newline-separated, one entry per line):
#   SNMP_GATES / SERVICE_VERSION_GATES: "PATTERN:CATEGORY:TIER:WEIGHT"
#   PORT_SIGNALS:                       "PROTO:PORT:CATEGORY:TIER:WEIGHT"
#   BANNER_SIGNALS:                     "FIELD_TYPE:PATTERN:CATEGORY:TIER:WEIGHT"
#   MAC_VENDOR_SIGNALS:                 "PATTERN:CATEGORY:TIER:WEIGHT"
#   TTL_SIGNALS:                        "TTL_VALUE:CATEGORY:TIER:WEIGHT"
#   DNS_SIGNALS:                        "PATTERN:CATEGORY:TIER:WEIGHT"
#
# TIER 1 entries (gates) short-circuit classification immediately.
# TIER 2/3 entries contribute a weighted score.
# Gates are checked in entry order — more specific patterns must precede generic ones.

# ---------------------------------------------------------------------------
# TIER 1: SNMP sysDescr gates (first match wins)
# Linux-based network appliances MUST appear before any generic "Linux" entry.
# "Linux" in sysDescr is NOT a gate — handled as Tier 2 in BANNER_SIGNALS.
# ---------------------------------------------------------------------------
SNMP_GATES="Cisco IOS:network_device:1:99
JUNOS:network_device:1:99
FortiOS:network_device:1:99
PAN-OS:network_device:1:99
Aruba:network_device:1:99
EOS:network_device:1:99
NX-OS:network_device:1:99
ExtremeXOS:network_device:1:99
Comware:network_device:1:99
RouterOS:network_device:1:99
ASA:network_device:1:99
EdgeOS:network_device:1:99
AirOS:network_device:1:99
UniFi:network_device:1:99
OpenWrt:network_device:1:99
DD-WRT:network_device:1:99
pfSense:network_device:1:99
OPNsense:network_device:1:99
VyOS:network_device:1:99
GenuGate:network_device:1:99
GenuScreen:network_device:1:99
GenuBox:network_device:1:99
Eaton:network_device:1:99
Powerware:network_device:1:99
Liebert:network_device:1:99
Vertiv:network_device:1:99
American Power Conversion:network_device:1:99
MGE UPS Systems:network_device:1:99
Data ONTAP:network_device:1:99
NetApp Release:network_device:1:99
DiskStation:network_device:1:99
QTS:network_device:1:99
Fabric OS:network_device:1:99
Integrated Lights-Out:network_device:1:99
iDRAC:network_device:1:99
iRMC:network_device:1:99
HP LaserJet:network_device/printer:1:99
HP OfficeJet:network_device/printer:1:99
HP PageWide:network_device/printer:1:99
Canon iR:network_device/printer:1:99
Xerox:network_device/printer:1:99
Epson:network_device/printer:1:99
Brother Print:network_device/printer:1:99
Lexmark:network_device/printer:1:99
Ricoh:network_device/printer:1:99
Konica Minolta:network_device/printer:1:99
Kyocera:network_device/printer:1:99"

# ---------------------------------------------------------------------------
# TIER 1: Service version string gates
# ---------------------------------------------------------------------------
SERVICE_VERSION_GATES="Cisco IOS:network_device:1:99
Juniper Networks:network_device:1:99
Aruba Networks:network_device:1:99
Fortinet:network_device:1:99
Palo Alto:network_device:1:99
OpenSSH_for_Windows:windows:1:99
smbd:linux:1:99
Samba:linux:1:99
Microsoft Windows:windows:1:99"

# ---------------------------------------------------------------------------
# TIER 2: Port signals (TCP/UDP open)
# ---------------------------------------------------------------------------
PORT_SIGNALS="tcp:445:windows:2:60
tcp:135:windows:2:45
tcp:5985:windows:2:50
tcp:5986:windows:2:50
tcp:139:windows:2:35
tcp:3389:windows:2:40
tcp:88:windows:2:35
tcp:111:linux:2:35
tcp:2049:linux:2:40
udp:161:network_device:2:25
udp:623:network_device:2:30
tcp:515:network_device/printer:2:55
tcp:631:network_device/printer:2:55
tcp:9100:network_device/printer:2:60"

# ---------------------------------------------------------------------------
# TIER 2: Banner / header / OS-string signals
# Field types: http_server | ssh_banner | nmap_os_string | snmp_sysdescr
# Patterns are passed to `grep -iE`; avoid colons in patterns.
# ---------------------------------------------------------------------------
BANNER_SIGNALS="http_server:Microsoft-IIS:windows:2:55
http_server:Apache.*(Ubuntu|Debian|CentOS|Red Hat|Fedora|AlmaLinux|Rocky):linux:2:55
http_server:nginx:linux:2:20
ssh_banner:Ubuntu:linux:2:65
ssh_banner:Debian:linux:2:65
ssh_banner:CentOS:linux:2:65
ssh_banner:Red Hat:linux:2:65
ssh_banner:Fedora:linux:2:65
ssh_banner:Alpine:linux:2:65
ssh_banner:openSUSE:linux:2:65
ssh_banner:RHEL:linux:2:65
ssh_banner:FreeBSD:linux:2:60   # intentional: no BSD category — unix-like, linux bucket is acceptable
nmap_os_string:Windows:windows:2:60
nmap_os_string:Linux:linux:2:60
snmp_sysdescr:Linux:linux:2:55
snmp_sysdescr:Windows:windows:2:55
http_server:HP-iLO:network_device:2:70
http_server:iDRAC:network_device:2:70
http_server:iRMC:network_device:2:70"

# ---------------------------------------------------------------------------
# TIER 2: MAC vendor signals
# HP networking (HPE) vs HP printers (HP Inc) have distinct OUI prefixes.
# ---------------------------------------------------------------------------
MAC_VENDOR_SIGNALS="Cisco Systems:network_device:2:45
Juniper Networks:network_device:2:45
Aruba Networks:network_device:2:45
Hewlett Packard Enterprise:network_device:2:45
Fortinet:network_device:2:45
Palo Alto Networks:network_device:2:45
Check Point:network_device:2:45
HP Inc:network_device/printer:2:40
Canon:network_device/printer:2:40
Xerox:network_device/printer:2:40
Epson:network_device/printer:2:40
Brother Industries:network_device/printer:2:40
Lexmark:network_device/printer:2:40
Ricoh:network_device/printer:2:40
Eaton:network_device:2:45
Schneider Electric:network_device:2:45
Vertiv:network_device:2:45
NetApp:network_device:2:45
Brocade:network_device:2:45"

# ---------------------------------------------------------------------------
# TIER 2: Normalized starting TTL (exact match after traceroute normalization)
# ---------------------------------------------------------------------------
TTL_SIGNALS="128:windows:2:40
64:linux:2:40
255:network_device:2:40"

# ---------------------------------------------------------------------------
# TIER 3: DNS hostname pattern signals (max +20 contribution per category)
# Patterns are passed to `grep -iE` against the hostname string.
# ---------------------------------------------------------------------------
DNS_SIGNALS="win|wks|desk|desktop|workstation:windows:3:10
sw|rt|rtr|gw|fw|vpn|router|switch|firewall|core|edge|dist|access:network_device:3:15
ubuntu|debian|rhel|linux|srv|web|db|mail|proxy:linux:3:8"
