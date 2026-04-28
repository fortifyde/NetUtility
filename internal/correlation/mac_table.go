package correlation

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type macEntry struct {
	SwitchIP  string
	Interface string
	VLAN      int
}

type macIndex struct {
	entries map[string]macEntry // normalized MAC → entry
}

func newMACIndex() *macIndex {
	return &macIndex{entries: make(map[string]macEntry)}
}

const macPattern = `[0-9a-fA-F]{4}[.\-][0-9a-fA-F]{4}[.\-][0-9a-fA-F]{4}|[0-9a-fA-F]{2}(?:[:\-][0-9a-fA-F]{2}){5}`
// typeKeyword matches any non-whitespace token in the type column.
// Previously enumerated known values; now permissive to handle all Cisco/HP variants.
const typeKeyword = `\S+`

// macTableCiscoRe matches Cisco IOS/NX-OS format: VLAN  MAC  TYPE  PORT
var macTableCiscoRe = regexp.MustCompile(
	`^\s*(\d+)\s+(` + macPattern + `)\s+(?:` + typeKeyword + `)\s+([A-Za-z0-9/:._-]+)`,
)

// macTableHPRe matches HP Comware/ProVision format: MAC  VLAN  STATE  PORT
var macTableHPRe = regexp.MustCompile(
	`^\s*(` + macPattern + `)\s+(\d+)\s+(?:` + typeKeyword + `)\s+([A-Za-z0-9/:._-]+)`,
)

// parse scans complianceOutput (full text of compliance_commands.txt for one device)
// and adds any MAC table entries it finds to the index.
func (mi *macIndex) parse(complianceOutput, switchIP string) {
	for _, line := range strings.Split(complianceOutput, "\n") {
		mac, iface, vlan := parseMACLine(line)
		if mac == "" {
			continue
		}
		// Don't overwrite an existing entry — first switch that sees the MAC wins.
		if _, exists := mi.entries[mac]; !exists {
			mi.entries[mac] = macEntry{SwitchIP: switchIP, Interface: iface, VLAN: vlan}
		}
	}
}

// parseMACLine tries both Cisco (VLAN first) and HP (MAC first) formats.
// Returns empty mac string if the line doesn't match either format.
func parseMACLine(line string) (mac, iface string, vlan int) {
	if m := macTableCiscoRe.FindStringSubmatch(line); m != nil {
		v, err := strconv.Atoi(m[1])
		if err != nil {
			return "", "", 0
		}
		norm := normalizeMAC(m[2])
		if norm == "" {
			return "", "", 0
		}
		return norm, m[3], v
	}
	if m := macTableHPRe.FindStringSubmatch(line); m != nil {
		v, err := strconv.Atoi(m[2])
		if err != nil {
			return "", "", 0
		}
		norm := normalizeMAC(m[1])
		if norm == "" {
			return "", "", 0
		}
		return norm, m[3], v
	}
	return "", "", 0
}

// normalizeMAC converts any MAC address format to lowercase colon-separated pairs.
// Accepts: Cisco dot (aabb.cc00.0100), HP dash (aabb-cc00-0100), colon (aa:bb:cc:00:01:00).
func normalizeMAC(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	// Strip all separators to get 12 hex digits.
	stripped := strings.NewReplacer(".", "", "-", "", ":", "").Replace(raw)
	if len(stripped) != 12 {
		return ""
	}
	for _, c := range stripped {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return ""
		}
	}
	return fmt.Sprintf("%s:%s:%s:%s:%s:%s",
		stripped[0:2], stripped[2:4], stripped[4:6],
		stripped[6:8], stripped[8:10], stripped[10:12])
}
