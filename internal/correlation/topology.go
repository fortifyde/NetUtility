package correlation

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// TopologyGenerator creates network topology visualizations from correlated data.
type TopologyGenerator struct {
	workspaceDir string
}

// NewTopologyGenerator creates a topology generator that writes output to workspaceDir/topology/.
func NewTopologyGenerator(workspaceDir string) *TopologyGenerator {
	return &TopologyGenerator{workspaceDir: workspaceDir}
}

// TopologyOutput holds the paths of generated topology files.
type TopologyOutput struct {
	HTMLViewer string // path to interactive HTML viewer
}

// GenerateAll produces the interactive HTML topology viewer.
func (tg *TopologyGenerator) GenerateAll(correlations map[string]*CorrelationResult) (*TopologyOutput, error) {
	if len(correlations) == 0 {
		return nil, fmt.Errorf("no correlation results to visualize")
	}

	htmlPath, err := tg.GenerateHTMLViewer(correlations)
	if err != nil {
		return nil, fmt.Errorf("generating HTML viewer: %w", err)
	}

	return &TopologyOutput{HTMLViewer: htmlPath}, nil
}

// GenerateHTMLViewer produces a self-contained HTML file with embedded JavaScript
// for interactive topology viewing (pan, zoom, filter, VLAN tabs, search).
func (tg *TopologyGenerator) GenerateHTMLViewer(correlations map[string]*CorrelationResult) (string, error) {
	if len(correlations) == 0 {
		return "", fmt.Errorf("no correlation results to visualize")
	}

	vlanGroups := tg.groupByVLAN(correlations)
	vlanOrder := sortedKeys(vlanGroups)

	type hostJSON struct {
		IP              string            `json:"ip"`
		Hostname        string            `json:"hostname"`
		MAC             string            `json:"mac"`
		OS              string            `json:"os"`
		Category        string            `json:"category"`
		Vendor          string            `json:"vendor"`
		VLANID          string            `json:"vlan_id"`
		VLANName        string            `json:"vlan_name"`
		DeviceType      string            `json:"device_type"`
		Ports           []Port            `json:"ports"`
		Attributes      map[string]string `json:"attributes"`
		RiskScore       int               `json:"risk_score"`
		RiskDetails     RiskBreakdown     `json:"risk_details"`
		Vulnerabilities []Vulnerability   `json:"vulnerabilities"`
		Recommendations []string          `json:"recommendations"`
		IsLocal         bool              `json:"is_local"`
	}
	type vlanJSON struct {
		ID      string     `json:"id"`
		Name    string     `json:"name"`
		Hosts   []hostJSON `json:"hosts"`
		AvgRisk int        `json:"avg_risk"`
	}

	scannerSubnet := ""
	for _, corr := range correlations {
		if corr.HostInfo != nil && corr.HostInfo.IP != "" {
			scannerSubnet = subnetFromIP(corr.HostInfo.IP)
			break
		}
	}

	var vlans []vlanJSON
	for _, vlan := range vlanOrder {
		hosts := vlanGroups[vlan]
		var hostList []hostJSON
		var totalRisk int
		for _, corr := range hosts {
			hj := hostJSON{
				IP:              safeHost(corr),
				Category:        hostCategoryFromResult(corr),
				Ports:           []Port{},
				RiskDetails:     RiskBreakdown{},
				Vulnerabilities: []Vulnerability{},
				Recommendations: []string{},
			}
			if corr.HostInfo != nil {
				hj.Hostname = corr.HostInfo.Hostname
				hj.MAC = corr.HostInfo.MACAddress
				hj.OS = corr.HostInfo.OS
				hj.Ports = corr.HostInfo.Ports
				hj.Vendor = corr.HostInfo.Attributes["vendor"]
				hj.VLANID = corr.HostInfo.Attributes["vlan_id"]
				hj.VLANName = corr.HostInfo.Attributes["vlan_name"]
				hj.DeviceType = corr.HostInfo.Attributes["device_type"]
				hj.Attributes = corr.HostInfo.Attributes
				hj.IsLocal = subnetFromIP(corr.HostInfo.IP) == scannerSubnet || len(vlanOrder) > 1
			}
			hj.RiskScore = corr.RiskScore
			hj.RiskDetails = corr.RiskDetails
			hj.Vulnerabilities = corr.Vulnerabilities
			hj.Recommendations = corr.Recommendations
			totalRisk += corr.RiskScore
			hostList = append(hostList, hj)
		}
		avgRisk := 0
		if len(hostList) > 0 {
			avgRisk = totalRisk / len(hostList)
		}
		vlans = append(vlans, vlanJSON{ID: vlan, Name: vlanGroupName(vlan, hosts), Hosts: hostList, AvgRisk: avgRisk})
	}

	vlansData, err := json.Marshal(vlans)
	if err != nil {
		return "", fmt.Errorf("marshaling topology data: %w", err)
	}

	connections := tg.inferConnections(correlations, vlanGroups)
	connData, err := json.Marshal(connections)
	if err != nil {
		return "", fmt.Errorf("marshaling connection data: %w", err)
	}

	html := topologyHTMLHead + topologyD3 + "\nconst VLANS = " + string(vlansData) + ";\nconst CONNECTIONS = " + string(connData) + ";\n" + topologyHTMLJS + "\n</script>\n</body>\n</html>"

	outDir := filepath.Join(tg.workspaceDir, "topology")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", fmt.Errorf("creating topology dir: %w", err)
	}

	ts := time.Now().Format("20060102_150405")
	htmlPath := filepath.Join(outDir, "topology_viewer_"+ts+".html")
	if err := os.WriteFile(htmlPath, []byte(html), 0o644); err != nil {
		return "", fmt.Errorf("writing HTML viewer: %w", err)
	}

	return htmlPath, nil
}

// --- Shared helpers ---

func (tg *TopologyGenerator) groupByVLAN(correlations map[string]*CorrelationResult) map[string][]*CorrelationResult {
	groups := make(map[string][]*CorrelationResult)
	for _, corr := range correlations {
		vlan := vlanForHost(corr)
		groups[vlan] = append(groups[vlan], corr)
	}
	return groups
}

func vlanForHost(corr *CorrelationResult) string {
	if corr.HostInfo != nil && corr.HostInfo.Attributes != nil {
		if v := corr.HostInfo.Attributes["vlan_id"]; v != "" {
			return v
		}
	}
	if corr.HostInfo != nil && corr.HostInfo.IP != "" {
		return subnetFromIP(corr.HostInfo.IP)
	}
	return "default"
}

func subnetFromIP(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) >= 3 {
		return parts[0] + "." + parts[1] + "." + parts[2] + ".0/24"
	}
	return "default"
}

func safeHost(corr *CorrelationResult) string {
	if corr.HostInfo != nil && corr.HostInfo.IP != "" {
		return corr.HostInfo.IP
	}
	return corr.Host
}

func vlanGroupName(vlan string, hosts []*CorrelationResult) string {
	for _, corr := range hosts {
		if corr.HostInfo != nil && corr.HostInfo.Attributes != nil {
			if name := corr.HostInfo.Attributes["vlan_name"]; name != "" {
				return "VLAN " + vlan + " (" + name + ")"
			}
		}
	}
	if vlan != "default" {
		return "VLAN " + vlan
	}
	return "Default Network"
}

func sortedKeys(m map[string][]*CorrelationResult) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// connectionJSON represents an inferred edge between two hosts in the topology.
type connectionJSON struct {
	Source string `json:"source"` // IP
	Target string `json:"target"` // IP
	Type   string `json:"type"`   // "gateway", "same_vlan"
	Label  string `json:"label"`  // e.g., "VLAN 100 <-> VLAN 200"
}

// inferConnections builds inferred edges between hosts based on gateway detection
// and VLAN membership. Since LLDP/SNMP/traceroute are unreliable in air-gapped
// environments, we infer relationships from device types and VLAN membership.
func (tg *TopologyGenerator) inferConnections(correlations map[string]*CorrelationResult, vlanGroups map[string][]*CorrelationResult) []connectionJSON {
	var connections []connectionJSON
	seen := make(map[string]bool) // "source->target" dedup

	addConn := func(src, tgt, typ, label string) {
		key := src + "->" + tgt
		if seen[key] {
			return
		}
		seen[key] = true
		connections = append(connections, connectionJSON{Source: src, Target: tgt, Type: typ, Label: label})
	}

	// Find gateway/routers — devices that serve multiple VLANs or have router device_type
	gateways := make(map[string][]string) // gateway IP -> VLANs it appears in or serves
	for ip, corr := range correlations {
		if isGateway(corr) {
			vlan := vlanForHost(corr)
			gateways[ip] = append(gateways[ip], vlan)
		}
	}

	// For multi-VLAN scenarios, connect gateways to all VLANs
	if len(vlanGroups) > 1 {
		for gwIP, gwVLANs := range gateways {
			for _, vlan := range sortedKeys(vlanGroups) {
				// Connect gateway to the first host in each VLAN
				hosts := vlanGroups[vlan]
				if len(hosts) == 0 {
					continue
				}
				target := safeHost(hosts[0])
				if target == gwIP {
					// Pick another host if first is the gateway itself
					if len(hosts) > 1 {
						target = safeHost(hosts[1])
					} else {
						continue
					}
				}
				// Check if this VLAN is already the gateway's own
				ownVLAN := false
				for _, gv := range gwVLANs {
					if gv == vlan {
						ownVLAN = true
						break
					}
				}
				label := "VLAN " + gwVLANs[0] + " <-> VLAN " + vlan
				if ownVLAN {
					label = "gateway " + gwIP
				}
				addConn(gwIP, target, "gateway", label)
			}
		}
	}

	// Connect hosts within the same VLAN to a representative (first host)
	for vlan, hosts := range vlanGroups {
		if len(hosts) <= 1 {
			continue
		}
		rep := safeHost(hosts[0])
		for _, h := range hosts[1:] {
			ip := safeHost(h)
			if ip != rep {
				addConn(rep, ip, "same_vlan", "VLAN "+vlan)
			}
		}
	}

	return connections
}

// isGateway returns true if the host appears to be a gateway or router.
func isGateway(corr *CorrelationResult) bool {
	if corr.HostInfo == nil || corr.HostInfo.Attributes == nil {
		return false
	}
	dt := strings.ToLower(corr.HostInfo.Attributes["device_type"])
	if dt == "router" || dt == "gateway" || dt == "firewall" || dt == "layer3" || dt == "switch_l3" {
		return true
	}
	// Check capabilities attribute
	caps := strings.ToLower(corr.HostInfo.Attributes["capabilities"])
	if strings.Contains(caps, "router") || strings.Contains(caps, "gateway") {
		return true
	}
	return false
}
