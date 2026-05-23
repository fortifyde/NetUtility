package correlation

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	vlanDefault    = "default"
	hostTypeRouter = "router"
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

	if ce := NewConfigEnricher(tg.workspaceDir); ce.HasConfigs() {
		_ = ce.Enrich(correlations)
	}

	vlanGroups := tg.groupByVLAN(correlations)
	vlanOrder := sortedKeys(vlanGroups)

	type hostJSON struct {
		IP                 string              `json:"ip"`
		Hostname           string              `json:"hostname"`
		MAC                string              `json:"mac"`
		OS                 string              `json:"os"`
		Category           string              `json:"category"`
		Vendor             string              `json:"vendor"`
		VLANID             string              `json:"vlan_id"`
		VLANName           string              `json:"vlan_name"`
		DeviceType         string              `json:"device_type"`
		Ports              []Port              `json:"ports"`
		Attributes         map[string]string   `json:"attributes"`
		RiskScore          int                 `json:"risk_score"`
		RiskDetails        RiskBreakdown       `json:"risk_details"`
		Vulnerabilities    []Vulnerability     `json:"vulnerabilities"`
		Recommendations    []string            `json:"recommendations"`
		IsLocal            bool                `json:"is_local"`
		ComplianceFindings []ComplianceFinding `json:"compliance_findings"`
		ComplianceSeverity string              `json:"compliance_severity"`
	}
	type vlanJSON struct {
		ID      string     `json:"id"`
		Name    string     `json:"name"`
		Hosts   []hostJSON `json:"hosts"`
		AvgRisk int        `json:"avg_risk"`
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
				if hj.Hostname == "" {
					hj.Hostname, _ = corr.HostInfo.Attributes["netbios_name"]
				}
				hj.MAC = corr.HostInfo.MACAddress
				hj.OS = corr.HostInfo.OS
				hj.Ports = corr.HostInfo.Ports
				hj.Vendor = corr.HostInfo.Attributes["vendor"]
				hj.VLANID = corr.HostInfo.Attributes["vlan_id"]
				hj.VLANName = corr.HostInfo.Attributes["vlan_name"]
				hj.DeviceType = corr.HostInfo.Attributes["device_type"]
				hj.Attributes = corr.HostInfo.Attributes
				hj.IsLocal = corr.HostInfo.MACAddress != ""
			}
			hj.RiskScore = corr.RiskScore
			hj.RiskDetails = corr.RiskDetails
			hj.Vulnerabilities = corr.Vulnerabilities
			hj.Recommendations = corr.Recommendations
			hj.ComplianceFindings = corr.ComplianceFindings
			hj.ComplianceSeverity = corr.ComplianceSeverity
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
	if err := os.MkdirAll(outDir, 0750); err != nil {
		return "", fmt.Errorf("creating topology dir: %w", err)
	}

	ts := time.Now().Format("20060102_150405")
	htmlPath := filepath.Join(outDir, "topology_viewer_"+ts+".html")
	if err := os.WriteFile(htmlPath, []byte(html), 0644); err != nil { //nolint:gosec // G306: workspace output — user must be able to read/edit
		return "", fmt.Errorf("writing HTML viewer: %w", err)
	}

	tg.fixTopologyOwnership(outDir)

	return htmlPath, nil
}


// fixTopologyOwnership restores ownership of the topology directory to the
// invoking user when netutil is run via sudo. Without this, the directory and its
// files are owned by root, preventing the user from managing them directly.
func (tg *TopologyGenerator) fixTopologyOwnership(topologyDir string) {
	if os.Geteuid() != 0 {
		return
	}
	sudoUID := os.Getenv("SUDO_UID")
	sudoGID := os.Getenv("SUDO_GID")
	if sudoUID == "" || sudoGID == "" {
		return
	}
	uid, err := strconv.Atoi(sudoUID)
	if err != nil {
		return
	}
	gid, err := strconv.Atoi(sudoGID)
	if err != nil {
		return
	}
	_ = filepath.Walk(topologyDir, func(path string, _ os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		_ = syscall.Chown(path, uid, gid)
		return nil
	})
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
	return vlanDefault
}

func subnetFromIP(ip string) string {
	if strings.Contains(ip, ":") {
		// IPv6: use first 3 groups as a /48-equivalent prefix
		parts := strings.Split(ip, ":")
		if len(parts) >= 3 {
			return parts[0] + ":" + parts[1] + ":" + parts[2] + "::/48"
		}
		return vlanDefault
	}
	parts := strings.Split(ip, ".")
	if len(parts) >= 3 {
		return parts[0] + "." + parts[1] + "." + parts[2] + ".0/24"
	}
	return vlanDefault
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
	if vlan != vlanDefault {
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

	// Emit confirmed physical edges from MAC table cross-correlation.
	// Track which hosts already have a physical link so they are excluded from inferred topology.
	hostsWithPhysical := make(map[string]bool)
	for ip, corr := range correlations {
		for _, pl := range corr.PhysicalLinks {
			if pl.SwitchIP == ip {
				continue
			}
			addConn(pl.SwitchIP, ip, "physical", pl.Interface)
			hostsWithPhysical[ip] = true
		}
	}

	// Find gateway/routers — devices that serve multiple VLANs or have router device_type
	gateways := make(map[string][]string) // gateway IP -> VLANs it appears in or serves
	for ip, corr := range correlations {
		if isGateway(corr) {
			vlan := vlanForHost(corr)
			gateways[ip] = append(gateways[ip], vlan)
		}
	}

	// Connect hosts within the same VLAN in a star topology.
	// Hosts that already have a confirmed physical link are skipped.
	// Use a gateway as the hub if one is present in the VLAN; otherwise use the first host.
	for vlan, hosts := range vlanGroups {
		if len(hosts) <= 1 {
			continue
		}
		rep := safeHost(hosts[0])
		repIsGateway := false
		for _, h := range hosts {
			ip := safeHost(h)
			if _, isGW := gateways[ip]; isGW {
				rep = ip
				repIsGateway = true
				break
			}
		}
		edgeType := "same_vlan"
		if repIsGateway {
			edgeType = "gateway"
		}
		for _, h := range hosts {
			ip := safeHost(h)
			if ip != rep && !hostsWithPhysical[ip] {
				addConn(rep, ip, edgeType, "VLAN "+vlan)
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
	if dt == hostTypeRouter || dt == "gateway" || dt == "firewall" || dt == "layer3" || dt == "switch_l3" {
		return true
	}
	// Check capabilities attribute
	caps := strings.ToLower(corr.HostInfo.Attributes["capabilities"])
	if strings.Contains(caps, hostTypeRouter) || strings.Contains(caps, "gateway") {
		return true
	}
	return false
}
