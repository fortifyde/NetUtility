package correlation

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ResultParser handles parsing of different scan result formats
type ResultParser struct {
	workspaceDir string
}

// NewResultParser creates a new result parser
func NewResultParser(workspaceDir string) *ResultParser {
	return &ResultParser{
		workspaceDir: workspaceDir,
	}
}

// ParseJobResult automatically parses job output based on script type and content
func (rp *ResultParser) ParseJobResult(scriptPath, outputContent string, timestamp time.Time) (*ScanResult, error) {
	scriptName := filepath.Base(scriptPath)

	// Determine scan type based on script path and content
	scanType := rp.determineScanType(scriptPath, outputContent)

	result := &ScanResult{
		ID:              fmt.Sprintf("%s_%d", scriptName, timestamp.Unix()),
		Type:            scanType,
		Timestamp:       timestamp,
		Source:          scriptName,
		FilePath:        "", // No file path for live output
		Hosts:           make([]Host, 0),
		Services:        make([]Service, 0),
		Vulnerabilities: make([]Vulnerability, 0),
		Metadata:        make(map[string]interface{}),
	}

	// Parse based on detected type
	switch scanType {
	case ScanTypeNetworkEnum:
		return rp.parseNetworkEnumeration(result, outputContent)
	case ScanTypePortScan:
		return rp.parsePortScan(result, outputContent)
	case ScanTypeVulnerability:
		return rp.parseVulnerabilityScan(result, outputContent)
	case ScanTypeCapture:
		return rp.parseNetworkCapture(result, outputContent)
	case ScanTypeServiceScan:
		return rp.parseServiceScan(result, outputContent)
	case ScanTypeHostCategorization:
		return rp.parseCategorizationDetails(result, outputContent)
	case ScanTypeNikto:
		return rp.parseNiktoXMLResult(result, outputContent)
	case ScanTypeSSLScan:
		return rp.parseSSLScanResult(result, outputContent)
	case ScanTypeNmapXML:
		return rp.parseNmapXML(result, outputContent)
	case ScanTypeSSLScanXML:
		return rp.parseSSLScanXML(result, outputContent)
	case ScanTypeLLDP:
		return rp.parseLLDPCDPResult(result, outputContent)
	case ScanTypeSNMP:
		return rp.parseSNMPResult(result, outputContent)
	case ScanTypeExploitSearch:
		return rp.parseExploitSearchResult(result, outputContent)
	case ScanTypeFingerprint:
		return rp.parseFingerprintResult(result, outputContent)
	case ScanTypeARP:
		return rp.parseARPResult(result, outputContent)
	case ScanTypeTestSSL:
		return rp.parseTestSSLResult(result, outputContent)
	default:
		return rp.parseGenericOutput(result, outputContent)
	}
}

// determineScanType determines the scan type based on script path and output content
func (rp *ResultParser) determineScanType(scriptPath, outputContent string) ScanType {
	scriptName := strings.ToLower(filepath.Base(scriptPath))
	contentLower := strings.ToLower(outputContent)

	// ph7 categorization details file — must be checked before generic name patterns
	if strings.Contains(scriptName, "categorization_details") {
		return ScanTypeHostCategorization
	}

	// Nmap XML detection — check before generic name patterns
	if strings.Contains(contentLower, "<nmaprun") {
		return ScanTypeNmapXML
	}

	// Nikto XML detection — check content before generic name patterns
	if strings.Contains(contentLower, "<niktoscan") {
		return ScanTypeNikto
	}
	// sslscan XML detection — check before text-based sslscan
	if strings.Contains(contentLower, "sslscan results") && strings.Contains(contentLower, "<document") {
		return ScanTypeSSLScanXML
	}
	// LLDP/CDP XML detection
	if strings.Contains(contentLower, "<lldp_cdp_results") {
		return ScanTypeLLDP
	}

	// SNMP results XML detection
	if strings.Contains(contentLower, "<snmp_results") {
		return ScanTypeSNMP
	}

	// Exploit search XML detection
	if strings.Contains(contentLower, "<exploit_results") {
		return ScanTypeExploitSearch
	}

	// Passive fingerprint XML detection
	if strings.Contains(contentLower, "<fingerprint_results") {
		return ScanTypeFingerprint
	}

	// ARP results XML detection
	if strings.Contains(contentLower, "<arp_results") {
		return ScanTypeARP
	}
	// testssl.sh JSON detection — real -oj output is a flat JSON array of findings
	// each with "id", "ip", "port", "severity", "finding" fields.
	if strings.HasPrefix(strings.TrimSpace(outputContent), "[") &&
		strings.Contains(contentLower, "\"severity\"") &&
		strings.Contains(contentLower, "\"finding\"") &&
		(strings.Contains(scriptName, "testssl") ||
			(strings.Contains(contentLower, "\"ip\"") && strings.Contains(contentLower, "\"port\""))) {
		return ScanTypeTestSSL
	}

	// SSLscan text detection (must be after XML check)
	// sslscan detection — check filename and content
	if strings.Contains(scriptName, "sslscan") {
		return ScanTypeSSLScan
	}

	// .nmap text files are parsed for port/service data (the companion .xml
	// file provides authoritative vulnerability findings). Without this guard,
	// "vuln_results.nmap" would route to ScanTypeVulnerability and produce
	// false positives from NSE output like "ROCA: Vulnerable RSA generation".
	ext := filepath.Ext(scriptName)
	if ext == ".nmap" {
		return ScanTypePortScan
	}

	// Remaining script name patterns.
	if strings.Contains(scriptName, "enum") || strings.Contains(scriptName, "discovery") {
		return ScanTypeNetworkEnum
	}
	if strings.Contains(scriptName, "vuln") || strings.Contains(scriptName, "nse") {
		return ScanTypeVulnerability
	}
	if strings.Contains(scriptName, "capture") || strings.Contains(scriptName, "tshark") {
		return ScanTypeCapture
	}
	if strings.Contains(scriptName, "service") || strings.Contains(scriptName, "version") {
		return ScanTypeServiceScan
	}

	// Check output content patterns
	if strings.Contains(contentLower, "nmap scan report") {
		return ScanTypePortScan
	}
	if strings.Contains(contentLower, "vulnerability") || strings.Contains(contentLower, "cve-") {
		return ScanTypeVulnerability
	}
	if strings.Contains(contentLower, "packets captured") {
		return ScanTypeCapture
	}
	if strings.Contains(contentLower, "host is up") || strings.Contains(contentLower, "ping statistics") {
		return ScanTypeNetworkEnum
	}
	// Default to network enumeration for network-related scripts
	if strings.Contains(scriptPath, "network") {
		return ScanTypeNetworkEnum
	}

	return ScanTypePortScan // Default fallback
}

// parseNetworkEnumeration parses network enumeration output (ping, arp, etc.)
func (rp *ResultParser) parseNetworkEnumeration(result *ScanResult, content string) (*ScanResult, error) {
	lines := strings.Split(content, "\n")
	discoveredHosts := make(map[string]*Host)

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Parse ping responses
		if strings.Contains(line, "PING") && strings.Contains(line, "(") {
			ipRegex := regexp.MustCompile(`\((\d+\.\d+\.\d+\.\d+)\)`)
			if matches := ipRegex.FindStringSubmatch(line); len(matches) > 1 {
				ip := matches[1]
				discoveredHosts[ip] = &Host{
					IP:       ip,
					Status:   "up",
					LastSeen: result.Timestamp,
					Ports:    make([]Port, 0),
				}
				result.Targets = append(result.Targets, ip)
			}
		}

		// Parse fping output
		if strings.Contains(line, "is alive") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				ip := parts[0]
				discoveredHosts[ip] = &Host{
					IP:       ip,
					Status:   "up",
					LastSeen: result.Timestamp,
					Ports:    make([]Port, 0),
				}
				result.Targets = append(result.Targets, ip)
			}
		}

		// Parse ARP table entries
		if strings.Contains(line, "ether") && len(strings.Fields(line)) >= 3 {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				ip := parts[0]
				mac := parts[2]
				if host, exists := discoveredHosts[ip]; exists {
					host.MACAddress = mac
				} else {
					discoveredHosts[ip] = &Host{
						IP:         ip,
						MACAddress: mac,
						Status:     "up",
						LastSeen:   result.Timestamp,
						Ports:      make([]Port, 0),
					}
				}
			}
		}
	}

	// Convert map to slice
	for _, host := range discoveredHosts {
		result.Hosts = append(result.Hosts, *host)
	}

	return result, nil
}

// parsePortScan parses nmap port scan output
func (rp *ResultParser) parsePortScan(result *ScanResult, content string) (*ScanResult, error) {
	lines := strings.Split(content, "\n")
	var currentHost *Host

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Host detection
		if strings.Contains(line, "Nmap scan report for") {
			if currentHost != nil {
				result.Hosts = append(result.Hosts, *currentHost)
			}

			ipRegex := regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)`)
			hostnameRegex := regexp.MustCompile(`Nmap scan report for ([^\s]+) \(`)

			var ip, hostname string
			if matches := ipRegex.FindStringSubmatch(line); len(matches) > 1 {
				ip = matches[1]
			}
			if matches := hostnameRegex.FindStringSubmatch(line); len(matches) > 1 {
				hostname = matches[1]
			}

			if ip != "" {
				currentHost = &Host{
					IP:       ip,
					Hostname: hostname,
					Status:   "up",
					LastSeen: result.Timestamp,
					Ports:    make([]Port, 0),
				}
				result.Targets = append(result.Targets, ip)
			}
		}

		// Port detection
		if currentHost != nil && (strings.Contains(line, "/tcp") || strings.Contains(line, "/udp")) {
			portRegex := regexp.MustCompile(`(\d+)/(tcp|udp)\s+(\w+)\s+(.*)`)
			if matches := portRegex.FindStringSubmatch(line); len(matches) > 4 {
				portNum, _ := strconv.Atoi(matches[1])
				protocol := matches[2]
				state := matches[3]
				serviceInfo := strings.TrimSpace(matches[4])

				port := Port{
					Number:   portNum,
					Protocol: protocol,
					State:    state,
				}

				// Parse service information
				serviceParts := strings.Fields(serviceInfo)
				if len(serviceParts) > 0 {
					port.Service = serviceParts[0]
					if len(serviceParts) > 1 {
						port.Version = strings.Join(serviceParts[1:], " ")
					}
				}

				currentHost.Ports = append(currentHost.Ports, port)

				// Add to services if open
				if state == "open" {
					service := Service{
						Host:     currentHost.IP,
						Port:     portNum,
						Protocol: protocol,
						Name:     port.Service,
						Version:  port.Version,
					}
					result.Services = append(result.Services, service)
				}
			}
		}

		// OS detection
		if currentHost != nil && strings.Contains(line, "OS details:") {
			osRegex := regexp.MustCompile(`OS details:\s*(.+)`)
			if matches := osRegex.FindStringSubmatch(line); len(matches) > 1 {
				currentHost.OS = strings.TrimSpace(matches[1])
			}
		}

		// MAC address (only present when scanning as root on same subnet)
		if currentHost != nil && strings.Contains(line, "MAC Address:") {
			macRegex := regexp.MustCompile(`MAC Address:\s*([0-9A-Fa-f:]{17})`)
			if matches := macRegex.FindStringSubmatch(line); len(matches) > 1 && currentHost.MACAddress == "" {
				currentHost.MACAddress = strings.ToUpper(matches[1])
			}
		}
	}

	// Add the last host
	if currentHost != nil {
		result.Hosts = append(result.Hosts, *currentHost)
	}

	return result, nil
}

// parseVulnerabilityScan parses vulnerability scan output
func (rp *ResultParser) parseVulnerabilityScan(result *ScanResult, content string) (*ScanResult, error) {
	lines := strings.Split(content, "\n")
	var currentHost string

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Extract host from nmap output
		if strings.Contains(line, "Nmap scan report for") {
			ipRegex := regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)`)
			if matches := ipRegex.FindStringSubmatch(line); len(matches) > 1 {
				currentHost = matches[1]
				result.Targets = append(result.Targets, currentHost)
			}
		}

		// Parse NSE vulnerability scripts
		lineLower := strings.ToLower(line)
		if currentHost != "" && strings.Contains(lineLower, "vulnerable") {
			// Skip negative findings from nmap NSE scripts
			if strings.Contains(lineLower, "not vulnerable") || strings.Contains(lineLower, "no vulnerable") {
				continue
			}
			severity := "medium" // Default severity
			title := line

			// Determine severity from keywords
			if strings.Contains(lineLower, "critical") {
				severity = "critical"
			} else if strings.Contains(lineLower, "high") {
				severity = "high"
			} else if strings.Contains(lineLower, "low") {
				severity = "low"
			}

			vuln := Vulnerability{
				Host:        currentHost,
				Title:       title,
				Description: line,
				Severity:    severity,
				Discovery:   result.Timestamp,
			}

			// Extract CVE if present
			cveRegex := regexp.MustCompile(`(CVE-\d{4}-\d+)`)
			if matches := cveRegex.FindStringSubmatch(line); len(matches) > 1 {
				vuln.CVE = matches[1]
			}

			result.Vulnerabilities = append(result.Vulnerabilities, vuln)
		}
	}

	return result, nil
}

// parseNetworkCapture parses network capture output
func (rp *ResultParser) parseNetworkCapture(result *ScanResult, content string) (*ScanResult, error) {
	lines := strings.Split(content, "\n")
	hostSet := make(map[string]bool)

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Parse tshark output for IP addresses
		ipRegex := regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)`)
		matches := ipRegex.FindAllString(line, -1)

		for _, ip := range matches {
			// Skip broadcast and multicast addresses
			if !strings.HasSuffix(ip, ".255") && !strings.HasPrefix(ip, "224.") {
				hostSet[ip] = true
			}
		}

		// Parse protocols and services from packet captures
		if strings.Contains(strings.ToLower(line), "http") {
			// Extract HTTP traffic details
		}
		if strings.Contains(strings.ToLower(line), "ssh") {
			// Extract SSH traffic details
		}
	}

	// Create host entries for discovered IPs
	for ip := range hostSet {
		host := Host{
			IP:       ip,
			Status:   "observed",
			LastSeen: result.Timestamp,
			Ports:    make([]Port, 0),
		}
		result.Hosts = append(result.Hosts, host)
		result.Targets = append(result.Targets, ip)
	}

	return result, nil
}

// parseServiceScan parses service detection output
func (rp *ResultParser) parseServiceScan(result *ScanResult, content string) (*ScanResult, error) {
	// Similar to port scan but focuses on service details
	return rp.parsePortScan(result, content)
}

// parseCategorizationDetails parses ph7 categorization_details.txt files.
// Format: tab-separated columns IP, Hostname, Category, Vendor, Confidence, Score, Evidence, MAC (header row present).
func (rp *ResultParser) parseCategorizationDetails(result *ScanResult, content string) (*ScanResult, error) {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 3 {
			continue
		}
		ip := strings.TrimSpace(fields[0])
		// Skip header row
		if ip == "IP" || ip == "" {
			continue
		}

		host := Host{
			IP:         ip,
			Status:     "up",
			LastSeen:   result.Timestamp,
			Ports:      make([]Port, 0),
			Attributes: make(map[string]string),
		}

		if len(fields) > 1 {
			if h := strings.TrimSpace(fields[1]); h != "" && h != "-" {
				host.Hostname = h
			}
		}
		attrKeys := []string{"category", "vendor", "confidence", "score"}
		for i, key := range attrKeys {
			col := i + 2 // columns start at index 2
			if col < len(fields) {
				if v := strings.TrimSpace(fields[col]); v != "" && v != "-" {
					host.Attributes[key] = v
				}
			}
		}
		// Column 7 (index 7): MAC address (optional, added in later format version)
		if len(fields) > 7 {
			if mac := strings.TrimSpace(fields[7]); mac != "" && mac != "-" {
				host.MACAddress = mac
			}
		}
		// Column 9 (index 8): Normalized TTL (optional, added in later format version)
		if len(fields) > 8 {
			if ttl := strings.TrimSpace(fields[8]); ttl != "" && ttl != "-" {
				host.Attributes["ttl_normalized"] = ttl
			}
		}

		result.Hosts = append(result.Hosts, host)
		result.Targets = append(result.Targets, ip)
	}
	return result, nil
}

// parseGenericOutput parses generic script output for IP addresses and basic info
func (rp *ResultParser) parseGenericOutput(result *ScanResult, content string) (*ScanResult, error) {
	lines := strings.Split(content, "\n")
	hostSet := make(map[string]bool)

	// Extract IP addresses from any output
	ipRegex := regexp.MustCompile(`\b(\d+\.\d+\.\d+\.\d+)\b`)

	for _, line := range lines {
		matches := ipRegex.FindAllString(line, -1)
		for _, ip := range matches {
			// Skip common non-host IPs
			if !strings.HasSuffix(ip, ".0") && !strings.HasSuffix(ip, ".255") &&
				!strings.HasPrefix(ip, "0.") && !strings.HasPrefix(ip, "127.") {
				hostSet[ip] = true
			}
		}
	}

	// Create basic host entries
	for ip := range hostSet {
		host := Host{
			IP:       ip,
			Status:   "mentioned",
			LastSeen: result.Timestamp,
			Ports:    make([]Port, 0),
		}
		result.Hosts = append(result.Hosts, host)
		result.Targets = append(result.Targets, ip)
	}

	return result, nil
}

// ParseResultFile parses a result file and returns a scan result
func (rp *ResultParser) ParseResultFile(filePath string) (*ScanResult, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	return rp.ParseJobResult(filePath, string(content), fileInfo.ModTime())
}

// ScanWorkspaceForResults scans the workspace directory recursively for result files.
// It processes nmap output files (.nmap, .xml), the ph7 categorization_details.txt,
// and supplementary tool XML outputs (sslscan_*.xml, nikto.xml, nmap supplementary XML).
// Generic .txt and .log files are intentionally excluded: they contain human-readable
// reports that mention every IP in the scan range, which would flood the host inventory
// with hundreds of spurious "unknown" entries.
func (rp *ResultParser) ScanWorkspaceForResults() ([]*ScanResult, error) {
	if rp.workspaceDir == "" {
		return nil, fmt.Errorf("workspace directory not set")
	}

	var results []*ScanResult

	err := fs.WalkDir(os.DirFS(rp.workspaceDir), ".", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() {
			return nil
		}

		base := filepath.Base(path)
		ext := filepath.Ext(path)

		// Accept .nmap, .xml, and .json files, plus categorization_details.txt.
		// sslscan.txt is excluded: sslscan now outputs per-host XML files instead.
		// .json files are accepted for testssl.sh output.
		if ext != ".nmap" && ext != ".xml" && ext != ".json" && base != "categorization_details.txt" {
			return nil
		}

		fullPath := filepath.Join(rp.workspaceDir, path)

		// Skip files larger than 10 MB.
		info, statErr := d.Info()
		if statErr != nil || info.Size() > 10*1024*1024 {
			return nil
		}

		result, parseErr := rp.ParseResultFile(fullPath)
		if parseErr != nil {
			return nil // skip unparseable files
		}
		results = append(results, result)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scanning workspace: %w", err)
	}

	return results, nil
}

// --- Nikto XML types for parsing ---

// niktoScan is the top-level XML structure (singular <niktoscan>).
type niktoScan struct {
	XMLName     xml.Name           `xml:"niktoscan"`
	ScanDetails []niktoScanDetails `xml:"scandetails"`
}

// niktoScans is a wrapper for the plural root <niktoscans> that some
// nikto output formats use when multiple scans are present.
type niktoScans struct {
	XMLName xml.Name    `xml:"niktoscans"`
	Scans   []niktoScan `xml:"niktoscan"`
}

// niktoScanDetails holds per-target scan details.
type niktoScanDetails struct {
	TargetIP   string      `xml:"targetip,attr"`
	TargetPort string      `xml:"targetport,attr"`
	TargetHost string      `xml:"targethostname,attr"`
	Items      []niktoItem `xml:"item"`
}

// niktoItem represents a single finding.
type niktoItem struct {
	Method          string `xml:"method,attr"`
	URL              string `xml:"url,attr"`
	DescAttr        string `xml:"description,attr"` // attribute form (test data)
	Description     string `xml:"description"`       // CDATA element content (real nikto output)
	ID              string `xml:"id,attr"`
	Text            string `xml:",chardata"`
}

// --- Nmap XML types for parsing ---

// nmapRun is the top-level XML structure for nmap XML output.
type nmapRun struct {
	XMLName xml.Name     `xml:"nmaprun"`
	Hosts   []nmapHost   `xml:"host"`
}

type nmapHost struct {
	Status    nmapStatus    `xml:"status"`
	Addresses []nmapAddress `xml:"address"`
	Hostnames nmapHostnames `xml:"hostnames"`
	Ports     *nmapPorts    `xml:"ports"`
	OS        *nmapOS        `xml:"os"`
}

type nmapOS struct {
	Matches []nmapOSMatch `xml:"osmatch"`
}

type nmapOSMatch struct {
	Name     string           `xml:"name,attr"`
	Accuracy string           `xml:"accuracy,attr"`
	Classes  []nmapOSClass   `xml:"osclass"`
}

type nmapOSClass struct {
	Type     string `xml:"type,attr"`
	Vendor   string `xml:"vendor,attr"`
	OSFamily string `xml:"osfamily,attr"`
}

type nmapStatus struct {
	State string `xml:"state,attr"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr"`
}

type nmapHostnames struct {
	Names []nmapHostname `xml:"hostname"`
}

type nmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string        `xml:"protocol,attr"`
	PortID   int           `xml:"portid,attr"`
	State    nmapPortState `xml:"state"`
	Service  *nmapService  `xml:"service"`
	Scripts  []nmapScript  `xml:"script"`
}

type nmapPortState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name      string `xml:"name,attr"`
	Product   string `xml:"product,attr"`
	Version   string `xml:"version,attr"`
	ExtraInfo string `xml:"extrainfo,attr"`
	Method    string `xml:"method,attr"`
	Conf      int    `xml:"conf,attr"`
}

type nmapScript struct {
	ID     string      `xml:"id,attr"`
	Output string      `xml:"output,attr"`
	Tables []nmapTable `xml:"table"`
	Elems  []nmapElem  `xml:"elem"`
}

type nmapTable struct {
	Key    string      `xml:"key,attr"`
	Elems  []nmapElem  `xml:"elem"`
	Tables []nmapTable `xml:"table"`
}

type nmapElem struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

// parseNmapXML parses nmap XML output into scan results.
// It extracts hosts, ports, services, and NSE script findings.
// Only scripts reporting VULNERABLE or LIKELY VULNERABLE state produce
// vulnerability entries; the vulners script (CPE database lookup) is skipped.
func (rp *ResultParser) parseNmapXML(result *ScanResult, content string) (*ScanResult, error) {
	var run nmapRun
	if err := xml.Unmarshal([]byte(content), &run); err != nil {
		return rp.parseGenericOutput(result, content)
	}

	for _, h := range run.Hosts {
		if h.Status.State != "up" {
			continue
		}

		var ip, mac, hostname string
		for _, addr := range h.Addresses {
			switch addr.AddrType {
			case "ipv4", "ipv6":
				ip = addr.Addr
			case "mac":
				mac = addr.Addr
			}
		}
		if ip == "" {
			continue
		}
		for _, name := range h.Hostnames.Names {
			if name.Type == "user" || hostname == "" {
				hostname = name.Name
			}
		}

		host := Host{
			IP:         ip,
			Hostname:   hostname,
			MACAddress: mac,
			Status:     h.Status.State,
			LastSeen:   result.Timestamp,
			Ports:      make([]Port, 0),
			Attributes: make(map[string]string),
		}
		result.Targets = append(result.Targets, ip)

		// Extract OS detection from nmap -O scan (osmatch).
		// Store the best match as host OS and os_match attribute.
		if h.OS != nil && len(h.OS.Matches) > 0 {
			best := h.OS.Matches[0]
			host.OS = best.Name
			host.OSDetails = best.Name
			host.Attributes["os_match"] = best.Name
			if best.Accuracy != "" {
				host.Attributes["os_match_accuracy"] = best.Accuracy
			}
			// Extract device type from osclass if available
			for _, cls := range best.Classes {
				if cls.Type != "" {
					host.Attributes["device_type"] = cls.Type
					break
				}
			}
		}

		if h.Ports == nil {
			result.Hosts = append(result.Hosts, host)
			continue
		}

		for _, p := range h.Ports.Ports {
			port := Port{
				Number:   p.PortID,
				Protocol: p.Protocol,
				State:    p.State.State,
			}
			if p.Service != nil {
				port.Service = p.Service.Name
				port.Version = p.Service.Version
				if p.Service.Product != "" {
					port.Banner = p.Service.Product
					if p.Service.Version != "" {
						port.Banner += " " + p.Service.Version
					}
				}
			}
			host.Ports = append(host.Ports, port)

			if p.State.State == "open" {
				svc := Service{
					Host:     ip,
					Port:     p.PortID,
					Protocol: p.Protocol,
					Name:     port.Service,
				}
				if p.Service != nil {
					svc.Version = p.Service.Version
					svc.Product = p.Service.Product
					svc.ExtraInfo = p.Service.ExtraInfo
					svc.Confidence = p.Service.Conf
				}
				result.Services = append(result.Services, svc)
			}

			// Process NSE scripts for vulnerabilities.
			for _, script := range p.Scripts {
				// Skip vulners script — it's a CPE database lookup, not findings.
				if script.ID == "vulners" {
					continue
				}

				rp.extractScriptFindings(result, ip, p.PortID, script)
			}
		}

		result.Hosts = append(result.Hosts, host)
	}

	return result, nil
}

// extractScriptFindings processes a single NSE script element and extracts
// vulnerability entries for confirmed or likely vulnerable findings.
func (rp *ResultParser) extractScriptFindings(result *ScanResult, hostIP string, portNum int, script nmapScript) {
	for _, tbl := range script.Tables {
		state := findElemByKey(tbl.Elems, "state")

		// Only include confirmed or likely vulnerabilities.
		if state == "NOT VULNERABLE" || state == "" {
			// For scripts without a state elem at this level, check child tables.
			// Some scripts nest findings deeper.
			foundChild := false
			for _, child := range tbl.Tables {
				childState := findElemByKey(child.Elems, "state")
				if childState == "VULNERABLE" || childState == "LIKELY VULNERABLE" {
					foundChild = true
					rp.addVulnFromTable(result, hostIP, portNum, script.ID, child)
				}
			}
			if !foundChild && state == "" {
				// No state at all — informational script (e.g., http-cookie-flags, http-server-header).
				// Skip: these are not vulnerability findings.
			}
			continue
		}

		rp.addVulnFromTable(result, hostIP, portNum, script.ID, tbl)
	}
}

// addVulnFromTable creates a Vulnerability from an nmap script table entry.
func (rp *ResultParser) addVulnFromTable(result *ScanResult, hostIP string, portNum int, scriptID string, tbl nmapTable) {
	title := findElemByKey(tbl.Elems, "title")
	state := findElemByKey(tbl.Elems, "state")
	if title == "" {
		title = tbl.Key // Use the table key (often CVE ID) as fallback title
	}
	if title == "" {
		title = scriptID
	}

	severity := "medium"
	if state == "VULNERABLE" {
		severity = "high"
	}

	// Extract CVE from IDs table.
	cve := ""
	var refs []string
	for _, child := range tbl.Tables {
		if child.Key == "ids" {
			for _, elem := range child.Elems {
				if strings.HasPrefix(elem.Value, "CVE:") {
					cve = strings.TrimPrefix(elem.Value, "CVE:")
				}
			}
		}
		if child.Key == "refs" {
			for _, elem := range child.Elems {
				refs = append(refs, elem.Value)
			}
		}
	}
	// Also try to extract CVE from the table key.
	if cve == "" {
		cveRegex := regexp.MustCompile(`(CVE-\d{4}-\d+)`)
		if m := cveRegex.FindStringSubmatch(tbl.Key); len(m) > 1 {
			cve = m[1]
		}
	}

	// Extract description.
	desc := ""
	for _, child := range tbl.Tables {
		if child.Key == "description" {
			if len(child.Elems) > 0 {
				desc = child.Elems[0].Value
			}
			break
		}
	}
	if desc == "" {
		desc = title
	}

	result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
		Host:        hostIP,
		Port:        portNum,
		Service:     scriptID,
		CVE:         cve,
		Title:       title,
		Description: desc,
		Severity:    severity,
		Source:      "nmap-nse",
		References:  refs,
		Discovery:   result.Timestamp,
	})
}

// findElemByKey finds the first elem in the list with the given key.
func findElemByKey(elems []nmapElem, key string) string {
	for _, e := range elems {
		if e.Key == key {
			return e.Value
		}
	}
	return ""
}
// splitXMLDocuments splits content that contains multiple concatenated XML
// documents (e.g., nikto appending per-host results) into individual documents.
func splitXMLDocuments(content string) []string {
	var docs []string
	idx := 0
	for {
		next := strings.Index(content[idx:], "<?xml")
		if next < 0 {
			break
		}
		start := idx + next
		end := strings.Index(content[start+5:], "<?xml")
		if end < 0 {
			docs = append(docs, content[start:])
			break
		}
		docs = append(docs, content[start:start+5+end])
		idx = start + 5 + end
	}
	return docs
}

// parseNiktoXMLResult parses nikto XML output into vulnerabilities.
// Nikto appends per-host XML to the same file, producing concatenated XML
// documents. We split on <?xml boundaries and parse each document separately.
func (rp *ResultParser) parseNiktoXMLResult(result *ScanResult, content string) (*ScanResult, error) {
	var allDetails []niktoScanDetails

	for _, doc := range splitXMLDocuments(content) {
		// Try plural wrapper first (<niktoscans><niktoscan>...).
		var scans niktoScans
		if err := xml.Unmarshal([]byte(doc), &scans); err == nil && len(scans.Scans) > 0 {
			for _, s := range scans.Scans {
				allDetails = append(allDetails, s.ScanDetails...)
			}
			continue
		}
		// Try singular root (<niktoscan>...).
		var single niktoScan
		if err := xml.Unmarshal([]byte(doc), &single); err != nil {
			continue
		}
		allDetails = append(allDetails, single.ScanDetails...)
	}

	if len(allDetails) == 0 {
		return rp.parseGenericOutput(result, content)
	}

	seenHosts := make(map[string]bool)
	for _, details := range allDetails {
		ip := details.TargetIP
		if ip == "" {
			continue
		}

		if !seenHosts[ip] {
			seenHosts[ip] = true
			result.Hosts = append(result.Hosts, Host{
				IP:       ip,
				Hostname: details.TargetHost,
				Status:   "up",
				LastSeen: result.Timestamp,
				Ports:    make([]Port, 0),
			})
			result.Targets = append(result.Targets, ip)
		}

		// Parse port if available
		port := 0
		if details.TargetPort != "" {
			port, _ = strconv.Atoi(details.TargetPort)
		}

		// First pass: collect items grouped by (host, port, itemID).
		// Items with the same nikto ID (e.g., "013587" for missing security
		// headers) represent the same class of finding and should be
		// consolidated into one scored entry.
		type itemGroup struct {
			title    string
			severity string
		}
		type groupKey struct {
			host string
			port int
			id   string
		}
		groups := make(map[groupKey][]itemGroup)

		for _, item := range details.Items {
			severity := niktoSeverity(item)

			title := item.Description
			if title == "" {
				title = item.DescAttr
			}
			if title == "" {
				title = item.Text
			}
			if title == "" && item.URL != "" {
				title = fmt.Sprintf("%s %s", item.Method, item.URL)
			}
			if title == "" {
				title = "Nikto finding"
			}

			// Use a unique key for items without a nikto ID so they aren't
			// incorrectly grouped with other items that also lack an ID.
			itemID := item.ID
			if itemID == "" {
				itemID = "_" + strconv.Itoa(len(groups))
			}
			key := groupKey{host: ip, port: port, id: itemID}
			groups[key] = append(groups[key], itemGroup{
				title:    strings.TrimSpace(title),
				severity: severity,
			})
		}

		// Second pass: emit one vulnerability per group.
		// For multi-item groups, consolidate into a single entry with count.
		for key, items := range groups {
			if len(items) == 1 {
				result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
					Host:        key.host,
					Port:        key.port,
					Title:       items[0].title,
					Severity:    items[0].severity,
					Source:      "nikto",
					Discovery:   result.Timestamp,
				})
				continue
			}

			// Extract the common prefix from titles for the group title.
			// e.g., "Suggested security header missing: referrer-policy"
			//   → prefix = "Suggested security header missing"
			//   → suffixes = ["referrer-policy", "x-content-type-options", ...]
			prefix := commonPrefix(items[0].title, items[1].title)
			for _, it := range items[2:] {
				prefix = commonPrefix(prefix, it.title)
			}
			prefix = strings.TrimRight(prefix, ": ")

			// Collect the variable suffixes after the common prefix.
			var suffixes []string
			for _, it := range items {
				suffix := strings.TrimPrefix(it.title, prefix)
				suffix = strings.TrimLeft(suffix, ": ")
				if suffix != "" {
					suffixes = append(suffixes, suffix)
				}
			}

			// Build consolidated title.
			consolidated := prefix
			if len(suffixes) > 0 {
				consolidated = fmt.Sprintf("%s (%d): %s", prefix, len(items), strings.Join(suffixes, ", "))
			} else {
				consolidated = fmt.Sprintf("%s (%d instances)", prefix, len(items))
			}

			// Use the highest severity from the group.
			sev := items[0].severity
			for _, it := range items[1:] {
				if severityRank(it.severity) > severityRank(sev) {
					sev = it.severity
				}
			}

			result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
				Host:        key.host,
				Port:        key.port,
				Title:       consolidated,
				Severity:    sev,
				Source:      "nikto",
				Discovery:   result.Timestamp,
			})
		}
	}

	return result, nil
}

// niktoSeverity assigns a heuristic severity to a nikto finding based on the
// structured description attribute, which is nikto's canonical finding summary.
func niktoSeverity(item niktoItem) string {
	text := strings.ToLower(item.Description)
	if text == "" {
		text = strings.ToLower(item.DescAttr)
	}

	highKW := []string{"vulnerable", "unrestricted", "credentials", "default password",
		"default credential", "admin panel", "backdoor", "shell",
		"remote code", "rce", "injection"}
	for _, kw := range highKW {
		if strings.Contains(text, kw) {
			return "high"
		}
	}

	mediumKW := []string{"found", "enumerated", "version", "header", "missing",
		"disabled", "enabled", "x-powered", "server:", "cookie"}
	for _, kw := range mediumKW {
		if strings.Contains(text, kw) {
			return "medium"
		}
	}

	return "low"
}

// commonPrefix returns the common prefix of two strings.
func commonPrefix(a, b string) string {
	shorter := len(a)
	if len(b) < shorter {
		shorter = len(b)
	}
	i := 0
	for i < shorter && a[i] == b[i] {
		i++
	}
	return strings.TrimRight(a[:i], " ")
}

// severityRank returns a numeric rank for comparing severities.
func severityRank(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// parseSSLScanResult parses sslscan text output into vulnerabilities.
func (rp *ResultParser) parseSSLScanResult(result *ScanResult, content string) (*ScanResult, error) {
	lines := strings.Split(content, "\n")

	// sslscan can contain results for multiple hosts separated by "--- Host: <ip> ---"
	var currentIP string
	var currentPort int
	seenHosts := make(map[string]bool)
	seenDH := make(map[string]bool) // "host:bits" dedup for weak DH findings
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Detect host separator
		if strings.HasPrefix(line, "--- Host:") {
			hostLine := strings.TrimPrefix(line, "--- Host:")
			hostLine = strings.TrimSuffix(strings.TrimSpace(hostLine), "---")
			ip := strings.TrimSpace(hostLine)
			if ip != "" {
				currentIP = ip
				if !seenHosts[currentIP] {
					seenHosts[currentIP] = true
					result.Hosts = append(result.Hosts, Host{
						IP:       currentIP,
						Status:   "up",
						LastSeen: result.Timestamp,
						Ports:    make([]Port, 0),
					})
					result.Targets = append(result.Targets, currentIP)
				}
			}
			continue
		}

		if currentIP == "" {
			continue
		}

		lineLower := strings.ToLower(line)

		// Detect SSLv2/SSLv3 — critical
		if (strings.Contains(lineLower, "sslv2") || strings.Contains(lineLower, "sslv3")) &&
			strings.Contains(lineLower, "enabled") {
			proto := "SSLv3"
			if strings.Contains(lineLower, "sslv2") {
				proto = "SSLv2"
			}
			result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
				Host:        currentIP,
				Port:        currentPort,
				Title:       fmt.Sprintf("%s enabled", proto),
				Description: line,
				Severity:    "critical",
				Source:      "sslscan",
				Discovery:   result.Timestamp,
			})
		}

		// Detect TLS 1.0/1.1 — medium
		if (strings.Contains(lineLower, "tlsv1.0") || strings.Contains(lineLower, "tlsv1.1") ||
			strings.Contains(lineLower, "tls 1.0") || strings.Contains(lineLower, "tls 1.1")) &&
			strings.Contains(lineLower, "enabled") {
			result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
				Host:        currentIP,
				Port:        currentPort,
				Title:       "Deprecated TLS version enabled",
				Description: line,
				Severity:    "medium",
				Source:      "sslscan",
				Discovery:   result.Timestamp,
			})
		}

		// Detect weak ciphers — high
		weakCiphers := []string{"des", "rc4", "export", "null"}
		for _, weak := range weakCiphers {
			if strings.Contains(lineLower, weak) && !strings.Contains(lineLower, "not ") && !strings.Contains(lineLower, "disabled") {
				result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
					Host:        currentIP,
					Port:        currentPort,
					Title:       fmt.Sprintf("Weak cipher: %s", strings.ToUpper(weak)),
					Description: line,
					Severity:    "high",
					Source:      "sslscan",
					Discovery:   result.Timestamp,
				})
				break
			}
		}

		// Detect weak DH groups (1024 bits or less) — deduplicate per host.
		if currentIP != "" && strings.Contains(line, "DHE") && strings.Contains(line, "bits") {
			bitRegex := regexp.MustCompile(`DHE\s+(\d+)\s+bits`)
			if matches := bitRegex.FindStringSubmatch(line); len(matches) > 1 {
				bits, _ := strconv.Atoi(matches[1])
				if bits <= 1024 {
					key := fmt.Sprintf("%s:%d", currentIP, bits)
					if !seenDH[key] {
						seenDH[key] = true
						result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
							Host:        currentIP,
							Port:        currentPort,
							Title:       fmt.Sprintf("Weak DH key exchange group (%d bits)", bits),
							Description: line,
							Severity:    "medium",
							Source:      "sslscan",
							Discovery:   result.Timestamp,
						})
					}
				}
			}
		}

		// Detect certificate issues — medium
		certIssues := []string{"self-signed", "expired", "weak key"}
		for _, issue := range certIssues {
			if strings.Contains(lineLower, issue) {
				result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
					Host:        currentIP,
					Port:        currentPort,
					Title:       fmt.Sprintf("Certificate issue: %s", issue),
					Description: line,
					Severity:    "medium",
					Source:      "sslscan",
					Discovery:   result.Timestamp,
				})
				break
			}
		}
		
		// Detect self-signed certificate from issuer line
		if currentIP != "" && strings.Contains(lineLower, "issuer") &&
			strings.Contains(lineLower, "self-signed") {
			result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
				Host:        currentIP,
				Port:        currentPort,
				Title:       "Self-signed SSL certificate",
				Description: line,
				Severity:    "medium",
				Source:      "sslscan",
				Discovery:   result.Timestamp,
			})
		}

		// Detect port from sslscan output
		if strings.Contains(line, "SSL/TLS") && strings.Contains(line, ":") {
			portRegex := regexp.MustCompile(`(\d+)`)
			if matches := portRegex.FindStringSubmatch(line); len(matches) > 1 {
				currentPort, _ = strconv.Atoi(matches[1])
			}
		}
	}

	return result, nil
}

// --- sslscan XML types ---

type sslscanDocument struct {
	XMLName  xml.Name      `xml:"document"`
	SSLTests []sslscanTest `xml:"ssltest"`
}

type sslscanTest struct {
	Host      string             `xml:"host,attr"`
	Port      int                `xml:"port,attr"`
	SNIName   string             `xml:"sniname,attr"`
	Protocols []sslscanProtocol  `xml:"protocol"`
	Ciphers   []sslscanCipher    `xml:"cipher"`
	Groups    []sslscanGroup     `xml:"group"`
	Heartbleed []sslscanHeartbleed `xml:"heartbleed"`
	Certs     *sslscanCerts      `xml:"certificates"`
}

type sslscanProtocol struct {
	Type    string `xml:"type,attr"`
	Version string `xml:"version,attr"`
	Enabled string `xml:"enabled,attr"`
}

type sslscanCipher struct {
	Status     string `xml:"status,attr"`
	SSLVersion string `xml:"sslversion,attr"`
	Bits       int    `xml:"bits,attr"`
	Cipher     string `xml:"cipher,attr"`
	Strength   string `xml:"strength,attr"`
	DHEBits    int    `xml:"dhebits,attr"`
}

type sslscanGroup struct {
	SSLVersion string `xml:"sslversion,attr"`
	Bits       int    `xml:"bits,attr"`
	Name       string `xml:"name,attr"`
	Strength   string `xml:"strength,attr"`
}

type sslscanHeartbleed struct {
	SSLVersion string `xml:"sslversion,attr"`
	Vulnerable string `xml:"vulnerable,attr"`
}

type sslscanCerts struct {
	Certificate sslscanCert `xml:"certificate"`
}

type sslscanCert struct {
	SigAlgorithm string `xml:"signature-algorithm"`
	PK           struct {
		Type string `xml:"type,attr"`
		Bits int    `xml:"bits,attr"`
	} `xml:"pk"`
	Subject    string `xml:"subject"`
	Altnames   string `xml:"altnames"`
	Issuer     string `xml:"issuer"`
	SelfSigned string `xml:"self-signed"`
	Expired    string `xml:"expired"`
	NotBefore  string `xml:"not-valid-before"`
	NotAfter   string `xml:"not-valid-after"`
}

// parseSSLScanXML parses sslscan XML output into vulnerabilities.
func (rp *ResultParser) parseSSLScanXML(result *ScanResult, content string) (*ScanResult, error) {
	var doc sslscanDocument
	if err := xml.Unmarshal([]byte(content), &doc); err != nil {
		return rp.parseGenericOutput(result, content)
	}

	for _, test := range doc.SSLTests {
		ip := test.Host
		if ip == "" {
			continue
		}

		result.Hosts = append(result.Hosts, Host{
			IP:       ip,
			Status:   "up",
			LastSeen: result.Timestamp,
			Ports:    make([]Port, 0),
		})
		result.Targets = append(result.Targets, ip)

		port := test.Port

		// SSLv2/SSLv3 — critical
		for _, proto := range test.Protocols {
			if proto.Enabled != "1" {
				continue
			}
			if proto.Type == "ssl" && (proto.Version == "2" || proto.Version == "3") {
				name := "SSLv3"
				if proto.Version == "2" {
					name = "SSLv2"
				}
				result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
					Host:        ip,
					Port:        port,
					Title:       fmt.Sprintf("%s enabled", name),
					Severity:    "critical",
					Source:      "sslscan",
					Discovery:   result.Timestamp,
				})
			}
			// TLS 1.0/1.1 — medium
			if proto.Type == "tls" && (proto.Version == "1.0" || proto.Version == "1.1") {
				result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
					Host:        ip,
					Port:        port,
					Title:       "Deprecated TLS version enabled",
					Description: fmt.Sprintf("TLS %s is enabled", proto.Version),
					Severity:    "medium",
					Source:      "sslscan",
					Discovery:   result.Timestamp,
				})
			}
		}

		// Heartbleed
		for _, hb := range test.Heartbleed {
			if hb.Vulnerable == "1" {
				result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
					Host:        ip,
					Port:        port,
					Title:       "OpenSSL Heartbleed",
					Severity:    "high",
					Source:      "sslscan",
					Discovery:   result.Timestamp,
				})
				break // only report once per host
			}
		}

		// Weak DH groups (deduplicate by bit size)
		seenDHE := make(map[int]bool)
		for _, cipher := range test.Ciphers {
			if cipher.DHEBits > 0 && cipher.DHEBits <= 1024 && !seenDHE[cipher.DHEBits] {
				seenDHE[cipher.DHEBits] = true
				result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
					Host:        ip,
					Port:        port,
					Title:       fmt.Sprintf("Weak DH key exchange group (%d bits)", cipher.DHEBits),
					Severity:    "medium",
					Source:      "sslscan",
					Discovery:   result.Timestamp,
				})
			}
		}

		// Certificate issues
		if test.Certs != nil {
			cert := test.Certs.Certificate
			if cert.SelfSigned == "true" {
				result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
					Host:        ip,
					Port:        port,
					Title:       "Self-signed SSL certificate",
					Severity:    "medium",
					Source:      "sslscan",
					Discovery:   result.Timestamp,
				})
			}
			if cert.Expired == "true" {
				result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
					Host:        ip,
					Port:        port,
					Title:       "Expired SSL certificate",
					Severity:    "high",
					Source:      "sslscan",
					Discovery:   result.Timestamp,
				})
			}
		}
	}

	return result, nil
}

// --- LLDP/CDP XML types ---

// lldpCDPResults is the top-level XML structure for LLDP/CDP neighbor discovery.
type lldpCDPResults struct {
	XMLName    xml.Name       `xml:"lldp_cdp_results"`
	Neighbors []lldpCDPNbr    `xml:"neighbor"`
}

type lldpCDPNbr struct {
	Protocol          string `xml:"protocol,attr"`
	Hostname          string `xml:"hostname"`
	ManagementIP      string `xml:"management_ip"`
	RemotePort        string `xml:"remote_port"`
	RemotePortDesc    string `xml:"remote_port_desc"`
	SystemDescription string `xml:"system_description"`
	Capabilities      string `xml:"capabilities"`
	VLANID            string `xml:"vlan_id"`
	VLANName          string `xml:"vlan_name"`
	Platform          string `xml:"platform"`
	SoftwareVersion   string `xml:"software_version"`
	LocalInterface    string `xml:"local_interface"`
}

// parseLLDPCDPResult parses LLDP/CDP XML output into scan results.
func (rp *ResultParser) parseLLDPCDPResult(result *ScanResult, content string) (*ScanResult, error) {
	var doc lldpCDPResults
	if err := xml.Unmarshal([]byte(content), &doc); err != nil {
		return rp.parseGenericOutput(result, content)
	}

	seenHosts := make(map[string]bool)
	for _, nbr := range doc.Neighbors {
		ip := nbr.ManagementIP
		if ip == "" {
			// Try to extract IP from hostname if it looks like an IP
			if net.ParseIP(nbr.Hostname) != nil {
				ip = nbr.Hostname
			}
		}
		if ip == "" && nbr.Hostname == "" {
			continue
		}

		host := Host{
			Status:     "neighbor",
			LastSeen:   result.Timestamp,
			Ports:      make([]Port, 0),
			Attributes: make(map[string]string),
		}
		if ip != "" {
			host.IP = ip
		}
		if nbr.Hostname != "" && net.ParseIP(nbr.Hostname) == nil {
			host.Hostname = nbr.Hostname
		}

		if nbr.Protocol != "" {
			host.Attributes["discovery_protocol"] = nbr.Protocol
		}
		if nbr.LocalInterface != "" {
			host.Attributes["local_interface"] = nbr.LocalInterface
		}
		if nbr.RemotePort != "" {
			host.Attributes["remote_port"] = nbr.RemotePort
		}
		if nbr.Capabilities != "" {
			host.Attributes["capabilities"] = nbr.Capabilities
		}
		if nbr.VLANID != "" {
			host.Attributes["vlan_id"] = nbr.VLANID
		}
		if nbr.VLANName != "" {
			host.Attributes["vlan_name"] = nbr.VLANName
		}
		if nbr.Platform != "" {
			host.Attributes["platform"] = nbr.Platform
			host.OS = nbr.Platform
		}
		if nbr.SystemDescription != "" {
			host.Attributes["system_description"] = nbr.SystemDescription
			host.OSDetails = nbr.SystemDescription
		}

		if !seenHosts[ip] {
			seenHosts[ip] = true
			result.Hosts = append(result.Hosts, host)
			if ip != "" {
				result.Targets = append(result.Targets, ip)
			}
		}
	}

	return result, nil
}

// --- SNMP XML types ---

// snmpResults is the top-level XML structure for SNMP interrogation output.
type snmpResults struct {
	XMLName xml.Name    `xml:"snmp_results"`
	Devices []snmpDevice `xml:"device"`
}

type snmpDevice struct {
	IP              string          `xml:"ip,attr"`
	SysDescription  string          `xml:"sys_description"`
	SysUptime       string          `xml:"sys_uptime"`
	Hostname        string          `xml:"hostname"`
	Interfaces      []snmpInterface `xml:"interfaces>interface"`
	ARPEntries      []snmpARPEntry  `xml:"arp_entries>entry"`
	VLANs           []snmpVLAN      `xml:"vlans>vlan"`
	Routes          []snmpRoute     `xml:"routes>route"`
}

type snmpInterface struct {
	Name   string `xml:"name"`
	Status string `xml:"status"`
	Speed  string `xml:"speed"`
}

type snmpARPEntry struct {
	MAC       string `xml:"mac,attr"`
	IP        string `xml:"ip,attr"`
	Interface string `xml:"interface,attr"`
}

type snmpVLAN struct {
	ID   string `xml:"id,attr"`
	Name string `xml:"name,attr"`
}

type snmpRoute struct {
	Dest      string `xml:"dest,attr"`
	Gateway   string `xml:"gateway,attr"`
	Interface string `xml:"interface,attr"`
}

// parseSNMPResult parses SNMP interrogation XML output into scan results.
func (rp *ResultParser) parseSNMPResult(result *ScanResult, content string) (*ScanResult, error) {
	var doc snmpResults
	if err := xml.Unmarshal([]byte(content), &doc); err != nil {
		return rp.parseGenericOutput(result, content)
	}

	for _, dev := range doc.Devices {
		if dev.IP == "" {
			continue
		}

		host := Host{
			IP:         dev.IP,
			Hostname:   dev.Hostname,
			Status:     "up",
			LastSeen:   result.Timestamp,
			Ports:      make([]Port, 0),
			Attributes: make(map[string]string),
		}

		if dev.SysDescription != "" {
			host.OSDetails = dev.SysDescription
			host.Attributes["sys_description"] = dev.SysDescription
		}
		if dev.SysUptime != "" {
			host.Attributes["sys_uptime"] = dev.SysUptime
		}

		// Collect interface info as attributes
		var ifNames []string
		for _, iface := range dev.Interfaces {
			ifNames = append(ifNames, fmt.Sprintf("%s (%s)", iface.Name, iface.Status))
		}
		if len(ifNames) > 0 {
			host.Attributes["interfaces"] = strings.Join(ifNames, ", ")
		}

		// Collect VLAN info
		var vlans []string
		for _, v := range dev.VLANs {
			vlans = append(vlans, fmt.Sprintf("%s (%s)", v.ID, v.Name))
		}
		if len(vlans) > 0 {
			host.Attributes["vlans"] = strings.Join(vlans, ", ")
		}

		// Collect routing info
		var routes []string
		for _, r := range dev.Routes {
			routes = append(routes, fmt.Sprintf("%s via %s", r.Dest, r.Gateway))
		}
		if len(routes) > 0 {
			host.Attributes["routes"] = strings.Join(routes, ", ")
		}

		result.Hosts = append(result.Hosts, host)
		result.Targets = append(result.Targets, dev.IP)

		// ARP entries become additional host entries
		for _, entry := range dev.ARPEntries {
			if entry.IP != "" && entry.MAC != "" {
				arpHost := Host{
					IP:         entry.IP,
					MACAddress: strings.ToUpper(entry.MAC),
					Status:     "arp_entry",
					LastSeen:   result.Timestamp,
					Ports:      make([]Port, 0),
					Attributes: make(map[string]string),
				}
				arpHost.Attributes["source"] = "snmp_arp"
				arpHost.Attributes["interface"] = entry.Interface
				result.Hosts = append(result.Hosts, arpHost)
			}
		}
	}

	return result, nil
}

// --- Exploit Search XML types ---

// exploitResults is the top-level XML structure for searchsploit output.
type exploitResults struct {
	XMLName xml.Name      `xml:"exploit_results"`
	Hosts   []exploitHost `xml:"host"`
}

type exploitHost struct {
	IP       string          `xml:"ip,attr"`
	Services []exploitSvc    `xml:"service"`
}

type exploitSvc struct {
	Port     int              `xml:"port,attr"`
	Product  string           `xml:"product,attr"`
	Version  string           `xml:"version,attr"`
	Exploits []exploitEntry   `xml:"exploit"`
}

type exploitEntry struct {
	Title    string `xml:"title,attr"`
	Type     string `xml:"type,attr"`
	Platform string `xml:"platform,attr"`
	Path     string `xml:"path,attr"`
}

// parseExploitSearchResult parses searchsploit XML output into vulnerabilities.
func (rp *ResultParser) parseExploitSearchResult(result *ScanResult, content string) (*ScanResult, error) {
	var doc exploitResults
	if err := xml.Unmarshal([]byte(content), &doc); err != nil {
		return rp.parseGenericOutput(result, content)
	}

	seenHosts := make(map[string]bool)
	for _, h := range doc.Hosts {
		if h.IP == "" {
			continue
		}

		if !seenHosts[h.IP] {
			seenHosts[h.IP] = true
			result.Hosts = append(result.Hosts, Host{
				IP:       h.IP,
				Status:   "up",
				LastSeen: result.Timestamp,
				Ports:    make([]Port, 0),
			})
			result.Targets = append(result.Targets, h.IP)
		}

		for _, svc := range h.Services {
			for _, expl := range svc.Exploits {
				exploitSeverity := "high"
				switch strings.ToLower(expl.Type) {
				case "dos", "local":
					exploitSeverity = "medium"
				}
				vuln := Vulnerability{
					Host:        h.IP,
					Port:        svc.Port,
					Title:       expl.Title,
					Description: fmt.Sprintf("%s %s exploit: %s", svc.Product, svc.Version, expl.Title),
					Severity:    exploitSeverity,
					Source:      "searchsploit",
					Discovery:   result.Timestamp,
				}
				if expl.Type != "" {
					vuln.References = append(vuln.References, fmt.Sprintf("type: %s", expl.Type))
				}
				if expl.Platform != "" {
					vuln.References = append(vuln.References, fmt.Sprintf("platform: %s", expl.Platform))
				}
				if expl.Path != "" {
					vuln.References = append(vuln.References, expl.Path)
				}
				result.Vulnerabilities = append(result.Vulnerabilities, vuln)
			}
		}
	}

	return result, nil
}

// --- Passive Fingerprint XML types ---

// fingerprintResults is the top-level XML structure for passive fingerprinting.
type fingerprintResults struct {
	XMLName xml.Name           `xml:"fingerprint_results"`
	Hosts   []fingerprintHost  `xml:"host"`
}

type fingerprintHost struct {
	IP         string              `xml:"ip,attr"`
	MAC        string              `xml:"mac,attr"`
	OSGuess    string              `xml:"os_guess"`
	DeviceType string              `xml:"device_type"`
	Confidence string              `xml:"confidence"`
	Evidence   []fingerprintSource `xml:"evidence>source"`
}

type fingerprintSource struct {
	Name  string `xml:"name,attr"`
	Value string `xml:",chardata"`
}

// parseFingerprintResult parses passive fingerprinting XML output.
func (rp *ResultParser) parseFingerprintResult(result *ScanResult, content string) (*ScanResult, error) {
	var doc fingerprintResults
	if err := xml.Unmarshal([]byte(content), &doc); err != nil {
		return rp.parseGenericOutput(result, content)
	}

	for _, fh := range doc.Hosts {
		if fh.IP == "" {
			continue
		}

		host := Host{
			IP:         fh.IP,
			MACAddress: strings.ToUpper(fh.MAC),
			Status:     "fingerprinted",
			LastSeen:   result.Timestamp,
			Ports:      make([]Port, 0),
			Attributes: make(map[string]string),
		}

		if fh.OSGuess != "" {
			host.OS = fh.OSGuess
		}
		if fh.DeviceType != "" {
			host.Attributes["device_type"] = fh.DeviceType
		}
		if fh.Confidence != "" {
			host.Attributes["fingerprint_confidence"] = fh.Confidence
		}

		// Store evidence sources
		for _, ev := range fh.Evidence {
			host.Attributes["evidence_"+ev.Name] = ev.Value
		}

		result.Hosts = append(result.Hosts, host)
		result.Targets = append(result.Targets, fh.IP)
	}

	return result, nil
}

// --- ARP Results XML types ---

// arpResults is the top-level XML structure for ARP table ingestion.
type arpResults struct {
	XMLName  xml.Name    `xml:"arp_results"`
	Metadata arpMeta     `xml:"metadata"`
	Entries  []arpEntry  `xml:"entry"`
}

type arpMeta struct {
	Timestamp string `xml:"timestamp"`
	Interface string `xml:"interface"`
}

type arpEntry struct {
	IP        string `xml:"ip,attr"`
	MAC       string `xml:"mac,attr"`
	Interface string `xml:"interface,attr"`
	State     string `xml:"state,attr"`
}

// parseARPResult parses ARP table XML output into scan results.
func (rp *ResultParser) parseARPResult(result *ScanResult, content string) (*ScanResult, error) {
	var doc arpResults
	if err := xml.Unmarshal([]byte(content), &doc); err != nil {
		return rp.parseGenericOutput(result, content)
	}

	for _, entry := range doc.Entries {
		if entry.IP == "" {
			continue
		}

		host := Host{
			IP:         entry.IP,
			MACAddress: strings.ToUpper(entry.MAC),
			Status:     "arp_entry",
			LastSeen:   result.Timestamp,
			Ports:      make([]Port, 0),
			Attributes: make(map[string]string),
		}
		if entry.Interface != "" {
			host.Attributes["interface"] = entry.Interface
		}
		if entry.State != "" {
			host.Attributes["arp_state"] = entry.State
		}

		result.Hosts = append(result.Hosts, host)
		result.Targets = append(result.Targets, entry.IP)
	}

	return result, nil
}

// --- testssl.sh JSON types ---

// testsslFinding represents one entry in testssl.sh -oj flat JSON array output.
// Each finding has an id, target ip:port, severity, and human-readable finding text.
type testsslFinding struct {
	ID       string `json:"id"`
	IP       string `json:"ip"` // may be "host:port" or just IP
	Port     string `json:"port"`
	Severity string `json:"severity"`
	Finding  string `json:"finding"`
	CVE      string `json:"cve"`
	CWE      string `json:"cwe"`
}

// parseTestSSLResult parses testssl.sh -oj JSON array output into vulnerabilities.
// testssl -oj writes a flat JSON array where each element is one finding.
func (rp *ResultParser) parseTestSSLResult(result *ScanResult, content string) (*ScanResult, error) {
	var findings []testsslFinding
	if err := json.Unmarshal([]byte(strings.TrimSpace(content)), &findings); err != nil {
		return rp.parseGenericOutput(result, content)
	}

	seenHosts := make(map[string]bool)
	for _, f := range findings {
		// The ip field may be "host:port" (IPv4) or "[::1]:port" (IPv6); extract just the IP.
		ip := f.IP
		if idx := strings.LastIndex(ip, ":"); idx >= 0 && !strings.HasPrefix(ip, "[") {
			ip = ip[:idx]
		} else if strings.HasPrefix(ip, "[") {
			// Strip brackets from IPv6 literal
			ip = strings.TrimPrefix(ip, "[")
			if idx := strings.Index(ip, "]"); idx >= 0 {
				ip = ip[:idx]
			}
		}
		if ip == "" {
			continue
		}

		port := 0
		if f.Port != "" {
			port, _ = strconv.Atoi(f.Port)
		}

		if !seenHosts[ip] {
			seenHosts[ip] = true
			result.Hosts = append(result.Hosts, Host{
				IP:       ip,
				Status:   "up",
				LastSeen: result.Timestamp,
				Ports:    make([]Port, 0),
			})
			result.Targets = append(result.Targets, ip)
		}

		// Skip purely informational findings
		sev := strings.ToLower(strings.TrimSpace(f.Severity))
		if sev == "" || sev == "info" || sev == "ok" || sev == "not tested" {
			continue
		}
		if sev == "warn" {
			sev = "low"
		}

		vuln := Vulnerability{
			Host:        ip,
			Port:        port,
			Title:       f.ID + ": " + f.Finding,
			Description: f.Finding,
			Severity:    sev,
			Service:     f.ID,
			Source:      "testssl",
			Discovery:   result.Timestamp,
		}
		if f.CVE != "" {
			vuln.CVE = f.CVE
		}
		result.Vulnerabilities = append(result.Vulnerabilities, vuln)
	}

	return result, nil
}
