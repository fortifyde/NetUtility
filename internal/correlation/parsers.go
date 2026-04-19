package correlation

import (
	"fmt"
	"io/fs"
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

	// Check script name patterns
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
		if currentHost != "" && strings.Contains(strings.ToLower(line), "vulnerable") {
			severity := "medium" // Default severity
			title := line

			// Determine severity from keywords
			lineLower := strings.ToLower(line)
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
// It processes nmap output files (.nmap, .xml) and the ph7 categorization_details.txt.
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

		// Only process nmap output files and the ph7 categorization details file.
		if ext != ".nmap" && ext != ".xml" && base != "categorization_details.txt" {
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
