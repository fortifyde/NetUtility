package correlation

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ScanType represents different types of network scans
type ScanType string

const (
	ScanTypeNetworkEnum         ScanType = "network_enumeration"
	ScanTypeVulnerability       ScanType = "vulnerability_scan"
	ScanTypeCapture             ScanType = "network_capture"
	ScanTypePortScan            ScanType = "port_scan"
	ScanTypeServiceScan         ScanType = "service_scan"
	ScanTypeOSDetection         ScanType = "os_detection"
	ScanTypeHostCategorization  ScanType = "host_categorization"
)

// ScanResult represents the result of a network scan
type ScanResult struct {
	ID              string                 `json:"id"`
	Type            ScanType               `json:"type"`
	Timestamp       time.Time              `json:"timestamp"`
	Source          string                 `json:"source"`          // Script or tool name
	FilePath        string                 `json:"file_path"`       // Path to result file
	Targets         []string               `json:"targets"`         // IP addresses or ranges scanned
	Hosts           []Host                 `json:"hosts"`           // Discovered hosts
	Services        []Service              `json:"services"`        // Discovered services
	Vulnerabilities []Vulnerability        `json:"vulnerabilities"` // Found vulnerabilities
	Metadata        map[string]any `json:"metadata"`        // Additional data
}

// Host represents a discovered network host
type Host struct {
	IP         string            `json:"ip"`
	Hostname   string            `json:"hostname,omitempty"`
	MACAddress string            `json:"mac_address,omitempty"`
	OS         string            `json:"os,omitempty"`
	OSDetails  string            `json:"os_details,omitempty"`
	Status     string            `json:"status"` // up, down, filtered
	LastSeen   time.Time         `json:"last_seen"`
	Ports      []Port            `json:"ports,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// Port represents an open port on a host
type Port struct {
	Number   int    `json:"number"`
	Protocol string `json:"protocol"` // tcp, udp
	State    string `json:"state"`    // open, closed, filtered
	Service  string `json:"service,omitempty"`
	Version  string `json:"version,omitempty"`
	Banner   string `json:"banner,omitempty"`
}

// Service represents a network service
type Service struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Protocol   string `json:"protocol"`
	Name       string `json:"name"`
	Version    string `json:"version,omitempty"`
	Product    string `json:"product,omitempty"`
	ExtraInfo  string `json:"extra_info,omitempty"`
	Confidence int    `json:"confidence,omitempty"`
}

// Vulnerability represents a security vulnerability
type Vulnerability struct {
	Host        string    `json:"host"`
	Port        int       `json:"port,omitempty"`
	Service     string    `json:"service,omitempty"`
	CVE         string    `json:"cve,omitempty"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"` // critical, high, medium, low, info
	References  []string  `json:"references,omitempty"`
	Solution    string    `json:"solution,omitempty"`
	Discovery   time.Time `json:"discovery"`
}

// CorrelationResult represents correlated findings across multiple scans
type CorrelationResult struct {
	Host            string                 `json:"host"`
	HostInfo        *Host                  `json:"host_info"`
	RelatedScans    []string               `json:"related_scans"`
	Services        []Service              `json:"services"`
	Vulnerabilities []Vulnerability        `json:"vulnerabilities"`
	Timeline        []TimelineEvent        `json:"timeline"`
	RiskScore       int                    `json:"risk_score"`
	Recommendations []string               `json:"recommendations"`
	Metadata        map[string]any `json:"metadata"`
}

// TimelineEvent represents an event in the scan timeline
type TimelineEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	ScanType    ScanType  `json:"scan_type"`
	Event       string    `json:"event"`
	Description string    `json:"description"`
	Source      string    `json:"source"`
}

// Correlator manages scan result correlation
type Correlator struct {
	results         map[string]*ScanResult
	correlations    map[string]*CorrelationResult
	workspaceDir    string
	dataDir         string // directory where correlations.json is stored (alongside the binary)
	manualOverrides map[string]string // ip → category; loaded from manual_categories.json
	excludedHosts   map[string]bool   // ips excluded via exclude_team_ips.sh; never shown or re-added
	mu              sync.RWMutex
}

// NewCorrelator creates a new result correlator. correlations.json is stored
// in the same directory as the running binary, not in the workspace.
func NewCorrelator(workspaceDir string) *Correlator {
	dataDir := ""
	if execPath, err := os.Executable(); err == nil {
		dataDir = filepath.Dir(execPath)
	}
	return newCorrelatorWithDataDir(workspaceDir, dataDir)
}

// newCorrelatorWithDataDir is used in tests to inject an explicit data directory.
func newCorrelatorWithDataDir(workspaceDir, dataDir string) *Correlator {
	return &Correlator{
		results:         make(map[string]*ScanResult),
		correlations:    make(map[string]*CorrelationResult),
		workspaceDir:    workspaceDir,
		dataDir:         dataDir,
		manualOverrides: make(map[string]string),
		excludedHosts:   make(map[string]bool),
	}
}

// AddScanResult adds a new scan result and triggers correlation
func (c *Correlator) AddScanResult(result *ScanResult) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.results[result.ID] = result

	// Trigger correlation for affected hosts
	affectedHosts := c.extractHostsFromResult(result)
	for _, host := range affectedHosts {
		c.correlateHost(host)
	}

	return c.saveResults()
}

// extractHostsFromResult extracts all host IPs from a scan result
func (c *Correlator) extractHostsFromResult(result *ScanResult) []string {
	hostSet := make(map[string]bool)

	// Add explicit targets
	for _, target := range result.Targets {
		if ip := net.ParseIP(target); ip != nil {
			hostSet[target] = true
		}
	}

	// Add discovered hosts
	for _, host := range result.Hosts {
		hostSet[host.IP] = true
	}

	// Add hosts from services
	for _, service := range result.Services {
		hostSet[service.Host] = true
	}

	// Add hosts from vulnerabilities
	for _, vuln := range result.Vulnerabilities {
		hostSet[vuln.Host] = true
	}

	hosts := make([]string, 0, len(hostSet))
	for host := range hostSet {
		hosts = append(hosts, host)
	}

	return hosts
}

// correlateHost correlates all scan results for a specific host
func (c *Correlator) correlateHost(hostIP string) {
	if c.excludedHosts[hostIP] {
		return
	}
	correlation := &CorrelationResult{
		Host:            hostIP,
		RelatedScans:    make([]string, 0),
		Services:        make([]Service, 0),
		Vulnerabilities: make([]Vulnerability, 0),
		Timeline:        make([]TimelineEvent, 0),
		Recommendations: make([]string, 0),
		Metadata:        make(map[string]any),
	}

	// Collect data from all relevant scans
	for _, result := range c.results {
		if c.resultContainsHost(result, hostIP) {
			correlation.RelatedScans = append(correlation.RelatedScans, result.ID)

			// Add timeline event
			correlation.Timeline = append(correlation.Timeline, TimelineEvent{
				Timestamp:   result.Timestamp,
				ScanType:    result.Type,
				Event:       "scan_completed",
				Description: fmt.Sprintf("%s scan completed", result.Type),
				Source:      result.Source,
			})

			// Merge host information
			for _, host := range result.Hosts {
				if host.IP == hostIP {
					correlation.HostInfo = c.mergeHostInfo(correlation.HostInfo, &host)
				}
			}

			// Collect services
			for _, service := range result.Services {
				if service.Host == hostIP {
					correlation.Services = append(correlation.Services, service)
				}
			}

			// Collect vulnerabilities
			for _, vuln := range result.Vulnerabilities {
				if vuln.Host == hostIP {
					correlation.Vulnerabilities = append(correlation.Vulnerabilities, vuln)
				}
			}
		}
	}

	// Sort timeline by timestamp
	c.sortTimeline(correlation.Timeline)

	// Calculate risk score
	correlation.RiskScore = c.calculateRiskScore(correlation)

	// Generate recommendations
	correlation.Recommendations = c.generateRecommendations(correlation)

	c.correlations[hostIP] = correlation
	c.applyManualOverrides()
}

// resultContainsHost checks if a scan result contains information about a host
func (c *Correlator) resultContainsHost(result *ScanResult, hostIP string) bool {
	// Check targets
	for _, target := range result.Targets {
		if target == hostIP {
			return true
		}
		// Check if IP is in a CIDR range
		if strings.Contains(target, "/") {
			if _, network, err := net.ParseCIDR(target); err == nil {
				if network.Contains(net.ParseIP(hostIP)) {
					return true
				}
			}
		}
	}

	// Check discovered hosts
	for _, host := range result.Hosts {
		if host.IP == hostIP {
			return true
		}
	}

	// Check services
	for _, service := range result.Services {
		if service.Host == hostIP {
			return true
		}
	}

	// Check vulnerabilities
	for _, vuln := range result.Vulnerabilities {
		if vuln.Host == hostIP {
			return true
		}
	}

	return false
}

// mergeHostInfo merges host information from multiple scans
func (c *Correlator) mergeHostInfo(existing *Host, new *Host) *Host {
	if existing == nil {
		return new
	}

	// Keep the most recent information
	if new.LastSeen.After(existing.LastSeen) {
		existing.LastSeen = new.LastSeen
	}

	// Merge non-empty fields
	if new.Hostname != "" && existing.Hostname == "" {
		existing.Hostname = new.Hostname
	}
	if new.MACAddress != "" && existing.MACAddress == "" {
		existing.MACAddress = new.MACAddress
	}
	if new.OS != "" {
		existing.OS = new.OS
		existing.OSDetails = new.OSDetails
	}
	if new.Status != "" {
		existing.Status = new.Status
	}

	// Merge ports
	existing.Ports = c.mergePorts(existing.Ports, new.Ports)

	// Merge attributes
	if existing.Attributes == nil {
		existing.Attributes = make(map[string]string)
	}
	for key, value := range new.Attributes {
		existing.Attributes[key] = value
	}

	return existing
}

// mergePorts merges port information, keeping the most detailed data
func (c *Correlator) mergePorts(existing []Port, new []Port) []Port {
	portMap := make(map[string]Port)

	// Add existing ports
	for _, port := range existing {
		key := fmt.Sprintf("%d-%s", port.Number, port.Protocol)
		portMap[key] = port
	}

	// Merge new ports
	for _, port := range new {
		key := fmt.Sprintf("%d-%s", port.Number, port.Protocol)
		if existingPort, exists := portMap[key]; exists {
			// Keep more detailed information
			if port.Service != "" && existingPort.Service == "" {
				existingPort.Service = port.Service
			}
			if port.Version != "" && existingPort.Version == "" {
				existingPort.Version = port.Version
			}
			if port.Banner != "" && existingPort.Banner == "" {
				existingPort.Banner = port.Banner
			}
			if port.State == "open" {
				existingPort.State = port.State
			}
			portMap[key] = existingPort
		} else {
			portMap[key] = port
		}
	}

	// Convert back to slice
	mergedPorts := make([]Port, 0, len(portMap))
	for _, port := range portMap {
		mergedPorts = append(mergedPorts, port)
	}

	return mergedPorts
}

// sortTimeline sorts timeline events by timestamp
func (c *Correlator) sortTimeline(timeline []TimelineEvent) {
	sort.Slice(timeline, func(i, j int) bool {
		return timeline[i].Timestamp.Before(timeline[j].Timestamp)
	})
}

// calculateRiskScore calculates a risk score based on discovered vulnerabilities and services
func (c *Correlator) calculateRiskScore(correlation *CorrelationResult) int {
	score := 0

	// Base score for having services
	score += len(correlation.Services) * 5

	// Score based on vulnerabilities
	for _, vuln := range correlation.Vulnerabilities {
		switch strings.ToLower(vuln.Severity) {
		case "critical":
			score += 100
		case "high":
			score += 75
		case "medium":
			score += 50
		case "low":
			score += 25
		case "info":
			score += 10
		}
	}

	// Score based on open ports
	if correlation.HostInfo != nil {
		for _, port := range correlation.HostInfo.Ports {
			if port.State == "open" {
				score += 10

				// Higher risk for certain services
				switch strings.ToLower(port.Service) {
				case "ssh", "telnet", "ftp", "http", "https", "smtp", "pop3", "imap":
					score += 20
				case "smb", "netbios", "ldap", "kerberos":
					score += 30
				case "mysql", "postgresql", "oracle", "mssql":
					score += 25
				}
			}
		}
	}

	// Cap the score at 1000
	if score > 1000 {
		score = 1000
	}

	return score
}

// generateRecommendations generates security recommendations based on findings
func (c *Correlator) generateRecommendations(correlation *CorrelationResult) []string {
	recommendations := make([]string, 0)

	// Recommendations based on vulnerabilities
	criticalCount := 0
	highCount := 0
	for _, vuln := range correlation.Vulnerabilities {
		switch strings.ToLower(vuln.Severity) {
		case "critical":
			criticalCount++
		case "high":
			highCount++
		}
	}

	if criticalCount > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("URGENT: Address %d critical vulnerabilities immediately", criticalCount))
	}
	if highCount > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("Prioritize fixing %d high-severity vulnerabilities", highCount))
	}

	// Recommendations based on services
	serviceMap := make(map[string]bool)
	for _, service := range correlation.Services {
		serviceMap[strings.ToLower(service.Name)] = true
	}

	if serviceMap["telnet"] {
		recommendations = append(recommendations, "Replace Telnet with SSH for secure remote access")
	}
	if serviceMap["ftp"] {
		recommendations = append(recommendations, "Consider using SFTP or FTPS instead of plain FTP")
	}
	if serviceMap["http"] && !serviceMap["https"] {
		recommendations = append(recommendations, "Implement HTTPS to encrypt web traffic")
	}
	if serviceMap["smb"] {
		recommendations = append(recommendations, "Review SMB configuration and disable unnecessary versions")
	}

	// General recommendations
	if len(correlation.Services) > 10 {
		recommendations = append(recommendations, "Review running services and disable unnecessary ones")
	}

	if correlation.RiskScore > 500 {
		recommendations = append(recommendations, "High risk score - conduct immediate security review")
	}

	return recommendations
}

// GetCorrelationForHost returns correlation results for a specific host
func (c *Correlator) GetCorrelationForHost(hostIP string) (*CorrelationResult, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.excludedHosts[hostIP] {
		return nil, false
	}
	correlation, exists := c.correlations[hostIP]
	return correlation, exists
}

// GetAllCorrelations returns all correlation results
func (c *Correlator) GetAllCorrelations() map[string]*CorrelationResult {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make(map[string]*CorrelationResult)
	for k, v := range c.correlations {
		if !c.excludedHosts[k] {
			result[k] = v
		}
	}
	return result
}

// GetHighRiskHosts returns hosts with risk scores above the threshold
func (c *Correlator) GetHighRiskHosts(threshold int) []*CorrelationResult {
	c.mu.RLock()
	defer c.mu.RUnlock()

	highRisk := make([]*CorrelationResult, 0)
	for _, correlation := range c.correlations {
		if correlation.RiskScore >= threshold {
			highRisk = append(highRisk, correlation)
		}
	}

	return highRisk
}

// saveResults saves correlation results to disk
func (c *Correlator) saveResults() error {
	if c.dataDir == "" {
		return nil
	}

	correlationDir := filepath.Join(c.dataDir, "correlations")
	if err := os.MkdirAll(correlationDir, 0755); err != nil {
		return fmt.Errorf("failed to create correlation directory: %w", err)
	}

	// Save correlations
	correlationFile := filepath.Join(correlationDir, "correlations.json")
	data, err := json.MarshalIndent(c.correlations, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal correlations: %w", err)
	}

	if err := os.WriteFile(correlationFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write correlations: %w", err)
	}

	return nil
}

func (c *Correlator) manualOverridesPath() string {
	if c.dataDir == "" {
		return ""
	}
	return filepath.Join(c.dataDir, "correlations", "manual_categories.json")
}

func (c *Correlator) loadManualOverrides() error {
	path := c.manualOverridesPath()
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading manual_categories.json: %w", err)
	}
	return json.Unmarshal(data, &c.manualOverrides)
}

func (c *Correlator) saveManualOverrides() error {
	path := c.manualOverridesPath()
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("creating correlations directory: %w", err)
	}
	data, err := json.MarshalIndent(c.manualOverrides, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling manual overrides: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

func (c *Correlator) excludedHostsPath() string {
	if c.dataDir == "" {
		return ""
	}
	return filepath.Join(c.dataDir, "correlations", "excluded_hosts.json")
}

// loadExcludedHosts reads excluded_hosts.json and removes any excluded entries from
// c.correlations. Caller must hold c.mu.
func (c *Correlator) loadExcludedHosts() error {
	path := c.excludedHostsPath()
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading excluded_hosts.json: %w", err)
	}
	var excluded map[string]bool
	if err := json.Unmarshal(data, &excluded); err != nil {
		return fmt.Errorf("parsing excluded_hosts.json: %w", err)
	}
	c.excludedHosts = excluded
	for ip := range c.excludedHosts {
		delete(c.correlations, ip)
	}
	return nil
}

func (c *Correlator) saveExcludedHosts() error {
	path := c.excludedHostsPath()
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("creating correlations dir: %w", err)
	}
	data, err := json.MarshalIndent(c.excludedHosts, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling excluded hosts: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// ExcludeHosts adds IPs to the permanent exclusion list, removes them from in-memory
// correlations, and persists both files.
func (c *Correlator) ExcludeHosts(ips []string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, ip := range ips {
		c.excludedHosts[ip] = true
		delete(c.correlations, ip)
	}
	if err := c.saveExcludedHosts(); err != nil {
		return err
	}
	return c.saveResults()
}

// applyManualOverrides stamps manual category overrides onto live correlations.
// Must be called with c.mu held.
func (c *Correlator) applyManualOverrides() {
	for ip, cat := range c.manualOverrides {
		if corr, ok := c.correlations[ip]; ok && corr.HostInfo != nil {
			if corr.HostInfo.Attributes == nil {
				corr.HostInfo.Attributes = make(map[string]string)
			}
			corr.HostInfo.Attributes["category"] = cat
		}
	}
}

// SetManualCategory permanently overrides the category for a host.
func (c *Correlator) SetManualCategory(ip, category string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.manualOverrides[ip] = category

	if corr, ok := c.correlations[ip]; ok && corr.HostInfo != nil {
		if corr.HostInfo.Attributes == nil {
			corr.HostInfo.Attributes = make(map[string]string)
		}
		corr.HostInfo.Attributes["category"] = category
	}

	if err := c.saveManualOverrides(); err != nil {
		return fmt.Errorf("saving manual overrides: %w", err)
	}
	return c.saveResults()
}

// LoadResults loads saved correlation results from disk
func (c *Correlator) LoadResults() error {
	if c.dataDir == "" {
		return nil
	}

	correlationFile := filepath.Join(c.dataDir, "correlations", "correlations.json")
	if _, err := os.Stat(correlationFile); os.IsNotExist(err) {
		return nil
	}

	data, err := os.ReadFile(correlationFile)
	if err != nil {
		return fmt.Errorf("failed to read correlations: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if err := json.Unmarshal(data, &c.correlations); err != nil {
		return fmt.Errorf("failed to unmarshal correlations: %w", err)
	}

	if err := c.loadManualOverrides(); err != nil {
		return fmt.Errorf("loading manual overrides: %w", err)
	}
	c.applyManualOverrides()

	if err := c.loadExcludedHosts(); err != nil {
		return fmt.Errorf("loading excluded hosts: %w", err)
	}

	return nil
}

// ParseNmapOutput parses nmap output and creates a scan result
func ParseNmapOutput(filePath, scanID string) (*ScanResult, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	result := &ScanResult{
		ID:        scanID,
		Type:      ScanTypePortScan,
		Timestamp: time.Now(),
		Source:    "nmap",
		FilePath:  filePath,
		Hosts:     make([]Host, 0),
		Services:  make([]Service, 0),
	}

	// Simple regex-based parsing (could be enhanced with XML parsing)
	lines := strings.Split(string(content), "\n")
	var currentHost *Host

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Host detection
		if strings.Contains(line, "Nmap scan report for") {
			ipRegex := regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)`)
			if matches := ipRegex.FindStringSubmatch(line); len(matches) > 1 {
				if currentHost != nil {
					result.Hosts = append(result.Hosts, *currentHost)
				}
				currentHost = &Host{
					IP:       matches[1],
					Status:   "up",
					LastSeen: time.Now(),
					Ports:    make([]Port, 0),
				}
				result.Targets = append(result.Targets, matches[1])
			}
		}

		// Port detection
		if currentHost != nil && (strings.Contains(line, "/tcp") || strings.Contains(line, "/udp")) {
			portRegex := regexp.MustCompile(`(\d+)/(tcp|udp)\s+(\w+)\s+(.*)`)
			if matches := portRegex.FindStringSubmatch(line); len(matches) > 4 {
				portNum, _ := strconv.Atoi(matches[1])
				port := Port{
					Number:   portNum,
					Protocol: matches[2],
					State:    matches[3],
					Service:  strings.Fields(matches[4])[0],
				}
				currentHost.Ports = append(currentHost.Ports, port)

				// Add to services
				if port.State == "open" {
					service := Service{
						Host:     currentHost.IP,
						Port:     portNum,
						Protocol: matches[2],
						Name:     port.Service,
					}
					result.Services = append(result.Services, service)
				}
			}
		}
	}

	// Add the last host
	if currentHost != nil {
		result.Hosts = append(result.Hosts, *currentHost)
	}

	return result, nil
}
