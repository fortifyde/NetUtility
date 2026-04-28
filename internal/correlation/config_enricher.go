package correlation

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ConfigEnricher reads gathered device config directories and enriches CorrelationResult
// objects with compliance findings and physical topology (MAC table cross-correlation).
type ConfigEnricher struct {
	workspaceDir string
}

// NewConfigEnricher returns an enricher that reads from workspaceDir/configs/gather_*/.
func NewConfigEnricher(workspaceDir string) *ConfigEnricher {
	return &ConfigEnricher{workspaceDir: workspaceDir}
}

// HasConfigs returns true if at least one gather session directory exists.
func (ce *ConfigEnricher) HasConfigs() bool {
	dir, err := ce.latestSessionDir()
	return err == nil && dir != ""
}

// Enrich enriches correlations in-place with compliance findings and physical links.
// It is best-effort: partial failures are silently skipped.
func (ce *ConfigEnricher) Enrich(correlations map[string]*CorrelationResult) error {
	sessionDir, err := ce.latestSessionDir()
	if err != nil || sessionDir == "" {
		return err
	}

	dirs, err := ce.deviceDirs(sessionDir)
	if err != nil {
		return err
	}

	idx := newMACIndex()
	for _, dir := range dirs {
		_ = ce.enrichDevice(dir, idx, correlations)
	}
	ce.applyPhysicalLinks(idx, correlations)
	return nil
}

// latestSessionDir returns the most recent configs/gather_*/ directory.
func (ce *ConfigEnricher) latestSessionDir() (string, error) {
	configsDir := filepath.Join(ce.workspaceDir, "configs")
	entries, err := os.ReadDir(configsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}

	var sessions []string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "gather_") {
			sessions = append(sessions, filepath.Join(configsDir, e.Name()))
		}
	}
	if len(sessions) == 0 {
		return "", nil
	}
	sort.Strings(sessions)
	return sessions[len(sessions)-1], nil
}

// deviceDirs returns all device_<IP> subdirectories within sessionDir.
func (ce *ConfigEnricher) deviceDirs(sessionDir string) ([]string, error) {
	entries, err := os.ReadDir(sessionDir)
	if err != nil {
		return nil, err
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "device_") {
			dirs = append(dirs, filepath.Join(sessionDir, e.Name()))
		}
	}
	return dirs, nil
}

// enrichDevice processes one device directory: reads metadata, running config (compliance),
// and compliance_commands.txt (MAC table). Updates correlations and populates the MAC index.
func (ce *ConfigEnricher) enrichDevice(deviceDir string, idx *macIndex, correlations map[string]*CorrelationResult) error {
	ip, vendor := readMetadata(deviceDir)
	if ip == "" {
		return nil
	}

	// Compliance: parse running config
	runningConfig, _ := readFileContents(filepath.Join(deviceDir, "running_config.txt"))
	if runningConfig != "" {
		findings, severity := checkCompliance(runningConfig, vendor)
		if corr, ok := correlations[ip]; ok {
			corr.ComplianceFindings = findings
			corr.ComplianceSeverity = severity
		}
	}

	// MAC table: parse compliance_commands.txt
	complianceOutput, _ := readFileContents(filepath.Join(deviceDir, "compliance_commands.txt"))
	if complianceOutput != "" {
		idx.parse(complianceOutput, ip)
	}

	return nil
}

// applyPhysicalLinks matches host MACs in correlations against the MAC index
// and writes PhysicalLinks onto the matching CorrelationResult.
func (ce *ConfigEnricher) applyPhysicalLinks(idx *macIndex, correlations map[string]*CorrelationResult) {
	for _, corr := range correlations {
		if corr.HostInfo == nil || corr.HostInfo.MACAddress == "" {
			continue
		}
		mac := normalizeMAC(corr.HostInfo.MACAddress)
		if mac == "" {
			continue
		}
		entry, ok := idx.entries[mac]
		if !ok {
			continue
		}
		corr.PhysicalLinks = append(corr.PhysicalLinks, PhysicalLink{
			SwitchIP:  entry.SwitchIP,
			Interface: entry.Interface,
			VLAN:      entry.VLAN,
		})
	}
}

// readMetadata parses metadata.txt and returns the device IP and vendor string.
func readMetadata(deviceDir string) (ip, vendor string) {
	data, err := readFileContents(filepath.Join(deviceDir, "metadata.txt"))
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "IP Address:") {
			ip = strings.TrimSpace(strings.TrimPrefix(line, "IP Address:"))
		} else if strings.HasPrefix(line, "Vendor/OS:") {
			vendor = strings.TrimSpace(strings.TrimPrefix(line, "Vendor/OS:"))
		}
	}
	return ip, vendor
}

// readFileContents reads a file and returns its content as a string.
func readFileContents(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
