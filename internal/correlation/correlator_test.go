package correlation

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewCorrelator(t *testing.T) {
	correlator := NewCorrelator("/test/workspace")

	if correlator.workspaceDir != "/test/workspace" {
		t.Errorf("workspaceDir = %s, want /test/workspace", correlator.workspaceDir)
	}
	if correlator.results == nil {
		t.Error("results should be initialized")
	}
	if correlator.correlations == nil {
		t.Error("correlations should be initialized")
	}
}

func TestExtractHostsFromResult(t *testing.T) {
	correlator := NewCorrelator("")

	result := &ScanResult{
		Targets: []string{"192.168.1.1", "192.168.1.2", "invalid"},
		Hosts: []Host{
			{IP: "192.168.1.3"},
			{IP: "192.168.1.4"},
		},
		Services: []Service{
			{Host: "192.168.1.5"},
		},
		Vulnerabilities: []Vulnerability{
			{Host: "192.168.1.6"},
		},
	}

	hosts := correlator.extractHostsFromResult(result)

	// Should extract all unique valid IPs
	expectedCount := 6 // 1.1, 1.2, 1.3, 1.4, 1.5, 1.6
	if len(hosts) != expectedCount {
		t.Errorf("len(hosts) = %d, want %d", len(hosts), expectedCount)
	}

	// Check that all expected IPs are present
	expectedIPs := map[string]bool{
		"192.168.1.1": true,
		"192.168.1.2": true,
		"192.168.1.3": true,
		"192.168.1.4": true,
		"192.168.1.5": true,
		"192.168.1.6": true,
	}

	for _, host := range hosts {
		if !expectedIPs[host] {
			t.Errorf("Unexpected host: %s", host)
		}
	}
}

func TestResultContainsHost(t *testing.T) {
	correlator := NewCorrelator("")

	result := &ScanResult{
		Targets:         []string{"192.168.1.0/24", "10.0.0.5"},
		Hosts:           []Host{{IP: "172.16.0.1"}},
		Services:        []Service{{Host: "192.168.2.1"}},
		Vulnerabilities: []Vulnerability{{Host: "192.168.3.1"}},
	}

	tests := []struct {
		ip       string
		contains bool
	}{
		{"10.0.0.5", true},     // Direct target match
		{"192.168.1.50", true}, // In CIDR range
		{"192.168.1.1", true},  // In CIDR range
		{"172.16.0.1", true},   // In hosts
		{"192.168.2.1", true},  // In services
		{"192.168.3.1", true},  // In vulnerabilities
		{"10.0.0.6", false},    // Not found
		{"192.168.2.0", false}, // Not in result
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			contains := correlator.resultContainsHost(result, tt.ip)
			if contains != tt.contains {
				t.Errorf("resultContainsHost(%s) = %v, want %v", tt.ip, contains, tt.contains)
			}
		})
	}
}

func TestMergeHostInfo(t *testing.T) {
	correlator := NewCorrelator("")

	t.Run("merge into nil", func(t *testing.T) {
		newHost := &Host{
			IP:       "192.168.1.1",
			Hostname: "testhost",
			Status:   "up",
			LastSeen: time.Now(),
		}

		merged := correlator.mergeHostInfo(nil, newHost)
		if merged.IP != newHost.IP {
			t.Errorf("merged IP = %s, want %s", merged.IP, newHost.IP)
		}
	})

	t.Run("merge with newer data", func(t *testing.T) {
		oldTime := time.Now().Add(-1 * time.Hour)
		newTime := time.Now()

		existing := &Host{
			IP:         "192.168.1.1",
			Hostname:   "",
			MACAddress: "aa:bb:cc:dd:ee:ff",
			LastSeen:   oldTime,
		}

		newHost := &Host{
			IP:         "192.168.1.1",
			Hostname:   "newhostname",
			MACAddress: "",
			OS:         "Linux",
			LastSeen:   newTime,
		}

		merged := correlator.mergeHostInfo(existing, newHost)

		if merged.Hostname != "newhostname" {
			t.Errorf("Hostname not updated: %s", merged.Hostname)
		}
		if merged.MACAddress != "aa:bb:cc:dd:ee:ff" {
			t.Error("MACAddress should be preserved")
		}
		if merged.OS != "Linux" {
			t.Error("OS should be updated")
		}
		if !merged.LastSeen.Equal(newTime) {
			t.Error("LastSeen should be updated to newer time")
		}
	})
}

func TestMergePorts(t *testing.T) {
	correlator := NewCorrelator("")

	existing := []Port{
		{Number: 80, Protocol: "tcp", State: "open", Service: "http"},
		{Number: 443, Protocol: "tcp", State: "open", Service: "https"},
	}

	newPorts := []Port{
		{Number: 80, Protocol: "tcp", State: "open", Service: "http", Version: "Apache 2.4"},
		{Number: 22, Protocol: "tcp", State: "open", Service: "ssh"},
	}

	merged := correlator.mergePorts(existing, newPorts)

	// Should have 3 ports total (80, 443, 22)
	if len(merged) != 3 {
		t.Errorf("len(merged) = %d, want 3", len(merged))
	}

	// Check that port 80 has version info merged
	found80 := false
	for _, port := range merged {
		if port.Number == 80 {
			found80 = true
			if port.Version != "Apache 2.4" {
				t.Errorf("Port 80 version = %s, want Apache 2.4", port.Version)
			}
		}
	}
	if !found80 {
		t.Error("Port 80 not found in merged ports")
	}
}

func TestCalculateRiskScore(t *testing.T) {
	correlator := NewCorrelator("")

	tests := []struct {
		name        string
		correlation *CorrelationResult
		wantMin     int
		wantMax     int
	}{
		{
			name: "no findings",
			correlation: &CorrelationResult{
				Services:        []Service{},
				Vulnerabilities: []Vulnerability{},
			},
			wantMin: 0,
			wantMax: 0,
		},
		{
			name: "with services only",
			correlation: &CorrelationResult{
				Services: []Service{
					{Name: "http", Port: 80},
					{Name: "ssh", Port: 22},
				},
				Vulnerabilities: []Vulnerability{},
			},
			wantMin: 10,
			wantMax: 50,
		},
		{
			name: "with critical vulnerability",
			correlation: &CorrelationResult{
				Services: []Service{},
				Vulnerabilities: []Vulnerability{
					{Severity: "critical", Title: "Critical vuln"},
				},
			},
			wantMin: 100,
			wantMax: 150,
		},
		{
			name: "with high-risk services",
			correlation: &CorrelationResult{
				Services:        []Service{},
				Vulnerabilities: []Vulnerability{},
				HostInfo: &Host{
					Ports: []Port{
						{Number: 22, Service: "ssh", State: "open"},
						{Number: 445, Service: "smb", State: "open"},
					},
				},
			},
			wantMin: 60,
			wantMax: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := correlator.calculateRiskScore(tt.correlation)
			if score < tt.wantMin || score > tt.wantMax {
				t.Errorf("calculateRiskScore() = %d, want between %d and %d", score, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestCalculateRiskScoreCapped(t *testing.T) {
	correlator := NewCorrelator("")

	// Create a correlation with many critical vulnerabilities
	vulns := make([]Vulnerability, 0)
	for i := 0; i < 20; i++ {
		vulns = append(vulns, Vulnerability{Severity: "critical"})
	}

	correlation := &CorrelationResult{
		Vulnerabilities: vulns,
	}

	score := correlator.calculateRiskScore(correlation)
	if score > 1000 {
		t.Errorf("Risk score should be capped at 1000, got %d", score)
	}
}

func TestGenerateRecommendations(t *testing.T) {
	correlator := NewCorrelator("")

	t.Run("critical vulnerabilities", func(t *testing.T) {
		correlation := &CorrelationResult{
			Vulnerabilities: []Vulnerability{
				{Severity: "critical"},
				{Severity: "critical"},
			},
			RiskScore: 300,
		}

		recs := correlator.generateRecommendations(correlation)
		found := false
		for _, rec := range recs {
			if contains(rec, "critical") {
				found = true
				break
			}
		}
		if !found {
			t.Error("Should recommend addressing critical vulnerabilities")
		}
	})

	t.Run("telnet service", func(t *testing.T) {
		correlation := &CorrelationResult{
			Services: []Service{
				{Name: "telnet", Port: 23},
			},
			RiskScore: 100,
		}

		recs := correlator.generateRecommendations(correlation)
		found := false
		for _, rec := range recs {
			if contains(rec, "Telnet") || contains(rec, "SSH") {
				found = true
				break
			}
		}
		if !found {
			t.Error("Should recommend replacing Telnet with SSH")
		}
	})

	t.Run("high risk score", func(t *testing.T) {
		correlation := &CorrelationResult{
			RiskScore: 600,
		}

		recs := correlator.generateRecommendations(correlation)
		found := false
		for _, rec := range recs {
			if contains(rec, "High risk") {
				found = true
				break
			}
		}
		if !found {
			t.Error("Should recommend security review for high risk score")
		}
	})
}

func TestGetCorrelationForHost(t *testing.T) {
	correlator := NewCorrelator("")

	// Add a correlation
	correlator.correlations["192.168.1.1"] = &CorrelationResult{
		Host:      "192.168.1.1",
		RiskScore: 100,
	}

	// Test existing host
	corr, exists := correlator.GetCorrelationForHost("192.168.1.1")
	if !exists {
		t.Error("Should find existing correlation")
	}
	if corr.Host != "192.168.1.1" {
		t.Errorf("Host = %s, want 192.168.1.1", corr.Host)
	}

	// Test non-existent host
	_, exists = correlator.GetCorrelationForHost("192.168.1.2")
	if exists {
		t.Error("Should not find non-existent correlation")
	}
}

func TestGetAllCorrelations(t *testing.T) {
	correlator := NewCorrelator("")

	correlator.correlations["192.168.1.1"] = &CorrelationResult{Host: "192.168.1.1"}
	correlator.correlations["192.168.1.2"] = &CorrelationResult{Host: "192.168.1.2"}

	all := correlator.GetAllCorrelations()

	if len(all) != 2 {
		t.Errorf("len(all) = %d, want 2", len(all))
	}

	// Verify it's a copy (modifying returned map shouldn't affect original)
	all["192.168.1.3"] = &CorrelationResult{Host: "192.168.1.3"}
	if len(correlator.correlations) != 2 {
		t.Error("Modifying returned map should not affect original")
	}
}

func TestGetHighRiskHosts(t *testing.T) {
	correlator := NewCorrelator("")

	correlator.correlations["192.168.1.1"] = &CorrelationResult{
		Host:      "192.168.1.1",
		RiskScore: 100,
	}
	correlator.correlations["192.168.1.2"] = &CorrelationResult{
		Host:      "192.168.1.2",
		RiskScore: 500,
	}
	correlator.correlations["192.168.1.3"] = &CorrelationResult{
		Host:      "192.168.1.3",
		RiskScore: 300,
	}

	highRisk := correlator.GetHighRiskHosts(250)

	if len(highRisk) != 2 {
		t.Errorf("len(highRisk) = %d, want 2", len(highRisk))
	}

	// Verify correct hosts are returned
	for _, host := range highRisk {
		if host.RiskScore < 250 {
			t.Errorf("Host %s has risk score %d, should be >= 250", host.Host, host.RiskScore)
		}
	}
}

func TestSaveAndLoadResults(t *testing.T) {
	tempDir := t.TempDir()
	correlator := NewCorrelator(tempDir)

	// Add some correlations
	correlator.correlations["192.168.1.1"] = &CorrelationResult{
		Host:      "192.168.1.1",
		RiskScore: 100,
		Services:  []Service{{Name: "http"}},
	}

	// Save
	if err := correlator.saveResults(); err != nil {
		t.Fatalf("saveResults() error = %v", err)
	}

	// Verify file was created
	correlationFile := filepath.Join(tempDir, "correlations", "correlations.json")
	if _, err := os.Stat(correlationFile); os.IsNotExist(err) {
		t.Error("Correlation file was not created")
	}

	// Create new correlator and load
	correlator2 := NewCorrelator(tempDir)
	if err := correlator2.LoadResults(); err != nil {
		t.Fatalf("LoadResults() error = %v", err)
	}

	// Verify loaded data
	if len(correlator2.correlations) != 1 {
		t.Errorf("len(correlations) = %d, want 1", len(correlator2.correlations))
	}

	corr, exists := correlator2.correlations["192.168.1.1"]
	if !exists {
		t.Error("Loaded correlation not found")
	}
	if corr.RiskScore != 100 {
		t.Errorf("RiskScore = %d, want 100", corr.RiskScore)
	}
}

func TestLoadResultsNoFile(t *testing.T) {
	tempDir := t.TempDir()
	correlator := NewCorrelator(tempDir)

	// Should not error when file doesn't exist
	if err := correlator.LoadResults(); err != nil {
		t.Errorf("LoadResults() should not error when file doesn't exist: %v", err)
	}
}

func TestSaveResultsNoWorkspace(t *testing.T) {
	correlator := NewCorrelator("")

	// Should not error when workspace is empty
	if err := correlator.saveResults(); err != nil {
		t.Errorf("saveResults() should not error when workspace is empty: %v", err)
	}
}

func TestAddScanResultAndCorrelate(t *testing.T) {
	tempDir := t.TempDir()
	correlator := NewCorrelator(tempDir)

	result := &ScanResult{
		ID:        "scan1",
		Type:      ScanTypePortScan,
		Timestamp: time.Now(),
		Source:    "test",
		Hosts: []Host{
			{
				IP:       "192.168.1.1",
				Status:   "up",
				LastSeen: time.Now(),
				Ports: []Port{
					{Number: 80, Protocol: "tcp", State: "open", Service: "http"},
				},
			},
		},
		Services: []Service{
			{Host: "192.168.1.1", Port: 80, Name: "http"},
		},
	}

	if err := correlator.AddScanResult(result); err != nil {
		t.Fatalf("AddScanResult() error = %v", err)
	}

	// Verify correlation was created
	corr, exists := correlator.GetCorrelationForHost("192.168.1.1")
	if !exists {
		t.Fatal("Correlation should be created for host")
	}

	if len(corr.Services) != 1 {
		t.Errorf("len(Services) = %d, want 1", len(corr.Services))
	}
	if len(corr.Timeline) != 1 {
		t.Errorf("len(Timeline) = %d, want 1", len(corr.Timeline))
	}
}

func TestSortTimeline(t *testing.T) {
	correlator := NewCorrelator("")

	now := time.Now()
	timeline := []TimelineEvent{
		{Timestamp: now.Add(2 * time.Hour), Event: "third"},
		{Timestamp: now, Event: "first"},
		{Timestamp: now.Add(1 * time.Hour), Event: "second"},
	}

	correlator.sortTimeline(timeline)

	if timeline[0].Event != "first" {
		t.Error("Timeline should be sorted in chronological order")
	}
	if timeline[1].Event != "second" {
		t.Error("Timeline should be sorted in chronological order")
	}
	if timeline[2].Event != "third" {
		t.Error("Timeline should be sorted in chronological order")
	}
}

func TestResultContainsHostCIDR(t *testing.T) {
	correlator := NewCorrelator("")

	result := &ScanResult{
		Targets: []string{"192.168.1.0/24"},
	}

	tests := []struct {
		ip       string
		expected bool
	}{
		{"192.168.1.1", true},
		{"192.168.1.100", true},
		{"192.168.1.254", true},
		{"192.168.2.1", false},
		{"10.0.0.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			result := correlator.resultContainsHost(result, tt.ip)
			if result != tt.expected {
				t.Errorf("resultContainsHost(%s) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestParseNmapOutput(t *testing.T) {
	tempDir := t.TempDir()
	nmapFile := filepath.Join(tempDir, "scan.nmap")

	nmapOutput := `Starting Nmap 7.80 ( https://nmap.org )
Nmap scan report for 192.168.1.1
Host is up (0.0010s latency).
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https

Nmap scan report for 192.168.1.2
Host is up (0.0020s latency).
PORT     STATE SERVICE
3306/tcp open  mysql

Nmap done: 2 IP addresses (2 hosts up) scanned in 1.23 seconds
`

	if err := os.WriteFile(nmapFile, []byte(nmapOutput), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	result, err := ParseNmapOutput(nmapFile, "test-scan")
	if err != nil {
		t.Fatalf("ParseNmapOutput() error = %v", err)
	}

	if result.ID != "test-scan" {
		t.Errorf("ID = %s, want test-scan", result.ID)
	}
	if result.Type != ScanTypePortScan {
		t.Errorf("Type = %s, want %s", result.Type, ScanTypePortScan)
	}

	if len(result.Hosts) != 2 {
		t.Errorf("len(Hosts) = %d, want 2", len(result.Hosts))
	}

	// Check first host
	if len(result.Hosts) > 0 {
		host := result.Hosts[0]
		if host.IP != "192.168.1.1" {
			t.Errorf("Host IP = %s, want 192.168.1.1", host.IP)
		}
		if len(host.Ports) != 3 {
			t.Errorf("len(Ports) = %d, want 3", len(host.Ports))
		}
	}

	// Check services were extracted
	if len(result.Services) < 3 {
		t.Errorf("len(Services) = %d, want at least 3", len(result.Services))
	}
}

// Helper function
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

func TestParseNmapOutputUDPBeforeHost(t *testing.T) {
	// UDP port line appears before any host header — previously caused nil pointer panic.
	input := `Starting Nmap 7.94
53/udp open  domain
Nmap scan report for 192.168.1.1
Host is up (0.001s latency).
22/tcp open  ssh
Nmap done: 1 IP address (1 host up) scanned`

	tempDir := t.TempDir()
	nmapFile := filepath.Join(tempDir, "scan.nmap")
	if err := os.WriteFile(nmapFile, []byte(input), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	result, err := ParseNmapOutput(nmapFile, "test-udp-before-host")
	if err != nil {
		t.Fatalf("ParseNmapOutput returned unexpected error: %v", err)
	}
	if len(result.Hosts) != 1 {
		t.Errorf("got %d hosts, want 1", len(result.Hosts))
	}
	if len(result.Hosts) > 0 && result.Hosts[0].IP != "192.168.1.1" {
		t.Errorf("got host IP %s, want 192.168.1.1", result.Hosts[0].IP)
	}
}

func TestScanTypeConstants(t *testing.T) {
	// Verify scan type constants are defined
	tests := []ScanType{
		ScanTypeNetworkEnum,
		ScanTypeVulnerability,
		ScanTypeCapture,
		ScanTypePortScan,
		ScanTypeServiceScan,
		ScanTypeOSDetection,
	}

	for _, st := range tests {
		if st == "" {
			t.Error("Scan type constant should not be empty")
		}
	}
}

func TestIPParsing(t *testing.T) {
	// Test that IP parsing works correctly in extractHostsFromResult
	correlator := NewCorrelator("")

	result := &ScanResult{
		Targets: []string{"192.168.1.1"},
	}

	hosts := correlator.extractHostsFromResult(result)

	// Verify IP was parsed correctly
	ip := net.ParseIP("192.168.1.1")
	if ip == nil {
		t.Error("IP parsing should work")
	}

	if len(hosts) != 1 {
		t.Errorf("len(hosts) = %d, want 1", len(hosts))
	}
}
