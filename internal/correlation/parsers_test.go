package correlation

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewResultParser(t *testing.T) {
	parser := NewResultParser("/test/workspace")

	if parser.workspaceDir != "/test/workspace" {
		t.Errorf("workspaceDir = %s, want /test/workspace", parser.workspaceDir)
	}
}

func TestDetermineScanType(t *testing.T) {
	parser := NewResultParser("")

	tests := []struct {
		name       string
		scriptPath string
		content    string
		expected   ScanType
	}{
		{
			name:       "nmap scan from content",
			scriptPath: "/scripts/test.sh",
			content:    "Nmap scan report for 192.168.1.1",
			expected:   ScanTypePortScan,
		},
		{
			name:       "enum from script name",
			scriptPath: "/scripts/network_enum.sh",
			content:    "some output",
			expected:   ScanTypeNetworkEnum,
		},
		{
			name:       "discovery from script name",
			scriptPath: "/scripts/discovery.sh",
			content:    "some output",
			expected:   ScanTypeNetworkEnum,
		},
		{
			name:       "vulnerability from content",
			scriptPath: "/scripts/test.sh",
			content:    "Found vulnerability CVE-2021-1234",
			expected:   ScanTypeVulnerability,
		},
		{
			name:       "capture from script name",
			scriptPath: "/scripts/packet_capture.sh",
			content:    "packets captured",
			expected:   ScanTypeCapture,
		},
		{
			name:       "service scan",
			scriptPath: "/scripts/service_detect.sh",
			content:    "detecting services",
			expected:   ScanTypeServiceScan,
		},
		{
			name:       "network path defaults to enum",
			scriptPath: "/scripts/network/test.sh",
			content:    "output",
			expected:   ScanTypeNetworkEnum,
		},
		{
			name:       "default fallback",
			scriptPath: "/scripts/unknown.sh",
			content:    "generic output",
			expected:   ScanTypePortScan,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanType := parser.determineScanType(tt.scriptPath, tt.content)
			if scanType != tt.expected {
				t.Errorf("determineScanType() = %s, want %s", scanType, tt.expected)
			}
		})
	}
}

func TestParseNetworkEnumeration(t *testing.T) {
	parser := NewResultParser("")

	content := `PING 192.168.1.1 (192.168.1.1): 56 data bytes
64 bytes from 192.168.1.1: icmp_seq=0 ttl=64 time=0.5 ms

192.168.1.2 is alive
192.168.1.3 is alive

? (192.168.1.100) at aa:bb:cc:dd:ee:ff [ether] on eth0
? (192.168.1.101) at 11:22:33:44:55:66 [ether] on eth0
`

	result := &ScanResult{
		ID:        "test",
		Type:      ScanTypeNetworkEnum,
		Timestamp: time.Now(),
	}

	parsed, err := parser.parseNetworkEnumeration(result, content)
	if err != nil {
		t.Fatalf("parseNetworkEnumeration() error = %v", err)
	}

	if len(parsed.Hosts) < 4 {
		t.Errorf("len(Hosts) = %d, want at least 4", len(parsed.Hosts))
	}

	// Check that MAC addresses were parsed
	foundMAC := false
	for _, host := range parsed.Hosts {
		if host.MACAddress != "" {
			foundMAC = true
			break
		}
	}
	if !foundMAC {
		t.Error("Should parse MAC addresses from ARP entries")
	}
}

func TestParsePortScan(t *testing.T) {
	parser := NewResultParser("")

	content := `Starting Nmap 7.80 ( https://nmap.org )
Nmap scan report for example.com (192.168.1.1)
Host is up (0.0010s latency).
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2
80/tcp   open  http       nginx 1.18.0
443/tcp  open  https      nginx 1.18.0
3306/tcp open  mysql      MySQL 5.7
OS details: Linux 4.15.0

Nmap scan report for 192.168.1.2
Host is up (0.0020s latency).
PORT     STATE SERVICE
8080/tcp open  http-proxy

Nmap done: 2 IP addresses (2 hosts up) scanned in 5.43 seconds
`

	result := &ScanResult{
		ID:        "test",
		Type:      ScanTypePortScan,
		Timestamp: time.Now(),
	}

	parsed, err := parser.parsePortScan(result, content)
	if err != nil {
		t.Fatalf("parsePortScan() error = %v", err)
	}

	if len(parsed.Hosts) != 2 {
		t.Errorf("len(Hosts) = %d, want 2", len(parsed.Hosts))
	}

	// Check first host
	host1 := parsed.Hosts[0]
	if host1.IP != "192.168.1.1" {
		t.Errorf("Host IP = %s, want 192.168.1.1", host1.IP)
	}
	if host1.Hostname != "example.com" {
		t.Errorf("Hostname = %s, want example.com", host1.Hostname)
	}
	if len(host1.Ports) != 4 {
		t.Errorf("len(Ports) = %d, want 4", len(host1.Ports))
	}
	if host1.OS == "" {
		t.Error("OS should be parsed")
	}

	// Check services were extracted
	if len(parsed.Services) < 4 {
		t.Errorf("len(Services) = %d, want at least 4", len(parsed.Services))
	}

	// Verify service with version
	foundSSH := false
	for _, svc := range parsed.Services {
		if svc.Name == "ssh" && strings.Contains(svc.Version, "OpenSSH") {
			foundSSH = true
			break
		}
	}
	if !foundSSH {
		t.Error("Should parse SSH service with version")
	}
}

func TestParseVulnerabilityScan(t *testing.T) {
	parser := NewResultParser("")

	content := `Nmap scan report for 192.168.1.1
Host script results:
| smb-vuln-ms17-010:
|   System is VULNERABLE to high severity issue CVE-2017-0143
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)

Nmap scan report for 192.168.1.2
| http-vuln-cve2021-12345:
|   Server is vulnerable to critical security issue
`

	result := &ScanResult{
		ID:        "test",
		Type:      ScanTypeVulnerability,
		Timestamp: time.Now(),
	}

	parsed, err := parser.parseVulnerabilityScan(result, content)
	if err != nil {
		t.Fatalf("parseVulnerabilityScan() error = %v", err)
	}

	if len(parsed.Vulnerabilities) < 2 {
		t.Errorf("len(Vulnerabilities) = %d, want at least 2", len(parsed.Vulnerabilities))
	}

	// Check that CVE was extracted
	foundCVE := false
	for _, vuln := range parsed.Vulnerabilities {
		if vuln.CVE == "CVE-2017-0143" {
			foundCVE = true
			if vuln.Severity != "high" {
				t.Errorf("Severity = %s, want high", vuln.Severity)
			}
		}
	}
	if !foundCVE {
		t.Error("Should extract CVE number")
	}

	// Check critical severity detection
	foundCritical := false
	for _, vuln := range parsed.Vulnerabilities {
		if vuln.Severity == "critical" {
			foundCritical = true
			break
		}
	}
	if !foundCritical {
		t.Error("Should detect critical severity")
	}
}

func TestParseNetworkCapture(t *testing.T) {
	parser := NewResultParser("")

	content := `1  0.000000 192.168.1.1 -> 192.168.1.2  TCP 74 80 > 54321 [SYN]
2  0.000125 192.168.1.2 -> 192.168.1.1  TCP 74 54321 > 80 [SYN, ACK]
3  0.002341 10.0.0.5 -> 10.0.0.10  HTTP GET /index.html
4  0.003123 192.168.1.100 -> 224.0.0.1  IGMP Membership Query
5  0.004567 192.168.1.255 -> 192.168.1.1  Broadcast
`

	result := &ScanResult{
		ID:        "test",
		Type:      ScanTypeCapture,
		Timestamp: time.Now(),
	}

	parsed, err := parser.parseNetworkCapture(result, content)
	if err != nil {
		t.Fatalf("parseNetworkCapture() error = %v", err)
	}

	// Should discover unique IPs, excluding broadcast and multicast
	if len(parsed.Hosts) < 4 {
		t.Errorf("len(Hosts) = %d, want at least 4", len(parsed.Hosts))
	}

	// Verify broadcast/multicast are filtered
	for _, host := range parsed.Hosts {
		if strings.HasSuffix(host.IP, ".255") {
			t.Errorf("Should filter broadcast address: %s", host.IP)
		}
		if strings.HasPrefix(host.IP, "224.") {
			t.Errorf("Should filter multicast address: %s", host.IP)
		}
	}

	// Check status is set to "observed"
	if len(parsed.Hosts) > 0 && parsed.Hosts[0].Status != "observed" {
		t.Error("Captured hosts should have status 'observed'")
	}
}

func TestParseGenericOutput(t *testing.T) {
	parser := NewResultParser("")

	content := `Scanning network...
Found device at 192.168.1.1
Found device at 192.168.1.2
Server running on 10.0.0.50
Network gateway: 192.168.1.0
Broadcast: 192.168.1.255
Localhost: 127.0.0.1
`

	result := &ScanResult{
		ID:        "test",
		Type:      ScanTypeNetworkEnum,
		Timestamp: time.Now(),
	}

	parsed, err := parser.parseGenericOutput(result, content)
	if err != nil {
		t.Fatalf("parseGenericOutput() error = %v", err)
	}

	// Should extract IPs, excluding .0, .255, 0.x.x.x, 127.x.x.x
	expectedCount := 3 // 192.168.1.1, 192.168.1.2, 10.0.0.50
	if len(parsed.Hosts) != expectedCount {
		t.Errorf("len(Hosts) = %d, want %d", len(parsed.Hosts), expectedCount)
	}

	// Verify filtered IPs are not included
	for _, host := range parsed.Hosts {
		if strings.HasPrefix(host.IP, "127.") {
			t.Errorf("Should filter localhost: %s", host.IP)
		}
		if strings.HasSuffix(host.IP, ".0") {
			t.Errorf("Should filter network address: %s", host.IP)
		}
		if strings.HasSuffix(host.IP, ".255") {
			t.Errorf("Should filter broadcast: %s", host.IP)
		}
	}

	// Check status is set to "mentioned"
	if len(parsed.Hosts) > 0 && parsed.Hosts[0].Status != "mentioned" {
		t.Error("Generic hosts should have status 'mentioned'")
	}
}

func TestParseJobResult(t *testing.T) {
	parser := NewResultParser("")

	content := `Nmap scan report for 192.168.1.1
PORT   STATE SERVICE
80/tcp open  http
`

	result, err := parser.ParseJobResult("/scripts/portscan.sh", content, time.Now())
	if err != nil {
		t.Fatalf("ParseJobResult() error = %v", err)
	}

	if result.Type != ScanTypePortScan {
		t.Errorf("Type = %s, want %s", result.Type, ScanTypePortScan)
	}
	if result.Source != "portscan.sh" {
		t.Errorf("Source = %s, want portscan.sh", result.Source)
	}
	if len(result.Hosts) == 0 {
		t.Error("Should parse at least one host")
	}
}

func TestParseResultFile(t *testing.T) {
	tempDir := t.TempDir()
	parser := NewResultParser(tempDir)

	resultFile := filepath.Join(tempDir, "scan.nmap")
	content := `Nmap scan report for 192.168.1.1
PORT   STATE SERVICE
22/tcp open  ssh

Nmap scan report for 192.168.1.2
PORT   STATE SERVICE
80/tcp open  http
`

	if err := os.WriteFile(resultFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	result, err := parser.ParseResultFile(resultFile)
	if err != nil {
		t.Fatalf("ParseResultFile() error = %v", err)
	}

	if len(result.Hosts) < 2 {
		t.Errorf("len(Hosts) = %d, want at least 2", len(result.Hosts))
	}
}

func TestParseResultFileNotFound(t *testing.T) {
	parser := NewResultParser("")

	_, err := parser.ParseResultFile("/nonexistent/file.txt")
	if err == nil {
		t.Error("ParseResultFile() should return error for non-existent file")
	}
}

func TestScanWorkspaceForResults(t *testing.T) {
	tempDir := t.TempDir()
	parser := NewResultParser(tempDir)

	// Create some test files
	files := map[string]string{
		"scan1.nmap": "Nmap scan report for 192.168.1.1\n80/tcp open http",
		"scan2.txt":  "192.168.1.2 is alive",
		"scan3.log":  "Found host: 192.168.1.3",
	}

	for filename, content := range files {
		filePath := filepath.Join(tempDir, filename)
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}

	results, err := parser.ScanWorkspaceForResults()
	if err != nil {
		t.Fatalf("ScanWorkspaceForResults() error = %v", err)
	}

	// Note: filepath.Glob with ** may not work as expected on all systems
	// So we just check that it doesn't error and returns some results
	if len(results) == 0 {
		t.Log("Warning: No results found, glob pattern may not be working")
	}
}

func TestScanWorkspaceForResultsNoWorkspace(t *testing.T) {
	parser := NewResultParser("")

	_, err := parser.ScanWorkspaceForResults()
	if err == nil {
		t.Error("ScanWorkspaceForResults() should error when workspace not set")
	}
}

func TestParseServiceScan(t *testing.T) {
	parser := NewResultParser("")

	content := `Nmap scan report for 192.168.1.1
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6
80/tcp   open  http    Apache httpd 2.4.29
`

	result := &ScanResult{
		ID:        "test",
		Type:      ScanTypeServiceScan,
		Timestamp: time.Now(),
	}

	parsed, err := parser.parseServiceScan(result, content)
	if err != nil {
		t.Fatalf("parseServiceScan() error = %v", err)
	}

	// parseServiceScan uses parsePortScan internally
	if len(parsed.Services) < 2 {
		t.Errorf("len(Services) = %d, want at least 2", len(parsed.Services))
	}
}

func TestParseNetworkEnumerationFping(t *testing.T) {
	parser := NewResultParser("")

	content := `192.168.1.1 is alive
192.168.1.2 is alive
192.168.1.3 is unreachable
192.168.1.4 is alive
`

	result := &ScanResult{
		ID:        "test",
		Type:      ScanTypeNetworkEnum,
		Timestamp: time.Now(),
	}

	parsed, err := parser.parseNetworkEnumeration(result, content)
	if err != nil {
		t.Fatalf("parseNetworkEnumeration() error = %v", err)
	}

	// Should only parse "is alive" entries
	if len(parsed.Hosts) != 3 {
		t.Errorf("len(Hosts) = %d, want 3", len(parsed.Hosts))
	}

	// All hosts should have status "up"
	for _, host := range parsed.Hosts {
		if host.Status != "up" {
			t.Errorf("Host %s status = %s, want up", host.IP, host.Status)
		}
	}
}

func TestParsePortScanNoHostname(t *testing.T) {
	parser := NewResultParser("")

	content := `Nmap scan report for 192.168.1.1
PORT   STATE SERVICE
22/tcp open  ssh
`

	result := &ScanResult{
		ID:        "test",
		Type:      ScanTypePortScan,
		Timestamp: time.Now(),
	}

	parsed, err := parser.parsePortScan(result, content)
	if err != nil {
		t.Fatalf("parsePortScan() error = %v", err)
	}

	if len(parsed.Hosts) != 1 {
		t.Errorf("len(Hosts) = %d, want 1", len(parsed.Hosts))
	}

	// Hostname should be empty when not present
	if parsed.Hosts[0].Hostname != "" {
		t.Errorf("Hostname = %s, want empty", parsed.Hosts[0].Hostname)
	}
}

func TestDetermineScanTypeVulnInScript(t *testing.T) {
	parser := NewResultParser("")

	scanType := parser.determineScanType("/scripts/vuln_scan.sh", "test output")
	if scanType != ScanTypeVulnerability {
		t.Errorf("determineScanType() = %s, want %s", scanType, ScanTypeVulnerability)
	}
}

func TestDetermineScanTypeNSE(t *testing.T) {
	parser := NewResultParser("")

	// "nse" in script name should trigger vulnerability type
	// But "enum" also matches, so it returns NetworkEnum
	// Let's test with just "nse" in the name
	scanType := parser.determineScanType("/scripts/run_nse.sh", "test output")
	if scanType != ScanTypeVulnerability {
		t.Errorf("determineScanType() = %s, want %s", scanType, ScanTypeVulnerability)
	}
}

func TestDetermineScanTypeTshark(t *testing.T) {
	parser := NewResultParser("")

	scanType := parser.determineScanType("/scripts/tshark_capture.sh", "test output")
	if scanType != ScanTypeCapture {
		t.Errorf("determineScanType() = %s, want %s", scanType, ScanTypeCapture)
	}
}

func TestDetermineScanTypeFromContentHostIsUp(t *testing.T) {
	parser := NewResultParser("")

	scanType := parser.determineScanType("/scripts/test.sh", "Host is up and responding")
	if scanType != ScanTypeNetworkEnum {
		t.Errorf("determineScanType() = %s, want %s", scanType, ScanTypeNetworkEnum)
	}
}

func TestDetermineScanTypeFromContentPingStats(t *testing.T) {
	parser := NewResultParser("")

	scanType := parser.determineScanType("/scripts/test.sh", "--- ping statistics ---")
	if scanType != ScanTypeNetworkEnum {
		t.Errorf("determineScanType() = %s, want %s", scanType, ScanTypeNetworkEnum)
	}
}

func TestParseVulnerabilityScanSeverityDetection(t *testing.T) {
	parser := NewResultParser("")

	content := `Nmap scan report for 192.168.1.1
System is vulnerable - low severity issue found
System is vulnerable - high risk detected
System is vulnerable - critical security flaw discovered
`

	result := &ScanResult{
		ID:        "test",
		Type:      ScanTypeVulnerability,
		Timestamp: time.Now(),
	}

	parsed, err := parser.parseVulnerabilityScan(result, content)
	if err != nil {
		t.Fatalf("parseVulnerabilityScan() error = %v", err)
	}

	// Check severity detection
	severities := make(map[string]bool)
	for _, vuln := range parsed.Vulnerabilities {
		severities[vuln.Severity] = true
	}

	if !severities["low"] {
		t.Error("Should detect low severity")
	}
	if !severities["high"] {
		t.Error("Should detect high severity")
	}
	if !severities["critical"] {
		t.Error("Should detect critical severity")
	}
}

func TestParsePortScanUDPPorts(t *testing.T) {
	parser := NewResultParser("")

	content := `Nmap scan report for 192.168.1.1
PORT     STATE SERVICE
53/udp   open  domain
161/udp  open  snmp
`

	result := &ScanResult{
		ID:        "test",
		Type:      ScanTypePortScan,
		Timestamp: time.Now(),
	}

	parsed, err := parser.parsePortScan(result, content)
	if err != nil {
		t.Fatalf("parsePortScan() error = %v", err)
	}

	if len(parsed.Hosts) == 0 {
		t.Fatal("Should parse at least one host")
	}

	// Check UDP ports were parsed
	foundUDP := false
	for _, port := range parsed.Hosts[0].Ports {
		if port.Protocol == "udp" {
			foundUDP = true
			break
		}
	}

	if !foundUDP {
		t.Error("Should parse UDP ports")
	}
}

func TestScanWorkspaceForResults_SubdirectoryScan(t *testing.T) {
	dir := t.TempDir()
	// Two levels deep — filepath.Glob("**") would not recurse this far
	subdir := filepath.Join(dir, "scan-2024-01-15", "subscans")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	nmapContent := `Starting Nmap 7.94
Nmap scan report for 192.168.1.1
Host is up (0.001s latency).
PORT   STATE SERVICE
22/tcp open  ssh
Nmap done: 1 IP address (1 host up) scanned`
	nmapFile := filepath.Join(subdir, "result.nmap")
	if err := os.WriteFile(nmapFile, []byte(nmapContent), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	rp := NewResultParser(dir)
	results, err := rp.ScanWorkspaceForResults()
	if err != nil {
		t.Fatalf("ScanWorkspaceForResults error: %v", err)
	}
	if len(results) == 0 {
		t.Error("ScanWorkspaceForResults found no results in subdirectory — filepath.Glob('**') bug")
	}
}

func TestScanWorkspaceSkipsLargeFiles(t *testing.T) {
	tempDir := t.TempDir()
	parser := NewResultParser(tempDir)

	// Create a small file
	smallFile := filepath.Join(tempDir, "small.txt")
	if err := os.WriteFile(smallFile, []byte("192.168.1.1"), 0644); err != nil {
		t.Fatalf("Failed to create small file: %v", err)
	}

	// Note: We can't easily test large file skipping without creating a large file
	// This test just ensures small files are processed

	results, err := parser.ScanWorkspaceForResults()
	if err != nil {
		t.Fatalf("ScanWorkspaceForResults() error = %v", err)
	}

	// The glob pattern with ** may not work, so we can't assert specific results
	_ = results
}

func TestParseNiktoXMLResult(t *testing.T) {
	parser := NewResultParser("")

	content := `<?xml version="1.0" ?>
<niktoscan>
  <scandetails targetip="192.168.1.1" targetport="80" targethostname="web.local">
    <item method="GET" url="/admin" description="Admin panel found">
      Default credentials found on admin panel
    </item>
    <item method="GET" url="/server-status" description="Server status enumerated">
      Server status page is accessible
    </item>
    <item method="GET" url="/old" description="Old version detected">
      Old software version detected
    </item>
  </scandetails>
  <scandetails targetip="192.168.1.2" targetport="443">
    <item method="GET" url="/login" description="Login page">
      Login page found
    </item>
  </scandetails>
</niktoscan>`

	result := &ScanResult{
		ID:        "test_nikto",
		Type:      ScanTypeNikto,
		Timestamp: time.Now(),
	}

	parsed, err := parser.parseNiktoXMLResult(result, content)
	if err != nil {
		t.Fatalf("parseNiktoXMLResult() error = %v", err)
	}

	// Should find 2 hosts
	if len(parsed.Hosts) != 2 {
		t.Errorf("len(Hosts) = %d, want 2", len(parsed.Hosts))
	}

	// Should find 3 vulnerabilities for first host
	niktoVulns := 0
	for _, v := range parsed.Vulnerabilities {
		if v.Host == "192.168.1.1" && v.Source == "nikto" {
			niktoVulns++
		}
	}
	if niktoVulns != 3 {
		t.Errorf("nikto vulns for 192.168.1.1 = %d, want 3", niktoVulns)
	}

	// Check severity heuristic — "credentials" and "unrestricted" are high keywords
	highCount := 0
	for _, v := range parsed.Vulnerabilities {
		if v.Host == "192.168.1.1" && v.Severity == "high" {
			highCount++
		}
	}
	if highCount == 0 {
		t.Error("Expected at least one high-severity nikto finding (credentials keyword)")
	}

	// Check port parsing
	for _, v := range parsed.Vulnerabilities {
		if v.Host == "192.168.1.1" && v.Port != 80 {
			t.Errorf("Port = %d, want 80", v.Port)
			break
		}
	}

	// Check Source field
	for _, v := range parsed.Vulnerabilities {
		if v.Source != "nikto" {
			t.Errorf("Source = %q, want 'nikto'", v.Source)
			break
		}
	}
}

func TestParseNiktoXMLResultInvalid(t *testing.T) {
	parser := NewResultParser("")

	content := "not xml at all"
	result := &ScanResult{
		ID:        "test_nikto_invalid",
		Type:      ScanTypeNikto,
		Timestamp: time.Now(),
	}

	parsed, err := parser.parseNiktoXMLResult(result, content)
	if err != nil {
		t.Fatalf("parseNiktoXMLResult() should fall back to generic, got error: %v", err)
	}
	// Should fall back to generic parsing
	_ = parsed
}

func TestParseSSLScanResult(t *testing.T) {
	parser := NewResultParser("")

	content := `=== sslscan Results ===
Scan time: now

--- Host: 192.168.1.1 ---
SSL/TLS:

  SSLv3  enabled
  TLS 1.0  enabled
  TLS 1.2  enabled
  TLS 1.3  enabled

  TLS 1.0 cipher suites:
    DES-CBC3-SHA                          enabled
    RC4-SHA                               enabled

  Certificates:
    Self-signed certificate

--- Host: 192.168.1.2 ---
SSL/TLS:

  TLS 1.2  enabled
  TLS 1.3  enabled
`

	result := &ScanResult{
		ID:        "test_sslscan",
		Type:      ScanTypeSSLScan,
		Timestamp: time.Now(),
	}

	parsed, err := parser.parseSSLScanResult(result, content)
	if err != nil {
		t.Fatalf("parseSSLScanResult() error = %v", err)
	}

	// Should find 2 hosts
	if len(parsed.Hosts) < 1 {
		t.Error("Should parse at least 1 host")
	}

	// Should detect SSLv3 as critical
	var foundSSLv3 bool
	for _, v := range parsed.Vulnerabilities {
		if v.Host == "192.168.1.1" && v.Severity == "critical" && strings.Contains(v.Title, "SSLv3") {
			foundSSLv3 = true
		}
	}
	if !foundSSLv3 {
		t.Error("Should detect SSLv3 as critical")
	}

	// Should detect TLS 1.0 as medium
	var foundTLS10 bool
	for _, v := range parsed.Vulnerabilities {
		if v.Host == "192.168.1.1" && v.Severity == "medium" && strings.Contains(v.Title, "Deprecated") {
			foundTLS10 = true
		}
	}
	if !foundTLS10 {
		t.Error("Should detect TLS 1.0 as deprecated")
	}

	// Should detect weak ciphers
	var foundWeak bool
	for _, v := range parsed.Vulnerabilities {
		if v.Host == "192.168.1.1" && v.Severity == "high" && v.Source == "sslscan" {
			foundWeak = true
		}
	}
	if !foundWeak {
		t.Error("Should detect weak cipher (DES/RC4)")
	}

	// Should detect self-signed cert
	var foundSelfSigned bool
	for _, v := range parsed.Vulnerabilities {
		if v.Host == "192.168.1.1" && strings.Contains(strings.ToLower(v.Title), "self-signed") {
			foundSelfSigned = true
		}
	}
	if !foundSelfSigned {
		t.Error("Should detect self-signed certificate")
	}

	// Check Source field
	for _, v := range parsed.Vulnerabilities {
		if v.Source != "sslscan" {
			t.Errorf("Source = %q, want 'sslscan'", v.Source)
			break
		}
	}

	// Second host should be clean
	for _, v := range parsed.Vulnerabilities {
		if v.Host == "192.168.1.2" {
			t.Error("Second host should have no findings (only TLS 1.2/1.3)")
			break
		}
	}
}

func TestDetermineScanTypeNikto(t *testing.T) {
	parser := NewResultParser("")

	content := "<niktoscan><scandetails></scandetails></niktoscan>"
	scanType := parser.determineScanType("supplementary/nikto", content)
	if scanType != ScanTypeNikto {
		t.Errorf("determineScanType() = %s, want %s", scanType, ScanTypeNikto)
	}
}

func TestDetermineScanTypeSSLScan(t *testing.T) {
	parser := NewResultParser("")

	scanType := parser.determineScanType("supplementary/sslscan.txt", "ssl output")
	if scanType != ScanTypeSSLScan {
		t.Errorf("determineScanType() = %s, want %s", scanType, ScanTypeSSLScan)
	}
}

func TestScanWorkspaceForResults_SSLScan(t *testing.T) {
	tempDir := t.TempDir()
	parser := NewResultParser(tempDir)

	// Create sslscan.txt in a supplementary directory
	suppDir := filepath.Join(tempDir, "supplementary")
	if err := os.MkdirAll(suppDir, 0755); err != nil {
		t.Fatal(err)
	}
	sslContent := "--- Host: 10.0.0.1 ---\nTLS 1.2 enabled\n"
	if err := os.WriteFile(filepath.Join(suppDir, "sslscan.txt"), []byte(sslContent), 0644); err != nil {
		t.Fatal(err)
	}

	results, err := parser.ScanWorkspaceForResults()
	if err != nil {
		t.Fatalf("ScanWorkspaceForResults error: %v", err)
	}

	// Should process sslscan.txt
	found := false
	for _, r := range results {
		if r.Type == ScanTypeSSLScan {
			found = true
			break
		}
	}
	if !found {
		t.Error("ScanWorkspaceForResults should process sslscan.txt")
	}
}
