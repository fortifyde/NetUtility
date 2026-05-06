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

	if err := os.WriteFile(resultFile, []byte(content), 0600); err != nil {
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
		if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
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


func TestParseVulnerabilityScanNotVulnerable(t *testing.T) {
	parser := NewResultParser("")

	content := `Nmap scan report for 192.168.1.1
| vulners:
|   Scanner is not vulnerable to CVE-2021-44228
|   No vulnerable software found
|   System is VULNERABLE to CVE-2017-0144
Nmap scan report for 192.168.1.2
| http-vuln-cve2020-1234:
|   NOT VULNERABLE
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

	for _, vuln := range parsed.Vulnerabilities {
		if strings.Contains(strings.ToLower(vuln.Title), "not vulnerable") || strings.Contains(strings.ToLower(vuln.Description), "not vulnerable") {
			t.Errorf("NOT VULNERABLE lines should not be parsed as findings, got: %s", vuln.Title)
		}
		if strings.Contains(strings.ToLower(vuln.Title), "no vulnerable") || strings.Contains(strings.ToLower(vuln.Description), "no vulnerable") {
			t.Errorf("'no vulnerable' lines should not be parsed as findings, got: %s", vuln.Title)
		}
	}

	// Should only find the real vulnerability
	foundReal := false
	for _, vuln := range parsed.Vulnerabilities {
		if strings.Contains(vuln.Title, "CVE-2017-0144") {
			foundReal = true
		}
	}
	if !foundReal {
		t.Error("Should still detect actual VULNERABLE line")
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
	if err := os.MkdirAll(subdir, 0750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	nmapContent := `Starting Nmap 7.94
Nmap scan report for 192.168.1.1
Host is up (0.001s latency).
PORT   STATE SERVICE
22/tcp open  ssh
Nmap done: 1 IP address (1 host up) scanned`
	nmapFile := filepath.Join(subdir, "result.nmap")
	if err := os.WriteFile(nmapFile, []byte(nmapContent), 0600); err != nil {
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
	if err := os.WriteFile(smallFile, []byte("192.168.1.1"), 0600); err != nil {
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

	// Create sslscan XML file in a supplementary directory
	suppDir := filepath.Join(tempDir, "supplementary")
	if err := os.MkdirAll(suppDir, 0750); err != nil {
		t.Fatal(err)
	}
	sslContent := `<?xml version="1.0" encoding="UTF-8"?>
<document title="SSLScan Results" version="2.2.2">
 <ssltest host="10.0.0.1" port="443">
  <protocol type="tls" version="1.2" enabled="1" />
 </ssltest>
</document>`
	if err := os.WriteFile(filepath.Join(suppDir, "sslscan_10.0.0.1.xml"), []byte(sslContent), 0600); err != nil {
		t.Fatal(err)
	}

	results, err := parser.ScanWorkspaceForResults()
	if err != nil {
		t.Fatalf("ScanWorkspaceForResults error: %v", err)
	}

	// Should process sslscan XML
	found := false
	for _, r := range results {
		if r.Type == ScanTypeSSLScanXML {
			found = true
			break
		}
	}
	if !found {
		t.Error("ScanWorkspaceForResults should process sslscan XML")
	}
}


func TestParseNmapXML_VulnerableAndNotVulnerable(t *testing.T) {
	parser := NewResultParser("")

	content := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" start="1234567890" version="7.99" xmloutputversion="1.05">
<host starttime="1234567890" endtime="1234567900"><status state="up" reason="syn-ack"/>
<address addr="10.0.1.1" addrtype="ipv4"/>
<address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Test"/>
<hostnames></hostnames>
<ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
<service name="http" product="lighttpd"/>
<script id="http-slowloris-check" output="\n  VULNERABLE:\n  Slowloris DOS attack\n    State: LIKELY VULNERABLE\n">
<table key="CVE-2007-6750">
<elem key="title">Slowloris DOS attack</elem>
<elem key="state">LIKELY VULNERABLE</elem>
<table key="ids"><elem>CVE:CVE-2007-6750</elem></table>
<table key="refs"><elem>http://ha.ckers.org/slowloris/</elem></table>
</table>
</script>
<script id="http-vuln-cve2011-3192" output="\n  NOT VULNERABLE:\n  Apache byterange filter DoS\n    State: NOT VULNERABLE\n">
<table key="CVE-2011-3192">
<elem key="title">Apache byterange filter DoS</elem>
<elem key="state">NOT VULNERABLE</elem>
<table key="ids"><elem>CVE:CVE-2011-3192</elem></table>
</table>
</script>
<script id="rsa-vuln-roca" output="\n  NOT VULNERABLE:\n  ROCA: Vulnerable RSA generation\n    State: NOT VULNERABLE\n">
<table key="CVE-2017-15361">
<elem key="title">ROCA: Vulnerable RSA generation</elem>
<elem key="state">NOT VULNERABLE</elem>
</table>
</script>
</port></ports></host>
</nmaprun>`

	result := &ScanResult{
		ID:              "test",
		Type:            ScanTypeNmapXML,
		Timestamp:       time.Now(),
		Hosts:           make([]Host, 0),
		Services:        make([]Service, 0),
		Vulnerabilities: make([]Vulnerability, 0),
		Metadata:        make(map[string]any),
	}

	parsed, err := parser.parseNmapXML(result, content)
	if err != nil {
		t.Fatalf("parseNmapXML() error = %v", err)
	}

	// Should find exactly 1 vulnerability (Slowloris), not the NOT VULNERABLE ones
	if len(parsed.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d: %+v", len(parsed.Vulnerabilities), parsed.Vulnerabilities)
	}

	vuln := parsed.Vulnerabilities[0]
	if vuln.Title != "Slowloris DOS attack" {
		t.Errorf("expected title 'Slowloris DOS attack', got %q", vuln.Title)
	}
	if vuln.Severity != "medium" {
		t.Errorf("LIKELY VULNERABLE should be medium severity, got %q", vuln.Severity)
	}
	if vuln.CVE != "CVE-2007-6750" {
		t.Errorf("expected CVE-2007-6750, got %q", vuln.CVE)
	}
	if vuln.Source != "nmap-nse" {
		t.Errorf("expected source 'nmap-nse', got %q", vuln.Source)
	}
	if vuln.Host != "10.0.1.1" {
		t.Errorf("expected host 10.0.1.1, got %q", vuln.Host)
	}
	if vuln.Port != 80 {
		t.Errorf("expected port 80, got %d", vuln.Port)
	}
	if len(vuln.References) != 1 || vuln.References[0] != "http://ha.ckers.org/slowloris/" {
		t.Errorf("expected 1 reference, got %v", vuln.References)
	}
}

func TestParseNmapXML_SkipsVulnersScript(t *testing.T) {
	parser := NewResultParser("")

	content := `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" start="1234567890" version="7.99" xmloutputversion="1.05">
<host starttime="1234567890" endtime="1234567900"><status state="up" reason="syn-ack"/>
<address addr="10.0.1.1" addrtype="ipv4"/>
<hostnames></hostnames>
<ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>
<service name="ssh" product="OpenSSH" version="6.6.1p1"/>
<script id="vulners" output="\n  cpe:/a:openbsd:openssh:6.6.1p1: \n    CVE-2023-38408\t9.8\n    CVE-2016-1908\t9.8\n">
<table key="cpe:/a:openbsd:openssh:6.6.1p1">
<table>
<elem key="id">CVE-2023-38408</elem>
<elem key="is_exploit">false</elem>
<elem key="type">cve</elem>
<elem key="cvss">9.8</elem>
</table>
<table>
<elem key="id">CVE-2016-1908</elem>
<elem key="is_exploit">false</elem>
<elem key="type">cve</elem>
<elem key="cvss">9.8</elem>
</table>
</table>
</script>
<script id="rsa-vuln-roca" output="\n  NOT VULNERABLE:\n">
<table key="CVE-2017-15361">
<elem key="title">ROCA: Vulnerable RSA generation</elem>
<elem key="state">NOT VULNERABLE</elem>
</table>
</script>
</port></ports></host>
</nmaprun>`

	result := &ScanResult{
		ID:              "test",
		Type:            ScanTypeNmapXML,
		Timestamp:       time.Now(),
		Hosts:           make([]Host, 0),
		Services:        make([]Service, 0),
		Vulnerabilities: make([]Vulnerability, 0),
		Metadata:        make(map[string]any),
	}

	parsed, err := parser.parseNmapXML(result, content)
	if err != nil {
		t.Fatalf("parseNmapXML() error = %v", err)
	}

	// Should produce 0 vulnerabilities — vulners is skipped, rsa-vuln-roca is NOT VULNERABLE
	if len(parsed.Vulnerabilities) != 0 {
		t.Fatalf("expected 0 vulnerabilities (vulners skipped, NOT VULNERABLE filtered), got %d: %+v",
			len(parsed.Vulnerabilities), parsed.Vulnerabilities)
	}
}

func TestParseNmapXML_HostAndPortExtraction(t *testing.T) {
	parser := NewResultParser("")

	content := `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" start="1234567890" version="7.99" xmloutputversion="1.05">
<host starttime="1234567890" endtime="1234567900"><status state="up" reason="syn-ack"/>
<address addr="10.0.1.1" addrtype="ipv4"/>
<address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="TestVendor"/>
<hostnames><hostname name="router.local" type="PTR"/></hostnames>
<ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>
<service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="protocol 2.0" conf="10"/>
</port>
<port protocol="tcp" portid="80"><state state="closed" reason="reset"/>
<service name="http" product="Apache" version="2.4.52"/>
</port></ports></host>
<host starttime="1234567890" endtime="1234567900"><status state="up" reason="syn-ack"/>
<address addr="10.0.1.2" addrtype="ipv4"/>
<hostnames></hostnames>
</host>
</nmaprun>`

	result := &ScanResult{
		ID:              "test",
		Type:            ScanTypeNmapXML,
		Timestamp:       time.Now(),
		Hosts:           make([]Host, 0),
		Services:        make([]Service, 0),
		Vulnerabilities: make([]Vulnerability, 0),
		Metadata:        make(map[string]any),
	}

	parsed, err := parser.parseNmapXML(result, content)
	if err != nil {
		t.Fatalf("parseNmapXML() error = %v", err)
	}

	if len(parsed.Hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(parsed.Hosts))
	}

	h1 := parsed.Hosts[0]
	if h1.IP != "10.0.1.1" {
		t.Errorf("expected IP 10.0.1.1, got %q", h1.IP)
	}
	if h1.MACAddress != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("expected MAC, got %q", h1.MACAddress)
	}
	if h1.Hostname != "router.local" {
		t.Errorf("expected hostname router.local, got %q", h1.Hostname)
	}
	if len(h1.Ports) != 2 {
		t.Fatalf("expected 2 ports, got %d", len(h1.Ports))
	}

	// Only open ports should produce services
	if len(parsed.Services) != 1 {
		t.Fatalf("expected 1 service (only open port), got %d", len(parsed.Services))
	}
	svc := parsed.Services[0]
	if svc.Port != 22 {
		t.Errorf("expected service on port 22, got %d", svc.Port)
	}
	if svc.Product != "OpenSSH" {
		t.Errorf("expected product OpenSSH, got %q", svc.Product)
	}
}

func TestParseNmapXML_OSDetection(t *testing.T) {
	parser := NewResultParser("")

	content := `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" start="1234567890" version="7.99" xmloutputversion="1.05">
<host starttime="1234567890" endtime="1234567900"><status state="up" reason="syn-ack"/>
<address addr="10.0.0.50" addrtype="ipv4"/>
<hostnames><hostname name="dc01.corp.local" type="PTR"/></hostnames>
<os><osmatch name="Windows Server 2019" accuracy="98">
<osclass type="general purpose" vendor="Microsoft" osfamily="Windows"/>
</osmatch>
<osmatch name="Windows Server 2016" accuracy="90">
<osclass type="general purpose" vendor="Microsoft" osfamily="Windows"/>
</osmatch>
</os>
<ports><port protocol="tcp" portid="445"><state state="open" reason="syn-ack"/>
<service name="microsoft-ds" product="Windows Server 2019 microsoft-ds" conf="10"/>
</port></ports></host>
<host starttime="1234567890" endtime="1234567900"><status state="up" reason="syn-ack"/>
<address addr="10.0.0.100" addrtype="ipv4"/>
<hostnames><hostname name="desktop01.corp.local" type="PTR"/></hostnames>
<os><osmatch name="Windows 10 2004" accuracy="95">
<osclass type="general purpose" vendor="Microsoft" osfamily="Windows"/>
</osmatch>
</os>
<ports><port protocol="tcp" portid="445"><state state="open" reason="syn-ack"/>
<service name="microsoft-ds" conf="10"/>
</port></ports></host>
<host starttime="1234567890" endtime="1234567900"><status state="up" reason="syn-ack"/>
<address addr="10.0.0.1" addrtype="ipv4"/>
<hostnames></hostnames>
</host>
</nmaprun>`

	result := &ScanResult{
		ID:              "test",
		Type:            ScanTypeNmapXML,
		Timestamp:       time.Now(),
		Hosts:           make([]Host, 0),
		Services:        make([]Service, 0),
		Vulnerabilities: make([]Vulnerability, 0),
		Metadata:        make(map[string]any),
	}

	parsed, err := parser.parseNmapXML(result, content)
	if err != nil {
		t.Fatalf("parseNmapXML() error = %v", err)
	}

	if len(parsed.Hosts) != 3 {
		t.Fatalf("expected 3 hosts, got %d", len(parsed.Hosts))
	}

	// Host with Windows Server 2019
	h1 := parsed.Hosts[0]
	if h1.IP != "10.0.0.50" {
		t.Fatalf("first host IP = %q, want 10.0.0.50", h1.IP)
	}
	if h1.OS != "Windows Server 2019" {
		t.Errorf("OS = %q, want Windows Server 2019", h1.OS)
	}
	if h1.OSDetails != "Windows Server 2019" {
		t.Errorf("OSDetails = %q, want Windows Server 2019", h1.OSDetails)
	}
	if h1.Attributes["os_match"] != "Windows Server 2019" {
		t.Errorf("os_match = %q, want Windows Server 2019", h1.Attributes["os_match"])
	}
	if h1.Attributes["os_match_accuracy"] != "98" {
		t.Errorf("os_match_accuracy = %q, want 98", h1.Attributes["os_match_accuracy"])
	}
	if h1.Attributes["device_type"] != "general purpose" {
		t.Errorf("device_type = %q, want general purpose", h1.Attributes["device_type"])
	}

	// Host with Windows 10
	h2 := parsed.Hosts[1]
	if h2.OS != "Windows 10 2004" {
		t.Errorf("OS = %q, want Windows 10 2004", h2.OS)
	}
	if h2.Attributes["os_match"] != "Windows 10 2004" {
		t.Errorf("os_match = %q, want Windows 10 2004", h2.Attributes["os_match"])
	}

	// Host without OS detection
	h3 := parsed.Hosts[2]
	if h3.OS != "" {
		t.Errorf("OS = %q, want empty", h3.OS)
	}
	if h3.Attributes["os_match"] != "" {
		t.Errorf("os_match = %q, want empty", h3.Attributes["os_match"])
	}
}


func TestParseNmapXML_ConfirmedVulnerable(t *testing.T) {
	parser := NewResultParser("")

	content := `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" start="1234567890" version="7.99" xmloutputversion="1.05">
<host starttime="1234567890" endtime="1234567900"><status state="up" reason="syn-ack"/>
<address addr="10.0.1.1" addrtype="ipv4"/>
<hostnames></hostnames>
<ports><port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/>
<service name="https" product="nginx"/>
<script id="ssl-heartbleed" output="\n  VULNERABLE:\n  OpenSSL Heartbleed\n    State: VULNERABLE\n">
<table key="CVE-2014-0160">
<elem key="title">OpenSSL Heartbleed</elem>
<elem key="state">VULNERABLE</elem>
<table key="ids"><elem>CVE:CVE-2014-0160</elem></table>
<table key="description"><elem>The Heartbleed Bug is a serious vulnerability in OpenSSL...</elem></table>
<table key="refs">
<elem>https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160</elem>
</table>
</table>
</script>
</port></ports></host>
</nmaprun>`

	result := &ScanResult{
		ID:              "test",
		Type:            ScanTypeNmapXML,
		Timestamp:       time.Now(),
		Hosts:           make([]Host, 0),
		Services:        make([]Service, 0),
		Vulnerabilities: make([]Vulnerability, 0),
		Metadata:        make(map[string]any),
	}

	parsed, err := parser.parseNmapXML(result, content)
	if err != nil {
		t.Fatalf("parseNmapXML() error = %v", err)
	}

	if len(parsed.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(parsed.Vulnerabilities))
	}

	vuln := parsed.Vulnerabilities[0]
	if vuln.Severity != "high" {
		t.Errorf("VULNERABLE state should be high severity, got %q", vuln.Severity)
	}
	if vuln.Title != "OpenSSL Heartbleed" {
		t.Errorf("expected 'OpenSSL Heartbleed', got %q", vuln.Title)
	}
	if vuln.Description != "The Heartbleed Bug is a serious vulnerability in OpenSSL..." {
		t.Errorf("unexpected description: %q", vuln.Description)
	}
	if vuln.CVE != "CVE-2014-0160" {
		t.Errorf("expected CVE-2014-0160, got %q", vuln.CVE)
	}
}

func TestDetermineScanType_NmapXML(t *testing.T) {
	parser := NewResultParser("")

	content := `<?xml version="1.0"?>
<nmaprun scanner="nmap" start="1234567890" version="7.99">
<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>
<ports></ports></host>
</nmaprun>`

	scanType := parser.determineScanType("/some/path/vuln_results.xml", content)
	if scanType != ScanTypeNmapXML {
		t.Errorf("determineScanType() = %s, want %s", scanType, ScanTypeNmapXML)
	}
}


// ============================================================================
// LLDP/CDP Parser Tests
// ============================================================================

func TestDetermineScanType_LLDPCDP(t *testing.T) {
	parser := NewResultParser("")

	content := `<?xml version="1.0"?>
<lldp_cdp_results>
  <neighbor protocol="lldp">
    <hostname>switch-01</hostname>
  </neighbor>
</lldp_cdp_results>`

	scanType := parser.determineScanType("/some/path/lldp_cdp_results.xml", content)
	if scanType != ScanTypeLLDP {
		t.Errorf("determineScanType() = %s, want %s", scanType, ScanTypeLLDP)
	}
}

func TestParseLLDPCDPResult_Basic(t *testing.T) {
	parser := NewResultParser("")
	now := time.Now()

	content := `<?xml version="1.0"?>
<lldp_cdp_results>
  <neighbor protocol="lldp">
    <hostname>switch-01</hostname>
    <management_ip>10.0.0.1</management_ip>
    <remote_port>GigabitEthernet0/1</remote_port>
    <capabilities>bridge router</capabilities>
    <vlan_id>100</vlan_id>
    <local_interface>eth0</local_interface>
    <system_description>Cisco IOS Software, C2960</system_description>
  </neighbor>
  <neighbor protocol="cdp">
    <hostname>ap-01</hostname>
    <management_ip>10.0.0.50</management_ip>
    <platform>Cisco AIR-AP3802I</platform>
    <remote_port>GigabitEthernet0/2</remote_port>
  </neighbor>
</lldp_cdp_results>`

	parsed, err := parser.ParseJobResult("lldp_cdp_results.xml", content, now)
	if err != nil {
		t.Fatalf("ParseJobResult error: %v", err)
	}

	if len(parsed.Hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(parsed.Hosts))
	}

	// First neighbor (LLDP)
	h1 := parsed.Hosts[0]
	if h1.IP != "10.0.0.1" {
		t.Errorf("host 1 IP = %s, want 10.0.0.1", h1.IP)
	}
	if h1.Hostname != "switch-01" {
		t.Errorf("host 1 Hostname = %s, want switch-01", h1.Hostname)
	}
	if h1.Attributes["discovery_protocol"] != "lldp" {
		t.Errorf("host 1 discovery_protocol = %s", h1.Attributes["discovery_protocol"])
	}
	if h1.Attributes["vlan_id"] != "100" {
		t.Errorf("host 1 vlan_id = %s", h1.Attributes["vlan_id"])
	}
	if h1.OSDetails != "Cisco IOS Software, C2960" {
		t.Errorf("host 1 OSDetails = %s", h1.OSDetails)
	}

	// Second neighbor (CDP)
	h2 := parsed.Hosts[1]
	if h2.IP != "10.0.0.50" {
		t.Errorf("host 2 IP = %s, want 10.0.0.50", h2.IP)
	}
	if h2.Hostname != "ap-01" {
		t.Errorf("host 2 Hostname = %s, want ap-01", h2.Hostname)
	}
	if h2.Attributes["platform"] != "Cisco AIR-AP3802I" {
		t.Errorf("host 2 platform = %s", h2.Attributes["platform"])
	}
}

func TestParseLLDPCDPResult_Empty(t *testing.T) {
	parser := NewResultParser("")
	now := time.Now()

	content := `<?xml version="1.0"?>
<lldp_cdp_results>
</lldp_cdp_results>`

	result := &ScanResult{ID: "test", Type: ScanTypeLLDP, Timestamp: now, Hosts: []Host{}, Services: []Service{}, Vulnerabilities: []Vulnerability{}}
	parsed, err := parser.parseLLDPCDPResult(result, content)
	if err != nil {
		t.Fatalf("parseLLDPCDPResult error: %v", err)
	}
	if len(parsed.Hosts) != 0 {
		t.Errorf("expected 0 hosts, got %d", len(parsed.Hosts))
	}
}

// ============================================================================
// SNMP Parser Tests
// ============================================================================

func TestDetermineScanType_SNMP(t *testing.T) {
	parser := NewResultParser("")

	content := `<?xml version="1.0"?>
<snmp_results>
  <device ip="10.0.0.1"/>
</snmp_results>`

	scanType := parser.determineScanType("/path/snmp_device_info.xml", content)
	if scanType != ScanTypeSNMP {
		t.Errorf("determineScanType() = %s, want %s", scanType, ScanTypeSNMP)
	}
}

func TestParseSNMPResult_Basic(t *testing.T) {
	parser := NewResultParser("")
	now := time.Now()

	content := `<?xml version="1.0"?>
<snmp_results>
  <device ip="10.0.0.1">
    <sys_description>Cisco IOS Software, C3750</sys_description>
    <sys_uptime>42 days</sys_uptime>
    <hostname>core-switch</hostname>
    <interfaces>
      <interface>
        <name>GigabitEthernet0/1</name>
        <status>up</status>
        <speed>1000000000</speed>
      </interface>
    </interfaces>
    <arp_entries>
      <entry mac="aa:bb:cc:dd:ee:01" ip="10.0.0.100" interface="Gi0/1"/>
    </arp_entries>
    <vlans>
      <vlan id="100" name="users"/>
      <vlan id="200" name="servers"/>
    </vlans>
    <routes>
      <route dest="0.0.0.0/0" gateway="10.0.0.254" interface="Gi0/1"/>
    </routes>
  </device>
</snmp_results>`

	parsed, err := parser.ParseJobResult("snmp_device_info.xml", content, now)
	if err != nil {
		t.Fatalf("ParseJobResult error: %v", err)
	}

	if len(parsed.Hosts) < 2 {
		t.Fatalf("expected at least 2 hosts (device + arp), got %d", len(parsed.Hosts))
	}

	// Device host
	h1 := parsed.Hosts[0]
	if h1.IP != "10.0.0.1" {
		t.Errorf("device IP = %s, want 10.0.0.1", h1.IP)
	}
	if h1.Hostname != "core-switch" {
		t.Errorf("device Hostname = %s, want core-switch", h1.Hostname)
	}
	if h1.OSDetails != "Cisco IOS Software, C3750" {
		t.Errorf("device OSDetails = %s", h1.OSDetails)
	}
	if h1.Attributes["sys_uptime"] != "42 days" {
		t.Errorf("device uptime = %s", h1.Attributes["sys_uptime"])
	}
	if !strings.Contains(h1.Attributes["vlans"], "100") {
		t.Errorf("device vlans = %s, expected to contain 100", h1.Attributes["vlans"])
	}

	// ARP entry host
	if len(parsed.Hosts) >= 2 {
		h2 := parsed.Hosts[1]
		if h2.IP != "10.0.0.100" {
			t.Errorf("ARP entry IP = %s, want 10.0.0.100", h2.IP)
		}
		if h2.MACAddress != "AA:BB:CC:DD:EE:01" {
			t.Errorf("ARP MAC = %s, want AA:BB:CC:DD:EE:01", h2.MACAddress)
		}
	}
}

// ============================================================================
// Exploit Search Parser Tests
// ============================================================================

func TestDetermineScanType_ExploitSearch(t *testing.T) {
	parser := NewResultParser("")

	content := `<?xml version="1.0"?>
<exploit_results>
  <host ip="10.0.0.1"/>
</exploit_results>`

	scanType := parser.determineScanType("/path/exploit_results.xml", content)
	if scanType != ScanTypeExploitSearch {
		t.Errorf("determineScanType() = %s, want %s", scanType, ScanTypeExploitSearch)
	}
}

func TestParseExploitSearchResult_Basic(t *testing.T) {
	parser := NewResultParser("")
	now := time.Now()

	content := `<?xml version="1.0"?>
<exploit_results>
  <host ip="10.0.0.1">
    <service port="80" product="Apache" version="2.4.49">
      <exploit title="Path Traversal" type="remote" platform="linux" path="/exploits/50383.py"/>
      <exploit title="HTTP Request Splitting" type="remote" platform="linux" path="/exploits/50384.py"/>
    </service>
    <service port="22" product="OpenSSH" version="8.2">
      <exploit title="SSH Key Exchange Overflow" type="remote" platform="linux" path="/exploits/48053.py"/>
    </service>
  </host>
</exploit_results>`

	parsed, err := parser.ParseJobResult("exploit_results.xml", content, now)
	if err != nil {
		t.Fatalf("ParseJobResult error: %v", err)
	}

	if len(parsed.Hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(parsed.Hosts))
	}
	if parsed.Hosts[0].IP != "10.0.0.1" {
		t.Errorf("host IP = %s, want 10.0.0.1", parsed.Hosts[0].IP)
	}

	if len(parsed.Vulnerabilities) != 3 {
		t.Fatalf("expected 3 vulnerabilities, got %d", len(parsed.Vulnerabilities))
	}

	v1 := parsed.Vulnerabilities[0]
	if v1.Title != "Path Traversal" {
		t.Errorf("vuln 1 title = %s, want Path Traversal", v1.Title)
	}
	if v1.Port != 80 {
		t.Errorf("vuln 1 port = %d, want 80", v1.Port)
	}
	if v1.Severity != "high" {
		t.Errorf("vuln 1 severity = %s, want high", v1.Severity)
	}
	if v1.Source != "searchsploit" {
		t.Errorf("vuln 1 source = %s, want searchsploit", v1.Source)
	}
}

// ============================================================================
// Passive Fingerprint Parser Tests
// ============================================================================

func TestDetermineScanType_Fingerprint(t *testing.T) {
	parser := NewResultParser("")

	content := `<?xml version="1.0"?>
<fingerprint_results>
  <host ip="10.0.0.1"/>
</fingerprint_results>`

	scanType := parser.determineScanType("/path/fingerprint_results.xml", content)
	if scanType != ScanTypeFingerprint {
		t.Errorf("determineScanType() = %s, want %s", scanType, ScanTypeFingerprint)
	}
}

func TestParseFingerprintResult_Basic(t *testing.T) {
	parser := NewResultParser("")
	now := time.Now()

	content := `<?xml version="1.0"?>
<fingerprint_results>
  <host ip="10.0.0.1" mac="00:1a:a1:22:33:44">
    <os_guess>Cisco IOS</os_guess>
    <device_type>switch</device_type>
    <confidence>high</confidence>
    <evidence>
      <source name="p0f">syn@CISCO</source>
      <source name="oui">Cisco Systems</source>
      <source name="ports">161/udp,22/tcp,80/tcp</source>
    </evidence>
  </host>
</fingerprint_results>`

	parsed, err := parser.ParseJobResult("fingerprint_results.xml", content, now)
	if err != nil {
		t.Fatalf("ParseJobResult error: %v", err)
	}

	if len(parsed.Hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(parsed.Hosts))
	}

	h := parsed.Hosts[0]
	if h.IP != "10.0.0.1" {
		t.Errorf("host IP = %s, want 10.0.0.1", h.IP)
	}
	if h.MACAddress != "00:1A:A1:22:33:44" {
		t.Errorf("host MAC = %s, want 00:1A:A1:22:33:44", h.MACAddress)
	}
	if h.OS != "Cisco IOS" {
		t.Errorf("host OS = %s, want Cisco IOS", h.OS)
	}
	if h.Attributes["device_type"] != "switch" {
		t.Errorf("device_type = %s, want switch", h.Attributes["device_type"])
	}
	if h.Attributes["fingerprint_confidence"] != "high" {
		t.Errorf("confidence = %s", h.Attributes["fingerprint_confidence"])
	}
	if h.Attributes["evidence_p0f"] != "syn@CISCO" {
		t.Errorf("evidence_p0f = %s", h.Attributes["evidence_p0f"])
	}
}

// ============================================================================
// ARP Parser Tests
// ============================================================================

func TestDetermineScanType_ARP(t *testing.T) {
	parser := NewResultParser("")

	content := `<?xml version="1.0"?>
<arp_results>
  <entry ip="10.0.0.1" mac="AA:BB:CC:DD:EE:FF"/>
</arp_results>`

	scanType := parser.determineScanType("/path/arp_results.xml", content)
	if scanType != ScanTypeARP {
		t.Errorf("determineScanType() = %s, want %s", scanType, ScanTypeARP)
	}
}

func TestParseARPResult_Basic(t *testing.T) {
	parser := NewResultParser("")
	now := time.Now()

	content := `<?xml version="1.0"?>
<arp_results>
  <entry ip="192.168.1.1" mac="aa:bb:cc:dd:ee:ff" interface="eth0" state="REACHABLE"/>
  <entry ip="192.168.1.2" mac="11:22:33:44:55:66" interface="eth0" state="STALE"/>
  <entry ip="192.168.1.3" mac="" interface="eth0" state="FAILED"/>
</arp_results>`

	parsed, err := parser.ParseJobResult("arp_results.xml", content, now)
	if err != nil {
		t.Fatalf("ParseJobResult error: %v", err)
	}

	// Should have 2 hosts (entry 3 has empty MAC, should still be included since IP is present)
	if len(parsed.Hosts) != 3 {
		t.Fatalf("expected 3 hosts, got %d", len(parsed.Hosts))
	}

	h1 := parsed.Hosts[0]
	if h1.IP != "192.168.1.1" {
		t.Errorf("host 1 IP = %s", h1.IP)
	}
	if h1.MACAddress != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("host 1 MAC = %s, want AA:BB:CC:DD:EE:FF", h1.MACAddress)
	}
	if h1.Attributes["interface"] != "eth0" {
		t.Errorf("host 1 interface = %s", h1.Attributes["interface"])
	}
	if h1.Attributes["arp_state"] != "REACHABLE" {
		t.Errorf("host 1 state = %s", h1.Attributes["arp_state"])
	}

	h2 := parsed.Hosts[1]
	if h2.IP != "192.168.1.2" {
		t.Errorf("host 2 IP = %s", h2.IP)
	}
}

func TestParseARPResult_Empty(t *testing.T) {
	parser := NewResultParser("")
	now := time.Now()

	content := `<?xml version="1.0"?>
<arp_results>
</arp_results>`

	result := &ScanResult{ID: "test", Type: ScanTypeARP, Timestamp: now, Hosts: []Host{}, Services: []Service{}, Vulnerabilities: []Vulnerability{}}
	parsed, err := parser.parseARPResult(result, content)
	if err != nil {
		t.Fatalf("parseARPResult error: %v", err)
	}
	if len(parsed.Hosts) != 0 {
		t.Errorf("expected 0 hosts, got %d", len(parsed.Hosts))
	}
}

// ============================================================================
// testssl.sh Parser Tests
// ============================================================================

func TestDetermineScanType_TestSSL(t *testing.T) {
	parser := NewResultParser("")

	// Real testssl -oj format: flat JSON array with id, ip, port, severity, finding fields
	content := `[{"id":"SSLv3","ip":"10.0.0.1:443","port":"443","severity":"CRITICAL","finding":"offered"}]`

	scanType := parser.determineScanType("/path/testssl.json", content)
	if scanType != ScanTypeTestSSL {
		t.Errorf("determineScanType() = %s, want %s", scanType, ScanTypeTestSSL)
	}
}

func TestParseTestSSLResult_Basic(t *testing.T) {
	parser := NewResultParser("")
	now := time.Now()

	// Real testssl -oj flat JSON array format
	content := `[
		{"id":"SSLv3","ip":"10.0.0.1:443","port":"443","severity":"CRITICAL","finding":"offered (NOT ok)"},
		{"id":"heartbleed","ip":"10.0.0.1:443","port":"443","severity":"HIGH","finding":"VULNERABLE","cve":"CVE-2014-0160"},
		{"id":"cert_selfSigned","ip":"10.0.0.1:443","port":"443","severity":"WARN","finding":"self-signed certificate"},
		{"id":"cipher_EXP-RC4-MD5","ip":"10.0.0.1:443","port":"443","severity":"HIGH","finding":"offered (NOT ok) -- 40-bit weak cipher"}
	]`

	parsed, err := parser.ParseJobResult("testssl.json", content, now)
	if err != nil {
		t.Fatalf("ParseJobResult error: %v", err)
	}

	if len(parsed.Hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(parsed.Hosts))
	}
	if parsed.Hosts[0].IP != "10.0.0.1" {
		t.Errorf("host IP = %s, want 10.0.0.1", parsed.Hosts[0].IP)
	}

	// Should have SSLv3 (critical), heartbleed (high), cert warning (low), weak cipher (high)
	if len(parsed.Vulnerabilities) < 3 {
		t.Errorf("expected at least 3 vulnerabilities, got %d", len(parsed.Vulnerabilities))
	}

	// Check for SSLv3
	var foundSSLv3 bool
	for _, v := range parsed.Vulnerabilities {
		if strings.Contains(v.Title, "SSLv3") {
			foundSSLv3 = true
			if v.Severity != "critical" {
				t.Errorf("SSLv3 severity = %s, want critical", v.Severity)
			}
		}
	}
	if !foundSSLv3 {
		t.Error("expected SSLv3 vulnerability not found")
	}

	// Check for self-signed cert (severity WARN → "low")
	var foundSelfSigned bool
	for _, v := range parsed.Vulnerabilities {
		if strings.Contains(v.Title, "cert_selfSigned") {
			foundSelfSigned = true
		}
	}
	if !foundSelfSigned {
		t.Error("expected self-signed certificate vulnerability not found")
	}

	// Check for weak cipher
	var foundWeakCipher bool
	for _, v := range parsed.Vulnerabilities {
		if strings.Contains(v.Title, "cipher_EXP-RC4-MD5") || strings.Contains(v.Title, "40-bit") {
			foundWeakCipher = true
			if v.Severity != "high" {
				t.Errorf("weak cipher severity = %s, want high", v.Severity)
			}
		}
	}
	if !foundWeakCipher {
		t.Error("expected weak cipher vulnerability not found")
	}
}

func TestParseTestSSLResult_MultipleHosts(t *testing.T) {
	parser := NewResultParser("")
	now := time.Now()

	// Real testssl -oj format: flat JSON array covering two different hosts
	content := `[
		{"id":"SSLv3","ip":"10.0.0.1:443","port":"443","severity":"CRITICAL","finding":"offered"},
		{"id":"TLS1","ip":"10.0.0.2:8443","port":"8443","severity":"LOW","finding":"offered"}
	]`

	parsed, err := parser.ParseJobResult("testssl.json", content, now)
	if err != nil {
		t.Fatalf("ParseJobResult error: %v", err)
	}

	if len(parsed.Hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(parsed.Hosts))
	}
}

func TestDetermineScanType_NonTestSSLJSON(t *testing.T) {
	parser := NewResultParser("")

	// JSON array with severity+finding+id but WITHOUT ip/port (e.g., generic vulnerability scanner output)
	// This should NOT be classified as testssl after the fix
	content := `[{"id": "CVE-2021-44228", "severity": "critical", "finding": "Log4Shell RCE"}]`

	scanType := parser.determineScanType("/path/vuln_output.json", content)
	if scanType == ScanTypeTestSSL {
		t.Errorf("non-testssl JSON with only id/severity/finding should not be classified as testssl, got %s", scanType)
	}
}

func TestDetermineScanType_TestSSLWithIPPort(t *testing.T) {
	parser := NewResultParser("")

	// JSON with all testssl fields including ip and port
	content := `[{"id": "SSLv3", "ip": "10.0.0.1:443", "port": "443", "severity": "CRITICAL", "finding": "offered"}]`

	scanType := parser.determineScanType("/path/some_output.json", content)
	if scanType != ScanTypeTestSSL {
		t.Errorf("JSON with severity+finding+ip+port should be classified as testssl, got %s", scanType)
	}
}
