package correlation

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFormatScreenshotNotes(t *testing.T) {
	tests := []struct {
		name         string
		screenshots  []ScreenshotInfo
		wantContains []string
	}{
		{
			name: "single screenshot",
			screenshots: []ScreenshotInfo{
				{IP: "192.168.1.1", URL: "http://192.168.1.1", StatusCode: "200", File: "/tmp/http--192.168.1.1-80.jpeg"},
			},
			wantContains: []string{
				"> [!screenshot]- http://192.168.1.1 (200)",
				"> [[screenshots/http--192.168.1.1-80.jpeg]]",
			},
		},
		{
			name: "multiple screenshots separated by br",
			screenshots: []ScreenshotInfo{
				{IP: "192.168.1.1", URL: "http://192.168.1.1", StatusCode: "200", File: "/tmp/a.png"},
				{IP: "192.168.1.1", URL: "https://192.168.1.1", StatusCode: "301", File: "/tmp/b.png"},
			},
			wantContains: []string{
				"> [!screenshot]- http://192.168.1.1 (200)",
				"> [!screenshot]- https://192.168.1.1 (301)",
				"<br>",
			},
		},
		{
			name:         "empty screenshots",
			screenshots:  []ScreenshotInfo{},
			wantContains: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatScreenshotNotes(tt.screenshots)
			if len(tt.screenshots) == 0 {
				if got != "" {
					t.Errorf("expected empty string for empty screenshots, got %q", got)
				}
				return
			}
			for _, substr := range tt.wantContains {
				if !strings.Contains(got, substr) {
					t.Errorf("formatScreenshotNotes() = %q, want to contain %q", got, substr)
				}
			}
		})
	}
}

func TestBuildHostEntry(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		corr *CorrelationResult
		want HostEntry
	}{
		{
			name: "full host info",
			ip:   "192.168.1.10",
			corr: &CorrelationResult{
				Host: "192.168.1.10",
				HostInfo: &Host{
					Hostname:  "DESKTOP-ABC",
					OS:        "Windows",
					OSDetails: "Windows 10 Pro",
					Ports: []Port{
						{Number: 135, Protocol: "tcp", State: "open", Service: "msrpc"},
						{Number: 445, Protocol: "tcp", State: "open", Service: "microsoft-ds"},
						{Number: 80, Protocol: "tcp", State: "closed"},
					},
					Attributes: map[string]string{
						"category": "windows",
						"vendor":   "Dell",
					},
				},
				Metadata: map[string]any{},
			},
			want: HostEntry{
				IP:          "192.168.1.10",
				Hostname:    "DESKTOP-ABC",
				Vendor:      "Dell",
				OSDetection: "Windows 10 Pro",
				OpenPorts:   "135, 445",
			},
		},
		{
			name: "minimal host info",
			ip:   "10.0.0.1",
			corr: &CorrelationResult{
				Host:     "10.0.0.1",
				HostInfo: &Host{},
			},
			want: HostEntry{
				IP: "10.0.0.1",
			},
		},
		{
			name: "hostname falls back to netbios",
			ip:   "10.0.0.2",
			corr: &CorrelationResult{
				Host: "10.0.0.2",
				HostInfo: &Host{
					Attributes: map[string]string{
						"netbios_name": "SERVER1",
					},
				},
			},
			want: HostEntry{
				IP:       "10.0.0.2",
				Hostname: "SERVER1",
			},
		},
		{
			name: "os falls back to OS field",
			ip:   "10.0.0.3",
			corr: &CorrelationResult{
				Host: "10.0.0.3",
				HostInfo: &Host{
					OS: "Linux",
				},
			},
			want: HostEntry{
				IP:          "10.0.0.3",
				OSDetection: "Linux",
			},
		},
		{
			name: "nil host info",
			ip:   "10.0.0.4",
			corr: &CorrelationResult{
				Host: "10.0.0.4",
			},
			want: HostEntry{
				IP: "10.0.0.4",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildHostEntry(tt.ip, tt.corr)
			if got.IP != tt.want.IP {
				t.Errorf("IP = %q, want %q", got.IP, tt.want.IP)
			}
			if got.Hostname != tt.want.Hostname {
				t.Errorf("Hostname = %q, want %q", got.Hostname, tt.want.Hostname)
			}
			if got.Vendor != tt.want.Vendor {
				t.Errorf("Vendor = %q, want %q", got.Vendor, tt.want.Vendor)
			}
			if got.OSDetection != tt.want.OSDetection {
				t.Errorf("OSDetection = %q, want %q", got.OSDetection, tt.want.OSDetection)
			}
			if got.OpenPorts != tt.want.OpenPorts {
				t.Errorf("OpenPorts = %q, want %q", got.OpenPorts, tt.want.OpenPorts)
			}
		})
	}
}

func TestHostCategoryFromResult(t *testing.T) {
	tests := []struct {
		name string
		corr *CorrelationResult
		want string
	}{
		{
			name: "windows category",
			corr: &CorrelationResult{
				HostInfo: &Host{
					Attributes: map[string]string{"category": "windows"},
				},
			},
			want: "windows",
		},
		{
			name: "linux category",
			corr: &CorrelationResult{
				HostInfo: &Host{
					Attributes: map[string]string{"category": "linux"},
				},
			},
			want: "linux",
		},
		{
			name: "network_device category",
			corr: &CorrelationResult{
				HostInfo: &Host{
					Attributes: map[string]string{"category": "network_device"},
				},
			},
			want: "network_device",
		},
		{
			name: "no attributes",
			corr: &CorrelationResult{
				HostInfo: &Host{},
			},
			want: "unknown",
		},
		{
			name: "nil host info",
			corr: &CorrelationResult{
				Host: "10.0.0.1",
			},
			want: "unknown",
		},
		{
			name: "nil correlation",
			corr: nil,
			want: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hostCategoryFromResult(tt.corr)
			if got != tt.want {
				t.Errorf("hostCategoryFromResult() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWriteMarkdownFile(t *testing.T) {
	tmpDir := t.TempDir()
	entries := []HostEntry{
		{
			IP:          "192.168.1.10",
			Hostname:    "DESKTOP-ABC",
			Vendor:      "Dell",
			OSDetection: "Windows 10",
			OpenPorts:   "135, 445",
		},
		{
			IP:          "192.168.1.20",
			Hostname:    "LAPTOP-XYZ",
			Vendor:      "HP",
			OSDetection: "Windows 11",
			OpenPorts:   "80, 443",
			Notes:       "> [!screenshot]- test",
		},
	}

	path := filepath.Join(tmpDir, "windows.md")
	if err := writeMarkdownFile(path, "windows", entries); err != nil {
		t.Fatalf("writeMarkdownFile() error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}

	content := string(data)

	// Check header.
	if !strings.Contains(content, "# Windows Hosts") {
		t.Error("missing heading")
	}
	if !strings.Contains(content, "| IP |") {
		t.Error("missing table header")
	}
	if !strings.Contains(content, "| 192.168.1.10 |") {
		t.Error("missing first host IP")
	}
	if !strings.Contains(content, "DESKTOP-ABC") {
		t.Error("missing hostname")
	}
	if !strings.Contains(content, "135, 445") {
		t.Error("missing ports")
	}
	if !strings.Contains(content, "> [!screenshot]- test") {
		t.Error("missing screenshot notes")
	}

	// Verify dash for missing fields.
	if !strings.Contains(content, "DESKTOP-ABC | Dell | Windows 10 | 135, 445 |  ") {
		t.Error("missing dash for empty notes")
	}
}

func TestGenerateDistributionPackage(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := t.TempDir()

	c := newCorrelatorWithDataDir(tmpDir, dataDir)

	// Add a windows host.
	c.correlations["192.168.1.10"] = &CorrelationResult{
		Host: "192.168.1.10",
		HostInfo: &Host{
			Hostname:  "DESKTOP-ABC",
			OS:        "Windows",
			OSDetails: "Windows 10 Pro",
			Ports: []Port{
				{Number: 135, Protocol: "tcp", State: "open"},
				{Number: 445, Protocol: "tcp", State: "open"},
			},
			Attributes: map[string]string{
				"category": "windows",
				"vendor":   "Dell",
			},
		},
		Metadata: map[string]any{},
	}

	// Add a linux host.
	c.correlations["192.168.1.20"] = &CorrelationResult{
		Host: "192.168.1.20",
		HostInfo: &Host{
			Hostname: "webserver",
			OS:       "Linux",
			Ports: []Port{
				{Number: 22, Protocol: "tcp", State: "open"},
				{Number: 80, Protocol: "tcp", State: "open"},
			},
			Attributes: map[string]string{
				"category": "linux",
				"vendor":   "Ubuntu",
			},
		},
		Metadata: map[string]any{},
	}

	// Add an unknown host — should be skipped.
	c.correlations["192.168.1.99"] = &CorrelationResult{
		Host: "192.168.1.99",
		HostInfo: &Host{
			Attributes: map[string]string{
				"category": "unknown",
			},
		},
		Metadata: map[string]any{},
	}

	archivePath, err := c.GenerateDistributionPackage()
	if err != nil {
		t.Fatalf("GenerateDistributionPackage() error: %v", err)
	}

	if !strings.HasPrefix(archivePath, filepath.Join(tmpDir, "discovery")) {
		t.Errorf("archive path = %q, want under discovery dir", archivePath)
	}
	if !strings.HasSuffix(archivePath, ".tar.gz") {
		t.Errorf("archive path = %q, want .tar.gz suffix", archivePath)
	}

	// Verify archive contents.
	f, err := os.Open(archivePath)
	if err != nil {
		t.Fatalf("opening archive: %v", err)
	}
	defer func() { _ = f.Close() }()

	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	foundFiles := make(map[string]bool)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("reading tar: %v", err)
		}
		foundFiles[hdr.Name] = true

		// Verify windows.md content.
		if hdr.Name == "windows.md" {
			var buf strings.Builder
			if _, err := io.Copy(&buf, tr); err != nil {
				t.Fatalf("reading windows.md: %v", err)
			}
			content := buf.String()
			if !strings.Contains(content, "192.168.1.10") {
				t.Error("windows.md missing windows host IP")
			}
			if !strings.Contains(content, "DESKTOP-ABC") {
				t.Error("windows.md missing hostname")
			}
			if strings.Contains(content, "192.168.1.20") {
				t.Error("windows.md should not contain linux host")
			}
		}

		// Verify linux.md content.
		if hdr.Name == "linux.md" {
			var buf strings.Builder
			if _, err := io.Copy(&buf, tr); err != nil {
				t.Fatalf("reading linux.md: %v", err)
			}
			content := buf.String()
			if !strings.Contains(content, "192.168.1.20") {
				t.Error("linux.md missing linux host IP")
			}
			if !strings.Contains(content, "webserver") {
				t.Error("linux.md missing hostname")
			}
		}

		// Verify metadata.txt.
		if hdr.Name == "metadata.txt" {
			var buf strings.Builder
			if _, err := io.Copy(&buf, tr); err != nil {
				t.Fatalf("reading metadata.txt: %v", err)
			}
			content := buf.String()
			if !strings.Contains(content, "windows: 1") {
				t.Error("metadata missing windows count")
			}
			if !strings.Contains(content, "linux: 1") {
				t.Error("metadata missing linux count")
			}
			if !strings.Contains(content, "total: 2") {
				t.Error("metadata missing total count")
			}
		}
	}

	if !foundFiles["windows.md"] {
		t.Error("archive missing windows.md")
	}
	if !foundFiles["linux.md"] {
		t.Error("archive missing linux.md")
	}
	if !foundFiles["metadata.txt"] {
		t.Error("archive missing metadata.txt")
	}
	// Unknown hosts should not produce a file.
	if foundFiles["unknown.md"] {
		t.Error("archive should not contain unknown.md")
	}
}

func TestGenerateDistributionPackageWithScreenshots(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := t.TempDir()

	// Create a fake screenshot file.
	screenshotDir := filepath.Join(tmpDir, "captures", "screenshots")
	if err := os.MkdirAll(screenshotDir, 0755); err != nil {
		t.Fatal(err)
	}
	screenshotPath := filepath.Join(screenshotDir, "http--192.168.1.10-80.jpeg")
	if err := os.WriteFile(screenshotPath, []byte("fake png data"), 0644); err != nil {
		t.Fatal(err)
	}

	c := newCorrelatorWithDataDir(tmpDir, dataDir)

	c.correlations["192.168.1.10"] = &CorrelationResult{
		Host: "192.168.1.10",
		HostInfo: &Host{
			Hostname: "DESKTOP-ABC",
			Ports:    []Port{{Number: 80, Protocol: "tcp", State: "open"}},
			Attributes: map[string]string{
				"category": "windows",
			},
		},
		Metadata: map[string]any{
			"screenshots": []map[string]string{
				{
					"url":         "http://192.168.1.10",
					"file":        screenshotPath,
					"status_code": "200",
				},
			},
		},
	}

	archivePath, err := c.GenerateDistributionPackage()
	if err != nil {
		t.Fatalf("GenerateDistributionPackage() error: %v", err)
	}

	// Verify archive contains screenshots directory and the file.
	f, err := os.Open(archivePath)
	if err != nil {
		t.Fatalf("opening archive: %v", err)
	}
	defer func() { _ = f.Close() }()

	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	foundScreenshot := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("reading tar: %v", err)
		}
		if strings.HasPrefix(hdr.Name, "screenshots/") && strings.HasSuffix(hdr.Name, ".jpeg") {
			foundScreenshot = true
			// Verify screenshot has sanitized name (gowitness naming convention).
			expected := "screenshots/http--192.168.1.10-80.jpeg"
			if hdr.Name != expected {
				t.Errorf("screenshot name = %q, want %q", hdr.Name, expected)
			}
		}

		// Verify markdown contains Obsidian callout.
		if hdr.Name == "windows.md" {
			var buf strings.Builder
			if _, err := io.Copy(&buf, tr); err != nil {
				t.Fatalf("reading windows.md: %v", err)
			}
			content := buf.String()
			if !strings.Contains(content, "> [!screenshot]-") {
				t.Error("windows.md missing Obsidian callout")
			}
			if !strings.Contains(content, "[[screenshots/") {
				t.Error("windows.md missing wikilink screenshot reference")
			}
		}
	}

	if !foundScreenshot {
		t.Error("archive missing screenshot file")
	}
}

func TestGenerateDistributionPackageNoCategorizedHosts(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := t.TempDir()

	c := newCorrelatorWithDataDir(tmpDir, dataDir)

	// Only unknown hosts.
	c.correlations["192.168.1.99"] = &CorrelationResult{
		Host: "192.168.1.99",
		HostInfo: &Host{
			Attributes: map[string]string{"category": "unknown"},
		},
		Metadata: map[string]any{},
	}

	_, err := c.GenerateDistributionPackage()
	if err == nil {
		t.Fatal("expected error for no categorized hosts")
	}
	if !strings.Contains(err.Error(), "no categorized hosts") {
		t.Errorf("error = %q, want 'no categorized hosts'", err.Error())
	}
}

func TestCompareIPsNumeric(t *testing.T) {
	tests := []struct {
		a, b string
		want bool // a < b
	}{
		{"192.168.1.1", "192.168.1.2", true},
		{"192.168.1.10", "192.168.1.2", false},
		{"10.0.0.1", "192.168.1.1", true},
		{"192.168.1.1", "192.168.1.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.a+"_"+tt.b, func(t *testing.T) {
			got := compareIPsNumeric(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("compareIPsNumeric(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}
