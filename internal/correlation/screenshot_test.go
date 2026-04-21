package correlation

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseScreenshotMarkers(t *testing.T) {
	tests := []struct {
		name       string
		output     string
		wantCount  int
		wantURL    string
		wantIP     string
		wantFile   string
		wantStatus string
	}{
		{
			name:       "single screenshot marker",
			output:     "##NETUTIL:SCREENSHOT## ip=192.168.1.1 url=http://192.168.1.1 file=/path/to/screenshot.png status=200",
			wantCount:  1,
			wantURL:    "http://192.168.1.1",
			wantIP:     "192.168.1.1",
			wantFile:   "/path/to/screenshot.png",
			wantStatus: "200",
		},
		{
			name: "multiple screenshot markers",
			output: `##NETUTIL:SCREENSHOT## ip=192.168.1.1 url=http://192.168.1.1 file=/path/to/screenshot1.png status=200
##NETUTIL:SCREENSHOT## ip=192.168.1.2 url=https://192.168.1.2 file=/path/to/screenshot2.png status=200`,
			wantCount: 2,
		},
		{
			name:       "marker with https URL and port",
			output:     "##NETUTIL:SCREENSHOT## ip=10.0.0.1 url=https://10.0.0.1:8443 file=/path/to/screenshot.png status=401",
			wantCount:  1,
			wantURL:    "https://10.0.0.1:8443",
			wantIP:     "10.0.0.1",
			wantFile:   "/path/to/screenshot.png",
			wantStatus: "401",
		},
		{
			name:       "marker with 404 status",
			output:     "##NETUTIL:SCREENSHOT## ip=192.168.1.100 url=http://192.168.1.100 file=/path/to/screenshot.png status=404",
			wantCount:  1,
			wantURL:    "http://192.168.1.100",
			wantIP:     "192.168.1.100",
			wantFile:   "/path/to/screenshot.png",
			wantStatus: "404",
		},
		{
			name:      "no screenshot markers",
			output:    "some other output\nwithout screenshot markers",
			wantCount: 0,
		},
		{
			name: "mixed output with screenshot markers",
			output: `Starting screenshot capture...
##NETUTIL:SCREENSHOT## ip=192.168.1.1 url=http://192.168.1.1 file=/path/to/screenshot1.png status=200
Processing...
##NETUTIL:SCREENSHOT## ip=192.168.1.2 url=https://192.168.1.2 file=/path/to/screenshot2.png status=200
Complete.`,
			wantCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseScreenshotMarkers(tt.output)

			if len(got) != tt.wantCount {
				t.Errorf("ParseScreenshotMarkers() returned %d items, want %d", len(got), tt.wantCount)
			}

			if tt.wantCount > 0 && tt.wantURL != "" {
				if len(got) == 0 {
					t.Errorf("ParseScreenshotMarkers() returned no items, want at least 1")
					return
				}
				if got[0].URL != tt.wantURL {
					t.Errorf("ParseScreenshotMarkers()[0].URL = %v, want %v", got[0].URL, tt.wantURL)
				}
				if got[0].IP != tt.wantIP {
					t.Errorf("ParseScreenshotMarkers()[0].IP = %v, want %v", got[0].IP, tt.wantIP)
				}
				if got[0].File != tt.wantFile {
					t.Errorf("ParseScreenshotMarkers()[0].File = %v, want %v", got[0].File, tt.wantFile)
				}
				if got[0].StatusCode != tt.wantStatus {
					t.Errorf("ParseScreenshotMarkers()[0].StatusCode = %v, want %v", got[0].StatusCode, tt.wantStatus)
				}
			}
		})
	}
}

func TestMergeScreenshotsIntoCorrelation(t *testing.T) {
	tests := []struct {
		name        string
		corr        *CorrelationResult
		screenshots []ScreenshotInfo
		wantCount   int
	}{
		{
			name: "merge into empty correlation",
			corr: &CorrelationResult{
				Host:     "192.168.1.1",
				Metadata: make(map[string]any),
			},
			screenshots: []ScreenshotInfo{
				{
					IP:         "192.168.1.1",
					URL:        "http://192.168.1.1",
					File:       "/path/to/screenshot1.png",
					StatusCode: "200",
				},
			},
			wantCount: 1,
		},
		{
			name: "merge multiple screenshots",
			corr: &CorrelationResult{
				Host:     "192.168.1.1",
				Metadata: make(map[string]any),
			},
			screenshots: []ScreenshotInfo{
				{
					IP:         "192.168.1.1",
					URL:        "http://192.168.1.1",
					File:       "/path/to/screenshot1.png",
					StatusCode: "200",
				},
				{
					IP:         "192.168.1.1",
					URL:        "https://192.168.1.1",
					File:       "/path/to/screenshot2.png",
					StatusCode: "200",
				},
			},
			wantCount: 2,
		},
		{
			name: "deduplicate existing screenshots",
			corr: &CorrelationResult{
				Host: "192.168.1.1",
				Metadata: map[string]any{
					"screenshots": []map[string]string{
						{
							"url":         "http://192.168.1.1",
							"file":        "/path/to/screenshot1.png",
							"status_code": "200",
						},
					},
				},
			},
			screenshots: []ScreenshotInfo{
				{
					IP:         "192.168.1.1",
					URL:        "http://192.168.1.1",
					File:       "/path/to/screenshot1.png",
					StatusCode: "200",
				},
			},
			wantCount: 1, // Should not duplicate
		},
		{
			name: "nil correlation",
			corr: nil,
			screenshots: []ScreenshotInfo{
				{
					IP:         "192.168.1.1",
					URL:        "http://192.168.1.1",
					File:       "/path/to/screenshot.png",
					StatusCode: "200",
				},
			},
			wantCount: 0, // Should handle nil gracefully
		},
		{
			name: "empty screenshots list",
			corr: &CorrelationResult{
				Host:     "192.168.1.1",
				Metadata: make(map[string]any),
			},
			screenshots: []ScreenshotInfo{},
			wantCount:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			MergeScreenshotsIntoCorrelation(tt.corr, tt.screenshots)

			if tt.corr == nil {
				return
			}

			screenshotData, ok := tt.corr.Metadata["screenshots"]
			if !ok && tt.wantCount > 0 {
				t.Errorf("MergeScreenshotsIntoCorrelation() did not set screenshots in metadata")
				return
			}

			if tt.wantCount == 0 {
				// Either no screenshots key or empty slice is acceptable
				if !ok {
					return
				}
				if screenshots, ok := screenshotData.([]map[string]string); ok {
					if len(screenshots) != 0 {
						t.Errorf("MergeScreenshotsIntoCorrelation() returned %d screenshots, want 0", len(screenshots))
					}
				}
				return
			}

			screenshots, ok := screenshotData.([]map[string]string)
			if !ok {
				t.Errorf("MergeScreenshotsIntoCorrelation() screenshots is not []map[string]string type")
				return
			}

			if len(screenshots) != tt.wantCount {
				t.Errorf("MergeScreenshotsIntoCorrelation() returned %d screenshots, want %d", len(screenshots), tt.wantCount)
			}
		})
	}
}

func TestGetScreenshotsForHost(t *testing.T) {
	tests := []struct {
		name         string
		corr         *CorrelationResult
		wantCount    int
		wantFirstURL string
	}{
		{
			name: "host with screenshots",
			corr: &CorrelationResult{
				Host: "192.168.1.1",
				Metadata: map[string]any{
					"screenshots": []map[string]string{
						{
							"url":         "http://192.168.1.1",
							"file":        "/path/to/screenshot1.png",
							"status_code": "200",
						},
						{
							"url":         "https://192.168.1.1",
							"file":        "/path/to/screenshot2.png",
							"status_code": "200",
						},
					},
				},
			},
			wantCount:    2,
			wantFirstURL: "http://192.168.1.1",
		},
		{
			name: "host with no screenshots",
			corr: &CorrelationResult{
				Host:     "192.168.1.2",
				Metadata: make(map[string]any),
			},
			wantCount: 0,
		},
		{
			name:      "nil correlation",
			corr:      nil,
			wantCount: 0,
		},
		{
			name: "host with nil metadata",
			corr: &CorrelationResult{
				Host:     "192.168.1.1",
				Metadata: nil,
			},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetScreenshotsForHost(tt.corr)

			if len(got) != tt.wantCount {
				t.Errorf("GetScreenshotsForHost() returned %d screenshots, want %d", len(got), tt.wantCount)
			}

			if tt.wantCount > 0 && len(got) > 0 && tt.wantFirstURL != "" {
				if got[0].URL != tt.wantFirstURL {
					t.Errorf("GetScreenshotsForHost()[0].URL = %v, want %v", got[0].URL, tt.wantFirstURL)
				}
				if got[0].IP != tt.corr.Host {
					t.Errorf("GetScreenshotsForHost()[0].IP = %v, want %v", got[0].IP, tt.corr.Host)
				}
			}
		})
	}
}

func TestFindScreenshotsOnDisk(t *testing.T) {
	t.Run("non-existent workspace directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		nonExistentDir := filepath.Join(tmpDir, "does_not_exist")

		got := FindScreenshotsOnDisk(nonExistentDir)

		if got == nil {
			t.Errorf("FindScreenshotsOnDisk() returned nil, want empty map")
		}

		if len(got) != 0 {
			t.Errorf("FindScreenshotsOnDisk() returned %d entries, want 0", len(got))
		}
	})

	t.Run("workspace without screenshots directory", func(t *testing.T) {
		tmpDir := t.TempDir()

		got := FindScreenshotsOnDisk(tmpDir)

		if got == nil {
			t.Errorf("FindScreenshotsOnDisk() returned nil, want empty map")
		}

		if len(got) != 0 {
			t.Errorf("FindScreenshotsOnDisk() returned %d entries, want 0", len(got))
		}
	})

	t.Run("workspace with screenshot JSONL file", func(t *testing.T) {
		tmpDir := t.TempDir()
		screenshotsDir := filepath.Join(tmpDir, "captures", "screenshots", "20250120_120000")
		if err := os.MkdirAll(screenshotsDir, 0755); err != nil {
			t.Fatalf("Failed to create screenshots directory: %v", err)
		}

		// Create a test JSONL file
		jsonlPath := filepath.Join(screenshotsDir, "gowitness.jsonl")
		jsonlContent := `{"url":"http://192.168.1.1","file":"/path/to/screenshot1.png","status":200}
{"url":"https://192.168.1.1","file":"/path/to/screenshot2.png","status":200}
{"url":"http://192.168.1.2","file":"/path/to/screenshot3.png","status":404}`
		if err := os.WriteFile(jsonlPath, []byte(jsonlContent), 0644); err != nil {
			t.Fatalf("Failed to write JSONL file: %v", err)
		}

		got := FindScreenshotsOnDisk(tmpDir)

		if len(got) == 0 {
			t.Errorf("FindScreenshotsOnDisk() returned 0 entries, want at least 1")
		}

		// Check for specific IPs
		if screenshots, ok := got["192.168.1.1"]; ok {
			if len(screenshots) != 2 {
				t.Errorf("FindScreenshotsOnDisk() returned %d screenshots for 192.168.1.1, want 2", len(screenshots))
			}
		} else {
			t.Errorf("FindScreenshotsOnDisk() did not find screenshots for 192.168.1.1")
		}

		if screenshots, ok := got["192.168.1.2"]; ok {
			if len(screenshots) != 1 {
				t.Errorf("FindScreenshotsOnDisk() returned %d screenshots for 192.168.1.2, want 1", len(screenshots))
			}
		} else {
			t.Errorf("FindScreenshotsOnDisk() did not find screenshots for 192.168.1.2")
		}
	})
}

func TestExtractIPFromURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "HTTP URL with IP",
			url:  "http://192.168.1.1",
			want: "192.168.1.1",
		},
		{
			name: "HTTPS URL with IP",
			url:  "https://10.0.0.1",
			want: "10.0.0.1",
		},
		{
			name: "URL with port",
			url:  "http://192.168.1.1:8080",
			want: "192.168.1.1",
		},
		{
			name: "URL with path",
			url:  "http://192.168.1.1/admin",
			want: "192.168.1.1",
		},
		{
			name: "URL with port and path",
			url:  "https://10.0.0.1:8443/login",
			want: "10.0.0.1",
		},
		{
			name: "hostname URL (not IP)",
			url:  "http://example.com",
			want: "",
		},
		{
			name: "hostname URL with port",
			url:  "https://example.com:443",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractIPFromURL(tt.url)
			if got != tt.want {
				t.Errorf("extractIPFromURL(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestGetStringFromMap(t *testing.T) {
	tests := []struct {
		name string
		m    map[string]interface{}
		key  string
		want string
	}{
		{
			name: "existing string key",
			m: map[string]interface{}{
				"url": "http://192.168.1.1",
			},
			key:  "url",
			want: "http://192.168.1.1",
		},
		{
			name: "missing key",
			m: map[string]interface{}{
				"url": "http://192.168.1.1",
			},
			key:  "file",
			want: "",
		},
		{
			name: "non-string value",
			m: map[string]interface{}{
				"status": 200,
			},
			key:  "status",
			want: "",
		},
		{
			name: "empty map",
			m:    map[string]interface{}{},
			key:  "url",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getStringFromMap(tt.m, tt.key)
			if got != tt.want {
				t.Errorf("getStringFromMap(%v, %q) = %v, want %v", tt.m, tt.key, got, tt.want)
			}
		})
	}
}

func TestParseScreenshotJSONL(t *testing.T) {
	t.Run("valid JSONL file", func(t *testing.T) {
		tmpDir := t.TempDir()
		jsonlPath := filepath.Join(tmpDir, "gowitness.jsonl")

		jsonlContent := `{"url":"http://192.168.1.1","file":"/path/to/screenshot1.png","status":200}
{"url":"https://192.168.1.1","file":"/path/to/screenshot2.png","status":200}
{"url":"http://192.168.1.2","file":"/path/to/screenshot3.png","status":404}`

		if err := os.WriteFile(jsonlPath, []byte(jsonlContent), 0644); err != nil {
			t.Fatalf("Failed to write JSONL file: %v", err)
		}

		got := parseScreenshotJSONL(jsonlPath)

		if len(got) != 3 {
			t.Errorf("parseScreenshotJSONL() returned %d screenshots, want 3", len(got))
		}

		// Check first screenshot
		if got[0].URL != "http://192.168.1.1" {
			t.Errorf("parseScreenshotJSONL()[0].URL = %v, want 'http://192.168.1.1'", got[0].URL)
		}
		if got[0].IP != "192.168.1.1" {
			t.Errorf("parseScreenshotJSONL()[0].IP = %v, want '192.168.1.1'", got[0].IP)
		}
		if got[0].StatusCode != "200" {
			t.Errorf("parseScreenshotJSONL()[0].StatusCode = %v, want '200'", got[0].StatusCode)
		}
	})

	t.Run("non-existent file", func(t *testing.T) {
		got := parseScreenshotJSONL("/does/not/exist.jsonl")

		if len(got) != 0 {
			t.Errorf("parseScreenshotJSONL() returned %d screenshots, want 0", len(got))
		}
	})

	t.Run("malformed JSONL file", func(t *testing.T) {
		tmpDir := t.TempDir()
		jsonlPath := filepath.Join(tmpDir, "gowitness.jsonl")

		jsonlContent := `{"url":"http://192.168.1.1","file":"/path/to/screenshot1.png","status":200}
invalid json line
{"url":"https://192.168.1.1","file":"/path/to/screenshot2.png","status":200}`

		if err := os.WriteFile(jsonlPath, []byte(jsonlContent), 0644); err != nil {
			t.Fatalf("Failed to write JSONL file: %v", err)
		}

		got := parseScreenshotJSONL(jsonlPath)

		// Should parse the valid lines and skip invalid
		if len(got) != 2 {
			t.Errorf("parseScreenshotJSONL() returned %d screenshots, want 2 (skipping invalid)", len(got))
		}
	})
}
