package correlation

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ScreenshotInfo represents information about a web screenshot
type ScreenshotInfo struct {
	IP         string `json:"ip"`
	URL        string `json:"url"`
	File       string `json:"file"`
	StatusCode string `json:"status_code"`
}

// ParseScreenshotMarkers extracts screenshot information from NETUTIL markers
func ParseScreenshotMarkers(output string) []ScreenshotInfo {
	screenshots := make([]ScreenshotInfo, 0)
	lines := strings.Split(output, "\n")

	// Match pattern: ##NETUTIL:SCREENSHOT## ip=<ip> url=<url> file=<filepath> status=<code>
	markerRegex := regexp.MustCompile(`##NETUTIL:SCREENSHOT##\s+ip=([^\s]+)\s+url=([^\s]+)\s+file=([^\s]+)\s+status=([^\s]+)`)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "##NETUTIL:SCREENSHOT##") {
			continue
		}

		matches := markerRegex.FindStringSubmatch(line)
		if len(matches) < 5 {
			continue
		}

		screenshot := ScreenshotInfo{
			IP:         matches[1],
			URL:        matches[2],
			File:       matches[3],
			StatusCode: matches[4],
		}

		screenshots = append(screenshots, screenshot)
	}

	return screenshots
}

// MergeScreenshotsIntoCorrelation merges screenshot data into a correlation result
func MergeScreenshotsIntoCorrelation(corr *CorrelationResult, screenshots []ScreenshotInfo) {
	if corr == nil || len(screenshots) == 0 {
		return
	}

	// Initialize screenshots in metadata if not exists
	if corr.Metadata["screenshots"] == nil {
		corr.Metadata["screenshots"] = make([]map[string]string, 0)
	}

	// Get existing screenshots
	existingScreenshots, ok := corr.Metadata["screenshots"].([]map[string]string)
	if !ok {
		existingScreenshots = make([]map[string]string, 0)
	}

	// Merge new screenshots
	for _, ss := range screenshots {
		// Check if screenshot already exists
		exists := false
		for _, existing := range existingScreenshots {
			if existing["url"] == ss.URL && existing["file"] == ss.File {
				exists = true
				break
			}
		}

		if !exists {
			screenshotMap := map[string]string{
				"url":         ss.URL,
				"file":        ss.File,
				"status_code": ss.StatusCode,
			}
			existingScreenshots = append(existingScreenshots, screenshotMap)
		}
	}

	corr.Metadata["screenshots"] = existingScreenshots
}

// GetScreenshotsForHost retrieves screenshots for a specific host from correlation
func GetScreenshotsForHost(corr *CorrelationResult) []ScreenshotInfo {
	if corr == nil || corr.Metadata == nil {
		return nil
	}

	screenshots := make([]ScreenshotInfo, 0)

	screenshotData, ok := corr.Metadata["screenshots"]
	if !ok {
		return nil
	}

	// Handle different JSON unmarshaling results
	switch v := screenshotData.(type) {
	case []ScreenshotInfo:
		return v
	case []map[string]string:
		for _, ss := range v {
			screenshots = append(screenshots, ScreenshotInfo{
				IP:         corr.Host,
				URL:        ss["url"],
				File:       ss["file"],
				StatusCode: ss["status_code"],
			})
		}
	case []interface{}:
		for _, item := range v {
			if ssMap, ok := item.(map[string]interface{}); ok {
				screenshots = append(screenshots, ScreenshotInfo{
					IP:         corr.Host,
					URL:        getStringFromMap(ssMap, "url"),
					File:       getStringFromMap(ssMap, "file"),
					StatusCode: getStringFromMap(ssMap, "status_code"),
				})
			}
		}
	}

	return screenshots
}

// getStringFromMap safely extracts a string from a map[string]interface{}
func getStringFromMap(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

// FindScreenshotsOnDisk scans the workspace for existing screenshot files
// This handles both standalone sessions (1 level) and auto-discovery sessions (2 levels)
func FindScreenshotsOnDisk(workspaceDir string) map[string][]ScreenshotInfo {
	screenshotsByIP := make(map[string][]ScreenshotInfo)

	if workspaceDir == "" {
		return screenshotsByIP
	}

	screenshotsDir := filepath.Join(workspaceDir, "captures", "screenshots")
	if _, err := os.Stat(screenshotsDir); os.IsNotExist(err) {
		return screenshotsByIP
	}

	// Walk through all timestamped screenshot directories
	err := filepath.WalkDir(screenshotsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // Continue on error
		}

		// Skip directories
		if d.IsDir() {
			return nil
		}

		// Look for gowitness.jsonl files
		if filepath.Base(path) == "gowitness.jsonl" {
			sessionScreenshots := parseScreenshotJSONL(path)
			for _, ss := range sessionScreenshots {
				if ss.IP != "" {
					screenshotsByIP[ss.IP] = append(screenshotsByIP[ss.IP], ss)
				}
			}
		}

		return nil
	})

	if err != nil {
		// Log but don't fail - partial results are still useful
		fmt.Fprintf(os.Stderr, "warning: error scanning screenshots directory: %v\n", err)
	}

	return screenshotsByIP
}

// parseScreenshotJSONL parses a gowitness JSONL file
func parseScreenshotJSONL(jsonlPath string) []ScreenshotInfo {
	screenshots := make([]ScreenshotInfo, 0)

	file, err := os.Open(jsonlPath)
	if err != nil {
		return screenshots
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var gowitnessResult struct {
			URL    string `json:"url"`
			File   string `json:"file"`
			Status int    `json:"status"`
		}

		if err := json.Unmarshal([]byte(line), &gowitnessResult); err != nil {
			continue
		}

		// Extract IP from URL
		ip := extractIPFromURL(gowitnessResult.URL)

		screenshot := ScreenshotInfo{
			IP:         ip,
			URL:        gowitnessResult.URL,
			File:       gowitnessResult.File,
			StatusCode: fmt.Sprintf("%d", gowitnessResult.Status),
		}

		screenshots = append(screenshots, screenshot)
	}

	return screenshots
}

// extractIPFromURL extracts an IP address from a URL
func extractIPFromURL(urlStr string) string {
	// Remove protocol
	urlStr = strings.TrimPrefix(urlStr, "http://")
	urlStr = strings.TrimPrefix(urlStr, "https://")

	// Remove port and path
	urlStr = strings.Split(urlStr, "/")[0]
	urlStr = strings.Split(urlStr, ":")[0]

	// Validate IP format
	ipRegex := regexp.MustCompile(`^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$`)
	if ipRegex.MatchString(urlStr) {
		return urlStr
	}

	return "" // Not an IP URL (might be hostname)
}
