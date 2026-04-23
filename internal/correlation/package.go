package correlation

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// CategoryFileNames maps category keys to their markdown output filenames.
var categoryFileNames = map[string]string{
	"windows":        "windows.md",
	"linux":          "linux.md",
	"network_device": "network_devices.md",
}

// CategoryTitles maps category keys to their markdown heading text.
var categoryTitles = map[string]string{
	"windows":        "Windows Hosts",
	"linux":          "Linux Hosts",
	"network_device": "Network Devices",
}

// HostEntry is a row in the distribution markdown table.
type HostEntry struct {
	IP              string
	Hostname        string
	Vendor          string
	OSDetection     string
	OpenPorts       string // comma-separated sorted port numbers
	Notes           string // Obsidian screenshot callout markdown (may be empty)
	ScreenshotFiles []ScreenshotInfo
}

// GenerateDistributionPackage creates a tar.gz archive containing categorized
// markdown hostlists and screenshot files. The archive is written to
// {workspaceDir}/discovery/hostfile_distribution_YYYYMMDD_HHMMSS.tar.gz.
func (c *Correlator) GenerateDistributionPackage() (string, error) {
	correlations := c.GetAllCorrelations()

	// Build host entries grouped by category.
	categoryEntries := make(map[string][]HostEntry)
	for ip, corr := range correlations {
		cat := hostCategoryFromResult(corr)
		if cat == "unknown" || cat == "" {
			continue
		}
		entry := buildHostEntry(ip, corr)
		categoryEntries[cat] = append(categoryEntries[cat], entry)
	}

	if len(categoryEntries) == 0 {
		return "", fmt.Errorf("no categorized hosts to package")
	}

	// Sort entries within each category by IP.
	for cat := range categoryEntries {
		sort.Slice(categoryEntries[cat], func(i, j int) bool {
			return compareIPsNumeric(categoryEntries[cat][i].IP, categoryEntries[cat][j].IP)
		})
	}

	timestamp := time.Now()
	ts := timestamp.Format("20060102_150405")
	archiveName := fmt.Sprintf("hostfile_distribution_%s.tar.gz", ts)

	discoveryDir := filepath.Join(c.workspaceDir, "discovery")
	if err := os.MkdirAll(discoveryDir, 0755); err != nil {
		return "", fmt.Errorf("creating discovery directory: %w", err)
	}
	archivePath := filepath.Join(discoveryDir, archiveName)

	tmpDir, err := os.MkdirTemp("", "netutil-package-*")
	if err != nil {
		return "", fmt.Errorf("creating temp directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Write markdown files.
	for cat, fileName := range categoryFileNames {
		entries, ok := categoryEntries[cat]
		if !ok || len(entries) == 0 {
			continue
		}
		if err := writeMarkdownFile(filepath.Join(tmpDir, fileName), cat, entries); err != nil {
			return "", fmt.Errorf("writing %s: %w", fileName, err)
		}
	}

	// Copy screenshot files.
	screenshotsDir := filepath.Join(tmpDir, "screenshots")
	hasScreenshots := false
	for _, entries := range categoryEntries {
		for _, e := range entries {
			if len(e.ScreenshotFiles) > 0 {
				hasScreenshots = true
				break
			}
		}
		if hasScreenshots {
			break
		}
	}
	if hasScreenshots {
		if err := os.MkdirAll(screenshotsDir, 0755); err != nil {
			return "", fmt.Errorf("creating screenshots directory: %w", err)
		}
		for _, entries := range categoryEntries {
			for _, e := range entries {
				for _, ss := range e.ScreenshotFiles {
					destName := filepath.Base(ss.File)
					destPath := filepath.Join(screenshotsDir, destName)
					if err := copyFile(ss.File, destPath); err != nil {
						// Best-effort: missing screenshots should not abort the package.
						_, _ = fmt.Fprintf(os.Stderr, "warning: skipping screenshot %s: %v\n", ss.File, err)
					}
				}
			}
		}
	}

	// Write metadata.
	if err := writeMetadata(filepath.Join(tmpDir, "metadata.txt"), timestamp, categoryEntries); err != nil {
		return "", fmt.Errorf("writing metadata: %w", err)
	}

	// Create archive.
	if err := createTarGz(tmpDir, archivePath); err != nil {
		return "", fmt.Errorf("creating archive: %w", err)
	}

	return archivePath, nil
}

// hostCategoryFromResult returns the category from HostInfo.Attributes,
// falling back to "unknown".
func hostCategoryFromResult(corr *CorrelationResult) string {
	if corr != nil && corr.HostInfo != nil {
		if cat, ok := corr.HostInfo.Attributes["category"]; ok && cat != "" {
			return cat
		}
	}
	return "unknown"
}

// buildHostEntry extracts a HostEntry from a CorrelationResult.
func buildHostEntry(ip string, corr *CorrelationResult) HostEntry {
	entry := HostEntry{
		IP: ip,
	}

	if corr.HostInfo != nil {
		entry.Hostname = corr.HostInfo.Hostname
		if nb, ok := corr.HostInfo.Attributes["netbios_name"]; ok && nb != "" && entry.Hostname == "" {
			entry.Hostname = nb
		}
		if v, ok := corr.HostInfo.Attributes["vendor"]; ok && v != "" {
			entry.Vendor = v
		}
		if corr.HostInfo.OSDetails != "" {
			entry.OSDetection = corr.HostInfo.OSDetails
		} else if corr.HostInfo.OS != "" {
			entry.OSDetection = corr.HostInfo.OS
		}

		var portNums []int
		for _, p := range corr.HostInfo.Ports {
			if p.State == "open" {
				portNums = append(portNums, p.Number)
			}
		}
		sort.Ints(portNums)
		var ports []string
		for _, n := range portNums {
			ports = append(ports, strconv.Itoa(n))
		}
		if len(ports) > 0 {
			entry.OpenPorts = strings.Join(ports, ", ")
		}
	}

	// Screenshots.
	screenshots := GetScreenshotsForHost(corr)
	if len(screenshots) > 0 {
		entry.ScreenshotFiles = screenshots
		entry.Notes = formatScreenshotNotes(screenshots)
	}

	return entry
}

// formatScreenshotNotes generates Obsidian foldable callout markdown for
// each screenshot. Multiple screenshots are separated by HTML <br> tags
// so they render inline within a markdown table cell.
func formatScreenshotNotes(screenshots []ScreenshotInfo) string {
	var blocks []string
	for _, ss := range screenshots {
		label := fmt.Sprintf("%s (%s)", ss.URL, ss.StatusCode)
		block := fmt.Sprintf("> [!screenshot]- %s\n> [[screenshots/%s]]", label, filepath.Base(ss.File))
		blocks = append(blocks, block)
	}
	return strings.Join(blocks, "<br>")
}

// writeMarkdownFile writes a markdown file with a table of host entries.
func writeMarkdownFile(path, category string, entries []HostEntry) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	w := bufio.NewWriter(f)

	title := categoryTitles[category]
	if title == "" {
		title = category
	}

	_, _ = fmt.Fprintf(w, "# %s\n\n", title)
	_, _ = fmt.Fprintf(w, "| IP | Hostname | MAC Vendor | OS Detection | Top 1k TCP Ports | Notes | Check |\n")
	_, _ = fmt.Fprintf(w, "|---|---|---|---|---|---|---|\n")

	for _, e := range entries {
		hostname := e.Hostname
		if hostname == "" {
			hostname = "-"
		}
		vendor := e.Vendor
		if vendor == "" {
			vendor = "-"
		}
		osDet := e.OSDetection
		if osDet == "" {
			osDet = "-"
		}
		ports := e.OpenPorts
		if ports == "" {
			ports = "-"
		}
		notes := e.Notes
		if notes == "" {
			notes = " "
		}
		_, _ = fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s |  |\n",
			e.IP, hostname, vendor, osDet, ports, notes)
	}

	return w.Flush()
}

// writeMetadata creates a metadata.txt with timestamp and host counts.
func writeMetadata(path string, ts time.Time, categoryEntries map[string][]HostEntry) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	w := bufio.NewWriter(f)
	_, _ = fmt.Fprintf(w, "Generated: %s\n", ts.Format(time.RFC3339))
	total := 0
	// Write categories in a stable order.
	for _, cat := range []string{"windows", "linux", "network_device"} {
		entries := categoryEntries[cat]
		count := len(entries)
		total += count
		_, _ = fmt.Fprintf(w, "%s: %d\n", cat, count)
	}
	_, _ = fmt.Fprintf(w, "total: %d\n", total)
	return w.Flush()
}

// copyFile copies src to dst. Creates dst parent directories if needed.
func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	_, err = io.Copy(out, in)
	return err
}

// createTarGz creates a tar.gz archive of the contents of srcDir at dstPath.
func createTarGz(srcDir, dstPath string) error {
	out, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	gw := gzip.NewWriter(out)
	defer func() { _ = gw.Close() }()

	tw := tar.NewWriter(gw)
	defer func() { _ = tw.Close() }()

	return filepath.Walk(srcDir, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(srcDir, filePath)
		if err != nil {
			return err
		}
		if relPath == "." {
			return nil
		}

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = relPath

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		return copyFileToTar(tw, filePath)
	})
}

func copyFileToTar(tw *tar.Writer, filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = io.Copy(tw, f)
	return err
}

// compareIPsNumeric sorts by numeric octet comparison.
func compareIPsNumeric(a, b string) bool {
	p1 := strings.Split(a, ".")
	p2 := strings.Split(b, ".")
	for i := 0; i < 4 && i < len(p1) && i < len(p2); i++ {
		n1, _ := strconv.Atoi(p1[i])
		n2, _ := strconv.Atoi(p2[i])
		if n1 != n2 {
			return n1 < n2
		}
	}
	return a < b
}
