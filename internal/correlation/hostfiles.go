package correlation

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var categoryPlainFile = map[string]string{
	"windows":        "windows_hosts.txt",
	"linux":          "linux_hosts.txt",
	"network_device": "network_devices.txt",
	"unknown":        "unknown.txt",
}

var categoryEnrichedFile = map[string]string{
	"windows":        "windows_hosts_enriched.txt",
	"linux":          "linux_hosts_enriched.txt",
	"network_device": "network_devices_enriched.txt",
	"unknown":        "unknown_enriched.txt",
}

func allCategoryFiles() []string {
	out := make([]string, 0, len(categoryPlainFile)+len(categoryEnrichedFile))
	for _, f := range categoryPlainFile {
		out = append(out, f)
	}
	for _, f := range categoryEnrichedFile {
		out = append(out, f)
	}
	return out
}

// MoveHostInHostfiles removes ip from all category files in every session
// hostfiles/ directory under workspaceDir/discovery/ that contains the host,
// then appends the bare IP to the plain file for newCategory.
// Sessions where ip is absent are skipped entirely.
func MoveHostInHostfiles(workspaceDir, ip, newCategory string) error {
	targetFile, ok := categoryPlainFile[newCategory]
	if !ok {
		return fmt.Errorf("unknown category %q", newCategory)
	}

	discoveryDir := filepath.Join(workspaceDir, "discovery")
	entries, err := os.ReadDir(discoveryDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading discovery dir: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		hostfilesDir := filepath.Join(discoveryDir, entry.Name(), "hostfiles")
		if _, statErr := os.Stat(hostfilesDir); os.IsNotExist(statErr) {
			continue
		}
		_ = moveHostInSession(hostfilesDir, ip, targetFile)
	}
	return nil
}

func moveHostInSession(hostfilesDir, ip, targetPlainFile string) error {
	found := false
	for _, fname := range allCategoryFiles() {
		if containsIP(filepath.Join(hostfilesDir, fname), ip) {
			found = true
			break
		}
	}
	if !found {
		return nil
	}

	for _, fname := range allCategoryFiles() {
		if err := removeIPFromFile(filepath.Join(hostfilesDir, fname), ip); err != nil {
			return err
		}
	}

	target := filepath.Join(hostfilesDir, targetPlainFile)
	f, err := os.OpenFile(target, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("opening %s: %w", target, err)
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, ip)
	return err
}

// containsIP returns true if path contains a line whose first whitespace-separated
// token equals ip. Comment lines and missing files return false.
func containsIP(path, ip string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == ip {
			return true
		}
	}
	return false
}

// removeIPFromFile rewrites path with all lines whose first token is ip removed.
// Missing files are silently skipped.
func removeIPFromFile(path, ip string) error {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("opening %s: %w", path, err)
	}

	var keep []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			fields := strings.Fields(trimmed)
			if len(fields) > 0 && fields[0] == ip {
				continue
			}
		}
		keep = append(keep, line)
	}
	f.Close()

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scanning %s: %w", path, err)
	}

	out := strings.Join(keep, "\n")
	if len(keep) > 0 {
		out += "\n"
	}
	return os.WriteFile(path, []byte(out), 0644)
}
