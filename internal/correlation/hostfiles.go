package correlation

import (
	"bufio"
	"fmt"
	"io/fs"
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

// allCategoryFiles returns every plain and enriched filename we manage, in a stable order.
var allCategoryFilenames = []string{
	"windows_hosts.txt",
	"linux_hosts.txt",
	"network_devices.txt",
	"unknown.txt",
	"windows_servers.txt",
	"windows_clients.txt",
	"windows_hosts_enriched.txt",
	"linux_hosts_enriched.txt",
	"network_devices_enriched.txt",
	"unknown_enriched.txt",
	"windows_servers_enriched.txt",
	"windows_clients_enriched.txt",
}

// MoveHostInHostfiles removes ip from all category files in every session
// hostfiles/ directory under workspaceDir/discovery/ that contains the host,
// then appends the bare IP to the plain file for newCategory.
// Sessions where ip is absent are skipped entirely.
// It recursively walks the discovery directory to find hostfiles/ at any depth,
// handling both standalone sessions and auto_discover sessions with nested subdirectories.
// Per-session errors are discarded (best-effort); only invalid newCategory or
// an unreadable discovery dir returns an error.
func MoveHostInHostfiles(workspaceDir, ip, newCategory string) error {
	targetFile, ok := categoryPlainFile[newCategory]
	if !ok {
		return fmt.Errorf("unknown category %q", newCategory)
	}

	discoveryDir := filepath.Join(workspaceDir, "discovery")
	if _, err := os.Stat(discoveryDir); os.IsNotExist(err) {
		return nil
	}

	var firstErr error
	err := filepath.WalkDir(discoveryDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if !d.IsDir() || d.Name() != "hostfiles" {
			return nil
		}
		// Found a hostfiles/ directory — process it
		if err := moveHostInSession(path, ip, targetFile, newCategory); err != nil && firstErr == nil {
			firstErr = err
		}
		return fs.SkipDir // Don't recurse into hostfiles/
	})
	if err != nil {
		return fmt.Errorf("walking discovery dir: %w", err)
	}
	return firstErr
}

// moveHostInSession handles a single hostfiles/ directory.
// It removes ip from any file that contains it, then appends it to targetPlainFile.
// If ip is not found in any file, the session is skipped entirely.
func moveHostInSession(hostfilesDir, ip, targetPlainFile, category string) error {
	found := false
	var enrichedData string // Track enriched data if found

	for _, fname := range allCategoryFilenames {
		path := filepath.Join(hostfilesDir, fname)

		// Extract enriched data BEFORE removing the IP line from the file.
		// removeIPFromFile rewrites the file without the matching line,
		// so we must read the enriched data first.
		if strings.Contains(fname, "_enriched") && enrichedData == "" {
			if data := extractEnrichedDataForIP(path, ip); data != "" {
				enrichedData = data
			}
		}

		removed, err := removeIPFromFile(path, ip)
		if err != nil {
			return err
		}
		if removed {
			found = true
		}
	}
	if !found {
		return nil
	}

	target := filepath.Join(hostfilesDir, targetPlainFile)
	f, err := os.OpenFile(target, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("opening %s: %w", target, err)
	}
	defer f.Close()
	if _, err := fmt.Fprintln(f, ip); err != nil {
		return err
	}

	// Also update enriched file if we had enriched data
	if enrichedData != "" {
		base := strings.TrimSuffix(targetPlainFile, ".txt")
		if base == targetPlainFile {
			return fmt.Errorf("expected .txt suffix in plain file %q", targetPlainFile)
		}
		targetEnriched := filepath.Join(hostfilesDir, base+"_enriched.txt")
		f2, err := os.OpenFile(targetEnriched, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("opening %s: %w", targetEnriched, err)
		}
		defer f2.Close()

		// Update the category field in the enriched data
		// Format: "IP HOSTNAME CATEGORY [tags]"
		fields := strings.Fields(enrichedData)
		if len(fields) >= 3 {
			fields[2] = category // Use the actual category name
			updatedEnrichedData := strings.Join(fields, " ")
			_, err = fmt.Fprintln(f2, updatedEnrichedData)
		} else {
			_, err = fmt.Fprintln(f2, enrichedData)
		}
		return err
	}

	return nil
}

// removeIPFromFile rewrites path with all lines whose first token is ip removed.
// Returns (true, nil) if any line was removed, (false, nil) if ip was not found,
// (false, err) on I/O error. Missing files return (false, nil).
func removeIPFromFile(path, ip string) (bool, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("opening %s: %w", path, err)
	}

	var keep []string
	removed := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			fields := strings.Fields(trimmed)
			if len(fields) > 0 && fields[0] == ip {
				removed = true
				continue
			}
		}
		keep = append(keep, line)
	}
	f.Close()

	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("scanning %s: %w", path, err)
	}

	if !removed {
		return false, nil
	}

	out := strings.Join(keep, "\n")
	if len(keep) > 0 {
		out += "\n"
	}
	return true, os.WriteFile(path, []byte(out), 0644)
}

// extractEnrichedDataForIP reads an enriched file and returns the line for a specific IP.
// Returns the full line (with hostname, category, tags) or empty string if not found.
func extractEnrichedDataForIP(filepath, ip string) string {
	f, err := os.Open(filepath)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			fields := strings.Fields(trimmed)
			if len(fields) > 0 && fields[0] == ip {
				return line // Return the full line with all enriched data
			}
		}
	}
	return ""
}
