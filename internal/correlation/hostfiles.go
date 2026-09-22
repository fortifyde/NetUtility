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
// Per-session errors are discarded (best-effort); only invalid newCategory or
// an unreadable discovery dir returns an error.
func MoveHostInHostfiles(workspaceDir, ip, newCategory string) error {
	targetFile, ok := categoryPlainFile[newCategory]
	if !ok {
		return fmt.Errorf("unknown category %q", newCategory)
	}

	return walkLiveHostfilesDirs(workspaceDir, func(hostfilesDir string) error {
		return moveHostInSession(hostfilesDir, ip, targetFile, newCategory)
	})
}

// walkLiveHostfilesDirs walks every live session hostfiles/ directory under
// workspaceDir/discovery/, at any depth — standalone sessions as well as
// auto_discovery sessions with nested subdirectories — and calls fn on each.
// The top-level discovery/archive/ tree is skipped: archived sessions are
// immutable snapshots. The first fn error is recorded and the walk continues;
// it is returned after the walk completes. A missing discovery/ dir is a no-op.
func walkLiveHostfilesDirs(workspaceDir string, fn func(hostfilesDir string) error) error {
	discoveryDir := filepath.Join(workspaceDir, "discovery")
	if _, err := os.Stat(discoveryDir); os.IsNotExist(err) {
		return nil
	}

	var firstErr error
	err := filepath.WalkDir(discoveryDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		if d.Name() == "archive" && filepath.Dir(path) == discoveryDir {
			// Archived sessions are immutable snapshots — never rewritten.
			return fs.SkipDir
		}
		if d.Name() != "hostfiles" {
			return nil
		}
		// Found a hostfiles/ directory — process it
		if err := fn(path); err != nil && firstErr == nil {
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
	f, err := os.OpenFile(target, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644) //nolint:gosec // G304,G306: workspace output — user must be able to read/edit
	if err != nil {
		return fmt.Errorf("opening %s: %w", target, err)
	}
	defer func() { _ = f.Close() }()
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
		f2, err := os.OpenFile(targetEnriched, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644) //nolint:gosec // G304,G306: workspace output — user must be able to read/edit
		if err != nil {
			return fmt.Errorf("opening %s: %w", targetEnriched, err)
		}
		defer func() { _ = f2.Close() }()

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
	f, err := os.Open(path) //nolint:gosec // G304: path from trusted workspace
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
	_ = f.Close()

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
	return true, os.WriteFile(path, []byte(out), 0644) //nolint:gosec // G306: workspace output — user must be able to read/edit
}

// RemoveHostFromHostfiles removes ip from every category file (plain and
// enriched) in every session hostfiles/ directory under workspaceDir/discovery/.
// Best-effort per session, mirroring MoveHostInHostfiles: walks discovery/ at
// any depth, skips into hostfiles/ dirs only, records the first session error.
func RemoveHostFromHostfiles(workspaceDir, ip string) error {
	return walkLiveHostfilesDirs(workspaceDir, func(hostfilesDir string) error {
		var firstErr error
		for _, fname := range allCategoryFilenames {
			if _, err := removeIPFromFile(filepath.Join(hostfilesDir, fname), ip); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return firstErr
	})
}

// SyncManualOverridesToHostfiles re-applies manual category overrides
// (manual_categories.json) to every live session hostfiles/ directory in the
// workspace. New discovery scans regenerate hostfiles purely from scan
// evidence, which drops manual categorizations; this restores agreement
// between the override store and the per-session hostfiles that the config
// gathering scripts consume. Best-effort per session, mirroring
// MoveHostInHostfiles.
func (c *Correlator) SyncManualOverridesToHostfiles() error {
	c.mu.RLock()
	overrides := make(map[string]string, len(c.manualOverrides))
	for ip, cat := range c.manualOverrides {
		overrides[ip] = cat
	}
	workspaceDir := c.workspaceDir
	c.mu.RUnlock()

	if len(overrides) == 0 || workspaceDir == "" {
		return nil
	}

	return walkLiveHostfilesDirs(workspaceDir, func(hostfilesDir string) error {
		return syncOverridesInSession(hostfilesDir, overrides)
	})
}

// syncOverridesInSession applies the manual category overrides to a single
// hostfiles/ directory. Unknown category keys are skipped so a hand-edited
// manual_categories.json cannot fail the whole sync. The first error is
// recorded and the loop continues.
func syncOverridesInSession(hostfilesDir string, overrides map[string]string) error {
	var firstErr error
	for ip, cat := range overrides {
		target, ok := categoryPlainFile[cat]
		if !ok {
			continue
		}
		if hostFiledUnderCategory(hostfilesDir, ip, target) {
			continue
		}
		if err := moveHostInSession(hostfilesDir, ip, target, cat); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// hostFiledUnderCategory reports whether the session already agrees with the
// override: ip appears in no managed category file other than targetPlainFile
// and its enriched variant. A host missing from every file also returns true —
// moveHostInSession would skip such a session anyway. Syncs run on every
// correlation refresh, so this guard keeps settled sessions byte-stable
// instead of rewriting (and mtime-churning) files that already agree.
func hostFiledUnderCategory(hostfilesDir, ip, targetPlainFile string) bool {
	targetEnriched := strings.TrimSuffix(targetPlainFile, ".txt") + "_enriched.txt"
	for _, fname := range allCategoryFilenames {
		if fname == targetPlainFile || fname == targetEnriched {
			continue
		}
		// extractEnrichedDataForIP matches any line whose first token is ip,
		// so it works for plain files too.
		if extractEnrichedDataForIP(filepath.Join(hostfilesDir, fname), ip) != "" {
			return false
		}
	}
	return true
}

// extractEnrichedDataForIP reads an enriched file and returns the line for a specific IP.
// Returns the full line (with hostname, category, tags) or empty string if not found.
func extractEnrichedDataForIP(filepath, ip string) string {
	f, err := os.Open(filepath) //nolint:gosec // G304: path from trusted workspace
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()

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
