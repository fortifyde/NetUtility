package correlation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func makeSession(t *testing.T, discoveryDir, sessionName string, files map[string]string) string {
	t.Helper()
	hostfilesDir := filepath.Join(discoveryDir, sessionName, "hostfiles")
	if err := os.MkdirAll(hostfilesDir, 0750); err != nil {
		t.Fatalf("makeSession: %v", err)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(hostfilesDir, name), []byte(content), 0600); err != nil {
			t.Fatalf("makeSession WriteFile: %v", err)
		}
	}
	return hostfilesDir
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: test path
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		t.Fatalf("readFile %s: %v", path, err)
	}
	return string(data)
}

func TestMoveHostInHostfiles_BasicMove(t *testing.T) {
	ws := t.TempDir()
	discoveryDir := filepath.Join(ws, "discovery")

	makeSession(t, discoveryDir, "session1", map[string]string{
		"windows_hosts.txt": "10.0.0.1\n10.0.0.2\n",
		"linux_hosts.txt":   "10.0.0.3\n",
	})

	if err := MoveHostInHostfiles(ws, "10.0.0.1", "linux"); err != nil {
		t.Fatalf("MoveHostInHostfiles: %v", err)
	}

	hf := filepath.Join(discoveryDir, "session1", "hostfiles")

	win := readFile(t, filepath.Join(hf, "windows_hosts.txt"))
	if strings.Contains(win, "10.0.0.1") {
		t.Errorf("10.0.0.1 still in windows_hosts.txt:\n%s", win)
	}
	if !strings.Contains(win, "10.0.0.2") {
		t.Errorf("10.0.0.2 unexpectedly removed from windows_hosts.txt:\n%s", win)
	}

	lin := readFile(t, filepath.Join(hf, "linux_hosts.txt"))
	if !strings.Contains(lin, "10.0.0.1") {
		t.Errorf("10.0.0.1 not found in linux_hosts.txt:\n%s", lin)
	}
}

func TestMoveHostInHostfiles_SkipsSessionWithoutHost(t *testing.T) {
	ws := t.TempDir()
	discoveryDir := filepath.Join(ws, "discovery")

	makeSession(t, discoveryDir, "session1", map[string]string{
		"windows_hosts.txt": "10.0.0.1\n",
	})
	makeSession(t, discoveryDir, "session2", map[string]string{
		"linux_hosts.txt": "10.0.0.99\n",
	})

	if err := MoveHostInHostfiles(ws, "10.0.0.1", "linux"); err != nil {
		t.Fatalf("MoveHostInHostfiles: %v", err)
	}

	hf2 := filepath.Join(discoveryDir, "session2", "hostfiles")
	lin2 := readFile(t, filepath.Join(hf2, "linux_hosts.txt"))
	if strings.Count(lin2, "10.0.0.1") != 0 {
		t.Errorf("10.0.0.1 unexpectedly added to session2 linux_hosts.txt:\n%s", lin2)
	}
}

func TestMoveHostInHostfiles_HandlesEnrichedFiles(t *testing.T) {
	ws := t.TempDir()
	discoveryDir := filepath.Join(ws, "discovery")

	makeSession(t, discoveryDir, "session1", map[string]string{
		"windows_hosts.txt":          "10.0.0.5\n",
		"windows_hosts_enriched.txt": "# Enriched windows hosts\n10.0.0.5 DESKTOP-ABC Windows_10 [smb,rdp]\n",
	})

	if err := MoveHostInHostfiles(ws, "10.0.0.5", "linux"); err != nil {
		t.Fatalf("MoveHostInHostfiles: %v", err)
	}

	hf := filepath.Join(discoveryDir, "session1", "hostfiles")

	enriched := readFile(t, filepath.Join(hf, "windows_hosts_enriched.txt"))
	if strings.Contains(enriched, "10.0.0.5") {
		t.Errorf("10.0.0.5 still in windows_hosts_enriched.txt:\n%s", enriched)
	}

	lin := readFile(t, filepath.Join(hf, "linux_hosts.txt"))
	if !strings.Contains(lin, "10.0.0.5") {
		t.Errorf("10.0.0.5 not found in linux_hosts.txt:\n%s", lin)
	}

	linEnriched := readFile(t, filepath.Join(hf, "linux_hosts_enriched.txt"))
	if !strings.Contains(linEnriched, "10.0.0.5") {
		t.Errorf("10.0.0.5 not found in linux_hosts_enriched.txt (enriched data should be preserved):\n%s", linEnriched)
	}
	// Category should be updated to "linux" in the enriched data
	if !strings.Contains(linEnriched, "linux") {
		t.Errorf("enriched data not updated with new category 'linux':\n%s", linEnriched)
	}
}

func TestMoveHostInHostfiles_CommentLinesPreserved(t *testing.T) {
	ws := t.TempDir()
	discoveryDir := filepath.Join(ws, "discovery")

	makeSession(t, discoveryDir, "session1", map[string]string{
		"linux_hosts_enriched.txt": "# header\n10.0.0.7 host1 Linux [ssh]\n10.0.0.8 host2 Linux [ssh]\n",
	})

	if err := MoveHostInHostfiles(ws, "10.0.0.7", "windows"); err != nil {
		t.Fatalf("MoveHostInHostfiles: %v", err)
	}

	hf := filepath.Join(discoveryDir, "session1", "hostfiles")
	enriched := readFile(t, filepath.Join(hf, "linux_hosts_enriched.txt"))

	if !strings.Contains(enriched, "# header") {
		t.Errorf("comment line removed:\n%s", enriched)
	}
	if !strings.Contains(enriched, "10.0.0.8") {
		t.Errorf("unrelated host removed:\n%s", enriched)
	}
	if strings.Contains(enriched, "10.0.0.7") {
		t.Errorf("moved host still present:\n%s", enriched)
	}
}

func TestMoveHostInHostfiles_NoDiscoveryDir(t *testing.T) {
	ws := t.TempDir()
	if err := MoveHostInHostfiles(ws, "10.0.0.1", "linux"); err != nil {
		t.Errorf("expected nil error with missing discovery dir, got: %v", err)
	}
}

func TestMoveHostInHostfiles_UnknownCategory(t *testing.T) {
	ws := t.TempDir()
	err := MoveHostInHostfiles(ws, "10.0.0.1", "banana")
	if err == nil {
		t.Error("expected error for unknown category, got nil")
	}
}

// makeNestedSession creates a hostfiles directory at an arbitrary depth under discoveryDir.
// e.g. makeNestedSession(t, dir, "auto_discovery/vlan_10") creates
//
//	<dir>/discovery/auto_discovery/vlan_10/hostfiles/
func makeNestedSession(t *testing.T, discoveryDir, subpath string, files map[string]string) string {
	t.Helper()
	hostfilesDir := filepath.Join(discoveryDir, subpath, "hostfiles")
	if err := os.MkdirAll(hostfilesDir, 0750); err != nil {
		t.Fatalf("makeNestedSession: %v", err)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(hostfilesDir, name), []byte(content), 0600); err != nil {
			t.Fatalf("makeNestedSession WriteFile: %v", err)
		}
	}
	return hostfilesDir
}

func TestMoveHostInHostfiles_NestedAutoDiscover(t *testing.T) {
	ws := t.TempDir()
	discoveryDir := filepath.Join(ws, "discovery")

	// Create a nested auto_discover session with hostfiles two levels deep
	makeNestedSession(t, discoveryDir, "auto_discovery/vlan_10", map[string]string{
		"windows_hosts.txt": "10.0.0.1\n10.0.0.2\n",
	})

	// Also create a standalone session at the top level
	makeSession(t, discoveryDir, "main_network", map[string]string{
		"linux_hosts.txt": "10.0.0.3\n",
	})

	if err := MoveHostInHostfiles(ws, "10.0.0.1", "linux"); err != nil {
		t.Fatalf("MoveHostInHostfiles: %v", err)
	}

	// Verify 10.0.0.1 was moved in the nested session
	nestedHF := filepath.Join(discoveryDir, "auto_discovery", "vlan_10", "hostfiles")
	win := readFile(t, filepath.Join(nestedHF, "windows_hosts.txt"))
	if strings.Contains(win, "10.0.0.1") {
		t.Errorf("10.0.0.1 still in nested windows_hosts.txt:\n%s", win)
	}
	lin := readFile(t, filepath.Join(nestedHF, "linux_hosts.txt"))
	if !strings.Contains(lin, "10.0.0.1") {
		t.Errorf("10.0.0.1 not found in nested linux_hosts.txt:\n%s", lin)
	}

	// Verify standalone session was NOT touched (10.0.0.1 was not in it)
	standaloneHF := filepath.Join(discoveryDir, "main_network", "hostfiles")
	standaloneLin := readFile(t, filepath.Join(standaloneHF, "linux_hosts.txt"))
	if strings.Contains(standaloneLin, "10.0.0.1") {
		t.Errorf("10.0.0.1 incorrectly added to standalone linux_hosts.txt:\n%s", standaloneLin)
	}
}

func TestMoveHostInHostfiles_L3BareIDDir(t *testing.T) {
	ws := t.TempDir()
	discoveryDir := filepath.Join(ws, "discovery")

	// L3 mode auto_discover with bare numeric directory
	makeNestedSession(t, discoveryDir, "auto_discovery/42", map[string]string{
		"unknown.txt": "10.0.0.50\n10.0.0.51\n",
	})

	if err := MoveHostInHostfiles(ws, "10.0.0.50", "network_device"); err != nil {
		t.Fatalf("MoveHostInHostfiles: %v", err)
	}

	nestedHF := filepath.Join(discoveryDir, "auto_discovery", "42", "hostfiles")
	unknown := readFile(t, filepath.Join(nestedHF, "unknown.txt"))
	if strings.Contains(unknown, "10.0.0.50") {
		t.Errorf("10.0.0.50 still in unknown.txt:\n%s", unknown)
	}
	nd := readFile(t, filepath.Join(nestedHF, "network_devices.txt"))
	if !strings.Contains(nd, "10.0.0.50") {
		t.Errorf("10.0.0.50 not found in network_devices.txt:\n%s", nd)
	}
}

func TestMoveHostInHostfilesSkipsArchive(t *testing.T) {
	ws := t.TempDir()
	discoveryDir := filepath.Join(ws, "discovery")

	// Archived session — must remain an immutable snapshot
	makeNestedSession(t, discoveryDir, "archive/old", map[string]string{
		"windows_hosts.txt": "10.0.0.1\n",
	})
	// Live session — recategorization applies here
	makeNestedSession(t, discoveryDir, "live", map[string]string{
		"windows_hosts.txt": "10.0.0.1\n",
	})

	if err := MoveHostInHostfiles(ws, "10.0.0.1", "linux"); err != nil {
		t.Fatalf("MoveHostInHostfiles: %v", err)
	}

	archivedWin := readFile(t, filepath.Join(discoveryDir, "archive", "old", "hostfiles", "windows_hosts.txt"))
	if archivedWin != "10.0.0.1\n" {
		t.Errorf("archived windows_hosts.txt was modified:\n%s", archivedWin)
	}

	liveHF := filepath.Join(discoveryDir, "live", "hostfiles")
	liveWin := readFile(t, filepath.Join(liveHF, "windows_hosts.txt"))
	if strings.Contains(liveWin, "10.0.0.1") {
		t.Errorf("10.0.0.1 still in live windows_hosts.txt:\n%s", liveWin)
	}
	liveLin := readFile(t, filepath.Join(liveHF, "linux_hosts.txt"))
	if !strings.Contains(liveLin, "10.0.0.1") {
		t.Errorf("10.0.0.1 not found in live linux_hosts.txt:\n%s", liveLin)
	}
}

func TestRemoveHostFromHostfiles_RemovesFromAllCategoryFiles(t *testing.T) {
	ws := t.TempDir()
	discoveryDir := filepath.Join(ws, "discovery")

	hf := makeSession(t, discoveryDir, "session1", map[string]string{
		"windows_hosts.txt":          "10.0.0.1\n10.0.0.2\n",
		"windows_hosts_enriched.txt": "# header\n10.0.0.1 WINHOST windows [smb]\n",
		"linux_hosts.txt":            "10.0.0.99\n",
	})

	if err := RemoveHostFromHostfiles(ws, "10.0.0.1"); err != nil {
		t.Fatalf("RemoveHostFromHostfiles: %v", err)
	}

	win := readFile(t, filepath.Join(hf, "windows_hosts.txt"))
	if strings.Contains(win, "10.0.0.1") {
		t.Errorf("10.0.0.1 still in windows_hosts.txt:\n%s", win)
	}
	if !strings.Contains(win, "10.0.0.2") {
		t.Errorf("10.0.0.2 unexpectedly removed from windows_hosts.txt:\n%s", win)
	}

	enriched := readFile(t, filepath.Join(hf, "windows_hosts_enriched.txt"))
	if strings.Contains(enriched, "10.0.0.1") {
		t.Errorf("10.0.0.1 still in windows_hosts_enriched.txt:\n%s", enriched)
	}
	if !strings.Contains(enriched, "# header") {
		t.Errorf("comment line dropped from windows_hosts_enriched.txt:\n%s", enriched)
	}

	lin := readFile(t, filepath.Join(hf, "linux_hosts.txt"))
	if lin != "10.0.0.99\n" {
		t.Errorf("linux_hosts.txt changed:\n%s", lin)
	}

	// No new files may appear in the session hostfiles dir.
	entries, err := os.ReadDir(hf)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	got := map[string]bool{}
	for _, e := range entries {
		got[e.Name()] = true
	}
	want := map[string]bool{
		"windows_hosts.txt":          true,
		"windows_hosts_enriched.txt": true,
		"linux_hosts.txt":            true,
	}
	for name := range want {
		if !got[name] {
			t.Errorf("expected file %s missing from hostfiles dir: %v", name, got)
		}
	}
	for name := range got {
		if !want[name] {
			t.Errorf("unexpected file %s created in hostfiles dir", name)
		}
	}
}

func TestRemoveHostFromHostfiles_NoDiscoveryDir(t *testing.T) {
	ws := t.TempDir()
	if err := RemoveHostFromHostfiles(ws, "10.0.0.1"); err != nil {
		t.Fatalf("RemoveHostFromHostfiles: %v", err)
	}
	if _, err := os.Stat(filepath.Join(ws, "discovery")); !os.IsNotExist(err) {
		t.Errorf("discovery/ unexpectedly created: %v", err)
	}
}

func TestSyncManualOverridesToHostfiles_AppliesOverridesAfterRescan(t *testing.T) {
	ws := t.TempDir()
	discoveryDir := filepath.Join(ws, "discovery")

	// Fresh scan output: the host landed in the linux files even though the
	// override says network_device — exactly what a rescan produces today.
	hf := makeSession(t, discoveryDir, "main_network", map[string]string{
		"linux_hosts.txt":          "10.0.0.7\n10.0.0.8\n",
		"linux_hosts_enriched.txt": "10.0.0.7 web01 linux [ssh]\n",
	})

	c := newCorrelatorWithDataDir(ws, t.TempDir())
	if err := c.SetManualCategory("10.0.0.7", "network_device"); err != nil {
		t.Fatalf("SetManualCategory: %v", err)
	}
	if err := c.SyncManualOverridesToHostfiles(); err != nil {
		t.Fatalf("SyncManualOverridesToHostfiles: %v", err)
	}

	nd := readFile(t, filepath.Join(hf, "network_devices.txt"))
	if !strings.Contains(nd, "10.0.0.7") {
		t.Errorf("10.0.0.7 not found in network_devices.txt:\n%s", nd)
	}
	lin := readFile(t, filepath.Join(hf, "linux_hosts.txt"))
	if strings.Contains(lin, "10.0.0.7") {
		t.Errorf("10.0.0.7 still in linux_hosts.txt:\n%s", lin)
	}
	if !strings.Contains(lin, "10.0.0.8") {
		t.Errorf("10.0.0.8 unexpectedly removed from linux_hosts.txt:\n%s", lin)
	}
	linEnriched := readFile(t, filepath.Join(hf, "linux_hosts_enriched.txt"))
	if strings.Contains(linEnriched, "10.0.0.7") {
		t.Errorf("10.0.0.7 still in linux_hosts_enriched.txt:\n%s", linEnriched)
	}
	ndEnriched := readFile(t, filepath.Join(hf, "network_devices_enriched.txt"))
	if !strings.Contains(ndEnriched, "10.0.0.7 web01 network_device [ssh]") {
		t.Errorf("10.0.0.7 enriched line not carried over with rewritten category in network_devices_enriched.txt:\n%s", ndEnriched)
	}
}

func TestSyncManualOverridesToHostfiles_NoWritesWhenSettled(t *testing.T) {
	ws := t.TempDir()
	discoveryDir := filepath.Join(ws, "discovery")

	// Settled session: the host already sits exactly where the override wants
	// it. The line order (override IP first) and the double spaces in the
	// enriched line would not survive a rewrite, so any write is detectable
	// bytewise.
	hf := makeSession(t, discoveryDir, "main_network", map[string]string{
		"network_devices.txt":          "10.0.0.7\n10.0.0.8\n",
		"network_devices_enriched.txt": "10.0.0.7  sw01  network_device  [snmp,lag]\n",
	})

	c := newCorrelatorWithDataDir(ws, t.TempDir())
	if err := c.SetManualCategory("10.0.0.7", "network_device"); err != nil {
		t.Fatalf("SetManualCategory: %v", err)
	}
	for i := range 2 {
		if err := c.SyncManualOverridesToHostfiles(); err != nil {
			t.Fatalf("SyncManualOverridesToHostfiles run %d: %v", i+1, err)
		}
	}

	if got := readFile(t, filepath.Join(hf, "network_devices.txt")); got != "10.0.0.7\n10.0.0.8\n" {
		t.Errorf("settled network_devices.txt was rewritten:\n%s", got)
	}
	if got := readFile(t, filepath.Join(hf, "network_devices_enriched.txt")); got != "10.0.0.7  sw01  network_device  [snmp,lag]\n" {
		t.Errorf("settled network_devices_enriched.txt was rewritten:\n%s", got)
	}
	if got := readFile(t, filepath.Join(hf, "linux_hosts.txt")); got != "" {
		t.Errorf("linux_hosts.txt unexpectedly created:\n%s", got)
	}
}

func TestSyncManualOverridesToHostfiles_SkipsArchive(t *testing.T) {
	ws := t.TempDir()
	discoveryDir := filepath.Join(ws, "discovery")

	// Archived session — must remain an immutable snapshot.
	archivedHF := makeNestedSession(t, discoveryDir, "archive/old_session", map[string]string{
		"linux_hosts.txt": "10.0.0.1\n",
	})
	// Live session — sync applies here.
	liveHF := makeSession(t, discoveryDir, "live_session", map[string]string{
		"linux_hosts.txt": "10.0.0.1\n",
	})

	c := newCorrelatorWithDataDir(ws, t.TempDir())
	if err := c.SetManualCategory("10.0.0.1", "network_device"); err != nil {
		t.Fatalf("SetManualCategory: %v", err)
	}
	if err := c.SyncManualOverridesToHostfiles(); err != nil {
		t.Fatalf("SyncManualOverridesToHostfiles: %v", err)
	}

	if got := readFile(t, filepath.Join(archivedHF, "linux_hosts.txt")); got != "10.0.0.1\n" {
		t.Errorf("archived linux_hosts.txt was modified:\n%s", got)
	}
	if got := readFile(t, filepath.Join(archivedHF, "network_devices.txt")); got != "" {
		t.Errorf("archived session gained network_devices.txt:\n%s", got)
	}

	nd := readFile(t, filepath.Join(liveHF, "network_devices.txt"))
	if !strings.Contains(nd, "10.0.0.1") {
		t.Errorf("10.0.0.1 not healed into live network_devices.txt:\n%s", nd)
	}
	if got := readFile(t, filepath.Join(liveHF, "linux_hosts.txt")); strings.Contains(got, "10.0.0.1") {
		t.Errorf("10.0.0.1 still in live linux_hosts.txt:\n%s", got)
	}
}

func TestSyncManualOverridesToHostfiles_UnknownCategorySkipped(t *testing.T) {
	ws := t.TempDir()
	discoveryDir := filepath.Join(ws, "discovery")

	hf := makeSession(t, discoveryDir, "session1", map[string]string{
		"linux_hosts.txt": "10.0.0.1\n",
	})

	// Hand-edited override store with a bogus category, plus the
	// correlations.json that LoadResults requires before it reads overrides.
	dataDir := t.TempDir()
	corrDir := filepath.Join(dataDir, "correlations")
	if err := os.MkdirAll(corrDir, 0750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(corrDir, "correlations.json"), []byte("{}"), 0600); err != nil {
		t.Fatalf("writing correlations.json: %v", err)
	}
	overrideData, err := json.MarshalIndent(map[string]string{"10.0.0.1": "banana"}, "", "  ")
	if err != nil {
		t.Fatalf("marshalling overrides: %v", err)
	}
	if err := os.WriteFile(filepath.Join(corrDir, "manual_categories.json"), overrideData, 0600); err != nil {
		t.Fatalf("writing manual_categories.json: %v", err)
	}

	c := newCorrelatorWithDataDir(ws, dataDir)
	if err := c.LoadResults(); err != nil {
		t.Fatalf("LoadResults: %v", err)
	}
	if err := c.SyncManualOverridesToHostfiles(); err != nil {
		t.Fatalf("SyncManualOverridesToHostfiles: %v", err)
	}

	if got := readFile(t, filepath.Join(hf, "linux_hosts.txt")); got != "10.0.0.1\n" {
		t.Errorf("linux_hosts.txt changed by unknown-category override:\n%s", got)
	}
	entries, err := os.ReadDir(hf)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "linux_hosts.txt" {
		t.Errorf("unexpected files in hostfiles dir: %v", entries)
	}
}
