package correlation

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func makeSession(t *testing.T, discoveryDir, sessionName string, files map[string]string) string {
	t.Helper()
	hostfilesDir := filepath.Join(discoveryDir, sessionName, "hostfiles")
	if err := os.MkdirAll(hostfilesDir, 0755); err != nil {
		t.Fatalf("makeSession: %v", err)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(hostfilesDir, name), []byte(content), 0644); err != nil {
			t.Fatalf("makeSession WriteFile: %v", err)
		}
	}
	return hostfilesDir
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
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
	if strings.Contains(linEnriched, "10.0.0.5") {
		t.Errorf("10.0.0.5 unexpectedly in linux_hosts_enriched.txt:\n%s", linEnriched)
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
