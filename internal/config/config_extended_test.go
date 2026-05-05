package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetOriginalUserNonRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root — skipping non-root GetOriginalUser test")
	}

	// When not root and not sudo, should return current user
	u, err := GetOriginalUser()
	if err != nil {
		t.Fatalf("GetOriginalUser() error: %v", err)
	}
	if u == nil {
		t.Fatal("GetOriginalUser() returned nil user")
	}
	if u.Uid == "" {
		t.Error("User.Uid should not be empty")
	}
}

func TestFixWorkspaceOwnershipNotConfigured(t *testing.T) {
	cfg := GetDefaultConfig()
	// Default config has empty WorkspaceDir
	err := cfg.FixWorkspaceOwnership()
	if err == nil {
		t.Error("expected error for unconfigured workspace")
	}
}

func TestFixWorkspacePermissionsNotConfigured(t *testing.T) {
	cfg := GetDefaultConfig()
	err := cfg.FixWorkspacePermissions()
	if err == nil {
		t.Error("expected error for unconfigured workspace")
	}
}

func TestEnsureWorkspaceWritableNotConfigured(t *testing.T) {
	cfg := GetDefaultConfig()
	err := cfg.EnsureWorkspaceWritable()
	if err == nil {
		t.Error("expected error for unconfigured workspace")
	}
}

func TestCreateWorkspace(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := GetDefaultConfig()
	cfg.WorkspaceDir = filepath.Join(tmpDir, "workspace")

	err := cfg.CreateWorkspace()
	if err != nil {
		t.Fatalf("CreateWorkspace() error: %v", err)
	}

	// Verify subdirectories were created
	expectedSubdirs := []string{
		"captures", "discovery", "scans", "analysis",
		"reports", "configs", "logs", "latest",
	}
	for _, subdir := range expectedSubdirs {
		path := filepath.Join(cfg.WorkspaceDir, subdir)
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("subdirectory %s not created: %v", subdir, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("%s is not a directory", subdir)
		}
	}

	// CreateWorkspace should be idempotent
	if err := cfg.CreateWorkspace(); err != nil {
		t.Fatalf("second CreateWorkspace() error: %v", err)
	}
}

func TestEnsureWorkspaceWritable(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := GetDefaultConfig()
	cfg.WorkspaceDir = filepath.Join(tmpDir, "workspace")

	err := cfg.EnsureWorkspaceWritable()
	if err != nil {
		t.Fatalf("EnsureWorkspaceWritable() error: %v", err)
	}

	// Verify write test file was cleaned up
	testFile := filepath.Join(cfg.WorkspaceDir, ".netutil_write_test")
	if _, err := os.Stat(testFile); !os.IsNotExist(err) {
		t.Error("write test file should have been cleaned up")
	}
}

func TestSetWorkspaceDirValidPath(t *testing.T) {
	cfg := GetDefaultConfig()
	err := cfg.SetWorkspaceDir("/tmp/test-workspace")
	if err != nil {
		t.Fatalf("SetWorkspaceDir() error: %v", err)
	}
	if cfg.WorkspaceDir != "/tmp/test-workspace" {
		t.Errorf("WorkspaceDir = %q, want %q", cfg.WorkspaceDir, "/tmp/test-workspace")
	}
}

func TestSetWorkspaceDirTrimsSlash(t *testing.T) {
	cfg := GetDefaultConfig()
	err := cfg.SetWorkspaceDir("/tmp/test-workspace/")
	if err != nil {
		t.Fatalf("SetWorkspaceDir() error: %v", err)
	}
	if cfg.WorkspaceDir != "/tmp/test-workspace" {
		t.Errorf("WorkspaceDir = %q, want %q", cfg.WorkspaceDir, "/tmp/test-workspace")
	}
}

func TestSetWorkspaceDirRejectsRelative(t *testing.T) {
	cfg := GetDefaultConfig()
	err := cfg.SetWorkspaceDir("relative/path")
	if err == nil {
		t.Error("expected error for relative path")
	}
}

func TestSetWorkspaceDirRejectsEmpty(t *testing.T) {
	cfg := GetDefaultConfig()
	err := cfg.SetWorkspaceDir("")
	if err == nil {
		t.Error("expected error for empty path")
	}
}

func TestSanitizeConfigRemovesInvalidInterfaces(t *testing.T) {
	cfg := &Config{
		LastUsedInterface: map[string]string{
			"scan":    "eth0",
			"bad":     "eth@0",
			"another": "",
		},
		RecentTargets:    []string{"192.168.1.1"},
		RecentCommands:   []RecentCommand{},
		ShowPathsShort:   true,
		DefaultInterface: "",
	}

	cfg.SanitizeConfig()

	if _, exists := cfg.LastUsedInterface["bad"]; exists {
		t.Error("invalid interface 'eth@0' should be removed")
	}
	if _, exists := cfg.LastUsedInterface["scan"]; !exists {
		t.Error("valid interface 'eth0' should be preserved")
	}
	if _, exists := cfg.LastUsedInterface["another"]; exists {
		t.Error("empty interface name should be removed")
	}
}

func TestSanitizeConfigRemovesInvalidTargets(t *testing.T) {
	cfg := &Config{
		LastUsedInterface: make(map[string]string),
		RecentTargets:     []string{"192.168.1.1", "not-valid", "10.0.0.0/8"},
		RecentCommands:    []RecentCommand{},
		ShowPathsShort:    true,
	}

	cfg.SanitizeConfig()

	if len(cfg.RecentTargets) != 2 {
		t.Errorf("expected 2 valid targets, got %d: %v", len(cfg.RecentTargets), cfg.RecentTargets)
	}
}

func TestSanitizeConfigFixesRelativeWorkspace(t *testing.T) {
	cfg := &Config{
		LastUsedInterface: make(map[string]string),
		RecentTargets:     []string{},
		RecentCommands:    []RecentCommand{},
		ShowPathsShort:    true,
		WorkspaceDir:      "relative/path",
	}

	cfg.SanitizeConfig()

	if !filepath.IsAbs(cfg.WorkspaceDir) {
		t.Errorf("relative WorkspaceDir should be converted to absolute, got %q", cfg.WorkspaceDir)
	}
}

func TestGetConfigStatusFields(t *testing.T) {
	cfg := GetDefaultConfig()
	cfg.WorkspaceDir = "/tmp/test-workspace"
	cfg.AddRecentTarget("10.0.0.1")
	cfg.AddRecentCommand("scan", true)

	status := cfg.GetConfigStatus()

	expectedKeys := []string{
		"workspace_dir",
		"workspace_exists",
		"recent_targets_count",
		"recent_commands_count",
		"validation_status",
	}
	for _, key := range expectedKeys {
		if _, exists := status[key]; !exists {
			t.Errorf("status missing key %q", key)
		}
	}

	// workspace_exists is false because /tmp/test-workspace doesn't exist on disk
	// workspace_dir is set correctly
	if status["workspace_dir"] != "/tmp/test-workspace" {
		t.Errorf("workspace_dir = %v, want /tmp/test-workspace", status["workspace_dir"])
	}
}
