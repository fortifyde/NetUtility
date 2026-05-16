package config

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestGetDefaultConfig(t *testing.T) {
	config := GetDefaultConfig()

	if config.WorkspaceDir != "" {
		t.Errorf("WorkspaceDir should be empty, got %s", config.WorkspaceDir)
	}
	if config.Language != "en" {
		t.Errorf("Language should be 'en', got %s", config.Language)
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name      string
		config    *Config
		wantError bool
	}{
		{
			name:      "valid default config",
			config:    GetDefaultConfig(),
			wantError: false,
		},
		{
			name: "invalid workspace dir - relative path",
			config: &Config{
				WorkspaceDir: "relative/path",
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.ValidateConfig()
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateConfig() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestSanitizeConfig(t *testing.T) {
	config := &Config{
		WorkspaceDir: "relative/path",
	}

	config.SanitizeConfig()

	if !filepath.IsAbs(config.WorkspaceDir) {
		t.Error("Relative workspace path should be converted to absolute")
	}
}

func TestSetWorkspaceDir(t *testing.T) {
	config := GetDefaultConfig()

	tests := []struct {
		name      string
		dir       string
		wantError bool
	}{
		{"empty string", "", true},
		{"relative path", "relative/path", true},
		{"trailing slash removed", "/tmp/workspace/", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := config.SetWorkspaceDir(tt.dir)
			if (err != nil) != tt.wantError {
				t.Errorf("SetWorkspaceDir(%s) error = %v, wantError %v", tt.dir, err, tt.wantError)
			}

			if !tt.wantError && strings.HasSuffix(config.WorkspaceDir, "/") {
				t.Error("Trailing slash should be removed")
			}
		})
	}
}

func TestIsWorkspaceConfigured(t *testing.T) {
	tests := []struct {
		name          string
		workspaceDir  string
		expectedValue bool
	}{
		{"empty workspace", "", false},
		{"relative path", "relative/path", false},
		{"absolute path", "/tmp/workspace", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := GetDefaultConfig()
			config.WorkspaceDir = tt.workspaceDir

			if got := config.IsWorkspaceConfigured(); got != tt.expectedValue {
				t.Errorf("IsWorkspaceConfigured() = %v, want %v", got, tt.expectedValue)
			}
		})
	}
}

func TestNeedsFirstTimeSetup(t *testing.T) {
	config := GetDefaultConfig()
	if !config.NeedsFirstTimeSetup() {
		t.Error("New config should need first time setup")
	}

	config.WorkspaceDir = "/tmp/workspace"
	if config.NeedsFirstTimeSetup() {
		t.Error("Config with workspace should not need first time setup")
	}
}

func TestGetConfigStatus(t *testing.T) {
	config := GetDefaultConfig()
	config.WorkspaceDir = "/tmp/test-workspace"

	status := config.GetConfigStatus()

	if status["workspace_dir"] != "/tmp/test-workspace" {
		t.Error("Status should include workspace_dir")
	}
	if status["validation_status"] != "valid" {
		t.Errorf("Status validation should be valid, got %v", status["validation_status"])
	}
}

func TestGetWorkspacePath(t *testing.T) {
	config := GetDefaultConfig()
	config.WorkspaceDir = "/home/user/workspace"

	expected := "/home/user/workspace/discovery"
	if got := config.GetWorkspacePath("discovery"); got != expected {
		t.Errorf("GetWorkspacePath(discovery) = %s, want %s", got, expected)
	}
}

func TestLoadConfigNonExistent(t *testing.T) {
	config := GetDefaultConfig()

	if config.WorkspaceDir != "" {
		t.Error("Default config should have empty WorkspaceDir")
	}
}

func TestSaveAndLoadConfig(t *testing.T) {
	config := GetDefaultConfig()
	config.WorkspaceDir = "/tmp/test-workspace"

	// Marshal to JSON
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent() error = %v", err)
	}

	// Unmarshal back
	var loaded Config
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if loaded.WorkspaceDir != config.WorkspaceDir {
		t.Errorf("WorkspaceDir = %s, want %s", loaded.WorkspaceDir, config.WorkspaceDir)
	}
}

func TestLoadConfigWithInvalidJSON(t *testing.T) {
	invalidJSON := []byte("{invalid json}")

	var config Config
	err := json.Unmarshal(invalidJSON, &config)
	if err == nil {
		t.Error("Unmarshal() should return error for invalid JSON")
	}
}

func TestLoadConfigNormalizesWorkspaceDir(t *testing.T) {
	testPath := "/tmp/workspace/"
	normalized := strings.TrimRight(testPath, "/")

	if strings.HasSuffix(normalized, "/") {
		t.Error("TrimRight should remove trailing slash")
	}
	if normalized != "/tmp/workspace" {
		t.Errorf("normalized path = %s, want /tmp/workspace", normalized)
	}

	config := &Config{
		WorkspaceDir: "/some/path/",
	}

	if config.WorkspaceDir != "" {
		config.WorkspaceDir = strings.TrimRight(config.WorkspaceDir, "/")
	}

	if strings.HasSuffix(config.WorkspaceDir, "/") {
		t.Error("WorkspaceDir should have trailing slash removed after normalization")
	}
}

func TestLanguageDefaultAndNormalisation(t *testing.T) {
	// Default config must have Language == "en"
	cfg := GetDefaultConfig()
	if cfg.Language != "en" {
		t.Errorf("default Language = %q, want %q", cfg.Language, "en")
	}

	// JSON round-trip: "de" is preserved
	jsonDE := `{"language":"de"}`
	var c1 Config
	if err := json.Unmarshal([]byte(jsonDE), &c1); err != nil {
		t.Fatal(err)
	}
	c1.normaliseLanguage()
	if c1.Language != "de" {
		t.Errorf("Language after normalise = %q, want %q", c1.Language, "de")
	}

	// Unknown value normalises to "en"
	jsonXX := `{"language":"fr"}`
	var c2 Config
	if err := json.Unmarshal([]byte(jsonXX), &c2); err != nil {
		t.Fatal(err)
	}
	c2.normaliseLanguage()
	if c2.Language != "en" {
		t.Errorf("Language after normalise = %q, want %q", c2.Language, "en")
	}

	// Missing field normalises to "en"
	jsonEmpty := `{}`
	var c3 Config
	if err := json.Unmarshal([]byte(jsonEmpty), &c3); err != nil {
		t.Fatal(err)
	}
	c3.normaliseLanguage()
	if c3.Language != "en" {
		t.Errorf("Language after normalise = %q, want %q", c3.Language, "en")
	}
}
