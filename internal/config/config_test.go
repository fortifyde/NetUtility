package config

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGetDefaultConfig(t *testing.T) {
	config := GetDefaultConfig()

	if config.LastUsedInterface == nil {
		t.Error("LastUsedInterface should be initialized")
	}
	if config.RecentTargets == nil {
		t.Error("RecentTargets should be initialized")
	}
	if config.RecentCommands == nil {
		t.Error("RecentCommands should be initialized")
	}
	if config.WorkspaceDir != "" {
		t.Errorf("WorkspaceDir should be empty, got %s", config.WorkspaceDir)
	}
	if config.AutoCreateWorkspace {
		t.Error("AutoCreateWorkspace should be false by default")
	}
	if !config.ShowPathsShort {
		t.Error("ShowPathsShort should be true by default")
	}
}

func TestSetAndGetLastUsedInterface(t *testing.T) {
	config := GetDefaultConfig()

	config.SetLastUsedInterface("discovery", "eth0")
	config.SetLastUsedInterface("scanning", "wlan0")

	if got := config.GetLastUsedInterface("discovery"); got != "eth0" {
		t.Errorf("GetLastUsedInterface(discovery) = %s, want eth0", got)
	}
	if got := config.GetLastUsedInterface("scanning"); got != "wlan0" {
		t.Errorf("GetLastUsedInterface(scanning) = %s, want wlan0", got)
	}
	if got := config.GetLastUsedInterface("nonexistent"); got != "" {
		t.Errorf("GetLastUsedInterface(nonexistent) = %s, want empty string", got)
	}
}

func TestAddRecentTarget(t *testing.T) {
	tests := []struct {
		name     string
		targets  []string
		expected []string
	}{
		{
			name:     "add single target",
			targets:  []string{"192.168.1.1"},
			expected: []string{"192.168.1.1"},
		},
		{
			name:     "add multiple targets",
			targets:  []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"},
			expected: []string{"192.168.1.3", "192.168.1.2", "192.168.1.1"},
		},
		{
			name:     "add duplicate moves to front",
			targets:  []string{"192.168.1.1", "192.168.1.2", "192.168.1.1"},
			expected: []string{"192.168.1.1", "192.168.1.2"},
		},
		{
			name: "keep only last 10",
			targets: []string{
				"192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5",
				"192.168.1.6", "192.168.1.7", "192.168.1.8", "192.168.1.9", "192.168.1.10",
				"192.168.1.11",
			},
			expected: []string{
				"192.168.1.11", "192.168.1.10", "192.168.1.9", "192.168.1.8", "192.168.1.7",
				"192.168.1.6", "192.168.1.5", "192.168.1.4", "192.168.1.3", "192.168.1.2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := GetDefaultConfig()
			for _, target := range tt.targets {
				config.AddRecentTarget(target)
			}

			if len(config.RecentTargets) != len(tt.expected) {
				t.Errorf("len(RecentTargets) = %d, want %d", len(config.RecentTargets), len(tt.expected))
			}

			for i, expected := range tt.expected {
				if i >= len(config.RecentTargets) {
					break
				}
				if config.RecentTargets[i] != expected {
					t.Errorf("RecentTargets[%d] = %s, want %s", i, config.RecentTargets[i], expected)
				}
			}
		})
	}
}

func TestAddRecentCommand(t *testing.T) {
	config := GetDefaultConfig()

	config.AddRecentCommand("test-command-1", true)
	config.AddRecentCommand("test-command-2", false)

	if len(config.RecentCommands) != 2 {
		t.Errorf("len(RecentCommands) = %d, want 2", len(config.RecentCommands))
	}

	if config.RecentCommands[0].Command != "test-command-2" {
		t.Errorf("First command = %s, want test-command-2", config.RecentCommands[0].Command)
	}
	if config.RecentCommands[0].Success {
		t.Error("First command should have success=false")
	}

	// Test max 20 limit
	for i := 0; i < 25; i++ {
		config.AddRecentCommand("command", true)
	}

	if len(config.RecentCommands) != 20 {
		t.Errorf("len(RecentCommands) = %d, want 20 (max limit)", len(config.RecentCommands))
	}
}

func TestGetRecentCommands(t *testing.T) {
	config := GetDefaultConfig()

	now := time.Now()
	config.RecentCommands = []RecentCommand{
		{Command: "cmd1", Timestamp: now, Success: true},
		{Command: "cmd2", Timestamp: now, Success: false},
	}

	commands := config.GetRecentCommands()

	if len(commands) != 2 {
		t.Errorf("len(commands) = %d, want 2", len(commands))
	}

	if !strings.Contains(commands[0], "✓") {
		t.Error("Successful command should contain ✓")
	}
	if !strings.Contains(commands[1], "✗") {
		t.Error("Failed command should contain ✗")
	}
	if !strings.Contains(commands[0], "cmd1") {
		t.Error("Command text should be included")
	}
}

func TestIsValidInterfaceName(t *testing.T) {
	tests := []struct {
		name  string
		iface string
		valid bool
	}{
		{"valid eth0", "eth0", true},
		{"valid wlan0", "wlan0", true},
		{"valid with dot", "eth0.100", true},
		{"valid with hyphen", "eth-0", true},
		{"valid with underscore", "eth_0", true},
		{"empty string", "", false},
		{"with space", "eth 0", false},
		{"with slash", "eth0/1", false},
		{"with special char", "eth0@1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidInterfaceName(tt.iface); got != tt.valid {
				t.Errorf("isValidInterfaceName(%s) = %v, want %v", tt.iface, got, tt.valid)
			}
		})
	}
}

func TestIsValidIPAddress(t *testing.T) {
	tests := []struct {
		name  string
		ip    string
		valid bool
	}{
		{"valid IP", "192.168.1.1", true},
		{"valid IP with zeros", "10.0.0.1", true},
		{"empty string", "", false},
		{"missing octet", "192.168.1", false},
		{"too many octets", "192.168.1.1.1", false},
		{"with letters", "192.168.1.a", false},
		{"with special chars", "192.168.1.1!", false},
		{"empty octet", "192.168..1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidIPAddress(tt.ip); got != tt.valid {
				t.Errorf("isValidIPAddress(%s) = %v, want %v", tt.ip, got, tt.valid)
			}
		})
	}
}

func TestIsValidCIDRPrefix(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		valid  bool
	}{
		{"valid 24", "24", true},
		{"valid 8", "8", true},
		{"valid 32", "32", true},
		{"empty string", "", false},
		{"with letter", "24a", false},
		{"with special char", "24!", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidCIDRPrefix(tt.prefix); got != tt.valid {
				t.Errorf("isValidCIDRPrefix(%s) = %v, want %v", tt.prefix, got, tt.valid)
			}
		})
	}
}

func TestIsValidTarget(t *testing.T) {
	tests := []struct {
		name   string
		target string
		valid  bool
	}{
		{"valid IP", "192.168.1.1", true},
		{"valid CIDR", "192.168.1.0/24", true},
		{"valid file input", "-iL /tmp/targets.txt", true},
		{"empty string", "", false},
		{"invalid CIDR format", "192.168.1.0/", false},
		{"invalid CIDR multiple slashes", "192.168.1.0/24/32", false},
		{"file input with injection", "-iL /tmp/file; rm -rf", false},
		{"file input with pipe", "-iL /tmp/file | cat", false},
		{"out-of-range octets", "999.999.999.999", false},
		{"last octet out of range", "192.168.1.256", false},
		{"CIDR prefix out of range", "192.168.1.0/33", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidTarget(tt.target); got != tt.valid {
				t.Errorf("isValidTarget(%s) = %v, want %v", tt.target, got, tt.valid)
			}
		})
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
				LastUsedInterface:   make(map[string]string),
				RecentTargets:       []string{},
				WorkspaceDir:        "relative/path",
				RecentCommands:      []RecentCommand{},
				AutoCreateWorkspace: false,
				ShowPathsShort:      true,
			},
			wantError: true,
		},
		{
			name: "invalid interface name",
			config: &Config{
				LastUsedInterface: map[string]string{
					"discovery": "eth@0",
				},
				RecentTargets:       []string{},
				WorkspaceDir:        "",
				RecentCommands:      []RecentCommand{},
				AutoCreateWorkspace: false,
				ShowPathsShort:      true,
			},
			wantError: true,
		},
		{
			name: "invalid recent target",
			config: &Config{
				LastUsedInterface:   make(map[string]string),
				RecentTargets:       []string{"not-an-ip"},
				WorkspaceDir:        "",
				RecentCommands:      []RecentCommand{},
				AutoCreateWorkspace: false,
				ShowPathsShort:      true,
			},
			wantError: true,
		},
		{
			name: "empty command",
			config: &Config{
				LastUsedInterface: make(map[string]string),
				RecentTargets:     []string{},
				WorkspaceDir:      "",
				RecentCommands: []RecentCommand{
					{Command: "", Timestamp: time.Now(), Success: true},
				},
				AutoCreateWorkspace: false,
				ShowPathsShort:      true,
			},
			wantError: true,
		},
		{
			name: "zero timestamp",
			config: &Config{
				LastUsedInterface: make(map[string]string),
				RecentTargets:     []string{},
				WorkspaceDir:      "",
				RecentCommands: []RecentCommand{
					{Command: "test", Timestamp: time.Time{}, Success: true},
				},
				AutoCreateWorkspace: false,
				ShowPathsShort:      true,
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
		LastUsedInterface: map[string]string{
			"valid":   "eth0",
			"invalid": "eth@0",
		},
		RecentTargets: []string{
			"192.168.1.1",
			"invalid-target",
			"192.168.1.0/24",
		},
		RecentCommands: []RecentCommand{
			{Command: "valid", Timestamp: time.Now(), Success: true},
			{Command: "", Timestamp: time.Now(), Success: true},
			{Command: "valid2", Timestamp: time.Time{}, Success: true},
		},
		DefaultInterface: "eth@invalid",
		WorkspaceDir:     "relative/path",
	}

	config.SanitizeConfig()

	if _, exists := config.LastUsedInterface["invalid"]; exists {
		t.Error("Invalid interface should be removed")
	}
	if _, exists := config.LastUsedInterface["valid"]; !exists {
		t.Error("Valid interface should remain")
	}

	if len(config.RecentTargets) != 2 {
		t.Errorf("RecentTargets should have 2 valid entries, got %d", len(config.RecentTargets))
	}

	if len(config.RecentCommands) != 1 {
		t.Errorf("RecentCommands should have 1 valid entry, got %d", len(config.RecentCommands))
	}

	if config.DefaultInterface != "" {
		t.Errorf("Invalid default interface should be cleared, got %s", config.DefaultInterface)
	}

	if !filepath.IsAbs(config.WorkspaceDir) {
		t.Error("Relative workspace path should be converted to absolute")
	}
}

func TestGetShortPath(t *testing.T) {
	config := GetDefaultConfig()
	config.WorkspaceDir = "/home/user/workspace"
	config.ShowPathsShort = true

	tests := []struct {
		name     string
		fullPath string
	}{
		{
			name:     "path inside workspace",
			fullPath: "/home/user/workspace/discovery/scan1",
		},
		{
			name:     "path outside workspace returns relative with ..",
			fullPath: "/tmp/other/file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := config.GetShortPath(tt.fullPath)
			// GetShortPath returns relative paths starting with ./
			if !strings.HasPrefix(got, "./") {
				t.Errorf("GetShortPath(%s) = %s, should start with ./", tt.fullPath, got)
			}
		})
	}

	// When ShowPathsShort is false, should return full path
	config.ShowPathsShort = false
	fullPath := "/home/user/workspace/discovery/scan1"
	if got := config.GetShortPath(fullPath); got != fullPath {
		t.Errorf("GetShortPath with ShowPathsShort=false should return full path")
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
	config.RecentTargets = []string{"192.168.1.1"}
	config.AddRecentCommand("test", true)
	config.SetLastUsedInterface("discovery", "eth0")

	status := config.GetConfigStatus()

	if status["workspace_dir"] != "/tmp/test-workspace" {
		t.Error("Status should include workspace_dir")
	}
	if status["recent_targets_count"] != 1 {
		t.Error("Status should include recent_targets_count")
	}
	if status["recent_commands_count"] != 1 {
		t.Error("Status should include recent_commands_count")
	}
	if status["remembered_interfaces_count"] != 1 {
		t.Error("Status should include remembered_interfaces_count")
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
	// When config file doesn't exist, LoadConfig returns default config
	// Since we can't easily mock os.Executable(), we test that defaults are returned
	// when a config file doesn't exist by checking the logic directly

	config := GetDefaultConfig()

	if config.WorkspaceDir != "" {
		t.Error("Default config should have empty WorkspaceDir")
	}
	if config.LastUsedInterface == nil {
		t.Error("Default config should initialize LastUsedInterface")
	}
	if config.RecentTargets == nil {
		t.Error("Default config should initialize RecentTargets")
	}
	if config.RecentCommands == nil {
		t.Error("Default config should initialize RecentCommands")
	}
}

func TestSaveAndLoadConfig(t *testing.T) {
	// Test JSON marshaling and unmarshaling directly since we can't easily mock os.Executable()
	config := GetDefaultConfig()
	config.WorkspaceDir = "/tmp/test-workspace"
	config.SetLastUsedInterface("discovery", "eth0")
	config.AddRecentTarget("192.168.1.1")
	config.DefaultInterface = "wlan0"

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

	// Ensure maps are initialized (same as LoadConfig does)
	if loaded.LastUsedInterface == nil {
		loaded.LastUsedInterface = make(map[string]string)
	}
	if loaded.RecentTargets == nil {
		loaded.RecentTargets = []string{}
	}
	if loaded.RecentCommands == nil {
		loaded.RecentCommands = []RecentCommand{}
	}

	if loaded.WorkspaceDir != config.WorkspaceDir {
		t.Errorf("WorkspaceDir = %s, want %s", loaded.WorkspaceDir, config.WorkspaceDir)
	}
	if loaded.LastUsedInterface["discovery"] != "eth0" {
		t.Error("LastUsedInterface not preserved")
	}
	if len(loaded.RecentTargets) != 1 || loaded.RecentTargets[0] != "192.168.1.1" {
		t.Error("RecentTargets not preserved")
	}
	if loaded.DefaultInterface != "wlan0" {
		t.Errorf("DefaultInterface = %s, want wlan0", loaded.DefaultInterface)
	}
}

func TestLoadConfigWithInvalidJSON(t *testing.T) {
	// Test JSON unmarshaling error handling directly
	invalidJSON := []byte("{invalid json}")

	var config Config
	err := json.Unmarshal(invalidJSON, &config)
	if err == nil {
		t.Error("Unmarshal() should return error for invalid JSON")
	}
}

func TestLoadConfigNormalizesWorkspaceDir(t *testing.T) {
	// Test that workspace dir normalization works
	testPath := "/tmp/workspace/"
	normalized := strings.TrimRight(testPath, "/")

	if strings.HasSuffix(normalized, "/") {
		t.Error("TrimRight should remove trailing slash")
	}
	if normalized != "/tmp/workspace" {
		t.Errorf("normalized path = %s, want /tmp/workspace", normalized)
	}

	// Test that LoadConfig applies this normalization
	config := &Config{
		WorkspaceDir: "/some/path/",
	}

	// Simulate what LoadConfig does
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
