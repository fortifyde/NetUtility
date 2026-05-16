package config

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const (
	ConfigDir  = ".netutil"
	ConfigFile = "config.json"
)

type Config struct {
	WorkspaceDir string `json:"workspace_dir"`
	Language     string `json:"language"`
}

// GetDefaultConfig returns a config with sensible defaults
func GetDefaultConfig() *Config {
	return &Config{
		WorkspaceDir: "", // No default workspace - user must configure
		Language:     "en",
	}
}

// normaliseLanguage ensures Language is a supported value; unknown values become "en".
func (c *Config) normaliseLanguage() {
	if c.Language != "de" {
		c.Language = "en"
	}
}

// GetConfigPath returns the path to the config file (stored alongside executable)
func GetConfigPath() (string, error) {
	// Get executable directory
	execPath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to get executable path: %w", err)
	}

	execDir := filepath.Dir(execPath)

	// Use netutil-config.json in executable directory
	return filepath.Join(execDir, "netutil-config.json"), nil
}

// LoadConfig loads configuration from file or returns defaults if file doesn't exist
func LoadConfig() (*Config, error) {
	configPath, err := GetConfigPath()
	if err != nil {
		return nil, fmt.Errorf("failed to get config path: %w", err)
	}

	// If config file doesn't exist, return defaults
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return GetDefaultConfig(), nil
	}

	data, err := os.ReadFile(configPath) //nolint:gosec // G304: configPath from executable path
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Normalize workspace directory path to remove trailing slashes
	if config.WorkspaceDir != "" {
		config.WorkspaceDir = strings.TrimRight(config.WorkspaceDir, "/")
	}

	// Normalise language — any value other than "de" becomes "en"
	config.normaliseLanguage()

	return &config, nil
}

// SaveConfig saves configuration to file
func (c *Config) SaveConfig() error {
	configPath, err := GetConfigPath()
	if err != nil {
		return fmt.Errorf("failed to get config path: %w", err)
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// CreateWorkspace creates the workspace directory structure
func (c *Config) CreateWorkspace() error {
	if c.WorkspaceDir == "" {
		return fmt.Errorf("workspace directory not configured")
	}

	// Create main workspace directory with permissions that allow root access
	if err := os.MkdirAll(c.WorkspaceDir, 0750); err != nil {
		return fmt.Errorf("failed to create workspace directory: %w", err)
	}

	// Create subdirectories with more permissive permissions for root access
	subdirs := []string{
		"captures",
		"discovery",
		"scans",
		"analysis",
		"reports",
		"configs",
		"logs",
	}

	for _, subdir := range subdirs {
		path := filepath.Join(c.WorkspaceDir, subdir)
		// Use 0777 permissions so root can write to user's workspace
		if err := os.MkdirAll(path, 0750); err != nil {
			return fmt.Errorf("failed to create subdirectory %s: %w", subdir, err)
		}
	}

	// Create symbolic links for latest results
	latestDir := filepath.Join(c.WorkspaceDir, "latest")
	if err := os.MkdirAll(latestDir, 0750); err != nil {
		return fmt.Errorf("failed to create latest directory: %w", err)
	}

	return nil
}

// GetWorkspacePath returns the full path for a workspace subdirectory
func (c *Config) GetWorkspacePath(subdir string) string {
	return filepath.Join(c.WorkspaceDir, subdir)
}

// ValidateConfig performs comprehensive validation of configuration values
func (c *Config) ValidateConfig() error {
	// Validate workspace directory
	if c.WorkspaceDir != "" {
		if !filepath.IsAbs(c.WorkspaceDir) {
			return fmt.Errorf("workspace_dir must be an absolute path")
		}

		// Check if parent directory exists
		parentDir := filepath.Dir(c.WorkspaceDir)
		if _, err := os.Stat(parentDir); os.IsNotExist(err) {
			return fmt.Errorf("workspace_dir parent directory does not exist: %s", parentDir)
		}
	}

	return nil
}

// SanitizeConfig removes invalid entries and fixes common issues
func (c *Config) SanitizeConfig() {
	// Ensure workspace directory is absolute
	if c.WorkspaceDir != "" && !filepath.IsAbs(c.WorkspaceDir) {
		if homeDir, err := os.UserHomeDir(); err == nil {
			c.WorkspaceDir = filepath.Join(homeDir, "netutil-workspace")
		}
	}
}

// GetConfigStatus returns a summary of the configuration status
func (c *Config) GetConfigStatus() map[string]any {
	status := make(map[string]any)

	status["workspace_dir"] = c.WorkspaceDir
	status["workspace_exists"] = false
	if c.WorkspaceDir != "" {
		if _, err := os.Stat(c.WorkspaceDir); err == nil {
			status["workspace_exists"] = true
		}
	}

	// Validation status
	if err := c.ValidateConfig(); err != nil {
		status["validation_status"] = "invalid"
		status["validation_error"] = err.Error()
	} else {
		status["validation_status"] = "valid"
	}

	return status
}

// IsWorkspaceConfigured returns true if workspace directory is set and valid
func (c *Config) IsWorkspaceConfigured() bool {
	return c.WorkspaceDir != "" && filepath.IsAbs(c.WorkspaceDir)
}

// SetWorkspaceDir sets the workspace directory and validates it
func (c *Config) SetWorkspaceDir(workspaceDir string) error {
	if workspaceDir == "" {
		return fmt.Errorf("workspace directory cannot be empty")
	}

	// Normalize path - remove trailing slashes for consistent concatenation
	workspaceDir = strings.TrimRight(workspaceDir, "/")

	if !filepath.IsAbs(workspaceDir) {
		return fmt.Errorf("workspace directory must be an absolute path")
	}

	// Check if parent directory exists
	parentDir := filepath.Dir(workspaceDir)
	if _, err := os.Stat(parentDir); os.IsNotExist(err) {
		return fmt.Errorf("parent directory does not exist: %s", parentDir)
	}

	c.WorkspaceDir = workspaceDir
	return nil
}

// NeedsFirstTimeSetup returns true if this is a first-time run
func (c *Config) NeedsFirstTimeSetup() bool {
	return !c.IsWorkspaceConfigured()
}

// GetOriginalUser returns the original user info when running as root via sudo
func GetOriginalUser() (*user.User, error) {
	// Check if running as root via sudo
	if os.Geteuid() == 0 {
		// Check for SUDO_UID and SUDO_GID environment variables
		if sudoUID := os.Getenv("SUDO_UID"); sudoUID != "" {
			uid, err := strconv.Atoi(sudoUID)
			if err == nil {
				return user.LookupId(strconv.Itoa(uid))
			}
		}
	}

	// Fallback to current user
	return user.Current()
}

// FixWorkspaceOwnership fixes workspace ownership when running as root.
func (c *Config) FixWorkspaceOwnership() error {
	if !c.IsWorkspaceConfigured() {
		return fmt.Errorf("workspace not configured")
	}
	FixWorkspaceOwnershipForPath(c.WorkspaceDir)
	return nil
}

// FixWorkspacePermissions ensures workspace directories have correct permissions for root access
func (c *Config) FixWorkspacePermissions() error {
	if !c.IsWorkspaceConfigured() {
		return fmt.Errorf("workspace not configured")
	}

	// Set permissions on workspace subdirectories to allow root write access
	subdirs := []string{
		"captures",
		"discovery",
		"scans",
		"analysis",
		"reports",
		"configs",
		"logs",
		"latest",
	}

	for _, subdir := range subdirs {
		dirPath := filepath.Join(c.WorkspaceDir, subdir)

		// Check if directory exists
		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			continue // Skip non-existent directories
		}

		// Set permissions to 0750 so root can write to user-owned directories
		if err := os.Chmod(dirPath, 0750); err != nil { //nolint:gosec // G302: directory chmod
			fmt.Fprintf(os.Stderr, "Warning: Failed to set permissions on %s: %v\n", dirPath, err)
		}
	}

	// Also fix permissions on the main workspace directory
	if err := os.Chmod(c.WorkspaceDir, 0750); err != nil { //nolint:gosec // G302: directory chmod
		fmt.Fprintf(os.Stderr, "Warning: Failed to set permissions on workspace root: %v\n", err)
	}

	return nil
}

// EnsureWorkspaceWritable ensures workspace is writable by current process
func (c *Config) EnsureWorkspaceWritable() error {
	if !c.IsWorkspaceConfigured() {
		return fmt.Errorf("workspace not configured")
	}

	// Create workspace if it doesn't exist
	if err := c.CreateWorkspace(); err != nil {
		return fmt.Errorf("failed to create workspace: %w", err)
	}

	// Fix permissions for existing directories (needed for root access)
	if err := c.FixWorkspacePermissions(); err != nil {
		return fmt.Errorf("failed to fix workspace permissions: %w", err)
	}

	// Fix ownership if running as root
	if err := c.FixWorkspaceOwnership(); err != nil {
		return fmt.Errorf("failed to fix workspace ownership: %w", err)
	}

	// Test write access by creating a temporary file
	testFile := filepath.Join(c.WorkspaceDir, ".netutil_write_test")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil { //nolint:gosec // G306: temp file immediately deleted
		return fmt.Errorf("workspace not writable: %w", err)
	}

	// Clean up test file
	_ = os.Remove(testFile)

	return nil
}

// FixWorkspaceOwnershipForPath fixes file ownership under dir when running as root via sudo.
func FixWorkspaceOwnershipForPath(dir string) {
	if os.Geteuid() != 0 {
		return
	}

	originalUser, err := GetOriginalUser()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to get original user for chown: %v\n", err)
		return
	}

	uid, err := strconv.Atoi(originalUser.Uid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Invalid user ID for chown: %v\n", err)
		return
	}
	gid, err := strconv.Atoi(originalUser.Gid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Invalid group ID for chown: %v\n", err)
		return
	}

	if err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if chownErr := syscall.Chown(path, uid, gid); chownErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to change ownership of %s: %v\n", path, chownErr)
		}
		return nil
	}); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: error walking %s for chown: %v\n", dir, err)
	}
}
