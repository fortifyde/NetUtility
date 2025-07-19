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
	"time"
)

const (
	ConfigDir  = ".netutil"
	ConfigFile = "config.json"
)

type Config struct {
	LastUsedInterface   map[string]string `json:"last_used_interface"`
	RecentTargets       []string          `json:"recent_targets"`
	WorkspaceDir        string            `json:"workspace_dir"`
	RecentCommands      []RecentCommand   `json:"recent_commands"`
	DefaultInterface    string            `json:"default_interface"`
	AutoCreateWorkspace bool              `json:"auto_create_workspace"`
	ShowPathsShort      bool              `json:"show_paths_short"`
}

type RecentCommand struct {
	Command   string    `json:"command"`
	Timestamp time.Time `json:"timestamp"`
	Success   bool      `json:"success"`
}

// GetDefaultConfig returns a config with sensible defaults
func GetDefaultConfig() *Config {
	return &Config{
		LastUsedInterface:   make(map[string]string),
		RecentTargets:       []string{},
		WorkspaceDir:        "", // No default workspace - user must configure
		RecentCommands:      []RecentCommand{},
		DefaultInterface:    "",
		AutoCreateWorkspace: false, // Only create after user sets workspace
		ShowPathsShort:      true,
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

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Ensure maps are initialized
	if config.LastUsedInterface == nil {
		config.LastUsedInterface = make(map[string]string)
	}
	if config.RecentTargets == nil {
		config.RecentTargets = []string{}
	}
	if config.RecentCommands == nil {
		config.RecentCommands = []RecentCommand{}
	}

	// Normalize workspace directory path to remove trailing slashes
	if config.WorkspaceDir != "" {
		config.WorkspaceDir = strings.TrimRight(config.WorkspaceDir, "/")
	}

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

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// SetLastUsedInterface stores the last used interface for a category
func (c *Config) SetLastUsedInterface(category, interfaceName string) {
	c.LastUsedInterface[category] = interfaceName
}

// GetLastUsedInterface retrieves the last used interface for a category
func (c *Config) GetLastUsedInterface(category string) string {
	return c.LastUsedInterface[category]
}

// AddRecentTarget adds a target to the recent targets list
func (c *Config) AddRecentTarget(target string) {
	// Remove if already exists
	for i, t := range c.RecentTargets {
		if t == target {
			c.RecentTargets = append(c.RecentTargets[:i], c.RecentTargets[i+1:]...)
			break
		}
	}

	// Add to beginning
	c.RecentTargets = append([]string{target}, c.RecentTargets...)

	// Keep only last 10
	if len(c.RecentTargets) > 10 {
		c.RecentTargets = c.RecentTargets[:10]
	}
}

// AddRecentCommand adds a command to the recent commands list
func (c *Config) AddRecentCommand(command string, success bool) {
	recentCmd := RecentCommand{
		Command:   command,
		Timestamp: time.Now(),
		Success:   success,
	}

	// Add to beginning
	c.RecentCommands = append([]RecentCommand{recentCmd}, c.RecentCommands...)

	// Keep only last 20
	if len(c.RecentCommands) > 20 {
		c.RecentCommands = c.RecentCommands[:20]
	}
}

// GetRecentCommands returns recent commands formatted for display
func (c *Config) GetRecentCommands() []string {
	var commands []string
	for _, cmd := range c.RecentCommands {
		status := "✓"
		if !cmd.Success {
			status = "✗"
		}
		timeStr := cmd.Timestamp.Format("15:04:05")
		commands = append(commands, fmt.Sprintf("%s %s %s", status, timeStr, cmd.Command))
	}
	return commands
}

// CreateWorkspace creates the workspace directory structure
func (c *Config) CreateWorkspace() error {
	if c.WorkspaceDir == "" {
		return fmt.Errorf("workspace directory not configured")
	}

	// Create main workspace directory with permissions that allow root access
	if err := os.MkdirAll(c.WorkspaceDir, 0755); err != nil {
		return fmt.Errorf("failed to create workspace directory: %w", err)
	}

	// Create subdirectories with more permissive permissions for root access
	subdirs := []string{
		"captures",
		"enumeration",
		"vulnerability",
		"configs",
		"logs",
	}

	for _, subdir := range subdirs {
		path := filepath.Join(c.WorkspaceDir, subdir)
		// Use 0777 permissions so root can write to user's workspace
		if err := os.MkdirAll(path, 0777); err != nil {
			return fmt.Errorf("failed to create subdirectory %s: %w", subdir, err)
		}
	}

	// Create symbolic links for latest results
	latestDir := filepath.Join(c.WorkspaceDir, "latest")
	if err := os.MkdirAll(latestDir, 0777); err != nil {
		return fmt.Errorf("failed to create latest directory: %w", err)
	}

	return nil
}

// GetWorkspacePath returns the full path for a workspace subdirectory
func (c *Config) GetWorkspacePath(subdir string) string {
	return filepath.Join(c.WorkspaceDir, subdir)
}

// GetShortPath returns a shortened path for display
func (c *Config) GetShortPath(fullPath string) string {
	if !c.ShowPathsShort {
		return fullPath
	}

	if filepath.IsAbs(fullPath) && c.WorkspaceDir != "" {
		if rel, err := filepath.Rel(c.WorkspaceDir, fullPath); err == nil {
			return "./" + rel
		}
	}

	return fullPath
}

// ValidateConfig performs comprehensive validation of configuration values
func (c *Config) ValidateConfig() error {
	var errors []string

	// Validate workspace directory
	if c.WorkspaceDir != "" {
		if !filepath.IsAbs(c.WorkspaceDir) {
			errors = append(errors, "workspace_dir must be an absolute path")
		}

		// Check if parent directory exists
		parentDir := filepath.Dir(c.WorkspaceDir)
		if _, err := os.Stat(parentDir); os.IsNotExist(err) {
			errors = append(errors, fmt.Sprintf("workspace_dir parent directory does not exist: %s", parentDir))
		}
	}

	// Validate interface names
	for category, iface := range c.LastUsedInterface {
		if !isValidInterfaceName(iface) {
			errors = append(errors, fmt.Sprintf("invalid interface name for category %s: %s", category, iface))
		}
	}

	// Validate recent targets
	for i, target := range c.RecentTargets {
		if !isValidTarget(target) {
			errors = append(errors, fmt.Sprintf("invalid recent target at index %d: %s", i, target))
		}
	}

	// Validate recent commands
	for i, cmd := range c.RecentCommands {
		if strings.TrimSpace(cmd.Command) == "" {
			errors = append(errors, fmt.Sprintf("empty command at index %d", i))
		}

		if cmd.Timestamp.IsZero() {
			errors = append(errors, fmt.Sprintf("invalid timestamp for command at index %d", i))
		}
	}

	// Validate default interface
	if c.DefaultInterface != "" && !isValidInterfaceName(c.DefaultInterface) {
		errors = append(errors, fmt.Sprintf("invalid default interface: %s", c.DefaultInterface))
	}

	if len(errors) > 0 {
		return fmt.Errorf("configuration validation failed: %s", strings.Join(errors, "; "))
	}

	return nil
}

// isValidInterfaceName checks if an interface name is valid
func isValidInterfaceName(name string) bool {
	if name == "" {
		return false
	}

	// Interface names should contain only alphanumeric characters, dots, and hyphens
	for _, char := range name {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '.' || char == '-' || char == '_') {
			return false
		}
	}

	return true
}

// isValidTarget checks if a target specification is valid
func isValidTarget(target string) bool {
	if target == "" {
		return false
	}

	// Check for file input format
	if strings.HasPrefix(target, "-iL ") {
		filePath := strings.TrimSpace(target[4:])
		return filePath != "" && !strings.ContainsAny(filePath, ";<>&|`$")
	}

	// Basic validation for IP addresses and ranges
	// This is a simplified check - more comprehensive validation would be in the validation package
	if strings.Contains(target, "/") {
		// CIDR notation
		parts := strings.Split(target, "/")
		if len(parts) != 2 {
			return false
		}
		return isValidIPAddress(parts[0]) && isValidCIDRPrefix(parts[1])
	}

	// Single IP address
	return isValidIPAddress(target)
}

// isValidIPAddress performs basic IP address validation
func isValidIPAddress(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}

	for _, part := range parts {
		if part == "" {
			return false
		}

		// Check if part contains only digits
		for _, char := range part {
			if char < '0' || char > '9' {
				return false
			}
		}
	}

	return true
}

// isValidCIDRPrefix checks if a CIDR prefix is valid
func isValidCIDRPrefix(prefix string) bool {
	if prefix == "" {
		return false
	}

	// Check if prefix contains only digits
	for _, char := range prefix {
		if char < '0' || char > '9' {
			return false
		}
	}

	return true
}

// SanitizeConfig removes invalid entries and fixes common issues
func (c *Config) SanitizeConfig() {
	// Remove invalid interface entries
	for category, iface := range c.LastUsedInterface {
		if !isValidInterfaceName(iface) {
			delete(c.LastUsedInterface, category)
		}
	}

	// Filter invalid recent targets
	validTargets := make([]string, 0, len(c.RecentTargets))
	for _, target := range c.RecentTargets {
		if isValidTarget(target) {
			validTargets = append(validTargets, target)
		}
	}
	c.RecentTargets = validTargets

	// Filter invalid recent commands
	validCommands := make([]RecentCommand, 0, len(c.RecentCommands))
	for _, cmd := range c.RecentCommands {
		if strings.TrimSpace(cmd.Command) != "" && !cmd.Timestamp.IsZero() {
			validCommands = append(validCommands, cmd)
		}
	}
	c.RecentCommands = validCommands

	// Validate default interface
	if c.DefaultInterface != "" && !isValidInterfaceName(c.DefaultInterface) {
		c.DefaultInterface = ""
	}

	// Ensure workspace directory is absolute
	if c.WorkspaceDir != "" && !filepath.IsAbs(c.WorkspaceDir) {
		if homeDir, err := os.UserHomeDir(); err == nil {
			c.WorkspaceDir = filepath.Join(homeDir, "netutil-workspace")
		}
	}
}

// GetConfigStatus returns a summary of the configuration status
func (c *Config) GetConfigStatus() map[string]interface{} {
	status := make(map[string]interface{})

	status["workspace_dir"] = c.WorkspaceDir
	status["workspace_exists"] = false
	if c.WorkspaceDir != "" {
		if _, err := os.Stat(c.WorkspaceDir); err == nil {
			status["workspace_exists"] = true
		}
	}

	status["recent_targets_count"] = len(c.RecentTargets)
	status["recent_commands_count"] = len(c.RecentCommands)
	status["remembered_interfaces_count"] = len(c.LastUsedInterface)
	status["default_interface"] = c.DefaultInterface
	status["auto_create_workspace"] = c.AutoCreateWorkspace
	status["show_paths_short"] = c.ShowPathsShort

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

// FixWorkspaceOwnership fixes workspace ownership when running as root
func (c *Config) FixWorkspaceOwnership() error {
	if !c.IsWorkspaceConfigured() {
		return fmt.Errorf("workspace not configured")
	}

	// Only fix ownership if running as root
	if os.Geteuid() != 0 {
		return nil // No need to fix ownership
	}

	// Get original user
	originalUser, err := GetOriginalUser()
	if err != nil {
		return fmt.Errorf("failed to get original user: %w", err)
	}

	// Parse user and group IDs
	uid, err := strconv.Atoi(originalUser.Uid)
	if err != nil {
		return fmt.Errorf("invalid user ID: %w", err)
	}

	gid, err := strconv.Atoi(originalUser.Gid)
	if err != nil {
		return fmt.Errorf("invalid group ID: %w", err)
	}

	// Fix ownership of workspace directory and subdirectories
	return filepath.Walk(c.WorkspaceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip files with errors
		}

		// Change ownership to original user
		if chownErr := syscall.Chown(path, uid, gid); chownErr != nil {
			// Log but don't fail - some files might not be changeable
			fmt.Fprintf(os.Stderr, "Warning: Failed to change ownership of %s: %v\n", path, chownErr)
		}

		return nil
	})
}

// FixWorkspacePermissions ensures workspace directories have correct permissions for root access
func (c *Config) FixWorkspacePermissions() error {
	if !c.IsWorkspaceConfigured() {
		return fmt.Errorf("workspace not configured")
	}

	// Set permissions on workspace subdirectories to allow root write access
	subdirs := []string{
		"captures",
		"enumeration",
		"vulnerability",
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

		// Set permissions to 0777 so root can write to user-owned directories
		if err := os.Chmod(dirPath, 0777); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to set permissions on %s: %v\n", dirPath, err)
		}
	}

	// Also fix permissions on the main workspace directory
	if err := os.Chmod(c.WorkspaceDir, 0777); err != nil {
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
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		return fmt.Errorf("workspace not writable: %w", err)
	}

	// Clean up test file
	os.Remove(testFile)

	return nil
}
