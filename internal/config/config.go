package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
		WorkspaceDir:        filepath.Join(os.Getenv("HOME"), "netutil-workspace"),
		RecentCommands:      []RecentCommand{},
		DefaultInterface:    "",
		AutoCreateWorkspace: true,
		ShowPathsShort:      true,
	}
}

// GetConfigPath returns the path to the config file
func GetConfigPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}

	configDir := filepath.Join(homeDir, ConfigDir)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create config directory: %w", err)
	}

	return filepath.Join(configDir, ConfigFile), nil
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

	// Create main workspace directory
	if err := os.MkdirAll(c.WorkspaceDir, 0755); err != nil {
		return fmt.Errorf("failed to create workspace directory: %w", err)
	}

	// Create subdirectories
	subdirs := []string{
		"captures",
		"enumeration",
		"vulnerability",
		"configs",
		"logs",
	}

	for _, subdir := range subdirs {
		path := filepath.Join(c.WorkspaceDir, subdir)
		if err := os.MkdirAll(path, 0755); err != nil {
			return fmt.Errorf("failed to create subdirectory %s: %w", subdir, err)
		}
	}

	// Create symbolic links for latest results
	latestDir := filepath.Join(c.WorkspaceDir, "latest")
	if err := os.MkdirAll(latestDir, 0755); err != nil {
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
