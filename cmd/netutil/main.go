package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"netutil/internal/app"
	"netutil/internal/config"
	"netutil/internal/metadata"
	"netutil/internal/ui"
)

func main() {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to load config: %v\n", err)
		cfg = config.GetDefaultConfig()
	}

	// Validate and sanitize configuration
	if err := cfg.ValidateConfig(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Configuration validation failed: %v\n", err)
		fmt.Fprintf(os.Stderr, "Sanitizing configuration...\n")
		cfg.SanitizeConfig()

		// Save sanitized config
		if saveErr := cfg.SaveConfig(); saveErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to save sanitized config: %v\n", saveErr)
		}
	}

	// Check if this is first-time setup
	if cfg.NeedsFirstTimeSetup() {
		fmt.Println("=== Welcome to NetUtility ===")
		fmt.Println("First-time setup required.")
		fmt.Println()
		fmt.Println("NetUtility needs a workspace directory to store:")
		fmt.Println("  • Network captures and analysis results")
		fmt.Println("  • Vulnerability scan data")
		fmt.Println("  • Configuration backups")
		fmt.Println("  • Log files")
		fmt.Println()

		if err := runFirstTimeSetup(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Setup failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Setup complete! Starting NetUtility...")
		fmt.Println()
	}

	// Initialize script registry
	registry := metadata.NewScriptRegistry("scripts")
	if err := registry.LoadMetadata(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to load script metadata: %v\n", err)
		registry = nil // Will fall back to hardcoded commands
	}

	// Set up workspace environment
	if cfg.IsWorkspaceConfigured() {
		// Ensure workspace is writable (handles creation and ownership)
		if err := cfg.EnsureWorkspaceWritable(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to ensure workspace is writable: %v\n", err)
		} else {
			// Set NETUTIL_WORKDIR environment variable
			os.Setenv("NETUTIL_WORKDIR", cfg.WorkspaceDir)
		}
	}

	// Check if CLI arguments are provided
	if len(os.Args) > 1 {
		command := strings.ToLower(os.Args[1])
		// Allow informational commands without root access
		if command == "help" || command == "--help" || command == "-h" ||
			command == "list" || command == "--list" || command == "-l" ||
			command == "recent" || command == "--recent" || command == "-r" {
			handleCLICommand(os.Args[1:], cfg, registry)
			return
		}

		// For other CLI commands, check root access first, then execute
		if err := app.CheckRootAccess(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		handleCLICommand(os.Args[1:], cfg, registry)
		return
	}

	// Default TUI mode - check root access
	if err := app.CheckRootAccess(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Default TUI mode - now with integrated streaming execution
	tui := ui.NewTUI()
	if err := tui.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running TUI: %v\n", err)
		os.Exit(1)
	}
}

// Command mappings for CLI shortcuts
var commandMappings = map[string]ScriptInfo{
	"scan":              {"scripts/network/network_enum.sh", "Network Enumeration"},
	"capture":           {"scripts/network/network_capture.sh", "Network Capture"},
	"enum":              {"scripts/network/network_enum.sh", "Network Enumeration"},
	"vuln":              {"scripts/vulnerability/deep_nse_scan.sh", "Vulnerability Scan"},
	"vulnerability":     {"scripts/vulnerability/deep_nse_scan.sh", "Vulnerability Scan"},
	"config-ip":         {"scripts/system/configure_ip.sh", "Configure IP"},
	"ip":                {"scripts/system/configure_ip.sh", "Configure IP"},
	"interfaces":        {"scripts/system/network_interfaces.sh", "Network Interfaces"},
	"routes":            {"scripts/system/configure_routes.sh", "Configure Routes"},
	"dns":               {"scripts/system/configure_dns.sh", "Configure DNS"},
	"backup":            {"scripts/system/backup_config.sh", "Backup Configuration"},
	"restore":           {"scripts/system/restore_config.sh", "Restore Configuration"},
	"workdir":           {"scripts/system/select_workdir.sh", "Select Working Directory"},
	"vlan":              {"scripts/system/add_vlan.sh", "Add VLAN"},
	"protocols":         {"scripts/network/unsafe_protocols.sh", "Unsafe Protocols"},
	"categorize":        {"scripts/network/categorize_hosts.sh", "Categorize Hosts"},
	"vlans":             {"scripts/network/extract_vlans.sh", "Extract VLANs"},
	"analysis":          {"scripts/vulnerability/vuln_analysis.sh", "Vulnerability Analysis"},
	"device-config":     {"scripts/config/device_config.sh", "Device Configuration"},
	"advanced-analysis": {"scripts/network/advanced_packet_analysis.sh", "Advanced Packet Analysis"},
	"mac-analysis":      {"scripts/network/mac_analysis.sh", "MAC Address Analysis"},
	"multi-discovery":   {"scripts/network/multi_phase_discovery.sh", "Multi-Phase Discovery"},
	"ipv6-discovery":    {"scripts/network/ipv6_discovery.sh", "IPv6 Discovery"},
	"logs":              {"scripts/system/log_management.sh", "Log Management"},
	"workflow":          {"scripts/network/integrated_workflow.sh", "Integrated Workflow"},
}

// Numeric shortcuts (most frequently used)
// runFirstTimeSetup handles the initial workspace configuration
func runFirstTimeSetup(cfg *config.Config) error {
	fmt.Print("Enter workspace directory path (absolute path): ")

	var workspaceDir string
	if _, err := fmt.Scanln(&workspaceDir); err != nil {
		return fmt.Errorf("failed to read workspace directory: %w", err)
	}

	// Validate and set workspace directory
	if err := cfg.SetWorkspaceDir(workspaceDir); err != nil {
		return fmt.Errorf("invalid workspace directory: %w", err)
	}

	// Create workspace structure
	if err := cfg.CreateWorkspace(); err != nil {
		return fmt.Errorf("failed to create workspace: %w", err)
	}

	// Save configuration
	if err := cfg.SaveConfig(); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	fmt.Printf("Workspace created at: %s\n", cfg.WorkspaceDir)
	return nil
}

var numericShortcuts = map[string]ScriptInfo{
	"1": {"scripts/network/network_enum.sh", "Network Enumeration"},
	"2": {"scripts/network/network_capture.sh", "Network Capture"},
	"3": {"scripts/vulnerability/deep_nse_scan.sh", "Vulnerability Scan"},
	"4": {"scripts/system/configure_ip.sh", "Configure IP"},
	"5": {"scripts/system/network_interfaces.sh", "Network Interfaces"},
}

type ScriptInfo struct {
	Path string
	Name string
}

// handleCLICommand processes command line arguments
func handleCLICommand(args []string, cfg *config.Config, registry *metadata.ScriptRegistry) {
	if len(args) == 0 {
		showHelp()
		return
	}

	command := strings.ToLower(args[0])

	// Handle special commands
	switch command {
	case "help", "--help", "-h":
		showHelp()
		return
	case "list", "--list", "-l":
		showCommands()
		return
	case "recent", "--recent", "-r":
		showRecent(cfg)
		return
	}

	// Use metadata registry if available, otherwise fall back to hardcoded mappings
	if registry != nil {
		// Try exact shortcut match first
		if script, exists := registry.GetScriptByShortcut(command); exists {
			success := executeScriptFromMetadata(script, cfg, registry)
			cfg.AddRecentCommand(command, success)
			cfg.SaveConfig()
			return
		}

		// Try fuzzy matching with metadata
		if script, exists := registry.FuzzyMatchScript(command); exists {
			fmt.Printf("Did you mean '%s'? Running %s...\n\n", script.Script.Name, script.Script.Name)
			success := executeScriptFromMetadata(script, cfg, registry)
			cfg.AddRecentCommand(command, success)
			cfg.SaveConfig()
			return
		}
	}

	// Fallback to hardcoded mappings
	// Check numeric shortcuts first
	if scriptInfo, exists := numericShortcuts[command]; exists {
		success := executeScript(scriptInfo.Path, scriptInfo.Name, cfg)
		cfg.AddRecentCommand(command, success)
		cfg.SaveConfig()
		return
	}

	// Check exact command matches
	if scriptInfo, exists := commandMappings[command]; exists {
		success := executeScript(scriptInfo.Path, scriptInfo.Name, cfg)
		cfg.AddRecentCommand(command, success)
		cfg.SaveConfig()
		return
	}

	// Try fuzzy matching
	if match := findFuzzyMatch(command); match != nil {
		fmt.Printf("Did you mean '%s'? Running %s...\n\n", match.Name, match.Name)
		success := executeScript(match.Path, match.Name, cfg)
		cfg.AddRecentCommand(command, success)
		cfg.SaveConfig()
		return
	}

	// Command not found
	fmt.Printf("Unknown command: %s\n\n", command)
	showHelp()
	os.Exit(1)
}

// findFuzzyMatch attempts to find a close match for the command
func findFuzzyMatch(input string) *ScriptInfo {
	// Check if input is a prefix of any command
	for cmd, scriptInfo := range commandMappings {
		if strings.HasPrefix(cmd, input) {
			return &scriptInfo
		}
	}

	// Check if input contains any command
	for cmd, scriptInfo := range commandMappings {
		if strings.Contains(cmd, input) {
			return &scriptInfo
		}
	}

	return nil
}

// executeScriptFromMetadata runs a script using metadata information
func executeScriptFromMetadata(script metadata.ScriptMetadata, cfg *config.Config, registry *metadata.ScriptRegistry) bool {
	scriptPath := registry.GetScriptPath(script)

	// Validate script before execution
	if err := registry.ValidateScript(script); err != nil {
		fmt.Printf("Error: Script validation failed: %v\n", err)
		return false
	}

	return runScriptDirect(scriptPath, script.Script.Name)
}

// executeScript runs a script directly without TUI
func executeScript(scriptPath, scriptName string, cfg *config.Config) bool {
	// Convert to absolute path
	absPath, err := filepath.Abs(scriptPath)
	if err != nil {
		fmt.Printf("Error: Could not resolve script path: %v\n", err)
		return false
	}

	// Check if script exists
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		fmt.Printf("Error: Script not found: %s\n", absPath)
		return false
	}

	return runScriptDirect(absPath, scriptName)
}

// showHelp displays available commands
func showHelp() {
	fmt.Printf("NetUtility - Network Security Toolkit\n\n")
	fmt.Printf("USAGE:\n")
	fmt.Printf("  netutil                    # Launch TUI (default)\n")
	fmt.Printf("  netutil <command>          # Run command directly\n")
	fmt.Printf("  netutil <number>           # Run numbered shortcut\n\n")
	fmt.Printf("SHORTCUTS:\n")
	fmt.Printf("  1-5                        # Most common tasks\n")
	fmt.Printf("  scan, enum                 # Network enumeration\n")
	fmt.Printf("  capture                    # Packet capture\n")
	fmt.Printf("  vuln, vulnerability        # Vulnerability scan\n")
	fmt.Printf("  ip, config-ip              # Configure IP addresses\n")
	fmt.Printf("  interfaces                 # Manage network interfaces\n\n")
	fmt.Printf("OPTIONS:\n")
	fmt.Printf("  -h, --help                 # Show this help\n")
	fmt.Printf("  -l, --list                 # List all commands\n")
	fmt.Printf("  -r, --recent               # Show recent commands\n\n")
	fmt.Printf("EXAMPLES:\n")
	fmt.Printf("  netutil scan               # Run network enumeration\n")
	fmt.Printf("  netutil 1                  # Run most common task\n")
	fmt.Printf("  netutil cap                # Fuzzy match -> capture\n")
	fmt.Printf("  netutil config-ip          # Configure IP addresses\n")
}

// showCommands lists all available commands
func showCommands() {
	fmt.Printf("Available Commands:\n\n")
	fmt.Printf("NUMERIC SHORTCUTS:\n")
	for num, info := range numericShortcuts {
		fmt.Printf("  %s    %s\n", num, info.Name)
	}
	fmt.Printf("\nCOMMANDS:\n")
	for cmd, info := range commandMappings {
		fmt.Printf("  %-15s %s\n", cmd, info.Name)
	}
}

// showRecent displays recent command history
func showRecent(cfg *config.Config) {
	fmt.Printf("Recent Commands:\n\n")

	recentCommands := cfg.GetRecentCommands()
	if len(recentCommands) == 0 {
		fmt.Printf("No recent commands found.\n")
		return
	}

	for _, cmd := range recentCommands {
		fmt.Printf("  %s\n", cmd)
	}
}

func runScriptDirect(scriptPath string, scriptName string) bool {
	// Clear screen
	fmt.Print("\033[2J\033[H")

	// Display script info
	fmt.Printf("\n=== Executing: %s ===\n\n", scriptName)

	// Run script directly in terminal
	cmd := exec.Command("bash", scriptPath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()

	// Show completion message
	success := err == nil
	if err != nil {
		fmt.Printf("\n\n[ERROR] Script failed: %v\n", err)
	} else {
		fmt.Printf("\n\nScript completed successfully.\n")
	}

	// In CLI mode, don't ask for enter, just exit
	if len(os.Args) > 1 {
		return success
	}

	// Ask user to press enter to continue (TUI mode)
	fmt.Printf("\nPress Enter to return to menu...")
	fmt.Scanln()

	// Clear screen again
	fmt.Print("\033[2J\033[H")

	return success
}
