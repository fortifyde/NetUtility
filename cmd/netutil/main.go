package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"netutil/internal/app"
	"netutil/internal/config"
	"netutil/internal/metadata"
	"netutil/internal/executor"
	"netutil/internal/ui"
)

// version is set at build time via -ldflags "-X main.version=..."
var version = "dev"

// ensureExecutable ensures all binaries in bin/ and shell scripts in scripts/
// have the executable bit set. Called at TUI startup so permissions are always
// correct regardless of how the files were installed or extracted.
func ensureExecutable(execDir, scriptsDir string) {
	// Make everything in bin/ executable
	binDir := filepath.Join(execDir, "bin")
	if entries, err := os.ReadDir(binDir); err == nil {
		for _, e := range entries {
			if !e.Type().IsRegular() {
				continue
			}
			path := filepath.Join(binDir, e.Name())
			if info, err := e.Info(); err == nil {
				if info.Mode()&0111 == 0 {
					_ = os.Chmod(path, info.Mode()|0755)
				}
			}
		}
	}

	// Make all .sh files in scripts/ (recursively) executable
	_ = filepath.Walk(scriptsDir, func(path string, info os.FileInfo, err error) error { //nolint:gosec // G122: air-gapped tool
		if err != nil || info.IsDir() {
			return nil
		}
		if filepath.Ext(path) == ".sh" && info.Mode()&0111 == 0 {
		_ = os.Chmod(path, info.Mode()|0755) //nolint:gosec // G122: air-gapped tool
		}
		return nil
	})
}

// getDefaultScriptsDir returns the path to the scripts directory
// located next to the executable (same pattern as config file)
func getDefaultScriptsDir() string {
	// Get executable directory
	execPath, err := os.Executable()
	if err != nil {
		// Fallback to relative path if we can't determine executable location
		return "scripts"
	}

	execDir := filepath.Dir(execPath)

	// Scripts directory is located next to the executable
	return filepath.Join(execDir, "scripts")
}

func main() {
	os.Exit(run())
}

func run() int {
	scriptsDir, shouldExit, exitCode := parseCLIFlags()
	if shouldExit {
		return exitCode
	}

	// Ensure bin/ and scripts/ are executable (idempotent, silent)
	execPath, _ := os.Executable()
	ensureExecutable(filepath.Dir(execPath), scriptsDir)

	// Load and validate configuration
	cfg := loadAndSanitizeConfig()

	// Handle first-time setup if needed
	if err := handleFirstTimeSetup(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Setup failed: %v\n", err)
		return 1
	}

	// Initialize script registry with resolved scripts directory
	registry := metadata.NewScriptRegistry(scriptsDir)
	if err := registry.LoadMetadata(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to load script metadata: %v\n", err)
		registry = nil // Will fall back to hardcoded commands
	}

	// Set up workspace environment
	setupWorkspaceEnv(cfg)

	// Get remaining arguments after flag parsing
	args := flag.Args()

	// Check if CLI arguments are provided
	if len(args) > 0 {
		command := strings.ToLower(args[0])
		// Allow informational commands without root access
		if command == "help" || command == "--help" || command == "-h" ||
			command == "list" || command == "--list" || command == "-l" {
			handleCLICommand(args, cfg, registry)
			return 0
		}

		// For other CLI commands, check root access first, then execute
		if err := app.CheckRootAccess(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return 1
		}

		if !handleCLICommand(args, cfg, registry) {
			return 1
		}
		return 0
	}

	// Default TUI mode - check root access
	if err := app.CheckRootAccess(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	// Default TUI mode - now with integrated streaming execution
	tui := ui.NewTUI(scriptsDir, cfg.WorkspaceDir, cfg.Language, version)
	defer tui.Stop() // Ensure child processes are killed on any exit path
	if err := tui.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running TUI: %v\n", err)
		return 1
	}

	return 0
}

// parseCLIFlags parses command-line flags and returns the resolved scripts directory.
// If the program should exit early (e.g., --version), shouldExit is true and
// exitCode contains the appropriate code.
func parseCLIFlags() (scriptsDir string, shouldExit bool, exitCode int) {
	scriptsDirFlag := flag.String("scripts-dir", "", "Path to scripts directory (default: next to executable)")
	showVersion := flag.Bool("version", false, "Show version")
	flag.Parse()

	if *showVersion {
		fmt.Printf("NetUtility %s\n", version)
		return "", true, 0
	}

	scriptsDir = getDefaultScriptsDir()
	if *scriptsDirFlag != "" {
		scriptsDir = *scriptsDirFlag
	}
	return scriptsDir, false, 0
}

// loadAndSanitizeConfig loads the application configuration, falling back to
// defaults on failure. If validation fails, the config is sanitized and saved.
func loadAndSanitizeConfig() *config.Config {
	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to load config: %v\n", err)
		cfg = config.GetDefaultConfig()
	}

	if err := cfg.ValidateConfig(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Configuration validation failed: %v\n", err)
		fmt.Fprintf(os.Stderr, "Sanitizing configuration...\n")
		cfg.SanitizeConfig()

		if saveErr := cfg.SaveConfig(); saveErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to save sanitized config: %v\n", saveErr)
		}
	}

	return cfg
}

// handleFirstTimeSetup runs the initial workspace configuration if needed.
// Returns nil if no setup is needed or if setup succeeds.
func handleFirstTimeSetup(cfg *config.Config) error {
	if !cfg.NeedsFirstTimeSetup() {
		return nil
	}

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
		return err
	}

	fmt.Println("Setup complete! Starting NetUtility...")
	fmt.Println()
	return nil
}

// setupWorkspaceEnv ensures the workspace directory is writable and sets the
// NETUTIL_WORKDIR environment variable for child processes.
func setupWorkspaceEnv(cfg *config.Config) {
	if !cfg.IsWorkspaceConfigured() {
		return
	}
	if err := cfg.EnsureWorkspaceWritable(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to ensure workspace is writable: %v\n", err)
		return
	}
	if err := os.Setenv("NETUTIL_WORKDIR", cfg.WorkspaceDir); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to set NETUTIL_WORKDIR: %v\n", err)
	}
}

// Command mappings for CLI shortcuts
var commandMappings = map[string]ScriptInfo{
	// Discovery
	"capture":         {"scripts/discovery/network_capture.sh", "Network Capture"},
	"multi-discovery": {"scripts/discovery/multi_phase_discovery.sh", "Discovery-Scan"},
	"extract-vlans":   {"scripts/discovery/extract_vlans.sh", "Extract VLANs"},
	"mac-analysis":    {"scripts/discovery/mac_analysis.sh", "MAC Address Analysis"},
	"packet-analysis": {"scripts/discovery/advanced_packet_analysis.sh", "Packet Capture Analysis"},
	// Scanning
	"port-scan":     {"scripts/scanning/port_service_scan.sh", "Port & Service Scan"},
	"full-scan":     {"scripts/scanning/port_service_scan.sh", "Port & Service Scan"},
	"vuln":          {"scripts/scanning/vulnerability_assessment.sh", "Vulnerability Assessment"},
	"vulnerability": {"scripts/scanning/vulnerability_assessment.sh", "Vulnerability Assessment"},
	// Host configuration
	"config-ip":        {"scripts/host-config/configure_ip.sh", "Configure IP Addresses"},
	"ip":               {"scripts/host-config/configure_ip.sh", "Configure IP Addresses"},
	"interfaces":       {"scripts/host-config/network_interfaces.sh", "Manage Network Interfaces"},
	"routes":           {"scripts/host-config/configure_routes.sh", "Configure Routes"},
	"dns":              {"scripts/host-config/configure_dns.sh", "Configure DNS"},
	"vlan":             {"scripts/host-config/add_vlan.sh", "Manage VLAN Interfaces"},
	"setup-fileserver": {"scripts/host-config/setup_file_server.sh", "Setup File Server"},
	// Utilities
	"backup":       {"scripts/utilities/backup_config.sh", "Backup Configuration"},
	"restore":      {"scripts/utilities/restore_config.sh", "Restore Configuration"},
	"workdir":      {"scripts/utilities/select_workdir.sh", "Select Working Directory"},
	"logs":         {"scripts/utilities/log_management.sh", "Log Management"},
	"update-oui":   {"scripts/utilities/update_oui_db.sh", "Update OUI Database"},
	"exclude-team": {"scripts/utilities/exclude_team_ips.sh", "Exclude Team IPs"},
	// Advanced
	"auto-discover":  {"scripts/advanced/auto_discover.sh", "Auto Discovery"},
	"gather-configs": {"scripts/config/gather_network_configs.sh", "Network Config Gatherer"},
	"screenshot":     {"scripts/advanced/web_screenshot.sh", "Web Services Gatherer"},
	"lldp":           {"scripts/advanced/lldp_cdp_discovery.sh", "LLDP/CDP Neighbor Discovery"},
	"cdp":            {"scripts/advanced/lldp_cdp_discovery.sh", "LLDP/CDP Neighbor Discovery"},
	"snmp":           {"scripts/advanced/snmp_interrogate.sh", "SNMP Device Interrogation"},
	"exploits":       {"scripts/advanced/exploit_search.sh", "Exploit Search"},
	"fingerprint":    {"scripts/discovery/passive_fingerprint.sh", "Passive Fingerprinting"},
	"arp":            {"scripts/discovery/arp_ingest.sh", "ARP Table Ingestion"},
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
	"1": {"scripts/discovery/multi_phase_discovery.sh", "Discovery-Scan"},
	"2": {"scripts/discovery/network_capture.sh", "Network Capture"},
	"3": {"scripts/scanning/vulnerability_assessment.sh", "Vulnerability Assessment"},
	"4": {"scripts/host-config/configure_ip.sh", "Configure IP Addresses"},
	"5": {"scripts/host-config/network_interfaces.sh", "Manage Network Interfaces"},
}

type ScriptInfo struct {
	Path string
	Name string
}

// handleCLICommand processes command line arguments. Returns false if the command was not found.
func handleCLICommand(args []string, cfg *config.Config, registry *metadata.ScriptRegistry) bool {
	if len(args) == 0 {
		showHelp()
		return true
	}

	command := strings.ToLower(args[0])

	// Handle special commands
	switch command {
	case "help", "--help", "-h":
		showHelp()
		return true
	case "list", "--list", "-l":
		showCommands()
		return true
	}

	// Use metadata registry if available, otherwise fall back to hardcoded mappings
	if registry != nil {
		// Try exact shortcut match first
		if script, exists := registry.GetScriptByShortcut(command); exists {
			executeScriptFromMetadata(script, cfg, registry)
			return true
		}

		// Try fuzzy matching with metadata
		if script, exists := registry.FuzzyMatchScript(command); exists {
			fmt.Printf("Did you mean '%s'? Running %s...\n\n", script.Script.Name, script.Script.Name)
			executeScriptFromMetadata(script, cfg, registry)
			return true
		}
	}

	// Fallback to hardcoded mappings
	// Check numeric shortcuts first
	if scriptInfo, exists := numericShortcuts[command]; exists {
		executeScript(scriptInfo.Path, scriptInfo.Name, cfg)
		return true
	}

	// Check exact command matches
	if scriptInfo, exists := commandMappings[command]; exists {
		executeScript(scriptInfo.Path, scriptInfo.Name, cfg)
		return true
	}

	// Try fuzzy matching
	if match := findFuzzyMatch(command); match != nil {
		fmt.Printf("Did you mean '%s'? Running %s...\n\n", match.Name, match.Name)
		executeScript(match.Path, match.Name, cfg)
		return true
	}

	// Command not found
	fmt.Printf("Unknown command: %s\n\n", command)
	showHelp()
	return false
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

	success := runScriptDirect(absPath, scriptName)

	// Fix workspace file ownership when running as root.
	if cfg.IsWorkspaceConfigured() {
		config.FixWorkspaceOwnershipForPath(cfg.WorkspaceDir)
	}

	return success
}

// showHelp displays available commands
func showHelp() {
	fmt.Printf("NetUtility %s - Network Security Toolkit\n\n", version)
	fmt.Printf("USAGE:\n")
	fmt.Printf("  netutil [flags]            # Launch TUI (default)\n")
	fmt.Printf("  netutil [flags] <command>  # Run command directly\n")
	fmt.Printf("  netutil [flags] <number>   # Run numbered shortcut\n\n")
	fmt.Printf("FLAGS:\n")
	fmt.Printf("  --scripts-dir <path>       # Override scripts directory location\n")
	fmt.Printf("  --version                  # Show version\n\n")
	fmt.Printf("SHORTCUTS:\n")
	fmt.Printf("  1-5                        # Most common tasks\n")
	fmt.Printf("  scan, enum                 # Network enumeration\n")
	fmt.Printf("  capture                    # Packet capture\n")
	fmt.Printf("  vuln, vulnerability        # Vulnerability assessment\n")
	fmt.Printf("  ip, config-ip              # Configure IP addresses\n")
	fmt.Printf("  interfaces                 # Manage network interfaces\n\n")
	fmt.Printf("OPTIONS:\n")
	fmt.Printf("  -h, --help                 # Show this help\n")
	fmt.Printf("  -h, --help                 # Show this help\n")
	fmt.Printf("  -l, --list                 # List all commands\n\n")
	fmt.Printf("EXAMPLES:\n")
	fmt.Printf("  netutil scan               # Run network enumeration\n")
	fmt.Printf("  netutil 1                  # Run most common task\n")
	fmt.Printf("  netutil cap                # Fuzzy match -> capture\n")
	fmt.Printf("  netutil config-ip          # Configure IP addresses\n")
	fmt.Printf("  netutil --scripts-dir /custom/path list\n")
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


func runScriptDirect(scriptPath string, scriptName string) bool {
	// Clear screen
	fmt.Print("\033[2J\033[H")

	// Display script info
	fmt.Printf("\n=== Executing: %s ===\n\n", scriptName)

	// Run script directly in terminal
	interp, interpArgs := executor.DetectInterpreter(scriptPath)
	cmd := exec.Command(interp, append(interpArgs, scriptPath)...)
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
	_, _ = fmt.Scanln()

	// Clear screen again
	fmt.Print("\033[2J\033[H")

	return success
}
