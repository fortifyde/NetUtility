package main

import (
	"fmt"
	"os"
	"os/exec"

	"netutil/internal/app"
	"netutil/internal/ui"
)

func main() {
	if err := app.CheckRootAccess(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	for {
		tui := ui.NewTUI()

		if err := tui.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error running TUI: %v\n", err)
			os.Exit(1)
		}

		// Check if a script was selected for execution
		scriptPath, scriptName := tui.GetScriptToRun()
		if scriptPath != "" {
			// Run the script directly in terminal
			runScriptDirect(scriptPath, scriptName)
		} else {
			// User exited normally, break the loop
			break
		}
	}
}

func runScriptDirect(scriptPath string, scriptName string) {
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
	if err != nil {
		fmt.Printf("\n\n[ERROR] Script failed: %v\n", err)
	} else {
		fmt.Printf("\n\nScript completed successfully.\n")
	}

	// Ask user to press enter to continue
	fmt.Printf("\nPress Enter to return to menu...")
	fmt.Scanln()

	// Clear screen again
	fmt.Print("\033[2J\033[H")
}
