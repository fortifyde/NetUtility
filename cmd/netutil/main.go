package main

import (
	"fmt"
	"os"

	"netutil/internal/app"
	"netutil/internal/ui"
)

func main() {
	if err := app.CheckRootAccess(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	tui := ui.NewTUI()

	if err := tui.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running TUI: %v\n", err)
		os.Exit(1)
	}
}
