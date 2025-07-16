package ui

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"netutil/internal/executor"
)

type TUI struct {
	app             *tview.Application
	pages           *tview.Pages
	categoryList    *tview.List
	taskList        *tview.List
	outputView      *tview.TextView
	statusBar       *tview.TextView
	inputField      *tview.InputField
	inputModal      *tview.Modal
	currentCategory string
	executor        *executor.Executor
	scriptRunning   bool
	interactiveMode bool
	currentPrompt   string
	activeSession   *executor.InteractiveSession
	inputResponse   chan string
	inputMu         sync.RWMutex // Separate mutex for input handling
	awaitingInput   bool         // Track if we're waiting for user input
	mu              sync.RWMutex
}

type Category struct {
	Name  string
	Tasks []Task
}

type Task struct {
	Name        string
	Description string
	Script      string
}

// getCategories returns the list of available categories and their tasks.
func getCategories() []Category {
	return []Category{
		{
			Name: "System Configuration",
			Tasks: []Task{
				{Name: "Select Working Directory", Description: "Choose working directory for operations", Script: "select_workdir.sh"},
				{Name: "Network Interfaces", Description: "View and toggle network interfaces", Script: "network_interfaces.sh"},
				{Name: "Configure IP Addresses", Description: "Set IP addresses on interfaces", Script: "configure_ip.sh"},
				{Name: "Add VLAN Interfaces", Description: "Create VLAN subinterfaces", Script: "add_vlan.sh"},
				{Name: "Configure Routes", Description: "View and configure IP routes", Script: "configure_routes.sh"},
				{Name: "Configure Nameservers", Description: "Set DNS nameservers", Script: "configure_dns.sh"},
				{Name: "Backup Configuration", Description: "Backup current network configuration", Script: "backup_config.sh"},
				{Name: "Restore Configuration", Description: "Restore network configuration from backup", Script: "restore_config.sh"},
			},
		},
		{
			Name: "Network Reconnaissance",
			Tasks: []Task{
				{Name: "Network Capture", Description: "Run tshark packet capture for 10 minutes", Script: "network_capture.sh"},
				{Name: "Extract VLAN IDs", Description: "Extract VLAN IDs from capture files", Script: "extract_vlans.sh"},
				{Name: "Unsafe Protocol Detection", Description: "Detect unencrypted protocols in traffic", Script: "unsafe_protocols.sh"},
				{Name: "Network Enumeration", Description: "Scan network with nmap and fping", Script: "network_enum.sh"},
				{Name: "Host Categorization", Description: "Categorize discovered hosts by OS", Script: "categorize_hosts.sh"},
			},
		},
		{
			Name: "Vulnerability Assessment",
			Tasks: []Task{
				{Name: "Deep Scan with NSE", Description: "Full port scan with service detection and NSE vulnerability scripts", Script: "deep_nse_scan.sh"},
				{Name: "Vulnerability Analysis", Description: "Analyze results for known vulnerabilities", Script: "vuln_analysis.sh"},
			},
		},
		{
			Name: "Config Gatherer",
			Tasks: []Task{
				{Name: "Device Configuration Gathering", Description: "SSH to device, detect vendor, and gather configuration", Script: "device_config.sh"},
			},
		},
	}
}

func NewTUI() *TUI {
	app := tview.NewApplication()

	tui := &TUI{
		app:           app,
		pages:         tview.NewPages(),
		categoryList:  tview.NewList(),
		taskList:      tview.NewList(),
		outputView:    tview.NewTextView(),
		statusBar:     tview.NewTextView(),
		executor:      executor.NewExecutor(),
		inputResponse: make(chan string, 1),
	}

	tui.setupUI()
	return tui
}

func (t *TUI) setupUI() {
	t.categoryList.SetBorder(true).SetTitle("Categories")
	t.taskList.SetBorder(true).SetTitle("Tasks")
	t.outputView.SetBorder(true).SetTitle("Output")
	t.statusBar.SetBorder(true).SetTitle("Status")

	t.outputView.SetDynamicColors(true).SetScrollable(true)
	t.statusBar.SetText("Ready - Select a category to begin")

	for i, category := range getCategories() {
		t.categoryList.AddItem(category.Name, "", rune('1'+i), func() {
			t.showCategory(category.Name)
		})
	}

	t.categoryList.SetSelectedFunc(func(index int, mainText, secondaryText string, shortcut rune) {
		t.showCategory(mainText)
	})

	t.taskList.SetSelectedFunc(func(index int, mainText, secondaryText string, shortcut rune) {
		t.executeTask(mainText)
	})

	leftPanel := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(t.categoryList, 0, 1, true).
		AddItem(t.taskList, 0, 1, false)

	rightPanel := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(t.outputView, 0, 4, false).
		AddItem(t.statusBar, 3, 0, false)

	main := tview.NewFlex().
		AddItem(leftPanel, 0, 1, true).
		AddItem(rightPanel, 0, 2, false)

	t.pages.AddPage("main", main, true, true)
	t.app.SetRoot(t.pages, true)

	t.app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyTab:
			t.switchFocus()
			return nil
		case tcell.KeyEscape:
			// Check if we're in interactive mode first
			if t.isSessionActive() {
				t.app.QueueUpdateDraw(func() {
					if _, err := fmt.Fprintf(t.outputView, "\n[yellow]Interactive session cancelled by user[white]\n"); err != nil {
						// Log error but continue
					}
					t.statusBar.SetText("Interactive session cancelled")
				})
				t.terminateActiveSession()
				t.hideInputModal()
				t.app.SetFocus(t.taskList)
				return nil
			}
			// Otherwise, exit the application
			t.app.Stop()
			return nil
		case tcell.KeyCtrlC:
			// Ctrl+C should also cancel interactive sessions
			if t.isSessionActive() {
				t.app.QueueUpdateDraw(func() {
					if _, err := fmt.Fprintf(t.outputView, "\n[yellow]Interactive session terminated by user (Ctrl+C)[white]\n"); err != nil {
						// Log error but continue
					}
					t.statusBar.SetText("Interactive session terminated")
				})
				t.terminateActiveSession()
				t.hideInputModal()
				t.app.SetFocus(t.taskList)
				return nil
			}
			return event
		default:
			// Handle all other keys by passing them through
			return event
		}
	})
}

func (t *TUI) showCategory(categoryName string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.currentCategory = categoryName
	t.taskList.Clear()
	t.taskList.SetTitle(fmt.Sprintf("Tasks - %s", categoryName))

	for _, category := range getCategories() {
		if category.Name == categoryName {
			for i, task := range category.Tasks {
				t.taskList.AddItem(task.Name, task.Description, rune('1'+i), nil)
			}
			break
		}
	}

	t.statusBar.SetText(fmt.Sprintf("Category: %s - Select a task to execute", categoryName))
	// Automatically focus on task list when category is selected
	t.app.SetFocus(t.taskList)
}

func (t *TUI) executeTask(taskName string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.scriptRunning {
		t.statusBar.SetText("Script already running - please wait for completion")
		if _, err := fmt.Fprintf(t.outputView, "[yellow]Another script is already running. Please wait for it to complete.[white]\n"); err != nil {
			// Log error but continue
		}
		return
	}

	// Check if there's an active interactive session
	if t.activeSession != nil && t.activeSession.IsActive() {
		t.statusBar.SetText("Interactive session active - please complete current interaction")
		if _, err := fmt.Fprintf(t.outputView, "[yellow]An interactive session is already active. Please complete the current interaction or press Escape to cancel.[white]\n"); err != nil {
			// Log error but continue
		}
		return
	}

	t.statusBar.SetText(fmt.Sprintf("Executing: %s", taskName))
	t.outputView.Clear()
	t.outputView.SetTitle(fmt.Sprintf("Output - %s", taskName))

	if _, err := fmt.Fprintf(t.outputView, "[yellow]Starting task: %s[white]\n", taskName); err != nil {
		// Log error but continue
	}
	if _, err := fmt.Fprintf(t.outputView, "[blue]Category: %s[white]\n\n", t.currentCategory); err != nil {
		// Log error but continue
	}

	for _, category := range getCategories() {
		if category.Name == t.currentCategory {
			for _, task := range category.Tasks {
				if task.Name == taskName {
					if _, err := fmt.Fprintf(t.outputView, "[green]Script: %s[white]\n", task.Script); err != nil {
						// Log error but continue
					}
					if _, err := fmt.Fprintf(t.outputView, "[gray]Description: %s[white]\n\n", task.Description); err != nil {
						// Log error but continue
					}

					scriptPath := filepath.Join("scripts", t.getScriptFolder(t.currentCategory), task.Script)
					t.scriptRunning = true

					// Automatically focus on output view when task is selected
					t.app.SetFocus(t.outputView)

					// All scripts now run in interactive mode to enable proper user interaction
					go t.runInteractiveScript(scriptPath, taskName)
					return
				}
			}
			break
		}
	}

	t.statusBar.SetText(fmt.Sprintf("Task completed: %s", taskName))
}

func (t *TUI) isInteractiveScript(scriptName string) bool {
	// List of scripts that require interactive input
	interactiveScripts := []string{
		// System scripts
		"network_interfaces.sh",
		"configure_ip.sh",
		"select_workdir.sh",
		"configure_dns.sh",
		"configure_routes.sh",
		"add_vlan.sh",
		"restore_config.sh",

		// Network scripts
		"network_enum.sh",
		"network_capture.sh",
		"extract_vlans.sh",
		"categorize_hosts.sh",
		"unsafe_protocols.sh",

		// Vulnerability scripts
		"deep_nse_scan.sh",
		"vuln_analysis.sh",

		// Config scripts
		"device_config.sh",
	}

	for _, interactive := range interactiveScripts {
		if scriptName == interactive {
			return true
		}
	}
	return false
}

func (t *TUI) getScriptFolder(category string) string {
	switch category {
	case "System Configuration":
		return "system"
	case "Network Reconnaissance":
		return "network"
	case "Vulnerability Assessment":
		return "vulnerability"
	case "Config Gatherer":
		return "config"
	default:
		return "unknown"
	}
}

func (t *TUI) switchFocus() {
	// Check if we're currently showing an input modal
	t.inputMu.RLock()
	isAwaitingInput := t.awaitingInput
	t.inputMu.RUnlock()

	// If input modal is active, cycle between input field and output view
	if isAwaitingInput {
		current := t.app.GetFocus()
		if current == t.inputField {
			t.app.SetFocus(t.outputView)
		} else {
			t.app.SetFocus(t.inputField)
		}
		return
	}

	// Check if script is running - keep focus cycling between output and task list
	t.mu.RLock()
	isScriptRunning := t.scriptRunning
	t.mu.RUnlock()

	if isScriptRunning {
		current := t.app.GetFocus()
		if current == t.outputView {
			t.app.SetFocus(t.taskList)
		} else {
			t.app.SetFocus(t.outputView)
		}
		return
	}

	// Normal focus cycling when no script is running
	current := t.app.GetFocus()
	switch current {
	case t.categoryList:
		t.app.SetFocus(t.taskList)
	case t.taskList:
		t.app.SetFocus(t.outputView)
	case t.outputView:
		t.app.SetFocus(t.categoryList)
	default:
		t.app.SetFocus(t.categoryList)
	}
}

func (t *TUI) UpdateOutput(text string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if _, err := fmt.Fprint(t.outputView, text); err != nil {
		// Log error but continue
	}
}

func (t *TUI) UpdateStatus(text string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.statusBar.SetText(text)
}

// updateStatusWithMode updates the status bar with interactive mode indicators
func (t *TUI) updateStatusWithMode(text string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	var statusText string
	if t.interactiveMode {
		statusText = fmt.Sprintf("[INTERACTIVE] %s", text)
	} else {
		statusText = text
	}

	t.statusBar.SetText(statusText)
}

// getExecutionState returns the current execution state for debugging
func (t *TUI) getExecutionState() map[string]interface{} {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return map[string]interface{}{
		"scriptRunning":    t.scriptRunning,
		"interactiveMode":  t.interactiveMode,
		"hasActiveSession": t.activeSession != nil,
		"sessionIsActive":  t.activeSession != nil && t.activeSession.IsActive(),
		"currentPrompt":    t.currentPrompt,
		"currentCategory":  t.currentCategory,
	}
}

func (t *TUI) Run() error {
	if err := t.app.Run(); err != nil {
		return fmt.Errorf("TUI application failed: %w", err)
	}
	return nil
}

func (t *TUI) Stop() {
	// Terminate any active session before stopping
	t.terminateActiveSession()
	t.app.Stop()
}

// terminateActiveSession safely terminates the current active session
func (t *TUI) terminateActiveSession() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.activeSession != nil && t.activeSession.IsActive() {
		if err := t.activeSession.Terminate(); err != nil {
			// Log error but continue
		}
		t.activeSession = nil
		t.interactiveMode = false
		t.scriptRunning = false
	}

	// Also clear any pending input state
	t.inputMu.Lock()
	t.awaitingInput = false
	t.inputMu.Unlock()

	// Clear the input response channel
	select {
	case <-t.inputResponse:
	default:
	}
}

// isSessionActive returns true if there's an active interactive session
func (t *TUI) isSessionActive() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.activeSession != nil && t.activeSession.IsActive()
}

// getCurrentSession returns the current active session (if any)
func (t *TUI) getCurrentSession() *executor.InteractiveSession {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.activeSession
}

// createInputModal creates and configures the input modal for user interaction
func (t *TUI) createInputModal(prompt string) {
	t.inputMu.Lock()
	defer t.inputMu.Unlock()

	// Clear any existing input state
	t.awaitingInput = true

	t.inputField = tview.NewInputField().
		SetLabel(prompt + " ").
		SetFieldWidth(50).
		SetDoneFunc(func(key tcell.Key) {
			switch key {
			case tcell.KeyEnter:
				input := t.inputField.GetText()
				t.inputField.SetText("")

				// Send the input response safely
				t.sendInputResponse(input)

				// Hide the modal
				t.hideInputModalInternal()
			case tcell.KeyEscape:
				// Cancel input - send empty string to unblock
				t.inputField.SetText("")
				t.sendInputResponse("")
				t.hideInputModalInternal()
			case tcell.KeyTab:
				// Allow tab switching while in input mode
				t.switchFocus()
			default:
				// Allow other keys to be handled by the input field
				return
			}
		})

	t.inputModal = tview.NewModal().
		AddButtons([]string{"OK", "Cancel"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			if buttonLabel == "OK" {
				input := t.inputField.GetText()
				t.inputField.SetText("")
				t.sendInputResponse(input)
			} else {
				// Cancel - send empty string to unblock
				t.sendInputResponse("")
			}

			// Hide the modal
			t.hideInputModalInternal()
		})

	// Create a flex container for the input field and modal
	inputContainer := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(t.inputField, 3, 0, true).
		AddItem(t.inputModal, 0, 1, false)

	// Set input field styling for better visibility
	t.inputField.SetBorder(true).SetTitle("User Input")

	t.pages.AddPage("input", inputContainer, true, false)
}

// showInputModal displays the input modal with the given prompt
func (t *TUI) showInputModal(prompt string) {
	t.app.QueueUpdateDraw(func() {
		// Only show modal if we're not already awaiting input
		t.inputMu.RLock()
		isAwaiting := t.awaitingInput
		t.inputMu.RUnlock()

		if !isAwaiting {
			// Remove any existing input page first
			t.pages.RemovePage("input")

			t.createInputModal(prompt)
			t.pages.ShowPage("input")
			t.app.SetFocus(t.inputField)
		}
	})
}

// hideInputModal hides the input modal
func (t *TUI) hideInputModal() {
	t.app.QueueUpdateDraw(func() {
		t.hideInputModalInternal()
	})
}

// hideInputModalInternal hides the input modal without queueing
func (t *TUI) hideInputModalInternal() {
	t.inputMu.Lock()
	t.awaitingInput = false
	t.inputMu.Unlock()

	// Remove the input page completely to prevent lingering references
	t.pages.RemovePage("input")

	// Return focus to output view to maintain interaction with running scripts
	t.app.SetFocus(t.outputView)
}

// sendInputResponse safely sends input to the response channel
func (t *TUI) sendInputResponse(input string) {
	t.inputMu.Lock()
	defer t.inputMu.Unlock()

	// Only send if we're actually awaiting input
	if t.awaitingInput {
		select {
		case t.inputResponse <- input:
			t.awaitingInput = false
		default:
			// Channel is full or closed, mark as not awaiting
			t.awaitingInput = false
		}
	}
}

// detectPrompt checks if a line contains a prompt requiring user input
func (t *TUI) detectPrompt(line string) bool {
	// Remove stdout/stderr prefixes for analysis
	cleanLine := line
	if strings.HasPrefix(line, "[stdout] ") {
		cleanLine = strings.TrimPrefix(line, "[stdout] ")
	} else if strings.HasPrefix(line, "[stderr] ") {
		cleanLine = strings.TrimPrefix(line, "[stderr] ")
	}

	// Trim whitespace for consistent pattern matching
	trimmed := strings.TrimSpace(cleanLine)
	lowerLine := strings.ToLower(trimmed)

	// High-priority patterns: Lines ending with common prompt indicators
	if strings.HasSuffix(trimmed, ": ") || strings.HasSuffix(trimmed, ":") {
		return true
	}

	// Detect read command prompt patterns commonly used in bash scripts
	readPatterns := []string{
		"read -p",    // read -p prompts
		"read -r -p", // read -r -p prompts
		"read -r -t", // read with timeout
		"read -t",    // read with timeout
		"read -s -p", // read silent (password) prompts
	}

	for _, pattern := range readPatterns {
		if strings.Contains(lowerLine, pattern) {
			return true
		}
	}

	// Common prompt text patterns (case-insensitive)
	promptPatterns := []string{
		"? ",        // Question prompts ending with question mark space
		"(y/n)",     // Yes/no prompts
		"[y/N]",     // Yes/no prompts with default N
		"[Y/n]",     // Yes/no prompts with default Y
		"(y/N)",     // Alternative yes/no format
		"(Y/n)",     // Alternative yes/no format
		"enter ",    // Enter prompts
		"input ",    // Input prompts
		"choice",    // Choice prompts
		"select",    // Selection prompts
		"option",    // Option selection prompts
		"password",  // Password prompts
		"username",  // Username prompts
		"continue",  // Continue prompts
		"proceed",   // Proceed prompts
		"address",   // IP address prompts
		"interface", // Interface prompts
		"device",    // Device prompts
		"path",      // File path prompts
		"file",      // File selection prompts
		"directory", // Directory selection prompts
		"timeout",   // Timeout-related prompts
		"waiting",   // Waiting for input prompts
	}

	// Check for prompt patterns
	for _, pattern := range promptPatterns {
		if strings.Contains(lowerLine, pattern) {
			return true
		}
	}

	// Check for lines that look like menu selections
	if strings.Contains(lowerLine, "select option") ||
		strings.Contains(lowerLine, "choose option") ||
		strings.Contains(lowerLine, "enter option") {
		return true
	}

	// Check for numbered menu patterns like "Select action (1-4):"
	if strings.Contains(lowerLine, "(") && strings.Contains(lowerLine, ")") &&
		(strings.Contains(lowerLine, "select") || strings.Contains(lowerLine, "choose")) {
		return true
	}

	return false
}

// extractPromptText extracts the prompt text from a line for display
func (t *TUI) extractPromptText(line string) string {
	// Remove stdout/stderr prefixes
	cleanLine := line
	if strings.HasPrefix(line, "[stdout] ") {
		cleanLine = strings.TrimPrefix(line, "[stdout] ")
	} else if strings.HasPrefix(line, "[stderr] ") {
		cleanLine = strings.TrimPrefix(line, "[stderr] ")
	}

	return strings.TrimSpace(cleanLine)
}

func (t *TUI) runInteractiveScript(scriptPath string, taskName string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	defer func() {
		t.mu.Lock()
		t.scriptRunning = false
		t.interactiveMode = false
		t.activeSession = nil
		t.mu.Unlock()

		// Clear input state on exit
		t.inputMu.Lock()
		t.awaitingInput = false
		t.inputMu.Unlock()

		// Hide any open input modal
		t.app.QueueUpdateDraw(func() {
			t.pages.HidePage("input")
		})
	}()

	t.app.QueueUpdateDraw(func() {
		if _, err := fmt.Fprintf(t.outputView, "[cyan]Executing interactive script: %s[white]\n", scriptPath); err != nil {
			// Log error but continue
		}
		if _, err := fmt.Fprintf(t.outputView, "[yellow]Interactive mode enabled - input prompts will appear when needed[white]\n"); err != nil {
			// Log error but continue
		}
		if _, err := fmt.Fprintf(t.outputView, "[blue]Press ESC to cancel interactive session[white]\n\n"); err != nil {
			// Log error but continue
		}
		t.updateStatusWithMode("Running interactive script - waiting for output...")
	})

	// Start the interactive session
	session, err := t.executor.ExecuteInteractiveScript(ctx, scriptPath)
	if err != nil {
		t.app.QueueUpdateDraw(func() {
			if _, err := fmt.Fprintf(t.outputView, "\n[red]Error starting interactive script: %v[white]\n", err); err != nil {
				// Log error but continue
			}
			t.statusBar.SetText("Script failed to start")
			t.app.SetFocus(t.taskList)
		})
		return
	}

	// Store the active session
	t.mu.Lock()
	t.activeSession = session
	t.interactiveMode = true
	t.mu.Unlock()

	// Handle session output and interaction
	go func() {
		for {
			select {
			case output, ok := <-session.GetOutputChannel():
				if !ok {
					return
				}
				t.app.QueueUpdateDraw(func() {
					if _, err := fmt.Fprintf(t.outputView, "%s\n", output); err != nil {
						// Log error but continue
					}

					// Check if this output contains a prompt
					if t.detectPrompt(output) {
						promptText := t.extractPromptText(output)
						t.currentPrompt = promptText
						t.updateStatusWithMode(fmt.Sprintf("Waiting for input: %s", promptText))
						t.showInputModal(promptText)
					}
				})
			case err, ok := <-session.GetErrorChannel():
				if !ok {
					return
				}
				t.app.QueueUpdateDraw(func() {
					if _, err := fmt.Fprintf(t.outputView, "[red]Error: %v[white]\n", err); err != nil {
						// Log error but continue
					}
				})
			case <-session.GetDoneChannel():
				t.app.QueueUpdateDraw(func() {
					if _, err := fmt.Fprintf(t.outputView, "\n[green]Interactive script completed[white]\n"); err != nil {
						// Log error but continue
					}
					t.statusBar.SetText("Script completed")
					t.app.SetFocus(t.taskList)
				})
				return
			case <-ctx.Done():
				t.app.QueueUpdateDraw(func() {
					if _, err := fmt.Fprintf(t.outputView, "\n[red]Script execution timed out[white]\n"); err != nil {
						// Log error but continue
					}
					t.statusBar.SetText("Script timed out")
					t.app.SetFocus(t.taskList)
				})
				// Terminate the session
				if session.IsActive() {
					if err := session.Terminate(); err != nil {
						// Log error but continue
					}
				}
				return
			}
		}
	}()

	// Handle user input responses
	go func() {
		for {
			select {
			case userInput := <-t.inputResponse:
				if session.IsActive() {
					// Only process non-empty input or if we're actually awaiting input
					t.inputMu.RLock()
					wasAwaiting := t.awaitingInput
					t.inputMu.RUnlock()

					if wasAwaiting {
						if userInput != "" {
							if err := session.SendInput(userInput); err != nil {
								t.app.QueueUpdateDraw(func() {
									if _, err := fmt.Fprintf(t.outputView, "[red]Error sending input: %v[white]\n", err); err != nil {
										// Log error but continue
									}
								})
							} else {
								t.app.QueueUpdateDraw(func() {
									if _, err := fmt.Fprintf(t.outputView, "[green]> %s[white]\n", userInput); err != nil {
										// Log error but continue
									}
									t.updateStatusWithMode("Input sent, waiting for response...")
								})
							}
						} else {
							// Empty input means cancellation
							t.app.QueueUpdateDraw(func() {
								if _, err := fmt.Fprintf(t.outputView, "[yellow]Input cancelled by user[white]\n"); err != nil {
									// Log error but continue
								}
								t.updateStatusWithMode("Input cancelled")
							})
						}
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Wait for the session to complete
	result, err := session.Wait()
	if err != nil {
		t.app.QueueUpdateDraw(func() {
			if _, err := fmt.Fprintf(t.outputView, "\n[red]Session error: %v[white]\n", err); err != nil {
				// Log error but continue
			}
			t.statusBar.SetText("Session failed")
			t.app.SetFocus(t.taskList)
		})
		return
	}

	if !result.Success {
		t.app.QueueUpdateDraw(func() {
			// Provide more detailed error information for interactive scripts
			if result.Error != nil {
				errorMsg := result.Error.Error()
				if strings.Contains(errorMsg, "exit status 1") {
					if _, err := fmt.Fprintf(t.outputView, "\n[yellow]Interactive script completed with warnings (exit code 1)[white]\n"); err != nil {
						// Log error but continue
					}
					if _, err := fmt.Fprintf(t.outputView, "[gray]This may indicate partial success or user cancellation - check output above[white]\n"); err != nil {
						// Log error but continue
					}
					t.statusBar.SetText("Interactive script completed with warnings")
				} else {
					if _, err := fmt.Fprintf(t.outputView, "\n[red]Interactive script failed with error: %v[white]\n", result.Error); err != nil {
						// Log error but continue
					}
					t.statusBar.SetText("Interactive script failed")
				}
			} else {
				if _, err := fmt.Fprintf(t.outputView, "\n[red]Interactive script failed (unknown error)[white]\n"); err != nil {
					// Log error but continue
				}
				t.statusBar.SetText("Interactive script failed")
			}
			t.app.SetFocus(t.taskList)
		})
	} else {
		// Successful completion
		t.app.QueueUpdateDraw(func() {
			if _, err := fmt.Fprintf(t.outputView, "\n[green]Interactive script completed successfully[white]\n"); err != nil {
				// Log error but continue
			}
			t.statusBar.SetText("Interactive script completed")
			t.app.SetFocus(t.taskList)
		})
	}
}
