package ui

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"netutil/internal/executor"
	"netutil/internal/jobs"
)

// OutputViewer displays real-time script output with interactive input
type OutputViewer struct {
	*tview.Flex
	app        *tview.Application
	pages      *tview.Pages
	jobManager *jobs.JobManager

	// UI Components
	outputView *tview.TextView
	inputField *tview.InputField
	statusLine *tview.TextView

	executor    *executor.StreamingExecutor
	result      *executor.StreamingResult
	outputLines []executor.OutputLine
	scriptPath  string // Store script path for title updates

	// Display settings
	showTimestamp bool
	showSource    bool
	maxLines      int
	searchQuery   string

	// State
	running      bool
	paused       bool
	following    bool // Auto-scroll to bottom
	waitingInput bool // Script is waiting for user input
	completed    bool // Script has finished execution
	mu           sync.RWMutex

	// Channels
	outputChan <-chan executor.OutputLine
	errorChan  <-chan error
	stopChan   chan struct{}

	// Callback for returning to main TUI with proper focus restoration
	returnToMainCallback func()
}

// NewOutputViewer creates a new output viewer
func NewOutputViewer(app *tview.Application, pages *tview.Pages, jobManager *jobs.JobManager, returnToMainCallback func()) *OutputViewer {
	// Create output view
	outputView := tview.NewTextView().
		SetDynamicColors(true).
		SetRegions(true).
		SetScrollable(true).
		SetWrap(true)

	// Create input field
	inputField := tview.NewInputField().
		SetLabel("Input: ").
		SetFieldWidth(0). // Use full width
		SetPlaceholder("Type your response here...")

	// Create status line
	statusLine := tview.NewTextView().
		SetDynamicColors(true).
		SetText("[green]Ready[::-] - Tab=Switch | Ctrl+J=Jobs | Ctrl+B=Background | Ctrl+Home=Home | Esc=Close")

	// Create flex layout
	flex := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(outputView, 0, 1, true).  // Output takes most space
		AddItem(statusLine, 1, 0, false). // Status line: 1 row
		AddItem(inputField, 1, 0, false)  // Input field: 1 row

	ov := &OutputViewer{
		Flex:                 flex,
		app:                  app,
		pages:                pages,
		jobManager:           jobManager,
		outputView:           outputView,
		inputField:           inputField,
		statusLine:           statusLine,
		showTimestamp:        true,
		showSource:           true,
		maxLines:             1000,
		following:            true,
		stopChan:             make(chan struct{}),
		returnToMainCallback: returnToMainCallback,
	}

	// Set up the layout
	ov.SetBorder(true).SetTitle("Script Output")
	ov.setupKeyBindings()
	ov.setupInputField()

	return ov
}

// setupKeyBindings configures keyboard shortcuts for the output viewer
func (ov *OutputViewer) setupKeyBindings() {
	// Set input capture on outputView for vim shortcuts (only when outputView is focused)
	ov.outputView.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		// Handle global keys that work regardless of which component is focused
		switch event.Key() {
		case tcell.KeyEscape:
			ov.Stop()
			if ov.returnToMainCallback != nil {
				ov.returnToMainCallback()
			} else {
				ov.pages.RemovePage("output")
			}
			return nil
		case tcell.KeyCtrlC:
			ov.Stop()
			return nil
		case tcell.KeyCtrlB:
			ov.BackgroundTask()
			return nil
		case tcell.KeyTab:
			// Switch focus to input field
			ov.app.SetFocus(ov.inputField)
			ov.statusLine.SetText("[yellow]Input Mode[::-] - Type response + Enter | Ctrl+J=Jobs | Ctrl+B=Background | Ctrl+Home=Home")
			return nil
		}

		// Handle vim-like shortcuts (only when outputView is focused)
		if event.Key() == tcell.KeyRune {
			switch event.Rune() {
			case 'q':
				ov.Stop()
				if ov.returnToMainCallback != nil {
					ov.returnToMainCallback()
				} else {
					ov.pages.RemovePage("output")
				}
				return nil
			case ' ':
				ov.TogglePause()
				return nil
			case 'f':
				ov.ToggleFollowing()
				return nil
			case 't':
				ov.ToggleTimestamp()
				return nil
			case 's':
				ov.ToggleSource()
				return nil
			case '/':
				ov.StartSearch()
				return nil
			case 'c':
				ov.Clear()
				return nil
			case 'G':
				ov.outputView.ScrollToEnd()
				return nil
			case 'g':
				ov.outputView.ScrollToBeginning()
				return nil
			case 'l':
				// Switch focus to input field
				ov.app.SetFocus(ov.inputField)
				ov.statusLine.SetText("[yellow]Input Mode[::-] - Type response + Enter | Ctrl+J=Jobs | Ctrl+B=Background | Ctrl+Home=Home")
				return nil
			}
		}

		return event
	})
}

// setupInputField configures the input field for user interaction
func (ov *OutputViewer) setupInputField() {
	// Set up input field to handle specific keys while letting all typing pass through
	ov.inputField.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		// Handle global keys that work regardless of which component is focused
		switch event.Key() {
		case tcell.KeyEscape:
			ov.Stop()
			if ov.returnToMainCallback != nil {
				ov.returnToMainCallback()
			} else {
				ov.pages.RemovePage("output")
			}
			return nil
		case tcell.KeyCtrlC:
			ov.Stop()
			return nil
		case tcell.KeyCtrlB:
			ov.BackgroundTask()
			return nil
		case tcell.KeyTab:
			// Switch focus to output view
			ov.app.SetFocus(ov.outputView)
			ov.statusLine.SetText("[green]View Mode[::-] - Tab=Input | Ctrl+J=Jobs | Ctrl+B=Background | Ctrl+Home=Home | Esc=Close")
			return nil
		case tcell.KeyEnter:
			// Check if script is completed - if so, return to main TUI
			ov.mu.RLock()
			isCompleted := ov.completed
			ov.mu.RUnlock()

			if isCompleted {
				// Script completed - return to main TUI with proper focus restoration
				ov.Stop()
				if ov.returnToMainCallback != nil {
					ov.returnToMainCallback()
				} else {
					ov.pages.RemovePage("output")
				}
				return nil
			}

			// Script still running - send input to script asynchronously to avoid UI deadlock
			input := ov.inputField.GetText()
			if input != "" {
				ov.inputField.SetText("") // Clear input field immediately
				// Run in goroutine to avoid blocking the UI thread
				go ov.sendInputToScript(input)
			}
			return nil // Consume the event
		}

		// Let ALL other keys pass through normally (including 'q', 'h', 'l', '/', etc.)
		// This is crucial - the input field should accept ANY typed character
		return event
	})
}

// sendInputToScript sends user input to the running script
func (ov *OutputViewer) sendInputToScript(input string) {
	if ov.executor != nil {
		err := ov.executor.SendInput(input)
		if err != nil {
			ov.addOutputLine(executor.OutputLine{
				Content:   fmt.Sprintf("Error sending input: %v", err),
				Timestamp: time.Now(),
				Source:    "system",
			})
		} else {
			// Show the sent input in the output
			ov.addOutputLine(executor.OutputLine{
				Content:   fmt.Sprintf("> %s", input),
				Timestamp: time.Now(),
				Source:    "input",
			})

			// Update status to show input was sent (asynchronously)
			ov.app.QueueUpdateDraw(func() {
				ov.statusLine.SetText("[green]Input sent[::-] - Waiting for response | Ctrl+J=Jobs | Ctrl+B=Background | Ctrl+Home=Home")
			})
		}
	}
}

// StartScript starts executing a script with real-time output
func (ov *OutputViewer) StartScript(scriptPath string) error {
	ov.mu.Lock()
	defer ov.mu.Unlock()

	if ov.running {
		return fmt.Errorf("script is already running")
	}

	// Create new streaming executor
	ov.executor = executor.NewStreamingExecutor()

	// Start script execution
	result, outputChan, errorChan := ov.executor.ExecuteScriptStreaming(scriptPath)
	ov.result = result
	ov.outputChan = outputChan
	ov.errorChan = errorChan
	ov.running = true
	ov.outputLines = make([]executor.OutputLine, 0)
	ov.scriptPath = scriptPath

	// Set initial title with job count
	ov.updateTitle(scriptPath, "Running")

	// Start output processing
	go ov.processOutput()

	return nil
}

// ConnectToJob connects the OutputViewer to an existing running job
func (ov *OutputViewer) ConnectToJob(job *jobs.Job) error {
	ov.mu.Lock()
	defer ov.mu.Unlock()

	if ov.running {
		return fmt.Errorf("viewer is already connected to a job")
	}

	if !job.IsRunning() {
		return fmt.Errorf("job is not running")
	}

	// Connect to the existing job's executor and channels
	ov.executor = job.Executor
	ov.result = job.Result
	ov.outputChan = job.OutputChan
	ov.errorChan = job.ErrorChan
	ov.running = true
	ov.outputLines = make([]executor.OutputLine, 0)
	ov.scriptPath = job.ScriptPath

	// Set initial title with job count
	ov.updateTitle(job.ScriptPath, "Running")

	// Start output processing
	go ov.processOutput()

	return nil
}

// processOutput processes incoming output lines and errors
func (ov *OutputViewer) processOutput() {
	defer func() {
		ov.mu.Lock()
		ov.running = false
		ov.completed = true
		ov.mu.Unlock()

		// Add completion message to output and update UI
		if ov.result != nil {
			status := "Completed"
			statusColor := "green"
			if !ov.result.Success {
				status = "Failed"
				statusColor = "red"
			}

			// Add visual separator and completion message
			ov.addOutputLine(executor.OutputLine{
				Content:   "────────────────────────────────────────────────────────────────",
				Timestamp: time.Now(),
				Source:    "system",
			})

			ov.addOutputLine(executor.OutputLine{
				Content:   fmt.Sprintf("Script %s - Duration: %v", strings.ToLower(status), ov.result.Duration.Round(time.Second)),
				Timestamp: time.Now(),
				Source:    "system",
			})

			ov.app.QueueUpdateDraw(func() {
				// Update title with job count and completion status
				ov.updateTitle(ov.scriptPath, fmt.Sprintf("%s - Duration: %v", status, ov.result.Duration.Round(time.Second)))

				// Update status line and input field for completion mode
				ov.statusLine.SetText(fmt.Sprintf("[%s]ENTER=Continue | Ctrl+J=Jobs | Ctrl+Home=Home | ESC=Close[::-]", statusColor))
			})
		}
	}()

	for {
		select {
		case line, ok := <-ov.outputChan:
			if !ok {
				// Output channel closed, script finished
				return
			}
			ov.addOutputLine(line)

		case err, ok := <-ov.errorChan:
			if !ok {
				// Error channel closed
				continue
			}
			if err != nil {
				// Add error as a line
				errorLine := executor.OutputLine{
					Content:   fmt.Sprintf("ERROR: %v", err),
					Timestamp: time.Now(),
					Source:    "error",
				}
				ov.addOutputLine(errorLine)
			}

		case <-ov.stopChan:
			// Stop requested
			if ov.executor != nil {
				ov.executor.Stop()
			}
			return
		}
	}
}

// addOutputLine adds a new output line to the display
func (ov *OutputViewer) addOutputLine(line executor.OutputLine) {
	ov.mu.Lock()
	defer ov.mu.Unlock()

	// Skip if paused
	if ov.paused {
		return
	}

	// Add to internal storage
	ov.outputLines = append(ov.outputLines, line)

	// Limit number of lines
	if len(ov.outputLines) > ov.maxLines {
		ov.outputLines = ov.outputLines[len(ov.outputLines)-ov.maxLines:]
	}

	// Check if this looks like a prompt waiting for input
	// BUT only auto-focus if this is output from script, not from user input
	if ov.detectInputPrompt(line.Content) && line.Source != "input" {
		ov.waitingInput = true
		ov.app.QueueUpdateDraw(func() {
			ov.app.SetFocus(ov.inputField)
			ov.statusLine.SetText("[yellow]Waiting for input[::-] - Enter selection + Enter | Ctrl+J=Jobs | Ctrl+B=Background | Ctrl+Home=Home")
		})
	}

	// Update display
	ov.app.QueueUpdateDraw(func() {
		ov.updateDisplay()
	})
}

// detectInputPrompt analyzes output to determine if script is waiting for input
func (ov *OutputViewer) detectInputPrompt(content string) bool {
	// Convert to lowercase for case-insensitive matching
	lower := strings.ToLower(content)

	// Common input prompt patterns
	prompts := []string{
		"enter selection",
		"choose option",
		"select option",
		"enter choice",
		"enter number",
		"enter option",
		"please select",
		"your choice",
		"enter your",
		"type your",
		"input:",
		"selection:",
		"choice:",
		"option:",
	}

	// Check for explicit prompt patterns
	for _, prompt := range prompts {
		if strings.Contains(lower, prompt) {
			return true
		}
	}

	// Check for numbered menu options (like "1. Option", "2. Option")
	if strings.Contains(content, "1.") && strings.Contains(content, "2.") {
		return true
	}

	// Check if line looks like a menu option
	trimmed := strings.TrimSpace(content)
	if len(trimmed) > 3 && trimmed[1] == '.' && trimmed[0] >= '1' && trimmed[0] <= '9' {
		return true
	}

	// Check for lines that end with colon (often prompts)
	if strings.HasSuffix(trimmed, ":") && len(trimmed) < 50 {
		// But avoid false positives like timestamps
		if !strings.Contains(lower, "===") && !strings.Contains(lower, "---") {
			return true
		}
	}

	return false
}

// updateDisplay refreshes the text view with current output
func (ov *OutputViewer) updateDisplay() {
	lines := ov.outputLines

	// Apply search filter if active
	if ov.searchQuery != "" {
		lines = executor.SearchOutput(lines, ov.searchQuery)
	}

	// Format output
	content := ov.formatLines(lines)

	// Update text view
	ov.outputView.SetText(content)

	// Auto-scroll to bottom if following
	if ov.following {
		ov.outputView.ScrollToEnd()
	}
}

// formatLines formats output lines for display
func (ov *OutputViewer) formatLines(lines []executor.OutputLine) string {
	var content strings.Builder

	for _, line := range lines {
		// Add timestamp if enabled
		if ov.showTimestamp {
			content.WriteString(fmt.Sprintf("[gray]%s[white] ",
				line.Timestamp.Format("15:04:05")))
		}

		// Add source if enabled
		if ov.showSource {
			color := "white"
			switch line.Source {
			case "stderr":
				color = "red"
			case "error":
				color = "red"
			case "stdout":
				color = "green"
			}
			content.WriteString(fmt.Sprintf("[%s][%s][white] ", color, line.Source))
		}

		// Add content with color coding for special lines
		lineContent := line.Content
		if strings.Contains(strings.ToLower(lineContent), "error") {
			lineContent = fmt.Sprintf("[red]%s[white]", lineContent)
		} else if strings.Contains(strings.ToLower(lineContent), "warning") {
			lineContent = fmt.Sprintf("[yellow]%s[white]", lineContent)
		} else if strings.Contains(strings.ToLower(lineContent), "success") {
			lineContent = fmt.Sprintf("[green]%s[white]", lineContent)
		}

		content.WriteString(lineContent)
		content.WriteString("\n")
	}

	return content.String()
}

// Stop stops the script execution
func (ov *OutputViewer) Stop() {
	ov.mu.Lock()
	defer ov.mu.Unlock()

	if !ov.running {
		return
	}

	// Signal stop
	select {
	case ov.stopChan <- struct{}{}:
	default:
	}

	// Stop executor
	if ov.executor != nil {
		ov.executor.Stop()
	}
}

// TogglePause toggles pause/resume of output display
func (ov *OutputViewer) TogglePause() {
	ov.mu.Lock()
	defer ov.mu.Unlock()

	ov.paused = !ov.paused

	status := "Running"
	if ov.paused {
		status = "Paused"
	}

	ov.app.QueueUpdateDraw(func() {
		currentTitle := ov.GetTitle()
		// Update title to show pause status
		if strings.Contains(currentTitle, "[") {
			parts := strings.Split(currentTitle, "[")
			newTitle := fmt.Sprintf("%s[%s]", parts[0], status)
			ov.SetTitle(newTitle)
		}
	})
}

// ToggleFollowing toggles auto-scroll to bottom
func (ov *OutputViewer) ToggleFollowing() {
	ov.mu.Lock()
	defer ov.mu.Unlock()

	ov.following = !ov.following
}

// ToggleTimestamp toggles timestamp display
func (ov *OutputViewer) ToggleTimestamp() {
	ov.mu.Lock()
	defer ov.mu.Unlock()

	ov.showTimestamp = !ov.showTimestamp
	ov.app.QueueUpdateDraw(func() {
		ov.updateDisplay()
	})
}

// ToggleSource toggles source (stdout/stderr) display
func (ov *OutputViewer) ToggleSource() {
	ov.mu.Lock()
	defer ov.mu.Unlock()

	ov.showSource = !ov.showSource
	ov.app.QueueUpdateDraw(func() {
		ov.updateDisplay()
	})
}

// StartSearch opens a search dialog
func (ov *OutputViewer) StartSearch() {
	var searchInput *tview.InputField

	searchInput = tview.NewInputField().
		SetLabel("Search: ").
		SetFieldWidth(30).
		SetDoneFunc(func(key tcell.Key) {
			if key == tcell.KeyEnter {
				query := searchInput.GetText()
				ov.SetSearchQuery(query)
			}
			ov.pages.RemovePage("search")
			ov.app.SetFocus(ov)
		})

	// Add input capture for escape key only
	searchInput.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEscape:
			ov.pages.RemovePage("search")
			ov.app.SetFocus(ov)
			return nil
		}
		// Let all other keys pass through
		return event
	})

	modal := tview.NewModal().
		SetText("Enter search query:").
		AddButtons([]string{"Search", "Clear", "Cancel"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			switch buttonLabel {
			case "Search":
				query := searchInput.GetText()
				ov.SetSearchQuery(query)
			case "Clear":
				ov.SetSearchQuery("")
			}
			ov.pages.RemovePage("search")
			ov.app.SetFocus(ov)
		})

	flex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(modal, 3, 0, false).
		AddItem(searchInput, 1, 0, true)

	ov.pages.AddPage("search", flex, true, true)
	ov.app.SetFocus(searchInput)
}

// SetSearchQuery sets the search query and updates display
func (ov *OutputViewer) SetSearchQuery(query string) {
	ov.mu.Lock()
	defer ov.mu.Unlock()

	ov.searchQuery = query
	ov.app.QueueUpdateDraw(func() {
		ov.updateDisplay()
	})
}

// Clear clears the output display
func (ov *OutputViewer) Clear() {
	ov.mu.Lock()
	defer ov.mu.Unlock()

	ov.outputLines = make([]executor.OutputLine, 0)
	ov.app.QueueUpdateDraw(func() {
		ov.outputView.SetText("")
	})
}

// SendInput sends input to the running script
func (ov *OutputViewer) SendInput(input string) error {
	ov.mu.RLock()
	defer ov.mu.RUnlock()

	if !ov.running || ov.executor == nil {
		return fmt.Errorf("no script is running")
	}

	return ov.executor.SendInput(input)
}

// IsRunning returns whether a script is currently running
func (ov *OutputViewer) IsRunning() bool {
	ov.mu.RLock()
	defer ov.mu.RUnlock()
	return ov.running
}

// GetResult returns the current script result
func (ov *OutputViewer) GetResult() *executor.StreamingResult {
	ov.mu.RLock()
	defer ov.mu.RUnlock()
	return ov.result
}

// GetOutputLines returns all captured output lines
func (ov *OutputViewer) GetOutputLines() []executor.OutputLine {
	ov.mu.RLock()
	defer ov.mu.RUnlock()
	return append([]executor.OutputLine{}, ov.outputLines...)
}

// ShowHelp displays help for the output viewer
func (ov *OutputViewer) ShowHelp() {
	helpText := `Output Viewer Help

Controls:
  Esc, q       Close viewer and stop script
  Ctrl+C       Stop script execution
  Space        Pause/resume output display
  f            Toggle auto-scroll (following)
  t            Toggle timestamp display
  s            Toggle source (stdout/stderr) display
  /            Search output
  c            Clear display
  G            Go to end
  g            Go to beginning

Display Features:
  - Real-time streaming output
  - Color-coded stderr (red) and stdout (green)
  - Automatic highlighting of errors/warnings
  - Search and filter capabilities
  - Pause/resume without stopping script
  - Timestamp and source information

Script Control:
  - Scripts can be stopped with Ctrl+C or Esc
  - Input can be sent to interactive scripts
  - Full execution history is maintained`

	helpModal := tview.NewModal().
		SetText(helpText).
		AddButtons([]string{"Close"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			ov.pages.RemovePage("output-help")
		})

	ov.pages.AddPage("output-help", helpModal, true, true)
}

// BackgroundTask minimizes the current script output and returns to main TUI
// while keeping the script running in the background
func (ov *OutputViewer) BackgroundTask() {
	ov.mu.Lock()
	defer ov.mu.Unlock()

	if !ov.running {
		// If script is not running, just close the output viewer
		ov.pages.RemovePage("output")
		return
	}

	// Disconnect from the job output but don't stop the job itself
	// The job continues running in JobManager and can be reconnected later
	ov.running = false

	// Signal our output processing goroutine to stop
	select {
	case ov.stopChan <- struct{}{}:
	default:
	}

	// Clear our references but don't stop the actual job execution
	ov.executor = nil
	ov.result = nil
	ov.outputChan = nil
	ov.errorChan = nil

	// Remove the output viewer and return to main TUI
	ov.pages.RemovePage("output")
}

// updateTitle updates the output viewer title with job count information
func (ov *OutputViewer) updateTitle(scriptPath, status string) {
	var title string

	if ov.jobManager != nil {
		stats := ov.jobManager.GetStats()
		jobCount := fmt.Sprintf("[%d/%d Jobs]", stats.RunningJobs, stats.MaxConcurrent)

		// Extract just the script name from the path
		scriptName := scriptPath
		if idx := strings.LastIndex(scriptPath, "/"); idx != -1 {
			scriptName = scriptPath[idx+1:]
		}

		title = fmt.Sprintf("Script Output %s - %s [%s]", jobCount, scriptName, status)
	} else {
		// Fallback if no job manager
		title = fmt.Sprintf("Script Output - %s [%s]", scriptPath, status)
	}

	ov.SetTitle(title)
}
