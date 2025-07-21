package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"netutil/internal/correlation"
	"netutil/internal/executor"
	"netutil/internal/jobs"
	"netutil/internal/metadata"
)

const (
	AppName    = "NetUtility"
	AppVersion = "v1.0.0"
)

type TUI struct {
	app   *tview.Application
	pages *tview.Pages

	// Base layout components
	headerPane   *tview.TextView
	categoryPane *tview.List
	taskPane     *tview.List
	infoPane     *tview.TextView

	// State management
	currentCategory string
	executor        *executor.Executor
	registry        *metadata.ScriptRegistry
	jobManager      *jobs.JobManager
	correlator      *correlation.Correlator

	mu sync.RWMutex
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
func (t *TUI) getCategories() []Category {
	// Use metadata registry if available
	if t.registry != nil {
		return t.getCategoriesFromMetadata()
	}

	// Fall back to hardcoded categories
	return t.getHardcodedCategories()
}

// getCategoriesFromMetadata builds categories from the metadata registry
func (t *TUI) getCategoriesFromMetadata() []Category {
	var categories []Category

	for _, categoryName := range t.registry.GetAllCategories() {
		// Skip template category - templates are for user creation, not TUI execution
		if categoryName == "template" {
			continue
		}

		scripts := t.registry.GetScriptsByCategory(categoryName)

		var tasks []Task
		for _, script := range scripts {
			tasks = append(tasks, Task{
				Name:        script.Script.Name,
				Description: script.Script.Description,
				Script:      script.Script.File,
			})
		}

		// Only add category if it has tasks
		if len(tasks) > 0 {
			// Format category name for display
			displayName := t.formatCategoryName(categoryName)
			categories = append(categories, Category{
				Name:  displayName,
				Tasks: tasks,
			})
		}
	}

	return categories
}

// formatCategoryName converts metadata category names to display names
func (t *TUI) formatCategoryName(category string) string {
	switch category {
	case "system":
		return "System Configuration"
	case "network":
		return "Network Reconnaissance"
	case "vulnerability":
		return "Detailed Port Scan"
	case "advanced":
		return "Advanced"
	case "config":
		return "Network Config Gatherer"
	default:
		// Capitalize first letter
		if len(category) > 0 {
			return string(category[0]-32) + category[1:]
		}
		return category
	}
}

// getHardcodedCategories returns the original hardcoded categories as fallback
func (t *TUI) getHardcodedCategories() []Category {
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
				{Name: "Network Capture", Description: "Capture network traffic with integrated security analysis and unsafe protocol detection", Script: "network_capture.sh"},
				{Name: "Extract VLAN IDs", Description: "Extract VLAN IDs from capture files", Script: "extract_vlans.sh"},
				{Name: "Multi-Phase Discovery", Description: "Comprehensive network discovery with host categorization", Script: "multi_phase_discovery.sh"},
				{Name: "Host Categorization", Description: "Categorize discovered hosts by OS", Script: "categorize_hosts.sh"},
			},
		},
		{
			Name: "Detailed Port Scan",
			Tasks: []Task{
				{Name: "Deep Scan with NSE", Description: "Full port scan with service detection and NSE vulnerability scripts", Script: "deep_nse_scan.sh"},
				{Name: "Vulnerability Analysis", Description: "Analyze results for known vulnerabilities", Script: "vuln_analysis.sh"},
			},
		},
		{
			Name: "Advanced",
			Tasks: []Task{
				{Name: "Integrated Workflow", Description: "Comprehensive workflow: capture, analysis, interface config, and discovery", Script: "integrated_workflow.sh"},
			},
		},
		{
			Name: "Network Config Gatherer",
			Tasks: []Task{
				{Name: "Device Configuration Gathering", Description: "SSH to device, detect vendor, and gather configuration", Script: "device_config.sh"},
			},
		},
	}
}

func NewTUI() *TUI {
	app := tview.NewApplication()

	// Initialize script registry with absolute path
	scriptsDir, err := filepath.Abs("scripts")
	if err != nil {
		scriptsDir = "scripts" // fallback to relative
	}

	registry := metadata.NewScriptRegistry(scriptsDir)
	if err := registry.LoadMetadata(); err != nil {
		// Log the error instead of silently falling back
		fmt.Fprintf(os.Stderr, "Warning: Failed to load script metadata: %v\n", err)
		fmt.Fprintf(os.Stderr, "Falling back to hardcoded categories\n")
		registry = nil
	} else {
		// Log successful metadata loading
		fmt.Fprintf(os.Stderr, "Loaded metadata for %d scripts from %s\n", len(registry.Scripts), scriptsDir)
	}

	tui := &TUI{
		app:          app,
		pages:        tview.NewPages(),
		headerPane:   tview.NewTextView(),
		categoryPane: tview.NewList(),
		taskPane:     tview.NewList(),
		infoPane:     tview.NewTextView(),
		executor:     executor.NewExecutor(),
		registry:     registry,
		jobManager:   jobs.NewJobManager(3),         // Allow 3 concurrent jobs
		correlator:   correlation.NewCorrelator(""), // Will be set with workspace dir later
	}

	tui.setupUI()
	return tui
}

func (t *TUI) setupUI() {
	// Setup header pane (program info)
	t.headerPane.SetBorder(true).SetTitle("Program Info")
	headerText := fmt.Sprintf(`[::b]%s %s[::-]
Network Security Toolkit

[yellow]Keys:[::-] Tab=Switch [yellow]hjkl[::-]=Navigate [yellow]/[::-]=Search [yellow]J[::-]=Jobs [yellow]C[::-]=Correlate [yellow]Ctrl+Home[::-]=Home [yellow]?[::-]=Help [yellow]q[::-]=Quit`, AppName, AppVersion)
	t.headerPane.SetText(headerText)
	t.headerPane.SetTextAlign(tview.AlignCenter)

	// Setup category pane
	t.categoryPane.SetBorder(true).SetTitle("Categories")
	t.categoryPane.ShowSecondaryText(false)

	// Setup task pane (75% width)
	t.taskPane.SetBorder(true).SetTitle("Select a category")
	t.taskPane.ShowSecondaryText(true)

	// Populate categories
	for i, category := range t.getCategories() {
		t.categoryPane.AddItem(category.Name, "", rune('1'+i), func() {
			t.showCategory(category.Name)
		})
	}

	// Set category selection handler
	t.categoryPane.SetSelectedFunc(func(index int, mainText, secondaryText string, shortcut rune) {
		t.showCategory(mainText)
	})

	// Add mouse support diagnostic
	t.categoryPane.SetMouseCapture(func(action tview.MouseAction, event *tcell.EventMouse) (tview.MouseAction, *tcell.EventMouse) {
		if action == tview.MouseLeftClick {
			// Manual handling for mouse clicks
			_, y := event.Position()
			// Convert screen coordinates to list item (approximate)
			if y > 0 && y <= t.categoryPane.GetItemCount() {
				itemIndex := y - 1
				if itemIndex >= 0 && itemIndex < t.categoryPane.GetItemCount() {
					t.categoryPane.SetCurrentItem(itemIndex)
					mainText, _ := t.categoryPane.GetItemText(itemIndex)
					t.showCategory(mainText)
				}
			}
		}
		return action, event
	})

	// Set task selection handler
	t.taskPane.SetSelectedFunc(func(index int, mainText, secondaryText string, shortcut rune) {
		t.executeTask(mainText)
	})

	// Add mouse support to task pane
	t.taskPane.SetMouseCapture(func(action tview.MouseAction, event *tcell.EventMouse) (tview.MouseAction, *tcell.EventMouse) {
		if action == tview.MouseLeftClick {
			// Manual handling for mouse clicks
			_, y := event.Position()
			// Convert screen coordinates to list item (approximate)
			if y > 0 && y <= t.taskPane.GetItemCount() {
				itemIndex := y - 1
				if itemIndex >= 0 && itemIndex < t.taskPane.GetItemCount() {
					t.taskPane.SetCurrentItem(itemIndex)
					mainText, _ := t.taskPane.GetItemText(itemIndex)
					t.executeTask(mainText)
				}
			}
		}
		return action, event
	})

	// Add j/k navigation support to category pane
	t.categoryPane.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyRune {
			switch event.Rune() {
			case 'j':
				// Move down (like down arrow)
				currentItem := t.categoryPane.GetCurrentItem()
				itemCount := t.categoryPane.GetItemCount()
				if currentItem < itemCount-1 {
					t.categoryPane.SetCurrentItem(currentItem + 1)
				}
				return nil
			case 'k':
				// Move up (like up arrow)
				currentItem := t.categoryPane.GetCurrentItem()
				if currentItem > 0 {
					t.categoryPane.SetCurrentItem(currentItem - 1)
				}
				return nil
			}
		}
		// Let all other keys pass through to global handler
		return event
	})

	// Add j/k navigation support to task pane
	t.taskPane.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyRune {
			switch event.Rune() {
			case 'j':
				// Move down (like down arrow)
				currentItem := t.taskPane.GetCurrentItem()
				itemCount := t.taskPane.GetItemCount()
				if currentItem < itemCount-1 {
					t.taskPane.SetCurrentItem(currentItem + 1)
				}
				return nil
			case 'k':
				// Move up (like up arrow)
				currentItem := t.taskPane.GetCurrentItem()
				if currentItem > 0 {
					t.taskPane.SetCurrentItem(currentItem - 1)
				}
				return nil
			}
		}
		// Let all other keys pass through to global handler
		return event
	})

	// Setup info pane (informational panel for first-time users)
	t.infoPane.SetBorder(true).SetTitle("Quick Reference")
	t.infoPane.SetDynamicColors(true)
	t.updateInfoPanel() // Set initial content

	// Create layout: 2 columns, left column stacked (header + categories), right column (tasks)
	leftColumn := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(t.headerPane, 5, 0, false). // Fixed height for header
		AddItem(t.categoryPane, 0, 1, true) // Flexible height for categories

	topLayout := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(leftColumn, 0, 1, true). // 25% width for left column
		AddItem(t.taskPane, 0, 3, false) // 75% width for task pane

	mainLayout := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(topLayout, 0, 1, false). // Main content area
		AddItem(t.infoPane, 4, 0, false) // Fixed height for info panel

	// Setup main page
	t.pages.AddPage("main", mainLayout, true, true)
	t.app.SetRoot(t.pages, true)

	// Setup global key bindings
	t.app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		return t.handleGlobalKeys(event)
	})

	// Set initial focus
	t.app.SetFocus(t.categoryPane)
}

func (t *TUI) handleGlobalKeys(event *tcell.EventKey) *tcell.EventKey {
	// Handle global Ctrl+key shortcuts that work everywhere (including output viewer)
	if event.Key() == tcell.KeyCtrlJ {
		// Global Job Manager access - works even during script execution
		t.showJobsManager()
		return nil
	}
	if event.Key() == tcell.KeyCtrlD {
		// Global Dashboard access
		t.showDashboard()
		return nil
	}
	if event.Key() == tcell.KeyCtrlR && event.Modifiers()&tcell.ModCtrl != 0 {
		// Global Correlation viewer access (Ctrl+R to avoid conflict with 'r' refresh)
		t.showCorrelationViewer()
		return nil
	}
	if event.Key() == tcell.KeyHome && event.Modifiers()&tcell.ModCtrl != 0 {
		// Global Home - return to main TUI from anywhere (Ctrl+Home)
		t.returnToMain()
		return nil
	}

	// Check if we're on the output viewer page
	frontPageName, _ := t.pages.GetFrontPage()
	if frontPageName == "output" {
		// Let output viewer handle remaining keys when it's active
		// (but global Ctrl+key shortcuts were already processed above)
		return event
	}

	// Only process TUI vim shortcuts when on main page - let other pages handle their own navigation
	if frontPageName != "main" {
		// On non-main pages (jobs, dashboard, correlation), let the focused component handle all navigation
		return event
	}

	// Handle vim-like keys and enhanced navigation for main page only
	switch event.Key() {
	case tcell.KeyTab:
		t.switchFocus()
		return nil
	case tcell.KeyEscape:
		t.app.Stop()
		return nil
	case tcell.KeyRune:
		switch event.Rune() {
		case 'q':
			// Vim-like quit
			t.app.Stop()
			return nil
		case '/':
			// Search functionality
			t.startSearch()
			return nil
		case 'h':
			// Vim-like left (focus categories)
			t.app.SetFocus(t.categoryPane)
			t.updateInfoPanel()
			return nil
		case 'l':
			// Vim-like right (focus tasks)
			t.app.SetFocus(t.taskPane)
			t.updateInfoPanel()
			return nil
		case 'j':
			// Vim-like down - let the focused widget handle it
			return event
		case 'k':
			// Vim-like up - let the focused widget handle it
			return event
		case '?':
			// Show help
			t.showHelp()
			return nil
		case 'r':
			// Refresh/reload
			t.refreshCategories()
			return nil
		case 'J':
			// Show jobs manager (capital J)
			t.showJobsManager()
			return nil
		case 'C':
			// Show correlation viewer (capital C)
			t.showCorrelationViewer()
			return nil
		case 'D':
			// Show dashboard (capital D)
			t.showDashboard()
			return nil
		default:
			return event
		}
	default:
		return event
	}
}

func (t *TUI) switchFocus() {
	current := t.app.GetFocus()
	if current == t.categoryPane {
		t.app.SetFocus(t.taskPane)
	} else {
		t.app.SetFocus(t.categoryPane)
	}
	// Update info panel to reflect new focus
	t.updateInfoPanel()
}

func (t *TUI) showCategory(categoryName string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.currentCategory = categoryName
	t.taskPane.Clear()
	t.taskPane.SetTitle(fmt.Sprintf("Tasks - %s", categoryName))

	// Find and display tasks for selected category
	for _, category := range t.getCategories() {
		if category.Name == categoryName {
			for i, task := range category.Tasks {
				t.taskPane.AddItem(task.Name, task.Description, rune('1'+i), nil)
			}
			break
		}
	}

	// Switch focus to task pane
	t.app.SetFocus(t.taskPane)

	// Update info panel to reflect new context
	t.updateInfoPanel()
}

func (t *TUI) executeTask(taskName string) {
	// Find the task script - use metadata registry if available
	var scriptPath string
	var foundScript bool

	if t.registry != nil {
		// Use metadata registry to get correct script path
		for _, category := range t.getCategories() {
			if category.Name == t.currentCategory {
				for _, task := range category.Tasks {
					if task.Name == taskName {
						// Find the script metadata to get proper path
						for _, categoryName := range t.registry.GetAllCategories() {
							if t.formatCategoryName(categoryName) == t.currentCategory {
								scripts := t.registry.GetScriptsByCategory(categoryName)
								for _, script := range scripts {
									if script.Script.Name == taskName {
										scriptPath = t.registry.GetScriptPath(script)
										foundScript = true
										break
									}
								}
								if foundScript {
									break
								}
							}
						}
						break
					}
				}
				break
			}
		}
	} else {
		// Fallback to hardcoded path resolution
		for _, category := range t.getCategories() {
			if category.Name == t.currentCategory {
				for _, task := range category.Tasks {
					if task.Name == taskName {
						scriptPath = filepath.Join("scripts", t.getScriptFolder(t.currentCategory), task.Script)
						foundScript = true
						break
					}
				}
				break
			}
		}
	}

	if !foundScript || scriptPath == "" {
		t.showErrorModal("Script Not Found", fmt.Sprintf("Could not find script for task: %s", taskName))
		return
	}

	// Execute with streaming output viewer instead of blocking
	t.executeTaskWithStreaming(scriptPath, taskName)
}

// executeTaskWithStreaming executes a task using the JobManager for consistent tracking
func (t *TUI) executeTaskWithStreaming(scriptPath, taskName string) {
	// Convert to absolute path
	absPath, err := filepath.Abs(scriptPath)
	if err != nil {
		// Show error modal
		t.showErrorModal("Path Error", fmt.Sprintf("Could not resolve script path: %v", err))
		return
	}

	// Always create and start job via JobManager for consistent tracking
	jobID := fmt.Sprintf("job_%d", time.Now().Unix())
	job := t.jobManager.CreateJob(jobID, taskName, absPath)

	// Try to start the job
	if err := t.jobManager.StartJob(job.ID); err != nil {
		// Job couldn't start immediately - show options
		t.showExecutionOptions(absPath, taskName)
		return
	}

	// Job started successfully - show live output
	outputViewer := NewOutputViewer(t.app, t.pages, t.jobManager)
	t.pages.AddPage("output", outputViewer, true, true)
	t.app.SetFocus(outputViewer)

	// Connect OutputViewer to the running job
	if err := outputViewer.ConnectToJob(job); err != nil {
		t.showErrorModal("Connection Error", fmt.Sprintf("Failed to connect to job: %v", err))
		t.pages.RemovePage("output")
		return
	}
}

// showExecutionOptions shows options for script execution when at capacity
func (t *TUI) showExecutionOptions(scriptPath, taskName string) {
	modal := tview.NewModal().
		SetText(fmt.Sprintf("Maximum concurrent jobs reached.\n\nHow would you like to execute '%s'?", taskName)).
		AddButtons([]string{"Queue Job", "View Jobs", "Cancel"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			t.pages.RemovePage("execution-options")
			switch buttonLabel {
			case "Queue Job":
				t.queueJob(scriptPath, taskName)
			case "View Jobs":
				t.showJobsManager()
			}
		})

	t.pages.AddPage("execution-options", modal, true, true)
}

// queueJob queues a job for later execution
func (t *TUI) queueJob(scriptPath, taskName string) {
	jobID := fmt.Sprintf("job_%d", time.Now().Unix())
	job := t.jobManager.CreateJob(jobID, taskName, scriptPath)

	// Try to start it immediately (in case a slot opened up)
	if err := t.jobManager.StartJob(job.ID); err != nil {
		// Job was queued, show confirmation
		t.showInfoModal("Job Queued", fmt.Sprintf("'%s' has been queued for execution.\n\nPress 'J' to view job manager.", taskName))
	} else {
		// Job started immediately
		t.showInfoModal("Job Started", fmt.Sprintf("'%s' has been started in the background.\n\nPress 'J' to view job manager.", taskName))
	}
}

// showJobsManager displays the jobs management interface
func (t *TUI) showJobsManager() {
	ShowJobsViewer(t.app, t.pages, t.jobManager)
}

// showCorrelationViewer displays the correlation viewer interface
func (t *TUI) showCorrelationViewer() {
	ShowCorrelationViewer(t.app, t.pages, t.correlator)
}

// showDashboard displays the dashboard interface
func (t *TUI) showDashboard() {
	ShowDashboard(t.app, t.pages, t.jobManager, t.correlator, nil)
}

// showInfoModal displays an info message to the user
func (t *TUI) showInfoModal(title, message string) {
	infoModal := tview.NewModal().
		SetText(message).
		AddButtons([]string{"OK"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			t.pages.RemovePage("info")
		})

	t.pages.AddPage("info", infoModal, true, true)
}

// showErrorModal displays an error message to the user
func (t *TUI) showErrorModal(title, message string) {
	errorModal := tview.NewModal().
		SetText(message).
		AddButtons([]string{"OK"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			t.pages.RemovePage("error")
		})

	t.pages.AddPage("error", errorModal, true, true)
}

func (t *TUI) getScriptFolder(category string) string {
	switch category {
	case "System Configuration":
		return "system"
	case "Network Reconnaissance":
		return "network"
	case "Detailed Port Scan":
		return "vulnerability"
	case "Advanced":
		return "network"
	case "Network Config Gatherer":
		return "config"
	default:
		return "unknown"
	}
}

func (t *TUI) Run() error {
	if err := t.app.Run(); err != nil {
		return fmt.Errorf("TUI application failed: %w", err)
	}
	return nil
}

func (t *TUI) Stop() {
	t.executor.Stop()
	t.app.Stop()
}

// startSearch opens a search dialog for filtering tasks
func (t *TUI) startSearch() {
	var form *tview.Form

	// Create a simple form
	form = tview.NewForm().
		AddInputField("Search", "", 30, nil, nil).
		AddButton("Search", func() {
			query := form.GetFormItem(0).(*tview.InputField).GetText()
			t.filterTasks(query)
			t.pages.RemovePage("search")
			t.app.SetFocus(t.taskPane)
		}).
		AddButton("Cancel", func() {
			t.pages.RemovePage("search")
			t.app.SetFocus(t.taskPane)
		})

	form.SetBorder(true).SetTitle("Search Tasks")

	// Get the input field and add input capture for escape key only
	searchInput := form.GetFormItem(0).(*tview.InputField)
	searchInput.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEscape:
			t.pages.RemovePage("search")
			t.app.SetFocus(t.taskPane)
			return nil
		}
		// Let all other keys pass through
		return event
	})

	t.pages.AddPage("search", form, true, true)
	t.app.SetFocus(form)
}

// filterTasks filters the current task list based on query
func (t *TUI) filterTasks(query string) {
	if query == "" {
		// Refresh to show all tasks
		t.showCategory(t.currentCategory)
		return
	}

	t.taskPane.Clear()
	query = strings.ToLower(query)

	// Filter tasks from current category
	for _, category := range t.getCategories() {
		if category.Name == t.currentCategory {
			taskIndex := 0
			for _, task := range category.Tasks {
				// Check if query matches task name or description
				if strings.Contains(strings.ToLower(task.Name), query) ||
					strings.Contains(strings.ToLower(task.Description), query) {
					taskIndex++
					t.taskPane.AddItem(task.Name, task.Description, rune('0'+taskIndex), nil)
				}
			}
			break
		}
	}

	t.taskPane.SetTitle(fmt.Sprintf("Tasks - %s (filtered: %s)", t.currentCategory, query))
}

// showHelp displays help information
func (t *TUI) showHelp() {
	helpText := `NetUtility TUI Help

Navigation:
  Tab          Switch between categories and tasks
  Enter        Select category or execute task
  Escape, q    Quit application
  
Vim-like Keys:
  h            Focus categories (left panel)
  l            Focus tasks (right panel)  
  j            Move down in current panel
  k            Move up in current panel
  
Search & Analysis:
  /            Start search mode
  J            View job manager (concurrent execution)
  C            View correlation analysis (cross-scan results)
  
Other:
  ?            Show this help
  r            Refresh categories
  
Advanced Features:
  - Up to 3 scripts can run concurrently
  - Additional scripts are queued automatically
  - Use 'J' to view running, queued, and completed jobs
  - Use 'C' to analyze correlated results across scans
  - Risk scoring and security recommendations
  
Mouse:
  Click        Select items
  Scroll       Navigate lists`

	helpModal := tview.NewModal().
		SetText(helpText).
		AddButtons([]string{"Close"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			t.pages.RemovePage("help")
		})

	t.pages.AddPage("help", helpModal, true, true)
}

// refreshCategories reloads the category list
func (t *TUI) refreshCategories() {
	// Reload metadata if available
	if t.registry != nil {
		if err := t.registry.LoadMetadata(); err != nil {
			// Log error but continue with cached data
		}
	}

	// Clear and repopulate categories
	t.categoryPane.Clear()
	for i, category := range t.getCategories() {
		t.categoryPane.AddItem(category.Name, "", rune('1'+i), func() {
			t.showCategory(category.Name)
		})
	}

	// Clear task pane
	t.taskPane.Clear()
	t.taskPane.SetTitle("Select a category")
	t.currentCategory = ""
}

// updateInfoPanel updates the informational panel with context-sensitive content
func (t *TUI) updateInfoPanel() {
	current := t.app.GetFocus()
	var content strings.Builder

	// Context-sensitive help based on current focus
	if current == t.categoryPane {
		// Categories panel is focused
		content.WriteString("[yellow]Categories Panel:[::-] [white]↑↓/jk[::-]=Navigate [white]Enter[::-]=Select Category [white]Tab/l[::-]=Go to Tasks\n")
		content.WriteString("[yellow]Available:[::-] System Config, Network Recon, Vulnerability Assessment, Config Gathering\n")
		content.WriteString("[yellow]Quick:[::-] [white]J[::-]=Jobs [white]C[::-]=Correlations [white]?[::-]=Help [white]q[::-]=Quit [white]/[::-]=Search")
	} else if current == t.taskPane {
		// Tasks panel is focused
		if t.currentCategory != "" {
			content.WriteString(fmt.Sprintf("[yellow]%s Tasks:[::-] [white]↑↓/jk[::-]=Navigate [white]Enter[::-]=Execute Task [white]Tab/h[::-]=Back to Categories\n", t.currentCategory))
			content.WriteString("[yellow]Execution:[::-] Live output viewer • Up to 3 concurrent jobs • [white]Ctrl+J[::-]=Jobs [white]Ctrl+B[::-]=Background\n")
			content.WriteString("[yellow]Global:[::-] [white]Ctrl+J[::-]=Jobs [white]Ctrl+D[::-]=Dashboard [white]Ctrl+R[::-]=Correlations [white]Ctrl+Home[::-]=Home [white]/[::-]=Search [white]q[::-]=Quit")
		} else {
			content.WriteString("[yellow]Tasks Panel:[::-] [white]Tab/h[::-]=Select Category First [white]/[::-]=Search [white]?[::-]=Help\n")
			content.WriteString("[yellow]Features:[::-] Real-time execution • Background job management • Result correlation\n")
			content.WriteString("[yellow]Access:[::-] [white]J[::-]=Job Manager [white]C[::-]=Correlation Analysis [white]q[::-]=Quit")
		}
	} else {
		// Default/general help
		content.WriteString("[yellow]Essential:[::-] [white]Tab[::-]=Switch Panels [white]Enter[::-]=Select [white]q[::-]=Quit [white]?[::-]=Full Help\n")
		content.WriteString("[yellow]Navigate:[::-] [white]h[::-]=Categories [white]l[::-]=Tasks [white]j/k[::-]=Move Up/Down [white]/[::-]=Search\n")
		content.WriteString("[yellow]Global:[::-] [white]Ctrl+J[::-]=Jobs [white]Ctrl+D[::-]=Dashboard [white]Ctrl+R[::-]=Correlations [white]Ctrl+Home[::-]=Home [white]r[::-]=Refresh")
	}

	t.infoPane.SetText(content.String())
}

// returnToMain returns to the main TUI from any other view
func (t *TUI) returnToMain() {
	// Remove any overlays and return to main page
	pageNames := []string{"output", "dashboard", "jobs", "correlation", "info", "error", "execution-options", "search", "help"}

	for _, pageName := range pageNames {
		t.pages.RemovePage(pageName)
	}

	// Switch to main page and set focus to appropriate panel
	t.pages.SwitchToPage("main")

	// Focus on categories if no category selected, otherwise focus on tasks
	if t.currentCategory == "" {
		t.app.SetFocus(t.categoryPane)
	} else {
		t.app.SetFocus(t.taskPane)
	}

	// Update info panel to reflect current focus
	t.updateInfoPanel()
}
