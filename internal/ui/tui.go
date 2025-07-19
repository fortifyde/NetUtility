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
		return "Vulnerability Assessment"
	case "config":
		return "Config Gatherer"
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

[yellow]Keys:[::-] Tab=Switch [yellow]hjkl[::-]=Navigate [yellow]/[::-]=Search [yellow]J[::-]=Jobs [yellow]C[::-]=Correlate [yellow]?[::-]=Help [yellow]q[::-]=Quit`, AppName, AppVersion)
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

	// Set task selection handler
	t.taskPane.SetSelectedFunc(func(index int, mainText, secondaryText string, shortcut rune) {
		t.executeTask(mainText)
	})

	// Create layout: 2 columns, left column stacked (header + categories), right column (tasks)
	leftColumn := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(t.headerPane, 5, 0, false). // Fixed height for header
		AddItem(t.categoryPane, 0, 1, true) // Flexible height for categories

	mainLayout := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(leftColumn, 0, 1, true). // 25% width for left column
		AddItem(t.taskPane, 0, 3, false) // 75% width for task pane

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
	// Check if we're on the output viewer page
	frontPageName, _ := t.pages.GetFrontPage()
	if frontPageName == "output" {
		// Let output viewer handle ALL keys when it's active
		return event
	}

	// Only process TUI vim shortcuts when on main page
	// Handle vim-like keys and enhanced navigation
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
			return nil
		case 'l':
			// Vim-like right (focus tasks)
			t.app.SetFocus(t.taskPane)
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

// executeTaskWithStreaming executes a task using the streaming output viewer
func (t *TUI) executeTaskWithStreaming(scriptPath, taskName string) {
	// Convert to absolute path
	absPath, err := filepath.Abs(scriptPath)
	if err != nil {
		// Show error modal
		t.showErrorModal("Path Error", fmt.Sprintf("Could not resolve script path: %v", err))
		return
	}

	// Check if we can run immediately or should queue
	if t.jobManager.CanStartNewJob() {
		// Run immediately with live output
		outputViewer := NewOutputViewer(t.app, t.pages)
		t.pages.AddPage("output", outputViewer, true, true)
		t.app.SetFocus(outputViewer)

		if err := outputViewer.StartScript(absPath); err != nil {
			t.showErrorModal("Execution Error", fmt.Sprintf("Failed to start script: %v", err))
			t.pages.RemovePage("output")
			return
		}
	} else {
		// Ask user if they want to queue the job
		t.showExecutionOptions(absPath, taskName)
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
	case "Vulnerability Assessment":
		return "vulnerability"
	case "Config Gatherer":
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
