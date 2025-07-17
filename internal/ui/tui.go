package ui

import (
	"fmt"
	"path/filepath"
	"sync"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"netutil/internal/executor"
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
	scriptToRun     string
	scriptName      string

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
		app:          app,
		pages:        tview.NewPages(),
		headerPane:   tview.NewTextView(),
		categoryPane: tview.NewList(),
		taskPane:     tview.NewList(),
		executor:     executor.NewExecutor(),
	}

	tui.setupUI()
	return tui
}

func (t *TUI) setupUI() {
	// Setup header pane (program info)
	t.headerPane.SetBorder(true).SetTitle("Program Info")
	t.headerPane.SetText(fmt.Sprintf("[::b]%s %s[::-]\n\nNetwork Security Toolkit", AppName, AppVersion))
	t.headerPane.SetTextAlign(tview.AlignCenter)

	// Setup category pane
	t.categoryPane.SetBorder(true).SetTitle("Categories")
	t.categoryPane.ShowSecondaryText(false)

	// Setup task pane (75% width)
	t.taskPane.SetBorder(true).SetTitle("Select a category")
	t.taskPane.ShowSecondaryText(true)

	// Populate categories
	for i, category := range getCategories() {
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
	// Handle normal mode keys
	switch event.Key() {
	case tcell.KeyTab:
		t.switchFocus()
		return nil
	case tcell.KeyEscape:
		t.app.Stop()
		return nil
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
	for _, category := range getCategories() {
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
	// Find the task script
	var scriptPath string
	for _, category := range getCategories() {
		if category.Name == t.currentCategory {
			for _, task := range category.Tasks {
				if task.Name == taskName {
					scriptPath = filepath.Join("scripts", t.getScriptFolder(t.currentCategory), task.Script)
					break
				}
			}
			break
		}
	}

	if scriptPath == "" {
		return
	}

	// Store script information for execution after TUI exits
	t.mu.Lock()
	t.scriptToRun = scriptPath
	t.scriptName = taskName
	t.mu.Unlock()

	// Stop the TUI application
	t.app.Stop()
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

func (t *TUI) GetScriptToRun() (string, string) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.scriptToRun, t.scriptName
}

func (t *TUI) ClearScriptToRun() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.scriptToRun = ""
	t.scriptName = ""
}
