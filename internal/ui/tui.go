package ui

import (
	"context"
	"fmt"
	"path/filepath"
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
	currentCategory string
	executor        *executor.Executor
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

var categories = []Category{
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

func NewTUI() *TUI {
	app := tview.NewApplication()

	tui := &TUI{
		app:          app,
		pages:        tview.NewPages(),
		categoryList: tview.NewList(),
		taskList:     tview.NewList(),
		outputView:   tview.NewTextView(),
		statusBar:    tview.NewTextView(),
		executor:     executor.NewExecutor(),
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

	for i, category := range categories {
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
			t.app.Stop()
			return nil
		}
		return event
	})
}

func (t *TUI) showCategory(categoryName string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.currentCategory = categoryName
	t.taskList.Clear()
	t.taskList.SetTitle(fmt.Sprintf("Tasks - %s", categoryName))

	for _, category := range categories {
		if category.Name == categoryName {
			for i, task := range category.Tasks {
				t.taskList.AddItem(task.Name, task.Description, rune('1'+i), func() {
					t.executeTask(task.Name)
				})
			}
			break
		}
	}

	t.statusBar.SetText(fmt.Sprintf("Category: %s - Select a task to execute", categoryName))
}

func (t *TUI) executeTask(taskName string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.statusBar.SetText(fmt.Sprintf("Executing: %s", taskName))
	t.outputView.Clear()
	t.outputView.SetTitle(fmt.Sprintf("Output - %s", taskName))

	fmt.Fprintf(t.outputView, "[yellow]Starting task: %s[white]\n", taskName)
	fmt.Fprintf(t.outputView, "[blue]Category: %s[white]\n\n", t.currentCategory)

	for _, category := range categories {
		if category.Name == t.currentCategory {
			for _, task := range category.Tasks {
				if task.Name == taskName {
					fmt.Fprintf(t.outputView, "[green]Script: %s[white]\n", task.Script)
					fmt.Fprintf(t.outputView, "[gray]Description: %s[white]\n\n", task.Description)

					scriptPath := filepath.Join("scripts", t.getScriptFolder(t.currentCategory), task.Script)
					go t.runScript(scriptPath)
					return
				}
			}
			break
		}
	}

	t.statusBar.SetText(fmt.Sprintf("Task completed: %s", taskName))
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

	fmt.Fprint(t.outputView, text)
}

func (t *TUI) UpdateStatus(text string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.statusBar.SetText(text)
}

func (t *TUI) Run() error {
	return t.app.Run()
}

func (t *TUI) Stop() {
	t.app.Stop()
}

func (t *TUI) runScript(scriptPath string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	t.app.QueueUpdateDraw(func() {
		fmt.Fprintf(t.outputView, "[cyan]Executing script: %s[white]\n\n", scriptPath)
		t.statusBar.SetText("Script running...")
	})

	go func() {
		for {
			select {
			case output, ok := <-t.executor.GetOutputChannel():
				if !ok {
					return
				}
				t.app.QueueUpdateDraw(func() {
					fmt.Fprintf(t.outputView, "%s\n", output)
				})
			case <-t.executor.GetDoneChannel():
				t.app.QueueUpdateDraw(func() {
					fmt.Fprintf(t.outputView, "\n[green]Script execution completed[white]\n")
					t.statusBar.SetText("Script completed")
				})
				return
			case <-ctx.Done():
				t.app.QueueUpdateDraw(func() {
					fmt.Fprintf(t.outputView, "\n[red]Script execution timed out[white]\n")
					t.statusBar.SetText("Script timed out")
				})
				return
			}
		}
	}()

	result, err := t.executor.ExecuteScript(ctx, scriptPath)
	if err != nil {
		t.app.QueueUpdateDraw(func() {
			fmt.Fprintf(t.outputView, "\n[red]Error executing script: %v[white]\n", err)
			t.statusBar.SetText("Script failed")
		})
		return
	}

	if !result.Success {
		t.app.QueueUpdateDraw(func() {
			fmt.Fprintf(t.outputView, "\n[red]Script failed with error: %v[white]\n", result.Error)
			t.statusBar.SetText("Script failed")
		})
	}
}
