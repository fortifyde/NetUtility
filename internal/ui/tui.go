package ui

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"netutil/internal/config"
	"netutil/internal/correlation"
	"netutil/internal/jobs"
	"netutil/internal/metadata"
)

const (
	AppName    = "NetUtility"
	AppVersion = "v0.3.1"
)

type TUI struct {
	app   *tview.Application
	pages *tview.Pages

	// Base layout components
	headerPane      *tview.TextView
	categoryPane    *tview.List
	taskPane        *tview.List
	infoPane        *tview.TextView
	assessmentPanel *tview.TextView
	jobsPanel       *tview.TextView

	// State management
	currentCategory        string
	workspaceDir           string
	registry               *metadata.ScriptRegistry
	jobManager             *jobs.JobManager
	correlator             *correlation.Correlator
	jobsViewer             *JobsViewer
	dashboardViewer        *Dashboard
	corrViewer             *CorrelationViewer
	outputViewer           *OutputViewer
	taskListIsContinuation []bool // true for wrapped-description continuation rows
	lang                   string

	str *Strings

	jobCounter         atomic.Int64
	mainViewTickerStop chan struct{}
	stopOnce           sync.Once
}

type Category struct {
	Name  string
	Tasks []Task
}

type Task struct {
	Name          string // display name (localized)
	Description   string // display description (localized)
	CanonicalName string // English name from YAML, used for merge matching
	Script        string
	SubTasks      []Task // len > 0: selecting this task shows a sub-menu modal
}

// SearchResult pairs a matched task with the category it belongs to.
type SearchResult struct {
	Task         Task
	CategoryName string
}

// searchAllCategories returns all tasks across every category whose name or
// description contains query (case-insensitive). Returns nil for empty query.
func (t *TUI) searchAllCategories(query string) []SearchResult {
	if query == "" {
		return nil
	}
	lower := strings.ToLower(query)
	var results []SearchResult
	for _, cat := range t.getCategories() {
		for _, task := range cat.Tasks {
			if strings.Contains(strings.ToLower(task.Name), lower) ||
				strings.Contains(strings.ToLower(task.Description), lower) {
				results = append(results, SearchResult{Task: task, CategoryName: cat.Name})
			}
		}
	}
	return results
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

// getCategoriesFromMetadata builds categories from the metadata registry.
// Task.Script is set to the fully-resolved script path so executeTask needs
// no further registry lookups.
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
				CanonicalName: script.Script.Name,
				Name:          script.Script.LocalizedName(t.lang),
				Description:   script.Script.LocalizedDescription(t.lang),
				Script:        t.registry.GetScriptPath(script),
			})
		}

		// Only add category if it has tasks
		if len(tasks) > 0 {
			displayName := t.formatCategoryName(categoryName)
			categories = append(categories, Category{
				Name:  displayName,
				Tasks: tasks,
			})
		}
	}

	categories = mergeInterfaceTasks(categories, t.str)
	return mergeCaptureAnalysisTasks(categories, t.str)
}

// wrapText splits text into lines of at most width runes, breaking at word boundaries.
func wrapText(text string, width int) []string {
	if width <= 0 || text == "" {
		return []string{text}
	}
	var lines []string
	for len(text) > 0 {
		if len([]rune(text)) <= width {
			lines = append(lines, text)
			break
		}
		cutAt := width
		runes := []rune(text)
		for cutAt > 0 && runes[cutAt] != ' ' {
			cutAt--
		}
		if cutAt == 0 {
			cutAt = width // no space found — hard cut
		}
		lines = append(lines, string(runes[:cutAt]))
		text = strings.TrimLeft(string(runes[cutAt:]), " ")
	}
	return lines
}

// formatCategoryName converts metadata category names to display names
func (t *TUI) formatCategoryName(category string) string {
	switch category {
	case "host-config":
		return t.str.CatHostConfig
	case "utilities":
		return t.str.CatSystemUtilities
	case "discovery":
		return t.str.CatNetworkDiscovery
	case "scanning":
		return t.str.CatPortScanning
	case "advanced":
		return t.str.CatAdvancedTools
	default:
		if len(category) > 0 {
			return strings.ToUpper(category[:1]) + category[1:]
		}
		return category
	}
}

// getHardcodedCategories returns the original hardcoded categories as fallback.
// Script paths are relative to the working directory.
func (t *TUI) getHardcodedCategories() []Category {
	s := func(folder, file string) string {
		return filepath.Join("scripts", folder, file)
	}
	return []Category{
		{
			Name: t.str.CatHostConfig,
			Tasks: []Task{
				{Name: t.str.TaskSelectWorkDir, Description: t.str.TaskSelectWorkDirDesc, Script: s("system", "select_workdir.sh")},
				{
					Name:        t.str.TaskConfigInterfaces,
					Description: t.str.TaskConfigInterfacesDesc,
					SubTasks: []Task{
						{Name: t.str.TaskInterfaceStates, Description: t.str.TaskInterfaceStatesDesc, Script: s("system", "network_interfaces.sh")},
						{Name: t.str.TaskVLANInterfaces, Description: t.str.TaskVLANInterfacesDesc, Script: s("system", "add_vlan.sh")},
					},
				},
				{Name: t.str.TaskConfigureIP, Description: t.str.TaskConfigureIPDesc, Script: s("system", "configure_ip.sh")},
				{Name: t.str.TaskConfigureRoutes, Description: t.str.TaskConfigureRoutesDesc, Script: s("system", "configure_routes.sh")},
				{Name: t.str.TaskConfigureNameservers, Description: t.str.TaskConfigureNameserversDesc, Script: s("system", "configure_dns.sh")},
				{Name: t.str.TaskBackupConfig, Description: t.str.TaskBackupConfigDesc, Script: s("system", "backup_config.sh")},
				{Name: t.str.TaskRestoreConfig, Description: t.str.TaskRestoreConfigDesc, Script: s("system", "restore_config.sh")},
			},
		},
		{
			Name: t.str.CatNetworkDiscovery,
			Tasks: []Task{
				{Name: t.str.TaskNetworkCapture, Description: t.str.TaskNetworkCaptureDesc, Script: s("network", "network_capture.sh")},
				{Name: t.str.TaskExtractVLANIDs, Description: t.str.TaskExtractVLANIDsDesc, Script: s("network", "extract_vlans.sh")},
				{Name: t.str.TaskMultiPhaseDiscovery, Description: t.str.TaskMultiPhaseDiscoveryDesc, Script: s("network", "multi_phase_discovery.sh")},
				{Name: t.str.TaskHostCategorization, Description: t.str.TaskHostCategorizationDesc, Script: s("network", "categorize_hosts.sh")},
			},
		},
		{
			Name: t.str.CatPortScanning,
			Tasks: []Task{
				{Name: t.str.TaskPortServiceScan, Description: t.str.TaskPortServiceScanDesc, Script: s("scanning", "port_service_scan.sh")},
				{Name: t.str.TaskVulnAssessment, Description: t.str.TaskVulnAssessmentDesc, Script: s("scanning", "vulnerability_assessment.sh")},
			},
		},
		{
			Name: t.str.CatAdvancedTools,
			Tasks: []Task{
				{Name: t.str.TaskIntegratedWorkflow, Description: t.str.TaskIntegratedWorkflowDesc, Script: s("network", "integrated_workflow.sh")},
			},
		},
		{
			Name: t.str.CatAdvancedTools,
			Tasks: []Task{
				{Name: t.str.TaskDeviceConfigGathering, Description: t.str.TaskDeviceConfigGatheringDesc, Script: s("config", "device_config.sh")},
			},
		},
	}
}

// mergeInterfaceTasks finds "Manage Network Interfaces" and "Manage VLAN Interfaces"
// in the "Host Configuration" category and replaces them with a single composite
// "Configure Interfaces" task whose SubTasks hold the originals.
func mergeInterfaceTasks(categories []Category, str *Strings) []Category {
	for ci, cat := range categories {
		if cat.Name != str.CatHostConfig {
			continue
		}
		var ifaceTask, vlanTask Task
		ifaceIdx := -1
		for ti, task := range cat.Tasks {
			switch task.CanonicalName {
			case "Manage Network Interfaces":
				ifaceTask = task
				if ifaceIdx == -1 {
					ifaceIdx = ti
				}
			case "Manage VLAN Interfaces":
				vlanTask = task
			}
		}
		if ifaceIdx == -1 || vlanTask.CanonicalName == "" {
			continue // one or both source tasks missing — skip this category
		}
		// Build new task list without the two interface tasks
		newTasks := make([]Task, 0, len(cat.Tasks)-1)
		for _, t := range cat.Tasks {
			if t.CanonicalName != "Manage Network Interfaces" && t.CanonicalName != "Manage VLAN Interfaces" {
				newTasks = append(newTasks, t)
			}
		}
		composite := Task{
			Name:          str.TaskConfigInterfaces,
			CanonicalName: "Configure Interfaces",
			Description:   str.TaskConfigInterfacesDesc,
			SubTasks: []Task{
				{Name: str.TaskInterfaceStates, CanonicalName: "Manage Network Interfaces", Description: ifaceTask.Description, Script: ifaceTask.Script},
				{Name: str.TaskVLANInterfaces, CanonicalName: "Manage VLAN Interfaces", Description: vlanTask.Description, Script: vlanTask.Script},
			},
		}
		// Insert composite at the original position of the first interface task
		if ifaceIdx > len(newTasks) {
			ifaceIdx = len(newTasks)
		}
		newTasks = append(newTasks[:ifaceIdx:ifaceIdx], append([]Task{composite}, newTasks[ifaceIdx:]...)...)
		categories[ci].Tasks = newTasks
		break
	}
	return categories
}

// mergeCaptureAnalysisTasks finds "Extract VLANs", "MAC Address Analysis", and
// "Packet Capture Analysis" in the "Network Discovery" category and replaces them
// with a single composite "Network Capture Analysis" task.
func mergeCaptureAnalysisTasks(categories []Category, str *Strings) []Category {
	for ci, cat := range categories {
		if cat.Name != str.CatNetworkDiscovery {
			continue
		}
		var vlanTask, macTask, captureTask Task
		firstIdx := -1
		for ti, task := range cat.Tasks {
			switch task.CanonicalName {
			case "Extract VLANs":
				vlanTask = task
				if firstIdx == -1 {
					firstIdx = ti
				}
			case "MAC Address Analysis":
				macTask = task
				if firstIdx == -1 {
					firstIdx = ti
				}
			case "Packet Capture Analysis":
				captureTask = task
				if firstIdx == -1 {
					firstIdx = ti
				}
			}
		}
		if firstIdx == -1 || vlanTask.CanonicalName == "" || macTask.CanonicalName == "" || captureTask.CanonicalName == "" {
			continue
		}
		newTasks := make([]Task, 0, len(cat.Tasks)-2)
		for _, t := range cat.Tasks {
			if t.CanonicalName != "Extract VLANs" && t.CanonicalName != "MAC Address Analysis" && t.CanonicalName != "Packet Capture Analysis" {
				newTasks = append(newTasks, t)
			}
		}
		composite := Task{
			Name:          str.TaskNetworkCaptureAnalysis,
			CanonicalName: "Network Capture Analysis",
			Description:   str.TaskNetworkCaptureAnalysisDesc,
			SubTasks: []Task{
				{Name: str.TaskExtractVLANIDs, CanonicalName: "Extract VLANs", Description: vlanTask.Description, Script: vlanTask.Script},
				{Name: macTask.Name, CanonicalName: "MAC Address Analysis", Description: macTask.Description, Script: macTask.Script},
				{Name: captureTask.Name, CanonicalName: "Packet Capture Analysis", Description: captureTask.Description, Script: captureTask.Script},
			},
		}
		// Insert composite immediately after "Network Capture" if present, otherwise at firstIdx
		insertIdx := -1
		for ti, t := range newTasks {
			if t.CanonicalName == "Network Capture" {
				insertIdx = ti + 1
				break
			}
		}
		if insertIdx == -1 {
			insertIdx = firstIdx
			if insertIdx > len(newTasks) {
				insertIdx = len(newTasks)
			}
		}
		newTasks = append(newTasks[:insertIdx:insertIdx], append([]Task{composite}, newTasks[insertIdx:]...)...)
		categories[ci].Tasks = newTasks
		break
	}
	return categories
}

// ensureTrueColor sets COLORTERM=truecolor if not already set, enabling
// tcell to use 24-bit RGB color sequences. Terminals that don't support
// these sequences will silently ignore them.
func ensureTrueColor() {
	if os.Getenv("COLORTERM") != "" {
		return
	}
	_ = os.Setenv("COLORTERM", "truecolor")
}

func NewTUI(scriptsDir, workspaceDir, lang string) *TUI {

	// Ensure TrueColor is available for screenshot rendering.
	// Many terminals (e.g., qterminal) support 24-bit color but don't set
	// COLORTERM, which tcell uses to decide whether to emit RGB escape sequences.
	ensureTrueColor()

	app := tview.NewApplication()

	// Initialize script registry with provided scripts directory
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
		app:                app,
		pages:              tview.NewPages(),
		headerPane:         tview.NewTextView().SetDynamicColors(true),
		categoryPane:       tview.NewList(),
		taskPane:           tview.NewList(),
		infoPane:           tview.NewTextView(),
		assessmentPanel:    tview.NewTextView().SetDynamicColors(true).SetScrollable(false),
		jobsPanel:          tview.NewTextView().SetDynamicColors(true).SetScrollable(false),
		registry:           registry,
		workspaceDir:       workspaceDir,
		jobManager:         jobs.NewJobManager(3),
		correlator:         correlation.NewCorrelator(workspaceDir),
		mainViewTickerStop: make(chan struct{}),
	}
	tui.str = stringsForLang(lang)
	tui.lang = lang

	if workspaceDir != "" {
		tui.jobManager.SetOnJobDone(func() { config.FixWorkspaceOwnershipForPath(workspaceDir) })
	}

	if workspaceDir != "" {
		if err := tui.correlator.LoadResults(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to load correlation results: %v\n", err)
		}
		tui.loadWorkspaceResults()
	}

	tui.setupUI()
	tui.startCorrelationWorker()
	tui.startMainViewTicker()
	return tui
}

// loadWorkspaceResults reloads persistent state from disk (picking up any changes made by
// external scripts such as exclude_team_ips.sh), then rescans workspace result files.
// Excluded hosts loaded from disk are never re-added by the workspace scan.
func (t *TUI) loadWorkspaceResults() {
	if err := t.correlator.LoadResults(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to reload correlation results: %v\n", err)
	}
	parser := correlation.NewResultParser(t.workspaceDir)
	results, err := parser.ScanWorkspaceForResults()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to scan workspace for results: %v\n", err)
		return
	}
	for _, result := range results {
		if err := t.correlator.AddScanResult(result); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to load workspace result: %v\n", err)
		}
	}

	// Merge screenshot data from gowitness JSONL files on disk
	if err := t.correlator.MergeScreenshotFiles(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to merge screenshot files: %v\n", err)
	}
}

// startCorrelationWorker re-scans the workspace after each completed job to pick up new result files.
func (t *TUI) startCorrelationWorker() {
	if t.workspaceDir == "" {
		return
	}
	_, completedChan, _ := t.jobManager.GetJobEventChannels()
	go func() {
		for range completedChan {
			t.loadWorkspaceResults()
		}
	}()
}

// startMainViewTicker starts a background goroutine that periodically
// updates the assessment checklist and active jobs panel.
func (t *TUI) startMainViewTicker() {
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				t.app.QueueUpdateDraw(func() {
					t.updateJobsPanel()
					t.updateAssessmentPanel()
				})
			case <-t.mainViewTickerStop:
				return
			}
		}
	}()
}

// updateJobsPanel renders the active jobs panel showing running and pending jobs.
func (t *TUI) updateJobsPanel() {
	allJobs := t.jobManager.GetAllJobs()

	var active []*jobs.Job
	for _, j := range allJobs {
		status := j.GetStatus()
		if status == jobs.JobStatusRunning || status == jobs.JobStatusPending {
			active = append(active, j)
		}
	}

	if len(active) == 0 {
		t.jobsPanel.SetText(t.str.JobsPanelNoActive)
		return
	}

	var sb strings.Builder
	sb.WriteString("\n")

	indicatorChars := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧"}

	for _, job := range active {
		status := job.GetStatus()
		needsInput := job.NeedsInput()

		// Status icon and name
		switch {
		case needsInput:
			sb.WriteString("[yellow]\u2691[white] ")
		case status == jobs.JobStatusRunning:
			sb.WriteString("[green]\u25CF[white] ")
		default:
			sb.WriteString("\u25CB ")
		}

		// Job name
		name := job.Name
		sb.WriteString(name)

		// Duration for running jobs
		if status == jobs.JobStatusRunning {
			dur := time.Since(job.StartTime).Round(time.Second)
			sb.WriteString(fmt.Sprintf("  %v", dur))
		}
		sb.WriteString("\n")

		// Progress line
		if needsInput {
			sb.WriteString("  ")
			sb.WriteString(t.str.FmtJobsPanelNeedsInput)
		} else if status == jobs.JobStatusRunning {
			current, total, desc := job.GetPhaseProgress()
			if total > 0 {
				sb.WriteString("  ")
				sb.WriteString(renderProgressBar(current, total, desc))
			} else {
				idx := int(time.Now().Unix()) % len(indicatorChars)
				sb.WriteString(fmt.Sprintf("  %s %s", indicatorChars[idx], t.str.ProgressRunning))
			}
		}
		sb.WriteString("\n")
	}

	t.jobsPanel.SetText(sb.String())
}

// updateAssessmentPanel renders the compact assessment workflow checklist.
func (t *TUI) updateAssessmentPanel() {
	var sb strings.Builder
	sb.WriteString("\n")

	phases := []struct {
		name     string
		check    func() bool
		suffixFn func() string // optional suffix (e.g. uncategorized count)
	}{
		{t.str.AssessmentPhaseCapture, t.checkCaptureDone, nil},
		{t.str.AssessmentPhaseSysConfig, t.checkSysConfigDone, nil},
		{t.str.AssessmentPhaseDiscovery, t.checkDiscoveryDone, nil},
		{t.str.AssessmentPhaseCategorize, t.checkCategorizeDone, t.categorizeSuffix},
		{t.str.AssessmentPhasePortVuln, t.checkPortVulnDone, nil},
		{t.str.AssessmentPhaseDevConfig, t.checkDevConfigDone, nil},
	}

	for _, phase := range phases {
		if phase.check() {
			sb.WriteString("[green]\u2713[white] ")
		} else {
			sb.WriteString("\u25CB ")
		}
		sb.WriteString(phase.name)
		if phase.suffixFn != nil {
			sb.WriteString(phase.suffixFn())
		}
		sb.WriteString("\n")
	}

	t.assessmentPanel.SetText(sb.String())
}

// Assessment completion checks.

func (t *TUI) checkCaptureDone() bool {
	if t.workspaceDir == "" {
		return false
	}
	matches, _ := filepath.Glob(filepath.Join(t.workspaceDir, "captures", "capture_*.pcap"))
	return len(matches) > 0
}

func (t *TUI) checkSysConfigDone() bool {
	// Check for at least one UP non-loopback interface with an IPv4 address.
	// Read sysfs directly instead of spawning "ip -j addr" every 2 seconds.
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return false
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == "lo" {
			continue
		}
		state, err := os.ReadFile(filepath.Join("/sys/class/net", name, "operstate"))
		if err != nil || strings.TrimSpace(string(state)) != "up" {
			continue
		}
		// Check for a non-loopback IPv4 address.
		iface, err := net.InterfaceByName(name)
		if err != nil {
			continue
		}
		ifaceAddrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range ifaceAddrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipNet.IP.To4() != nil && !ipNet.IP.IsLoopback() {
				return true
			}
		}
	}
	return false
}

func (t *TUI) checkDiscoveryDone() bool {
	return len(t.correlator.GetAllCorrelations()) > 0
}

func (t *TUI) checkCategorizeDone() bool {
	hosts := t.correlator.GetAllCorrelations()
	for _, h := range hosts {
		if h.HostInfo != nil && h.HostInfo.Attributes != nil && h.HostInfo.Attributes["category"] == "unknown" {
			return false
		}
	}
	return len(hosts) > 0
}

func (t *TUI) categorizeSuffix() string {
	var unknown int
	hosts := t.correlator.GetAllCorrelations()
	for _, h := range hosts {
		if h.HostInfo != nil && h.HostInfo.Attributes != nil && h.HostInfo.Attributes["category"] == "unknown" {
			unknown++
		}
	}
	if unknown > 0 {
		return fmt.Sprintf(t.str.FmtAssessmentUncategorized, unknown)
	}
	return ""
}

func (t *TUI) checkPortVulnDone() bool {
	if t.workspaceDir == "" {
		return false
	}
	base := filepath.Join(t.workspaceDir, "port_and_security_scans")
	found := false
	_ = filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
		if err != nil || found {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".nmap") || strings.HasSuffix(path, ".xml") {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

func (t *TUI) checkDevConfigDone() bool {
	if t.workspaceDir == "" {
		return false
	}
	matches, _ := filepath.Glob(filepath.Join(t.workspaceDir, "configs", "gather_*", "session_summary.txt"))
	if len(matches) > 0 {
		return true
	}
	matches, _ = filepath.Glob(filepath.Join(t.workspaceDir, "configs", "gather_*", "device_*", "running_config.txt"))
	return len(matches) > 0
}

func (t *TUI) setupUI() {
	// Setup header pane (program info)
	t.headerPane.SetBorder(true).SetTitle(t.str.PaneTitleProgramInfo)
	headerText := fmt.Sprintf(t.str.FmtHeaderText, AppName, AppVersion)
	t.headerPane.SetText(headerText)
	t.headerPane.SetTextAlign(tview.AlignCenter)

	// Setup category pane
	t.categoryPane.SetBorder(true).SetTitle(t.str.PaneTitleCategories)
	t.categoryPane.ShowSecondaryText(false)

	// Setup task pane (75% width)
	t.taskPane.SetBorder(true).SetTitle(t.str.PaneTitleTaskDefault)
	t.taskPane.ShowSecondaryText(false)
	t.taskPane.SetSelectedFocusOnly(true)

	// Populate categories
	for i, category := range t.getCategories() {
		name := category.Name
		t.categoryPane.AddItem(name, "", rune('1'+i), func() {
			t.showCategory(name)
		})
	}

	// Update task pane when category highlight changes (without moving focus)
	t.categoryPane.SetChangedFunc(func(index int, mainText, secondaryText string, shortcut rune) {
		t.populateTaskPane(mainText)
	})

	// Set category selection handler (Enter key — moves focus to task pane)
	t.categoryPane.SetSelectedFunc(func(index int, mainText, secondaryText string, shortcut rune) {
		t.showCategory(mainText)
	})

	// Show the first category's tasks on startup. Defer to the first draw so
	// the task pane has its actual width from the flex layout, avoiding early
	// text wrapping from the fallback width.
	t.taskPane.SetDrawFunc(func(screen tcell.Screen, x, y, width, height int) (int, int, int, int) {
		t.taskPane.SetDrawFunc(nil) // one-shot: remove itself after first draw
		if categories := t.getCategories(); len(categories) > 0 {
			t.populateTaskPane(categories[0].Name)
		}
		return t.taskPane.GetInnerRect()
	})

	// Set task selection handler — ignore continuation (wrapped description) rows
	t.taskPane.SetSelectedFunc(func(index int, mainText, secondaryText string, shortcut rune) {
		if t.isContinuation(index) {
			return
		}
		t.executeTask(mainText)
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

	// Add j/k and arrow key navigation to task pane, skipping continuation rows
	t.taskPane.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyRune:
			switch event.Rune() {
			case 'j':
				t.moveTaskDown()
				return nil
			case 'k':
				t.moveTaskUp()
				return nil
			}
		case tcell.KeyDown:
			t.moveTaskDown()
			return nil
		case tcell.KeyUp:
			t.moveTaskUp()
			return nil
		}
		return event
	})

	// Setup info pane (informational panel for first-time users)
	t.infoPane.SetBorder(true).SetTitle(t.str.PaneTitleQuickRef)
	t.infoPane.SetDynamicColors(true)
	t.updateInfoPanel() // Set initial content

	// Setup assessment panel (compact checklist at bottom of left column)
	t.assessmentPanel.SetBorder(true).SetTitle(t.str.PaneTitleAssessment)

	// Setup active jobs panel (bottom of right column)
	t.jobsPanel.SetBorder(true).SetTitle(t.str.PaneTitleActiveJobsPanel)
	t.jobsPanel.SetText(t.str.JobsPanelNoActive)

	// Layout: Left column = header + categories + assessment checklist
	//         Right column = tasks (top) + active jobs (bottom)
	//         Bottom = info/keybindings
	leftColumn := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(t.headerPane, 5, 0, false).     // Fixed height for header
		AddItem(t.categoryPane, 0, 1, true).    // Flexible height for categories
		AddItem(t.assessmentPanel, 9, 0, false) // Fixed height for assessment checklist

	rightColumn := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(t.taskPane, 0, 1, false). // Flexible: tasks
		AddItem(t.jobsPanel, 0, 1, false) // Flexible: active jobs

	topLayout := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(leftColumn, 0, 1, true).  // 25% width for left column
		AddItem(rightColumn, 0, 3, false) // 75% width for right column

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

	// Set initial focus and apply visual focus indicator
	t.setActiveFocus(t.categoryPane)
}

func (t *TUI) handleGlobalKeys(event *tcell.EventKey) *tcell.EventKey {
	// Consume Ctrl+C to prevent tview's built-in handler from stopping the application.
	// tview calls a.Stop() on unhandled Ctrl+C (application.go ~L433). All pages handle
	// their own cancellation — the output viewer uses it to stop streaming, the main page
	// has no use for it. Either way the TUI must stay alive.
	if event.Key() == tcell.KeyCtrlC {
		if t.outputViewer != nil {
			t.outputViewer.CancelAndReturn()
		}
		return nil
	}

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
	if event.Key() == tcell.KeyCtrlN {
		// Global Host view access
		t.showCorrelationViewer()
		return nil
	}
	// Ctrl+Z: tcell puts the terminal in raw mode (ISIG cleared),
	// so the kernel never converts Ctrl+Z to SIGTSTP — safe to use as a keybind.
	if event.Key() == tcell.KeyCtrlZ {
		// Global return to main TUI from anywhere
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
		t.confirmQuit()
		return nil
	case tcell.KeyRune:
		switch event.Rune() {
		case 'q':
			// Vim-like quit — shows confirmation if jobs are running
			t.confirmQuit()
			return nil
		case '/':
			// Search functionality
			t.startSearch()
			return nil
		case 'h':
			// Vim-like left (focus categories)
			t.setActiveFocus(t.categoryPane)
			return nil
		case 'l':
			// Vim-like right (focus tasks)
			t.setActiveFocus(t.taskPane)
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
		t.setActiveFocus(t.taskPane)
	} else {
		t.setActiveFocus(t.categoryPane)
	}
}

// setActiveFocus focuses the given pane and updates border colors: the active
// pane gets a blue border, all others revert to the terminal default.
func (t *TUI) setActiveFocus(pane *tview.List) {
	t.app.SetFocus(pane)
	if pane == t.categoryPane {
		t.categoryPane.SetBorderColor(tcell.ColorBlue)
		t.taskPane.SetBorderColor(tcell.ColorDefault)
	} else {
		t.categoryPane.SetBorderColor(tcell.ColorDefault)
		t.taskPane.SetBorderColor(tcell.ColorBlue)
	}
	t.updateInfoPanel()
}

func (t *TUI) showCategory(categoryName string) {
	t.populateTaskPane(categoryName)
	t.setActiveFocus(t.taskPane)
}

// populateTaskPane clears the task pane and fills it with the tasks for the
// given category. It does NOT move focus to the task pane.
func (t *TUI) populateTaskPane(categoryName string) {
	t.currentCategory = categoryName
	t.taskPane.Clear()
	t.taskListIsContinuation = t.taskListIsContinuation[:0]
	t.taskPane.SetTitle(fmt.Sprintf(t.str.FmtTasksTitle, categoryName))

	_, _, paneWidth, _ := t.taskPane.GetInnerRect()
	if paneWidth <= 0 {
		paneWidth = 58 // fallback before first draw
	}

	// Find and display tasks for selected category
	for _, category := range t.getCategories() {
		if category.Name == categoryName {
			for _, task := range category.Tasks {
				lines := wrapText(task.Description, paneWidth)
				t.taskPane.AddItem(task.Name, "", 0, nil)
				t.taskListIsContinuation = append(t.taskListIsContinuation, false)
				for _, line := range lines {
					t.taskPane.AddItem("[green]  "+line+"[white]", "", 0, nil)
					t.taskListIsContinuation = append(t.taskListIsContinuation, true)
				}
			}
			break
		}
	}
}

func (t *TUI) isContinuation(idx int) bool {
	return idx >= 0 && idx < len(t.taskListIsContinuation) && t.taskListIsContinuation[idx]
}

func (t *TUI) moveTaskDown() {
	cur := t.taskPane.GetCurrentItem()
	count := t.taskPane.GetItemCount()
	next := cur + 1
	for next < count && t.isContinuation(next) {
		next++
	}
	if next < count {
		t.taskPane.SetCurrentItem(next)
	}
}

func (t *TUI) moveTaskUp() {
	cur := t.taskPane.GetCurrentItem()
	prev := cur - 1
	for prev >= 0 && t.isContinuation(prev) {
		prev--
	}
	if prev >= 0 {
		t.taskPane.SetCurrentItem(prev)
	}
}

func (t *TUI) executeTask(taskName string) {
	// Task.Script always holds the resolved path (set by getCategoriesFromMetadata
	// or getHardcodedCategories), so a single pass through the current category suffices.
	for _, category := range t.getCategories() {
		if category.Name != t.currentCategory {
			continue
		}
		for _, task := range category.Tasks {
			if task.Name == taskName {
				if len(task.SubTasks) > 0 {
					t.showSubTaskMenu(task)
					return
				}
				t.executeTaskWithStreaming(task.Script, taskName)
				return
			}
		}
	}

	t.showErrorModal(t.str.TitleScriptNotFound, fmt.Sprintf(t.str.FmtScriptNotFound, taskName))
}

// executeTaskWithStreaming executes a task using the JobManager for consistent tracking
func (t *TUI) executeTaskWithStreaming(scriptPath, taskName string) {
	// Convert to absolute path
	absPath, err := filepath.Abs(scriptPath)
	if err != nil {
		// Show error modal
		t.showErrorModal(t.str.TitlePathError, fmt.Sprintf(t.str.FmtPathError, err))
		return
	}

	// Check capacity before creating a job to avoid orphaned pending entries
	if !t.jobManager.CanStartNewJob() {
		t.showExecutionOptions(absPath, taskName)
		return
	}

	// Create and start job via JobManager for consistent tracking
	jobID := fmt.Sprintf("job_%d", t.jobCounter.Add(1))
	job := t.jobManager.CreateJob(jobID, taskName, absPath)
	if err := t.jobManager.StartJob(job.ID); err != nil {
		// Unexpected failure — clean up the orphan and show options
		t.jobManager.RemoveJob(job.ID)
		t.showExecutionOptions(absPath, taskName)
		return
	}

	// Job started successfully - show live output
	t.outputViewer = NewOutputViewer(t.app, t.pages, t.jobManager, t.returnToMain, t.str)
	t.pages.AddPage("output", t.outputViewer, true, true)
	t.outputViewer.FocusView()

	// Connect OutputViewer to the running job
	if err := t.outputViewer.ConnectToJob(job); err != nil {
		t.showErrorModal(t.str.TitleConnectionError, fmt.Sprintf(t.str.FmtConnectionError, err))
		t.pages.RemovePage("output")
		return
	}
}

// showSubTaskMenu shows a modal letting the user pick which sub-task
// operation to run. Each sub-task is executed immediately on selection.
func (t *TUI) showSubTaskMenu(task Task) {
	buttons := make([]string, 0, len(task.SubTasks)+1)
	for _, sub := range task.SubTasks {
		buttons = append(buttons, sub.Name)
	}
	buttons = append(buttons, t.str.BtnCancel)

	modal := tview.NewModal().
		SetText(fmt.Sprintf("%s\n\n%s", task.Name, t.str.SubtaskSelectOp)).
		AddButtons(buttons).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			t.pages.RemovePage("subtask-menu")
			if buttonLabel == t.str.BtnCancel {
				t.setActiveFocus(t.taskPane)
				return
			}
			for _, sub := range task.SubTasks {
				if sub.Name == buttonLabel {
					t.executeTaskWithStreaming(sub.Script, sub.Name)
					return
				}
			}
		})

	t.pages.AddPage("subtask-menu", modal, true, true)
}

// showExecutionOptions shows options for script execution when at capacity
func (t *TUI) showExecutionOptions(scriptPath, taskName string) {
	modal := tview.NewModal().
		SetText(fmt.Sprintf(t.str.FmtExecutionOptions, taskName)).
		AddButtons([]string{t.str.BtnQueueJob, t.str.BtnViewJobs, t.str.BtnCancel}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			t.pages.RemovePage("execution-options")
			switch buttonLabel {
			case t.str.BtnQueueJob:
				t.queueJob(scriptPath, taskName)
			case t.str.BtnViewJobs:
				t.showJobsManager()
			}
		})

	t.pages.AddPage("execution-options", modal, true, true)
}

// queueJob queues a job for later execution
func (t *TUI) queueJob(scriptPath, taskName string) {
	jobID := fmt.Sprintf("job_%d", t.jobCounter.Add(1))
	job := t.jobManager.CreateJob(jobID, taskName, scriptPath)

	// Try to start it immediately (in case a slot opened up)
	if err := t.jobManager.StartJob(job.ID); err != nil {
		// Job was queued, show confirmation
		t.showInfoModal(t.str.TitleJobQueued, fmt.Sprintf(t.str.FmtJobQueued, taskName))
	} else {
		// Job started immediately
		t.showInfoModal(t.str.TitleJobStarted, fmt.Sprintf(t.str.FmtJobStarted, taskName))
	}
}

// showJobsManager displays the jobs management interface
func (t *TUI) showJobsManager() {
	if t.jobsViewer == nil {
		t.jobsViewer = NewJobsViewer(t.app, t.pages, t.jobManager, func() {
			t.jobsViewer = nil
			t.returnToMain()
		}, t.str)
	}
	t.pages.AddPage("jobs", t.jobsViewer, true, true)
	t.app.SetFocus(t.jobsViewer.jobsList)
}

// showCorrelationViewer displays the correlation viewer interface
func (t *TUI) showCorrelationViewer() {
	if t.corrViewer != nil {
		t.corrViewer.Close()
		t.corrViewer = nil
	}
	t.corrViewer = NewCorrelationViewer(t.app, t.pages, t.correlator, t.returnToMain, t.workspaceDir, t.str)
	t.pages.AddPage("correlation", t.corrViewer, true, true)
	t.app.SetFocus(t.corrViewer.hostsList)
}

// showDashboard displays the dashboard interface
func (t *TUI) showDashboard() {
	if t.dashboardViewer != nil {
		t.dashboardViewer.Close()
		t.dashboardViewer = nil
	}
	t.dashboardViewer = NewDashboard(t.app, t.pages, t.jobManager, t.correlator, nil, t.returnToMain, t.str)
	t.pages.AddPage("dashboard", t.dashboardViewer, true, true)
	t.app.SetFocus(t.dashboardViewer.topFindingsTable)
}

// showInfoModal displays an info message to the user
func (t *TUI) showInfoModal(title, message string) {
	infoModal := tview.NewModal().
		SetText(message).
		AddButtons([]string{t.str.BtnOK}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			t.pages.RemovePage("info")
		})

	t.pages.AddPage("info", infoModal, true, true)
}

// showErrorModal displays an error message to the user
func (t *TUI) showErrorModal(title, message string) {
	errorModal := tview.NewModal().
		SetText(message).
		AddButtons([]string{t.str.BtnOK}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			t.pages.RemovePage("error")
		})

	t.pages.AddPage("error", errorModal, true, true)
}

func (t *TUI) Run() error {
	if err := t.app.Run(); err != nil {
		return fmt.Errorf("TUI application failed: %w", err)
	}
	return nil
}

func (t *TUI) Stop() {
	t.stopOnce.Do(func() { close(t.mainViewTickerStop) })
	t.app.Stop()
}

// startSearch opens a compact centered modal for searching tasks across all categories.
func (t *TUI) startSearch() {
	prevFocus := t.categoryPane
	if t.app.GetFocus() == t.taskPane {
		prevFocus = t.taskPane
	}

	var results []SearchResult

	closeModal := func() {
		t.pages.RemovePage("search")
		t.setActiveFocus(prevFocus)
	}

	inputField := tview.NewInputField().
		SetLabel(t.str.SearchLabel).
		SetFieldWidth(0)

	resultList := tview.NewList().ShowSecondaryText(false)

	// searchContinuations[i] == true means list item i is a wrapped description line, not a result
	var searchContinuations []bool
	// searchResultIdx[i] is the results[] index for list item i (-1 for continuation items)
	var searchResultIdx []int

	isCont := func(idx int) bool {
		return idx >= 0 && idx < len(searchContinuations) && searchContinuations[idx]
	}
	resultForIdx := func(idx int) int {
		if idx < 0 || idx >= len(searchResultIdx) {
			return -1
		}
		return searchResultIdx[idx]
	}

	moveSearchDown := func() {
		cur := resultList.GetCurrentItem()
		count := resultList.GetItemCount()
		next := cur + 1
		for next < count && isCont(next) {
			next++
		}
		if next < count {
			resultList.SetCurrentItem(next)
		}
	}
	moveSearchUp := func() {
		cur := resultList.GetCurrentItem()
		prev := cur - 1
		for prev >= 0 && isCont(prev) {
			prev--
		}
		if prev >= 0 {
			resultList.SetCurrentItem(prev)
		}
	}

	updateResults := func(query string) {
		resultList.Clear()
		searchContinuations = searchContinuations[:0]
		searchResultIdx = searchResultIdx[:0]
		results = t.searchAllCategories(query)

		_, _, listWidth, _ := resultList.GetInnerRect()
		if listWidth <= 0 {
			listWidth = 36 // fallback before first draw (40% of 80col - borders)
		}

		for i, r := range results {
			header := fmt.Sprintf("%s  [%s]", r.Task.Name, r.CategoryName)
			resultList.AddItem(header, "", 0, nil)
			searchContinuations = append(searchContinuations, false)
			searchResultIdx = append(searchResultIdx, i)
			for _, line := range wrapText(r.Task.Description, listWidth) {
				resultList.AddItem("[green]  "+line+"[white]", "", 0, nil)
				searchContinuations = append(searchContinuations, true)
				searchResultIdx = append(searchResultIdx, i)
			}
		}
	}

	inputField.SetChangedFunc(updateResults)

	inputField.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyDown, tcell.KeyEnter:
			if resultList.GetItemCount() > 0 {
				t.app.SetFocus(resultList)
				resultList.SetCurrentItem(0)
			}
			return nil
		case tcell.KeyEscape:
			closeModal()
			return nil
		}
		return event
	})

	resultList.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEscape:
			closeModal()
			return nil
		case tcell.KeyUp:
			cur := resultList.GetCurrentItem()
			prev := cur - 1
			for prev >= 0 && isCont(prev) {
				prev--
			}
			if prev < 0 {
				t.app.SetFocus(inputField)
				return nil
			}
			moveSearchUp()
			return nil
		case tcell.KeyDown:
			moveSearchDown()
			return nil
		case tcell.KeyRune:
			switch event.Rune() {
			case 'j':
				moveSearchDown()
				return nil
			case 'k':
				cur := resultList.GetCurrentItem()
				prev := cur - 1
				for prev >= 0 && isCont(prev) {
					prev--
				}
				if prev < 0 {
					t.app.SetFocus(inputField)
					return nil
				}
				moveSearchUp()
				return nil
			}
		}
		return event
	})

	resultList.SetSelectedFunc(func(index int, _, _ string, _ rune) {
		ri := resultForIdx(index)
		if ri < 0 || ri >= len(results) {
			return
		}
		r := results[ri]
		closeModal()
		t.currentCategory = r.CategoryName
		if len(r.Task.SubTasks) > 0 {
			t.showSubTaskMenu(r.Task)
		} else {
			t.executeTaskWithStreaming(r.Task.Script, r.Task.Name)
		}
	})

	// Content box: input on top, results list below
	contentBox := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(inputField, 3, 0, true).
		AddItem(resultList, 0, 1, false)
	contentBox.SetBorder(true).SetTitle(t.str.PaneTitleSearch)

	// Center: 40% wide (3:4:3), 60% tall (1:3:1)
	centerRow := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(nil, 0, 3, false).
		AddItem(contentBox, 0, 4, true).
		AddItem(nil, 0, 3, false)

	modal := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(nil, 0, 1, false).
		AddItem(centerRow, 0, 3, true).
		AddItem(nil, 0, 1, false)

	t.pages.AddPage("search", modal, true, true)
	t.app.SetFocus(inputField)
}

// showHelp displays help information
func (t *TUI) showHelp() {
	helpModal := tview.NewModal().
		SetText(t.str.HelpText).
		AddButtons([]string{t.str.BtnClose}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			t.pages.RemovePage("help")
		})

	t.pages.AddPage("help", helpModal, true, true)
}

// updateInfoPanel updates the informational panel with context-sensitive content
func (t *TUI) updateInfoPanel() {
	current := t.app.GetFocus()
	var content strings.Builder

	if current == t.categoryPane {
		content.WriteString(t.str.InfoCatLine1)
		content.WriteString(t.str.InfoCatLine2)
	} else if current == t.taskPane {
		if t.currentCategory != "" {
			content.WriteString(fmt.Sprintf(t.str.FmtInfoTaskLine1, t.currentCategory))
		} else {
			content.WriteString(t.str.InfoTaskNoCatLine1)
		}
		content.WriteString(t.str.InfoGlobalLine)
	} else {
		content.WriteString(t.str.InfoDefaultLine1)
		content.WriteString(t.str.InfoDefaultLine2)
	}

	t.infoPane.SetText(content.String())
}

// returnToMain returns to the main TUI from any other view
func (t *TUI) returnToMain() {
	// Remove any overlays and return to main page
	pageNames := []string{"output", "job-output", "dashboard", "jobs", "correlation", "info", "error", "execution-options", "search", "help", "subtask-menu", "host-search", "host-categorize"}

	for _, pageName := range pageNames {
		t.pages.RemovePage(pageName)
	}

	// Switch to main page and set focus to appropriate panel
	t.pages.SwitchToPage("main")

	// Focus on categories if no category selected, otherwise focus on tasks
	if t.currentCategory == "" {
		t.setActiveFocus(t.categoryPane)
	} else {
		t.setActiveFocus(t.taskPane)
	}
}

// confirmQuit quits immediately if no jobs are running. If jobs are running,
// shows a modal asking the user to confirm before abandoning them.
func (t *TUI) confirmQuit() {
	stats := t.jobManager.GetStats()
	if stats.RunningJobs == 0 {
		t.app.Stop()
		return
	}
	message := fmt.Sprintf(t.str.FmtConfirmQuit, stats.RunningJobs)
	modal := tview.NewModal().
		SetText(message).
		AddButtons([]string{t.str.BtnQuit, t.str.BtnCancel}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			t.pages.RemovePage("quit-confirm")
			if buttonLabel == t.str.BtnQuit {
				t.app.Stop()
			}
		})
	t.pages.AddPage("quit-confirm", modal, true, true)
}
