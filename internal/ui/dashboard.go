package ui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"netutil/internal/correlation"
	"netutil/internal/jobs"
	"netutil/internal/workflow"
)

// Dashboard displays overview statistics and recent activity
type Dashboard struct {
	*tview.Flex
	app            *tview.Application
	pages          *tview.Pages
	jobManager     *jobs.JobManager
	correlator     *correlation.Correlator
	workflowEngine *workflow.WorkflowEngine

	// UI components
	statsPanel   *tview.TextView
	activityList *tview.List
	hostsTable   *tview.Table
	alertsPanel  *tview.TextView
	chartsPanel  *tview.TextView
	controlsText *tview.TextView

	// State
	refreshTicker        *time.Ticker
	stopChan             chan struct{}
	returnToMainCallback func()
}

// DashboardStats contains aggregated statistics for the discovery dashboard.
type DashboardStats struct {
	TotalHosts      int
	ActiveHosts     int
	TotalServices   int
	HostsByCategory map[string]int // keyed by category: "windows", "linux", "network_device", "unknown"
	RunningJobs     int
	CompletedJobs   int
	FailedJobs      int
	ActiveWorkflows int
	MaxConcurrent   int
	LastScanTime    time.Time
}

// ActivityItem represents a recent activity entry
type ActivityItem struct {
	Timestamp   time.Time
	Type        string // "job", "workflow", "scan", "alert"
	Title       string
	Description string
	Status      string
	Severity    string // for alerts
}

// NewDashboard creates a new dashboard
func NewDashboard(app *tview.Application, pages *tview.Pages, jobManager *jobs.JobManager,
	correlator *correlation.Correlator, workflowEngine *workflow.WorkflowEngine, returnToMainCallback func()) *Dashboard {

	d := &Dashboard{
		Flex:                 tview.NewFlex(),
		app:                  app,
		pages:                pages,
		jobManager:           jobManager,
		correlator:           correlator,
		workflowEngine:       workflowEngine,
		stopChan:             make(chan struct{}),
		returnToMainCallback: returnToMainCallback,
	}

	d.setupUI()
	d.startRefreshTimer()
	return d
}

// setupUI initializes the dashboard interface
func (d *Dashboard) setupUI() {
	// Create stats panel
	d.statsPanel = tview.NewTextView().SetDynamicColors(true)
	d.statsPanel.SetBorder(true).SetTitle("Discovery Stats")

	// Create activity list
	d.activityList = tview.NewList()
	d.activityList.SetBorder(true).SetTitle("Recent Activity")

	// Create hosts table
	d.hostsTable = tview.NewTable().SetBorders(true).SetSelectable(true, false)
	d.hostsTable.SetBorder(true).SetTitle("Discovered Hosts")

	// Create alerts panel
	d.alertsPanel = tview.NewTextView().SetDynamicColors(true).SetScrollable(true)
	d.alertsPanel.SetBorder(true).SetTitle("Job Activity")

	// Create charts panel (ASCII charts)
	d.chartsPanel = tview.NewTextView().SetDynamicColors(true)
	d.chartsPanel.SetBorder(true).SetTitle("Category Breakdown")

	// Create controls panel
	d.controlsText = tview.NewTextView().SetDynamicColors(true)
	d.controlsText.SetBorder(true).SetTitle("Controls")
	d.controlsText.SetText(`[yellow]Dashboard:[::-] [white]Enter[::-]=Details  [white]q[::-]=Close  [yellow]Global:[::-] [white]Ctrl+J[::-]=Jobs  [white]Ctrl+N[::-]=Hosts  [white]Ctrl+Z[::-]=Main`)

	// Layout: 3x2 grid
	topRow := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(d.statsPanel, 0, 2, false).
		AddItem(d.chartsPanel, 0, 3, false).
		AddItem(d.alertsPanel, 0, 2, false)

	middleRow := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(d.activityList, 0, 1, false).
		AddItem(d.hostsTable, 0, 2, true)

	bottomRow := d.controlsText

	d.SetDirection(tview.FlexRow).
		AddItem(topRow, 0, 2, false).
		AddItem(middleRow, 0, 2, false).
		AddItem(bottomRow, 3, 0, false)

	// Setup key bindings
	d.setupKeyBindings()

	// Initial update
	d.updateDashboard()
}

// setupKeyBindings configures keyboard shortcuts
func (d *Dashboard) setupKeyBindings() {
	d.hostsTable.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEscape:
			d.Close()
			return nil
		case tcell.KeyEnter:
			d.viewHostDetails()
			return nil
		case tcell.KeyRune:
			switch event.Rune() {
			case 'q':
				d.Close()
				return nil
			}
		}
		return event
	})

	// Activity list key bindings
	d.activityList.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyTab:
			d.app.SetFocus(d.hostsTable)
			return nil
		case tcell.KeyRune:
			switch event.Rune() {
			case 'q':
				d.Close()
				return nil
			}
		}
		return event
	})
}

// updateDashboard refreshes all dashboard components
func (d *Dashboard) updateDashboard() {
	correlations := d.correlator.GetAllCorrelations()

	stats := d.calculateStats(correlations)

	d.updateStatsPanel(stats)
	d.updateChartsPanel(stats)
	d.updateActivityPanel()
	d.updateActivityList(correlations)
	d.updateHostsTable(correlations)
}

// calculateStats aggregates discovery statistics from correlations and jobs.
func (d *Dashboard) calculateStats(correlations map[string]*correlation.CorrelationResult) DashboardStats {
	stats := DashboardStats{
		HostsByCategory: make(map[string]int),
	}

	jobStats := d.jobManager.GetStats()
	stats.RunningJobs = jobStats.RunningJobs
	stats.CompletedJobs = jobStats.CompletedJobs
	stats.FailedJobs = jobStats.FailedJobs
	stats.MaxConcurrent = jobStats.MaxConcurrent

	stats.TotalHosts = len(correlations)

	for _, corr := range correlations {
		if corr.HostInfo != nil && corr.HostInfo.Status == "up" {
			stats.ActiveHosts++
		}
		stats.TotalServices += len(corr.Services)
		stats.HostsByCategory[hostCategory(corr)]++

		if len(corr.Timeline) > 0 {
			lastEvent := corr.Timeline[len(corr.Timeline)-1]
			if lastEvent.Timestamp.After(stats.LastScanTime) {
				stats.LastScanTime = lastEvent.Timestamp
			}
		}
	}

	if d.workflowEngine != nil {
		workflows := d.workflowEngine.GetAllWorkflows()
		for _, wf := range workflows {
			if wf.Status == workflow.WorkflowStatusRunning {
				stats.ActiveWorkflows++
			}
		}
	}

	return stats
}

// updateStatsPanel renders the discovery statistics panel.
func (d *Dashboard) updateStatsPanel(stats DashboardStats) {
	var content strings.Builder

	content.WriteString("[yellow]Discovery Stats[::-]\n\n")
	content.WriteString(fmt.Sprintf("Hosts Discovered:  [white]%d[::-]\n", stats.TotalHosts))
	content.WriteString(fmt.Sprintf("  Windows:         [green]%d[::-]\n", stats.HostsByCategory["windows"]))
	content.WriteString(fmt.Sprintf("  Linux:           [yellow]%d[::-]\n", stats.HostsByCategory["linux"]))
	content.WriteString(fmt.Sprintf("  Net Devices:     [blue]%d[::-]\n", stats.HostsByCategory["network_device"]))
	content.WriteString(fmt.Sprintf("  Unknown:         [gray]%d[::-]\n", stats.HostsByCategory["unknown"]))
	content.WriteString("\n")
	content.WriteString(fmt.Sprintf("Services Found:    [white]%d[::-]\n", stats.TotalServices))
	content.WriteString("\n")
	content.WriteString("[yellow]Jobs[::-]\n")
	content.WriteString(fmt.Sprintf("Running:   [green]%d[::-]/%d max\n", stats.RunningJobs, stats.MaxConcurrent))
	content.WriteString(fmt.Sprintf("Completed: [blue]%d[::-]\n", stats.CompletedJobs))
	content.WriteString(fmt.Sprintf("Failed:    [red]%d[::-]\n", stats.FailedJobs))
	if !stats.LastScanTime.IsZero() {
		content.WriteString(fmt.Sprintf("\nLast Scan: [white]%s[::-]\n", stats.LastScanTime.Format("15:04")))
	}

	d.statsPanel.SetText(content.String())
}

// updateChartsPanel renders a category breakdown bar chart.
func (d *Dashboard) updateChartsPanel(stats DashboardStats) {
	var content strings.Builder

	categories := []string{"windows", "linux", "network_device", "unknown"}
	labels := []string{"Windows   ", "Linux     ", "Net Device", "Unknown   "}

	maxCount := 0
	for _, cat := range categories {
		if n := stats.HostsByCategory[cat]; n > maxCount {
			maxCount = n
		}
	}

	if maxCount == 0 {
		content.WriteString("[gray]No hosts discovered yet.[::-]\n\n")
		content.WriteString("[gray]Run Network Discovery from[::-]\n")
		content.WriteString("[gray]the Scripts menu to populate.[::-]\n")
	} else {
		const barWidth = 15
		for i, cat := range categories {
			count := stats.HostsByCategory[cat]
			filled := count * barWidth / maxCount
			if filled > barWidth {
				filled = barWidth
			}
			bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
			color := categoryTviewColor(cat)
			content.WriteString(fmt.Sprintf("[%s]%s[::-]  [%s]%s[::-]  [white]%d[::-]\n",
				color, labels[i], color, bar, count))
		}
	}

	d.chartsPanel.SetText(content.String())
}

// updateActivityPanel renders recent job activity in the Job Activity panel.
func (d *Dashboard) updateActivityPanel() {
	var content strings.Builder

	allJobs := d.jobManager.GetAllJobs()

	// Running jobs first, then by start time descending
	sort.Slice(allJobs, func(i, j int) bool {
		si := allJobs[i].GetStatus()
		sj := allJobs[j].GetStatus()
		if (si == jobs.JobStatusRunning) != (sj == jobs.JobStatusRunning) {
			return si == jobs.JobStatusRunning
		}
		return allJobs[i].StartTime.After(allJobs[j].StartTime)
	})

	maxItems := 8
	if len(allJobs) < maxItems {
		maxItems = len(allJobs)
	}

	for i := 0; i < maxItems; i++ {
		job := allJobs[i]
		status := job.GetStatus()
		var prefix, color string
		switch status {
		case jobs.JobStatusRunning:
			prefix, color = "●", "green"
		case jobs.JobStatusCompleted:
			prefix, color = "✓", "blue"
		case jobs.JobStatusFailed:
			prefix, color = "✗", "red"
		case jobs.JobStatusCancelled:
			prefix, color = "⊘", "gray"
		default:
			prefix, color = "○", "yellow"
		}

		var dur time.Duration
		if job.IsRunning() {
			dur = time.Since(job.StartTime)
		} else {
			dur = job.GetDuration()
		}

		name := job.Name
		if len([]rune(name)) > 22 {
			name = string([]rune(name)[:21]) + "…"
		}

		content.WriteString(fmt.Sprintf("[%s]%s %s  %s[::-]\n",
			color, prefix, name, formatJobDuration(dur)))
	}

	if len(allJobs) == 0 {
		content.WriteString("[gray]No jobs run yet.[::-]\n")
		content.WriteString("[gray]Start a discovery from[::-]\n")
		content.WriteString("[gray]the Scripts menu.[::-]\n")
	}

	d.alertsPanel.SetText(content.String())
}

// updateActivityList updates the recent activity list
func (d *Dashboard) updateActivityList(correlations map[string]*correlation.CorrelationResult) {
	d.activityList.Clear()

	activities := d.getRecentActivities(correlations)

	// Sort by timestamp (newest first)
	sort.Slice(activities, func(i, j int) bool {
		return activities[i].Timestamp.After(activities[j].Timestamp)
	})

	// Show up to 10 recent activities
	maxItems := 10
	if len(activities) < maxItems {
		maxItems = len(activities)
	}

	for i := 0; i < maxItems; i++ {
		activity := activities[i]
		timeStr := activity.Timestamp.Format("15:04")
		statusColor := d.getActivityColor(activity.Status)

		item := fmt.Sprintf("[%s]%s[::-] %s - %s", statusColor, timeStr, activity.Title, activity.Status)
		d.activityList.AddItem(item, activity.Description, 0, nil)
	}

	if len(activities) == 0 {
		d.activityList.AddItem("No recent activity", "", 0, nil)
	}
}

// getRecentActivities collects recent activities from various sources
func (d *Dashboard) getRecentActivities(correlations map[string]*correlation.CorrelationResult) []ActivityItem {
	var activities []ActivityItem

	// Add job activities
	jobs := d.jobManager.GetAllJobs()
	for _, job := range jobs {
		if !job.StartTime.IsZero() {
			activities = append(activities, ActivityItem{
				Timestamp:   job.StartTime,
				Type:        "job",
				Title:       fmt.Sprintf("Job: %s", job.Name),
				Description: fmt.Sprintf("Script: %s", job.ScriptPath),
				Status:      string(job.GetStatus()),
			})
		}
	}

	// Add correlation activities (scan timeline events)
	for _, correlation := range correlations {
		for _, event := range correlation.Timeline {
			activities = append(activities, ActivityItem{
				Timestamp:   event.Timestamp,
				Type:        "scan",
				Title:       fmt.Sprintf("Scan: %s", event.Source),
				Description: event.Description,
				Status:      "completed",
			})
		}
	}

	// Add workflow activities if available
	if d.workflowEngine != nil {
		workflows := d.workflowEngine.GetAllWorkflows()
		for _, workflow := range workflows {
			if !workflow.StartTime.IsZero() {
				activities = append(activities, ActivityItem{
					Timestamp:   workflow.StartTime,
					Type:        "workflow",
					Title:       fmt.Sprintf("Workflow: %s", workflow.Name),
					Description: workflow.Description,
					Status:      string(workflow.Status),
				})
			}
		}
	}

	return activities
}

// getActivityColor returns appropriate color for activity status
func (d *Dashboard) getActivityColor(status string) string {
	switch strings.ToLower(status) {
	case "completed":
		return "green"
	case "running":
		return "yellow"
	case "failed":
		return "red"
	case "cancelled":
		return "gray"
	default:
		return "white"
	}
}

// updateHostsTable renders discovered hosts sorted by category then IP.
func (d *Dashboard) updateHostsTable(correlations map[string]*correlation.CorrelationResult) {
	d.hostsTable.Clear()

	headers := []string{"IP", "Category", "Vendor", "Hostname", "Open Ports"}
	for i, header := range headers {
		d.hostsTable.SetCell(0, i, tview.NewTableCell(header).
			SetTextColor(tcell.ColorYellow).
			SetAlign(tview.AlignCenter).
			SetSelectable(false))
	}

	type hostEntry struct {
		ip     string
		result *correlation.CorrelationResult
	}

	var entries []hostEntry
	for ip, result := range correlations {
		entries = append(entries, hostEntry{ip, result})
	}

	sort.Slice(entries, func(i, j int) bool {
		ci := categoryOrder(hostCategory(entries[i].result))
		cj := categoryOrder(hostCategory(entries[j].result))
		if ci != cj {
			return ci < cj
		}
		return compareIPs(entries[i].ip, entries[j].ip)
	})

	if len(entries) == 0 {
		d.hostsTable.SetCell(1, 0,
			tview.NewTableCell("No hosts discovered yet — run Network Discovery to populate.").
				SetTextColor(tcell.ColorGray).
				SetAlign(tview.AlignCenter).
				SetSelectable(false).
				SetExpansion(5))
		return
	}

	maxHosts := 10
	if len(entries) < maxHosts {
		maxHosts = len(entries)
	}

	for i := 0; i < maxHosts; i++ {
		row := i + 1
		e := entries[i]
		cat := hostCategory(e.result)
		d.hostsTable.SetCell(row, 0, tview.NewTableCell(e.ip))
		d.hostsTable.SetCell(row, 1, tview.NewTableCell(cat).SetTextColor(categoryTcellColor(cat)))
		d.hostsTable.SetCell(row, 2, tview.NewTableCell(hostVendor(e.result)))
		d.hostsTable.SetCell(row, 3, tview.NewTableCell(hostHostname(e.result)))
		d.hostsTable.SetCell(row, 4, tview.NewTableCell(hostOpenPorts(e.result)))
	}

	if d.hostsTable.GetRowCount() > 1 {
		d.hostsTable.Select(1, 0)
	}
}

// viewHostDetails shows detailed information for selected host
func (d *Dashboard) viewHostDetails() {
	row, _ := d.hostsTable.GetSelection()
	if row <= 0 { // Skip header
		return
	}

	hostCell := d.hostsTable.GetCell(row, 0)
	if hostCell == nil {
		return
	}

	hostIP := hostCell.Text
	if correlation, exists := d.correlator.GetCorrelationForHost(hostIP); exists {
		d.showHostDetailsModal(hostIP, correlation)
	}
}

// showHostDetailsModal displays a summary modal for the selected host.
func (d *Dashboard) showHostDetailsModal(hostIP string, corr *correlation.CorrelationResult) {
	var details strings.Builder

	details.WriteString(fmt.Sprintf("[yellow]Host: %s[::-]\n\n", hostIP))

	cat := hostCategory(corr)
	vendor := hostVendor(corr)
	hostname := hostHostname(corr)

	details.WriteString(fmt.Sprintf("Category: [%s]%s[::-]\n", categoryTviewColor(cat), cat))
	details.WriteString(fmt.Sprintf("Vendor:   [white]%s[::-]\n", vendor))
	details.WriteString(fmt.Sprintf("Hostname: [white]%s[::-]\n", hostname))
	details.WriteString(fmt.Sprintf("Services: [white]%d[::-]\n", len(corr.Services)))

	if corr.HostInfo != nil {
		mac := corr.HostInfo.MACAddress
		if mac == "" {
			mac = "-"
		}
		details.WriteString(fmt.Sprintf("MAC:      [white]%s[::-]\n", mac))
		osStr := corr.HostInfo.OSDetails
		if osStr == "" {
			osStr = corr.HostInfo.OS
		}
		if osStr == "" {
			osStr = "-"
		}
		details.WriteString(fmt.Sprintf("OS:       [white]%s[::-]\n", osStr))
	}

	details.WriteString("\n[yellow]Recent Scans:[::-]\n")
	for _, event := range corr.Timeline {
		details.WriteString(fmt.Sprintf("• %s - %s\n",
			event.Timestamp.Format("15:04"), event.Description))
	}

	modal := tview.NewModal().
		SetText(details.String()).
		AddButtons([]string{"View Inventory", "Close"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			d.pages.RemovePage("host-details")
			if buttonLabel == "View Inventory" {
				ShowCorrelationViewer(d.app, d.pages, d.correlator, func() {
					d.app.SetFocus(d.hostsTable)
				})
			}
		})

	d.pages.AddPage("host-details", modal, true, true)
}

// refresh updates all dashboard data
func (d *Dashboard) refresh() {
	d.app.QueueUpdateDraw(func() {
		d.updateDashboard()
	})
}

// startRefreshTimer starts automatic refresh
func (d *Dashboard) startRefreshTimer() {
	d.refreshTicker = time.NewTicker(5 * time.Second)
	go func() {
		for {
			select {
			case <-d.refreshTicker.C:
				d.refresh()
			case <-d.stopChan:
				return
			}
		}
	}()
}

// Close closes the dashboard
func (d *Dashboard) Close() {
	if d.refreshTicker != nil {
		d.refreshTicker.Stop()
		d.refreshTicker = nil
	}
	select {
	case <-d.stopChan:
		return
	default:
	}
	close(d.stopChan)
	d.pages.RemovePage("dashboard")
	if d.returnToMainCallback != nil {
		d.returnToMainCallback()
	}
}

// showInfo displays an info message
func (d *Dashboard) showInfo(message string) {
	modal := tview.NewModal().
		SetText(message).
		AddButtons([]string{"OK"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			d.pages.RemovePage("info")
		})

	d.pages.AddPage("info", modal, true, true)
}

// formatJobDuration formats a duration for the activity panel display.
func formatJobDuration(d time.Duration) string {
	if d == 0 {
		return "-"
	}
	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	}
	return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
}

// ShowDashboard creates and displays a dashboard page.
// For the main TUI use showDashboard() which passes a proper returnToMain callback.
func ShowDashboard(app *tview.Application, pages *tview.Pages, jobManager *jobs.JobManager,
	correlator *correlation.Correlator, workflowEngine *workflow.WorkflowEngine) {

	dashboard := NewDashboard(app, pages, jobManager, correlator, workflowEngine, nil)
	pages.AddPage("dashboard", dashboard, true, true)
	app.SetFocus(dashboard.hostsTable)
}
