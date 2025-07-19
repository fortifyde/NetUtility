package ui

import (
	"fmt"
	"sort"
	"strconv"
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
	refreshTicker *time.Ticker
	stopChan      chan struct{}
}

// DashboardStats contains aggregated statistics
type DashboardStats struct {
	TotalHosts           int
	ActiveHosts          int
	TotalServices        int
	TotalVulnerabilities int
	CriticalVulns        int
	HighRiskHosts        int
	RunningJobs          int
	CompletedJobs        int
	FailedJobs           int
	ActiveWorkflows      int
	AverageRiskScore     float64
	LastScanTime         time.Time
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
	correlator *correlation.Correlator, workflowEngine *workflow.WorkflowEngine) *Dashboard {

	d := &Dashboard{
		Flex:           tview.NewFlex(),
		app:            app,
		pages:          pages,
		jobManager:     jobManager,
		correlator:     correlator,
		workflowEngine: workflowEngine,
		stopChan:       make(chan struct{}),
	}

	d.setupUI()
	d.startRefreshTimer()
	return d
}

// setupUI initializes the dashboard interface
func (d *Dashboard) setupUI() {
	// Create stats panel
	d.statsPanel = tview.NewTextView().SetDynamicColors(true)
	d.statsPanel.SetBorder(true).SetTitle("System Statistics")

	// Create activity list
	d.activityList = tview.NewList()
	d.activityList.SetBorder(true).SetTitle("Recent Activity")

	// Create hosts table
	d.hostsTable = tview.NewTable().SetBorders(true).SetSelectable(true, false)
	d.hostsTable.SetBorder(true).SetTitle("Top Risk Hosts")

	// Create alerts panel
	d.alertsPanel = tview.NewTextView().SetDynamicColors(true).SetScrollable(true)
	d.alertsPanel.SetBorder(true).SetTitle("Security Alerts")

	// Create charts panel (ASCII charts)
	d.chartsPanel = tview.NewTextView().SetDynamicColors(true)
	d.chartsPanel.SetBorder(true).SetTitle("Risk Distribution")

	// Create controls panel
	d.controlsText = tview.NewTextView().SetDynamicColors(true)
	d.controlsText.SetBorder(true).SetTitle("Controls")
	d.controlsText.SetText(`[yellow]Dashboard Controls:[::-]
[white]r[::-]        Refresh all data
[white]j[::-]        View job manager
[white]c[::-]        View correlations
[white]w[::-]        View workflows
[white]Enter[::-]    View host details
[white]q[::-]        Close dashboard`)

	// Layout: 3x2 grid
	topRow := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(d.statsPanel, 0, 1, false).
		AddItem(d.chartsPanel, 0, 1, false).
		AddItem(d.alertsPanel, 0, 1, false)

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
			case 'r':
				d.refresh()
				return nil
			case 'j':
				ShowJobsViewer(d.app, d.pages, d.jobManager)
				return nil
			case 'c':
				ShowCorrelationViewer(d.app, d.pages, d.correlator)
				return nil
			case 'w':
				d.showWorkflows()
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
			case 'r':
				d.refresh()
				return nil
			}
		}
		return event
	})
}

// updateDashboard refreshes all dashboard components
func (d *Dashboard) updateDashboard() {
	stats := d.calculateStats()

	d.updateStatsPanel(stats)
	d.updateChartsPanel(stats)
	d.updateAlertsPanel(stats)
	d.updateActivityList()
	d.updateHostsTable()
}

// calculateStats calculates dashboard statistics
func (d *Dashboard) calculateStats() DashboardStats {
	stats := DashboardStats{}

	// Job statistics
	jobStats := d.jobManager.GetStats()
	stats.RunningJobs = jobStats.RunningJobs
	stats.CompletedJobs = jobStats.CompletedJobs
	stats.FailedJobs = jobStats.FailedJobs

	// Correlation statistics
	correlations := d.correlator.GetAllCorrelations()
	stats.TotalHosts = len(correlations)

	var totalRiskScore int
	for _, correlation := range correlations {
		if correlation.HostInfo != nil && correlation.HostInfo.Status == "up" {
			stats.ActiveHosts++
		}
		stats.TotalServices += len(correlation.Services)
		stats.TotalVulnerabilities += len(correlation.Vulnerabilities)

		for _, vuln := range correlation.Vulnerabilities {
			if strings.ToLower(vuln.Severity) == "critical" {
				stats.CriticalVulns++
			}
		}

		if correlation.RiskScore >= 500 {
			stats.HighRiskHosts++
		}

		totalRiskScore += correlation.RiskScore

		// Find last scan time
		if len(correlation.Timeline) > 0 {
			lastEvent := correlation.Timeline[len(correlation.Timeline)-1]
			if lastEvent.Timestamp.After(stats.LastScanTime) {
				stats.LastScanTime = lastEvent.Timestamp
			}
		}
	}

	if stats.TotalHosts > 0 {
		stats.AverageRiskScore = float64(totalRiskScore) / float64(stats.TotalHosts)
	}

	// Workflow statistics
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

// updateStatsPanel updates the statistics panel
func (d *Dashboard) updateStatsPanel(stats DashboardStats) {
	var content strings.Builder

	content.WriteString("[yellow]Network Overview[::-]\n")
	content.WriteString(fmt.Sprintf("Total Hosts: [white]%d[::-]\n", stats.TotalHosts))
	content.WriteString(fmt.Sprintf("Active Hosts: [green]%d[::-]\n", stats.ActiveHosts))
	content.WriteString(fmt.Sprintf("Services: [white]%d[::-]\n", stats.TotalServices))
	content.WriteString("\n")

	content.WriteString("[yellow]Security Status[::-]\n")
	content.WriteString(fmt.Sprintf("Vulnerabilities: [white]%d[::-]\n", stats.TotalVulnerabilities))
	content.WriteString(fmt.Sprintf("Critical: [red]%d[::-]\n", stats.CriticalVulns))
	content.WriteString(fmt.Sprintf("High Risk Hosts: [orange]%d[::-]\n", stats.HighRiskHosts))
	content.WriteString(fmt.Sprintf("Avg Risk Score: [white]%.1f[::-]\n", stats.AverageRiskScore))
	content.WriteString("\n")

	content.WriteString("[yellow]Activity[::-]\n")
	content.WriteString(fmt.Sprintf("Running Jobs: [green]%d[::-]\n", stats.RunningJobs))
	content.WriteString(fmt.Sprintf("Completed: [blue]%d[::-]\n", stats.CompletedJobs))
	content.WriteString(fmt.Sprintf("Failed: [red]%d[::-]\n", stats.FailedJobs))
	content.WriteString(fmt.Sprintf("Active Workflows: [yellow]%d[::-]\n", stats.ActiveWorkflows))
	content.WriteString("\n")

	if !stats.LastScanTime.IsZero() {
		content.WriteString(fmt.Sprintf("Last Scan: [white]%s[::-]\n",
			stats.LastScanTime.Format("15:04:05")))
	}

	d.statsPanel.SetText(content.String())
}

// updateChartsPanel updates the charts panel with ASCII visualizations
func (d *Dashboard) updateChartsPanel(stats DashboardStats) {
	var content strings.Builder

	content.WriteString("[yellow]Risk Level Distribution[::-]\n\n")

	// Get risk distribution
	riskBuckets := map[string]int{
		"Critical": 0,
		"High":     0,
		"Medium":   0,
		"Low":      0,
		"None":     0,
	}

	correlations := d.correlator.GetAllCorrelations()
	for _, correlation := range correlations {
		switch {
		case correlation.RiskScore >= 750:
			riskBuckets["Critical"]++
		case correlation.RiskScore >= 500:
			riskBuckets["High"]++
		case correlation.RiskScore >= 250:
			riskBuckets["Medium"]++
		case correlation.RiskScore >= 100:
			riskBuckets["Low"]++
		default:
			riskBuckets["None"]++
		}
	}

	// Create simple ASCII bar chart
	maxCount := 0
	for _, count := range riskBuckets {
		if count > maxCount {
			maxCount = count
		}
	}

	if maxCount > 0 {
		// Risk levels in order
		levels := []string{"Critical", "High", "Medium", "Low", "None"}
		colors := []string{"red", "orange", "yellow", "green", "gray"}

		for i, level := range levels {
			count := riskBuckets[level]
			barLength := 0
			if maxCount > 0 {
				barLength = (count * 20) / maxCount
			}

			bar := strings.Repeat("█", barLength)
			content.WriteString(fmt.Sprintf("[%s]%-8s[::-] [%s]%s[::-] [white]%d[::-]\n",
				colors[i], level, colors[i], bar, count))
		}
	} else {
		content.WriteString("No risk data available\n")
	}

	content.WriteString("\n[yellow]Vulnerability Trends[::-]\n")
	content.WriteString(fmt.Sprintf("Critical: [red]%d[::-] | ", stats.CriticalVulns))
	content.WriteString(fmt.Sprintf("Total: [white]%d[::-]\n", stats.TotalVulnerabilities))

	// Simple trend indicator
	if stats.CriticalVulns > 0 {
		content.WriteString("[red]⚠ Critical vulnerabilities detected[::-]\n")
	} else if stats.TotalVulnerabilities > 10 {
		content.WriteString("[yellow]⚡ Multiple vulnerabilities found[::-]\n")
	} else {
		content.WriteString("[green]✓ Low vulnerability count[::-]\n")
	}

	d.chartsPanel.SetText(content.String())
}

// updateAlertsPanel updates the security alerts panel
func (d *Dashboard) updateAlertsPanel(stats DashboardStats) {
	var content strings.Builder

	content.WriteString("[yellow]Security Alerts[::-]\n\n")

	alertCount := 0

	// Check for critical vulnerabilities
	if stats.CriticalVulns > 0 {
		content.WriteString(fmt.Sprintf("[red]🔥 CRITICAL[::-] %d critical vulnerabilities detected\n", stats.CriticalVulns))
		alertCount++
	}

	// Check for high-risk hosts
	if stats.HighRiskHosts > 0 {
		content.WriteString(fmt.Sprintf("[orange]⚠ HIGH RISK[::-] %d hosts with risk score ≥500\n", stats.HighRiskHosts))
		alertCount++
	}

	// Check for failed jobs
	if stats.FailedJobs > 0 {
		content.WriteString(fmt.Sprintf("[red]❌ JOBS[::-] %d jobs failed\n", stats.FailedJobs))
		alertCount++
	}

	// Check for stale data
	if !stats.LastScanTime.IsZero() && time.Since(stats.LastScanTime) > 24*time.Hour {
		content.WriteString("[yellow]⏰ STALE[::-] Last scan >24h ago\n")
		alertCount++
	}

	// Check for unusual activity
	if stats.TotalHosts > 100 {
		content.WriteString("[blue]📊 INFO[::-] Large network detected\n")
		alertCount++
	}

	if alertCount == 0 {
		content.WriteString("[green]✅ No active alerts[::-]\n")
		content.WriteString("\nSystem status: [green]Normal[::-]\n")
	} else {
		content.WriteString(fmt.Sprintf("\n[white]Total alerts: %d[::-]", alertCount))
	}

	d.alertsPanel.SetText(content.String())
}

// updateActivityList updates the recent activity list
func (d *Dashboard) updateActivityList() {
	d.activityList.Clear()

	activities := d.getRecentActivities()

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
func (d *Dashboard) getRecentActivities() []ActivityItem {
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
	correlations := d.correlator.GetAllCorrelations()
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

// updateHostsTable updates the top risk hosts table
func (d *Dashboard) updateHostsTable() {
	d.hostsTable.Clear()

	// Set headers
	headers := []string{"Host", "Risk", "Vulns", "Services", "Status"}
	for i, header := range headers {
		d.hostsTable.SetCell(0, i, tview.NewTableCell(header).
			SetTextColor(tcell.ColorYellow).
			SetAlign(tview.AlignCenter).
			SetSelectable(false))
	}

	// Get correlations and sort by risk score
	correlations := d.correlator.GetAllCorrelations()

	type hostRisk struct {
		host   string
		result *correlation.CorrelationResult
	}

	var hosts []hostRisk
	for host, result := range correlations {
		hosts = append(hosts, hostRisk{host, result})
	}

	sort.Slice(hosts, func(i, j int) bool {
		return hosts[i].result.RiskScore > hosts[j].result.RiskScore
	})

	// Show top 10 hosts
	maxHosts := 10
	if len(hosts) < maxHosts {
		maxHosts = len(hosts)
	}

	for i := 0; i < maxHosts; i++ {
		row := i + 1
		host := hosts[i]
		result := host.result

		hostIP := host.host
		riskScore := strconv.Itoa(result.RiskScore)
		vulnCount := strconv.Itoa(len(result.Vulnerabilities))
		serviceCount := strconv.Itoa(len(result.Services))

		status := "Unknown"
		if result.HostInfo != nil {
			status = result.HostInfo.Status
		}

		// Color coding for risk score
		riskColor := tcell.ColorGreen
		if result.RiskScore >= 750 {
			riskColor = tcell.ColorRed
		} else if result.RiskScore >= 500 {
			riskColor = tcell.ColorOrange
		} else if result.RiskScore >= 250 {
			riskColor = tcell.ColorYellow
		}

		d.hostsTable.SetCell(row, 0, tview.NewTableCell(hostIP))
		d.hostsTable.SetCell(row, 1, tview.NewTableCell(riskScore).SetTextColor(riskColor))
		d.hostsTable.SetCell(row, 2, tview.NewTableCell(vulnCount))
		d.hostsTable.SetCell(row, 3, tview.NewTableCell(serviceCount))
		d.hostsTable.SetCell(row, 4, tview.NewTableCell(status))
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

// showHostDetailsModal displays detailed host information
func (d *Dashboard) showHostDetailsModal(hostIP string, correlation *correlation.CorrelationResult) {
	var details strings.Builder

	details.WriteString(fmt.Sprintf("[yellow]Host: %s[::-]\n\n", hostIP))
	details.WriteString(fmt.Sprintf("Risk Score: [white]%d[::-]\n", correlation.RiskScore))
	details.WriteString(fmt.Sprintf("Services: [white]%d[::-]\n", len(correlation.Services)))
	details.WriteString(fmt.Sprintf("Vulnerabilities: [white]%d[::-]\n", len(correlation.Vulnerabilities)))

	if correlation.HostInfo != nil {
		details.WriteString(fmt.Sprintf("Status: [white]%s[::-]\n", correlation.HostInfo.Status))
		if correlation.HostInfo.OS != "" {
			details.WriteString(fmt.Sprintf("OS: [white]%s[::-]\n", correlation.HostInfo.OS))
		}
	}

	details.WriteString("\n[yellow]Recent Scans:[::-]\n")
	for _, event := range correlation.Timeline {
		details.WriteString(fmt.Sprintf("• %s - %s\n",
			event.Timestamp.Format("15:04"), event.Description))
	}

	modal := tview.NewModal().
		SetText(details.String()).
		AddButtons([]string{"View Correlation", "Close"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			d.pages.RemovePage("host-details")
			if buttonLabel == "View Correlation" {
				ShowCorrelationViewer(d.app, d.pages, d.correlator)
			}
		})

	d.pages.AddPage("host-details", modal, true, true)
}

// showWorkflows shows workflow information
func (d *Dashboard) showWorkflows() {
	if d.workflowEngine == nil {
		d.showInfo("Workflow engine not available")
		return
	}

	d.showInfo("Workflow viewer not yet implemented")
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
	}
	close(d.stopChan)
	d.pages.RemovePage("dashboard")
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

// Helper function to create a dashboard page
func ShowDashboard(app *tview.Application, pages *tview.Pages, jobManager *jobs.JobManager,
	correlator *correlation.Correlator, workflowEngine *workflow.WorkflowEngine) {

	dashboard := NewDashboard(app, pages, jobManager, correlator, workflowEngine)
	pages.AddPage("dashboard", dashboard, true, true)
	app.SetFocus(dashboard.hostsTable)
}
