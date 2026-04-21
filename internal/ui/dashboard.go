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

// Dashboard displays overview statistics and security posture.
type Dashboard struct {
	*tview.Flex
	app            *tview.Application
	pages          *tview.Pages
	jobManager     *jobs.JobManager
	correlator     *correlation.Correlator
	workflowEngine *workflow.WorkflowEngine

	// UI components
	statsPanel       *tview.TextView
	riskPanel        *tview.TextView
	topFindingsTable *tview.Table
	servicesPanel    *tview.TextView
	alertsPanel      *tview.TextView
	chartsPanel      *tview.TextView
	controlsText     *tview.TextView

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
	// Top row panels
	d.statsPanel = tview.NewTextView().SetDynamicColors(true)
	d.statsPanel.SetBorder(true).SetTitle("Discovery Stats")

	d.chartsPanel = tview.NewTextView().SetDynamicColors(true)
	d.chartsPanel.SetBorder(true).SetTitle("Category Breakdown")

	d.alertsPanel = tview.NewTextView().SetDynamicColors(true).SetScrollable(true)
	d.alertsPanel.SetBorder(true).SetTitle("Job Activity")

	// Middle row panels — security/risk row
	d.riskPanel = tview.NewTextView().SetDynamicColors(true)
	d.riskPanel.SetBorder(true).SetTitle("Risk Overview")

	d.topFindingsTable = tview.NewTable().SetBorders(true).SetSelectable(true, false)
	d.topFindingsTable.SetBorder(true).SetTitle("Top Findings")

	d.servicesPanel = tview.NewTextView().SetDynamicColors(true)
	d.servicesPanel.SetBorder(true).SetTitle("Service Landscape")

	// Controls panel
	d.controlsText = tview.NewTextView().SetDynamicColors(true)
	d.controlsText.SetBorder(true).SetTitle("Controls")
	d.controlsText.SetText(`[yellow]Dashboard:[::-] [white]Enter[::-]=Risk Details  [white]q[::-]=Close  [yellow]Global:[::-] [white]Ctrl+J[::-]=Jobs  [white]Ctrl+N[::-]=Hosts  [white]Ctrl+Z[::-]=Main`)

	// Layout: top row (Discovery Stats | Category Breakdown | Job Activity)
	topRow := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(d.statsPanel, 0, 2, false).
		AddItem(d.chartsPanel, 0, 3, false).
		AddItem(d.alertsPanel, 0, 2, false)

	// Middle row (Risk Overview | Top Findings | Service Landscape)
	middleRow := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(d.riskPanel, 0, 1, false).
		AddItem(d.topFindingsTable, 0, 3, true).
		AddItem(d.servicesPanel, 0, 1, false)

	bottomRow := d.controlsText

	d.SetDirection(tview.FlexRow).
		AddItem(topRow, 0, 2, false).
		AddItem(middleRow, 0, 2, false).
		AddItem(bottomRow, 3, 0, false)

	d.setupKeyBindings()
	d.updateDashboard()
}

// setupKeyBindings configures keyboard shortcuts
func (d *Dashboard) setupKeyBindings() {
	d.topFindingsTable.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEscape:
			d.Close()
			return nil
		case tcell.KeyEnter:
			d.viewSelectedFinding()
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
	d.updateRiskPanel(correlations)
	d.updateTopFindings(correlations)
	d.updateServicesPanel(correlations)
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

// riskTiers defines risk score thresholds and display properties.
var riskTiers = []struct {
	minScore   int
	label      string
	tviewColor string
	tcellColor tcell.Color
}{
	{700, "Critical", "red", tcell.ColorRed},
	{500, "High", "orange", tcell.ColorOrange},
	{200, "Medium", "yellow", tcell.ColorYellow},
	{0, "Low", "green", tcell.ColorGreen},
}

// updateRiskPanel renders aggregate risk posture across all correlated hosts.
func (d *Dashboard) updateRiskPanel(correlations map[string]*correlation.CorrelationResult) {
	var content strings.Builder

	if len(correlations) == 0 {
		content.WriteString("[gray]No hosts discovered yet.[::-]\n")
		d.riskPanel.SetText(content.String())
		return
	}

	// Bucket hosts by risk tier.
	tierCounts := make(map[string]int)
	var totalScore int
	var highestIP string
	var highestScore int
	severityCounts := make(map[string]int)

	for ip, corr := range correlations {
		totalScore += corr.RiskScore
		if corr.RiskScore > highestScore {
			highestScore = corr.RiskScore
			highestIP = ip
		}
		for _, tier := range riskTiers {
			if corr.RiskScore >= tier.minScore {
				tierCounts[tier.label]++
				break
			}
		}
		for _, vuln := range corr.Vulnerabilities {
			severityCounts[strings.ToLower(vuln.Severity)]++
		}
	}

	content.WriteString("[yellow]Risk Distribution[::-]\n")
	for _, tier := range riskTiers {
		count := tierCounts[tier.label]
		content.WriteString(fmt.Sprintf("  [%s]■ %-9s %d hosts[::-]\n", tier.tviewColor, tier.label, count))
	}

	content.WriteString("\n[yellow]Severity Summary[::-]\n")
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if count := severityCounts[sev]; count > 0 {
			content.WriteString(fmt.Sprintf("  [%s]%-10s %d[::-]\n", severityTviewColor(sev), titleCase(sev)+":", count))
		}
	}

	avgScore := totalScore / len(correlations)
	content.WriteString(fmt.Sprintf("\nAverage Score: [white]%d[::-]\n", avgScore))
	if highestIP != "" {
		content.WriteString(fmt.Sprintf("Highest: [white]%s[::-] ([red]%d[::-])\n", highestIP, highestScore))
	}

	d.riskPanel.SetText(content.String())
}

// updateTopFindings renders the top-risk hosts as a selectable table.
func (d *Dashboard) updateTopFindings(correlations map[string]*correlation.CorrelationResult) {
	d.topFindingsTable.Clear()

	headers := []string{"", "IP", "Score", "Critical Finding"}
	for i, header := range headers {
		d.topFindingsTable.SetCell(0, i, tview.NewTableCell(header).
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
		return entries[i].result.RiskScore > entries[j].result.RiskScore
	})

	if len(entries) == 0 {
		d.topFindingsTable.SetCell(1, 0,
			tview.NewTableCell("No hosts discovered yet — run Network Discovery to populate.").
				SetTextColor(tcell.ColorGray).
				SetAlign(tview.AlignCenter).
				SetSelectable(false).
				SetExpansion(5))
		return
	}

	maxRows := 10
	if len(entries) < maxRows {
		maxRows = len(entries)
	}

	for i := 0; i < maxRows; i++ {
		row := i + 1
		e := entries[i]
		score := e.result.RiskScore

		// Determine risk tier color
		var tierColor tcell.Color
		for _, tier := range riskTiers {
			if score >= tier.minScore {
				tierColor = tier.tcellColor
				break
			}
		}

		// Top finding: first critical/high vulnerability title, or service summary
		finding := topFindingText(e.result)

		d.topFindingsTable.SetCell(row, 0, tview.NewTableCell("■").SetTextColor(tierColor).SetAlign(tview.AlignCenter))
		d.topFindingsTable.SetCell(row, 1, tview.NewTableCell(e.ip))
		d.topFindingsTable.SetCell(row, 2, tview.NewTableCell(fmt.Sprintf("%d", score)).SetTextColor(tierColor).SetAlign(tview.AlignCenter))
		d.topFindingsTable.SetCell(row, 3, tview.NewTableCell(finding))
	}

	if d.topFindingsTable.GetRowCount() > 1 {
		d.topFindingsTable.Select(1, 0)
	}
}

// updateServicesPanel renders service and port distribution across all hosts.
func (d *Dashboard) updateServicesPanel(correlations map[string]*correlation.CorrelationResult) {
	var content strings.Builder

	if len(correlations) == 0 {
		content.WriteString("[gray]No hosts discovered yet.[::-]\n")
		d.servicesPanel.SetText(content.String())
		return
	}

	// Count services by name
	serviceCounts := make(map[string]int)
	portSet := make(map[int]bool)
	maxPortHost := ""
	maxPortCount := 0

	for ip, corr := range correlations {
		seen := make(map[string]bool)
		for _, svc := range corr.Services {
			name := svc.Name
			if name == "" {
				name = fmt.Sprintf("port-%d", svc.Port)
			}
			if !seen[name] {
				serviceCounts[name]++
				seen[name] = true
			}
			portSet[svc.Port] = true
		}
		if len(corr.Services) > maxPortCount {
			maxPortCount = len(corr.Services)
			maxPortHost = ip
		}
	}

	// Sort services by count descending
	type svcEntry struct {
		name  string
		count int
	}
	var svcs []svcEntry
	for name, count := range serviceCounts {
		svcs = append(svcs, svcEntry{name, count})
	}
	sort.Slice(svcs, func(i, j int) bool {
		return svcs[i].count > svcs[j].count
	})

	content.WriteString("[yellow]Top Services[::-]\n")
	maxShow := 8
	if len(svcs) < maxShow {
		maxShow = len(svcs)
	}
	for i := 0; i < maxShow; i++ {
		s := svcs[i]
		content.WriteString(fmt.Sprintf("  [white]%-12s[::-] [green]%d[::-] hosts\n", s.name, s.count))
	}

	content.WriteString("\n[yellow]Ports[::-]\n")
	content.WriteString(fmt.Sprintf("  Unique open: [white]%d[::-]\n", len(portSet)))
	if maxPortHost != "" {
		content.WriteString(fmt.Sprintf("  Most exposed: [white]%s[::-] ([red]%d[::-])\n", maxPortHost, maxPortCount))
	}

	d.servicesPanel.SetText(content.String())
}

// viewSelectedFinding opens the host detail modal for the selected row.
func (d *Dashboard) viewSelectedFinding() {
	row, _ := d.topFindingsTable.GetSelection()
	if row <= 0 {
		return
	}

	hostCell := d.topFindingsTable.GetCell(row, 1)
	if hostCell == nil {
		return
	}

	hostIP := hostCell.Text
	if corr, exists := d.correlator.GetCorrelationForHost(hostIP); exists {
		d.showHostDetailsModal(hostIP, corr)
	}
}

// topFindingText returns the most notable finding for a host.
func topFindingText(corr *correlation.CorrelationResult) string {
	// Prefer the first critical/high vulnerability title
	for _, sev := range []string{"critical", "high"} {
		for _, vuln := range corr.Vulnerabilities {
			if strings.ToLower(vuln.Severity) == sev {
				title := vuln.Title
				if len([]rune(title)) > 35 {
					title = string([]rune(title)[:34]) + "…"
				}
				return title
			}
		}
	}

	// Count severity buckets for summary
	var medCount int
	for _, vuln := range corr.Vulnerabilities {
		if strings.ToLower(vuln.Severity) == "medium" {
			medCount++
		}
	}
	if medCount > 0 {
		return fmt.Sprintf("%d medium-severity vulns", medCount)
	}

	// Fall back to port/service exposure summary
	if len(corr.Services) > 0 {
		return fmt.Sprintf("%d open ports", len(corr.Services))
	}

	return "-"
}

// severityTviewColor returns a tview color tag for a vulnerability severity level.
func severityTviewColor(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "red"
	case "high":
		return "orange"
	case "medium":
		return "yellow"
	case "low":
		return "green"
	default:
		return "gray"
	}
}

// titleCase capitalizes the first letter of a string.
func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
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

	// Screenshot count
	screenshots := correlation.GetScreenshotsForHost(corr)
	if len(screenshots) > 0 {
		details.WriteString(fmt.Sprintf("Screenshots: [white]%d[::-]\n", len(screenshots)))
	}

	// Risk score
	details.WriteString(fmt.Sprintf("Risk Score: [white]%d[::-]\n", corr.RiskScore))

	// Vulnerability summary
	if len(corr.Vulnerabilities) > 0 {
		severityCounts := make(map[string]int)
		for _, vuln := range corr.Vulnerabilities {
			severityCounts[strings.ToLower(vuln.Severity)]++
		}
		details.WriteString("[yellow]Vulnerabilities:[::-]\n")
		for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
			if count := severityCounts[sev]; count > 0 {
				details.WriteString(fmt.Sprintf("  [%s]%s: %d[::-]\n", severityTviewColor(sev), titleCase(sev), count))
			}
		}
	}

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
		AddButtons([]string{"View Inventory", "View Screenshot", "Close"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			d.pages.RemovePage("host-details")
			switch buttonLabel {
			case "View Inventory":
				ShowCorrelationViewer(d.app, d.pages, d.correlator, func() {
					d.app.SetFocus(d.topFindingsTable)
				}, "")
			case "View Screenshot":
				ShowCorrelationViewer(d.app, d.pages, d.correlator, func() {
					d.app.SetFocus(d.topFindingsTable)
				}, hostIP)
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
	app.SetFocus(dashboard.topFindingsTable)
}
