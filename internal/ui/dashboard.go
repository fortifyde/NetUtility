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
	str            *Strings

	// UI components
	statsPanel       *tview.TextView
	riskPanel        *tview.TextView
	topFindingsTable *tview.Table
	servicesPanel    *tview.TextView
	alertsPanel      *tview.TextView
	chartsPanel      *tview.TextView
	controlsText     *tview.TextView

	// State
	selectedHostIP       string
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
	correlator *correlation.Correlator, workflowEngine *workflow.WorkflowEngine, returnToMainCallback func(), str *Strings) *Dashboard {

	d := &Dashboard{
		Flex:                 tview.NewFlex(),
		app:                  app,
		pages:                pages,
		jobManager:           jobManager,
		correlator:           correlator,
		workflowEngine:       workflowEngine,
		stopChan:             make(chan struct{}),
		returnToMainCallback: returnToMainCallback,
		str:                  str,
	}

	d.setupUI()
	d.startRefreshTimer()
	return d
}

// setupUI initializes the dashboard interface
func (d *Dashboard) setupUI() {
	// Top row panels
	d.statsPanel = tview.NewTextView().SetDynamicColors(true)
	d.statsPanel.SetBorder(true).SetTitle(d.str.PaneTitleDiscoveryStats)

	d.chartsPanel = tview.NewTextView().SetDynamicColors(true)
	d.chartsPanel.SetBorder(true).SetTitle(d.str.PaneTitleCategoryBreakdown)

	d.alertsPanel = tview.NewTextView().SetDynamicColors(true).SetScrollable(true)
	d.alertsPanel.SetBorder(true).SetTitle(d.str.PaneTitleJobActivity)

	// Middle row panels — security/risk row
	d.riskPanel = tview.NewTextView().SetDynamicColors(true)
	d.riskPanel.SetBorder(true).SetTitle(d.str.PaneTitleRiskOverview)

	d.topFindingsTable = tview.NewTable().SetBorders(true).SetSelectable(true, false)
	d.topFindingsTable.SetBorder(true).SetTitle(d.str.PaneTitleHostRisk)

	d.servicesPanel = tview.NewTextView().SetDynamicColors(true)
	d.servicesPanel.SetBorder(true).SetTitle(d.str.PaneTitleServiceLandscape)

	// Controls panel
	d.controlsText = tview.NewTextView().SetDynamicColors(true)
	d.controlsText.SetBorder(true).SetTitle(d.str.PaneTitleDashControls)
	d.controlsText.SetText(d.str.DashControlsText)

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
	content.WriteString(fmt.Sprintf(d.str.FmtDashStatsHostsDiscovered, stats.TotalHosts))
	content.WriteString(fmt.Sprintf(d.str.FmtDashStatsWindows, stats.HostsByCategory["windows"]))
	content.WriteString(fmt.Sprintf(d.str.FmtDashStatsLinux, stats.HostsByCategory["linux"]))
	content.WriteString(fmt.Sprintf(d.str.FmtDashStatsNetDevices, stats.HostsByCategory["network_device"]))
	content.WriteString(fmt.Sprintf(d.str.FmtDashStatsUnknown, stats.HostsByCategory["unknown"]))
	content.WriteString("\n")
	content.WriteString(fmt.Sprintf(d.str.FmtDashStatsServices, stats.TotalServices))
	content.WriteString("\n")
	content.WriteString(d.str.DashJobsHeading)
	content.WriteString(fmt.Sprintf(d.str.FmtDashJobsRunning, stats.RunningJobs, stats.MaxConcurrent))
	content.WriteString(fmt.Sprintf(d.str.FmtDashJobsCompleted, stats.CompletedJobs))
	content.WriteString(fmt.Sprintf(d.str.FmtDashJobsFailed, stats.FailedJobs))
	if !stats.LastScanTime.IsZero() {
		content.WriteString(fmt.Sprintf(d.str.FmtDashLastScan, stats.LastScanTime.Format("15:04")))
	}
	d.statsPanel.SetText(content.String())
}

// updateChartsPanel renders a category breakdown bar chart.
func (d *Dashboard) updateChartsPanel(stats DashboardStats) {
	var content strings.Builder

	categories := []string{"windows", "linux", "network_device", "unknown"}
	maxCount := 0
	for _, cat := range categories {
		if n := stats.HostsByCategory[cat]; n > maxCount {
			maxCount = n
		}
	}

	if maxCount == 0 {
		content.WriteString(d.str.DashNoChartYet)
	} else {
		const barWidth = 15
		for _, cat := range categories {
			count := stats.HostsByCategory[cat]
			filled := count * barWidth / maxCount
			if filled > barWidth {
				filled = barWidth
			}
			bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
			color := categoryTviewColor(cat)
			label := d.str.CategoryDisplayLabel(cat)
			content.WriteString(fmt.Sprintf(d.str.FmtDashCategoryBar, color, label, color, bar, count))
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
		content.WriteString(d.str.DashNoActivityYet)
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
		content.WriteString(d.str.DashNoHostsDiscovered)
		d.riskPanel.SetText(content.String())
		return
	}

	// Bucket hosts by risk tier.
	tierCounts := make(map[string]int)
	var totalScore int
	var highestIP string
	var highestScore int
	severityCounts := make(map[string]int)
	var niktoCount, sslCount int

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
			switch vuln.Source {
			case "nikto":
				niktoCount++
			case "sslscan":
				sslCount++
			}
		}
	}

	content.WriteString(d.str.DashRiskDistHeading)
	for _, tier := range riskTiers {
		count := tierCounts[tier.label]
		content.WriteString(fmt.Sprintf(d.str.FmtDashRiskTierLine, tier.tviewColor, d.str.RiskLabel(tier.label), count))
	}

	content.WriteString(d.str.DashSevSummaryHeading)
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if count := severityCounts[sev]; count > 0 {
			content.WriteString(fmt.Sprintf("  [%s]%-10s %d[::-]\n", severityTviewColor(sev), d.str.SeverityLabel(sev)+":", count))
		}
	}

	// Source breakdown
	if niktoCount > 0 || sslCount > 0 {
		content.WriteString(d.str.DashBySourceHeading)
		if niktoCount > 0 {
			content.WriteString(fmt.Sprintf(d.str.FmtDashNiktoFindings, niktoCount))
		}
		if sslCount > 0 {
			content.WriteString(fmt.Sprintf(d.str.FmtDashSSLIssues, sslCount))
		}
	}

	avgScore := totalScore / len(correlations)
	content.WriteString(fmt.Sprintf(d.str.FmtDashAvgScore, avgScore))
	if highestIP != "" {
		content.WriteString(fmt.Sprintf(d.str.FmtDashHighestRisk, highestIP, highestScore))
	}

	d.riskPanel.SetText(content.String())
}

// updateTopFindings renders all hosts in a scrollable risk table with stable selection.
func (d *Dashboard) updateTopFindings(correlations map[string]*correlation.CorrelationResult) {
	// Save current selection
	if row, _ := d.topFindingsTable.GetSelection(); row > 0 {
		if cell := d.topFindingsTable.GetCell(row, 1); cell != nil {
			d.selectedHostIP = cell.Text
		}
	}

	d.topFindingsTable.Clear()

	headers := []string{d.str.DashHeaderScore, d.str.DashHeaderIP, d.str.DashHeaderHostname, d.str.DashHeaderCategory, d.str.DashHeaderTopFinding}
	for i, header := range headers {
		cell := tview.NewTableCell(header).
			SetTextColor(tcell.ColorYellow).
			SetAlign(tview.AlignCenter).
			SetSelectable(false)
		if i == 4 {
			cell.SetExpansion(1)
		}
		d.topFindingsTable.SetCell(0, i, cell)
	}
	d.topFindingsTable.SetFixed(1, 0)

	type hostEntry struct {
		ip     string
		result *correlation.CorrelationResult
	}

	var entries []hostEntry
	for ip, result := range correlations {
		entries = append(entries, hostEntry{ip, result})
	}

	// Stable sort: score desc, IP asc tiebreaker
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].result.RiskScore != entries[j].result.RiskScore {
			return entries[i].result.RiskScore > entries[j].result.RiskScore
		}
		return compareIPs(entries[i].ip, entries[j].ip)
	})

	if len(entries) == 0 {
		d.topFindingsTable.SetCell(1, 0,
			tview.NewTableCell(d.str.DashNoHostsYet).
				SetTextColor(tcell.ColorGray).
				SetAlign(tview.AlignCenter).
				SetSelectable(false).
				SetExpansion(5))
		return
	}

	selectedRow := 1
	for i, e := range entries {
		row := i + 1
		score := e.result.RiskScore

		// Determine risk tier color
		var tierColor tcell.Color
		for _, tier := range riskTiers {
			if score >= tier.minScore {
				tierColor = tier.tcellColor
				break
			}
		}

		cat := hostCategory(e.result)
		hostname := hostHostname(e.result)
		if len([]rune(hostname)) > 20 {
			hostname = string([]rune(hostname)[:19]) + "…"
		}

		// Top finding with count suffix
		finding := d.topFindingText(e.result)
		totalVulns := len(e.result.Vulnerabilities)
		if totalVulns > 0 {
			finding = fmt.Sprintf(d.str.FmtFindingsCount, finding, totalVulns)
		}

		d.topFindingsTable.SetCell(row, 0, tview.NewTableCell(fmt.Sprintf("%d", score)).
			SetTextColor(tierColor).SetAlign(tview.AlignRight).SetMaxWidth(6))
		d.topFindingsTable.SetCell(row, 1, tview.NewTableCell(e.ip).SetMaxWidth(15))
		d.topFindingsTable.SetCell(row, 2, tview.NewTableCell(hostname).SetMaxWidth(20))
		d.topFindingsTable.SetCell(row, 3, tview.NewTableCell(cat).
			SetTextColor(tcell.Color(tcell.GetColor(categoryTviewColor(cat)))).SetMaxWidth(8))
		d.topFindingsTable.SetCell(row, 4, tview.NewTableCell(finding).SetExpansion(1))

		if e.ip == d.selectedHostIP {
			selectedRow = row
		}
	}

	if d.topFindingsTable.GetRowCount() > 1 {
		d.topFindingsTable.Select(selectedRow, 0)
	}
}

// updateServicesPanel renders service and port distribution across all hosts.
func (d *Dashboard) updateServicesPanel(correlations map[string]*correlation.CorrelationResult) {
	var content strings.Builder

	if len(correlations) == 0 {
		content.WriteString(d.str.DashNoHostsDiscovered)
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
		if svcs[i].count != svcs[j].count {
			return svcs[i].count > svcs[j].count
		}
		return svcs[i].name < svcs[j].name
	})

	content.WriteString(d.str.DashTopServicesHeading)
	maxShow := 8
	if len(svcs) < maxShow {
		maxShow = len(svcs)
	}
	for i := 0; i < maxShow; i++ {
		s := svcs[i]
		content.WriteString(fmt.Sprintf(d.str.FmtDashServiceEntry, s.name, s.count))
	}

	content.WriteString(d.str.DashPortsHeading)
	content.WriteString(fmt.Sprintf(d.str.FmtDashUniqueOpenPorts, len(portSet)))
	if maxPortHost != "" {
		content.WriteString(fmt.Sprintf(d.str.FmtDashMostExposedHost, maxPortHost, maxPortCount))
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
func (d *Dashboard) topFindingText(corr *correlation.CorrelationResult) string {
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
		return fmt.Sprintf(d.str.FmtTopFindingMedium, medCount)
	}

	// Fall back to port/service exposure summary
	if len(corr.Services) > 0 {
		return fmt.Sprintf(d.str.FmtTopFindingPorts, len(corr.Services))
	}

	return d.str.TopFindingNone
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

// showHostDetailsModal displays a scrollable vulnerability-focused detail view for the selected host.
func (d *Dashboard) showHostDetailsModal(hostIP string, corr *correlation.CorrelationResult) {
	cat := hostCategory(corr)
	hostname := hostHostname(corr)
	osLabel := "-"
	if corr.HostInfo != nil {
		if corr.HostInfo.OSDetails != "" {
			osLabel = corr.HostInfo.OSDetails
		} else if corr.HostInfo.OS != "" {
			osLabel = corr.HostInfo.OS
		}
	}

	// Header with OS context
	var headerExtra string
	if cat != "unknown" {
		headerExtra = fmt.Sprintf(" — [%s]%s[::-]", categoryTviewColor(cat), cat)
	}
	if osLabel != "-" {
		headerExtra += fmt.Sprintf(" [gray](%s)[::-]", osLabel)
	}
	var details strings.Builder
	if hostname != "-" {
		details.WriteString(fmt.Sprintf(d.str.FmtHostRiskDetailWithHost, hostIP, hostname, headerExtra))
	} else {
		details.WriteString(fmt.Sprintf(d.str.FmtHostRiskDetail, hostIP, headerExtra))
	}
	details.WriteString("\n\n")

	// Risk score with tier
	var tierLabel, tierColor string
	for _, tier := range riskTiers {
		if corr.RiskScore >= tier.minScore {
			tierLabel = tier.label
			tierColor = tier.tviewColor
			break
		}
	}
	details.WriteString(fmt.Sprintf(d.str.FmtRiskScore, tierColor, corr.RiskScore, tierColor, d.str.RiskLabel(tierLabel)))

	// Risk breakdown
	bd := corr.RiskDetails
	details.WriteString(fmt.Sprintf(d.str.FmtRiskBreakdownVulns, bd.VulnerabilityScore))
	details.WriteString(fmt.Sprintf(d.str.FmtRiskBreakdownService, bd.ServiceExposure))
	details.WriteString(fmt.Sprintf(d.str.FmtRiskBreakdownSSL, bd.SSLIssues))
	details.WriteString(fmt.Sprintf(d.str.FmtRiskBreakdownPorts, bd.OpenPortScore))

	// Risk factors by category
	factorCategories := []struct {
		key   string
		label string
	}{{"vulnerability", "Vulnerabilities"}, {"ssl", "SSL/TLS"}, {"service", "Service Exposure"}, {"port", "Open Ports"}}

	for _, cat := range factorCategories {
		var catFactors []correlation.RiskFactorDetail
		for _, f := range bd.Factors {
			if f.Category == cat.key {
				catFactors = append(catFactors, f)
			}
		}
		if len(catFactors) == 0 {
			continue
		}
		details.WriteString(fmt.Sprintf(d.str.FmtRiskFactorCategory, cat.label, len(catFactors)))
		maxFactors := len(catFactors)
		if maxFactors > 15 {
			maxFactors = 15
		}
		for i := 0; i < maxFactors; i++ {
			f := catFactors[i]
			source := ""
			if f.Source != "" {
				source = fmt.Sprintf(" (%s)", f.Source)
			}
			details.WriteString(fmt.Sprintf(d.str.FmtRiskFactorLine, f.Title, f.Score, source))
		}
		if len(catFactors) > maxFactors {
			details.WriteString(fmt.Sprintf(d.str.FmtAndMore, len(catFactors)-maxFactors))
		}
	}

	// Vulnerabilities by severity
	severities := []struct {
		sev   string
		color string
	}{{"critical", "red"}, {"high", "orange"}, {"medium", "yellow"}, {"low", "green"}, {"info", "gray"}}

	for _, s := range severities {
		var sevVulns []correlation.Vulnerability
		for _, v := range corr.Vulnerabilities {
			if strings.ToLower(v.Severity) == s.sev {
				sevVulns = append(sevVulns, v)
			}
		}
		if len(sevVulns) == 0 {
			continue
		}
		details.WriteString(fmt.Sprintf(d.str.FmtSevFindings, s.color, d.str.SeverityLabel(s.sev)))
		maxShow := len(sevVulns)
		if maxShow > 15 {
			maxShow = 15
		}
		for i := 0; i < maxShow; i++ {
			v := sevVulns[i]
			line := fmt.Sprintf("  ● %s", v.Title)
			if v.Source != "" {
				line += fmt.Sprintf(" (%s", v.Source)
				if v.Port > 0 {
					line += fmt.Sprintf(", port %d", v.Port)
				}
				line += ")"
			}
			details.WriteString(fmt.Sprintf("%s\n", line))
		}
		if len(sevVulns) > maxShow {
			details.WriteString(fmt.Sprintf(d.str.FmtAndMore, len(sevVulns)-maxShow))
		}
		details.WriteString("\n")
	}

	// Open ports summary
	var openPorts []string
	if corr.HostInfo != nil {
		for _, p := range corr.HostInfo.Ports {
			if p.State == "open" {
				openPorts = append(openPorts, fmt.Sprintf("%d", p.Number))
			}
		}
	}
	if len(openPorts) > 0 {
		details.WriteString(fmt.Sprintf(d.str.FmtHostOpenPorts, strings.Join(openPorts, ", ")))
	}

	// Build scrollable view
	textView := tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true).
		SetWrap(true).
		SetText(details.String())
	textView.SetBorder(true).SetTitle(fmt.Sprintf(d.str.FmtRiskDetailTitle, hostIP))

	// Button row
	buttonRow := tview.NewFlex().SetDirection(tview.FlexColumn)
	btnInventory := tview.NewButton(d.str.BtnViewInventory).SetSelectedFunc(func() {
		d.pages.RemovePage("host-details")
		ShowCorrelationViewer(d.app, d.pages, d.correlator, func() {
			d.app.SetFocus(d.topFindingsTable)
		}, "", d.str)
	})
	btnClose := tview.NewButton(d.str.BtnClose).SetSelectedFunc(func() {
		d.pages.RemovePage("host-details")
		d.app.SetFocus(d.topFindingsTable)
	})
	buttonRow.AddItem(btnInventory, 0, 1, true)
	buttonRow.AddItem(btnClose, 0, 1, true)

	// Layout
	modal := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(textView, 0, 1, true).
		AddItem(buttonRow, 1, 0, true)

	// Center the modal with padding
	centerFlex := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 0, 1, false).
			AddItem(modal, 0, 5, true).
			AddItem(nil, 0, 1, false), 0, 3, true).
		AddItem(nil, 0, 1, false)

	centerFlex.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEscape:
			d.pages.RemovePage("host-details")
			d.app.SetFocus(d.topFindingsTable)
			return nil
		case tcell.KeyTab:
			// Cycle focus between text view and buttons
			switch d.app.GetFocus() {
			case textView:
				d.app.SetFocus(btnInventory)
			case btnInventory:
				d.app.SetFocus(btnClose)
			default:
				d.app.SetFocus(textView)
			}
			return nil
		}
		return event
	})

	d.pages.AddPage("host-details", centerFlex, true, true)
	d.app.SetFocus(textView)
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

	dashboard := NewDashboard(app, pages, jobManager, correlator, workflowEngine, nil, stringsEN)
	pages.AddPage("dashboard", dashboard, true, true)
	app.SetFocus(dashboard.topFindingsTable)
}
