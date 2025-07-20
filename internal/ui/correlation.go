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
)

// CorrelationViewer displays correlated scan results
type CorrelationViewer struct {
	*tview.Flex
	app        *tview.Application
	pages      *tview.Pages
	correlator *correlation.Correlator

	// UI components
	hostsList    *tview.Table
	detailsPanel *tview.TextView
	timelineList *tview.List
	controlsText *tview.TextView

	// State
	selectedHost  string
	currentView   string // "hosts", "details", "timeline"
	refreshTicker *time.Ticker
	stopChan      chan struct{}
}

// NewCorrelationViewer creates a new correlation viewer
func NewCorrelationViewer(app *tview.Application, pages *tview.Pages, correlator *correlation.Correlator) *CorrelationViewer {
	cv := &CorrelationViewer{
		Flex:        tview.NewFlex(),
		app:         app,
		pages:       pages,
		correlator:  correlator,
		currentView: "hosts",
		stopChan:    make(chan struct{}),
	}

	cv.setupUI()
	cv.startRefreshTimer()
	return cv
}

// setupUI initializes the correlation viewer interface
func (cv *CorrelationViewer) setupUI() {
	// Create hosts table
	cv.hostsList = tview.NewTable().SetBorders(true).SetSelectable(true, false)
	cv.hostsList.SetBorder(true).SetTitle("Correlated Hosts")

	// Set table headers
	headers := []string{"Host", "Services", "Vulns", "Risk", "Last Scan", "Status"}
	for i, header := range headers {
		cv.hostsList.SetCell(0, i, tview.NewTableCell(header).
			SetTextColor(tcell.ColorYellow).
			SetAlign(tview.AlignCenter).
			SetSelectable(false))
	}

	// Create details panel
	cv.detailsPanel = tview.NewTextView().SetDynamicColors(true).SetScrollable(true)
	cv.detailsPanel.SetBorder(true).SetTitle("Host Details")

	// Create timeline list
	cv.timelineList = tview.NewList()
	cv.timelineList.SetBorder(true).SetTitle("Scan Timeline")

	// Create controls panel
	cv.controlsText = tview.NewTextView().SetDynamicColors(true)
	cv.controlsText.SetBorder(true).SetTitle("Controls")
	cv.controlsText.SetText(`[yellow]Controls:[::-]
[white]Enter[::-]    View host details
[white]t[::-]        View timeline
[white]r[::-]        Refresh correlations
[white]s[::-]        Sort by risk score
[white]f[::-]        Filter high-risk hosts
[white]e[::-]        Export correlations
[white]q[::-]        Close correlation viewer`)

	// Layout: Left panel (hosts table), Right panel (details + timeline + controls)
	rightPanel := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(cv.detailsPanel, 0, 2, false).
		AddItem(cv.timelineList, 0, 1, false).
		AddItem(cv.controlsText, 8, 0, false)

	cv.SetDirection(tview.FlexColumn).
		AddItem(cv.hostsList, 0, 1, true).
		AddItem(rightPanel, 0, 1, false)

	// Setup key bindings
	cv.setupKeyBindings()

	// Initial update
	cv.updateHostsList()
}

// setupKeyBindings configures keyboard shortcuts
func (cv *CorrelationViewer) setupKeyBindings() {
	cv.hostsList.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEscape:
			cv.Close()
			return nil
		case tcell.KeyEnter:
			cv.showHostDetails()
			return nil
		case tcell.KeyRune:
			switch event.Rune() {
			case 'q':
				cv.Close()
				return nil
			case 't':
				cv.showTimeline()
				return nil
			case 'r':
				cv.refresh()
				return nil
			case 's':
				cv.sortByRiskScore()
				return nil
			case 'f':
				cv.filterHighRisk()
				return nil
			case 'e':
				cv.exportCorrelations()
				return nil
			}
		}
		return event
	})

	// Selection handler
	cv.hostsList.SetSelectedFunc(func(row, column int) {
		cv.showHostDetails()
	})

	cv.hostsList.SetSelectionChangedFunc(func(row, column int) {
		if row > 0 { // Skip header row
			cell := cv.hostsList.GetCell(row, 0)
			if cell != nil {
				cv.selectedHost = cell.Text
				cv.updateDetailsPanel()
				cv.updateTimeline()
			}
		}
	})

	// Add mouse support to hosts table
	cv.hostsList.SetMouseCapture(func(action tview.MouseAction, event *tcell.EventMouse) (tview.MouseAction, *tcell.EventMouse) {
		if action == tview.MouseLeftClick {
			// Get click position relative to table
			_, y := event.Position()
			// Approximate row calculation
			row := y
			if row > 0 && row < cv.hostsList.GetRowCount() {
				cv.hostsList.Select(row, 0)
			}
		}
		return action, event
	})
}

// updateHostsList refreshes the hosts table
func (cv *CorrelationViewer) updateHostsList() {
	// Clear existing rows (except header)
	cv.hostsList.Clear()

	// Reset headers
	headers := []string{"Host", "Services", "Vulns", "Risk", "Last Scan", "Status"}
	for i, header := range headers {
		cv.hostsList.SetCell(0, i, tview.NewTableCell(header).
			SetTextColor(tcell.ColorYellow).
			SetAlign(tview.AlignCenter).
			SetSelectable(false))
	}

	// Get all correlations
	correlations := cv.correlator.GetAllCorrelations()

	// Convert to sorted slice
	type hostCorrelation struct {
		host   string
		result *correlation.CorrelationResult
	}

	hosts := make([]hostCorrelation, 0, len(correlations))
	for host, result := range correlations {
		hosts = append(hosts, hostCorrelation{host, result})
	}

	// Sort by risk score (highest first)
	sort.Slice(hosts, func(i, j int) bool {
		return hosts[i].result.RiskScore > hosts[j].result.RiskScore
	})

	// Add host rows
	for i, hc := range hosts {
		row := i + 1
		result := hc.result

		// Format data
		hostIP := hc.host
		serviceCount := strconv.Itoa(len(result.Services))
		vulnCount := strconv.Itoa(len(result.Vulnerabilities))
		riskScore := strconv.Itoa(result.RiskScore)

		// Determine last scan time
		lastScan := "Never"
		if len(result.Timeline) > 0 {
			lastEvent := result.Timeline[len(result.Timeline)-1]
			lastScan = lastEvent.Timestamp.Format("15:04:05")
		}

		// Determine status
		status := cv.getHostStatus(result)
		statusColor := cv.getStatusColor(result.RiskScore)
		riskColor := cv.getRiskColor(result.RiskScore)

		// Set table cells
		cv.hostsList.SetCell(row, 0, tview.NewTableCell(hostIP))
		cv.hostsList.SetCell(row, 1, tview.NewTableCell(serviceCount))
		cv.hostsList.SetCell(row, 2, tview.NewTableCell(vulnCount))
		cv.hostsList.SetCell(row, 3, tview.NewTableCell(riskScore).SetTextColor(riskColor))
		cv.hostsList.SetCell(row, 4, tview.NewTableCell(lastScan))
		cv.hostsList.SetCell(row, 5, tview.NewTableCell(status).SetTextColor(statusColor))
	}

	// Set initial selection to enable navigation (skip header row)
	if cv.hostsList.GetRowCount() > 1 {
		cv.hostsList.Select(1, 0)
	}
}

// getHostStatus determines the status of a host based on correlation data
func (cv *CorrelationViewer) getHostStatus(result *correlation.CorrelationResult) string {
	if result.RiskScore >= 750 {
		return "Critical"
	} else if result.RiskScore >= 500 {
		return "High Risk"
	} else if result.RiskScore >= 250 {
		return "Medium Risk"
	} else if result.RiskScore >= 100 {
		return "Low Risk"
	} else if len(result.Services) > 0 {
		return "Active"
	}
	return "Scanned"
}

// getStatusColor returns appropriate color for host status
func (cv *CorrelationViewer) getStatusColor(riskScore int) tcell.Color {
	if riskScore >= 750 {
		return tcell.ColorRed
	} else if riskScore >= 500 {
		return tcell.ColorOrange
	} else if riskScore >= 250 {
		return tcell.ColorYellow
	} else if riskScore >= 100 {
		return tcell.ColorLightBlue
	}
	return tcell.ColorGreen
}

// getRiskColor returns appropriate color for risk score
func (cv *CorrelationViewer) getRiskColor(riskScore int) tcell.Color {
	if riskScore >= 750 {
		return tcell.ColorRed
	} else if riskScore >= 500 {
		return tcell.ColorOrange
	} else if riskScore >= 250 {
		return tcell.ColorYellow
	}
	return tcell.ColorGreen
}

// updateDetailsPanel updates the details panel with information about the selected host
func (cv *CorrelationViewer) updateDetailsPanel() {
	if cv.selectedHost == "" {
		cv.detailsPanel.SetText("Select a host to view details")
		return
	}

	result, exists := cv.correlator.GetCorrelationForHost(cv.selectedHost)
	if !exists {
		cv.detailsPanel.SetText("No correlation data found for selected host")
		return
	}

	var details strings.Builder

	// Host information
	details.WriteString(fmt.Sprintf("[yellow]Host Information[::-]\n"))
	details.WriteString(fmt.Sprintf("IP Address: [white]%s[::-]\n", result.Host))

	if result.HostInfo != nil {
		if result.HostInfo.Hostname != "" {
			details.WriteString(fmt.Sprintf("Hostname: [white]%s[::-]\n", result.HostInfo.Hostname))
		}
		if result.HostInfo.OS != "" {
			details.WriteString(fmt.Sprintf("OS: [white]%s[::-]\n", result.HostInfo.OS))
		}
		if result.HostInfo.MACAddress != "" {
			details.WriteString(fmt.Sprintf("MAC: [white]%s[::-]\n", result.HostInfo.MACAddress))
		}
		details.WriteString(fmt.Sprintf("Status: [white]%s[::-]\n", result.HostInfo.Status))
		details.WriteString(fmt.Sprintf("Last Seen: [white]%s[::-]\n", result.HostInfo.LastSeen.Format("2006-01-02 15:04:05")))
	}

	details.WriteString(fmt.Sprintf("Risk Score: [%s]%d[::-]\n\n",
		cv.formatRiskColor(result.RiskScore), result.RiskScore))

	// Services
	details.WriteString(fmt.Sprintf("[yellow]Services (%d)[::-]\n", len(result.Services)))
	if len(result.Services) == 0 {
		details.WriteString("No services discovered\n")
	} else {
		for _, service := range result.Services {
			details.WriteString(fmt.Sprintf("  %d/%s - [white]%s[::-]",
				service.Port, service.Protocol, service.Name))
			if service.Version != "" {
				details.WriteString(fmt.Sprintf(" (%s)", service.Version))
			}
			details.WriteString("\n")
		}
	}
	details.WriteString("\n")

	// Vulnerabilities
	details.WriteString(fmt.Sprintf("[yellow]Vulnerabilities (%d)[::-]\n", len(result.Vulnerabilities)))
	if len(result.Vulnerabilities) == 0 {
		details.WriteString("No vulnerabilities found\n")
	} else {
		for _, vuln := range result.Vulnerabilities {
			severityColor := cv.getSeverityColor(vuln.Severity)
			details.WriteString(fmt.Sprintf("  [%s]%s[::-] - %s",
				severityColor, strings.ToUpper(vuln.Severity), vuln.Title))
			if vuln.Port > 0 {
				details.WriteString(fmt.Sprintf(" (Port %d)", vuln.Port))
			}
			details.WriteString("\n")
		}
	}
	details.WriteString("\n")

	// Recommendations
	details.WriteString(fmt.Sprintf("[yellow]Recommendations (%d)[::-]\n", len(result.Recommendations)))
	if len(result.Recommendations) == 0 {
		details.WriteString("No specific recommendations\n")
	} else {
		for i, rec := range result.Recommendations {
			details.WriteString(fmt.Sprintf("  %d. %s\n", i+1, rec))
		}
	}

	cv.detailsPanel.SetText(details.String())
}

// updateTimeline updates the timeline list with scan events
func (cv *CorrelationViewer) updateTimeline() {
	cv.timelineList.Clear()

	if cv.selectedHost == "" {
		return
	}

	result, exists := cv.correlator.GetCorrelationForHost(cv.selectedHost)
	if !exists {
		return
	}

	for _, event := range result.Timeline {
		timeStr := event.Timestamp.Format("15:04:05")
		scanType := string(event.ScanType)
		description := event.Description

		item := fmt.Sprintf("%s - %s", timeStr, description)
		cv.timelineList.AddItem(item, scanType, 0, nil)
	}
}

// formatRiskColor returns color name for tview formatting
func (cv *CorrelationViewer) formatRiskColor(riskScore int) string {
	if riskScore >= 750 {
		return "red"
	} else if riskScore >= 500 {
		return "orange"
	} else if riskScore >= 250 {
		return "yellow"
	}
	return "green"
}

// getSeverityColor returns color for vulnerability severity
func (cv *CorrelationViewer) getSeverityColor(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "red"
	case "high":
		return "orange"
	case "medium":
		return "yellow"
	case "low":
		return "lightblue"
	default:
		return "gray"
	}
}

// showHostDetails focuses on the details panel
func (cv *CorrelationViewer) showHostDetails() {
	cv.currentView = "details"
	cv.updateDetailsPanel()
}

// showTimeline focuses on the timeline
func (cv *CorrelationViewer) showTimeline() {
	cv.currentView = "timeline"
	cv.app.SetFocus(cv.timelineList)
}

// refresh updates all UI components
func (cv *CorrelationViewer) refresh() {
	cv.app.QueueUpdateDraw(func() {
		cv.updateHostsList()
		cv.updateDetailsPanel()
		cv.updateTimeline()
	})
}

// sortByRiskScore sorts hosts by risk score
func (cv *CorrelationViewer) sortByRiskScore() {
	cv.updateHostsList() // Already sorts by risk score
}

// filterHighRisk shows only high-risk hosts
func (cv *CorrelationViewer) filterHighRisk() {
	highRiskHosts := cv.correlator.GetHighRiskHosts(500)

	// Clear table and reset headers
	cv.hostsList.Clear()
	headers := []string{"Host", "Services", "Vulns", "Risk", "Last Scan", "Status"}
	for i, header := range headers {
		cv.hostsList.SetCell(0, i, tview.NewTableCell(header).
			SetTextColor(tcell.ColorYellow).
			SetAlign(tview.AlignCenter).
			SetSelectable(false))
	}

	// Add only high-risk hosts
	for i, result := range highRiskHosts {
		row := i + 1

		hostIP := result.Host
		serviceCount := strconv.Itoa(len(result.Services))
		vulnCount := strconv.Itoa(len(result.Vulnerabilities))
		riskScore := strconv.Itoa(result.RiskScore)

		lastScan := "Never"
		if len(result.Timeline) > 0 {
			lastEvent := result.Timeline[len(result.Timeline)-1]
			lastScan = lastEvent.Timestamp.Format("15:04:05")
		}

		status := cv.getHostStatus(result)
		statusColor := cv.getStatusColor(result.RiskScore)
		riskColor := cv.getRiskColor(result.RiskScore)

		cv.hostsList.SetCell(row, 0, tview.NewTableCell(hostIP))
		cv.hostsList.SetCell(row, 1, tview.NewTableCell(serviceCount))
		cv.hostsList.SetCell(row, 2, tview.NewTableCell(vulnCount))
		cv.hostsList.SetCell(row, 3, tview.NewTableCell(riskScore).SetTextColor(riskColor))
		cv.hostsList.SetCell(row, 4, tview.NewTableCell(lastScan))
		cv.hostsList.SetCell(row, 5, tview.NewTableCell(status).SetTextColor(statusColor))
	}

	// Set initial selection to enable navigation (skip header row)
	if cv.hostsList.GetRowCount() > 1 {
		cv.hostsList.Select(1, 0)
	}

	cv.hostsList.SetTitle(fmt.Sprintf("High-Risk Hosts (%d)", len(highRiskHosts)))
}

// exportCorrelations exports correlation data
func (cv *CorrelationViewer) exportCorrelations() {
	// Show export options
	modal := tview.NewModal().
		SetText("Export correlation data to file?").
		AddButtons([]string{"JSON", "CSV", "Cancel"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			cv.pages.RemovePage("export")
			switch buttonLabel {
			case "JSON":
				cv.showInfo("JSON export not yet implemented")
			case "CSV":
				cv.showInfo("CSV export not yet implemented")
			}
		})

	cv.pages.AddPage("export", modal, true, true)
}

// startRefreshTimer starts automatic refresh
func (cv *CorrelationViewer) startRefreshTimer() {
	cv.refreshTicker = time.NewTicker(5 * time.Second)
	go func() {
		for {
			select {
			case <-cv.refreshTicker.C:
				cv.refresh()
			case <-cv.stopChan:
				return
			}
		}
	}()
}

// Close closes the correlation viewer
func (cv *CorrelationViewer) Close() {
	if cv.refreshTicker != nil {
		cv.refreshTicker.Stop()
	}
	close(cv.stopChan)
	cv.pages.RemovePage("correlation")
}

// showInfo displays an info message
func (cv *CorrelationViewer) showInfo(message string) {
	modal := tview.NewModal().
		SetText(message).
		AddButtons([]string{"OK"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			cv.pages.RemovePage("info")
		})

	cv.pages.AddPage("info", modal, true, true)
}

// Helper function to create a correlation viewer page
func ShowCorrelationViewer(app *tview.Application, pages *tview.Pages, correlator *correlation.Correlator) {
	correlationViewer := NewCorrelationViewer(app, pages, correlator)
	pages.AddPage("correlation", correlationViewer, true, true)
	app.SetFocus(correlationViewer.hostsList)
}
