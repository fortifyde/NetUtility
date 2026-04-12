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

// hostCategory returns the ph7 category from HostInfo.Attributes ("windows",
// "linux", "network_device", or "unknown"). Falls back to "unknown" if unset.
func hostCategory(result *correlation.CorrelationResult) string {
	if result != nil && result.HostInfo != nil {
		if cat, ok := result.HostInfo.Attributes["category"]; ok && cat != "" {
			return cat
		}
	}
	return "unknown"
}

// hostVendor returns the ph7 vendor string, or "-" if absent.
func hostVendor(result *correlation.CorrelationResult) string {
	if result != nil && result.HostInfo != nil {
		if v, ok := result.HostInfo.Attributes["vendor"]; ok && v != "" && v != "-" {
			return v
		}
	}
	return "-"
}

// hostHostname returns the best available name: DNS hostname, then NetBIOS, then "-".
func hostHostname(result *correlation.CorrelationResult) string {
	if result != nil && result.HostInfo != nil {
		if result.HostInfo.Hostname != "" {
			return result.HostInfo.Hostname
		}
		if nb, ok := result.HostInfo.Attributes["netbios_name"]; ok && nb != "" {
			return nb
		}
	}
	return "-"
}

// hostOpenPorts returns a comma-joined list of open port numbers, truncated to 22 chars.
func hostOpenPorts(result *correlation.CorrelationResult) string {
	if result == nil || result.HostInfo == nil || len(result.HostInfo.Ports) == 0 {
		return "-"
	}
	var portNums []int
	for _, p := range result.HostInfo.Ports {
		if p.State == "open" {
			portNums = append(portNums, p.Number)
		}
	}
	if len(portNums) == 0 {
		return "-"
	}
	sort.Ints(portNums)
	var ports []string
	for _, n := range portNums {
		ports = append(ports, strconv.Itoa(n))
	}
	joined := strings.Join(ports, ",")
	if len([]rune(joined)) > 22 {
		return string([]rune(joined)[:21]) + "…"
	}
	return joined
}

// categoryOrder returns a sort key for display order: windows=0, linux=1, network_device=2, unknown=3.
func categoryOrder(cat string) int {
	switch cat {
	case "windows":
		return 0
	case "linux":
		return 1
	case "network_device":
		return 2
	default:
		return 3
	}
}

// categoryTcellColor returns the tcell display color for a category (for table cells).
func categoryTcellColor(cat string) tcell.Color {
	switch cat {
	case "windows":
		return tcell.ColorGreen
	case "linux":
		return tcell.ColorYellow
	case "network_device":
		return tcell.ColorBlue
	default:
		return tcell.ColorGray
	}
}

// categoryTviewColor returns the tview markup color name for a category (for TextView).
func categoryTviewColor(cat string) string {
	switch cat {
	case "windows":
		return "green"
	case "linux":
		return "yellow"
	case "network_device":
		return "aqua"
	default:
		return "gray"
	}
}

// compareIPs returns true if ip1 sorts before ip2 by numeric octet comparison.
func compareIPs(ip1, ip2 string) bool {
	p1 := strings.Split(ip1, ".")
	p2 := strings.Split(ip2, ".")
	for i := 0; i < 4 && i < len(p1) && i < len(p2); i++ {
		n1, _ := strconv.Atoi(p1[i])
		n2, _ := strconv.Atoi(p2[i])
		if n1 != n2 {
			return n1 < n2
		}
	}
	return ip1 < ip2
}

// filterCategories defines the cycling order for the category filter.
var filterCategories = []string{"", "windows", "linux", "network_device", "unknown"}

// cycleCategoryFilter advances filterCategory to the next value in the cycle.
func (cv *CorrelationViewer) cycleCategoryFilter() {
	for i, cat := range filterCategories {
		if cv.filterCategory == cat {
			cv.filterCategory = filterCategories[(i+1)%len(filterCategories)]
			break
		}
	}
	cv.updateHostsList()
	cv.updateControlsText()
}

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
	selectedHost         string
	currentView          string // "hosts", "details", "timeline"
	filterCategory       string // "" = all; "windows"/"linux"/"network_device"/"unknown" = filtered
	refreshTicker        *time.Ticker
	stopChan             chan struct{}
	returnToMainCallback func()
}

// NewCorrelationViewer creates a new correlation viewer
func NewCorrelationViewer(app *tview.Application, pages *tview.Pages, correlator *correlation.Correlator, returnToMainCallback func()) *CorrelationViewer {
	cv := &CorrelationViewer{
		Flex:                 tview.NewFlex(),
		app:                  app,
		pages:                pages,
		correlator:           correlator,
		currentView:          "hosts",
		stopChan:             make(chan struct{}),
		returnToMainCallback: returnToMainCallback,
	}

	cv.setupUI()
	cv.startRefreshTimer()
	return cv
}

// setupUI initializes the correlation viewer interface
func (cv *CorrelationViewer) setupUI() {
	// Create hosts table
	cv.hostsList = tview.NewTable().SetBorders(true).SetSelectable(true, false)
	cv.hostsList.SetBorder(true).SetTitle("Host Inventory")

	// Set table headers
	headers := []string{"IP", "Category", "Vendor", "Hostname", "Ports"}
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
	cv.updateControlsText()

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

// updateControlsText re-renders the controls panel to reflect current filter state.
func (cv *CorrelationViewer) updateControlsText() {
	filterLine := "[white]f[::-]        Cycle category filter"
	if cv.filterCategory != "" {
		filterLine = fmt.Sprintf("[yellow]f[::-]        Cycle filter [%s]", cv.filterCategory)
	}
	cv.controlsText.SetText(fmt.Sprintf(`[yellow]Controls:[::-]
[white]Enter[::-]    View host details
[white]t[::-]        View timeline
[white]r[::-]        Refresh
%s
[white]q[::-]        Close`, filterLine))
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
			case 'f':
				cv.cycleCategoryFilter()
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

}

// updateHostsList refreshes the hosts table with category-sorted inventory data.
func (cv *CorrelationViewer) updateHostsList() {
	title := "Host Inventory"
	switch cv.filterCategory {
	case "windows":
		title = "Host Inventory [Windows]"
	case "linux":
		title = "Host Inventory [Linux]"
	case "network_device":
		title = "Host Inventory [Network Devices]"
	case "unknown":
		title = "Host Inventory [Unknown]"
	}
	cv.hostsList.SetTitle(title)

	// Preserve the currently selected host IP so auto-refresh doesn't reset the cursor.
	prevSelected := cv.selectedHost

	cv.hostsList.Clear()

	headers := []string{"IP", "Category", "Vendor", "Hostname", "Ports"}
	for i, header := range headers {
		cv.hostsList.SetCell(0, i, tview.NewTableCell(header).
			SetTextColor(tcell.ColorYellow).
			SetAlign(tview.AlignCenter).
			SetSelectable(false))
	}

	correlations := cv.correlator.GetAllCorrelations()

	type hostEntry struct {
		ip     string
		result *correlation.CorrelationResult
	}

	var entries []hostEntry
	for ip, result := range correlations {
		cat := hostCategory(result)
		if cv.filterCategory == "" || cat == cv.filterCategory {
			entries = append(entries, hostEntry{ip, result})
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		ci := categoryOrder(hostCategory(entries[i].result))
		cj := categoryOrder(hostCategory(entries[j].result))
		if ci != cj {
			return ci < cj
		}
		return compareIPs(entries[i].ip, entries[j].ip)
	})

	reSelectRow := 1 // default to first data row
	for i, e := range entries {
		row := i + 1
		cat := hostCategory(e.result)
		cv.hostsList.SetCell(row, 0, tview.NewTableCell(e.ip))
		cv.hostsList.SetCell(row, 1, tview.NewTableCell(cat).SetTextColor(categoryTcellColor(cat)))
		cv.hostsList.SetCell(row, 2, tview.NewTableCell(hostVendor(e.result)))
		cv.hostsList.SetCell(row, 3, tview.NewTableCell(hostHostname(e.result)))
		cv.hostsList.SetCell(row, 4, tview.NewTableCell(hostOpenPorts(e.result)))
		if e.ip == prevSelected {
			reSelectRow = row
		}
	}

	if cv.hostsList.GetRowCount() > 1 {
		cv.hostsList.Select(reSelectRow, 0)
	}
}


// updateDetailsPanel renders host identity, classification, and port data for the selected host.
func (cv *CorrelationViewer) updateDetailsPanel() {
	if cv.selectedHost == "" {
		cv.detailsPanel.SetText("[gray]Select a host to view details[::-]")
		return
	}

	result, exists := cv.correlator.GetCorrelationForHost(cv.selectedHost)
	if !exists {
		cv.detailsPanel.SetText("[gray]No data found for selected host[::-]")
		return
	}

	var b strings.Builder

	// --- Identity ---
	b.WriteString("[yellow]Identity[::-]\n")
	b.WriteString(fmt.Sprintf("IP:       [white]%s[::-]\n", result.Host))
	mac := "-"
	hostname := "-"
	netbios := "-"
	osStr := "-"
	if result.HostInfo != nil {
		if result.HostInfo.MACAddress != "" {
			mac = result.HostInfo.MACAddress
		}
		if result.HostInfo.Hostname != "" {
			hostname = result.HostInfo.Hostname
		}
		if nb, ok := result.HostInfo.Attributes["netbios_name"]; ok && nb != "" {
			netbios = nb
		}
		if result.HostInfo.OSDetails != "" {
			osStr = result.HostInfo.OSDetails
		} else if result.HostInfo.OS != "" {
			osStr = result.HostInfo.OS
		}
	}
	b.WriteString(fmt.Sprintf("MAC:      [white]%s[::-]\n", mac))
	b.WriteString(fmt.Sprintf("Hostname: [white]%s[::-]\n", hostname))
	b.WriteString(fmt.Sprintf("NetBIOS:  [white]%s[::-]\n", netbios))
	b.WriteString(fmt.Sprintf("OS:       [white]%s[::-]\n", osStr))
	b.WriteString("\n")

	// --- Classification ---
	b.WriteString("[yellow]Classification[::-]\n")
	cat := hostCategory(result)
	vendor := hostVendor(result)
	confidence := "-"
	score := "-"
	if result.HostInfo != nil {
		if c, ok := result.HostInfo.Attributes["confidence"]; ok && c != "" {
			confidence = c
		}
		if s, ok := result.HostInfo.Attributes["score"]; ok && s != "" {
			score = s
		}
	}
	b.WriteString(fmt.Sprintf("Category:   [%s]%s[::-]\n", categoryTviewColor(cat), cat))
	b.WriteString(fmt.Sprintf("Vendor:     [white]%s[::-]\n", vendor))
	if score != "-" {
		b.WriteString(fmt.Sprintf("Confidence: [white]%s[::-]  (score %s)\n", confidence, score))
	} else {
		b.WriteString(fmt.Sprintf("Confidence: [white]%s[::-]\n", confidence))
	}
	b.WriteString("\n")

	// --- Ports & Services ---
	var openPorts []correlation.Port
	if result.HostInfo != nil {
		for _, p := range result.HostInfo.Ports {
			if p.State == "open" {
				openPorts = append(openPorts, p)
			}
		}
	}
	b.WriteString(fmt.Sprintf("[yellow]Ports & Services (%d)[::-]\n", len(openPorts)))
	if len(openPorts) == 0 {
		b.WriteString("[gray]No open ports found[::-]\n")
	} else {
		for _, p := range openPorts {
			svc := p.Service
			if svc == "" {
				svc = "-"
			}
			ver := p.Version
			if ver == "" {
				ver = "-"
			}
			b.WriteString(fmt.Sprintf("[white]%d/%s[::-]  %-8s  %s\n",
				p.Number, p.Protocol, svc, ver))
		}
	}

	cv.detailsPanel.SetText(b.String())
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

func (cv *CorrelationViewer) refresh() {
	cv.app.QueueUpdateDraw(func() {
		cv.updateControlsText()
		cv.updateHostsList()
		cv.updateDetailsPanel()
		cv.updateTimeline()
	})
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
		cv.refreshTicker = nil
	}
	select {
	case <-cv.stopChan:
		return
	default:
	}
	close(cv.stopChan)
	cv.pages.RemovePage("correlation")
	if cv.returnToMainCallback != nil {
		cv.returnToMainCallback()
	}
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

// ShowCorrelationViewer creates and displays a correlation viewer page.
// For the main TUI use showCorrelationViewer() which passes a proper returnToMain callback.
func ShowCorrelationViewer(app *tview.Application, pages *tview.Pages, correlator *correlation.Correlator, returnToMainCallback func()) {
	correlationViewer := NewCorrelationViewer(app, pages, correlator, returnToMainCallback)
	pages.AddPage("correlation", correlationViewer, true, true)
	app.SetFocus(correlationViewer.hostsList)
}
