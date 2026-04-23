package ui

import (
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
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

// hostOpenPorts returns a comma-joined list of open port numbers.
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
	return strings.Join(ports, ",")
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

// hostMatchesText reports whether a host passes a text filter.
// An empty text always matches. Matches are case-insensitive and checked against
// IP address, hostname, NetBIOS name, open port numbers, and open port service names.
func hostMatchesText(ip string, result *correlation.CorrelationResult, text string) bool {
	if text == "" {
		return true
	}
	lower := strings.ToLower(text)
	if strings.Contains(strings.ToLower(ip), lower) {
		return true
	}
	if result.HostInfo == nil {
		return false
	}
	if strings.Contains(strings.ToLower(result.HostInfo.Hostname), lower) {
		return true
	}
	if strings.Contains(strings.ToLower(hostVendor(result)), lower) {
		return true
	}
	if nb, ok := result.HostInfo.Attributes["netbios_name"]; ok {
		if strings.Contains(strings.ToLower(nb), lower) {
			return true
		}
	}
	for _, p := range result.HostInfo.Ports {
		if p.State != "open" {
			continue
		}
		if strings.Contains(strconv.Itoa(p.Number), lower) {
			return true
		}
		if strings.Contains(strings.ToLower(p.Service), lower) {
			return true
		}
	}
	return false
}

// filterCategories defines the cycling order for the category filter.
var filterCategories = []string{"", "windows", "linux", "network_device", "unknown"}

// categoryDisplayLabel returns the display label for a category raw value.
func categoryDisplayLabel(cat string) string {
	switch cat {
	case "windows":
		return "Windows"
	case "linux":
		return "Linux"
	case "network_device":
		return "Network Devices"
	case "unknown":
		return "Unknown"
	default:
		return ""
	}
}

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
	controlsText *tview.TextView

	// State
	selectedHost         string
	screenshotCache      map[string]image.Image
	filterCategory       string // "" = all; "windows"/"linux"/"network_device"/"unknown" = filtered
	filterText           string // "" = no text filter; non-empty = must match hostMatchesText
	refreshTicker        *time.Ticker
	stopChan             chan struct{}
	returnToMainCallback func()
	workspaceDir         string
	packageInProgress    atomic.Bool
}

// NewCorrelationViewer creates a new correlation viewer
func NewCorrelationViewer(app *tview.Application, pages *tview.Pages, correlator *correlation.Correlator, returnToMainCallback func(), workspaceDir string) *CorrelationViewer {
	cv := &CorrelationViewer{
		Flex:                 tview.NewFlex(),
		app:                  app,
		pages:                pages,
		correlator:           correlator,
		stopChan:             make(chan struct{}),
		returnToMainCallback: returnToMainCallback,
		workspaceDir:         workspaceDir,
		screenshotCache:      make(map[string]image.Image),
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

	// Create details panel
	cv.detailsPanel = tview.NewTextView().SetDynamicColors(true).SetScrollable(true)
	cv.detailsPanel.SetBorder(true).SetTitle("Host Details")

	// Create controls panel
	cv.controlsText = tview.NewTextView().SetDynamicColors(true)
	cv.controlsText.SetBorder(true).SetTitle("Controls")
	cv.updateControlsText()

	// Layout: Left panel (hosts table), Right panel (details + controls)
	rightPanel := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(cv.detailsPanel, 0, 1, false).
		AddItem(cv.controlsText, 8, 0, false)

	cv.SetDirection(tview.FlexColumn).
		AddItem(cv.hostsList, 0, 3, true).
		AddItem(rightPanel, 0, 2, false)

	// Setup key bindings
	cv.setupKeyBindings()

	// Initial update
	cv.updateHostsList()
}

// updateControlsText re-renders the controls panel to reflect current filter state.
func (cv *CorrelationViewer) updateControlsText() {
	var filterLine string
	switch {
	case cv.filterText != "":
		filterLine = "[yellow]f[::-]      Reset search"
	case cv.filterCategory != "":
		filterLine = fmt.Sprintf("[yellow]f[::-]      Cycle filter: %s", categoryDisplayLabel(cv.filterCategory))
	default:
		filterLine = "[white]f[::-]      Cycle category filter"
	}

	cv.controlsText.SetText(fmt.Sprintf(`[yellow]Navigation                    Actions[::-]
[white]Enter[::-]  View host details       [white]s[::-]  View screenshot
[white]/[::-]      Search hosts            [white]p[::-]  Generate package
%s
[white]Space[::-]  Categorize host         [white]q[::-]  Close

[yellow]Global:[::-] [white]Ctrl+J[::-]=Jobs  [white]Ctrl+D[::-]=Dashboard  [white]Ctrl+Z[::-]=Main`, filterLine))
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
			case 'f':
				if cv.filterText != "" {
					cv.filterText = ""
					cv.updateHostsList()
					cv.updateControlsText()
				} else {
					cv.cycleCategoryFilter()
				}
				return nil
			case '/':
				cv.openHostSearchModal()
				return nil
			case ' ':
				cv.openCategorizationModal()
				return nil
			case 's':
				cv.showScreenshotModal()
				return nil
			case 'p':
				cv.generatePackage()
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
			}
		}
	})

}

// updateHostsList refreshes the hosts table with category-sorted inventory data.
func (cv *CorrelationViewer) updateHostsList() {
	catLabel := categoryDisplayLabel(cv.filterCategory)
	title := "Host Inventory"
	switch {
	case catLabel != "" && cv.filterText != "":
		title = fmt.Sprintf("Host Inventory %s", tview.Escape(fmt.Sprintf("[%s · search: %s]", catLabel, cv.filterText)))
	case catLabel != "":
		title = fmt.Sprintf("Host Inventory %s", tview.Escape(fmt.Sprintf("[%s]", catLabel)))
	case cv.filterText != "":
		title = fmt.Sprintf("Host Inventory %s", tview.Escape(fmt.Sprintf("[search: %s]", cv.filterText)))
	}
	cv.hostsList.SetTitle(title)

	// Preserve the currently selected host IP so auto-refresh doesn't reset the cursor.
	prevSelected := cv.selectedHost

	cv.hostsList.Clear()

	type colPolicy struct {
		label     string
		expansion int
		maxWidth  int // 0 = unlimited
	}
	columns := []colPolicy{
		{"IP", 0, 0},
		{"Category", 0, 0},
		{"Hostname", 1, 30},
		{"Vendor", 0, 20},
		{"Ports", 2, 0},
	}
	for i, col := range columns {
		cell := tview.NewTableCell(col.label).
			SetTextColor(tcell.ColorYellow).
			SetAlign(tview.AlignCenter).
			SetSelectable(false).
			SetExpansion(col.expansion)
		if col.maxWidth > 0 {
			cell.SetMaxWidth(col.maxWidth)
		}
		cv.hostsList.SetCell(0, i, cell)
	}

	correlations := cv.correlator.GetAllCorrelations()

	type hostEntry struct {
		ip     string
		result *correlation.CorrelationResult
	}

	var entries []hostEntry
	for ip, result := range correlations {
		cat := hostCategory(result)
		if (cv.filterCategory == "" || cat == cv.filterCategory) &&
			hostMatchesText(ip, result, cv.filterText) {
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

	reSelectRow := 1
	found := false
	for i, e := range entries {
		row := i + 1
		cat := hostCategory(e.result)
		cv.hostsList.SetCell(row, 0, tview.NewTableCell(e.ip).SetExpansion(0))
		cv.hostsList.SetCell(row, 1, tview.NewTableCell(cat).SetTextColor(categoryTcellColor(cat)).SetExpansion(0))
		cv.hostsList.SetCell(row, 2, tview.NewTableCell(hostHostname(e.result)).SetExpansion(1).SetMaxWidth(30))
		cv.hostsList.SetCell(row, 3, tview.NewTableCell(hostVendor(e.result)).SetExpansion(0).SetMaxWidth(20))
		cv.hostsList.SetCell(row, 4, tview.NewTableCell(hostOpenPorts(e.result)).SetExpansion(2))
		if e.ip == prevSelected {
			reSelectRow = row
			found = true
		}
	}

	// If a previous selection existed but is no longer visible (e.g., due to
	// category filter change), select the last row to maintain context.
	if prevSelected != "" && !found && len(entries) > 0 {
		reSelectRow = len(entries)
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
	if result.HostInfo != nil {
		if ttl, ok := result.HostInfo.Attributes["ttl_normalized"]; ok && ttl != "" {
			b.WriteString(fmt.Sprintf("TTL:        [white]%s[::-]\n", ttl))
		}
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

	// --- Screenshots ---
	screenshots := correlation.GetScreenshotsForHost(result)
	b.WriteString(fmt.Sprintf("\n[yellow]Screenshots (%d)[::-]\n", len(screenshots)))
	if len(screenshots) == 0 {
		b.WriteString("[gray]No screenshots available[::-]\n")
	} else {
		for i, ss := range screenshots {
			statusColor := "green"
			if ss.StatusCode != "200" {
				statusColor = "yellow"
			}
			b.WriteString(fmt.Sprintf("[%s]%d.[:-] [white]%s[::-]  [gray](%s)[::-]\n",
				statusColor, i+1, ss.URL, ss.StatusCode))
		}
		b.WriteString("\n[gray]Press [yellow]s[gray] to view screenshots[::-]\n")
	}

	cv.detailsPanel.SetText(b.String())
}

// openHostSearchModal opens a compact modal for entering a text filter.
// Enter applies the filter; Esc cancels.
func (cv *CorrelationViewer) openHostSearchModal() {
	inputField := tview.NewInputField().
		SetLabel("Filter: ").
		SetFieldWidth(0).
		SetText(cv.filterText)

	closeModal := func() {
		cv.pages.RemovePage("host-search")
		cv.app.SetFocus(cv.hostsList)
	}

	applyFilter := func() {
		cv.filterText = strings.TrimSpace(inputField.GetText())
		closeModal()
		cv.updateHostsList()
		cv.updateControlsText()
	}

	inputField.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEnter:
			applyFilter()
			return nil
		case tcell.KeyEscape:
			closeModal()
			return nil
		}
		return event
	})

	// Fixed-height content box: border (2) + input field (1) + padding (2) = 5 rows
	contentBox := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(inputField, 3, 0, true)
	contentBox.SetBorder(true).SetTitle("Filter Hosts")

	centerRow := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(nil, 0, 3, false).
		AddItem(contentBox, 0, 4, true).
		AddItem(nil, 0, 3, false)

	modal := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(nil, 0, 2, false).
		AddItem(centerRow, 5, 0, true).
		AddItem(nil, 0, 2, false)

	cv.pages.AddPage("host-search", modal, true, true)
	cv.app.SetFocus(inputField)
}

func (cv *CorrelationViewer) openCategorizationModal() {
	if cv.selectedHost == "" {
		return
	}
	ip := cv.selectedHost

	closeModal := func() {
		cv.pages.RemovePage("host-categorize")
		cv.app.SetFocus(cv.hostsList)
	}

	applyCategory := func(category string) {
		closeModal()
		go func() {
			// In-memory state is updated even if persistence fails; discard the error.
			_ = cv.correlator.SetManualCategory(ip, category)
			if cv.workspaceDir != "" {
				_ = correlation.MoveHostInHostfiles(cv.workspaceDir, ip, category)
			}
			cv.app.QueueUpdateDraw(func() {
				cv.updateHostsList()
				cv.updateDetailsPanel()
			})
		}()
	}

	list := tview.NewList().
		AddItem("Windows", "", '1', func() { applyCategory("windows") }).
		AddItem("Linux", "", '2', func() { applyCategory("linux") }).
		AddItem("Network Device", "", '3', func() { applyCategory("network_device") }).
		AddItem("Cancel", "", 'q', closeModal)
	list.SetBorder(true).SetTitle(fmt.Sprintf("Categorize %s", ip))

	list.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEscape {
			closeModal()
			return nil
		}
		return event
	})

	centerRow := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(nil, 0, 2, false).
		AddItem(list, 0, 3, true).
		AddItem(nil, 0, 2, false)

	modal := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(nil, 0, 2, false).
		AddItem(centerRow, 8, 0, true).
		AddItem(nil, 0, 2, false)

	cv.pages.AddPage("host-categorize", modal, true, true)
	cv.app.SetFocus(list)
}

// showHostDetails updates the details panel for the selected host
func (cv *CorrelationViewer) showHostDetails() {
	cv.updateDetailsPanel()
}

// generatePackage creates a distribution archive and shows a result modal.
// If a package is already being generated, the call is a no-op.
func (cv *CorrelationViewer) generatePackage() {
	if !cv.packageInProgress.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer cv.packageInProgress.Store(false)
		path, err := cv.correlator.GenerateDistributionPackage()
		if err != nil {
			cv.app.QueueUpdateDraw(func() {
				modal := tview.NewModal().
					SetText(fmt.Sprintf("Failed to generate package:\n%v", err)).
					AddButtons([]string{"OK"}).
					SetDoneFunc(func(_ int, _ string) {
						cv.pages.RemovePage("package-result")
						cv.app.SetFocus(cv.hostsList)
					})
				cv.pages.AddPage("package-result", modal, true, true)
				cv.app.SetFocus(modal)
			})
			return
		}
		cv.app.QueueUpdateDraw(func() {
			modal := tview.NewModal().
				SetText(fmt.Sprintf("Distribution package generated:\n\n%s", path)).
				AddButtons([]string{"OK"}).
				SetDoneFunc(func(_ int, _ string) {
					cv.pages.RemovePage("package-result")
					cv.app.SetFocus(cv.hostsList)
				})
			cv.pages.AddPage("package-result", modal, true, true)
			cv.app.SetFocus(modal)
		})
	}()
}

func (cv *CorrelationViewer) refresh() {
	cv.app.QueueUpdateDraw(func() {
		cv.updateControlsText()
		cv.updateHostsList()
		cv.updateDetailsPanel()
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
	cv.pages.RemovePage("screenshot-modal")
	cv.pages.RemovePage("correlation")
	// Release cached screenshots to free memory
	for k := range cv.screenshotCache {
		delete(cv.screenshotCache, k)
	}
	if cv.returnToMainCallback != nil {
		cv.returnToMainCallback()
	}
}

// ShowCorrelationViewer creates and displays a correlation viewer page.
// For the main TUI use showCorrelationViewer() which passes a proper returnToMain callback.
// If focusHost is non-empty, the viewer pre-selects that host and opens the screenshot modal.
func ShowCorrelationViewer(app *tview.Application, pages *tview.Pages, correlator *correlation.Correlator, returnToMainCallback func(), workspaceDir string, focusHost ...string) {
	correlationViewer := NewCorrelationViewer(app, pages, correlator, returnToMainCallback, workspaceDir)
	pages.AddPage("correlation", correlationViewer, true, true)
	app.SetFocus(correlationViewer.hostsList)

	// Pre-select host and open screenshot modal if requested
	if len(focusHost) > 0 && focusHost[0] != "" {
		correlationViewer.selectHostByIP(focusHost[0])
		correlationViewer.showScreenshotModal()
	}
}

// selectHostByIP finds and selects a host in the table by its IP address.
func (cv *CorrelationViewer) selectHostByIP(ip string) {
	for row := 1; row < cv.hostsList.GetRowCount(); row++ {
		cell := cv.hostsList.GetCell(row, 0)
		if cell != nil && cell.Text == ip {
			cv.hostsList.Select(row, 0)
			cv.selectedHost = ip
			cv.updateDetailsPanel()
			return
		}
	}
}

// showNoScreenshotsNotice displays a brief modal when the selected host has no screenshots.
func (cv *CorrelationViewer) showNoScreenshotsNotice() {
	modal := tview.NewModal().
		SetText("No screenshots available for this host.\n\nRun the web screenshot script to capture screenshots.").
		AddButtons([]string{"OK"}).
		SetDoneFunc(func(_ int, _ string) {
			cv.pages.RemovePage("screenshot-notice")
			cv.app.SetFocus(cv.hostsList)
		})
	cv.pages.AddPage("screenshot-notice", modal, true, true)
	cv.app.SetFocus(modal)
}

// showScreenshotModal opens a full-screen modal to display screenshots for the selected host.
func (cv *CorrelationViewer) showScreenshotModal() {
	if cv.selectedHost == "" {
		return
	}

	result, exists := cv.correlator.GetCorrelationForHost(cv.selectedHost)
	if !exists {
		return
	}

	screenshots := correlation.GetScreenshotsForHost(result)
	if len(screenshots) == 0 {
		cv.showNoScreenshotsNotice()
		return
	}

	// Track current screenshot index for cycling
	currentIdx := 0

	// Create image widget
	imgWidget := tview.NewImage()
	imgWidget.SetBorder(true).SetTitle("Screenshot")

	// Create info bar at the bottom
	infoBar := tview.NewTextView().SetDynamicColors(true)
	infoBar.SetBorder(true).SetTitle("Info")

	// Helper to update the modal content
	updateView := func() {
		ss := screenshots[currentIdx]
		title := fmt.Sprintf("Screenshot [%d/%d]", currentIdx+1, len(screenshots))
		errLine := ""

		if img, err := cv.loadScreenshot(ss.File); err == nil {
			imgWidget.SetImage(img)
		} else {
			imgWidget.SetImage(nil)
			title += " [red](load error)[::-]"
			errLine = fmt.Sprintf("\n[red]Error:[::-] [gray]%v[::-]", err)
		}
		imgWidget.SetTitle(title)

		infoBar.SetText(fmt.Sprintf(
			"[yellow]URL:[::-] [white]%s[::-]   [yellow]Status:[::-] [white]%s[::-]   [yellow]File:[::-] [gray]%s[::-]%s\n\n[gray]Controls: [yellow]n[gray]=next  [yellow]p[gray]=prev  [yellow]o[gray]=open externally  [yellow]Esc/q[gray]=close",
			ss.URL, ss.StatusCode, ss.File, errLine,
		))
	}

	// Layout
	modal := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(imgWidget, 0, 1, true).
		AddItem(infoBar, 5, 0, false)

	// Key bindings for the modal
	modal.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEscape:
			cv.pages.RemovePage("screenshot-modal")
			cv.app.SetFocus(cv.hostsList)
			return nil
		case tcell.KeyRune:
			switch event.Rune() {
			case 'q':
				cv.pages.RemovePage("screenshot-modal")
				cv.app.SetFocus(cv.hostsList)
				return nil
			case 'n':
				if currentIdx < len(screenshots)-1 {
					currentIdx++
					updateView()
				}
				return nil
			case 'p':
				if currentIdx > 0 {
					currentIdx--
					updateView()
				}
				return nil
			case 'o':
				// Open screenshot externally
				ss := screenshots[currentIdx]
				cv.app.Suspend(func() {
					cmd := exec.Command("xdg-open", ss.File)
					if err := cmd.Run(); err != nil {
						fmt.Fprintf(os.Stderr, "failed to open %s: %v\n", ss.File, err)
					}
				})
				return nil
			}
		}
		return event
	})

	updateView()
	cv.pages.AddPage("screenshot-modal", modal, true, true)
	cv.app.SetFocus(modal)
}

// loadScreenshot loads a screenshot file from disk and caches it.
func (cv *CorrelationViewer) loadScreenshot(path string) (image.Image, error) {
	if img, ok := cv.screenshotCache[path]; ok {
		return img, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open screenshot: %w", err)
	}
	defer file.Close()

	img, _, err := image.Decode(file)
	if err != nil {
		return nil, fmt.Errorf("failed to decode screenshot: %w", err)
	}

	cv.screenshotCache[path] = img
	return img, nil
}
