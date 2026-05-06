package ui

import (
	"fmt"
	"image"
	"image/draw"
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

	xdraw "golang.org/x/image/draw"

	"netutil/internal/correlation"
)

const (
	catUnknown       = "unknown"
	catWindows       = "windows"
	catLinux         = "linux"
	catNetworkDevice = "network_device"
	colorGreen       = "green"
	colorYellow      = "yellow"
	colorGray        = "gray"
	portStatusOpen   = "open"
)

// hostCategory returns the ph7 category from HostInfo.Attributes ("windows",
// "linux", "network_device", or "unknown"). Falls back to "unknown" if unset.
func hostCategory(result *correlation.CorrelationResult) string {
	if result != nil && result.HostInfo != nil {
		if cat, ok := result.HostInfo.Attributes["category"]; ok && cat != "" {
			return cat
		}
	}
	return catUnknown
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
		if p.State == portStatusOpen {
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
	case catWindows:
		return 0
	case catLinux:
		return 1
	case catNetworkDevice:
		return 2
	default:
		return 3
	}
}

// categoryTcellColor returns the tcell display color for a category (for table cells).
func categoryTcellColor(cat string) tcell.Color {
	switch cat {
	case catWindows:
		return tcell.ColorGreen
	case catLinux:
		return tcell.ColorYellow
	case catNetworkDevice:
		return tcell.ColorBlue
	default:
		return tcell.ColorGray
	}
}

// categoryTviewColor returns the tview markup color name for a category (for TextView).
func categoryTviewColor(cat string) string {
	switch cat {
	case catWindows:
		return colorGreen
	case catLinux:
		return colorYellow
	case catNetworkDevice:
		return "aqua"
	default:
		return colorGray
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
		if p.State != portStatusOpen {
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
var filterCategories = []string{"", catWindows, catLinux, catNetworkDevice, catUnknown}

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
	str        *Strings

	// UI components
	hostsList    *tview.Table
	detailsPanel *tview.TextView
	controlsText *tview.TextView

	// State
	selectedHost         string
	selectedRow          int    // last known row position (1-based; 0 = header); used for neighbor selection after categorization
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
func NewCorrelationViewer(app *tview.Application, pages *tview.Pages, correlator *correlation.Correlator, returnToMainCallback func(), workspaceDir string, str *Strings) *CorrelationViewer {
	cv := &CorrelationViewer{
		Flex:                 tview.NewFlex(),
		app:                  app,
		pages:                pages,
		correlator:           correlator,
		str:                  str,
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
	cv.hostsList.SetBorder(true).SetTitle(cv.str.PaneTitleHostInventory)

	// Create details panel
	cv.detailsPanel = tview.NewTextView().SetDynamicColors(true).SetScrollable(true)
	cv.detailsPanel.SetBorder(true).SetTitle(cv.str.PaneTitleHostDetails)

	// Create controls panel
	cv.controlsText = tview.NewTextView().SetDynamicColors(true)
	cv.controlsText.SetBorder(true).SetTitle(cv.str.PaneTitleControls)
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
		filterLine = cv.str.CorrResetSearch
	case cv.filterCategory != "":
		filterLine = fmt.Sprintf(cv.str.FmtCorrFilterActiveCat, cv.str.CategoryDisplayLabel(cv.filterCategory))
	default:
		filterLine = cv.str.CorrCycleFilter
	}
	cv.controlsText.SetText(fmt.Sprintf(cv.str.FmtCorrControlsText, filterLine))
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
			case 't':
				cv.generateTopology()
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
				cv.selectedRow = row
				cv.updateDetailsPanel()
			}
		}
	})

}

// updateHostsList refreshes the hosts table with category-sorted inventory data.
func (cv *CorrelationViewer) updateHostsList() {
	catLabel := cv.str.CategoryDisplayLabel(cv.filterCategory)
	title := cv.str.PaneTitleHostInventory
	switch {
	case catLabel != "" && cv.filterText != "":
		title = fmt.Sprintf(cv.str.FmtHostInventoryFilterCat, tview.Escape(fmt.Sprintf("[%s · search: %s]", catLabel, cv.filterText)))
	case catLabel != "":
		title = fmt.Sprintf(cv.str.FmtHostInventoryFilterCat, tview.Escape(fmt.Sprintf("[%s]", catLabel)))
	case cv.filterText != "":
		title = fmt.Sprintf(cv.str.FmtHostInventoryFilterText, tview.Escape(fmt.Sprintf("[search: %s]", cv.filterText)))
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
		{cv.str.HostColIP, 0, 0},
		{cv.str.HostColCategory, 0, 0},
		{cv.str.HostColHostname, 1, 30},
		{cv.str.HostColVendor, 0, 20},
		{cv.str.HostColPorts, 2, 0},
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

	// If the previously selected host is no longer visible (filtered out,
	// or just categorized and cleared), select the nearest neighbor at the
	// previous row position so the user can continue working.
	if !found && cv.selectedRow > 0 && len(entries) > 0 {
		candidate := cv.selectedRow
		if candidate > len(entries) {
			candidate = len(entries)
		}
		if candidate < 1 {
			candidate = 1
		}
		reSelectRow = candidate
	}

	if cv.hostsList.GetRowCount() > 1 {
		cv.hostsList.Select(reSelectRow, 0)
	}
}

// updateDetailsPanel renders host identity, classification, and port data for the selected host.
func (cv *CorrelationViewer) updateDetailsPanel() {
	if cv.selectedHost == "" {
		cv.detailsPanel.SetText(cv.str.HostDetailsSelectPrompt)
		return
	}

	result, exists := cv.correlator.GetCorrelationForHost(cv.selectedHost)
	if !exists {
		cv.detailsPanel.SetText(cv.str.HostDetailsNoData)
		return
	}

	var b strings.Builder

	// --- Identity ---
	b.WriteString(cv.str.HostDetailsIdentity)
	fmt.Fprintf(&b, "IP:       [white]%s[::-]\n", result.Host)
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
	fmt.Fprintf(&b, "MAC:      [white]%s[::-]\n", mac)
	fmt.Fprintf(&b, "Hostname: [white]%s[::-]\n", hostname)
	fmt.Fprintf(&b, "NetBIOS:  [white]%s[::-]\n", netbios)
	fmt.Fprintf(&b, "OS:       [white]%s[::-]\n", osStr)
	b.WriteString("\n")

	// --- Classification ---
	b.WriteString(cv.str.HostDetailsClassification)
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
	fmt.Fprintf(&b, "Category:   [%s]%s[::-]\n", categoryTviewColor(cat), cat)
	fmt.Fprintf(&b, "Vendor:     [white]%s[::-]\n", vendor)
	if score != "-" {
		fmt.Fprintf(&b, "Confidence: [white]%s[::-]  (score %s)\n", confidence, score)
	} else {
		fmt.Fprintf(&b, "Confidence: [white]%s[::-]\n", confidence)
	}
	if result.HostInfo != nil {
		if ttl, ok := result.HostInfo.Attributes["ttl_normalized"]; ok && ttl != "" {
			fmt.Fprintf(&b, "TTL:        [white]%s[::-]\n", ttl)
		}
	}
	b.WriteString("\n")

	// --- Ports & Services ---
	var openPorts []correlation.Port
	if result.HostInfo != nil {
		for _, p := range result.HostInfo.Ports {
			if p.State == portStatusOpen {
				openPorts = append(openPorts, p)
			}
		}
	}
	fmt.Fprintf(&b, cv.str.FmtHostDetailsPorts, len(openPorts))
	if len(openPorts) == 0 {
		b.WriteString(cv.str.HostDetailsNoOpenPorts)
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
			fmt.Fprintf(&b, "[white]%d/%s[::-]  %-8s  %s\n",
				p.Number, p.Protocol, svc, ver)
		}
	}

	// --- Screenshots ---
	screenshots := correlation.GetScreenshotsForHost(result)
	fmt.Fprintf(&b, cv.str.FmtHostDetailsScreenshots, len(screenshots))
	if len(screenshots) == 0 {
		b.WriteString(cv.str.HostDetailsNoScreenshots)
	} else {
		for i, ss := range screenshots {
			statusColor := colorGreen
			if ss.StatusCode != "200" {
				statusColor = colorYellow
			}
			fmt.Fprintf(&b, "[%s]%d.[:-] [white]%s[::-]  [gray](%s)[::-]\n",
				statusColor, i+1, ss.URL, ss.StatusCode)
		}
		b.WriteString(cv.str.HostDetailsPressS)
	}

	cv.detailsPanel.SetText(b.String())
}

// openHostSearchModal opens a compact modal for entering a text filter.
// Enter applies the filter; Esc cancels.
func (cv *CorrelationViewer) openHostSearchModal() {
	inputField := tview.NewInputField().
		SetLabel(cv.str.FilterLabel).
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
	contentBox.SetBorder(true).SetTitle(cv.str.PaneTitleFilterHosts)

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
				// Clear the IP so updateHostsList selects the neighbor at the
				// old row position instead of re-selecting the categorized host.
				cv.selectedHost = ""
				cv.updateHostsList()
				cv.updateDetailsPanel()
			})
		}()
	}

	list := tview.NewList().
		AddItem(cv.str.CatModalWindows, "", '1', func() { applyCategory(catWindows) }).
		AddItem(cv.str.CatModalLinux, "", '2', func() { applyCategory(catLinux) }).
		AddItem(cv.str.CatModalNetDevice, "", '3', func() { applyCategory(catNetworkDevice) }).
		AddItem(cv.str.BtnCancel, "", 'q', closeModal)
	list.SetBorder(true).SetTitle(fmt.Sprintf(cv.str.FmtCatModalTitle, ip))

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

// generateTopology generates the interactive HTML topology viewer and opens it in a browser.
func (cv *CorrelationViewer) generateTopology() {
	correlations := cv.correlator.GetAllCorrelations()
	if len(correlations) == 0 {
		modal := tview.NewModal().
			SetText(cv.str.TopoNoData).
			AddButtons([]string{"OK"}).
			SetDoneFunc(func(_ int, _ string) {
				cv.pages.RemovePage("topology-result")
				cv.app.SetFocus(cv.hostsList)
			})
		cv.pages.AddPage("topology-result", modal, true, true)
		cv.app.SetFocus(modal)
		return
	}

	go func() {
		tg := correlation.NewTopologyGenerator(cv.workspaceDir)
		htmlPath, err := tg.GenerateHTMLViewer(correlations)
		if err != nil {
			cv.showTopologyError(err)
			return
		}

		// Try to open in browser
		cv.app.Suspend(func() {
			cmd := exec.Command("xdg-open", htmlPath)
			_ = cmd.Run()
		})

		cv.app.QueueUpdateDraw(func() {
			modal := tview.NewModal().
				SetText(fmt.Sprintf(cv.str.FmtTopoResult, htmlPath)).
				AddButtons([]string{"OK"}).
				SetDoneFunc(func(_ int, _ string) {
					cv.pages.RemovePage("topology-result")
					cv.app.SetFocus(cv.hostsList)
				})
			cv.pages.AddPage("topology-result", modal, true, true)
			cv.app.SetFocus(modal)
		})
	}()
}

// showTopologyError displays a topology generation error in a modal.
func (cv *CorrelationViewer) showTopologyError(err error) {
	cv.app.QueueUpdateDraw(func() {
		modal := tview.NewModal().
			SetText(fmt.Sprintf("Failed to generate topology:\n%v", err)).
			AddButtons([]string{"OK"}).
			SetDoneFunc(func(_ int, _ string) {
				cv.pages.RemovePage("topology-result")
				cv.app.SetFocus(cv.hostsList)
			})
		cv.pages.AddPage("topology-result", modal, true, true)
		cv.app.SetFocus(modal)
	})
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

// Close closes the correlation viewer.
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
func ShowCorrelationViewer(app *tview.Application, pages *tview.Pages, correlator *correlation.Correlator, returnToMainCallback func(), workspaceDir string, str *Strings, focusHost ...string) {
	correlationViewer := NewCorrelationViewer(app, pages, correlator, returnToMainCallback, workspaceDir, str)
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
// Images are rendered as colored halfblock Unicode characters via tcell's cell
// buffer (screen.SetContent). This approach works with any terminal and avoids
// the timing/fd issues of writing escape sequences directly to /dev/tty.
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

	currentIdx := 0
	// Cached cell data for the image. Rebuilt when image or dimensions change.
	var cachedCells []tcellCell
	var cachedCellW, cachedCellH int

	// imageBox displays the screenshot as colored halfblock characters.
	// SetDrawFunc is called during Box.Draw, after the border is drawn.
	// The callback uses screen.SetContent to place each colored cell.
	imageBox := tview.NewBox().SetBorder(true).SetTitle("Screenshot")
	imageBox.SetDrawFunc(func(screen tcell.Screen, x, y, w, h int) (int, int, int, int) {
		// The callback receives the outer rect (including border).
		// Inner area starts at (x+1, y+1) with size (w-2, h-2).
		innerX := x + 1
		innerY := y + 1
		innerW := w - 2
		innerH := h - 2
		if innerW <= 0 || innerH <= 0 {
			return innerX, innerY, innerW, innerH
		}

		// Rebuild cell data if image or dimensions changed.
		if innerW != cachedCellW || innerH != cachedCellH || len(cachedCells) != innerW*innerH {
			ss := screenshots[currentIdx]
			if img, err := cv.loadScreenshot(ss.File); err == nil {
				cachedCells = renderHalfblocks(img, innerW, innerH)
			} else {
				cachedCells = nil
			}
			cachedCellW = innerW
			cachedCellH = innerH
		}

		// Write cells to the tcell buffer.
		for i, c := range cachedCells {
			row := i / innerW
			col := i % innerW
			screen.SetContent(innerX+col, innerY+row, c.char, nil,
				tcell.StyleDefault.Foreground(c.fg).Background(c.bg))
		}

		return innerX, innerY, innerW, innerH
	})

	infoBar := tview.NewTextView().SetDynamicColors(true)
	infoBar.SetBorder(true).SetTitle("Info")

	// Layout
	modal := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(imageBox, 0, 1, true).
		AddItem(infoBar, 5, 0, false)

	// closeScreenshot removes the modal.
	closeScreenshot := func() {
		cv.pages.RemovePage("screenshot-modal")
		cv.app.SetFocus(cv.hostsList)
	}

	// updateView updates the info bar and invalidates the render cache.
	// The next draw cycle will regenerate and display the image.
	updateView := func() {
		ss := screenshots[currentIdx]
		title := fmt.Sprintf("Screenshot [%d/%d]", currentIdx+1, len(screenshots))
		errLine := ""

		if _, err := cv.loadScreenshot(ss.File); err != nil {
			title += " [red](load error)[::-]"
			errLine = fmt.Sprintf("\n[red]Error:[::-] [gray]%v[::-]", err)
		}
		imageBox.SetTitle(title)

		infoBar.SetText(fmt.Sprintf(
			"[yellow]URL:[::-] [white]%s[::-]   [yellow]Status:[::-] [white]%s[::-]   [yellow]File:[::-] [gray]%s[::-]%s\n\n[gray]Controls: [yellow]n[gray]=next  [yellow]p[gray]=prev  [yellow]o[gray]=open externally  [yellow]Esc/q[gray]=close",
			ss.URL, ss.StatusCode, ss.File, errLine,
		))

		// Invalidate cache to force re-render on next draw.
		cachedCells = nil
		cachedCellW = 0
		cachedCellH = 0
	}

	// Key bindings
	modal.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEscape:
			closeScreenshot()
			return nil
		case tcell.KeyRune:
			switch event.Rune() {
			case 'q':
				closeScreenshot()
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

	cv.pages.AddPage("screenshot-modal", modal, true, true)
	cv.app.SetFocus(modal)
	updateView()
	cv.app.ForceDraw()
}

// tcellCell holds a single character cell with foreground and background colors.
type tcellCell struct {
	char rune
	fg   tcell.Color
	bg   tcell.Color
}

// renderHalfblocks converts an image.Image into a grid of colored halfblock
// cells. Each cell uses the '▀' (upper half block) rune with the top pixel's
// color as foreground and the bottom pixel's color as background. This gives
// 2x vertical resolution per cell row.
func renderHalfblocks(img image.Image, cellW, cellH int) []tcellCell {
	bounds := img.Bounds()
	imgW := bounds.Dx()
	imgH := bounds.Dy()
	if imgW <= 0 || imgH <= 0 || cellW <= 0 || cellH <= 0 {
		return nil
	}

	cells := make([]tcellCell, cellW*cellH)

	// Pre-resize source image to exact half-block pixel dimensions using
	// high-quality CatmullRom interpolation. This avoids aliasing artifacts
	// from point-sampling when source and target dimensions don't match.
	targetW := cellW
	targetH := cellH * 2 // 2 pixel rows per cell (top=foreground, bottom=background)
	resized := image.NewRGBA(image.Rect(0, 0, targetW, targetH))
	xdraw.CatmullRom.Scale(resized, resized.Bounds(), img, img.Bounds(), draw.Over, nil)

	// Sample 1:1 from the resized image — no scaling math needed.
	for row := 0; row < cellH; row++ {
		for col := 0; col < cellW; col++ {
			topR, topG, topB, _ := resized.RGBAAt(col, row*2).RGBA()
			botR, botG, botB, _ := resized.RGBAAt(col, row*2+1).RGBA()

			cells[row*cellW+col] = tcellCell{
				char: '▀',
				fg:   tcell.NewRGBColor(int32(topR>>8), int32(topG>>8), int32(topB>>8)),
				bg:   tcell.NewRGBColor(int32(botR>>8), int32(botG>>8), int32(botB>>8)),
			}
		}
	}

	return cells
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
	defer func() { _ = file.Close() }()

	img, _, err := image.Decode(file)
	if err != nil {
		return nil, fmt.Errorf("failed to decode screenshot: %w", err)
	}

	cv.screenshotCache[path] = img
	return img, nil
}
