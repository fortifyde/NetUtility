package ui

// Strings holds all user-visible strings for one locale.
// Every exported field corresponds to one translatable UI element.
type Strings struct {
	// ── Panel titles ──────────────────────────────────────────────────────────
	PaneTitleProgramInfo       string
	PaneTitleCategories        string
	PaneTitleTaskDefault       string
	PaneTitleQuickRef          string
	PaneTitleSearch            string
	PaneTitleActiveJobs        string
	PaneTitleStatistics        string
	PaneTitleControls          string
	PaneTitleScriptOutput      string
	PaneTitleSearchOutput      string
	PaneTitleDiscoveryStats    string
	PaneTitleCategoryBreakdown string
	PaneTitleJobActivity       string
	PaneTitleRiskOverview      string
	PaneTitleHostRisk          string
	PaneTitleServiceLandscape  string
	PaneTitleDashControls      string
	PaneTitleHostInventory     string
	PaneTitleHostDetails       string
	PaneTitleFilterHosts       string

	// ── Header ────────────────────────────────────────────────────────────────
	// FmtHeaderText: Sprintf(fmt, AppName, AppVersion)
	FmtHeaderText string

	// ── Info panel (bottom bar) ───────────────────────────────────────────────
	InfoCatLine1       string // categories-focused, line 1
	InfoCatLine2       string // categories-focused, line 2
	FmtInfoTaskLine1   string // task-focused with category (no longer a format string)
	InfoTaskNoCatLine1 string // task-focused, no category selected
	InfoGlobalLine     string // second line for task-focused states
	InfoDefaultLine1   string // default state, line 1
	InfoDefaultLine2   string // default state, line 2

	// ── Task pane ─────────────────────────────────────────────────────────────
	FmtTasksTitle string // Sprintf(fmt, categoryName)

	// ── Search ────────────────────────────────────────────────────────────────
	SearchLabel string

	// ── Subtask modal ─────────────────────────────────────────────────────────
	SubtaskSelectOp string

	// ── Help ──────────────────────────────────────────────────────────────────
	HelpText         string
	HelpTitle        string
	OutputHelpTitle  string

	// ── Buttons ───────────────────────────────────────────────────────────────
	BtnOK            string
	BtnCancel        string
	BtnQuit          string
	BtnQueueJob      string
	BtnViewJobs      string
	BtnClose         string
	BtnYes           string
	BtnNo            string
	BtnViewInventory string

	// ── Job queue / execution modals ──────────────────────────────────────────
	TitleJobQueued       string
	FmtJobQueued         string // Sprintf(fmt, taskName)
	TitleJobStarted      string
	FmtJobStarted        string // Sprintf(fmt, taskName)
	FmtConfirmQuit       string // Sprintf(fmt, runningJobs)
	TitleScriptNotFound  string
	FmtScriptNotFound    string // Sprintf(fmt, taskName)
	TitlePathError       string
	FmtPathError         string // Sprintf(fmt, err)
	TitleConnectionError string
	FmtConnectionError   string // Sprintf(fmt, err)
	FmtExecutionOptions  string // Sprintf(fmt, taskName)

	// ── Category display names ────────────────────────────────────────────────
	CatNetworkSetup     string
	CatSystemUtilities  string
	CatNetworkDiscovery string
	CatCaptureAnalysis  string
	CatPortScanning     string
	CatReconnaissance   string
	CatConfigGathering  string

	// ── Hardcoded fallback task names & descriptions ──────────────────────────
	TaskSelectWorkDir              string
	TaskSelectWorkDirDesc          string
	TaskConfigInterfaces           string
	TaskConfigInterfacesDesc       string
	TaskInterfaceStates            string
	TaskInterfaceStatesDesc        string
	TaskVLANInterfaces             string
	TaskVLANInterfacesDesc         string
	TaskConfigureIP                string
	TaskConfigureIPDesc            string
	TaskConfigureRoutes            string
	TaskConfigureRoutesDesc        string
	TaskConfigureNameservers       string
	TaskConfigureNameserversDesc   string
	TaskBackupConfig               string
	TaskBackupConfigDesc           string
	TaskRestoreConfig              string
	TaskRestoreConfigDesc          string
	TaskNetworkCapture             string
	TaskNetworkCaptureDesc         string
	TaskExtractVLANIDs             string
	TaskExtractVLANIDsDesc         string
	TaskMultiPhaseDiscovery        string
	TaskMultiPhaseDiscoveryDesc    string
	TaskHostCategorization         string
	TaskHostCategorizationDesc     string
	TaskPortServiceScan            string
	TaskPortServiceScanDesc        string
	TaskVulnAssessment             string
	TaskVulnAssessmentDesc         string
	TaskSNMPInterrogate         string
	TaskSNMPInterrogateDesc     string
	TaskWebScreenshot           string
	TaskWebScreenshotDesc       string
	TaskExploitSearch           string
	TaskExploitSearchDesc       string
	TaskDeviceConfigGathering      string
	TaskDeviceConfigGatheringDesc  string
	TaskNetworkCaptureAnalysis     string
	TaskNetworkCaptureAnalysisDesc string

	// ── Jobs viewer ───────────────────────────────────────────────────────────
	JobsHeaderID        string
	JobsHeaderName      string
	JobsHeaderStatus    string
	JobsHeaderDuration  string
	JobsHeaderProgress  string
	JobsControlsText    string
	FmtJobStats         string // multi-line format; args: total,running,max,pending,completed,failed,cancelled,running,max
	ProgressWaiting     string
	ProgressRunning     string
	ProgressDone        string
	ProgressFailed      string
	ProgressCancelled   string
	ProgressUnknown     string
	FmtSetMaxConcurrent string // Sprintf(fmt, max)
	FmtMaxConcurrentSet string // Sprintf(fmt, max)
	FmtRemovedCompleted string // Sprintf(fmt, count)
	ErrJobNotFound      string
	FmtErrConnectJob    string // Sprintf(fmt, err)
	ErrNoOutputCaptured string
	ErrNoJobSelected    string
	FmtErrCancelJob     string // Sprintf(fmt, err)
	FmtShowErrorPrefix  string // Sprintf(fmt, message)

	// ── Output viewer ─────────────────────────────────────────────────────────
	StatusReady         string
	StatusInputMode     string
	StatusViewMode      string
	StatusWaitingInput  string
	StatusPasswordInput string
	StatusInputSent     string
	FmtStatusProgress   string // Sprintf(fmt, progressText)
	FmtStatusCompletion string // Sprintf(fmt, color)
	FmtScriptCompleted  string // Sprintf(fmt, statusLower, duration)
	FmtTitleWithJobs    string // Sprintf(fmt, jobCount, scriptName, status)
	FmtTitleNoJobs      string // Sprintf(fmt, scriptPath, status)
	OutputViewerHelp    string
	FmtHistoricalStatus string // Sprintf(fmt, colorName, statusStr)
	FmtReconnected      string // Sprintf(fmt, maxLines, totalLines)
	OutputGlobalLine     string

	// ── Dashboard ─────────────────────────────────────────────────────────────
	DashControlsText     string
	DashHeaderScore      string
	DashHeaderIP         string
	DashHeaderHostname   string
	DashHeaderCategory   string
	DashHeaderTopFinding string
	DashNoHostsYet       string
	FmtTopFindingMedium  string // Sprintf(fmt, count)
	FmtTopFindingPorts   string // Sprintf(fmt, count)
	TopFindingNone       string

	// Panel body strings
	DashStatsHeading            string
	FmtDashStatsHostsDiscovered string // Sprintf(fmt, count)
	FmtDashStatsWindows         string // Sprintf(fmt, count)
	FmtDashStatsLinux           string // Sprintf(fmt, count)
	FmtDashStatsNetDevices      string // Sprintf(fmt, count)
	FmtDashStatsUnknown         string // Sprintf(fmt, count)
	FmtDashStatsServices        string // Sprintf(fmt, count)
	DashJobsHeading             string
	FmtDashJobsRunning          string // Sprintf(fmt, running, max)
	FmtDashJobsCompleted        string // Sprintf(fmt, count)
	FmtDashJobsFailed           string // Sprintf(fmt, count)
	FmtDashLastScan             string // Sprintf(fmt, timeStr)
	DashNoChartYet              string
	FmtDashCategoryBar          string // Sprintf(fmt, color, label, color, bar, count)
	DashNoActivityYet           string
	DashNoHostsDiscovered       string
	DashRiskDistHeading         string
	DashSevSummaryHeading       string
	DashBySourceHeading         string
	FmtDashNiktoFindings        string // Sprintf(fmt, count)
	FmtDashSSLIssues            string // Sprintf(fmt, count)
	FmtDashAvgScore             string // Sprintf(fmt, score)
	FmtDashHighestRisk          string // Sprintf(fmt, ip, score)
	FmtDashRiskTierLine         string // Sprintf(fmt, color, riskLabel, count)
	DashTopServicesHeading      string
	FmtDashServiceEntry         string // Sprintf(fmt, name, count)
	DashPortsHeading            string
	FmtDashUniqueOpenPorts      string // Sprintf(fmt, count)
	FmtDashMostExposedHost      string // Sprintf(fmt, ip, count)
	FmtHostOpenPorts            string // Sprintf(fmt, portsList)
	FmtFindingsCount            string // Sprintf(fmt, finding, totalCount)

	RiskTierCritical          string
	RiskTierHigh              string
	RiskTierMedium            string
	RiskTierLow               string
	SevCritical               string
	SevHigh                   string
	SevMedium                 string
	SevLow                    string
	SevInfo                   string
	FmtSevFindings            string // Sprintf(fmt, sevLabel)
	FmtSevFindingsCount       string // Sprintf(fmt, sevLabel, count)
	FmtAndMore                string // Sprintf(fmt, count)
	FmtRiskScore              string // Sprintf(fmt, color, score, color, tierLabel)
	FmtRiskBreakdownVulns     string
	FmtRiskBreakdownService   string
	FmtRiskBreakdownSSL       string
	FmtRiskBreakdownPorts     string
	FmtRiskFactorCategory     string // Sprintf(fmt, category, count)
	FmtRiskFactorLine         string // Sprintf(fmt, title, score, source)
	FmtHostRiskDetailWithHost string // Sprintf(fmt, ip, hostname, extra)
	FmtHostRiskDetail         string // Sprintf(fmt, ip, extra)
	FmtRiskDetailTitle        string // Sprintf(fmt, ip)

	// ── Correlation viewer ────────────────────────────────────────────────────
	FmtCorrControlsText        string // Sprintf(fmt, filterLine)
	CorrResetSearch            string
	FmtCorrFilterActiveCat     string // Sprintf(fmt, catLabel)
	CorrCycleFilter            string
	HostColIP                  string
	HostColCategory            string
	HostColHostname            string
	HostColVendor              string
	HostColPorts               string
	HostDetailsSelectPrompt    string
	HostDetailsNoData          string
	HostDetailsIdentity        string
	HostDetailsClassification  string
	FmtHostDetailsPorts        string // Sprintf(fmt, count)
	HostDetailsNoOpenPorts     string
	FmtHostDetailsScreenshots  string // Sprintf(fmt, count)
	HostDetailsNoScreenshots   string
	HostDetailsPressS          string
	CatDisplayWindows          string
	CatDisplayLinux            string
	CatDisplayNetDevice        string
	CatDisplayUnknown          string
	FmtHostInventoryFilterCat  string // Sprintf(fmt, catLabel)
	FmtHostInventoryFilterText string // Sprintf(fmt, filterText)
	CatModalWindows            string
	CatModalLinux              string
	CatModalNetDevice          string
	FmtCatModalTitle           string // Sprintf(fmt, ip)
	// ── Topology viewer ────────────────────────────────────────────────────
	FmtTopoResult string // Sprintf(fmt, htmlPath)
	TopoNoData    string


	// ── Main view panels ────────────────────────────────────────────────────
	PaneTitleAssessment        string
	AssessmentPhaseCapture     string
	AssessmentPhaseSysConfig   string
	AssessmentPhaseDiscovery   string
	AssessmentPhaseCategorize  string
	AssessmentPhasePortVuln    string
	AssessmentPhaseDevConfig   string
	FmtAssessmentUncategorized string // Sprintf(fmt, count)

	PaneTitleActiveJobsPanel string
	JobsPanelNoActive        string
	FmtJobsPanelNeedsInput   string
	ProgressWaitingInput     string

	// ── Filter ────────────────────────────────────────────────────────────────
	FilterLabel string

	// ── Global status footer ─────────────────────────────────────────────────
	FmtGlobalStatusProgress   string // Sprintf(fmt, jobName, progressText)
	FmtGlobalStatusSpinner    string // Sprintf(fmt, jobName)
	FmtGlobalStatusVLANs      string // Sprintf(fmt, jobName, completed, total, vlanSummary)
	FmtGlobalStatusNeedsInput string // Sprintf(fmt, jobName)

	// ── VLAN breakdown ────────────────────────────────────────────────────────
	VLANDone       string
	VLANUnknown    string
	FmtVLANEntry   string // Sprintf(fmt, id, current, total)
	FmtVLANEntryDone string // Sprintf(fmt, id)

	// ── Output viewer re-entry ────────────────────────────────────────────────
	FmtReconnectedProgress string // Sprintf(fmt, progressText)
}

// CategoryDisplayLabel returns the localised display label for a category key.
func (s *Strings) CategoryDisplayLabel(cat string) string {
	switch cat {
	case "windows":
		return s.CatDisplayWindows
	case "linux":
		return s.CatDisplayLinux
	case "network_device":
		return s.CatDisplayNetDevice
	case "unknown":
		return s.CatDisplayUnknown
	default:
		return ""
	}
}

// RiskLabel returns the localised label for a risk tier key (English key preserved internally).
func (s *Strings) RiskLabel(key string) string {
	switch key {
	case "Critical":
		return s.RiskTierCritical
	case "High":
		return s.RiskTierHigh
	case "Medium":
		return s.RiskTierMedium
	case "Low":
		return s.RiskTierLow
	default:
		return key
	}
}

// SeverityLabel returns the localised label for a lowercase severity key.
func (s *Strings) SeverityLabel(sev string) string {
	switch sev {
	case "critical":
		return s.SevCritical
	case "high":
		return s.SevHigh
	case "medium":
		return s.SevMedium
	case "low":
		return s.SevLow
	default:
		return s.SevInfo
	}
}

var stringsEN = &Strings{
	// Panel titles
	PaneTitleProgramInfo:       "Program Info",
	PaneTitleCategories:        "Categories",
	PaneTitleTaskDefault:       "Select a category",
	PaneTitleQuickRef:          "Quick Reference",
	PaneTitleSearch:            "Search Scripts",
	PaneTitleActiveJobs:        "Active Jobs",
	PaneTitleStatistics:        "Statistics",
	PaneTitleControls:          "Controls",
	PaneTitleScriptOutput:      "Script Output",
	PaneTitleSearchOutput:      "Search Output",
	PaneTitleDiscoveryStats:    "Discovery Stats",
	PaneTitleCategoryBreakdown: "Category Breakdown",
	PaneTitleJobActivity:       "Job Activity",
	PaneTitleRiskOverview:      "Risk Overview",
	PaneTitleHostRisk:          "Host Risk",
	PaneTitleServiceLandscape:  "Service Landscape",
	PaneTitleDashControls:      "Controls",
	PaneTitleHostInventory:     "Host Inventory",
	PaneTitleHostDetails:       "Host Details",
	PaneTitleFilterHosts:       "Filter Hosts",

	// Header
	FmtHeaderText: "[cyan::b]%s[white::-] [green]%s[white]\n[gray]Network Assessment Toolkit[-]\n\n[yellow]Keys:[white] [cyan]Tab[white]=Switch [cyan]hjkl[white]=Navigate [cyan]/[white]=Search [cyan]Ctrl+J[white]=Jobs [cyan]Ctrl+N[white]=Hosts [cyan]Ctrl+D[white]=Dashboard [cyan]q[white]=Quit",

	// Info panel
	InfoCatLine1:       "[aqua]↑↓←→/hjkl[white] Navigate  [aqua]Enter[white] Select  [aqua]Tab[white] Switch  [aqua]/[white] Search  [aqua]?[white] Help  [aqua]Esc/q[white] Quit\n",
	InfoCatLine2:       "[gray]Ctrl+J[white] Jobs   [gray]Ctrl+D[white] Dashboard   [gray]Ctrl+N[white] Hosts   [gray]Ctrl+Z[white] Main",
	FmtInfoTaskLine1:   "[aqua]↑↓←→/hjkl[white] Navigate  [aqua]Enter[white] Execute  [aqua]Tab[white] Switch  [aqua]/[white] Search  [aqua]?[white] Help  [aqua]Esc/q[white] Quit\n",
	InfoTaskNoCatLine1: "[aqua]Tab[white] Switch to categories  [aqua]/[white] Search  [aqua]?[white] Help  [aqua]Esc/q[white] Quit\n",
	InfoGlobalLine:     "[gray]Ctrl+J[white] Jobs   [gray]Ctrl+D[white] Dashboard   [gray]Ctrl+N[white] Hosts   [gray]Ctrl+Z[white] Main",
	InfoDefaultLine1:   "[aqua]↑↓←→/hjkl[white] Move  [aqua]Tab[white] Switch  [aqua]/[white] Search  [aqua]?[white] Help\n",
	InfoDefaultLine2:   "[gray]Ctrl+J[white] Jobs   [gray]Ctrl+D[white] Dashboard   [gray]Ctrl+N[white] Hosts   [gray]Ctrl+Z[white] Main   [aqua]Esc/q[white] Quit",

	// Task pane
	FmtTasksTitle: "Scripts - %s",

	// Search
	SearchLabel: "Search: ",

	// Subtask modal
	SubtaskSelectOp: "Select a script:",

	// Help
HelpText: `[yellow]Navigation:[white]
  [aqua]↑/↓ or j/k[white]    Move within current panel
  [aqua]←/→ or h/l[white]    Switch panels

[yellow]Actions:[white]
  [aqua]Enter[white]          Execute selected script
  [aqua]Esc[white] / [aqua]q[white]       Quit
  [aqua]/[white]              Search scripts
  [aqua]?[white]              Toggle this help

[yellow]Global (any view):[white]
  [aqua]Ctrl+J[white]         Job manager
  [aqua]Ctrl+D[white]         Dashboard
  [aqua]Ctrl+N[white]         Host inventory
  [aqua]Ctrl+Z[white]         Return to main

[yellow]Host Inventory ([aqua]Ctrl+N[white]):[white]
  [white][aqua]Space[white]  Categorize host   [aqua]/[white] Search   [aqua]f[white] Filter
  [white][aqua]p[white]      Package hostfiles  [aqua]t[white] Topology map

[yellow]Job Manager ([aqua]Ctrl+J[white]):[white]
  [white][aqua]1-9[white]    Set concurrency   [aqua]c[white] Cancel   [aqua]C[white] Clear done

[yellow]Tips:[white]
  [white]- Scripts run concurrently (adjust with [aqua]1-9[white] in Job Manager)
  [white]- Excess scripts queue automatically
  [white]- Scripts are auto-discovered from .meta.yaml files
  [white]- The Assessment Checklist scans script results to provide a workflow overview of typical assessment tasks`,
	HelpTitle:       "Help",
	OutputHelpTitle: "Output Viewer Help",

	// Buttons
	BtnOK:            "OK",
	BtnCancel:        "Cancel",
	BtnQuit:          "Quit",
	BtnQueueJob:      "Queue Job",
	BtnViewJobs:      "View Jobs",
	BtnClose:         "Close",
	BtnYes:           "Yes",
	BtnNo:            "No",
	BtnViewInventory: "View Host in Inventory",

	// Job queue modals
	TitleJobQueued:       "Job Queued",
	FmtJobQueued:         "'%s' has been queued for execution.\n\nPress Ctrl+J to view job manager.",
	TitleJobStarted:      "Job Started",
	FmtJobStarted:        "'%s' has been started in the background.\n\nPress Ctrl+J to view job manager.",
	FmtConfirmQuit:       "%d job(s) still running.\n\nQuit anyway? Running jobs will be abandoned.",
	TitleScriptNotFound:  "Script Not Found",
	FmtScriptNotFound:    "Could not find script: %s",
	TitlePathError:       "Path Error",
	FmtPathError:         "Could not resolve script path: %v",
	TitleConnectionError: "Connection Error",
	FmtConnectionError:   "Failed to connect to job: %v",
	FmtExecutionOptions:  "Maximum concurrent jobs reached.\n\nHow would you like to execute '%s'?",

	// Category display names
	CatNetworkSetup:     "Network Setup",
	CatSystemUtilities:  "System Utilities",
	CatNetworkDiscovery: "Network Discovery",
	CatCaptureAnalysis:  "Capture Analysis",
	CatPortScanning:     "Port Scanning",
	CatReconnaissance:   "Reconnaissance",
	CatConfigGathering:  "Config Gathering",

	// Hardcoded task names
	TaskSelectWorkDir:              "Select Working Directory",
	TaskSelectWorkDirDesc:          "Choose working directory for operations",
	TaskConfigInterfaces:           "Configure Interfaces",
	TaskConfigInterfacesDesc:       "Manage interface states or configure VLAN subinterfaces",
	TaskInterfaceStates:            "Interface States",
	TaskInterfaceStatesDesc:        "View and toggle network interfaces",
	TaskVLANInterfaces:             "VLAN Interfaces",
	TaskVLANInterfacesDesc:         "Create VLAN subinterfaces",
	TaskConfigureIP:                "Configure IP Addresses",
	TaskConfigureIPDesc:            "Set IP addresses on interfaces",
	TaskConfigureRoutes:            "Configure Routes",
	TaskConfigureRoutesDesc:        "View and configure IP routes",
	TaskConfigureNameservers:       "Configure Nameservers",
	TaskConfigureNameserversDesc:   "Set DNS nameservers",
	TaskBackupConfig:               "Backup Configuration",
	TaskBackupConfigDesc:           "Backup current network configuration",
	TaskRestoreConfig:              "Restore Configuration",
	TaskRestoreConfigDesc:          "Restore network configuration from backup",
	TaskNetworkCapture:             "Network Capture",
	TaskNetworkCaptureDesc:         "Capture network traffic with integrated security analysis and unsafe protocol detection",
	TaskExtractVLANIDs:             "Extract VLAN IDs",
	TaskExtractVLANIDsDesc:         "Extract VLAN IDs from capture files",
	TaskMultiPhaseDiscovery:        "Multi-Phase Discovery",
	TaskMultiPhaseDiscoveryDesc:    "Comprehensive network discovery with host categorization",
	TaskHostCategorization:         "Host Categorization",
	TaskHostCategorizationDesc:     "Categorize discovered hosts by OS",
	TaskPortServiceScan:            "Port & Service Scan",
	TaskPortServiceScanDesc:        "Comprehensive port scan with service version detection and OS fingerprinting",
	TaskVulnAssessment:             "Vulnerability Assessment",
	TaskVulnAssessmentDesc:         "Safe vulnerability assessment using NSE scripts and supplementary tools",
	TaskSNMPInterrogate:         "SNMP Interrogation",
	TaskSNMPInterrogateDesc:     "Query SNMP-enabled devices for system info, interfaces, ARP, VLANs, and routes",
	TaskWebScreenshot:           "Web Screenshot",
	TaskWebScreenshotDesc:       "Capture screenshots of web services discovered during scanning",
	TaskExploitSearch:           "Exploit Search",
	TaskExploitSearchDesc:       "Search exploit databases for vulnerabilities matching discovered services",
	TaskDeviceConfigGathering:      "Device Configuration Gathering",
	TaskDeviceConfigGatheringDesc:  "SSH to device, detect vendor, and gather configuration",
	TaskNetworkCaptureAnalysis:     "Network Capture Analysis",
	TaskNetworkCaptureAnalysisDesc: "Analyze VLANs, MAC addresses, or packet captures",

	// Jobs viewer
	JobsHeaderID:       "ID",
	JobsHeaderName:     "Name",
	JobsHeaderStatus:   "Status",
	JobsHeaderDuration: "Duration",
	JobsHeaderProgress: "Progress",
	JobsControlsText: `[aqua]↑↓[white] Navigate  [aqua]Enter[white] View Output  [aqua]c[white] Cancel  [aqua]C[white] Clear Done  [aqua]1-9[white] Max Jobs  [aqua]Esc/q[white] Close
[gray]Ctrl+J[white] Jobs   [gray]Ctrl+D[white] Dashboard   [gray]Ctrl+N[white] Hosts   [gray]Ctrl+Z[white] Main`,
	FmtJobStats: `[white]Total Jobs:[::-]      %d
[green]Running:[::-]         %d/%d
[blue]Pending:[::-]         %d
[green]Completed:[::-]       %d
[red]Failed:[::-]           %d
[gray]Cancelled:[::-]       %d

[yellow]Capacity:[::-]        %d/%d`,
	ProgressWaiting:     "⏳ Waiting",
	ProgressRunning:     "Running",
	ProgressDone:        "✅ Done",
	ProgressFailed:      "❌ Failed",
	ProgressCancelled:   "🚫 Cancelled",
	ProgressUnknown:     "❓ Unknown",
	FmtSetMaxConcurrent: "Set max concurrent jobs to %d?",
	FmtMaxConcurrentSet: "Max concurrent jobs set to %d",
	FmtRemovedCompleted: "Removed %d completed jobs",
	ErrJobNotFound:      "Job not found",
	FmtErrConnectJob:    "Failed to connect to job: %v",
	ErrNoOutputCaptured: "No output captured for this job",
	ErrNoJobSelected:    "No job selected",
	FmtErrCancelJob:     "Failed to cancel job: %v",
	FmtShowErrorPrefix:  "Error: %s",

	// Output viewer
	StatusReady:         "[green]Ready[white] — [aqua]Tab[white] Input Mode  [aqua]Space[white] Pause  [aqua]f[white] Follow  [aqua]t[white] Time  [aqua]s[white] Source  [aqua]/[white] Search  [aqua]g/G[white] Scroll  [aqua]?[white] Help",
	StatusInputMode:     "[yellow]Input Mode[white] — [aqua]Enter[white] Submit  [aqua]Tab[white] View Mode",
	StatusViewMode:      "[green]View Mode[white] — [aqua]Tab[white] Input Mode  [aqua]Space[white] Pause  [aqua]f[white] Follow  [aqua]t[white] Time  [aqua]s[white] Source  [aqua]/[white] Search  [aqua]g/G[white] Scroll  [aqua]?[white] Help",
	StatusWaitingInput:  "[yellow]Waiting for input[white] — [aqua]Enter[white] Submit  [aqua]Tab[white] View",
	StatusPasswordInput: "[yellow]Password input[white] — [aqua]Enter[white] Submit  [aqua]Tab[white] View",
	StatusInputSent:     "[green]Input sent[white] — Waiting for response...",
	FmtStatusProgress:   "[cyan]%s[white] — [aqua]Space[white] Pause  [aqua]f[white] Follow",
	FmtStatusCompletion: "[%s][aqua]Enter[white] Continue",
	FmtScriptCompleted:  "Script %s - Duration: %v",
	FmtTitleWithJobs:    "Script Output %s - %s [%s]",
	FmtTitleNoJobs:      "Script Output - %s [%s]",
OutputViewerHelp: `[yellow]Controls:[white]
  [aqua]Esc[white]          Cancel job and return to main
  [aqua]q[white]            Return to main (job keeps running)
  [aqua]Ctrl+C[white]       Stop script execution
  [aqua]Space[white]        Pause/resume output display
  [aqua]f[white]            Toggle auto-scroll (following)
  [aqua]t[white]            Toggle timestamp display
  [aqua]s[white]            Toggle source (stdout/stderr) display
  [aqua]/[white]            Search output
  [aqua]c[white]            Clear display
  [aqua]G[white]            Go to end
  [aqua]g[white]            Go to beginning

[yellow]Display Features:[white]
  [white]- Real-time streaming output
  [white]- Color-coded stderr (red) and stdout (green)
  [white]- Automatic highlighting of errors/warnings
  [white]- Search and filter capabilities
  [white]- Pause/resume without stopping script
  [white]- Timestamp and source information

[yellow]Script Control:[white]
  [white]- Scripts can be cancelled with [aqua]Esc[white] (kills the job)
  [white]- Press [aqua]q[white] to return to main while keeping the job running
  [white]- Input can be sent to interactive scripts
  [white]- Full execution history is maintained`,
	FmtHistoricalStatus: "[%s]%s - read-only[::-] | Esc=Close | Enter=Close",
	FmtReconnected:      "──── Reconnected - showing last %d of %d total lines ────",
	OutputGlobalLine:    "[gray]Ctrl+J[white] Jobs   [gray]Ctrl+D[white] Dashboard   [gray]Ctrl+N[white] Hosts   [gray]Ctrl+Z[white] Main   [aqua]Esc/q[white] Back",

	// Dashboard
	DashControlsText:     "[aqua]Enter[white] Risk Details  [aqua]Esc/q[white] Close\n[gray]Ctrl+J[white] Jobs   [gray]Ctrl+D[white] Dashboard   [gray]Ctrl+N[white] Hosts   [gray]Ctrl+Z[white] Main",
	DashHeaderScore:      "Score",
	DashHeaderIP:         "IP",
	DashHeaderHostname:   "Hostname",
	DashHeaderCategory:   "Category",
	DashHeaderTopFinding: "Top Finding (Total)",
	DashNoHostsYet:       "No hosts discovered yet — run Network Discovery to populate.",
	FmtTopFindingMedium:  "%d medium-severity vulns",
	FmtTopFindingPorts:   "%d open ports",
	TopFindingNone:       "-",

	// Panel body
	DashStatsHeading:            "[yellow]Discovery Stats[::-]\n\n",
	FmtDashStatsHostsDiscovered: "Hosts Discovered:  [white]%d[::-]\n",
	FmtDashStatsWindows:         "  Windows:         [green]%d[::-]\n",
	FmtDashStatsLinux:           "  Linux:           [yellow]%d[::-]\n",
	FmtDashStatsNetDevices:      "  Net Devices:     [blue]%d[::-]\n",
	FmtDashStatsUnknown:         "  Unknown:         [gray]%d[::-]\n",
	FmtDashStatsServices:        "Services Found:    [white]%d[::-]\n",
	DashJobsHeading:             "[yellow]Jobs[::-]\n",
	FmtDashJobsRunning:          "Running:   [green]%d[::-]/%d max\n",
	FmtDashJobsCompleted:        "Completed: [blue]%d[::-]\n",
	FmtDashJobsFailed:           "Failed:    [red]%d[::-]\n",
	FmtDashLastScan:             "\nLast Scan: [white]%s[::-]\n",
	DashNoChartYet:              "[gray]No hosts discovered yet.[::-]\n\n[gray]Run Network Discovery from[::-]\n[gray]the Scripts menu to populate.[::-]\n",
	FmtDashCategoryBar:          "[%s]%-16s[::-]  [%s]%s[::-]  [white]%d[::-]\n",
	DashNoActivityYet:           "[gray]No jobs run yet.[::-]\n[gray]Start a discovery from[::-]\n[gray]the Scripts menu.[::-]\n",
	DashNoHostsDiscovered:       "[gray]No hosts discovered yet.[::-]\n",
	DashRiskDistHeading:         "[yellow]Risk Distribution[::-]\n",
	DashSevSummaryHeading:       "\n[yellow]Severity Summary[::-]\n",
	DashBySourceHeading:         "\n[yellow]By Source[::-]\n",
	FmtDashNiktoFindings:        "  Nikto:     [white]%d findings[::-]\n",
	FmtDashSSLIssues:            "  SSL/TLS:   [white]%d issues[::-]\n",
	FmtDashAvgScore:             "\nAverage Score: [white]%d[::-]\n",
	FmtDashHighestRisk:          "Highest: [white]%s[::-] ([red]%d[::-])\n",
	FmtDashRiskTierLine:         "  [%s]■ %-9s %d hosts[::-]\n",
	DashTopServicesHeading:      "[yellow]Top Services[::-]\n",
	FmtDashServiceEntry:         "  [white]%-12s[::-] [green]%d[::-] hosts\n",
	DashPortsHeading:            "\n[yellow]Ports[::-]\n",
	FmtDashUniqueOpenPorts:      "  Unique open: [white]%d[::-]\n",
	FmtDashMostExposedHost:      "  Most exposed: [white]%s[::-] ([red]%d[::-])\n",
	FmtHostOpenPorts:            "Open Ports: [white]%s[::-]\n",
	FmtFindingsCount:            "%s (%d findings)",

	RiskTierCritical:          "Critical",
	RiskTierHigh:              "High",
	RiskTierMedium:            "Medium",
	RiskTierLow:               "Low",
	SevCritical:               "Critical",
	SevHigh:                   "High",
	SevMedium:                 "Medium",
	SevLow:                    "Low",
	SevInfo:                   "Info",
	FmtSevFindings:            "[%s]%s Findings[::-]\n",
	FmtSevFindingsCount:       "[%s]%s Findings (%d)[::-]\n",
	FmtAndMore:                "  ... and %d more\n",
	FmtRiskScore:              "Risk Score: [%s]%d/1000[%s] %s[::-]\n",
	FmtRiskBreakdownVulns:     "  Vulnerabilities:  [white]%d pts[::-]\n",
	FmtRiskBreakdownService:   "  Service Exposure: [white]%d pts[::-]\n",
	FmtRiskBreakdownSSL:       "  SSL/TLS Issues:   [white]%d pts[::-]\n",
	FmtRiskBreakdownPorts:     "  Open Ports:       [white]%d pts[::-]\n\n",
	FmtRiskFactorCategory:    "\n[white]%s (%d findings):[::-]\n",
	FmtRiskFactorLine:        "  [gray]●[::-] %s [darkgray](%d pts)%s[::-]\n",
	FmtHostRiskDetailWithHost: "[yellow]Host Risk Details: %s (%s)[::-]%s",
	FmtHostRiskDetail:         "[yellow]Host Risk Details: %s[::-]%s",
	FmtRiskDetailTitle:        "Risk Details: %s",

	// Correlation viewer
	FmtCorrControlsText: `[yellow]Navigation[white]                    [yellow]Actions[white]
[aqua]/[white]      Search hosts            [aqua]s[white]  View screenshot
[aqua]Space[white]  Categorize host         [aqua]p[white]  Create Hostfile Package
[aqua]f[white]      %s                      [aqua]t[white]  Generate Network Topology
[aqua]Esc/q[white]  Close

[gray]Ctrl+J[white] Jobs  [gray]Ctrl+D[white] Dashboard  [gray]Ctrl+N[white] Hosts  [gray]Ctrl+Z[white] Main`,
	CorrResetSearch:            "Reset search",
	FmtCorrFilterActiveCat:     "Cycle filter: %s",
	CorrCycleFilter:            "Cycle category filter",
	HostColIP:                  "IP",
	HostColCategory:            "Category",
	HostColHostname:            "Hostname",
	HostColVendor:              "Vendor",
	HostColPorts:               "Ports",
	HostDetailsSelectPrompt:    "[gray]Select a host to view details[::-]",
	HostDetailsNoData:          "[gray]No data found for selected host[::-]",
	HostDetailsIdentity:        "[yellow]Identity[::-]\n",
	HostDetailsClassification:  "[yellow]Classification[::-]\n",
	FmtHostDetailsPorts:        "[yellow]Ports & Services (%d)[::-]\n",
	HostDetailsNoOpenPorts:     "[gray]No open ports found[::-]\n",
	FmtHostDetailsScreenshots:  "\n[yellow]Screenshots (%d)[::-]\n",
	HostDetailsNoScreenshots:   "[gray]No screenshots available[::-]\n",
	HostDetailsPressS:          "\n[gray]Press [yellow]s[gray] to view screenshots[::-]\n",
	CatDisplayWindows:          "Windows",
	CatDisplayLinux:            "Linux",
	CatDisplayNetDevice:        "Network Devices",
	CatDisplayUnknown:          "Unknown",
	FmtHostInventoryFilterCat:  "Host Inventory %s",
	FmtHostInventoryFilterText: "Host Inventory %s",
	CatModalWindows:            "Windows",
	CatModalLinux:              "Linux",
	CatModalNetDevice:          "Network Device",
	FmtCatModalTitle:           "Categorize %s",

	// Topology viewer
	FmtTopoResult: "Topology viewer generated:\n\n%s",
	TopoNoData:    "No correlation data available.\nRun discovery scans first.",

	// Main view panels
	PaneTitleAssessment:        "Assessment Checklist",
	AssessmentPhaseCapture:     "Capture",
	AssessmentPhaseSysConfig:   "System Configuration",
	AssessmentPhaseDiscovery:   "Discovery Scans",
	AssessmentPhaseCategorize:  "Host Categorization",
	AssessmentPhasePortVuln:    "Port/Vuln Scans",
	AssessmentPhaseDevConfig:   "Device Config Gathering",
	FmtAssessmentUncategorized: "(%d uncategorized)",

	PaneTitleActiveJobsPanel: "Active Jobs",
	JobsPanelNoActive:        "No active jobs. Select a task and press Enter.",
	FmtJobsPanelNeedsInput:   "[yellow]\u2691 Waiting for input[white]",
	ProgressWaitingInput:     "\u2691 Waiting for input",

	FilterLabel: "Filter: ",

	// Global status footer
	FmtGlobalStatusProgress: "[green]●[white] %s [cyan]%s[white]",
	FmtGlobalStatusSpinner:  "[green]●[white] %s",
	FmtGlobalStatusVLANs:    "[green]●[white] %s [cyan]%d/%d VLANs[white] — %s",
	FmtGlobalStatusNeedsInput: "[yellow]\u2691[white] %s [yellow]waiting for input[white]",

	// VLAN breakdown
	VLANDone:         "✓",
	VLANUnknown:      "?",
	FmtVLANEntry:     "%s:%d/%d",
	FmtVLANEntryDone: "%s:✓",

	// Output viewer re-entry
	FmtReconnectedProgress: "──── Reconnected — %s ────",
}

var stringsDE = &Strings{
	// Panel titles
	PaneTitleProgramInfo:       "Programminfo",
	PaneTitleCategories:        "Kategorien",
	PaneTitleTaskDefault:       "Kategorie auswählen",
	PaneTitleQuickRef:          "Steuerung",
	PaneTitleSearch:            "Skripte suchen",
	PaneTitleActiveJobs:        "Aktive Jobs",
	PaneTitleStatistics:        "Statistiken",
	PaneTitleControls:          "Steuerung",
	PaneTitleScriptOutput:      "Skriptausgabe",
	PaneTitleSearchOutput:      "Ausgabe durchsuchen",
	PaneTitleDiscoveryStats:    "Discovery-Statistik",
	PaneTitleCategoryBreakdown: "Kategorieverteilung",
	PaneTitleJobActivity:       "Job-Aktivität",
	PaneTitleRiskOverview:      "Risikoübersicht",
	PaneTitleHostRisk:          "Host-Risiko",
	PaneTitleServiceLandscape:  "Dienstelandschaft",
	PaneTitleDashControls:      "Steuerung",
	PaneTitleHostInventory:     "Host-Inventar",
	PaneTitleHostDetails:       "Host-Details",
	PaneTitleFilterHosts:       "Hosts filtern",

	// Header
	FmtHeaderText: "[cyan::b]%s[white::-] [green]%s[white]\n[gray]Netzwerk-Analyse-Toolkit[-]\n\n[yellow]Tasten:[white] [cyan]Tab[white]=Wechseln [cyan]hjkl[white]=Navigieren [cyan]/[white]=Suchen [cyan]Ctrl+J[white]=Jobs [cyan]Ctrl+N[white]=Hosts [cyan]Ctrl+D[white]=Dashboard [cyan]q[white]=Beenden",

	// Info panel
	InfoCatLine1:       "[aqua]↑↓←→/hjkl[white] Navigieren  [aqua]Enter[white] Auswählen  [aqua]Tab[white] Wechseln  [aqua]/[white] Suchen  [aqua]?[white] Hilfe  [aqua]Esc/q[white] Beenden\n",
	InfoCatLine2:       "[gray]Ctrl+J[white] Jobs   [gray]Ctrl+D[white] Dashboard   [gray]Ctrl+N[white] Hosts   [gray]Ctrl+Z[white] Hauptmenü",
	FmtInfoTaskLine1:   "[aqua]↑↓←→/hjkl[white] Navigieren  [aqua]Enter[white] Ausführen  [aqua]Tab[white] Wechseln  [aqua]/[white] Suchen  [aqua]?[white] Hilfe  [aqua]Esc/q[white] Beenden\n",
	InfoTaskNoCatLine1: "[aqua]Tab[white] Zu Kategorien wechseln  [aqua]/[white] Suchen  [aqua]?[white] Hilfe  [aqua]Esc/q[white] Beenden\n",
	InfoGlobalLine:     "[gray]Ctrl+J[white] Jobs   [gray]Ctrl+D[white] Dashboard   [gray]Ctrl+N[white] Hosts   [gray]Ctrl+Z[white] Hauptmenü",
	InfoDefaultLine1:   "[aqua]↑↓←→/hjkl[white] Bewegen  [aqua]Tab[white] Wechseln  [aqua]/[white] Suchen  [aqua]?[white] Hilfe\n",
	InfoDefaultLine2:   "[gray]Ctrl+J[white] Jobs   [gray]Ctrl+D[white] Dashboard   [gray]Ctrl+N[white] Hosts   [gray]Ctrl+Z[white] Hauptmenü   [aqua]Esc/q[white] Beenden",

	// Task pane
	FmtTasksTitle: "Skripte – %s",

	// Search
	SearchLabel: "Suche: ",

	// Subtask modal
	SubtaskSelectOp: "Skript auswählen:",

	// Help
HelpText: `[yellow]Navigation:[white]
  [aqua]↑/↓ oder j/k[white]    Im aktuellen Panel bewegen
  [aqua]←/→ oder h/l[white]    Panels wechseln

[yellow]Aktionen:[white]
  [aqua]Enter[white]            Ausgewähltes Skript ausführen
  [aqua]Esc[white] / [aqua]q[white]         Beenden
  [aqua]/[white]                Skripte suchen
  [aqua]?[white]                Diese Hilfe anzeigen

[yellow]Global (jede Ansicht):[white]
  [aqua]Ctrl+J[white]           Job-Verwaltung
  [aqua]Ctrl+D[white]           Dashboard
  [aqua]Ctrl+N[white]           Host-Inventar
  [aqua]Ctrl+Z[white]           Zurück zum Hauptmenü

[yellow]Host-Inventar ([aqua]Ctrl+N[white]):[white]
  [white][aqua]Leertaste[white]  Host kategorisieren   [aqua]/[white] Suchen   [aqua]f[white] Filter
  [white][aqua]p[white]          Hostdateienpaket erstellen  [aqua]t[white] Topologieplan erstellen

[yellow]Job-Verwaltung ([aqua]Ctrl+J[white]):[white]
  [white][aqua]1-9[white]    Parallelität setzen   [aqua]c[white] Abbrechen   [aqua]C[white] Fertige löschen

[yellow]Tipps:[white]
  [white]- Skripte laufen parallel (einstellbar mit [aqua]1-9[white] in Job-Verwaltung)
  [white]- Zusätzliche Skripte werden automatisch eingereiht
  [white]- Skripte werden aus .meta.yaml-Dateien automatisch erkannt
  [white]- Die Prüfungs-Checkliste wertet Skriptergebnisse aus und bietet eine Workflow-Übersicht typischer Prüfungsaufgaben`,
	HelpTitle:       "Hilfe",
	OutputHelpTitle: "Ausgabe-Hilfe",

	// Buttons
	BtnOK:            "OK",
	BtnCancel:        "Abbrechen",
	BtnQuit:          "Beenden",
	BtnQueueJob:      "In Warteschlange",
	BtnViewJobs:      "Jobs anzeigen",
	BtnClose:         "Schließen",
	BtnYes:           "Ja",
	BtnNo:            "Nein",
	BtnViewInventory: "Host im Inventar anzeigen",

	// Job queue modals
	TitleJobQueued:       "Job eingereiht",
	FmtJobQueued:         "'%s' wurde zur Ausführung eingereiht.\n\nCtrl+J drücken zum Anzeigen.",
	TitleJobStarted:      "Job gestartet",
	FmtJobStarted:        "'%s' wurde im Hintergrund gestartet.\n\nCtrl+J drücken zum Anzeigen.",
	FmtConfirmQuit:       "%d Job(s) noch aktiv.\n\nTrotzdem beenden? Laufende Jobs werden abgebrochen.",
	TitleScriptNotFound:  "Skript nicht gefunden",
	FmtScriptNotFound:    "Kein Skript gefunden: %s",
	TitlePathError:       "Pfadfehler",
	FmtPathError:         "Skriptpfad konnte nicht aufgelöst werden: %v",
	TitleConnectionError: "Verbindungsfehler",
	FmtConnectionError:   "Verbindung zum Skript fehlgeschlagen: %v",
	FmtExecutionOptions:  "Maximale Anzahl gleichzeitiger Jobs erreicht.\n\nWie soll '%s' ausgeführt werden?",

	// Category display names
	CatNetworkSetup:     "Host-Einrichtung",
	CatSystemUtilities:  "Werkzeuge",
	CatNetworkDiscovery: "Discovery",
	CatCaptureAnalysis:  "Analyse",
	CatPortScanning:     "Port-Scans",
	CatReconnaissance:   "Reconnaissance",
	CatConfigGathering:  "Konfig-Erfassung",

	// Hardcoded task names
	TaskSelectWorkDir:              "Arbeitsverzeichnis wählen",
	TaskSelectWorkDirDesc:          "Arbeitsverzeichnis für Operationen auswählen",
	TaskConfigInterfaces:           "Schnittstellen konfigurieren",
	TaskConfigInterfacesDesc:       "Schnittstellenstatus verwalten oder VLAN-Subschnittstellen einrichten",
	TaskInterfaceStates:            "Schnittstellenstatus",
	TaskInterfaceStatesDesc:        "Netzwerkschnittstellen anzeigen und umschalten",
	TaskVLANInterfaces:             "VLAN-Schnittstellen",
	TaskVLANInterfacesDesc:         "VLAN-Subschnittstellen erstellen",
	TaskConfigureIP:                "IP-Adressen konfigurieren",
	TaskConfigureIPDesc:            "IP-Adressen auf Schnittstellen setzen",
	TaskConfigureRoutes:            "Routen konfigurieren",
	TaskConfigureRoutesDesc:        "IP-Routen anzeigen und konfigurieren",
	TaskConfigureNameservers:       "DNS konfigurieren",
	TaskConfigureNameserversDesc:   "DNS-Nameserver festlegen",
	TaskBackupConfig:               "Konfiguration sichern",
	TaskBackupConfigDesc:           "Aktuelle Netzwerkkonfiguration sichern",
	TaskRestoreConfig:              "Konfiguration wiederherstellen",
	TaskRestoreConfigDesc:          "Netzwerkkonfiguration aus Backup wiederherstellen",
	TaskNetworkCapture:             "Netzwerkmitschnitt",
	TaskNetworkCaptureDesc:         "Netzwerkverkehr aufzeichnen mit Sicherheitsanalyse und Erkennung unsicherer Protokolle",
	TaskExtractVLANIDs:             "VLAN-IDs extrahieren",
	TaskExtractVLANIDsDesc:         "VLAN-IDs aus Mitschnittdateien extrahieren",
	TaskMultiPhaseDiscovery:        "Discovery Scan",
	TaskMultiPhaseDiscoveryDesc:    "Umfassender Discovery-Scan mit Host-Kategorisierung",
	TaskHostCategorization:         "Host-Kategorisierung",
	TaskHostCategorizationDesc:     "Erkannte Hosts nach Betriebssystem kategorisieren",
	TaskPortServiceScan:            "Port- & Dienst-Scan",
	TaskPortServiceScanDesc:        "Umfassender Port-Scan mit Diensterkennung und OS-Fingerprinting",
	TaskVulnAssessment:             "Schwachstellen-Scan",
	TaskVulnAssessmentDesc:         "Minimalinvasive Schwachstellenanalyse mit NSE-Skripten und ergänzenden Werkzeugen",
	TaskSNMPInterrogate:         "SNMP-Abfrage",
	TaskSNMPInterrogateDesc:     "SNMP-Geräte abfragen: Systeminfos, Schnittstellen, ARP, VLANs und Routen",
	TaskWebScreenshot:           "Web-Screenshot",
	TaskWebScreenshotDesc:       "Screenshots von erkannten Webdiensten erstellen",
	TaskExploitSearch:           "Exploit-Suche",
	TaskExploitSearchDesc:       "Exploit-Datenbanken nach Schwachstellen für erkannte Dienste durchsuchen",
	TaskDeviceConfigGathering:      "Netzwerkgeräte-Konfig-Erfassung",
	TaskDeviceConfigGatheringDesc:  "Per SSH zum Gerät verbinden, Hersteller erkennen und Konfiguration sammeln",
	TaskNetworkCaptureAnalysis:     "Netzwerkmitschnitt-Analyse",
	TaskNetworkCaptureAnalysisDesc: "VLANs, MAC-Adressen oder Paketmitschnitte analysieren",

	// Jobs viewer
	JobsHeaderID:       "ID",
	JobsHeaderName:     "Name",
	JobsHeaderStatus:   "Status",
	JobsHeaderDuration: "Dauer",
	JobsHeaderProgress: "Fortschritt",
	JobsControlsText: `[aqua]↑↓[white] Navigieren  [aqua]Enter[white] Ausgabe  [aqua]c[white] Abbrechen  [aqua]C[white] Fertige löschen  [aqua]1-9[white] Max Jobs  [aqua]Esc/q[white] Schließen
[gray]Ctrl+J[white] Jobs   [gray]Ctrl+D[white] Dashboard   [gray]Ctrl+N[white] Hosts   [gray]Ctrl+Z[white] Hauptmenü`,
	FmtJobStats: `[white]Jobs gesamt:[::-]      %d
[green]Laufend:[::-]          %d/%d
[blue]Ausstehend:[::-]       %d
[green]Abgeschlossen:[::-]   %d
[red]Fehlgeschlagen:[::-]   %d
[gray]Abgebrochen:[::-]      %d

[yellow]Kapazität:[::-]        %d/%d`,
	ProgressWaiting:     "⏳ Wartend",
	ProgressRunning:     "Läuft",
	ProgressDone:        "✅ Fertig",
	ProgressFailed:      "❌ Fehler",
	ProgressCancelled:   "🚫 Abgebrochen",
	ProgressUnknown:     "❓ Unbekannt",
	FmtSetMaxConcurrent: "Max. gleichzeitige Jobs auf %d setzen?",
	FmtMaxConcurrentSet: "Max. gleichzeitige Jobs auf %d gesetzt",
	FmtRemovedCompleted: "%d abgeschlossene Jobs entfernt",
	ErrJobNotFound:      "Job nicht gefunden",
	FmtErrConnectJob:    "Verbindung zum Job fehlgeschlagen: %v",
	ErrNoOutputCaptured: "Keine Ausgabe für diesen Job verfügbar",
	ErrNoJobSelected:    "Kein Job ausgewählt",
	FmtErrCancelJob:     "Job konnte nicht abgebrochen werden: %v",
	FmtShowErrorPrefix:  "Fehler: %s",

	// Output viewer
	StatusReady:         "[green]Bereit[white] — [aqua]Tab[white] Eingabemodus  [aqua]Leertaste[white] Pause  [aqua]f[white] Folgen  [aqua]t[white] Zeit  [aqua]s[white] Quelle  [aqua]/[white] Suchen  [aqua]g/G[white] Scrollen  [aqua]?[white] Hilfe",
	StatusInputMode:     "[yellow]Eingabemodus[white] — [aqua]Enter[white] Senden  [aqua]Tab[white] Ausgabemodus",
	StatusViewMode:      "[green]Ausgabemodus[white] — [aqua]Tab[white] Eingabemodus  [aqua]Leertaste[white] Pause  [aqua]f[white] Folgen  [aqua]t[white] Zeit  [aqua]s[white] Quelle  [aqua]/[white] Suchen  [aqua]g/G[white] Scrollen  [aqua]?[white] Hilfe",
	StatusWaitingInput:  "[yellow]Wartet auf Eingabe[white] — [aqua]Enter[white] Senden  [aqua]Tab[white] Ausgabe",
	StatusPasswordInput: "[yellow]Passworteingabe[white] — [aqua]Enter[white] Senden  [aqua]Tab[white] Ausgabe",
	StatusInputSent:     "[green]Eingabe gesendet[white] — Warte auf Antwort...",
	FmtStatusProgress:   "[cyan]%s[white] — [aqua]Leertaste[white] Pause  [aqua]f[white] Folgen",
	FmtStatusCompletion: "[%s][aqua]Enter[white] Weiter",
	FmtScriptCompleted:  "Skript %s – Dauer: %v",
	FmtTitleWithJobs:    "Skriptausgabe %s – %s [%s]",
	FmtTitleNoJobs:      "Skriptausgabe – %s [%s]",
OutputViewerHelp: `[yellow]Steuerung:[white]
  [aqua]Esc[white]          Skript abbrechen und zurück zum Hauptmenü
  [aqua]q[white]            Zurück (Skript läuft weiter)
  [aqua]Ctrl+C[white]       Skriptausführung stoppen
  [aqua]Leertaste[white]    Ausgabe pausieren/fortsetzen
  [aqua]f[white]            Auto-Scrollen toggle
  [aqua]t[white]            Zeitstempel toggle
  [aqua]s[white]            Quelle (stdout/stderr) toggle
  [aqua]/[white]            Ausgabe durchsuchen
  [aqua]c[white]            Anzeige leeren
  [aqua]G[white]            Zum Ende springen
  [aqua]g[white]            Zum Anfang springen

[yellow]Skriptsteuerung:[white]
  [white]- Skripte können mit [aqua]Esc[white] abgebrochen werden
  [white]- [aqua]q[white] kehrt zurück, während das Skript weiterläuft
  [white]- Eingaben können an interaktive Skripte gesendet werden
  [white]- Vollständiger Ausführungsverlauf wird gespeichert`,
	FmtHistoricalStatus: "[%s]%s – schreibgeschützt[::-] | Esc=Schließen | Enter=Schließen",
	FmtReconnected:      "──── Reconnected – zeige letzte %d von %d Zeilen ────",
	OutputGlobalLine:    "[gray]Ctrl+J[white] Jobs   [gray]Ctrl+D[white] Dashboard   [gray]Ctrl+N[white] Hosts   [gray]Ctrl+Z[white] Hauptmenü   [aqua]Esc/q[white] Zurück",

	// Dashboard
	DashControlsText:     "[aqua]Enter[white] Risikodetails  [aqua]Esc/q[white] Schließen\n[gray]Ctrl+J[white] Jobs   [gray]Ctrl+D[white] Dashboard   [gray]Ctrl+N[white] Hosts   [gray]Ctrl+Z[white] Hauptmenü",
	DashHeaderScore:      "Punkte",
	DashHeaderIP:         "IP",
	DashHeaderHostname:   "Hostname",
	DashHeaderCategory:   "Kategorie",
	DashHeaderTopFinding: "Wichtigster Fund (Gesamt)",
	DashNoHostsYet:       "Noch keine Hosts erkannt — Discovery starten.",

	// Panel body
	DashStatsHeading:            "[yellow]Discovery-Statistiken[::-]\n\n",
	FmtDashStatsHostsDiscovered: "Entdeckte Hosts:    [white]%d[::-]\n",
	FmtDashStatsWindows:         "  Windows:          [green]%d[::-]\n",
	FmtDashStatsLinux:           "  Linux:            [yellow]%d[::-]\n",
	FmtDashStatsNetDevices:      "  Netzwerkgeräte:   [blue]%d[::-]\n",
	FmtDashStatsUnknown:         "  Unbekannt:        [gray]%d[::-]\n",
	FmtDashStatsServices:        "Dienste gefunden:   [white]%d[::-]\n",
	DashJobsHeading:             "[yellow]Jobs[::-]\n",
	FmtDashJobsRunning:          "Laufend:      [green]%d[::-]/%d max\n",
	FmtDashJobsCompleted:        "Abgeschlossen: [blue]%d[::-]\n",
	FmtDashJobsFailed:           "Fehlgeschlagen: [red]%d[::-]\n",
	FmtDashLastScan:             "\nLetzter Scan: [white]%s[::-]\n",
	DashNoChartYet:              "[gray]Noch keine Hosts erkannt.[::-]\n\n[gray]Starte Discovery-Scan[::-]\n[gray]über das Skripte-Menü.[::-]\n",
	FmtDashCategoryBar:          "[%s]%-16s[::-]  [%s]%s[::-]  [white]%d[::-]\n",
	DashNoActivityYet:           "[gray]Noch keine Jobs ausgeführt.[::-]\n[gray]Starte Discovery-Scan[::-]\n[gray]über das Skripte-Menü.[::-]\n",
	DashNoHostsDiscovered:       "[gray]Noch keine Hosts erkannt.[::-]\n",
	DashRiskDistHeading:         "[yellow]Risikoverteilung[::-]\n",
	DashSevSummaryHeading:       "\n[yellow]Schweregrad-Übersicht[::-]\n",
	DashBySourceHeading:         "\n[yellow]Weitere Tools:[::-]\n",
	FmtDashNiktoFindings:        "  Nikto:     [white]%d Befunde[::-]\n",
	FmtDashSSLIssues:            "  SSL/TLS:   [white]%d Probleme[::-]\n",
	FmtDashAvgScore:             "\nDurchschnittliche Punktzahl: [white]%d[::-]\n",
	FmtDashHighestRisk:          "Höchste: [white]%s[::-] ([red]%d[::-])\n",
	FmtDashRiskTierLine:         "  [%s]■ %-9s %d Hosts[::-]\n",
	DashTopServicesHeading:      "[yellow]Top-Dienste[::-]\n",
	FmtDashServiceEntry:         "  [white]%-12s[::-] [green]%d[::-] Hosts\n",
	DashPortsHeading:            "\n[yellow]Ports[::-]\n",
	FmtDashUniqueOpenPorts:      "  Einmalig offen: [white]%d[::-]\n",
	FmtDashMostExposedHost:      "  Am meisten exponiert: [white]%s[::-] ([red]%d[::-])\n",
	FmtHostOpenPorts:            "Offene Ports: [white]%s[::-]\n",
	FmtFindingsCount:            "%s (%d Befunde)",

	FmtTopFindingMedium:       "%d mittlere Schwachstellen",
	FmtTopFindingPorts:        "%d offene Ports",
	TopFindingNone:            "-",
	RiskTierCritical:          "Kritisch",
	RiskTierHigh:              "Hoch",
	RiskTierMedium:            "Mittel",
	RiskTierLow:               "Niedrig",
	SevCritical:               "Kritisch",
	SevHigh:                   "Hoch",
	SevMedium:                 "Mittel",
	SevLow:                    "Niedrig",
	SevInfo:                   "Info",
	FmtSevFindings:            "[%s]%s Befunde[::-]\n",
	FmtSevFindingsCount:       "[%s]%s Befunde (%d)[::-]\n",
	FmtAndMore:                "  ... und %d weitere\n",
	FmtRiskScore:              "Risiko-Score: [%s]%d/1000[%s] %s[::-]\n",
	FmtRiskBreakdownVulns:     "  Schwachstellen:    [white]%d Pkt[::-]\n",
	FmtRiskBreakdownService:   "  Dienst-Exponierung: [white]%d Pkt[::-]\n",
	FmtRiskBreakdownSSL:       "  SSL/TLS-Probleme:  [white]%d Pkt[::-]\n",
	FmtRiskBreakdownPorts:     "  Offene Ports:      [white]%d Pkt[::-]\n\n",
	FmtRiskFactorCategory:    "\n[white]%s (%d Findings):[::-]\n",
	FmtRiskFactorLine:        "  [gray]●[::-] %s [darkgray](%d Pkt)%s[::-]\n",
	FmtHostRiskDetailWithHost: "[yellow]Host-Risikodetails: %s (%s)[::-]%s",
	FmtHostRiskDetail:         "[yellow]Host-Risikodetails: %s[::-]%s",
	FmtRiskDetailTitle:        "Risikodetails: %s",

	// Correlation viewer
	FmtCorrControlsText: `[yellow]Navigation[white]                     [yellow]Aktionen[white]
[aqua]/[white]      Hosts suchen            [aqua]s[white]  Screenshot anzeigen
[aqua]Space[white]  Host kategorisieren     [aqua]p[white]  Hostfile-Paket erstellen
[aqua]f[white]      %s                      [aqua]t[white]  Netzwerktopologie erstellen
[aqua]Esc/q[white]  Schließen

[gray]Ctrl+J[white] Jobs  [gray]Ctrl+D[white] Dashboard  [gray]Ctrl+N[white] Hosts  [gray]Ctrl+Z[white] Hauptmenü`,
	CorrResetSearch:            "Suche zurücksetzen",
	FmtCorrFilterActiveCat:     "Filter wechseln: %s",
	CorrCycleFilter:            "Kategoriefilter wechseln",
	HostColIP:                  "IP",
	HostColCategory:            "Kategorie",
	HostColHostname:            "Hostname",
	HostColVendor:              "Hersteller",
	HostColPorts:               "Ports",
	HostDetailsSelectPrompt:    "[gray]Host auswählen für Details[::-]",
	HostDetailsNoData:          "[gray]Keine Daten für gewählten Host[::-]",
	HostDetailsIdentity:        "[yellow]Eigenschaften[::-]\n",
	HostDetailsClassification:  "[yellow]Klassifizierung[::-]\n",
	FmtHostDetailsPorts:        "[yellow]Ports & Dienste (%d)[::-]\n",
	HostDetailsNoOpenPorts:     "[gray]Keine offenen Ports gefunden[::-]\n",
	FmtHostDetailsScreenshots:  "\n[yellow]Screenshots (%d)[::-]\n",
	HostDetailsNoScreenshots:   "[gray]Keine Screenshots vorhanden[::-]\n",
	HostDetailsPressS:          "\n[gray]Taste [yellow]s[gray] drücken für Screenshots[::-]\n",
	CatDisplayWindows:          "Windows",
	CatDisplayLinux:            "Linux",
	CatDisplayNetDevice:        "Netzwerkgeräte",
	CatDisplayUnknown:          "Unbekannt",
	FmtHostInventoryFilterCat:  "Host-Inventar %s",
	FmtHostInventoryFilterText: "Host-Inventar %s",
	CatModalWindows:            "Windows",
	CatModalLinux:              "Linux",
	CatModalNetDevice:          "Netzwerkgerät",
	FmtCatModalTitle:           "Host kategorisieren: %s",

	// Topology viewer
	FmtTopoResult: "Topologie-Viewer erstellt:\n\n%s",
	TopoNoData:    "Keine Korrelationsdaten vorhanden.\nZuerst Discovery-Scans ausführen.",

	// Main view panels
	PaneTitleAssessment:        "Prüfungs-Checkliste",
	AssessmentPhaseCapture:     "Mitschnitt",
	AssessmentPhaseSysConfig:   "Systemkonfiguration",
	AssessmentPhaseDiscovery:   "Discovery-Scans",
	AssessmentPhaseCategorize:  "Host-Kategorisierung",
	AssessmentPhasePortVuln:    "Port/Vuln-Scans",
	AssessmentPhaseDevConfig:   "Geräte-Konfig-Erfassung",
	FmtAssessmentUncategorized: "(%d unkategorisiert)",

	PaneTitleActiveJobsPanel: "Aktive Jobs",
	JobsPanelNoActive:        "Keine aktiven Jobs. Skript auswählen und Enter drücken.",
	FmtJobsPanelNeedsInput:   "[yellow]\u2691 Wartet auf Eingabe[white]",
	ProgressWaitingInput:     "\u2691 Wartet auf Eingabe",

	FilterLabel: "Filter: ",

	// Global status footer
	FmtGlobalStatusProgress: "[green]●[white] %s [cyan]%s[white]",
	FmtGlobalStatusSpinner:  "[green]●[white] %s",
	FmtGlobalStatusVLANs:    "[green]●[white] %s [cyan]%d/%d VLANs[white] — %s",
	FmtGlobalStatusNeedsInput: "[yellow]\u2691[white] %s [yellow]wartet auf Eingabe[white]",

	// VLAN breakdown
	VLANDone:         "✓",
	VLANUnknown:      "?",
	FmtVLANEntry:     "%s:%d/%d",
	FmtVLANEntryDone: "%s:✓",

	// Output viewer re-entry
	FmtReconnectedProgress: "──── Reconnected — %s ────",
}

func stringsForLang(lang string) *Strings {
	if lang == "de" {
		return stringsDE
	}
	return stringsEN
}
