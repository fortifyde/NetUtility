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
	FmtInfoTaskLine1   string // task-focused with category, Sprintf(fmt, categoryName)
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
	HelpText string

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
	CatHostConfig       string
	CatSystemUtilities  string
	CatNetworkDiscovery string
	CatPortScanning     string
	CatAdvancedTools    string

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
	TaskIntegratedWorkflow         string
	TaskIntegratedWorkflowDesc     string
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
	ErrJobNotFound       string
	FmtErrConnectJob     string // Sprintf(fmt, err)
	ErrNoOutputCaptured  string
	ErrNoJobSelected     string
	FmtErrCancelJob      string // Sprintf(fmt, err)
	FmtShowErrorPrefix   string // Sprintf(fmt, message)

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

	RiskTierCritical     string
	RiskTierHigh         string
	RiskTierMedium       string
	RiskTierLow          string
	SevCritical          string
	SevHigh              string
	SevMedium            string
	SevLow               string
	SevInfo              string
	FmtSevFindings       string // Sprintf(fmt, sevLabel)
	FmtSevFindingsCount  string // Sprintf(fmt, sevLabel, count)
	FmtAndMore           string // Sprintf(fmt, count)
	FmtRiskScore         string // Sprintf(fmt, color, score, color, tierLabel)
	FmtRiskBreakdownVulns   string
	FmtRiskBreakdownService string
	FmtRiskBreakdownSSL     string
	FmtRiskBreakdownPorts   string
	FmtHostRiskDetailWithHost string // Sprintf(fmt, ip, hostname, extra)
	FmtHostRiskDetail         string // Sprintf(fmt, ip, extra)
	FmtRiskDetailTitle        string // Sprintf(fmt, ip)

	// ── Correlation viewer ────────────────────────────────────────────────────
	FmtCorrControlsText    string // Sprintf(fmt, filterLine)
	CorrResetSearch        string
	FmtCorrFilterActiveCat string // Sprintf(fmt, catLabel)
	CorrCycleFilter        string
	HostColIP              string
	HostColCategory        string
	HostColHostname        string
	HostColVendor          string
	HostColPorts           string
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

	// ── Filter ────────────────────────────────────────────────────────────────
	FilterLabel string
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
	InfoCatLine1:       "[yellow]Categories:[::-] [white]↑↓/jk[::-]=Navigate [white]Enter[::-]=Select [white]Tab/l[::-]=Scripts [white]/[::-]=Search [white]?[::-]=Help [white]q[::-]=Quit\n",
	InfoCatLine2:       "[yellow]Global:[::-]     [white]Ctrl+J[::-]=Jobs [white]Ctrl+D[::-]=Dashboard [white]Ctrl+N[::-]=Hosts [white]Ctrl+Z[::-]=Main",
	FmtInfoTaskLine1:   "[yellow]%s:[::-] [white]↑↓/jk[::-]=Navigate [white]Enter[::-]=Execute [white]Tab/h[::-]=Categories [white]/[::-]=Search\n",
	InfoTaskNoCatLine1: "[yellow]Scripts:[::-] Select a category first  [white]Tab/h[::-]=Categories [white]/[::-]=Search\n",
	InfoGlobalLine:     "[yellow]Global:[::-] [white]Ctrl+J[::-]=Jobs [white]Ctrl+D[::-]=Dashboard [white]Ctrl+N[::-]=Hosts [white]Ctrl+Z[::-]=Main [white]q[::-]=Quit",
	InfoDefaultLine1:   "[yellow]Navigate:[::-] [white]Tab[::-]=Switch [white]h[::-]=Categories [white]l[::-]=Scripts [white]j/k[::-]=Move [white]/[::-]=Search [white]?[::-]=Help\n",
	InfoDefaultLine2:   "[yellow]Global:[::-]   [white]Ctrl+J[::-]=Jobs [white]Ctrl+D[::-]=Dashboard [white]Ctrl+N[::-]=Hosts [white]Ctrl+Z[::-]=Main [white]q[::-]=Quit",

	// Task pane
	FmtTasksTitle: "Scripts - %s",

	// Search
	SearchLabel: "Search: ",

	// Subtask modal
	SubtaskSelectOp: "Select an operation:",

	// Help
	HelpText: `NetUtility TUI Help

Navigation:
  Tab          Switch between categories and scripts
  Enter        Select category or execute script
  Escape, q    Quit application

Vim-like Keys:
  h            Focus categories (left panel)
  l            Focus scripts (right panel)
  j            Move down in current panel
  k            Move up in current panel

Search:
  /            Start search mode

Global (work from any view):
  Ctrl+J       Job manager
  Ctrl+D       Dashboard
  Ctrl+N       Host inventory
  Ctrl+Z       Return to main screen

Advanced Features:
  - Up to 3 scripts can run concurrently
  - Additional scripts are queued automatically
  - Use Ctrl+J to view running, queued, and completed jobs
  - Use Ctrl+N to view correlated host inventory

Mouse:
  Click        Select items
  Scroll       Navigate lists`,

	// Buttons
	BtnOK:            "OK",
	BtnCancel:        "Cancel",
	BtnQuit:          "Quit",
	BtnQueueJob:      "Queue Job",
	BtnViewJobs:      "View Jobs",
	BtnClose:         "Close",
	BtnYes:           "Yes",
	BtnNo:            "No",
	BtnViewInventory: "View Inventory",

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
	CatHostConfig:       "Host Configuration",
	CatSystemUtilities:  "System Utilities",
	CatNetworkDiscovery: "Network Discovery",
	CatPortScanning:     "Port Scanning",
	CatAdvancedTools:    "Advanced Tools",

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
	TaskIntegratedWorkflow:         "Integrated Workflow",
	TaskIntegratedWorkflowDesc:     "Comprehensive workflow: capture, analysis, interface config, and discovery",
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
	JobsControlsText: `[yellow]Controls:[::-]
[white]Enter[::-]    View job output
[white]c[::-]        Cancel selected job
[white]C[::-]        Clear completed jobs
[white]1-9[::-]      Set max concurrent jobs
[white]q[::-]        Close
[yellow]Global:[::-] [white]Ctrl+D[::-]=Dashboard  [white]Ctrl+N[::-]=Hosts  [white]Ctrl+Z[::-]=Main`,
	FmtJobStats: `[yellow]Job Statistics:[::-]

[white]Total Jobs:[::-]      %d
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
	StatusReady:         "[green]Ready[::-] - Space=Pause f=Follow t=Time s=Source /=Search g/G=Scroll | q=Back Esc=Cancel",
	StatusInputMode:     "[yellow]Input Mode[::-] - Enter=Submit Tab=View | q=Back Esc=Cancel",
	StatusViewMode:      "[green]View Mode[::-] - Tab=Input Space=Pause f=Follow t=Time s=Source /=Search g/G=Scroll | q=Back Esc=Cancel",
	StatusWaitingInput:  "[yellow]Waiting for input[::-] - Enter=Submit Tab=View | q=Back Esc=Cancel",
	StatusPasswordInput: "[yellow]Password input[::-] - Enter=Submit Tab=View | q=Back Esc=Cancel",
	StatusInputSent:     "[green]Input sent[::-] - Waiting for response... | q=Back Esc=Cancel",
	FmtStatusProgress:   "[cyan]%s[white] | q=Back Esc=Cancel",
	FmtStatusCompletion: "[%s]Enter=Continue | q=Back Esc=Close[::-]",
	FmtScriptCompleted:  "Script %s - Duration: %v",
	FmtTitleWithJobs:    "Script Output %s - %s [%s]",
	FmtTitleNoJobs:      "Script Output - %s [%s]",
	OutputViewerHelp: `Output Viewer Help

Controls:
  Esc          Cancel job and return to main
  q            Return to main (job keeps running)
  Ctrl+C       Stop script execution
  Space        Pause/resume output display
  f            Toggle auto-scroll (following)
  t            Toggle timestamp display
  s            Toggle source (stdout/stderr) display
  /            Search output
  c            Clear display
  G            Go to end
  g            Go to beginning

Display Features:
  - Real-time streaming output
  - Color-coded stderr (red) and stdout (green)
  - Automatic highlighting of errors/warnings
  - Search and filter capabilities
  - Pause/resume without stopping script
  - Timestamp and source information

Script Control:
  - Scripts can be cancelled with Esc (kills the job)
  - Press q to return to main while keeping the job running
  - Input can be sent to interactive scripts
  - Full execution history is maintained`,
	FmtHistoricalStatus: "[%s]%s - read-only[::-] | Esc=Close | Enter=Close",
	FmtReconnected:      "──── Reconnected - showing last %d of %d total lines ────",

	// Dashboard
	DashControlsText:     "[yellow]Dashboard:[::-] [white]Enter[::-]=Risk Details  [white]q[::-]=Close  [yellow]Global:[::-] [white]Ctrl+J[::-]=Jobs  [white]Ctrl+N[::-]=Hosts  [white]Ctrl+Z[::-]=Main",
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

	RiskTierCritical:     "Critical",
	RiskTierHigh:         "High",
	RiskTierMedium:       "Medium",
	RiskTierLow:          "Low",
	SevCritical:          "Critical",
	SevHigh:              "High",
	SevMedium:            "Medium",
	SevLow:               "Low",
	SevInfo:              "Info",
	FmtSevFindings:       "[%s]%s Findings[::-]\n",
	FmtSevFindingsCount:  "[%s]%s Findings (%d)[::-]\n",
	FmtAndMore:           "  ... and %d more\n",
	FmtRiskScore:         "Risk Score: [%s]%d/1000[%s] %s[::-]\n",
	FmtRiskBreakdownVulns:   "  Vulnerabilities:  [white]%d pts[::-]\n",
	FmtRiskBreakdownService: "  Service Exposure: [white]%d pts[::-]\n",
	FmtRiskBreakdownSSL:     "  SSL/TLS Issues:   [white]%d pts[::-]\n",
	FmtRiskBreakdownPorts:   "  Open Ports:       [white]%d pts[::-]\n\n",
	FmtHostRiskDetailWithHost: "[yellow]Host Risk Details: %s (%s)[::-]%s",
	FmtHostRiskDetail:         "[yellow]Host Risk Details: %s[::-]%s",
	FmtRiskDetailTitle:        "Risk Details: %s",

	// Correlation viewer
	FmtCorrControlsText: `[yellow]Navigation                    Actions[::-]
[white]Enter[::-]  View host details       [white]s[::-]  View screenshot
[white]/[::-]      Search hosts            [white]p[::-]  Generate package
%s
[white]Space[::-]  Categorize host         [white]q[::-]  Close

[yellow]Global:[::-] [white]Ctrl+J[::-]=Jobs  [white]Ctrl+D[::-]=Dashboard  [white]Ctrl+Z[::-]=Main`,
	CorrResetSearch:        "[yellow]f[::-]      Reset search",
	FmtCorrFilterActiveCat: "[yellow]f[::-]      Cycle filter: %s",
	CorrCycleFilter:        "[white]f[::-]      Cycle category filter",
	HostColIP:              "IP",
	HostColCategory:        "Category",
	HostColHostname:        "Hostname",
	HostColVendor:          "Vendor",
	HostColPorts:           "Ports",
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
	FilterLabel:                "Filter: ",
}

var stringsDE = &Strings{
	// Panel titles
	PaneTitleProgramInfo:       "Programminfo",
	PaneTitleCategories:        "Kategorien",
	PaneTitleTaskDefault:       "Kategorie auswählen",
	PaneTitleQuickRef:          "Kurzübersicht",
	PaneTitleSearch:            "Skripte suchen",
	PaneTitleActiveJobs:        "Aktive Jobs",
	PaneTitleStatistics:        "Statistiken",
	PaneTitleControls:          "Steuerung",
	PaneTitleScriptOutput:      "Skriptausgabe",
	PaneTitleSearchOutput:      "Ausgabe durchsuchen",
	PaneTitleDiscoveryStats:    "Erkennungsstatistik",
	PaneTitleCategoryBreakdown: "Kategorieverteilung",
	PaneTitleJobActivity:       "Job-Aktivität",
	PaneTitleRiskOverview:      "Risikoübersicht",
	PaneTitleHostRisk:          "Host-Risiko",
	PaneTitleServiceLandscape:  "Dienstlandschaft",
	PaneTitleDashControls:      "Steuerung",
	PaneTitleHostInventory:     "Host-Inventar",
	PaneTitleHostDetails:       "Host-Details",
	PaneTitleFilterHosts:       "Hosts filtern",

	// Header
	FmtHeaderText: "[cyan::b]%s[white::-] [green]%s[white]\n[gray]Netzwerk-Analyse-Toolkit[-]\n\n[yellow]Tasten:[white] [cyan]Tab[white]=Wechseln [cyan]hjkl[white]=Navigieren [cyan]/[white]=Suchen [cyan]Ctrl+J[white]=Jobs [cyan]Ctrl+N[white]=Hosts [cyan]Ctrl+D[white]=Dashboard [cyan]q[white]=Beenden",

	// Info panel
	InfoCatLine1:       "[yellow]Kategorien:[::-] [white]↑↓/jk[::-]=Navigieren [white]Enter[::-]=Auswählen [white]Tab/l[::-]=Skripte [white]/[::-]=Suchen [white]?[::-]=Hilfe [white]q[::-]=Beenden\n",
	InfoCatLine2:       "[yellow]Global:[::-]     [white]Ctrl+J[::-]=Jobs [white]Ctrl+D[::-]=Dashboard [white]Ctrl+N[::-]=Hosts [white]Ctrl+Z[::-]=Hauptmenü",
	FmtInfoTaskLine1:   "[yellow]%s:[::-] [white]↑↓/jk[::-]=Navigieren [white]Enter[::-]=Ausführen [white]Tab/h[::-]=Kategorien [white]/[::-]=Suchen\n",
	InfoTaskNoCatLine1: "[yellow]Skripte:[::-] Zuerst Kategorie auswählen  [white]Tab/h[::-]=Kategorien [white]/[::-]=Suchen\n",
	InfoGlobalLine:     "[yellow]Global:[::-] [white]Ctrl+J[::-]=Jobs [white]Ctrl+D[::-]=Dashboard [white]Ctrl+N[::-]=Hosts [white]Ctrl+Z[::-]=Hauptmenü [white]q[::-]=Beenden",
	InfoDefaultLine1:   "[yellow]Navigation:[::-] [white]Tab[::-]=Wechseln [white]h[::-]=Kategorien [white]l[::-]=Skripte [white]j/k[::-]=Bewegen [white]/[::-]=Suchen [white]?[::-]=Hilfe\n",
	InfoDefaultLine2:   "[yellow]Global:[::-]   [white]Ctrl+J[::-]=Jobs [white]Ctrl+D[::-]=Dashboard [white]Ctrl+N[::-]=Hosts [white]Ctrl+Z[::-]=Hauptmenü [white]q[::-]=Beenden",

	// Task pane
	FmtTasksTitle: "Skripte – %s",

	// Search
	SearchLabel: "Suche: ",

	// Subtask modal
	SubtaskSelectOp: "Vorgang auswählen:",

	// Help
	HelpText: `NetUtility TUI Hilfe

Navigation:
  Tab          Zwischen Kategorien und Skripten wechseln
  Enter        Kategorie auswählen oder Skript ausführen
  Escape, q    Anwendung beenden

Vim-Tasten:
  h            Kategorien fokussieren (linkes Panel)
  l            Skripte fokussieren (rechtes Panel)
  j            Im aktuellen Panel nach unten
  k            Im aktuellen Panel nach oben

Suche:
  /            Suchmodus starten

Global (von überall):
  Ctrl+J       Job-Verwaltung
  Ctrl+D       Dashboard
  Ctrl+N       Host-Inventar
  Ctrl+Z       Zurück zum Hauptbildschirm

Erweiterte Funktionen:
  - Bis zu 3 Skripte können gleichzeitig laufen
  - Weitere Skripte werden automatisch eingereiht
  - Ctrl+J zum Anzeigen laufender, wartender und abgeschlossener Jobs
  - Ctrl+N zum Anzeigen des korrelierten Host-Inventars

Maus:
  Klick        Elemente auswählen
  Scrollen     Listen durchsuchen`,

	// Buttons
	BtnOK:            "OK",
	BtnCancel:        "Abbrechen",
	BtnQuit:          "Beenden",
	BtnQueueJob:      "In Warteschlange",
	BtnViewJobs:      "Jobs anzeigen",
	BtnClose:         "Schließen",
	BtnYes:           "Ja",
	BtnNo:            "Nein",
	BtnViewInventory: "Inventar anzeigen",

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
	CatHostConfig:       "Host-Konfiguration",
	CatSystemUtilities:  "Systemwerkzeuge",
	CatNetworkDiscovery: "Netzwerkerkennung",
	CatPortScanning:     "Port-Scan",
	CatAdvancedTools:    "Erweiterte Werkzeuge",

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
	TaskConfigureNameservers:       "Nameserver konfigurieren",
	TaskConfigureNameserversDesc:   "DNS-Nameserver festlegen",
	TaskBackupConfig:               "Konfiguration sichern",
	TaskBackupConfigDesc:           "Aktuelle Netzwerkkonfiguration sichern",
	TaskRestoreConfig:              "Konfiguration wiederherstellen",
	TaskRestoreConfigDesc:          "Netzwerkkonfiguration aus Backup wiederherstellen",
	TaskNetworkCapture:             "Netzwerkmitschnitt",
	TaskNetworkCaptureDesc:         "Netzwerkverkehr aufzeichnen mit Sicherheitsanalyse und Erkennung unsicherer Protokolle",
	TaskExtractVLANIDs:             "VLAN-IDs extrahieren",
	TaskExtractVLANIDsDesc:         "VLAN-IDs aus Mitschnittdateien extrahieren",
	TaskMultiPhaseDiscovery:        "Mehrstufige Erkennung",
	TaskMultiPhaseDiscoveryDesc:    "Umfassende Netzwerkerkennung mit Host-Kategorisierung",
	TaskHostCategorization:         "Host-Kategorisierung",
	TaskHostCategorizationDesc:     "Erkannte Hosts nach Betriebssystem kategorisieren",
	TaskPortServiceScan:            "Port- & Dienst-Scan",
	TaskPortServiceScanDesc:        "Umfassender Port-Scan mit Diensterkennung und OS-Fingerprinting",
	TaskVulnAssessment:             "Schwachstellenanalyse",
	TaskVulnAssessmentDesc:         "Sichere Schwachstellenanalyse mit NSE-Skripten und ergänzenden Werkzeugen",
	TaskIntegratedWorkflow:         "Integrierter Workflow",
	TaskIntegratedWorkflowDesc:     "Umfassender Workflow: Mitschnitt, Analyse, Schnittstellenkonfiguration und Erkennung",
	TaskDeviceConfigGathering:      "Gerätekonfiguration erfassen",
	TaskDeviceConfigGatheringDesc:  "Per SSH zum Gerät verbinden, Hersteller erkennen und Konfiguration einlesen",
	TaskNetworkCaptureAnalysis:     "Netzwerkmitschnitt-Analyse",
	TaskNetworkCaptureAnalysisDesc: "VLANs, MAC-Adressen oder Paketmitschnitte analysieren",

	// Jobs viewer
	JobsHeaderID:       "ID",
	JobsHeaderName:     "Name",
	JobsHeaderStatus:   "Status",
	JobsHeaderDuration: "Dauer",
	JobsHeaderProgress: "Fortschritt",
	JobsControlsText: `[yellow]Steuerung:[::-]
[white]Enter[::-]    Ausgabe anzeigen
[white]c[::-]        Gewählten Job abbrechen
[white]C[::-]        Abgeschlossene Jobs löschen
[white]1-9[::-]      Max. gleichzeitige Jobs setzen
[white]q[::-]        Schließen
[yellow]Global:[::-] [white]Ctrl+D[::-]=Dashboard  [white]Ctrl+N[::-]=Hosts  [white]Ctrl+Z[::-]=Hauptmenü`,
	FmtJobStats: `[yellow]Job-Statistik:[::-]

[white]Jobs gesamt:[::-]      %d
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
	StatusReady:         "[green]Bereit[::-] - Leertaste=Pause f=Folgen t=Zeit s=Quelle /=Suchen g/G=Scrollen | q=Zurück Esc=Abbrechen",
	StatusInputMode:     "[yellow]Eingabemodus[::-] - Enter=Senden Tab=Anzeigen | q=Zurück Esc=Abbrechen",
	StatusViewMode:      "[green]Ansichtsmodus[::-] - Tab=Eingabe Leertaste=Pause f=Folgen t=Zeit s=Quelle /=Suchen g/G=Scrollen | q=Zurück Esc=Abbrechen",
	StatusWaitingInput:  "[yellow]Wartet auf Eingabe[::-] - Enter=Senden Tab=Anzeigen | q=Zurück Esc=Abbrechen",
	StatusPasswordInput: "[yellow]Passworteingabe[::-] - Enter=Senden Tab=Anzeigen | q=Zurück Esc=Abbrechen",
	StatusInputSent:     "[green]Eingabe gesendet[::-] - Warte auf Antwort... | q=Zurück Esc=Abbrechen",
	FmtStatusProgress:   "[cyan]%s[white] | q=Zurück Esc=Abbrechen",
	FmtStatusCompletion: "[%s]Enter=Weiter | q=Zurück Esc=Schließen[::-]",
	FmtScriptCompleted:  "Skript %s – Dauer: %v",
	FmtTitleWithJobs:    "Skriptausgabe %s – %s [%s]",
	FmtTitleNoJobs:      "Skriptausgabe – %s [%s]",
	OutputViewerHelp: `Ausgabe-Anzeige Hilfe

Steuerung:
  Esc          Skript abbrechen und zurück zum Hauptmenü
  q            Zurück (Skript läuft weiter)
  Ctrl+C       Skriptausführung stoppen
  Leertaste    Ausgabe pausieren/fortsetzen
  f            Auto-Scrollen umschalten
  t            Zeitstempel umschalten
  s            Quelle (stdout/stderr) umschalten
  /            Ausgabe durchsuchen
  c            Anzeige leeren
  G            Zum Ende springen
  g            Zum Anfang springen

Anzeigefunktionen:
  - Echtzeit-Ausgabe
  - Farbcodierung: stderr (rot) und stdout (grün)
  - Automatische Hervorhebung von Fehlern/Warnungen
  - Suche und Filterung
  - Pausieren ohne Skript zu stoppen
  - Zeitstempel und Quellinformation

Skriptsteuerung:
  - Skripte können mit Esc abgebrochen werden
  - q kehrt zurück, während das Skript weiterläuft
  - Eingaben können an interaktive Skripte gesendet werden
  - Vollständiger Ausführungsverlauf wird gespeichert`,
	FmtHistoricalStatus: "[%s]%s – schreibgeschützt[::-] | Esc=Schließen | Enter=Schließen",
	FmtReconnected:      "──── Reconnected – zeige letzte %d von %d Zeilen ────",

	// Dashboard
	DashControlsText:     "[yellow]Dashboard:[::-] [white]Enter[::-]=Risikodetails  [white]q[::-]=Schließen  [yellow]Global:[::-] [white]Ctrl+J[::-]=Jobs  [white]Ctrl+N[::-]=Hosts  [white]Ctrl+Z[::-]=Hauptmenü",
	DashHeaderScore:      "Punkte",
	DashHeaderIP:         "IP",
	DashHeaderHostname:   "Hostname",
	DashHeaderCategory:   "Kategorie",
	DashHeaderTopFinding: "Wichtigster Fund (Gesamt)",
	DashNoHostsYet:       "Noch keine Hosts erkannt — Netzwerkerkennung starten.",

	// Panel body
	DashStatsHeading:            "[yellow]Entdeckungsstatistiken[::-]\n\n",
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
	DashNoChartYet:              "[gray]Noch keine Hosts erkannt.[::-]\n\n[gray]Starten Sie die Netzwerkerkennung[::-]\n[gray]über das Skripte-Menü.[::-]\n",
	FmtDashCategoryBar:          "[%s]%-16s[::-]  [%s]%s[::-]  [white]%d[::-]\n",
	DashNoActivityYet:           "[gray]Noch keine Jobs ausgeführt.[::-]\n[gray]Starten Sie eine Erkennung[::-]\n[gray]über das Skripte-Menü.[::-]\n",
	DashNoHostsDiscovered:       "[gray]Noch keine Hosts erkannt.[::-]\n",
	DashRiskDistHeading:         "[yellow]Risikoverteilung[::-]\n",
	DashSevSummaryHeading:       "\n[yellow]Schweregrad-Übersicht[::-]\n",
	DashBySourceHeading:         "\n[yellow]Nach Quelle[::-]\n",
	FmtDashNiktoFindings:        "  Nikto:     [white]%d Befunde[::-]\n",
	FmtDashSSLIssues:            "  SSL/TLS:   [white]%d Probleme[::-]\n",
	FmtDashAvgScore:             "\nDurchschnittliche Punktzahl: [white]%d[::-]\n",
	FmtDashHighestRisk:          "Höchste: [white]%s[::-] ([red]%d[::-])\n",
	FmtDashRiskTierLine:         "  [%s]■ %-9s %d Hosts[::-]\n",
	DashTopServicesHeading:      "[yellow]Top-Dienste[::-]\n",
	FmtDashServiceEntry:         "  [white]%-12s[::-] [green]%d[::-] Hosts\n",
	DashPortsHeading:            "\n[yellow]Ports[::-]\n",
	FmtDashUniqueOpenPorts:      "  Eindeutig offen: [white]%d[::-]\n",
	FmtDashMostExposedHost:      "  Am meisten exponiert: [white]%s[::-] ([red]%d[::-])\n",
	FmtHostOpenPorts:            "Offene Ports: [white]%s[::-]\n",
	FmtFindingsCount:            "%s (%d Befunde)",

	FmtTopFindingMedium:  "%d mittlere Schwachstellen",
	FmtTopFindingPorts:   "%d offene Ports",
	TopFindingNone:       "-",
	RiskTierCritical:     "Kritisch",
	RiskTierHigh:         "Hoch",
	RiskTierMedium:       "Mittel",
	RiskTierLow:          "Niedrig",
	SevCritical:          "Kritisch",
	SevHigh:              "Hoch",
	SevMedium:            "Mittel",
	SevLow:               "Niedrig",
	SevInfo:              "Info",
	FmtSevFindings:       "[%s]%s Befunde[::-]\n",
	FmtSevFindingsCount:  "[%s]%s Befunde (%d)[::-]\n",
	FmtAndMore:           "  ... und %d weitere\n",
	FmtRiskScore:         "Risiko-Score: [%s]%d/1000[%s] %s[::-]\n",
	FmtRiskBreakdownVulns:   "  Schwachstellen:    [white]%d Pkt[::-]\n",
	FmtRiskBreakdownService: "  Dienst-Exponierung: [white]%d Pkt[::-]\n",
	FmtRiskBreakdownSSL:     "  SSL/TLS-Probleme:  [white]%d Pkt[::-]\n",
	FmtRiskBreakdownPorts:   "  Offene Ports:      [white]%d Pkt[::-]\n\n",
	FmtHostRiskDetailWithHost: "[yellow]Host-Risikodetails: %s (%s)[::-]%s",
	FmtHostRiskDetail:         "[yellow]Host-Risikodetails: %s[::-]%s",
	FmtRiskDetailTitle:        "Risikodetails: %s",

	// Correlation viewer
	FmtCorrControlsText: `[yellow]Navigation                     Aktionen[::-]
[white]Enter[::-]  Host-Details anzeigen   [white]s[::-]  Screenshot anzeigen
[white]/[::-]      Hosts suchen            [white]p[::-]  Paket erstellen
%s
[white]Space[::-]  Host kategorisieren     [white]q[::-]  Schließen

[yellow]Global:[::-] [white]Ctrl+J[::-]=Jobs  [white]Ctrl+D[::-]=Dashboard  [white]Ctrl+Z[::-]=Hauptmenü`,
	CorrResetSearch:        "[yellow]f[::-]      Suche zurücksetzen",
	FmtCorrFilterActiveCat: "[yellow]f[::-]      Filter wechseln: %s",
	CorrCycleFilter:        "[white]f[::-]      Kategoriefilter wechseln",
	HostColIP:              "IP",
	HostColCategory:        "Kategorie",
	HostColHostname:        "Hostname",
	HostColVendor:          "Hersteller",
	HostColPorts:           "Ports",
	HostDetailsSelectPrompt:    "[gray]Host auswählen für Details[::-]",
	HostDetailsNoData:          "[gray]Keine Daten für gewählten Host[::-]",
	HostDetailsIdentity:        "[yellow]Identität[::-]\n",
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
	FilterLabel:                "Filter: ",
}

func stringsForLang(lang string) *Strings {
	if lang == "de" {
		return stringsDE
	}
	return stringsEN
}
