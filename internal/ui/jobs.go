package ui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"netutil/internal/jobs"
)

// JobsViewer displays and manages concurrent jobs
type JobsViewer struct {
	*tview.Flex
	app        *tview.Application
	pages      *tview.Pages
	jobManager *jobs.JobManager

	// UI components
	jobsList     *tview.Table
	statsText    *tview.TextView
	controlsText *tview.TextView

	// State
	selectedJob   string
	jobIDMapping  map[int]string // Maps table row to actual job ID
	refreshTicker *time.Ticker
	stopChan      chan struct{}

	// Callback for returning to main TUI with proper focus restoration
	returnToMainCallback func()

	// Internationalization
	str *Strings
}

// NewJobsViewer creates a new jobs viewer
func NewJobsViewer(app *tview.Application, pages *tview.Pages, jobManager *jobs.JobManager, returnToMainCallback func(), str *Strings) *JobsViewer {
	jv := &JobsViewer{
		Flex:                 tview.NewFlex(),
		app:                  app,
		pages:                pages,
		jobManager:           jobManager,
		jobIDMapping:         make(map[int]string),
		stopChan:             make(chan struct{}),
		returnToMainCallback: returnToMainCallback,
		str:                  str,
	}

	jv.setupUI()
	jv.startRefreshTimer()
	return jv
}

// setupUI initializes the jobs viewer interface
func (jv *JobsViewer) setupUI() {
	// Create jobs table
	jv.jobsList = tview.NewTable().SetBorders(true).SetSelectable(true, false)
	jv.jobsList.SetBorder(true).SetTitle(jv.str.PaneTitleActiveJobs)

	// Set table headers
	headers := []string{jv.str.JobsHeaderID, jv.str.JobsHeaderName, jv.str.JobsHeaderStatus, jv.str.JobsHeaderDuration, jv.str.JobsHeaderProgress}
	for i, header := range headers {
		cell := tview.NewTableCell(header).
			SetTextColor(tcell.ColorYellow).
			SetAlign(tview.AlignCenter).
			SetSelectable(false)
		if i == 4 {
			cell.SetExpansion(1)
		}
		jv.jobsList.SetCell(0, i, cell)
	}

	// Create stats panel
	jv.statsText = tview.NewTextView().SetDynamicColors(true)
	jv.statsText.SetBorder(true).SetTitle(jv.str.PaneTitleStatistics)

	// Create controls panel
	jv.controlsText = tview.NewTextView().SetDynamicColors(true)
	jv.controlsText.SetBorder(true).SetTitle(jv.str.PaneTitleControls)
	jv.controlsText.SetText(jv.str.JobsControlsText)

	// Layout: Left panel (table), Right panel (stats + controls)
	rightPanel := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(jv.statsText, 0, 1, false).
		AddItem(jv.controlsText, 9, 0, false)

	jv.SetDirection(tview.FlexColumn).
		AddItem(jv.jobsList, 0, 2, true).
		AddItem(rightPanel, 30, 0, false)

	// Setup key bindings
	jv.setupKeyBindings()

	// Initial update
	jv.updateJobsList()
	jv.updateStats()
}

// setupKeyBindings configures keyboard shortcuts
func (jv *JobsViewer) setupKeyBindings() {
	jv.jobsList.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEscape:
			jv.Close()
			return nil
		case tcell.KeyEnter:
			jv.viewJobOutput()
			return nil
		case tcell.KeyRune:
			switch event.Rune() {
			case 'q':
				jv.Close()
				return nil
			case 'c':
				jv.cancelSelectedJob()
				return nil
			case 'C':
				jv.clearCompletedJobs()
				return nil
			case '1', '2', '3', '4', '5', '6', '7', '8', '9':
				maxConcurrent, _ := strconv.Atoi(string(event.Rune()))
				jv.confirmSetMaxConcurrent(maxConcurrent)
				return nil
			}
		}
		return event
	})

	// Selection handler
	jv.jobsList.SetSelectedFunc(func(row, column int) {
		jv.viewJobOutput()
	})

	jv.jobsList.SetSelectionChangedFunc(func(row, column int) {
		if row > 0 { // Skip header row
			// Use the actual job ID from our mapping instead of truncated display text
			if actualJobID, exists := jv.jobIDMapping[row]; exists {
				jv.selectedJob = actualJobID
			} else {
				jv.selectedJob = ""
			}
		}
	})

}

// updateJobsList refreshes the jobs table
func (jv *JobsViewer) updateJobsList() {
	// Store currently selected job ID before clearing (for selection preservation)
	previouslySelectedJob := jv.selectedJob

	// Clear existing rows (except header)
	jv.jobsList.Clear()
	// Clear job ID mapping
	jv.jobIDMapping = make(map[int]string)

	// Reset headers
	headers := []string{jv.str.JobsHeaderID, jv.str.JobsHeaderName, jv.str.JobsHeaderStatus, jv.str.JobsHeaderDuration, jv.str.JobsHeaderProgress}
	for i, header := range headers {
		cell := tview.NewTableCell(header).
			SetTextColor(tcell.ColorYellow).
			SetAlign(tview.AlignCenter).
			SetSelectable(false)
		if i == 4 {
			cell.SetExpansion(1)
		}
		jv.jobsList.SetCell(0, i, cell)
	}

	// Add job rows
	allJobs := jv.jobManager.GetAllJobs()
	rowToSelect := 1 // Default to first row if previously selected job not found

	for i, job := range allJobs {
		row := i + 1

		// Format job data
		jobID := job.ID
		if len(jobID) > 8 {
			jobID = jobID[:8] + "..."
		}

		jobName := job.Name

		status := string(job.GetStatus())
		statusColor := jv.getStatusColor(job.GetStatus())

		duration := jv.formatDuration(job.GetDuration())
		if job.IsRunning() {
			duration = jv.formatDuration(time.Since(job.StartTime))
		}

		progress := jv.getJobProgress(job)

		// Set table cells (jobID is truncated for display)
		jv.jobsList.SetCell(row, 0, tview.NewTableCell(jobID))
		jv.jobsList.SetCell(row, 1, tview.NewTableCell(jobName))
		jv.jobsList.SetCell(row, 2, tview.NewTableCell(status).SetTextColor(statusColor))
		jv.jobsList.SetCell(row, 3, tview.NewTableCell(duration))
		jv.jobsList.SetCell(row, 4, tview.NewTableCell(progress).SetExpansion(1))

		// Store mapping from row to actual full job ID
		jv.jobIDMapping[row] = job.ID

		// Check if this is the previously selected job
		if job.ID == previouslySelectedJob {
			rowToSelect = row
		}
	}

	// Restore selection to previously selected job (or default to row 1)
	if jv.jobsList.GetRowCount() > 1 {
		jv.jobsList.Select(rowToSelect, 0)
	}
}

// updateStats refreshes the statistics panel
func (jv *JobsViewer) updateStats() {
	stats := jv.jobManager.GetStats()

	statsText := fmt.Sprintf(jv.str.FmtJobStats,
		stats.TotalJobs,
		stats.RunningJobs, stats.MaxConcurrent,
		stats.PendingJobs,
		stats.CompletedJobs,
		stats.FailedJobs,
		stats.CancelledJobs,
		stats.RunningJobs, stats.MaxConcurrent)

	jv.statsText.SetText(statsText)
}

// getStatusColor returns the appropriate color for a job status
func (jv *JobsViewer) getStatusColor(status jobs.JobStatus) tcell.Color {
	switch status {
	case jobs.JobStatusRunning:
		return tcell.ColorGreen
	case jobs.JobStatusCompleted:
		return tcell.ColorBlue
	case jobs.JobStatusFailed:
		return tcell.ColorRed
	case jobs.JobStatusCancelled:
		return tcell.ColorGray
	case jobs.JobStatusPending:
		return tcell.ColorYellow
	default:
		return tcell.ColorWhite
	}
}

// formatDuration formats a duration for display
func (jv *JobsViewer) formatDuration(d time.Duration) string {
	if d == 0 {
		return "-"
	}

	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	} else if d < time.Hour {
		return fmt.Sprintf("%.1fm", d.Minutes())
	} else {
		return fmt.Sprintf("%.1fh", d.Hours())
	}
}

// getJobProgress returns a progress indicator for the job
func (jv *JobsViewer) getJobProgress(job *jobs.Job) string {
	switch job.GetStatus() {
	case jobs.JobStatusPending:
		return jv.str.ProgressWaiting
	case jobs.JobStatusRunning:
		current, total, desc := job.GetPhaseProgress()
		if total > 0 {
			return renderProgressBar(current, total, desc)
		}
		indicators := []string{"⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"}
		idx := int(time.Now().Unix()) % len(indicators)
		return fmt.Sprintf("%s %s", indicators[idx], jv.str.ProgressRunning)
	case jobs.JobStatusCompleted:
		return jv.str.ProgressDone
	case jobs.JobStatusFailed:
		return jv.str.ProgressFailed
	case jobs.JobStatusCancelled:
		return jv.str.ProgressCancelled
	default:
		return jv.str.ProgressUnknown
	}
}

// renderProgressBar renders a compact Unicode block progress bar.
// Example: "[████████░░] 2/3 V100:3/8 V200:done"
func renderProgressBar(current, total int, desc string) string {
	const barWidth = 10
	filled := current * barWidth / total
	if filled > barWidth {
		filled = barWidth
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	if len([]rune(desc)) > 20 {
		desc = string([]rune(desc)[:20])
	}
	if desc != "" {
		return fmt.Sprintf("[%s] %d/%d %s", bar, current, total, desc)
	}
	return fmt.Sprintf("[%s] %d/%d", bar, current, total)
}

// viewJobOutput opens the output viewer for the selected job.
// For running jobs it attaches live; for finished jobs it shows the stored output.
func (jv *JobsViewer) viewJobOutput() {
	if jv.selectedJob == "" {
		return
	}

	job, exists := jv.jobManager.GetJob(jv.selectedJob)
	if !exists {
		jv.showError(jv.str.ErrJobNotFound)
		return
	}

	outputViewer := NewOutputViewer(jv.app, jv.pages, jv.jobManager, func() {
		jv.pages.RemovePage("job-output")
		jv.app.SetFocus(jv.jobsList)
	})

	if job.IsRunning() {
		if err := outputViewer.ConnectToJob(job); err != nil {
			jv.showError(fmt.Sprintf(jv.str.FmtErrConnectJob, err))
			return
		}
	} else {
		// Show stored output for completed/failed/cancelled jobs
		lines := job.GetOutputLines()
		if len(lines) == 0 {
			jv.showError(jv.str.ErrNoOutputCaptured)
			return
		}
		outputViewer.ShowHistoricalOutput(job.Name, job.GetStatus(), lines)
	}

	jv.pages.AddPage("job-output", outputViewer, true, true)
	outputViewer.FocusView()
}

// cancelSelectedJob cancels the currently selected job
func (jv *JobsViewer) cancelSelectedJob() {
	if jv.selectedJob == "" {
		jv.showError(jv.str.ErrNoJobSelected)
		return
	}

	if err := jv.jobManager.CancelJob(jv.selectedJob); err != nil {
		jv.showError(fmt.Sprintf(jv.str.FmtErrCancelJob, err))
		return
	}

	jv.refresh()
}

// clearCompletedJobs removes all completed jobs
func (jv *JobsViewer) clearCompletedJobs() {
	removed := jv.jobManager.ClearCompletedJobs()
	jv.showInfo(fmt.Sprintf(jv.str.FmtRemovedCompleted, removed))
	jv.refresh()
}

// confirmSetMaxConcurrent shows a modal asking the user to confirm the new
// maximum concurrent job limit before applying it.
func (jv *JobsViewer) confirmSetMaxConcurrent(max int) {
	modal := tview.NewModal().
		SetText(fmt.Sprintf(jv.str.FmtSetMaxConcurrent, max)).
		AddButtons([]string{jv.str.BtnYes, jv.str.BtnNo}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			jv.pages.RemovePage("confirm-concurrency")
			if buttonLabel == jv.str.BtnYes {
				jv.setMaxConcurrent(max)
			}
		})
	jv.pages.AddPage("confirm-concurrency", modal, true, true)
}

// setMaxConcurrent sets the maximum number of concurrent jobs
func (jv *JobsViewer) setMaxConcurrent(max int) {
	jv.jobManager.SetMaxConcurrent(max)
	jv.showInfo(fmt.Sprintf(jv.str.FmtMaxConcurrentSet, max))
}

// refresh updates all UI components
func (jv *JobsViewer) refresh() {
	// Update directly - we're already on the UI thread when called from key handlers
	jv.updateJobsList()
	jv.updateStats()
}

// startRefreshTimer starts automatic refresh
func (jv *JobsViewer) startRefreshTimer() {
	jv.refreshTicker = time.NewTicker(1 * time.Second)
	go func() {
		for {
			select {
			case <-jv.refreshTicker.C:
				// Use QueueUpdateDraw for background goroutine updates
				jv.app.QueueUpdateDraw(func() {
					jv.updateJobsList()
					jv.updateStats()
				})
			case <-jv.stopChan:
				return
			}
		}
	}()
}

// ShowJobsViewer creates and displays a new jobs viewer page.
// For the main TUI use showJobsManager() which reuses a cached instance.
func ShowJobsViewer(app *tview.Application, pages *tview.Pages, jobManager *jobs.JobManager, returnToMainCallback func(), str *Strings) {
	jv := NewJobsViewer(app, pages, jobManager, returnToMainCallback, str)
	pages.AddPage("jobs", jv, true, true)
	app.SetFocus(jv.jobsList)
}

// Close closes the jobs viewer and stops its refresh ticker.
func (jv *JobsViewer) Close() {
	if jv.refreshTicker != nil {
		jv.refreshTicker.Stop()
		jv.refreshTicker = nil
	}
	select {
	case <-jv.stopChan:
		return
	default:
	}
	close(jv.stopChan)
	jv.pages.RemovePage("jobs")
	if jv.returnToMainCallback != nil {
		jv.returnToMainCallback()
	}
}

// showError displays an error message
func (jv *JobsViewer) showError(message string) {
	modal := tview.NewModal().
		SetText(fmt.Sprintf(jv.str.FmtShowErrorPrefix, message)).
		AddButtons([]string{jv.str.BtnOK}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			jv.pages.RemovePage("error")
		})

	jv.pages.AddPage("error", modal, true, true)
}

// showInfo displays an info message
func (jv *JobsViewer) showInfo(message string) {
	modal := tview.NewModal().
		SetText(message).
		AddButtons([]string{jv.str.BtnOK}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			jv.pages.RemovePage("info")
		})

	jv.pages.AddPage("info", modal, true, true)
}
