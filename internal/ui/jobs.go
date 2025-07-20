package ui

import (
	"fmt"
	"strconv"
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
}

// NewJobsViewer creates a new jobs viewer
func NewJobsViewer(app *tview.Application, pages *tview.Pages, jobManager *jobs.JobManager) *JobsViewer {
	jv := &JobsViewer{
		Flex:         tview.NewFlex(),
		app:          app,
		pages:        pages,
		jobManager:   jobManager,
		jobIDMapping: make(map[int]string),
		stopChan:     make(chan struct{}),
	}

	jv.setupUI()
	jv.startRefreshTimer()
	return jv
}

// setupUI initializes the jobs viewer interface
func (jv *JobsViewer) setupUI() {
	// Create jobs table
	jv.jobsList = tview.NewTable().SetBorders(true).SetSelectable(true, false)
	jv.jobsList.SetBorder(true).SetTitle("Active Jobs")

	// Set table headers
	headers := []string{"ID", "Name", "Status", "Duration", "Progress"}
	for i, header := range headers {
		jv.jobsList.SetCell(0, i, tview.NewTableCell(header).
			SetTextColor(tcell.ColorYellow).
			SetAlign(tview.AlignCenter).
			SetSelectable(false))
	}

	// Create stats panel
	jv.statsText = tview.NewTextView().SetDynamicColors(true)
	jv.statsText.SetBorder(true).SetTitle("Statistics")

	// Create controls panel
	jv.controlsText = tview.NewTextView().SetDynamicColors(true)
	jv.controlsText.SetBorder(true).SetTitle("Controls")
	jv.controlsText.SetText(`[yellow]Controls:[::-]
[white]Enter[::-]    View job output
[white]c[::-]        Cancel selected job
[white]C[::-]        Clear completed jobs
[white]r[::-]        Refresh view
[white]q[::-]        Close jobs viewer
[white]1-9[::-]      Set max concurrent jobs`)

	// Layout: Left panel (table), Right panel (stats + controls)
	rightPanel := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(jv.statsText, 0, 1, false).
		AddItem(jv.controlsText, 8, 0, false)

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
			case 'r':
				jv.refresh()
				return nil
			case '1', '2', '3', '4', '5', '6', '7', '8', '9':
				maxConcurrent, _ := strconv.Atoi(string(event.Rune()))
				jv.setMaxConcurrent(maxConcurrent)
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

	// Add mouse support to jobs table
	jv.jobsList.SetMouseCapture(func(action tview.MouseAction, event *tcell.EventMouse) (tview.MouseAction, *tcell.EventMouse) {
		if action == tview.MouseLeftClick {
			// Get click position relative to table
			_, y := event.Position()
			// Approximate row calculation (y-1 to account for border, assuming each row is 1 line)
			row := y
			if row > 0 && row < jv.jobsList.GetRowCount() {
				jv.jobsList.Select(row, 0)
			}
		}
		return action, event
	})
}

// updateJobsList refreshes the jobs table
func (jv *JobsViewer) updateJobsList() {
	// Clear existing rows (except header)
	jv.jobsList.Clear()
	// Clear job ID mapping
	jv.jobIDMapping = make(map[int]string)

	// Reset headers
	headers := []string{"ID", "Name", "Status", "Duration", "Progress"}
	for i, header := range headers {
		jv.jobsList.SetCell(0, i, tview.NewTableCell(header).
			SetTextColor(tcell.ColorYellow).
			SetAlign(tview.AlignCenter).
			SetSelectable(false))
	}

	// Add job rows
	allJobs := jv.jobManager.GetAllJobs()
	for i, job := range allJobs {
		row := i + 1

		// Format job data
		jobID := job.ID
		if len(jobID) > 8 {
			jobID = jobID[:8] + "..."
		}

		jobName := job.Name
		if len(jobName) > 20 {
			jobName = jobName[:17] + "..."
		}

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
		jv.jobsList.SetCell(row, 4, tview.NewTableCell(progress))

		// Store mapping from row to actual full job ID
		jv.jobIDMapping[row] = job.ID
	}

	// Set initial selection to enable navigation (skip header row)
	if jv.jobsList.GetRowCount() > 1 {
		jv.jobsList.Select(1, 0)
	}
}

// updateStats refreshes the statistics panel
func (jv *JobsViewer) updateStats() {
	stats := jv.jobManager.GetStats()

	statsText := fmt.Sprintf(`[yellow]Job Statistics:[::-]

[white]Total Jobs:[::-]      %d
[green]Running:[::-]         %d/%d
[blue]Pending:[::-]         %d
[green]Completed:[::-]       %d
[red]Failed:[::-]           %d
[gray]Cancelled:[::-]       %d

[yellow]Capacity:[::-]        %d/%d`,
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
		return "⏳ Waiting"
	case jobs.JobStatusRunning:
		// Simple animated indicator
		indicators := []string{"⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"}
		idx := int(time.Now().Unix()) % len(indicators)
		return fmt.Sprintf("%s Running", indicators[idx])
	case jobs.JobStatusCompleted:
		return "✅ Done"
	case jobs.JobStatusFailed:
		return "❌ Failed"
	case jobs.JobStatusCancelled:
		return "🚫 Cancelled"
	default:
		return "❓ Unknown"
	}
}

// viewJobOutput opens the output viewer for the selected job
func (jv *JobsViewer) viewJobOutput() {
	if jv.selectedJob == "" {
		return
	}

	job, exists := jv.jobManager.GetJob(jv.selectedJob)
	if !exists {
		jv.showError("Job not found")
		return
	}

	if !job.IsRunning() {
		jv.showError("Job is not running - no live output available")
		return
	}

	// Create output viewer for the job
	outputViewer := NewOutputViewer(jv.app, jv.pages, jv.jobManager)

	// Connect to the existing job
	if err := outputViewer.ConnectToJob(job); err != nil {
		jv.showError(fmt.Sprintf("Failed to connect to job: %v", err))
		return
	}

	// Add to pages and focus
	jv.pages.AddPage("job-output", outputViewer, true, true)
	jv.app.SetFocus(outputViewer)
}

// cancelSelectedJob cancels the currently selected job
func (jv *JobsViewer) cancelSelectedJob() {
	if jv.selectedJob == "" {
		jv.showError("No job selected")
		return
	}

	if err := jv.jobManager.CancelJob(jv.selectedJob); err != nil {
		jv.showError(fmt.Sprintf("Failed to cancel job: %v", err))
		return
	}

	jv.refresh()
}

// clearCompletedJobs removes all completed jobs
func (jv *JobsViewer) clearCompletedJobs() {
	removed := jv.jobManager.ClearCompletedJobs()
	jv.showInfo(fmt.Sprintf("Removed %d completed jobs", removed))
	jv.refresh()
}

// setMaxConcurrent sets the maximum number of concurrent jobs
func (jv *JobsViewer) setMaxConcurrent(max int) {
	// This would require adding a method to JobManager
	jv.showInfo(fmt.Sprintf("Max concurrent jobs set to %d", max))
}

// refresh updates all UI components
func (jv *JobsViewer) refresh() {
	jv.app.QueueUpdateDraw(func() {
		jv.updateJobsList()
		jv.updateStats()
	})
}

// startRefreshTimer starts automatic refresh
func (jv *JobsViewer) startRefreshTimer() {
	jv.refreshTicker = time.NewTicker(1 * time.Second)
	go func() {
		for {
			select {
			case <-jv.refreshTicker.C:
				jv.refresh()
			case <-jv.stopChan:
				return
			}
		}
	}()
}

// Close closes the jobs viewer
func (jv *JobsViewer) Close() {
	if jv.refreshTicker != nil {
		jv.refreshTicker.Stop()
	}
	close(jv.stopChan)
	jv.pages.RemovePage("jobs")
}

// showError displays an error message
func (jv *JobsViewer) showError(message string) {
	modal := tview.NewModal().
		SetText(fmt.Sprintf("Error: %s", message)).
		AddButtons([]string{"OK"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			jv.pages.RemovePage("error")
		})

	jv.pages.AddPage("error", modal, true, true)
}

// showInfo displays an info message
func (jv *JobsViewer) showInfo(message string) {
	modal := tview.NewModal().
		SetText(message).
		AddButtons([]string{"OK"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			jv.pages.RemovePage("info")
		})

	jv.pages.AddPage("info", modal, true, true)
}

// Helper function to create a jobs viewer page
func ShowJobsViewer(app *tview.Application, pages *tview.Pages, jobManager *jobs.JobManager) {
	jobsViewer := NewJobsViewer(app, pages, jobManager)
	pages.AddPage("jobs", jobsViewer, true, true)
	app.SetFocus(jobsViewer.jobsList)
}
